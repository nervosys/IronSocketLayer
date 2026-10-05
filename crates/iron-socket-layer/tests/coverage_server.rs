//! Requirements-based tests for server-side outcomes the rest of the suite
//! did not reach: refused ClientHellos, PSK, ticket, ECH and 0-RTT refusals,
//! HelloRetryRequest checks, ALPN and client-authentication outcomes.
//!
//! Hellos are taken from this crate's client and edited while still in
//! plaintext; where an edit invalidates a PSK binder, the binder is computed
//! again from the PSK, so that the server's decision is the one under test.

mod common;

use std::sync::Arc;

use common::*;
use iron_socket_layer::config::{
    ClientAuth, ClientConfig, EarlyDataPolicy, ExternalPsk, PeerVerification, Profile, ServerConfig,
};
use iron_socket_layer::crypto::hpke;
use iron_socket_layer::crypto::kx::KeyShare;
use iron_socket_layer::crypto::sign::KeyKind;
use iron_socket_layer::crypto::HashAlg;
use iron_socket_layer::ech::{self, EchServer};
use iron_socket_layer::enums::{
    AlertDescription, CipherSuite, ContentType, HandshakeType, NamedGroup, SignatureScheme,
};
use iron_socket_layer::key_schedule::EarlyStage;
use iron_socket_layer::msgs::{
    self, CertificateMsg, CertificateVerify, ClientHello, EchHello, OfferedPsks, PskIdentity,
    ServerHello,
};
use iron_socket_layer::quic::{QuicConnection, Version};
use iron_socket_layer::record;
use iron_socket_layer::report::{HandshakeState, Property};
use iron_socket_layer::resumption::{StoredTicket, TicketKeys};
use iron_socket_layer::x509::RootStore;
use iron_socket_layer::{Connection, ErrorKind, Level};

const NAME: &str = "server.test";
const REQUEST: &[u8] = b"GET /status HTTP/1.1\r\nHost: x\r\n\r\n";

fn rng() -> ic_drbg::Rng {
    ic_drbg::Rng::from_os().unwrap()
}

/// The first handshake message in a flight's first record.
fn first_message(flight: &[u8]) -> (HandshakeType, Vec<u8>) {
    assert_eq!(flight[0], 22, "a handshake record first");
    let len = u16::from_be_bytes([flight[3], flight[4]]) as usize;
    let rec = &flight[5..5 + len];
    let n = u32::from_be_bytes([0, rec[1], rec[2], rec[3]]) as usize;
    (HandshakeType::from_wire(rec[0]), rec[4..4 + n].to_vec())
}

/// A plaintext handshake record carrying one message.
fn record_of(ty: HandshakeType, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    record::write_plaintext(
        ContentType::Handshake,
        &msgs::frame(ty, body).unwrap(),
        &mut out,
    );
    out
}

/// Split QUIC CRYPTO data into whole handshake messages, headers included.
fn messages(mut data: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    while !data.is_empty() {
        let n = 4 + u32::from_be_bytes([0, data[1], data[2], data[3]]) as usize;
        out.push(data[..n].to_vec());
        data = &data[n..];
    }
    out
}

/// The ClientHello this crate's client sends first.
fn hello(cc: &Arc<ClientConfig>, name: &str) -> ClientHello {
    let mut c = Connection::client(cc.clone(), name).unwrap();
    let (ty, body) = first_message(&c.take_tls());
    assert_eq!(ty, HandshakeType::ClientHello);
    ClientHello::decode(&body).unwrap()
}

/// The ServerHello at the front of a server flight.
fn server_hello(flight: &[u8]) -> ServerHello {
    let (ty, body) = first_message(flight);
    assert_eq!(ty, HandshakeType::ServerHello);
    ServerHello::decode(&body).unwrap()
}

/// Recompute binder `i` of an edited hello from its PSK (RFC 8446 §4.2.11.2).
fn bind(ch: &mut ClientHello, i: usize, psk: &[u8], hash: HashAlg, external: bool) {
    let msg = msgs::frame(HandshakeType::ClientHello, &ch.encode().unwrap()).unwrap();
    let cut = msg.len() - ch.psk.as_ref().unwrap().binders_len();
    let th = hash.digest(&msg[..cut]);
    let stage = EarlyStage::new(hash, Some(psk)).unwrap();
    let binder = if external {
        stage.external_binder(th.as_bytes())
    } else {
        stage.resumption_binder(th.as_bytes())
    }
    .unwrap();
    ch.psk.as_mut().unwrap().binders[i] = binder.as_bytes().to_vec();
}

/// A copy of the ticket the client holds for `name`, left in its store.
fn held_ticket(cc: &ClientConfig, name: &str) -> StoredTicket {
    let store = cc.tickets.as_ref().unwrap();
    let t = store.take(name, now()).expect("the client holds a ticket");
    store.put(t.clone());
    t
}

fn hash_of(suite: CipherSuite) -> HashAlg {
    record::suite_params(suite).unwrap().1
}

/// Connect and hand the client its NewSessionTicket.
fn get_ticket(cc: &Arc<ClientConfig>, sc: &Arc<ServerConfig>, name: &str) {
    let (mut c, mut s) = connect(cc.clone(), sc.clone(), name).unwrap();
    c.read_tls(&s.take_tls()).unwrap();
    assert!(c.report().tickets_received >= 1);
}

fn pump(c: &mut Connection, s: &mut Connection) {
    for _ in 0..4 {
        let to_c = s.take_tls();
        if !to_c.is_empty() {
            let _ = c.read_tls(&to_c);
        }
        let to_s = c.take_tls();
        if !to_s.is_empty() {
            let _ = s.read_tls(&to_s);
        }
    }
}

/// A 0-RTT attempt from a client that holds a ticket, run to completion.
fn early_attempt(
    cc: &Arc<ClientConfig>,
    sc: &Arc<ServerConfig>,
    name: &str,
) -> (Connection, Connection) {
    let mut c = Connection::client_with_early_data(cc.clone(), name, REQUEST).unwrap();
    let mut s = Connection::server(sc.clone()).unwrap();
    s.read_tls(&c.take_tls()).unwrap();
    pump(&mut c, &mut s);
    assert_eq!(c.state(), HandshakeState::Connected, "{:?}", c.error());
    assert_eq!(s.state(), HandshakeState::Connected, "{:?}", s.error());
    (c, s)
}

fn early_configs(pki: &Pki) -> (ClientConfig, ServerConfig) {
    let mut cc = pki.client_config(Profile::Default);
    cc.early_data = true;
    let mut sc = pki.server_config(Profile::Default);
    sc.early_data = Some(EarlyDataPolicy::new(16_384));
    (cc, sc)
}

/// Move every pending QUIC flight from one side to the other.
fn deliver(from: &mut QuicConnection, to: &mut QuicConnection) {
    while let Ok(Some(_)) = from.next_key_change() {}
    while let Some((level, data)) = from.write_handshake() {
        to.read_handshake(level, &data).unwrap();
    }
    while let Ok(Some(_)) = to.next_key_change() {}
}

/// The client's CRYPTO data at the Initial level: its ClientHello.
fn quic_hello(cc: &Arc<ClientConfig>) -> ClientHello {
    let mut c = QuicConnection::client(cc.clone(), NAME, b"c", Version::V1).unwrap();
    while let Ok(Some(_)) = c.next_key_change() {}
    let (level, data) = c.write_handshake().unwrap();
    assert_eq!(level, Level::Initial);
    let m = messages(&data);
    assert_eq!(m.len(), 1);
    ClientHello::decode(&m[0][4..]).unwrap()
}

fn quic_client_hello_frame(ch: &ClientHello) -> Vec<u8> {
    msgs::frame(HandshakeType::ClientHello, &ch.encode().unwrap()).unwrap()
}

// ---------------------------------------------------------------------------
// Client authentication and post-quantum authentication claims.

/// REQ-PHA-003: post-handshake authentication applies the handshake's rule
/// for post-quantum authentication. A client that authenticates afterwards
/// with a classical certificate, or with an ML-DSA leaf trusted directly as
/// an anchor (no chain signature verified), withdraws the server's
/// post-quantum authentication claim; an ML-DSA chain keeps it. A client
/// that answers with a classical signature withdraws its own claim.
#[test]
fn post_handshake_authentication_keeps_post_quantum_claims_honest() {
    let pki = Pki::with_kinds(KeyKind::MlDsa65, KeyKind::MlDsa65, NAME);
    let ml_dsa = pki.client_identity(KeyKind::MlDsa65, "agent-pq");
    let mut anchored = RootStore::new();
    anchored.add_der(&ml_dsa.chain[0]).unwrap();
    let cases = [
        (
            "classical chain",
            pki.client_identity(KeyKind::EcdsaP256, "agent-ec"),
            pki.roots(),
            false,
        ),
        ("ML-DSA chain", ml_dsa.clone(), pki.roots(), true),
        ("ML-DSA leaf as anchor", ml_dsa, anchored, false),
    ];
    for (name, identity, roots, pq) in cases {
        let mut cc = pki.client_config(Profile::Default).with_identity(identity);
        cc.post_handshake_auth = true;
        let sc = pki
            .server_config(Profile::Default)
            .with_client_auth(ClientAuth::OnDemand(PeerVerification::Roots(roots)));
        let (mut c, mut s) = connect(Arc::new(cc), Arc::new(sc), NAME).unwrap();
        assert!(
            s.report().has(Property::PostQuantumAuthentication),
            "{name}: the server's own ML-DSA signature is the only authentication so far"
        );
        s.request_client_auth().unwrap();
        pump(&mut c, &mut s);
        let r = s.report();
        assert!(
            r.has(Property::MutualAuthentication),
            "{name}: {}",
            r.to_json()
        );
        assert_eq!(
            r.has(Property::PostQuantumAuthentication),
            pq,
            "{name}: {}",
            r.to_json()
        );
        // The client applies the same rule to what it can see: its own
        // answer. A classical signature withdraws its claim too.
        let client_pq = name != "classical chain";
        let r = c.report();
        assert!(r.has(Property::MutualAuthentication), "{name}");
        assert_eq!(
            r.has(Property::PostQuantumAuthentication),
            client_pq,
            "{name} (client): {}",
            r.to_json()
        );
    }
}

/// HLR-003 (no LLR yet): a mutually authenticated server claims
/// post-quantum authentication only when the client's chain and
/// CertificateVerify are ML-DSA end to end. A classical client, or an ML-DSA
/// leaf trusted directly as an anchor (no chain signature verified), does
/// not earn it, though the server's own signature is ML-DSA.
#[test]
fn mutual_post_quantum_authentication_needs_an_ml_dsa_client_chain() {
    let pki = Pki::with_kinds(KeyKind::MlDsa65, KeyKind::MlDsa65, NAME);
    let ml_dsa = pki.client_identity(KeyKind::MlDsa65, "agent-pq");
    let mut anchored = RootStore::new();
    anchored.add_der(&ml_dsa.chain[0]).unwrap();
    let cases = [
        (
            "classical chain",
            pki.client_identity(KeyKind::EcdsaP256, "agent-ec"),
            pki.roots(),
            false,
        ),
        ("ML-DSA chain", ml_dsa.clone(), pki.roots(), true),
        ("ML-DSA leaf as anchor", ml_dsa, anchored, false),
    ];
    for (name, identity, roots, pq) in cases {
        let cc = pki.client_config(Profile::Default).with_identity(identity);
        let sc = pki
            .server_config(Profile::Default)
            .with_client_auth(ClientAuth::Required(PeerVerification::Roots(roots)));
        let (_, s) = connect(Arc::new(cc), Arc::new(sc), NAME).unwrap();
        let r = s.report();
        assert!(
            r.has(Property::MutualAuthentication),
            "{name}: {}",
            r.to_json()
        );
        assert_eq!(
            r.has(Property::PostQuantumAuthentication),
            pq,
            "{name}: {}",
            r.to_json()
        );
    }
}

/// REQ-PHA-001: a server asks for post-handshake authentication only on an
/// established connection; before the handshake completes the request is
/// refused and nothing is sent.
#[test]
fn client_authentication_cannot_be_requested_mid_handshake() {
    let pki = Pki::new(KeyKind::EcdsaP256, NAME);
    let mut cc = pki
        .client_config(Profile::Default)
        .with_identity(pki.client_identity(KeyKind::EcdsaP256, "agent"));
    cc.post_handshake_auth = true;
    let sc = pki
        .server_config(Profile::Default)
        .with_client_auth(ClientAuth::OnDemand(PeerVerification::Roots(pki.roots())));
    let mut c = Connection::client(Arc::new(cc), NAME).unwrap();
    let mut s = Connection::server(Arc::new(sc)).unwrap();
    let want = "post-handshake authentication needs an established TLS-over-TCP connection";
    let e = s.request_client_auth().unwrap_err();
    assert_eq!((e.kind(), e.context()), (ErrorKind::InvalidState, want));
    s.read_tls(&c.take_tls()).unwrap();
    assert_eq!(s.state(), HandshakeState::WaitFinished);
    let _flight = s.take_tls();
    let e = s.request_client_auth().unwrap_err();
    assert_eq!((e.kind(), e.context()), (ErrorKind::InvalidState, want));
    assert!(s.take_tls().is_empty(), "no CertificateRequest was sent");
}

/// QUIC handshake up to the client's second flight, which is returned as
/// separate messages instead of being delivered.
fn quic_client_auth_flight() -> (QuicConnection, Vec<Vec<u8>>) {
    let pki = Pki::new(KeyKind::EcdsaP256, NAME);
    let cc = pki
        .client_config(Profile::Default)
        .with_alpn(&[b"h3"])
        .with_identity(pki.client_identity(KeyKind::EcdsaP256, "agent"));
    let sc = pki
        .server_config(Profile::Default)
        .with_alpn(&[b"h3"])
        .with_client_auth(ClientAuth::Required(PeerVerification::Roots(pki.roots())));
    let mut c = QuicConnection::client(Arc::new(cc), NAME, b"c", Version::V1).unwrap();
    let mut s = QuicConnection::server(Arc::new(sc), b"s", Version::V1).unwrap();
    deliver(&mut c, &mut s);
    deliver(&mut s, &mut c);
    while let Ok(Some(_)) = c.next_key_change() {}
    let (level, data) = c.write_handshake().unwrap();
    assert_eq!(level, Level::Handshake);
    assert_eq!(s.state(), HandshakeState::WaitCertificate);
    (s, messages(&data))
}

/// REQ-MSG-006: a client Certificate answering an in-handshake
/// CertificateRequest has an empty certificate_request_context (RFC 8446
/// §4.4.2); anything else is illegal_parameter.
#[test]
fn an_in_handshake_client_certificate_must_have_an_empty_context() {
    let (mut s, flight) = quic_client_auth_flight();
    let real = CertificateMsg::decode(&flight[0][4..]).unwrap();
    assert!(real.context.is_empty());
    let body = CertificateMsg {
        context: vec![1],
        chain: real.chain,
        ocsp: None,
    }
    .encode()
    .unwrap();
    let e = s
        .read_handshake(
            Level::Handshake,
            &msgs::frame(HandshakeType::Certificate, &body).unwrap(),
        )
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::IllegalParameter);
    assert_eq!(e.context(), "client Certificate context must be empty");
    assert_eq!(s.alert(), Some(AlertDescription::IllegalParameter));
    assert_eq!(s.state(), HandshakeState::Failed);
}

/// REQ-SIG-002: a client CertificateVerify signed with PKCS#1 v1.5, a scheme
/// the CertificateRequest never offered, is illegal_parameter before any
/// signature is checked.
#[test]
fn an_in_handshake_certificate_verify_must_use_a_requested_scheme() {
    let (mut s, flight) = quic_client_auth_flight();
    s.read_handshake(Level::Handshake, &flight[0]).unwrap();
    assert_eq!(s.state(), HandshakeState::WaitCertificateVerify);
    let body = CertificateVerify {
        scheme: SignatureScheme::RsaPkcs1Sha256,
        signature: vec![0; 256],
    }
    .encode()
    .unwrap();
    let e = s
        .read_handshake(
            Level::Handshake,
            &msgs::frame(HandshakeType::CertificateVerify, &body).unwrap(),
        )
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::IllegalParameter);
    assert_eq!(e.context(), "CertificateVerify uses a scheme not requested");
    assert_eq!(s.state(), HandshakeState::Failed);
}

// ---------------------------------------------------------------------------
// QUIC-specific refusals.

/// REQ-0RTT-005, REQ-QUIC-004: a QUIC client never sends EndOfEarlyData
/// (RFC 9001 §8.3); one is unexpected_message, which maps to QUIC error
/// 0x0100 + 10.
#[test]
fn quic_refuses_end_of_early_data() {
    let pki = Pki::new(KeyKind::EcdsaP256, NAME);
    let cc = Arc::new(pki.client_config(Profile::Default).with_alpn(&[b"h3"]));
    let sc = Arc::new(pki.server_config(Profile::Default).with_alpn(&[b"h3"]));
    let mut c = QuicConnection::client(cc, NAME, b"c", Version::V1).unwrap();
    let mut s = QuicConnection::server(sc, b"s", Version::V1).unwrap();
    deliver(&mut c, &mut s);
    deliver(&mut s, &mut c);
    assert_eq!(s.state(), HandshakeState::WaitFinished);
    let e = s
        .read_handshake(
            Level::Handshake,
            &msgs::frame(HandshakeType::EndOfEarlyData, &[]).unwrap(),
        )
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::UnexpectedMessage);
    assert_eq!(e.context(), "handshake message not permitted in this state");
    assert_eq!(s.transport_error_code(), Some(0x0100 + 10));
}

/// REQ-PHA-001: QUIC has no post-handshake authentication, so a client
/// Certificate, CertificateVerify or Finished after the handshake is
/// unexpected_message.
#[test]
fn quic_refuses_client_authentication_messages_after_the_handshake() {
    let pki = Pki::new(KeyKind::EcdsaP256, NAME);
    let cc = Arc::new(pki.client_config(Profile::Default).with_alpn(&[b"h3"]));
    let sc = Arc::new(pki.server_config(Profile::Default).with_alpn(&[b"h3"]));
    let late = [
        msgs::frame(HandshakeType::Finished, &[0; 32]).unwrap(),
        msgs::frame(
            HandshakeType::Certificate,
            &CertificateMsg {
                context: vec![],
                chain: vec![],
                ocsp: None,
            }
            .encode()
            .unwrap(),
        )
        .unwrap(),
        msgs::frame(
            HandshakeType::CertificateVerify,
            &CertificateVerify {
                scheme: SignatureScheme::EcdsaSecp256r1Sha256,
                signature: vec![0; 64],
            }
            .encode()
            .unwrap(),
        )
        .unwrap(),
    ];
    for msg in late {
        let mut c = QuicConnection::client(cc.clone(), NAME, b"c", Version::V1).unwrap();
        let mut s = QuicConnection::server(sc.clone(), b"s", Version::V1).unwrap();
        for _ in 0..3 {
            deliver(&mut c, &mut s);
            deliver(&mut s, &mut c);
        }
        assert_eq!(s.state(), HandshakeState::Connected);
        let e = s.read_handshake(Level::Application, &msg).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::UnexpectedMessage);
        assert_eq!(e.context(), "handshake message not permitted in this state");
    }
}

/// REQ-QUIC-004: a QUIC ClientHello has an empty legacy_session_id (RFC 9001
/// §8.4); one with a session ID is illegal_parameter, QUIC error 0x0100 + 47.
#[test]
fn quic_refuses_a_legacy_session_id() {
    let pki = Pki::new(KeyKind::EcdsaP256, NAME);
    let cc = Arc::new(pki.client_config(Profile::Default).with_alpn(&[b"h3"]));
    let sc = Arc::new(pki.server_config(Profile::Default).with_alpn(&[b"h3"]));
    let mut ch = quic_hello(&cc);
    assert!(ch.session_id.is_empty());
    let mut control = QuicConnection::server(sc.clone(), b"s", Version::V1).unwrap();
    control
        .read_handshake(Level::Initial, &quic_client_hello_frame(&ch))
        .unwrap();
    ch.session_id = vec![7; 32];
    let mut s = QuicConnection::server(sc, b"s", Version::V1).unwrap();
    let e = s
        .read_handshake(Level::Initial, &quic_client_hello_frame(&ch))
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::IllegalParameter);
    assert_eq!(e.context(), "QUIC ClientHello with a legacy_session_id");
    assert_eq!(s.transport_error_code(), Some(0x0100 + 47));
}

// ---------------------------------------------------------------------------
// ALPN and suite selection.

/// REQ-MSG-006: a server with ALPN protocols and `require_alpn` refuses a
/// client that offers none (no_application_protocol); without
/// `require_alpn` the handshake completes with no protocol; QUIC always
/// requires ALPN (RFC 9001 §8.1).
#[test]
fn a_client_without_alpn_is_refused_only_where_alpn_is_required() {
    let pki = Pki::new(KeyKind::EcdsaP256, NAME);
    let cc = Arc::new(pki.client_config(Profile::Default));
    assert!(cc.common.alpn.is_empty());
    let mut strict = pki.server_config(Profile::Default).with_alpn(&[b"h2"]);
    strict.common.require_alpn = true;
    let err = connect(cc.clone(), Arc::new(strict), NAME).unwrap_err();
    let e = err.server.unwrap();
    assert_eq!(e.kind(), ErrorKind::NoApplicationProtocol);
    assert_eq!(e.context(), "client offered no ALPN protocol");
    assert_eq!(
        err.client.and_then(|e| e.peer_alert()),
        Some(AlertDescription::NoApplicationProtocol)
    );

    let mut lenient = pki.server_config(Profile::Default).with_alpn(&[b"h2"]);
    lenient.common.require_alpn = false;
    let (c, s) = connect(cc, Arc::new(lenient), NAME).unwrap();
    assert_eq!(s.report().alpn, None);
    assert_eq!(c.report().alpn, None);

    let qc = Arc::new(pki.client_config(Profile::Default).with_alpn(&[b"h3"]));
    let qs = Arc::new(pki.server_config(Profile::Default).with_alpn(&[b"h3"]));
    let mut ch = quic_hello(&qc);
    ch.alpn.clear();
    let mut s = QuicConnection::server(qs, b"s", Version::V1).unwrap();
    let e = s
        .read_handshake(Level::Initial, &quic_client_hello_frame(&ch))
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::NoApplicationProtocol);
    assert_eq!(e.context(), "QUIC requires ALPN (RFC 9001 §8.1)");
    assert_eq!(s.transport_error_code(), Some(0x0100 + 120));
}

/// HLR-001 (no LLR yet; `server::SELECTION_RULE`): with
/// `prefer_server_order` the server's first suite the client offers wins;
/// without it, the client's first suite the server supports wins.
#[test]
fn suite_selection_follows_the_configured_preference() {
    let pki = Pki::new(KeyKind::EcdsaP256, NAME);
    let base = pki.server_config(Profile::Default);
    let ours = base.common.suites.clone();
    assert!(ours.len() >= 2);
    let mut cc = pki.client_config(Profile::Default);
    cc.common.suites = ours.iter().rev().copied().collect();
    let theirs = cc.common.suites.clone();
    assert_ne!(ours[0], theirs[0]);
    let cc = Arc::new(cc);
    for (prefer_server, want) in [(true, ours[0]), (false, theirs[0])] {
        let mut sc = base.clone();
        sc.prefer_server_order = prefer_server;
        let (c, s) = connect(cc.clone(), Arc::new(sc), NAME).unwrap();
        assert_eq!(
            s.report().suite,
            Some(want),
            "prefer_server_order {prefer_server}"
        );
        assert_eq!(c.suite(), Some(want));
    }
}

// ---------------------------------------------------------------------------
// HelloRetryRequest.

/// REQ-MSG-005: the second ClientHello keeps the first's random, session ID
/// and suites, and carries exactly one share, for the requested group.
#[test]
fn a_second_client_hello_keeps_its_fields_and_carries_only_the_requested_share() {
    let pki = Pki::new(KeyKind::EcdsaP256, NAME);
    let mut cc = pki.client_config(Profile::Default);
    cc.common.groups = vec![NamedGroup::X25519, NamedGroup::Secp384r1];
    cc.initial_key_shares = 1;
    let cc = Arc::new(cc);
    let mut sc = pki.server_config(Profile::Default);
    sc.common.groups = vec![NamedGroup::Secp384r1];
    let sc = Arc::new(sc);
    let exchange = || {
        let mut client = Connection::client(cc.clone(), NAME).unwrap();
        let mut server = Connection::server(sc.clone()).unwrap();
        server.read_tls(&client.take_tls()).unwrap();
        let retry = server.take_tls();
        assert!(server_hello(&retry).is_retry());
        client.read_tls(&retry).unwrap();
        let flight = client.take_tls();
        let at = if flight[0] == 20 { 6 } else { 0 };
        let (_, body) = first_message(&flight[at..]);
        (server, ClientHello::decode(&body).unwrap())
    };
    let (mut server, ch) = exchange();
    assert_eq!(ch.key_shares.len(), 1);
    assert_eq!(ch.session_id.len(), 32);
    server
        .read_tls(&record_of(
            HandshakeType::ClientHello,
            &ch.encode().unwrap(),
        ))
        .unwrap();
    type Edit = fn(&mut ClientHello);
    let changed = "second ClientHello changed a field it must not";
    let share = "second ClientHello does not carry exactly the requested share";
    let cases: &[(&str, Edit, &str)] = &[
        ("random", |ch| ch.random[0] ^= 1, changed),
        ("session ID", |ch| ch.session_id[0] ^= 1, changed),
        ("suites", |ch| ch.suites.reverse(), changed),
        (
            "two shares",
            |ch| ch.key_shares.push((NamedGroup::X25519, vec![9; 32])),
            share,
        ),
        (
            "another group's share",
            |ch| ch.key_shares = vec![(NamedGroup::X25519, vec![9; 32])],
            share,
        ),
    ];
    for (name, edit, want) in cases {
        let (mut server, mut ch) = exchange();
        let original = ch.clone();
        edit(&mut ch);
        assert_ne!(ch, original, "{name} must change the hello");
        let e = server
            .read_tls(&record_of(
                HandshakeType::ClientHello,
                &ch.encode().unwrap(),
            ))
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::IllegalParameter, "{name}");
        assert_eq!(e.context(), *want, "{name}");
        assert_eq!(server.take_tls(), [21, 3, 3, 0, 2, 2, 47], "{name}");
    }
}

// ---------------------------------------------------------------------------
// External PSKs and tickets.

/// REQ-EPSK-002: an external PSK is used only with its own hash. When no
/// suite with that hash is in common, the PSK is passed over before its
/// binder is checked and the server authenticates with its certificate.
#[test]
fn an_external_psk_without_a_suite_for_its_hash_is_passed_over() {
    let pki = Pki::new(KeyKind::EcdsaP256, NAME);
    let key = [7u8; 48];
    let psk = || ExternalPsk::new(b"k384", &key, HashAlg::Sha384).unwrap();
    let mut cc = pki.client_config(Profile::Default);
    cc.external_psk = Some(psk());
    let cc = Arc::new(cc);
    let mut sc = pki.server_config(Profile::Default);
    sc.external_psks = vec![psk()];
    let sc = Arc::new(sc);
    let ch = hello(&cc, NAME);
    assert_eq!(ch.psk.as_ref().unwrap().identities[0].identity, b"k384");
    // Unchanged, the SHA-384 PSK selects a SHA-384 suite.
    let mut s = Connection::server(sc.clone()).unwrap();
    s.read_tls(&record_of(
        HandshakeType::ClientHello,
        &ch.encode().unwrap(),
    ))
    .unwrap();
    let sh = server_hello(&s.take_tls());
    assert_eq!(sh.selected_psk, Some(0));
    assert_eq!(sh.suite, Some(CipherSuite::TlsAes256GcmSha384));
    // Offering only a SHA-256 suite: the PSK cannot be used, and its (now
    // stale) binder is never examined.
    let mut ch = ch;
    ch.suites = vec![CipherSuite::TlsAes128GcmSha256];
    let mut s = Connection::server(sc).unwrap();
    s.read_tls(&record_of(
        HandshakeType::ClientHello,
        &ch.encode().unwrap(),
    ))
    .unwrap();
    let sh = server_hello(&s.take_tls());
    assert_eq!(sh.selected_psk, None);
    assert_eq!(sh.suite, Some(CipherSuite::TlsAes128GcmSha256));
    assert!(
        s.report().local_signature_scheme.is_some(),
        "authenticated by certificate"
    );
}

/// REQ-PSK-003: a server configured without ticket keys resumes nothing; a
/// client offering a ticket gets a full, certificate-authenticated handshake
/// and no new ticket.
#[test]
fn a_server_without_ticket_keys_ignores_offered_tickets() {
    let pki = Pki::new(KeyKind::EcdsaP256, NAME);
    let cc = Arc::new(pki.client_config(Profile::Default));
    get_ticket(&cc, &Arc::new(pki.server_config(Profile::Default)), NAME);
    let mut plain = pki.server_config(Profile::Default);
    plain.tickets = None;
    let (c, s) = connect(cc, Arc::new(plain), NAME).unwrap();
    assert!(c
        .report()
        .events
        .iter()
        .any(|e| e.id == "event:ticket-offered"));
    for r in [c.report(), s.report()] {
        assert!(!r.resumed, "{}", r.to_json());
        assert!(r.has(Property::ServerAuthenticated));
    }
    assert!(!s
        .report()
        .events
        .iter()
        .any(|e| e.id == "event:ticket-sent"));
}

fn an_hour_ahead() -> u64 {
    now() + 3600
}

fn half_a_minute_ahead() -> u64 {
    now() + 30
}

/// REQ-PSK-003: a ticket is current only from its issue time (with a minute
/// of tolerance for clock steps) until its lifetime ends; one stamped an
/// hour in the server's future is not accepted.
#[test]
fn a_ticket_from_the_future_is_not_accepted() {
    let pki = Pki::new(KeyKind::EcdsaP256, NAME);
    let cases: [(fn() -> u64, bool); 2] = [(an_hour_ahead, false), (half_a_minute_ahead, true)];
    for (clock, resumes) in cases {
        let cc = Arc::new(pki.client_config(Profile::Default));
        let mut issuing = pki.server_config(Profile::Default);
        issuing.common.clock = clock;
        let issuing = Arc::new(issuing);
        get_ticket(&cc, &issuing, NAME);
        let mut later = pki.server_config(Profile::Default);
        later.tickets = issuing.tickets.clone();
        let (_, s) = connect(cc, Arc::new(later), NAME).unwrap();
        assert_eq!(s.report().resumed, resumes, "{}", s.report().to_json());
    }
}

/// REQ-PSK-005: a ticket resumes only under its own hash. A SHA-384 ticket
/// offered to a server that negotiates a SHA-256 suite gives a full
/// handshake.
#[test]
fn a_ticket_resumes_only_under_its_own_hash() {
    let pki = Pki::new(KeyKind::EcdsaP256, NAME);
    let cc = Arc::new(pki.client_config(Profile::Default));
    let mut issuing = pki.server_config(Profile::Default);
    issuing.common.suites = vec![CipherSuite::TlsAes256GcmSha384];
    let issuing = Arc::new(issuing);
    get_ticket(&cc, &issuing, NAME);
    assert_eq!(
        held_ticket(&cc, NAME).suite,
        CipherSuite::TlsAes256GcmSha384
    );
    let mut later = pki.server_config(Profile::Default);
    later.common.suites = vec![CipherSuite::TlsAes128GcmSha256];
    later.tickets = issuing.tickets.clone();
    let (c, s) = connect(cc, Arc::new(later), NAME).unwrap();
    assert!(c
        .report()
        .events
        .iter()
        .any(|e| e.id == "event:ticket-offered"));
    assert!(!s.report().resumed, "{}", s.report().to_json());
    assert!(s.report().has(Property::ServerAuthenticated));
}

// ---------------------------------------------------------------------------
// 0-RTT refusals.

/// REQ-0RTT-001: early data is accepted only on the first PSK identity. A
/// ticket that verifies as the second identity resumes, but the early data
/// is refused.
#[test]
fn early_data_is_refused_on_any_identity_but_the_first() {
    let pki = Pki::new(KeyKind::EcdsaP256, NAME);
    let (cc, sc) = early_configs(&pki);
    let (cc, sc) = (Arc::new(cc), Arc::new(sc));
    get_ticket(&cc, &sc, NAME);
    let t = held_ticket(&cc, NAME);
    let mut c = Connection::client_with_early_data(cc, NAME, REQUEST).unwrap();
    let (_, body) = first_message(&c.take_tls());
    let mut ch = ClientHello::decode(&body).unwrap();
    assert!(ch.early_data);
    let real = ch.psk.take().unwrap();
    // The decoy carries the real ticket's age, so that only the identity's
    // position can be the reason for refusing the early data.
    ch.psk = Some(OfferedPsks {
        identities: vec![
            PskIdentity {
                identity: vec![0xee; 64],
                obfuscated_ticket_age: real.identities[0].obfuscated_ticket_age,
            },
            real.identities[0].clone(),
        ],
        binders: vec![vec![0; 32], real.binders[0].clone()],
    });
    bind(&mut ch, 1, t.psk.as_bytes(), hash_of(t.suite), false);
    let mut s = Connection::server(sc).unwrap();
    s.read_tls(&record_of(
        HandshakeType::ClientHello,
        &ch.encode().unwrap(),
    ))
    .unwrap();
    assert_eq!(server_hello(&s.take_tls()).selected_psk, Some(1));
    assert!(s.report().resumed);
    assert_eq!(s.report().early_data, "early-data:rejected");
}

/// REQ-0RTT-001: a ticket that did not allow early data (max_early_data 0)
/// admits none, even at a server that now accepts 0-RTT.
#[test]
fn a_ticket_issued_without_early_data_admits_none() {
    let pki = Pki::new(KeyKind::EcdsaP256, NAME);
    let (cc, sc) = early_configs(&pki);
    let cc = Arc::new(cc);
    let mut issuing = pki.server_config(Profile::Default);
    issuing.tickets = sc.tickets.clone();
    get_ticket(&cc, &Arc::new(issuing), NAME);
    let t = held_ticket(&cc, NAME);
    assert_eq!(t.max_early_data, 0);
    let mut c = Connection::client_with_early_data(cc, NAME, REQUEST).unwrap();
    let (_, body) = first_message(&c.take_tls());
    let mut ch = ClientHello::decode(&body).unwrap();
    assert!(!ch.early_data, "the client does not send early data on it");
    ch.early_data = true;
    bind(&mut ch, 0, t.psk.as_bytes(), hash_of(t.suite), false);
    let mut s = Connection::server(Arc::new(sc)).unwrap();
    s.read_tls(&record_of(
        HandshakeType::ClientHello,
        &ch.encode().unwrap(),
    ))
    .unwrap();
    assert_eq!(server_hello(&s.take_tls()).selected_psk, Some(0));
    assert!(s.report().resumed);
    assert_eq!(s.report().early_data, "early-data:rejected");
}

/// REQ-0RTT-001: 0-RTT needs the ticket's suite. A server resuming a
/// TLS_AES_128_GCM_SHA256 ticket under ChaCha20-Poly1305 (same hash, so the
/// ticket resumes) refuses the early data, and the client gets it back.
#[test]
fn early_data_needs_the_tickets_suite() {
    let pki = Pki::new(KeyKind::EcdsaP256, NAME);
    let (cc, sc) = early_configs(&pki);
    let cc = Arc::new(cc);
    let mut issuing = sc.clone();
    issuing.common.suites = vec![CipherSuite::TlsAes128GcmSha256];
    get_ticket(&cc, &Arc::new(issuing), NAME);
    let mut later = sc;
    later.common.suites = vec![CipherSuite::TlsChaCha20Poly1305Sha256];
    let (mut c, s) = early_attempt(&cc, &Arc::new(later), NAME);
    assert!(s.report().resumed);
    assert_eq!(
        s.report().suite,
        Some(CipherSuite::TlsChaCha20Poly1305Sha256)
    );
    assert_eq!(s.report().early_data, "early-data:rejected");
    assert_eq!(c.take_rejected_early_data().as_deref(), Some(REQUEST));
}

/// REQ-0RTT-001: 0-RTT needs the ticket's ALPN protocol. A server that
/// negotiates a different protocol on resumption refuses the early data.
#[test]
fn early_data_needs_the_tickets_alpn_protocol() {
    let pki = Pki::new(KeyKind::EcdsaP256, NAME);
    let (cc, sc) = early_configs(&pki);
    let cc = Arc::new(cc.with_alpn(&[b"h2", b"http/1.1"]));
    get_ticket(&cc, &Arc::new(sc.clone().with_alpn(&[b"h2"])), NAME);
    let later = Arc::new(sc.with_alpn(&[b"http/1.1"]));
    let (mut c, s) = early_attempt(&cc, &later, NAME);
    assert!(s.report().resumed);
    assert_eq!(s.report().alpn.as_deref(), Some(&b"http/1.1"[..]));
    assert_eq!(s.report().early_data, "early-data:rejected");
    assert_eq!(c.take_rejected_early_data().as_deref(), Some(REQUEST));
}

/// REQ-0RTT-001, REQ-EPSK-001: a ticket issued in an external-PSK session
/// resumes as PSK-authenticated (never as certificate-authenticated), is
/// reported as a resumption rather than a fresh external-PSK handshake, and
/// never admits early data.
#[test]
fn a_ticket_from_an_external_psk_session_resumes_without_early_data() {
    const GATEWAY: &str = "gateway.local";
    let key = [0x42u8; 32];
    let psk = || ExternalPsk::new(b"sensor-17", &key, HashAlg::Sha256).unwrap();
    let mut sc = ServerConfig::external_psk_only(Profile::Default, vec![psk()]).unwrap();
    sc.tickets = Some(Arc::new(TicketKeys::generate(&mut rng()).unwrap()));
    sc.tickets_per_handshake = 1;
    sc.ticket_lifetime = 3600;
    sc.early_data = Some(EarlyDataPolicy::new(16_384));
    let sc = Arc::new(sc);
    let first = Arc::new(ClientConfig::external_psk(Profile::Default, psk()).unwrap());
    get_ticket(&first, &sc, GATEWAY);
    assert!(held_ticket(&first, GATEWAY).max_early_data > 0);
    // A client that holds only the ticket.
    let pki = Pki::new(KeyKind::EcdsaP256, GATEWAY);
    let mut cc = pki.client_config(Profile::Default);
    cc.tickets = first.tickets.clone();
    cc.early_data = true;
    let (mut c, s) = early_attempt(&Arc::new(cc), &sc, GATEWAY);
    assert_eq!(c.report().early_data, "early-data:rejected");
    assert_eq!(c.take_rejected_early_data().as_deref(), Some(REQUEST));
    let r = s.report();
    assert!(r.resumed, "{}", r.to_json());
    assert_eq!(r.early_data, "early-data:rejected");
    assert!(r.has(Property::PskAuthenticated));
    assert!(!r.has(Property::ServerAuthenticated));
    assert!(r.events.iter().any(|e| e.id == "event:session-resumed"));
    assert!(!r
        .events
        .iter()
        .any(|e| e.id == "event:external-psk-accepted"));
    // As for every resumed session, the server reports its configured
    // client-verification method; only a fresh external-PSK handshake
    // reports verification:external-psk.
    assert_eq!(r.verification, "verification:none-requested");
}

/// REQ-0RTT-005: a QUIC server accepts 0-RTT only on a ticket carrying
/// max_early_data 0xffffffff. A TCP ticket offered with early_data over QUIC
/// resumes, but no 0-RTT key is installed.
#[test]
fn quic_refuses_early_data_on_a_tcp_ticket() {
    let pki = Pki::new(KeyKind::EcdsaP256, NAME);
    let (cc, sc) = early_configs(&pki);
    let cc = Arc::new(cc.with_alpn(&[b"h3"]));
    let sc = sc.with_alpn(&[b"h3"]);
    get_ticket(&cc, &Arc::new(sc.clone()), NAME);
    let t = held_ticket(&cc, NAME);
    assert_eq!(t.max_early_data, 16_384);
    let mut quiet = (*cc).clone();
    quiet.tickets = None;
    let mut ch = quic_hello(&Arc::new(quiet));
    ch.psk_modes = vec![1];
    ch.early_data = true;
    ch.psk = Some(OfferedPsks {
        identities: vec![PskIdentity {
            identity: t.ticket.clone(),
            obfuscated_ticket_age: t.obfuscated_age(now()),
        }],
        binders: vec![vec![0; 32]],
    });
    bind(&mut ch, 0, t.psk.as_bytes(), hash_of(t.suite), false);
    // Empty transport parameters, equal to the TCP ticket's, so that only
    // the ticket's max_early_data can refuse the 0-RTT.
    let mut s = QuicConnection::server(Arc::new(sc), b"", Version::V1).unwrap();
    s.read_handshake(Level::Initial, &quic_client_hello_frame(&ch))
        .unwrap();
    while let Ok(Some(k)) = s.next_key_change() {
        assert_ne!(k.level, Level::Early, "a 0-RTT key was installed");
    }
    assert!(s.report().resumed);
    assert_eq!(s.report().early_data, "early-data:rejected");
}

// ---------------------------------------------------------------------------
// Encrypted Client Hello.

const REAL: &str = "secret-backend.test";
const PUBLIC: &str = "public.test";

fn ech_keys(id: u8) -> Arc<EchServer> {
    Arc::new(EchServer::generate(id, PUBLIC, 64, &mut rng()).unwrap())
}

fn ech_server(pki: &Pki, keys: Option<Arc<EchServer>>) -> ServerConfig {
    let mut sc = ServerConfig::new(Profile::Default, pki.identity_for(&[REAL, PUBLIC])).unwrap();
    sc.ech = keys;
    sc
}

/// An outer hello built on `base`, carrying `inner` sealed to the first
/// configuration in `list` (RFC 9849 §6.1), optionally with another
/// config_id or enc.
fn seal_outer(
    base: &ClientHello,
    inner: &ClientHello,
    list: &[u8],
    config_id: Option<u8>,
    enc: Option<Vec<u8>>,
) -> ClientHello {
    let cfg = &ech::parse_config_list(list).unwrap()[0];
    let suite = cfg.usable_suite().unwrap();
    let mut encoding = inner.clone();
    encoding.session_id.clear();
    let encoded = encoding.encode().unwrap();
    let (fresh, mut ctx) =
        hpke::setup_sender(&cfg.public_key, &cfg.hpke_info(), suite.1, &mut rng()).unwrap();
    let mut outer = base.clone();
    outer.server_name = Some(PUBLIC.into());
    outer.ech = Some(EchHello::Outer {
        suite,
        config_id: config_id.unwrap_or(cfg.config_id),
        enc: enc.unwrap_or(fresh),
        payload: vec![0; encoded.len() + 16],
    });
    let aad = outer.encode().unwrap();
    let sealed = ctx.seal(&aad, &encoded).unwrap();
    if let Some(EchHello::Outer { payload, .. }) = outer.ech.as_mut() {
        *payload = sealed;
    }
    outer
}

fn with_inner_marker(ch: &ClientHello) -> ClientHello {
    let mut inner = ch.clone();
    inner.ech = Some(EchHello::Inner);
    inner
}

/// REQ-ECH-003: a server with no ECH keys continues on the outer hello and
/// reports ECH as rejected; it has no retry configurations to give, so the
/// client, having authenticated the public name, aborts with none.
#[test]
fn a_server_without_ech_keys_rejects_ech_and_continues_on_the_outer_hello() {
    let pki = Pki::new(KeyKind::EcdsaP256, REAL);
    let mut cc = pki.client_config(Profile::Default);
    cc.ech_configs = Some(ech_keys(3).config_list().to_vec());
    let mut c = Connection::client(Arc::new(cc), REAL).unwrap();
    let mut s = Connection::server(Arc::new(ech_server(&pki, None))).unwrap();
    s.read_tls(&c.take_tls()).unwrap();
    assert_eq!(s.report().ech, "ech:rejected");
    assert_eq!(s.report().server_name.as_deref(), Some(PUBLIC));
    assert!(!s.report().has(Property::EncryptedClientHello));
    let e = c.read_tls(&s.take_tls()).unwrap_err();
    assert_eq!(e.kind(), ErrorKind::EchRejected);
    assert_eq!(c.ech_retry_configs(), None);
}

/// REQ-ECH-003: an ECH offer the server cannot open -- an unknown
/// config_id, or an enc whose X25519 output is all zero (RFC 9180 §7.1.4)
/// -- is rejected, not fatal: the server continues on the outer hello.
#[test]
fn an_ech_offer_the_server_cannot_open_is_rejected_not_fatal() {
    let pki = Pki::new(KeyKind::EcdsaP256, REAL);
    let keys = ech_keys(3);
    let sc = Arc::new(ech_server(&pki, Some(keys.clone())));
    let base = hello(&Arc::new(pki.client_config(Profile::Default)), REAL);
    let inner = with_inner_marker(&base);
    let list = keys.config_list();
    let cases = [
        (
            "well formed",
            seal_outer(&base, &inner, list, None, None),
            "ech:accepted",
        ),
        (
            "unknown config_id",
            seal_outer(&base, &inner, list, Some(4), None),
            "ech:rejected",
        ),
        (
            "all-zero enc",
            seal_outer(&base, &inner, list, None, Some(vec![0; 32])),
            "ech:rejected",
        ),
    ];
    for (name, outer, want) in cases {
        let mut s = Connection::server(sc.clone()).unwrap();
        s.read_tls(&record_of(
            HandshakeType::ClientHello,
            &outer.encode().unwrap(),
        ))
        .unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(s.report().ech, want, "{name}");
        let sni = if want == "ech:accepted" { REAL } else { PUBLIC };
        assert_eq!(s.report().server_name.as_deref(), Some(sni), "{name}");
    }
}

/// REQ-ECH-005: a decrypted ClientHelloInner must carry the inner ECH
/// marker (RFC 9849 §7.1); without it the hello is illegal_parameter.
#[test]
fn a_client_hello_inner_without_the_inner_marker_is_illegal() {
    let pki = Pki::new(KeyKind::EcdsaP256, REAL);
    let keys = ech_keys(3);
    let base = hello(&Arc::new(pki.client_config(Profile::Default)), REAL);
    assert_eq!(base.ech, None);
    let outer = seal_outer(&base, &base, keys.config_list(), None, None);
    let mut s = Connection::server(Arc::new(ech_server(&pki, Some(keys)))).unwrap();
    let e = s
        .read_tls(&record_of(
            HandshakeType::ClientHello,
            &outer.encode().unwrap(),
        ))
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::IllegalParameter);
    assert_eq!(e.context(), "ClientHelloInner lacks the inner ECH marker");
    assert_eq!(s.take_tls(), [21, 3, 3, 0, 2, 2, 47]);
}

/// REQ-ECH-007: ECH rejected in the first hello stays rejected after a
/// HelloRetryRequest. A second hello carrying a freshly sealed, valid inner
/// hello is not opened; the server continues on the outer hello.
#[test]
fn ech_rejected_before_a_retry_stays_rejected() {
    let pki = Pki::new(KeyKind::EcdsaP256, REAL);
    let keys = ech_keys(3);
    let mut sc = ech_server(&pki, Some(keys.clone()));
    sc.common.groups = vec![NamedGroup::Secp384r1];
    let mut cc = pki.client_config(Profile::Default);
    cc.common.groups = vec![NamedGroup::X25519, NamedGroup::Secp384r1];
    cc.initial_key_shares = 1;
    let base = hello(&Arc::new(cc), REAL);
    let list = keys.config_list();
    let first = seal_outer(&base, &with_inner_marker(&base), list, Some(4), None);
    let mut s = Connection::server(Arc::new(sc)).unwrap();
    s.read_tls(&record_of(
        HandshakeType::ClientHello,
        &first.encode().unwrap(),
    ))
    .unwrap();
    assert_eq!(s.report().ech, "ech:rejected");
    assert!(server_hello(&s.take_tls()).is_retry());
    let mut again = base.clone();
    let share = KeyShare::generate(NamedGroup::Secp384r1, &mut rng()).unwrap();
    again.key_shares = vec![(NamedGroup::Secp384r1, share.public().to_vec())];
    let second = seal_outer(&again, &with_inner_marker(&again), list, None, None);
    s.read_tls(&record_of(
        HandshakeType::ClientHello,
        &second.encode().unwrap(),
    ))
    .unwrap();
    let r = s.report();
    assert!(r.hello_retry);
    assert_eq!(r.ech, "ech:rejected");
    assert_eq!(r.server_name.as_deref(), Some(PUBLIC));
    assert!(!r.has(Property::EncryptedClientHello));
}
