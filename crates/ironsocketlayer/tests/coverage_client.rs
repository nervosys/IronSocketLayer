//! Client and connection behaviour that the rest of the suite left
//! unexercised: refusals of hostile or unusual server flights, the paths a
//! negotiation can take besides the common one, and the connection API's
//! edge cases.
//!
//! Hostile flights are made by editing a real server's messages where they
//! are still unprotected: the ServerHello and HelloRetryRequest over TCP, and
//! every handshake message over QUIC, where the TLS layer hands CRYPTO data
//! over in the clear and packet protection belongs to the QUIC stack.

mod common;

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use common::*;
use ironsocketlayer::config::{
    ClientConfig, EarlyDataPolicy, ExternalPsk, PeerVerification, Profile, ServerConfig,
};
use ironsocketlayer::crypto::sign::KeyKind;
use ironsocketlayer::crypto::HashAlg;
use ironsocketlayer::ech::EchServer;
use ironsocketlayer::enums::{
    AlertDescription, CipherSuite, ContentType, HandshakeType, NamedGroup, SignatureScheme,
};
use ironsocketlayer::msgs::{
    self, CertificateVerify, ClientHello, EncryptedExtensions, ServerHello,
};
use ironsocketlayer::quic::{QuicConnection, Version};
use ironsocketlayer::record;
use ironsocketlayer::report::{HandshakeState, Property};
use ironsocketlayer::resumption::{MemoryTicketStore, TicketStore};
use ironsocketlayer::{Connection, ErrorKind, Level};

const NAME: &str = "server.test";

// ---------------------------------------------------------------------------
// Wire helpers.

/// Every record in a flight, as (content type, body).
fn records(flight: &[u8]) -> Vec<(u8, Vec<u8>)> {
    let mut out = Vec::new();
    let mut at = 0;
    while at + 5 <= flight.len() {
        let len = u16::from_be_bytes([flight[at + 3], flight[at + 4]]) as usize;
        out.push((flight[at], flight[at + 5..at + 5 + len].to_vec()));
        at += 5 + len;
    }
    out
}

/// Every handshake message in a byte string, each with its four-byte header.
fn messages(bytes: &[u8]) -> Vec<(HandshakeType, Vec<u8>)> {
    let mut out = Vec::new();
    let mut at = 0;
    while at + 4 <= bytes.len() {
        let n = u32::from_be_bytes([0, bytes[at + 1], bytes[at + 2], bytes[at + 3]]) as usize;
        out.push((
            HandshakeType::from_wire(bytes[at]),
            bytes[at..at + 4 + n].to_vec(),
        ));
        at += 4 + n;
    }
    out
}

/// The body of the first handshake message in a flight's plaintext records.
fn first_handshake_body(flight: &[u8]) -> (HandshakeType, Vec<u8>) {
    let (_, body) = records(flight)
        .into_iter()
        .find(|(ty, _)| *ty == 22)
        .expect("a handshake record");
    let (ty, msg) = messages(&body).remove(0);
    (ty, msg[4..].to_vec())
}

/// A plaintext handshake record carrying one message.
fn record_of(ty: HandshakeType, body: &[u8]) -> Vec<u8> {
    let msg = msgs::frame(ty, body).unwrap();
    let mut out = Vec::new();
    record::write_plaintext(ContentType::Handshake, &msg, &mut out);
    out
}

/// Append one extension to an extension block that starts at `at`.
fn append_extension(body: &[u8], at: usize, ty: u16, data: &[u8]) -> Vec<u8> {
    let old = u16::from_be_bytes([body[at], body[at + 1]]) as usize;
    let mut out = body[..at].to_vec();
    out.extend_from_slice(&((old + 4 + data.len()) as u16).to_be_bytes());
    out.extend_from_slice(&body[at + 2..]);
    out.extend_from_slice(&ty.to_be_bytes());
    out.extend_from_slice(&(data.len() as u16).to_be_bytes());
    out.extend_from_slice(data);
    out
}

fn has_event(c: &Connection, id: &str) -> bool {
    c.report().events.iter().any(|e| e.id == id)
}

fn refused(r: ironsocketlayer::Result<()>, kind: ErrorKind, msg: &str) {
    let e = r.expect_err(msg);
    assert_eq!(e.kind(), kind, "{e}");
    assert!(e.to_string().contains(msg), "wanted {msg:?}, got {e}");
}

/// A client that has sent its hello, and the ServerHello a real server
/// answered with.
fn hello_exchange(
    cc: &Arc<ClientConfig>,
    sc: &Arc<ServerConfig>,
) -> (Connection, Connection, ServerHello) {
    let mut c = Connection::client(cc.clone(), NAME).unwrap();
    let mut s = Connection::server(sc.clone()).unwrap();
    s.read_tls(&c.take_tls()).unwrap();
    let (ty, body) = first_handshake_body(&s.take_tls());
    assert_eq!(ty, HandshakeType::ServerHello);
    (c, s, ServerHello::decode(&body).unwrap())
}

/// Store a ticket for `NAME` from a full handshake.
fn get_ticket(cc: &Arc<ClientConfig>, sc: &Arc<ServerConfig>) {
    let (mut c, mut s) = connect(cc.clone(), sc.clone(), NAME).unwrap();
    c.read_tls(&s.take_tls()).unwrap();
    assert!(c.report().tickets_received >= 1);
}

/// Pump a client made with early data and a server until both stop.
fn drive(c: &mut Connection, s: &mut Connection) {
    for _ in 0..6 {
        let _ = s.read_tls(&c.take_tls());
        let _ = c.read_tls(&s.take_tls());
    }
    let _ = s.read_tls(&c.take_tls());
}

const REQUEST: &[u8] = b"GET /status HTTP/1.1\r\nHost: x\r\n\r\n";

// ---------------------------------------------------------------------------
// ServerHello and HelloRetryRequest.

/// REQ-MSG-006: a ServerHello answering with an extension the client did not
/// offer is unsupported_extension (RFC 8446 section 4.2).
#[test]
fn a_server_hello_with_an_unoffered_extension_is_refused() {
    let pki = Pki::new(KeyKind::EcdsaP256, NAME);
    let cc = Arc::new(pki.client_config(Profile::Default));
    let sc = Arc::new(pki.server_config(Profile::Default));
    let (mut c, _, sh) = hello_exchange(&cc, &sc);
    let body = sh.encode().unwrap();
    // legacy_version, random, session_id, suite, compression, extensions.
    let at = 2 + 32 + 1 + sh.session_id.len() + 2 + 1;
    let edited = append_extension(&body, at, 0xfafa, b"unasked");
    refused(
        c.read_tls(&record_of(HandshakeType::ServerHello, &edited)),
        ErrorKind::UnsupportedExtension,
        "ServerHello carries an extension not offered",
    );
    assert_eq!(c.error().unwrap().id(), "error:unsupported-extension");
    assert_eq!(
        c.report().alert_sent,
        Some(AlertDescription::UnsupportedExtension)
    );
}

/// REQ-MSG-005: a HelloRetryRequest carrying only a cookie (RFC 8446
/// section 4.2.2) is answered with that cookie and the same key shares.
#[test]
fn a_cookie_only_retry_is_answered_with_the_cookie_and_the_same_shares() {
    let pki = Pki::new(KeyKind::EcdsaP256, NAME);
    let mut cc = pki.client_config(Profile::Default);
    cc.common.groups = vec![NamedGroup::X25519, NamedGroup::Secp384r1];
    cc.initial_key_shares = 1;
    let cc = Arc::new(cc);
    let mut sc = pki.server_config(Profile::Default);
    sc.common.groups = vec![NamedGroup::Secp384r1];
    let sc = Arc::new(sc);

    let mut c = Connection::client(cc, NAME).unwrap();
    let first = c.take_tls();
    let (_, ch1) = first_handshake_body(&first);
    let ch1 = ClientHello::decode(&ch1).unwrap();
    let mut s = Connection::server(sc).unwrap();
    s.read_tls(&first).unwrap();
    let (_, hrr) = first_handshake_body(&s.take_tls());
    let mut hrr = ServerHello::decode(&hrr).unwrap();
    assert!(hrr.is_retry());
    hrr.hrr_group = None;
    hrr.cookie = Some(b"opaque server state".to_vec());
    c.read_tls(&record_of(
        HandshakeType::ServerHello,
        &hrr.encode().unwrap(),
    ))
    .unwrap();

    let (_, ch2) = first_handshake_body(&c.take_tls());
    let ch2 = ClientHello::decode(&ch2).unwrap();
    assert_eq!(ch2.cookie.as_deref(), Some(&b"opaque server state"[..]));
    assert_eq!(ch2.key_shares, ch1.key_shares, "the shares were kept");
    assert_eq!(ch2.random, ch1.random);
    assert!(c.report().hello_retry);
    assert!(c
        .report()
        .events
        .iter()
        .any(|e| e.id == "event:hello-retry" && e.detail == "cookie"));
}

/// REQ-PSK-005: a retry choosing a suite whose hash differs from the
/// ticket's withdraws the ticket from the second hello; the session is then
/// a full, certificate-authenticated handshake.
#[test]
fn a_retry_to_another_hash_withdraws_the_ticket() {
    let pki = Pki::new(KeyKind::EcdsaP256, NAME);
    let mut first = pki.client_config(Profile::Default);
    first.common.suites = vec![CipherSuite::TlsAes128GcmSha256];
    let first = Arc::new(first);
    get_ticket(&first, &Arc::new(pki.server_config(Profile::Default)));

    let mut cc = pki.client_config(Profile::Default);
    cc.tickets = first.tickets.clone();
    cc.common.groups = vec![NamedGroup::X25519, NamedGroup::Secp384r1];
    cc.initial_key_shares = 1;
    let mut sc = pki.server_config(Profile::Default);
    sc.common.suites = vec![CipherSuite::TlsAes256GcmSha384];
    sc.common.groups = vec![NamedGroup::Secp384r1];
    let (cc, sc) = (Arc::new(cc), Arc::new(sc));

    let mut c = Connection::client(cc, NAME).unwrap();
    let hello = c.take_tls();
    let (_, ch1) = first_handshake_body(&hello);
    assert!(ClientHello::decode(&ch1).unwrap().psk.is_some());
    let mut s = Connection::server(sc).unwrap();
    s.read_tls(&hello).unwrap();
    c.read_tls(&s.take_tls()).unwrap();
    let second = c.take_tls();
    let (_, ch2) = first_handshake_body(&second);
    assert!(
        ClientHello::decode(&ch2).unwrap().psk.is_none(),
        "the second hello still offers the SHA-256 ticket"
    );
    s.read_tls(&second).unwrap();
    for _ in 0..3 {
        let _ = c.read_tls(&s.take_tls());
        let _ = s.read_tls(&c.take_tls());
    }
    assert_eq!(c.state(), HandshakeState::Connected, "{:?}", c.error());
    assert!(c.report().hello_retry);
    assert!(!c.report().resumed);
    assert_eq!(c.suite(), Some(CipherSuite::TlsAes256GcmSha384));
    assert!(c.report().has(Property::ServerAuthenticated));
}

/// REQ-PSK-005: a ServerHello resuming a ticket under a suite of another
/// hash is illegal_parameter.
#[test]
fn a_ticket_resumed_under_another_hash_is_refused() {
    let pki = Pki::new(KeyKind::EcdsaP256, NAME);
    let cc = Arc::new(pki.client_config(Profile::Default));
    let sc = Arc::new(pki.server_config(Profile::Default));
    get_ticket(&cc, &sc);
    let (mut c, _, mut sh) = hello_exchange(&cc, &sc);
    assert_eq!(sh.selected_psk, Some(0), "the server resumed");
    assert_eq!(sh.suite, Some(CipherSuite::TlsAes128GcmSha256));
    sh.suite = Some(CipherSuite::TlsAes256GcmSha384);
    refused(
        c.read_tls(&record_of(
            HandshakeType::ServerHello,
            &sh.encode().unwrap(),
        )),
        ErrorKind::IllegalParameter,
        "resumed with a suite of another hash",
    );
    assert_eq!(
        c.report().alert_sent,
        Some(AlertDescription::IllegalParameter)
    );
}

/// REQ-EPSK-001: a ServerHello accepting the external PSK under a suite of
/// another hash is illegal_parameter.
#[test]
fn an_external_psk_accepted_under_another_hash_is_refused() {
    let key = [0x42u8; 32];
    let psk = || ExternalPsk::new(b"sensor-17", &key, HashAlg::Sha256).unwrap();
    let cc = Arc::new(ClientConfig::external_psk(Profile::Default, psk()).unwrap());
    let sc = Arc::new(ServerConfig::external_psk_only(Profile::Default, vec![psk()]).unwrap());
    let (mut c, _, mut sh) = hello_exchange(&cc, &sc);
    assert_eq!(sh.selected_psk, Some(0), "the server accepted the PSK");
    assert_eq!(sh.suite, Some(CipherSuite::TlsAes128GcmSha256));
    sh.suite = Some(CipherSuite::TlsAes256GcmSha384);
    refused(
        c.read_tls(&record_of(
            HandshakeType::ServerHello,
            &sh.encode().unwrap(),
        )),
        ErrorKind::IllegalParameter,
        "suite hash differs from the external PSK's",
    );
}

/// External-PSK client and a certificate server that only speaks SHA-384
/// suites and needs a retry for its group.
fn psk_client_and_sha384_server(with_roots: bool) -> (Arc<ClientConfig>, Arc<ServerConfig>) {
    let pki = Pki::new(KeyKind::EcdsaP256, NAME);
    let psk = ExternalPsk::new(b"sensor-17", &[0x42; 32], HashAlg::Sha256).unwrap();
    let mut cc = if with_roots {
        pki.client_config(Profile::Default)
    } else {
        ClientConfig::external_psk(Profile::Default, psk.clone()).unwrap()
    };
    cc.external_psk = Some(psk);
    cc.common.groups = vec![NamedGroup::X25519, NamedGroup::Secp384r1];
    cc.initial_key_shares = 1;
    let mut sc = pki.server_config(Profile::Default);
    sc.common.suites = vec![CipherSuite::TlsAes256GcmSha384];
    sc.common.groups = vec![NamedGroup::Secp384r1];
    (Arc::new(cc), Arc::new(sc))
}

/// REQ-EPSK-001: a retry choosing a suite the external PSK's hash cannot
/// use withdraws the PSK (RFC 8446 section 4.1.2); with trust anchors the
/// handshake goes on authenticated by certificate.
#[test]
fn a_retry_to_another_hash_withdraws_the_external_psk() {
    let (cc, sc) = psk_client_and_sha384_server(true);
    let (mut c, mut s) = connect(cc, sc, NAME).unwrap();
    assert!(c.report().hello_retry);
    assert_eq!(c.suite(), Some(CipherSuite::TlsAes256GcmSha384));
    assert_eq!(c.report().verification, "verification:pkix");
    assert!(c.report().has(Property::ServerAuthenticated));
    assert!(!c.report().has(Property::PskAuthenticated));
    exchange(&mut c, &mut s);
}

/// REQ-EPSK-004: without trust anchors, the withdrawn PSK
/// leaves nothing to authenticate the server, and the client refuses.
#[test]
fn a_retry_that_rules_out_the_only_external_psk_is_refused() {
    let (cc, sc) = psk_client_and_sha384_server(false);
    let err = connect(cc, sc, NAME).unwrap_err();
    let e = err.client.expect("the client refused");
    assert_eq!(e.kind(), ErrorKind::HandshakeFailure, "{e}");
    assert!(e.to_string().contains("external PSK"), "{e}");
}

/// REQ-EPSK-001, REQ-EPSK-002: a retry to a suite of the external PSK's own
/// hash keeps the PSK, whose binder is recomputed over the new transcript;
/// the server accepts it and no certificate is involved.
#[test]
fn a_retry_to_the_same_hash_keeps_the_external_psk() {
    let psk = || ExternalPsk::new(b"sensor-17", &[0x42; 32], HashAlg::Sha256).unwrap();
    let mut cc = ClientConfig::external_psk(Profile::Default, psk()).unwrap();
    cc.common.groups = vec![NamedGroup::X25519, NamedGroup::Secp384r1];
    cc.initial_key_shares = 1;
    let mut sc = ServerConfig::external_psk_only(Profile::Default, vec![psk()]).unwrap();
    sc.common.groups = vec![NamedGroup::Secp384r1];
    let (mut c, mut s) = connect(Arc::new(cc), Arc::new(sc), NAME).unwrap();
    assert!(c.report().hello_retry);
    for r in [c.report(), s.report()] {
        assert!(r.has(Property::PskAuthenticated), "{}", r.to_json());
        assert_eq!(r.verification, "verification:external-psk");
    }
    exchange(&mut c, &mut s);
}

// ---------------------------------------------------------------------------
// ECH.

const REAL: &str = "secret-backend.test";
const PUBLIC: &str = "public.test";

fn ech_server() -> (Pki, Arc<EchServer>, ServerConfig) {
    let pki = Pki::new(KeyKind::EcdsaP256, REAL);
    let ech = Arc::new(
        EchServer::generate(3, PUBLIC, 64, &mut ic_drbg::Rng::from_os().unwrap()).unwrap(),
    );
    let mut sc = ServerConfig::new(Profile::Default, pki.identity_for(&[REAL, PUBLIC])).unwrap();
    sc.ech = Some(ech.clone());
    (pki, ech, sc)
}

/// REQ-ECH-001, REQ-PSK-001: with no ticket store, the inner hello offers no
/// psk_key_exchange_modes, so the server issues no ticket.
#[test]
fn ech_without_a_ticket_store_asks_for_no_tickets() {
    let (pki, ech, sc) = ech_server();
    let sc = Arc::new(sc);
    for store in [false, true] {
        let mut cc = pki.client_config(Profile::Default);
        cc.ech_configs = Some(ech.config_list().to_vec());
        if !store {
            cc.tickets = None;
        }
        let (mut c, mut s) = connect(Arc::new(cc), sc.clone(), REAL).unwrap();
        c.read_tls(&s.take_tls()).unwrap();
        assert!(c.report().has(Property::EncryptedClientHello));
        assert_eq!(c.report().ech, "ech:accepted");
        assert_eq!(
            c.report().tickets_received > 0,
            store,
            "tickets with a store: {store}"
        );
    }
}

/// REQ-ECH-003: a server that cannot decrypt the inner hello and asks for a
/// retry is answered with the outer hello again; the client then
/// authenticates the public name, refuses with ech_required and exposes the
/// retry configurations.
#[test]
fn ech_rejected_at_a_retry_still_aborts_with_retry_configs() {
    let (pki, ech, mut sc) = ech_server();
    sc.common.groups = vec![NamedGroup::Secp384r1];
    let stale = EchServer::generate(3, PUBLIC, 64, &mut ic_drbg::Rng::from_os().unwrap()).unwrap();
    let mut cc = pki.client_config(Profile::Default);
    cc.ech_configs = Some(stale.config_list().to_vec());
    cc.common.groups = vec![NamedGroup::X25519, NamedGroup::Secp384r1];
    cc.initial_key_shares = 1;
    let mut c = Connection::client(Arc::new(cc), REAL).unwrap();
    let mut s = Connection::server(Arc::new(sc)).unwrap();
    drive(&mut c, &mut s);
    assert!(c.report().hello_retry);
    let e = c.error().expect("the client refused");
    assert_eq!(e.kind(), ErrorKind::EchRejected, "{e}");
    assert_eq!(c.report().ech, "ech:rejected");
    assert_eq!(c.report().server_name.as_deref(), Some(PUBLIC));
    assert_eq!(c.ech_retry_configs(), Some(ech.config_list()));
    assert_eq!(
        s.error().and_then(|e| e.peer_alert()),
        Some(AlertDescription::EchRequired)
    );
}

// ---------------------------------------------------------------------------
// 0-RTT.

fn early_configs(pki: &Pki) -> (ClientConfig, ServerConfig) {
    let mut cc = pki.client_config(Profile::Default);
    cc.early_data = true;
    let mut sc = pki.server_config(Profile::Default);
    sc.early_data = Some(EarlyDataPolicy::new(16_384));
    (cc, sc)
}

/// REQ-0RTT-001: a ticket from a session that used one ALPN protocol sends
/// no early data on a connection that does not offer it; the data comes back.
#[test]
fn no_early_data_when_the_tickets_alpn_is_not_offered() {
    let pki = Pki::new(KeyKind::EcdsaP256, NAME);
    let (cc, sc) = early_configs(&pki);
    let sc = Arc::new(sc.with_alpn(&[b"h2", b"http/1.1"]));
    let first = Arc::new(cc.clone().with_alpn(&[b"h2"]));
    get_ticket(&first, &sc);
    let mut second = cc.with_alpn(&[b"http/1.1"]);
    second.tickets = first.tickets.clone();
    let mut c = Connection::client_with_early_data(Arc::new(second), NAME, REQUEST).unwrap();
    assert_eq!(c.report().early_data, "early-data:not-offered");
    assert!(
        has_event(&c, "event:ticket-offered"),
        "the ticket is still used"
    );
    let mut s = Connection::server(sc).unwrap();
    drive(&mut c, &mut s);
    assert_eq!(c.state(), HandshakeState::Connected, "{:?}", c.error());
    assert!(c.report().resumed);
    assert_eq!(c.alpn(), Some(&b"http/1.1"[..]));
    assert_eq!(c.take_rejected_early_data().as_deref(), Some(REQUEST));
}

/// REQ-0RTT-004: early data sent to a server that does not resume the
/// session is skipped by the server and returned to the caller.
#[test]
fn early_data_to_a_server_that_does_not_resume_is_returned() {
    let pki = Pki::new(KeyKind::EcdsaP256, NAME);
    let (cc, sc) = early_configs(&pki);
    let cc = Arc::new(cc);
    get_ticket(&cc, &Arc::new(sc.clone()));
    // Another server: its ticket keys cannot open the ticket.
    let (_, other) = early_configs(&pki);
    let mut c = Connection::client_with_early_data(cc, NAME, REQUEST).unwrap();
    assert_eq!(c.report().early_data, "early-data:offered");
    let mut s = Connection::server(Arc::new(other)).unwrap();
    drive(&mut c, &mut s);
    assert_eq!(c.state(), HandshakeState::Connected, "{:?}", c.error());
    assert_eq!(s.state(), HandshakeState::Connected, "{:?}", s.error());
    assert!(!c.report().resumed);
    assert!(c.report().has(Property::ServerAuthenticated));
    assert_eq!(c.report().early_data, "early-data:rejected");
    assert_eq!(s.available(), 0);
    assert_eq!(c.take_rejected_early_data().as_deref(), Some(REQUEST));
    exchange(&mut c, &mut s);
}

/// REQ-0RTT-001: a session resumed under a different suite (same hash) does
/// not take the early data, which was sealed under the ticket's suite; the
/// client switches to the handshake key and gets its data back.
#[test]
fn early_data_resumed_under_another_suite_is_returned() {
    let pki = Pki::new(KeyKind::EcdsaP256, NAME);
    let (cc, sc) = early_configs(&pki);
    let sc = Arc::new(sc);
    let mut first = cc.clone();
    first.common.suites = vec![CipherSuite::TlsChaCha20Poly1305Sha256];
    let first = Arc::new(first);
    get_ticket(&first, &sc);
    let mut second = cc;
    second.tickets = first.tickets.clone();
    second.common.suites = vec![
        CipherSuite::TlsAes128GcmSha256,
        CipherSuite::TlsChaCha20Poly1305Sha256,
    ];
    let mut c = Connection::client_with_early_data(Arc::new(second), NAME, REQUEST).unwrap();
    assert_eq!(c.report().early_data, "early-data:offered");
    let mut s = Connection::server(sc).unwrap();
    drive(&mut c, &mut s);
    assert_eq!(c.state(), HandshakeState::Connected, "{:?}", c.error());
    assert!(c.report().resumed);
    assert_eq!(c.suite(), Some(CipherSuite::TlsAes128GcmSha256));
    assert_eq!(c.report().early_data, "early-data:rejected");
    assert_eq!(c.take_rejected_early_data().as_deref(), Some(REQUEST));
    exchange(&mut c, &mut s);
}

// ---------------------------------------------------------------------------
// Tickets.

/// REQ-PSK-005: a ticket whose hash no offered suite uses is not offered;
/// the connection is a full handshake.
#[test]
fn a_ticket_no_offered_suite_can_use_is_not_offered() {
    let pki = Pki::new(KeyKind::EcdsaP256, NAME);
    let sc = Arc::new(pki.server_config(Profile::Default));
    let mut first = pki.client_config(Profile::Default);
    first.common.suites = vec![CipherSuite::TlsAes256GcmSha384];
    let first = Arc::new(first);
    get_ticket(&first, &sc);
    let mut cc = pki.client_config(Profile::Default);
    cc.tickets = first.tickets.clone();
    cc.common.suites = vec![
        CipherSuite::TlsAes128GcmSha256,
        CipherSuite::TlsChaCha20Poly1305Sha256,
    ];
    let mut c = Connection::client(Arc::new(cc.clone()), NAME).unwrap();
    let (_, ch) = first_handshake_body(&c.take_tls());
    assert!(ClientHello::decode(&ch).unwrap().psk.is_none());
    assert!(!has_event(&c, "event:ticket-offered"));
    // The same store, with the SHA-384 suite offered too, would use it.
    let (c, _) = connect(Arc::new(cc), sc, NAME).unwrap();
    assert!(!c.report().resumed);
}

/// REQ-PSK-003 (RFC 8446 section 4.6.1): a ticket with a lifetime of zero
/// is discarded, not stored; one with a lifetime is kept.
#[test]
fn a_ticket_with_zero_lifetime_is_discarded() {
    let pki = Pki::new(KeyKind::EcdsaP256, NAME);
    for lifetime in [0u32, 3600] {
        let store = Arc::new(MemoryTicketStore::default());
        let mut cc = pki.client_config(Profile::Default);
        cc.tickets = Some(store.clone() as Arc<dyn TicketStore>);
        let mut sc = pki.server_config(Profile::Default);
        sc.ticket_lifetime = lifetime;
        let (mut c, mut s) = connect(Arc::new(cc), Arc::new(sc), NAME).unwrap();
        c.read_tls(&s.take_tls()).unwrap();
        assert!(c.report().tickets_received >= 1);
        assert_eq!(store.is_empty(), lifetime == 0, "lifetime {lifetime}");
    }
}

// ---------------------------------------------------------------------------
// Pinning.

static CLOCK: AtomicU64 = AtomicU64::new(0);
fn test_clock() -> u64 {
    CLOCK.load(Ordering::SeqCst)
}

/// REQ-X509-007: a pinned certificate not yet valid is refused.
#[test]
fn a_pinned_certificate_not_yet_valid_is_refused() {
    let pki = Pki::new(KeyKind::EcdsaP256, NAME);
    CLOCK.store(now() - 10 * 86_400, Ordering::SeqCst);
    let mut cc = ClientConfig::pinned(Profile::Default, &pki.server_spki()).unwrap();
    cc.common.clock = test_clock;
    let err = connect(
        Arc::new(cc),
        Arc::new(pki.server_config(Profile::Default)),
        NAME,
    )
    .unwrap_err();
    let e = err.client.expect("the client refused");
    // The same leaf check as on a validated path (REQ-X509-075).
    assert_eq!(e.kind(), ErrorKind::CertificateExpired, "{e}");
}

/// REQ-X509-007: a pin with name checking on also requires the certificate
/// to cover the server name.
#[test]
fn a_pin_with_name_checks_refuses_a_certificate_for_another_name() {
    let pki = Pki::new(KeyKind::EcdsaP256, NAME);
    let sc = Arc::new(pki.server_config(Profile::Default));
    let mut cc = ClientConfig::pinned(Profile::Default, &pki.server_spki()).unwrap();
    if let PeerVerification::PinnedSpki { check_names, .. } = &mut cc.verification {
        *check_names = true;
    }
    let cc = Arc::new(cc);
    let (c, _) = connect(cc.clone(), sc.clone(), NAME).unwrap();
    assert!(c.report().has(Property::PinnedPeer));
    let err = connect(cc, sc, "other.test").unwrap_err();
    let e = err.client.expect("the client refused");
    assert_eq!(e.kind(), ErrorKind::CertificateNameMismatch, "{e}");
}

// ---------------------------------------------------------------------------
// Connection API and record layer.

/// REQ-CONN-005: close_notify before the handshake completes is a failure,
/// not a clean close.
#[test]
fn close_notify_during_the_handshake_is_a_failure() {
    let pki = Pki::new(KeyKind::EcdsaP256, NAME);
    let mut c = Connection::client(Arc::new(pki.client_config(Profile::Default)), NAME).unwrap();
    let _ = c.take_tls();
    refused(
        c.read_tls(&[21, 3, 3, 0, 2, 1, 0]),
        ErrorKind::HandshakeFailure,
        "peer closed during the handshake",
    );
    assert!(c.peer_closed());
    assert_eq!(c.state(), HandshakeState::Failed);
}

/// REQ-CONN-006: keys are updated only on an established connection: asking
/// before the handshake is invalid_state, and a peer's KeyUpdate before it
/// is unexpected_message.
#[test]
fn key_update_waits_for_the_handshake() {
    let pki = Pki::new(KeyKind::EcdsaP256, NAME);
    let cc = Arc::new(pki.client_config(Profile::Default));
    let mut c = Connection::client(cc.clone(), NAME).unwrap();
    refused(
        c.key_update(false),
        ErrorKind::InvalidState,
        "KeyUpdate needs an established TLS-over-TCP connection",
    );
    assert_eq!(c.report().key_updates_sent, 0);
    let mut c = Connection::client(cc, NAME).unwrap();
    let _ = c.take_tls();
    refused(
        c.read_tls(&record_of(HandshakeType::KeyUpdate, &[0])),
        ErrorKind::UnexpectedMessage,
        "KeyUpdate before the handshake completed",
    );
    assert_eq!(
        c.report().alert_sent,
        Some(AlertDescription::UnexpectedMessage)
    );
}

/// REQ-REC-004: a peer cannot make the connection buffer more than four
/// maximum records ahead of parsing; that is record_overflow.
#[test]
fn input_beyond_the_buffer_bound_is_record_overflow() {
    let pki = Pki::new(KeyKind::EcdsaP256, NAME);
    let mut c = Connection::client(Arc::new(pki.client_config(Profile::Default)), NAME).unwrap();
    let _ = c.take_tls();
    let bound = 4 * (record::HEADER_LEN + record::MAX_CIPHERTEXT) + 16 * 1024;
    refused(
        c.read_tls(&vec![22; bound + 1]),
        ErrorKind::RecordOverflow,
        "peer is sending faster than it is being read",
    );
    assert_eq!(
        c.report().alert_sent,
        Some(AlertDescription::RecordOverflow)
    );
}

/// No REQ id covers it (reported for the matrix): `wants_write` tells
/// whether `take_tls` has bytes.
#[test]
fn wants_write_reports_queued_bytes() {
    let pki = Pki::new(KeyKind::EcdsaP256, NAME);
    let mut c = Connection::client(Arc::new(pki.client_config(Profile::Default)), NAME).unwrap();
    assert!(c.wants_write(), "the ClientHello is queued");
    assert!(!c.take_tls().is_empty());
    assert!(!c.wants_write());
}

/// REQ-CONN-001: close_notify is sent once, and never after a failure, which
/// has already sent its alert.
#[test]
fn close_notify_is_sent_once_and_never_after_a_failure() {
    let pki = Pki::new(KeyKind::EcdsaP256, NAME);
    let cc = Arc::new(pki.client_config(Profile::Default));
    let sc = Arc::new(pki.server_config(Profile::Default));
    let (mut c, mut s) = connect(cc.clone(), sc, NAME).unwrap();
    c.close();
    let first = c.take_tls();
    assert!(!first.is_empty());
    c.close();
    assert!(c.take_tls().is_empty(), "a second close_notify was sent");
    s.read_tls(&first).unwrap();
    assert!(s.peer_closed());

    let mut c = Connection::client(cc, NAME).unwrap();
    let _ = c.take_tls();
    assert!(c.read_tls(&[23, 3, 3, 0, 1, 0x41]).is_err());
    assert!(!c.take_tls().is_empty(), "the fatal alert");
    c.close();
    assert!(c.take_tls().is_empty(), "close_notify after a fatal alert");
}

// ---------------------------------------------------------------------------
// QUIC.

const SERVER_PARAMS: &[u8] = b"\x04\x04\x80\x10\x00\x00";

fn quic_configs(pki: &Pki) -> (ClientConfig, ServerConfig) {
    (
        pki.client_config(Profile::Default).with_alpn(&[b"h3"]),
        pki.server_config(Profile::Default).with_alpn(&[b"h3"]),
    )
}

/// Run a QUIC handshake until neither side has anything to say.
fn quic_run(c: &mut QuicConnection, s: &mut QuicConnection) {
    for _ in 0..8 {
        while let Ok(Some(_)) = c.next_key_change() {}
        while let Some((l, d)) = c.write_handshake() {
            let _ = s.read_handshake(l, &d);
        }
        while let Ok(Some(_)) = s.next_key_change() {}
        while let Some((l, d)) = s.write_handshake() {
            let _ = c.read_handshake(l, &d);
        }
    }
}

/// A QUIC client that has the server's Initial (ServerHello) and the
/// server's Handshake-level flight, not yet delivered.
fn quic_server_flight(cc: ClientConfig, sc: ServerConfig) -> (QuicConnection, Vec<u8>) {
    let mut c = QuicConnection::client(Arc::new(cc), NAME, b"c", Version::V1).unwrap();
    let mut s = QuicConnection::server(Arc::new(sc), SERVER_PARAMS, Version::V1).unwrap();
    let (level, hello) = c.write_handshake().unwrap();
    s.read_handshake(level, &hello).unwrap();
    let (level, sh) = s.write_handshake().unwrap();
    assert_eq!(level, Level::Initial);
    c.read_handshake(level, &sh).unwrap();
    let (level, flight) = s.write_handshake().unwrap();
    assert_eq!(level, Level::Handshake);
    (c, flight)
}

/// The flight with the message of type `ty` replaced by `edit(body)`.
fn edit_message(flight: &[u8], ty: HandshakeType, edit: impl Fn(&[u8]) -> Vec<u8>) -> Vec<u8> {
    let mut out = Vec::new();
    for (t, msg) in messages(flight) {
        if t == ty {
            out.extend_from_slice(&msgs::frame(t, &edit(&msg[4..])).unwrap());
        } else {
            out.extend_from_slice(&msg);
        }
    }
    out
}

/// REQ-MSG-006: over QUIC the server must select an ALPN protocol even when
/// the client configuration does not require one (RFC 9001 section 8.1).
#[test]
fn quic_refuses_a_server_that_selects_no_alpn() {
    let pki = Pki::new(KeyKind::EcdsaP256, NAME);
    let (cc, sc) = quic_configs(&pki);
    assert!(!cc.common.require_alpn);
    let (mut c, flight) = quic_server_flight(cc, sc);
    let edited = edit_message(&flight, HandshakeType::EncryptedExtensions, |b| {
        let mut ee = EncryptedExtensions::decode(b).unwrap();
        assert!(ee.alpn.is_some());
        ee.alpn = None;
        ee.encode().unwrap()
    });
    refused(
        c.read_handshake(Level::Handshake, &edited),
        ErrorKind::NoApplicationProtocol,
        "server selected no ALPN protocol",
    );
    assert_eq!(c.alert(), Some(AlertDescription::NoApplicationProtocol));
    assert_eq!(c.transport_error_code(), Some(0x0178));
}

/// REQ-MSG-006: EncryptedExtensions answering an extension the client did
/// not offer is unsupported_extension (RFC 8446 section 4.2), whether the
/// type is unknown or one permitted in EncryptedExtensions
/// (max_fragment_length).
#[test]
fn encrypted_extensions_with_an_unoffered_extension_are_refused() {
    let pki = Pki::new(KeyKind::EcdsaP256, NAME);
    for (ty, data) in [(0xfafau16, &b"unasked"[..]), (1, &[4u8][..])] {
        let (cc, sc) = quic_configs(&pki);
        let (mut c, flight) = quic_server_flight(cc, sc);
        let edited = edit_message(&flight, HandshakeType::EncryptedExtensions, |b| {
            append_extension(b, 0, ty, data)
        });
        refused(
            c.read_handshake(Level::Handshake, &edited),
            ErrorKind::UnsupportedExtension,
            "EncryptedExtensions carries an extension not offered",
        );
        assert_eq!(c.alert(), Some(AlertDescription::UnsupportedExtension));
    }
}

/// REQ-MSG-006: a CertificateVerify under a scheme the client did not offer
/// for handshake signatures is illegal_parameter, before any verification.
#[test]
fn a_certificate_verify_under_an_unoffered_scheme_is_refused() {
    let pki = Pki::new(KeyKind::EcdsaP256, NAME);
    let (cc, sc) = quic_configs(&pki);
    let (mut c, flight) = quic_server_flight(cc, sc);
    let edited = edit_message(&flight, HandshakeType::CertificateVerify, |b| {
        let mut cv = CertificateVerify::decode(b).unwrap();
        cv.scheme = SignatureScheme::RsaPkcs1Sha256;
        cv.encode().unwrap()
    });
    refused(
        c.read_handshake(Level::Handshake, &edited),
        ErrorKind::IllegalParameter,
        "CertificateVerify uses a scheme not offered",
    );
    assert_eq!(c.alert(), Some(AlertDescription::IllegalParameter));
}

/// A connected QUIC client and server.
fn quic_connected(cc: ClientConfig, sc: ServerConfig) -> (QuicConnection, QuicConnection) {
    let mut c = QuicConnection::client(Arc::new(cc), NAME, b"c", Version::V1).unwrap();
    let mut s = QuicConnection::server(Arc::new(sc), SERVER_PARAMS, Version::V1).unwrap();
    quic_run(&mut c, &mut s);
    assert_eq!(c.state(), HandshakeState::Connected, "{:?}", c.error());
    (c, s)
}

/// HLR-002, no LLR yet (reported for the matrix): QUIC endpoints treat a
/// TLS KeyUpdate message as a connection error, unexpected_message (0x010a),
/// per RFC 9001 section 6.
#[test]
fn a_quic_peer_cannot_send_a_tls_key_update() {
    let pki = Pki::new(KeyKind::EcdsaP256, NAME);
    let (cc, sc) = quic_configs(&pki);
    let (mut c, _) = quic_connected(cc, sc);
    let update = msgs::frame(HandshakeType::KeyUpdate, &[1]).unwrap();
    refused(
        c.read_handshake(Level::Application, &update),
        ErrorKind::UnexpectedMessage,
        "QUIC forbids the TLS KeyUpdate message",
    );
    assert_eq!(c.transport_error_code(), Some(0x010a));
}

/// A NewSessionTicket body (RFC 8446 section 4.6.1) with no extensions.
fn new_session_ticket(lifetime: u32) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&lifetime.to_be_bytes());
    b.extend_from_slice(&7u32.to_be_bytes());
    b.extend_from_slice(&[1, 0]);
    b.extend_from_slice(&[0, 4, 1, 2, 3, 4]);
    b.extend_from_slice(&[0, 0]);
    msgs::frame(HandshakeType::NewSessionTicket, &b).unwrap()
}

/// REQ-PSK-001: a client with resumption disabled ignores a ticket it did
/// not ask for, without failing.
#[test]
fn a_ticket_sent_to_a_client_without_a_store_is_ignored() {
    let pki = Pki::new(KeyKind::EcdsaP256, NAME);
    let (mut cc, sc) = quic_configs(&pki);
    cc.tickets = None;
    let (mut c, _) = quic_connected(cc, sc);
    assert_eq!(c.report().tickets_received, 0, "none was asked for");
    c.read_handshake(Level::Application, &new_session_ticket(3600))
        .unwrap();
    assert_eq!(c.report().tickets_received, 1);
    assert_eq!(c.state(), HandshakeState::Connected);
}

/// REQ-0RTT-005, REQ-0RTT-001: over QUIC, a HelloRetryRequest also ends
/// 0-RTT; the handshake completes and the client reports the rejection.
#[test]
fn quic_early_data_ends_at_a_retry() {
    let pki = Pki::new(KeyKind::EcdsaP256, NAME);
    let (mut cc, mut sc) = quic_configs(&pki);
    cc.early_data = true;
    cc.common.groups = vec![NamedGroup::X25519, NamedGroup::Secp384r1];
    cc.initial_key_shares = 1;
    sc.early_data = Some(EarlyDataPolicy::new(16_384));
    let cc = Arc::new(cc);
    {
        let mut c = QuicConnection::client(cc.clone(), NAME, b"c", Version::V1).unwrap();
        let mut s =
            QuicConnection::server(Arc::new(sc.clone()), SERVER_PARAMS, Version::V1).unwrap();
        quic_run(&mut c, &mut s);
        assert_eq!(c.report().tickets_received, 1);
    }
    sc.common.groups = vec![NamedGroup::Secp384r1];
    let mut c = QuicConnection::client_with_early_data(cc, NAME, b"c", Version::V1).unwrap();
    assert_eq!(c.report().early_data, "early-data:offered");
    let mut s = QuicConnection::server(Arc::new(sc), SERVER_PARAMS, Version::V1).unwrap();
    quic_run(&mut c, &mut s);
    assert_eq!(c.state(), HandshakeState::Connected, "{:?}", c.error());
    assert!(c.report().hello_retry);
    assert!(c.report().resumed);
    assert_eq!(c.report().early_data, "early-data:rejected");
    assert_ne!(s.report().early_data, "early-data:accepted");
}

/// REQ-0RTT-001 (RFC 8446 section 4.2.10): a server may accept early data
/// only on the ticket it resumed and under the ticket's suite. The client
/// refuses, with illegal_parameter, EncryptedExtensions claiming acceptance
/// after a ServerHello that did not resume, or that resumed under another
/// suite.
#[test]
fn quic_early_data_accepted_without_its_ticket_or_suite_is_refused() {
    let pki = Pki::new(KeyKind::EcdsaP256, NAME);
    for other_suite in [false, true] {
        let (mut cc, mut sc) = quic_configs(&pki);
        cc.early_data = true;
        sc.early_data = Some(EarlyDataPolicy::new(16_384));
        let mut first = cc.clone();
        if other_suite {
            first.common.suites = vec![CipherSuite::TlsChaCha20Poly1305Sha256];
            cc.common.suites = vec![
                CipherSuite::TlsAes128GcmSha256,
                CipherSuite::TlsChaCha20Poly1305Sha256,
            ];
        }
        cc.tickets = first.tickets.clone();
        quic_connected(first, sc.clone());
        // Without the same ticket keys the server cannot resume.
        let server = if other_suite {
            sc
        } else {
            let mut fresh = pki.server_config(Profile::Default).with_alpn(&[b"h3"]);
            fresh.early_data = Some(EarlyDataPolicy::new(16_384));
            fresh
        };
        let mut c =
            QuicConnection::client_with_early_data(Arc::new(cc), NAME, b"c", Version::V1).unwrap();
        assert_eq!(c.report().early_data, "early-data:offered");
        let mut s = QuicConnection::server(Arc::new(server), SERVER_PARAMS, Version::V1).unwrap();
        let (level, hello) = c.write_handshake().unwrap();
        s.read_handshake(level, &hello).unwrap();
        let (level, sh) = s.write_handshake().unwrap();
        c.read_handshake(level, &sh).unwrap();
        assert_eq!(c.report().resumed, other_suite);
        let (level, flight) = s.write_handshake().unwrap();
        let (_, ee) = messages(&flight).remove(0);
        let mut ee = EncryptedExtensions::decode(&ee[4..]).unwrap();
        assert!(!ee.early_data, "the server itself refused the data");
        ee.early_data = true;
        let ee = msgs::frame(HandshakeType::EncryptedExtensions, &ee.encode().unwrap()).unwrap();
        refused(
            c.read_handshake(level, &ee),
            ErrorKind::IllegalParameter,
            "server accepted early data that was not sent",
        );
    }
}
