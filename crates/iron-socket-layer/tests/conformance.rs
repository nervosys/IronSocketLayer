//! RFC 8446 conformance of each side toward a non-conforming peer.
//!
//! Each case takes a real hello from one side, changes one field, and hands
//! it to the other side, which must refuse it with the error for that rule.
//! The hellos are plaintext, so a single field can be changed without
//! touching any keys; the checks on encrypted messages are covered elsewhere.

mod common;

use std::sync::Arc;

use common::*;
use iron_socket_layer::config::Profile;
use iron_socket_layer::crypto::sign::KeyKind;
use iron_socket_layer::enums::{
    CipherSuite, ContentType, HandshakeType, NamedGroup, ProtocolVersion,
};
use iron_socket_layer::msgs::{self, ClientHello, ServerHello};
use iron_socket_layer::record;
use iron_socket_layer::{Connection, Result};

/// The body of the first handshake message in a flight's first record.
fn first_message(flight: &[u8]) -> (HandshakeType, Vec<u8>) {
    assert_eq!(flight[0], 22, "a handshake record first");
    let len = u16::from_be_bytes([flight[3], flight[4]]) as usize;
    let rec = &flight[5..5 + len];
    let ty = HandshakeType::from_wire(rec[0]);
    let n = u32::from_be_bytes([0, rec[1], rec[2], rec[3]]) as usize;
    (ty, rec[4..4 + n].to_vec())
}

/// A plaintext handshake record carrying one message.
fn record_of(ty: HandshakeType, body: &[u8]) -> Vec<u8> {
    let msg = msgs::frame(ty, body).unwrap();
    let mut out = Vec::new();
    record::write_plaintext(ContentType::Handshake, &msg, &mut out);
    out
}

fn refused(r: Result<()>, want: &str) {
    let e = r.expect_err(want);
    assert!(e.to_string().contains(want), "wanted {want:?}, got {e}");
}

/// The server refuses ClientHellos that break RFC 8446's rules.
#[test]
fn the_server_refuses_non_conforming_client_hellos() {
    let pki = Pki::new(KeyKind::EcdsaP256, "server.test");
    let cc = Arc::new(pki.client_config(Profile::Default));
    let sc = Arc::new(pki.server_config(Profile::Default).with_alpn(&[b"h2"]));
    let hello = || {
        let mut c = Connection::client(cc.clone(), "server.test").unwrap();
        let (ty, body) = first_message(&c.take_tls());
        assert_eq!(ty, HandshakeType::ClientHello);
        ClientHello::decode(&body).unwrap()
    };
    let offer = |ch: &ClientHello| {
        let mut s = Connection::server(sc.clone()).unwrap();
        s.read_tls(&record_of(
            HandshakeType::ClientHello,
            &ch.encode().unwrap(),
        ))
    };
    // Unchanged, apart from an ALPN offer this server requires, it proceeds.
    let mut base = hello();
    base.alpn = vec![b"h2".to_vec()];
    offer(&base).unwrap();

    type Edit = fn(&mut ClientHello);
    let cases: &[(Edit, &str)] = &[
        (
            |c| c.versions = vec![ProtocolVersion::Tls12],
            "client does not offer TLS 1.3",
        ),
        (
            |c| c.sig_algs.clear(),
            "ClientHello without signature_algorithms",
        ),
        (|c| c.groups.clear(), "ClientHello without supported_groups"),
        (
            |c| c.key_shares[0].0 = NamedGroup::Secp521r1,
            "key share for a group not in supported_groups",
        ),
        (
            |c| c.suites = vec![CipherSuite::TlsAes128CcmSha256],
            "no cipher suite in common",
        ),
        (
            |c| {
                c.groups = vec![NamedGroup::X448];
                c.key_shares.clear();
            },
            "no key exchange group in common",
        ),
        (
            |c| c.alpn = vec![b"http/1.1".to_vec()],
            "no ALPN protocol in common",
        ),
        (
            |c| c.quic_params = Some(vec![1, 2]),
            "QUIC transport parameters over TCP",
        ),
    ];
    for (edit, want) in cases {
        let mut ch = base.clone();
        edit(&mut ch);
        refused(offer(&ch), want);
    }
}

/// The client refuses ServerHellos that break RFC 8446's rules.
#[test]
fn the_client_refuses_non_conforming_server_hellos() {
    let pki = Pki::new(KeyKind::EcdsaP256, "server.test");
    let cc = Arc::new(pki.client_config(Profile::Default));
    let sc = Arc::new(pki.server_config(Profile::Default));
    // A client that has sent its hello, and the ServerHello it was answered
    // with.
    let exchange = || {
        let mut c = Connection::client(cc.clone(), "server.test").unwrap();
        let mut s = Connection::server(sc.clone()).unwrap();
        s.read_tls(&c.take_tls()).unwrap();
        let (ty, body) = first_message(&s.take_tls());
        assert_eq!(ty, HandshakeType::ServerHello);
        (c, ServerHello::decode(&body).unwrap())
    };
    let answer = |c: &mut Connection, sh: &ServerHello| {
        c.read_tls(&record_of(
            HandshakeType::ServerHello,
            &sh.encode().unwrap(),
        ))
    };
    let (mut c, sh) = exchange();
    answer(&mut c, &sh).unwrap();

    type Edit = fn(&mut ServerHello);
    let cases: &[(Edit, &str)] = &[
        (
            |s| s.session_id[0] ^= 1,
            "legacy_session_id_echo does not match",
        ),
        (
            |s| s.suite = Some(CipherSuite::TlsAes128CcmSha256),
            "server selected a suite not offered",
        ),
        (|s| s.key_share = None, "ServerHello without key_share"),
        (
            |s| s.key_share.as_mut().unwrap().0 = NamedGroup::Secp521r1,
            "server key share for a group not shared",
        ),
        (
            |s| s.selected_psk = Some(0),
            "server selected a PSK that was not offered",
        ),
    ];
    for (edit, want) in cases {
        let (mut c, mut sh) = exchange();
        edit(&mut sh);
        refused(answer(&mut c, &sh), want);
    }
    // Our encoder always writes TLS 1.3, so a server selecting TLS 1.2 in
    // supported_versions is made by rewriting the extension's bytes.
    let (mut c, sh) = exchange();
    let mut body = sh.encode().unwrap();
    let ext = [0x00, 0x2b, 0x00, 0x02, 0x03, 0x04];
    let at = body.windows(6).position(|w| w == ext).unwrap();
    body[at + 5] = 0x03;
    refused(
        c.read_tls(&record_of(HandshakeType::ServerHello, &body)),
        "server selected a version not offered",
    );
}

/// The client refuses HelloRetryRequests that break RFC 8446 §4.1.4, and a
/// ServerHello that changes the suite a retry chose.
#[test]
fn the_client_refuses_non_conforming_retries() {
    let pki = Pki::new(KeyKind::EcdsaP256, "server.test");
    let mut cc = pki.client_config(Profile::Default);
    cc.common.groups = vec![NamedGroup::X25519, NamedGroup::Secp384r1];
    cc.initial_key_shares = 1;
    let cc = Arc::new(cc);
    let mut sc = pki.server_config(Profile::Default);
    sc.common.groups = vec![NamedGroup::Secp384r1];
    let sc = Arc::new(sc);
    // A client and server, and the retry the server answered with.
    let exchange = || {
        let mut c = Connection::client(cc.clone(), "server.test").unwrap();
        let mut s = Connection::server(sc.clone()).unwrap();
        s.read_tls(&c.take_tls()).unwrap();
        let (ty, body) = first_message(&s.take_tls());
        assert_eq!(ty, HandshakeType::ServerHello);
        let hrr = ServerHello::decode(&body).unwrap();
        assert!(hrr.is_retry());
        (c, s, hrr)
    };
    let answer = |c: &mut Connection, sh: &ServerHello| {
        c.read_tls(&record_of(
            HandshakeType::ServerHello,
            &sh.encode().unwrap(),
        ))
    };
    let (mut c, _, hrr) = exchange();
    answer(&mut c, &hrr).unwrap();

    type Edit = fn(&mut ServerHello);
    let cases: &[(Edit, &str)] = &[
        (
            |h| h.hrr_group = Some(NamedGroup::X25519),
            "retry names a group already shared",
        ),
        (
            |h| h.hrr_group = Some(NamedGroup::Secp521r1),
            "retry names a group not offered",
        ),
        (
            |h| {
                h.hrr_group = None;
                h.cookie = None;
            },
            "HelloRetryRequest would change nothing",
        ),
    ];
    for (edit, want) in cases {
        let (mut c, _, mut hrr) = exchange();
        edit(&mut hrr);
        refused(answer(&mut c, &hrr), want);
    }

    // A second retry, after the client has answered the first.
    let (mut c, _, hrr) = exchange();
    answer(&mut c, &hrr).unwrap();
    let _second_hello = c.take_tls();
    refused(answer(&mut c, &hrr), "second HelloRetryRequest");

    // The real server's ServerHello, with the suite changed from the retry's.
    let (mut c, mut s, hrr) = exchange();
    answer(&mut c, &hrr).unwrap();
    s.read_tls(&c.take_tls()).unwrap();
    let flight = s.take_tls();
    // Skip any ChangeCipherSpec record before the ServerHello.
    let at = if flight[0] == 20 { 6 } else { 0 };
    let (ty, body) = first_message(&flight[at..]);
    assert_eq!(ty, HandshakeType::ServerHello);
    let mut sh = ServerHello::decode(&body).unwrap();
    let other = [
        CipherSuite::TlsAes128GcmSha256,
        CipherSuite::TlsAes256GcmSha384,
        CipherSuite::TlsChaCha20Poly1305Sha256,
    ]
    .into_iter()
    .find(|x| Some(*x) != hrr.suite)
    .unwrap();
    sh.suite = Some(other);
    refused(answer(&mut c, &sh), "suite changed after HelloRetryRequest");
}

/// REQ-ECH-001: the server refuses outer hellos that misuse ECH: the inner
/// marker in an outer hello and, after a retry, a second hello that drops ECH
/// or brings a new encapsulated key (which must be empty the second time).
#[test]
fn the_server_refuses_misused_ech() {
    use iron_socket_layer::ech::EchServer;
    use iron_socket_layer::msgs::EchHello;
    const REAL: &str = "secret-backend.test";
    const PUBLIC: &str = "public.test";
    let pki = Pki::new(KeyKind::EcdsaP256, REAL);
    let ech = Arc::new(
        EchServer::generate(3, PUBLIC, 64, &mut ic_drbg::Rng::from_os().unwrap()).unwrap(),
    );
    let mut sc = iron_socket_layer::config::ServerConfig::new(
        Profile::Default,
        pki.identity_for(&[REAL, PUBLIC]),
    )
    .unwrap();
    sc.ech = Some(ech.clone());
    sc.common.groups = vec![NamedGroup::Secp384r1];
    let sc = Arc::new(sc);
    let mut cc = pki.client_config(Profile::Default);
    cc.ech_configs = Some(ech.config_list().to_vec());
    cc.common.groups = vec![NamedGroup::X25519, NamedGroup::Secp384r1];
    cc.initial_key_shares = 1;
    let cc = Arc::new(cc);

    // The inner marker in the outer hello.
    let mut c = Connection::client(cc.clone(), REAL).unwrap();
    let (_, body) = first_message(&c.take_tls());
    let mut ch = ClientHello::decode(&body).unwrap();
    ch.ech = Some(EchHello::Inner);
    let mut s = Connection::server(sc.clone()).unwrap();
    refused(
        s.read_tls(&record_of(
            HandshakeType::ClientHello,
            &ch.encode().unwrap(),
        )),
        "inner ECH marker in an outer ClientHello",
    );

    // After a retry: the second outer hello, changed.
    let second = |edit: fn(&mut ClientHello)| {
        let mut c = Connection::client(cc.clone(), REAL).unwrap();
        let mut s = Connection::server(sc.clone()).unwrap();
        s.read_tls(&c.take_tls()).unwrap();
        c.read_tls(&s.take_tls()).unwrap();
        let flight = c.take_tls();
        let at = if flight[0] == 20 { 6 } else { 0 };
        let (ty, body) = first_message(&flight[at..]);
        assert_eq!(ty, HandshakeType::ClientHello);
        let mut ch = ClientHello::decode(&body).unwrap();
        edit(&mut ch);
        s.read_tls(&record_of(
            HandshakeType::ClientHello,
            &ch.encode().unwrap(),
        ))
    };
    refused(second(|ch| ch.ech = None), "second ClientHello dropped ECH");
    refused(
        second(|ch| {
            if let Some(EchHello::Outer { enc, .. }) = &mut ch.ech {
                *enc = vec![7; 32];
            }
        }),
        "second ECH hello with a new enc",
    );
}

/// RFC 8446 §4.2.9: a ClientHello offering a PSK must carry
/// psk_key_exchange_modes. REQ-PSK-001.
#[test]
fn a_psk_offer_without_key_exchange_modes_is_refused() {
    let pki = Pki::new(KeyKind::EcdsaP256, "server.test");
    let cc = Arc::new(pki.client_config(Profile::Default));
    let sc = Arc::new(pki.server_config(Profile::Default));
    // A first connection leaves a ticket in the client's store.
    let (mut c, mut s) = connect(cc.clone(), sc.clone(), "server.test").unwrap();
    exchange(&mut c, &mut s);
    let mut c = Connection::client(cc, "server.test").unwrap();
    let (_, body) = first_message(&c.take_tls());
    let mut ch = ClientHello::decode(&body).unwrap();
    assert!(ch.psk.is_some(), "the second hello offers the ticket");
    ch.psk_modes.clear();
    let mut s = Connection::server(sc).unwrap();
    refused(
        s.read_tls(&record_of(
            HandshakeType::ClientHello,
            &ch.encode().unwrap(),
        )),
        "pre_shared_key without psk_key_exchange_modes",
    );
}
