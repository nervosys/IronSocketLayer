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
