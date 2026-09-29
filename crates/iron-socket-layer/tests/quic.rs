//! QUIC-TLS handshakes in memory: CRYPTO data carried level by level, keys
//! installed as they appear, and packet protection checked across the pair.

mod common;

use std::sync::Arc;

use common::*;
use iron_socket_layer::config::Profile;
use iron_socket_layer::crypto::sign::KeyKind;
use iron_socket_layer::enums::{AlertDescription, NamedGroup};
use iron_socket_layer::quic::{KeyInstall, QuicConnection, Version};
use iron_socket_layer::report::{HandshakeState, Property};
use iron_socket_layer::{ErrorKind, Level};

struct Side {
    conn: QuicConnection,
    installed: Vec<KeyInstall>,
}

fn pump(from: &mut Side, to: &mut Side) {
    while let Some((level, data)) = from.conn.write_handshake() {
        let _ = to.conn.read_handshake(level, &data);
        while let Ok(Some(k)) = to.conn.next_key_change() {
            to.installed.push(k);
        }
    }
    while let Ok(Some(k)) = from.conn.next_key_change() {
        from.installed.push(k);
    }
}

fn handshake(version: Version, pki: &Pki, profile: Profile) -> (Side, Side) {
    let cc = Arc::new(pki.client_config(profile).with_alpn(&[b"h3"]));
    let sc = Arc::new(pki.server_config(profile).with_alpn(&[b"h3"]));
    let mut c = Side {
        conn: QuicConnection::client(cc, "server.test", b"\x01\x02client-params", version).unwrap(),
        installed: vec![],
    };
    let mut s = Side {
        conn: QuicConnection::server(sc, b"\x03server-params", version).unwrap(),
        installed: vec![],
    };
    for _ in 0..6 {
        pump(&mut c, &mut s);
        pump(&mut s, &mut c);
    }
    (c, s)
}

fn key(side: &Side, level: Level, write: bool) -> &KeyInstall {
    side.installed
        .iter()
        .find(|k| k.level == level && k.write == write)
        .expect("key installed")
}

#[test]
fn quic_v1_and_v2_handshakes_complete_and_keys_pair_up() {
    let pki = Pki::new(KeyKind::EcdsaP256, "server.test");
    for version in [Version::V1, Version::V2] {
        let (c, s) = handshake(version, &pki, Profile::Default);
        assert_eq!(
            c.conn.state(),
            HandshakeState::Connected,
            "{version:?} {:?}",
            c.conn.error()
        );
        assert_eq!(s.conn.state(), HandshakeState::Connected);
        assert_eq!(
            c.conn.peer_transport_parameters(),
            Some(&b"\x03server-params"[..])
        );
        assert_eq!(
            s.conn.peer_transport_parameters(),
            Some(&b"\x01\x02client-params"[..])
        );
        assert_eq!(c.conn.alpn(), Some(&b"h3"[..]));
        assert_eq!(c.conn.report().group, Some(NamedGroup::X25519MlKem768));
        assert!(c.conn.report().has(Property::PostQuantumKeyExchange));
        assert_eq!(c.conn.report().transport, "transport:quic");
        for level in [Level::Handshake, Level::Application] {
            let cw = key(&c, level, true);
            let sr = key(&s, level, false);
            let mut payload = *b"STREAM frame";
            let tag = cw.keys.packet.seal(7, b"header", &mut payload).unwrap();
            let mut both = payload.to_vec();
            both.extend_from_slice(&tag);
            let n = sr.keys.packet.open(7, b"header", &mut both).unwrap();
            assert_eq!(&both[..n], b"STREAM frame");
            let sw = key(&s, level, true);
            let cr = key(&c, level, false);
            let mut p = *b"ACK";
            let tag = sw.keys.packet.seal(1, b"h", &mut p).unwrap();
            let mut both = p.to_vec();
            both.extend_from_slice(&tag);
            assert!(cr.keys.packet.open(1, b"h", &mut both).is_ok());
        }
        // No middlebox compatibility bytes, no records: only CRYPTO data.
        assert!(!c
            .conn
            .report()
            .events
            .iter()
            .any(|e| e.id == "event:alert-sent"));
    }
}

#[test]
fn one_rtt_key_update_stays_in_step() {
    let pki = Pki::new(KeyKind::Ed25519, "server.test");
    let (c, s) = handshake(Version::V1, &pki, Profile::Default);
    let mut cu = c.conn.key_update().unwrap();
    let mut su = s.conn.key_update().unwrap();
    for _ in 0..3 {
        let (c_local, _) = cu.next_keys().unwrap();
        let (_, s_remote) = su.next_keys().unwrap();
        let mut p = *b"after update";
        let tag = c_local.seal(99, b"h", &mut p).unwrap();
        let mut both = p.to_vec();
        both.extend_from_slice(&tag);
        s_remote.open(99, b"h", &mut both).unwrap();
    }
    assert_eq!(cu.generation(), 3);
}

#[test]
fn quic_without_alpn_is_refused_before_anything_is_sent() {
    let pki = Pki::new(KeyKind::EcdsaP256, "server.test");
    let cc = Arc::new(pki.client_config(Profile::Default));
    let err = QuicConnection::client(cc, "server.test", b"p", Version::V1).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::InvalidConfig);
}

#[test]
fn crypto_data_at_the_wrong_level_is_fatal_and_maps_to_a_transport_error() {
    let pki = Pki::new(KeyKind::EcdsaP256, "server.test");
    let sc = Arc::new(pki.server_config(Profile::Default).with_alpn(&[b"h3"]));
    let mut s = QuicConnection::server(sc, b"p", Version::V1).unwrap();
    let err = s
        .read_handshake(Level::Handshake, &[1, 0, 0, 0])
        .unwrap_err();
    assert_eq!(err.kind(), ErrorKind::UnexpectedMessage);
    assert_eq!(s.alert(), Some(AlertDescription::UnexpectedMessage));
    assert_eq!(s.transport_error_code(), Some(0x010a));
}

#[test]
fn a_tls_client_hello_carrying_quic_parameters_is_refused_over_tcp() {
    // The QUIC client's hello, replayed into a TCP server.
    let pki = Pki::new(KeyKind::EcdsaP256, "server.test");
    let cc = Arc::new(pki.client_config(Profile::Default).with_alpn(&[b"h3"]));
    let mut qc = QuicConnection::client(cc, "server.test", b"p", Version::V1).unwrap();
    let (_, hello) = qc.write_handshake().unwrap();
    let mut record = vec![22, 3, 1];
    record.extend_from_slice(&(hello.len() as u16).to_be_bytes());
    record.extend_from_slice(&hello);
    let mut s =
        iron_socket_layer::Connection::server(Arc::new(pki.server_config(Profile::Default)))
            .unwrap();
    assert_eq!(
        s.read_tls(&record).unwrap_err().kind(),
        ErrorKind::UnsupportedExtension
    );
}
