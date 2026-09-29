//! External pre-shared keys: authentication without certificates.

mod common;

use std::sync::Arc;

use common::*;
use iron_socket_layer::config::{ClientConfig, ExternalPsk, Profile, ServerConfig};
use iron_socket_layer::crypto::sign::KeyKind;
use iron_socket_layer::crypto::HashAlg;
use iron_socket_layer::enums::{AlertDescription, CipherSuite, NamedGroup};
use iron_socket_layer::report::Property;
use iron_socket_layer::ErrorKind;

const KEY: [u8; 32] = [0x42; 32];

fn psk(id: &[u8], key: &[u8], hash: HashAlg) -> ExternalPsk {
    ExternalPsk::new(id, key, hash).unwrap()
}

fn pair(client_key: &[u8]) -> (ClientConfig, ServerConfig) {
    let cc = ClientConfig::external_psk(
        Profile::Default,
        psk(b"sensor-17", client_key, HashAlg::Sha256),
    )
    .unwrap();
    let sc = ServerConfig::external_psk_only(
        Profile::Default,
        vec![psk(b"sensor-17", &KEY, HashAlg::Sha256)],
    )
    .unwrap();
    (cc, sc)
}

/// REQ-EPSK-001, REQ-EPSK-002: no certificate anywhere, a fresh hybrid key
/// exchange, and the PSK authenticates both ends.
#[test]
fn a_shared_key_authenticates_both_ends_without_certificates() {
    let (cc, sc) = pair(&KEY);
    let (mut c, mut s) = connect(Arc::new(cc), Arc::new(sc), "gateway.local").unwrap();
    for r in [c.report(), s.report()] {
        assert!(r.has(Property::PskAuthenticated), "{}", r.to_json());
        assert!(
            !r.has(Property::ServerAuthenticated),
            "no certificate was verified"
        );
        assert!(r.has(Property::ForwardSecrecy));
        assert!(r.has(Property::PostQuantumKeyExchange));
        assert_eq!(r.group, Some(NamedGroup::X25519MlKem768));
        assert_eq!(r.verification, "verification:external-psk");
        assert!(!r.resumed);
    }
    assert!(!c
        .report()
        .events
        .iter()
        .any(|e| e.detail == "message:certificate"));
    exchange(&mut c, &mut s);
}

/// REQ-EPSK-002: a client holding a different key is refused with decrypt_error.
#[test]
fn a_wrong_key_is_a_decrypt_error() {
    let (cc, sc) = pair(&[0x43; 32]);
    let err = connect(Arc::new(cc), Arc::new(sc), "gateway.local").unwrap_err();
    assert_eq!(err.server.map(|e| e.kind()), Some(ErrorKind::DecryptError));
    assert_eq!(
        err.client.and_then(|e| e.peer_alert()),
        Some(AlertDescription::DecryptError)
    );
}

/// REQ-EPSK-004: a server that does not accept the PSK cannot talk the
/// client into an unauthenticated session.
#[test]
fn no_silent_fallback_when_the_psk_is_not_accepted() {
    let pki = Pki::new(KeyKind::EcdsaP256, "gateway.local");
    let cc = ClientConfig::external_psk(Profile::Default, psk(b"unknown", &KEY, HashAlg::Sha256))
        .unwrap();
    let err = connect(
        Arc::new(cc),
        Arc::new(pki.server_config(Profile::Default)),
        "gateway.local",
    )
    .unwrap_err();
    assert_eq!(
        err.client.map(|e| e.kind()),
        Some(ErrorKind::HandshakeFailure)
    );
    // With trust anchors, the client may fall back to certificates.
    let mut cc = pki.client_config(Profile::Default);
    cc.external_psk = Some(psk(b"unknown", &KEY, HashAlg::Sha256));
    let (c, _) = connect(
        Arc::new(cc),
        Arc::new(pki.server_config(Profile::Default)),
        "gateway.local",
    )
    .unwrap();
    assert!(c.report().has(Property::ServerAuthenticated));
}

/// REQ-EPSK-003.
#[test]
fn weak_keys_and_bad_identities_are_refused() {
    assert_eq!(
        ExternalPsk::new(b"id", &[1; 16], HashAlg::Sha256)
            .unwrap_err()
            .kind(),
        ErrorKind::InvalidConfig
    );
    assert!(ExternalPsk::new(b"", &KEY, HashAlg::Sha256).is_err());
    assert!(ExternalPsk::new(b"id", &[1; 65], HashAlg::Sha256).is_err());
}

#[test]
fn a_sha384_psk_selects_a_sha384_suite() {
    let key = [7u8; 48];
    let cc =
        ClientConfig::external_psk(Profile::Default, psk(b"k384", &key, HashAlg::Sha384)).unwrap();
    let sc = ServerConfig::external_psk_only(
        Profile::Default,
        vec![psk(b"k384", &key, HashAlg::Sha384)],
    )
    .unwrap();
    let (c, _) = connect(Arc::new(cc), Arc::new(sc), "x.local").unwrap();
    assert_eq!(c.suite(), Some(CipherSuite::TlsAes256GcmSha384));
    assert!(c.report().has(Property::PskAuthenticated));
}

#[test]
fn external_psks_work_over_quic() {
    use iron_socket_layer::quic::{QuicConnection, Version};
    let (cc, sc) = pair(&KEY);
    let mut c = QuicConnection::client(
        Arc::new(cc.with_alpn(&[b"coap"])),
        "gateway.local",
        b"c",
        Version::V1,
    )
    .unwrap();
    let mut s =
        QuicConnection::server(Arc::new(sc.with_alpn(&[b"coap"])), b"s", Version::V1).unwrap();
    for _ in 0..6 {
        while let Some((l, d)) = c.write_handshake() {
            let _ = s.read_handshake(l, &d);
        }
        while let Some((l, d)) = s.write_handshake() {
            let _ = c.read_handshake(l, &d);
        }
        while let Ok(Some(_)) = c.next_key_change() {}
        while let Ok(Some(_)) = s.next_key_change() {}
    }
    assert!(!c.is_handshaking(), "{:?}", c.error());
    assert!(c.report().has(Property::PskAuthenticated));
}
