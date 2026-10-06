//! End-to-end TLS 1.3 handshakes between this crate's client and server,
//! in memory, across every implemented suite, group and key type.
//!
//! These prove the two state machines agree with each other. They cannot prove
//! either agrees with RFC 8446 — two implementations of the same mistake
//! interoperate perfectly — which is why `tests/interop.rs` exists as well.

mod common;

use std::sync::Arc;

use common::*;
use ironsocketlayer::config::{ClientAuth, ClientConfig, PeerVerification, Profile, ServerConfig};
use ironsocketlayer::crypto::kx::IMPLEMENTED_GROUPS;
use ironsocketlayer::crypto::sign::KeyKind;
use ironsocketlayer::enums::{AlertDescription, CipherSuite, NamedGroup, SignatureScheme};
use ironsocketlayer::record::IMPLEMENTED_SUITES;
use ironsocketlayer::report::{HandshakeState, Property};
use ironsocketlayer::{Connection, ErrorKind};

#[test]
fn default_profile_negotiates_hybrid_post_quantum() {
    let pki = Pki::new(KeyKind::EcdsaP256, "server.test");
    let client = Arc::new(pki.client_config(Profile::Default));
    let server = Arc::new(pki.server_config(Profile::Default));
    let (mut c, mut s) = connect(client, server, "server.test").unwrap();
    let r = c.report();
    assert_eq!(r.state, Some(HandshakeState::Connected));
    assert_eq!(r.group, Some(NamedGroup::X25519MlKem768));
    assert!(r.has(Property::PostQuantumKeyExchange));
    assert!(r.has(Property::ServerAuthenticated));
    assert!(!r.has(Property::MutualAuthentication));
    assert!(!r.hello_retry);
    let json = r.to_json();
    exchange(&mut c, &mut s);
    assert!(
        json.contains(r#""keyExchangeGroup":"group:x25519mlkem768""#),
        "{json}"
    );
}

#[test]
fn every_suite_and_group_completes() {
    let pki = Pki::new(KeyKind::EcdsaP256, "server.test");
    for &suite in IMPLEMENTED_SUITES {
        for &group in IMPLEMENTED_GROUPS {
            let mut cc = pki.client_config(Profile::Default);
            cc.common.suites = vec![suite];
            cc.common.groups = vec![group];
            let mut sc = pki.server_config(Profile::Default);
            sc.common.suites = vec![suite];
            sc.common.groups = vec![group];
            let (mut c, mut s) = connect(Arc::new(cc), Arc::new(sc), "server.test")
                .unwrap_or_else(|e| panic!("{suite} {group}: {e:?}"));
            assert_eq!(c.suite(), Some(suite));
            assert_eq!(c.report().group, Some(group));
            exchange(&mut c, &mut s);
        }
    }
}

#[test]
fn every_key_kind_authenticates_the_server() {
    for &kind in KeyKind::ALL {
        let pki = Pki::new(kind, "server.test");
        let (c, _s) = connect(
            Arc::new(pki.client_config(Profile::Default)),
            Arc::new(pki.server_config(Profile::Default)),
            "server.test",
        )
        .unwrap_or_else(|e| panic!("{kind:?}: {e:?}"));
        let scheme = c.report().peer_signature_scheme.unwrap();
        assert!(scheme.allowed_in_handshake());
        match kind {
            KeyKind::MlDsa44 => assert_eq!(scheme, SignatureScheme::MlDsa44),
            KeyKind::MlDsa65 => assert_eq!(scheme, SignatureScheme::MlDsa65),
            KeyKind::MlDsa87 => assert_eq!(scheme, SignatureScheme::MlDsa87),
            _ => {}
        }
        // The CA signs with ECDSA P-384, so no chain here is post-quantum end to end.
        assert!(!c.report().has(Property::PostQuantumAuthentication));
    }
}

#[test]
fn post_quantum_authentication_needs_the_whole_chain_to_be_ml_dsa() {
    let pki = Pki::with_kinds(KeyKind::MlDsa65, KeyKind::MlDsa65, "server.test");
    let (c, _) = connect(
        Arc::new(pki.client_config(Profile::PostQuantum)),
        Arc::new(pki.server_config(Profile::PostQuantum)),
        "server.test",
    )
    .unwrap();
    assert!(c.report().has(Property::PostQuantumAuthentication));
    assert!(c.report().has(Property::PostQuantumKeyExchange));
    // ML-DSA-65 is NIST category 3, comparable to AES-192.
    assert_eq!(c.report().peer_chain_min_bits, Some(192));
}

/// REQ-KX-005, REQ-SIG-005: explicit category 1 KEM and category 2 signatures
/// authenticate an all-post-quantum chain without changing named profiles.
#[test]
fn explicit_small_post_quantum_parameter_sets_complete() {
    let pki = Pki::with_kinds(KeyKind::MlDsa44, KeyKind::MlDsa44, "server.test");
    let mut cc = pki.client_config(Profile::PostQuantum);
    let mut sc = pki.server_config(Profile::PostQuantum);
    cc.common.groups = vec![NamedGroup::MlKem512];
    sc.common.groups = vec![NamedGroup::MlKem512];
    cc.common.schemes = vec![SignatureScheme::MlDsa44];
    sc.common.schemes = vec![SignatureScheme::MlDsa44];
    let (mut c, mut s) = connect(Arc::new(cc), Arc::new(sc), "server.test").unwrap();
    assert_eq!(c.report().group, Some(NamedGroup::MlKem512));
    assert_eq!(
        c.report().peer_signature_scheme,
        Some(SignatureScheme::MlDsa44)
    );
    assert_eq!(c.report().peer_key, Some("key:ml-dsa-44"));
    assert!(c.report().has(Property::PostQuantumKeyExchange));
    assert!(c.report().has(Property::PostQuantumAuthentication));
    exchange(&mut c, &mut s);
    for &profile in Profile::ALL {
        assert!(!profile.groups().contains(&NamedGroup::MlKem512));
        assert!(!profile.schemes().contains(&SignatureScheme::MlDsa44));
    }
}

#[test]
fn hello_retry_request_recovers_a_missing_share() {
    let pki = Pki::new(KeyKind::EcdsaP256, "server.test");
    let mut cc = pki.client_config(Profile::Default);
    cc.common.groups = vec![NamedGroup::X25519, NamedGroup::Secp384r1];
    cc.initial_key_shares = 1;
    let mut sc = pki.server_config(Profile::Default);
    sc.common.groups = vec![NamedGroup::Secp384r1];
    sc.retry_cookie = true;
    let (mut c, mut s) = connect(Arc::new(cc), Arc::new(sc), "server.test").unwrap();
    assert!(c.report().hello_retry);
    assert!(s.report().hello_retry);
    assert_eq!(c.report().group, Some(NamedGroup::Secp384r1));
    exchange(&mut c, &mut s);
}

/// A server that has sent a HelloRetryRequest with a cookie, and the client's
/// reply to it.
fn retried_hello(pki: &Pki) -> (Connection, Vec<u8>) {
    let mut cc = pki.client_config(Profile::Default);
    cc.common.groups = vec![NamedGroup::X25519, NamedGroup::Secp384r1];
    cc.initial_key_shares = 1;
    let mut sc = pki.server_config(Profile::Default);
    sc.common.groups = vec![NamedGroup::Secp384r1];
    sc.retry_cookie = true;
    let mut c = Connection::client(Arc::new(cc), "server.test").unwrap();
    let mut s = Connection::server(Arc::new(sc)).unwrap();
    s.read_tls(&c.take_tls()).unwrap();
    c.read_tls(&s.take_tls()).unwrap();
    (s, c.take_tls())
}

/// REQ-MSG-005: the second ClientHello must carry the cookie exactly as sent.
#[test]
fn a_second_hello_must_echo_the_cookie_unchanged() {
    let pki = Pki::new(KeyKind::EcdsaP256, "server.test");
    // The cookie extension: type 44, length 34, then a 32-byte cookie.
    let marker = [0x00, 0x2c, 0x00, 0x22, 0x00, 0x20];
    let find = |b: &[u8]| {
        b.windows(marker.len())
            .position(|w| w == marker)
            .expect("cookie extension")
    };

    let (mut s, ch2) = retried_hello(&pki);
    s.read_tls(&ch2).unwrap();

    // The last byte of the cookie changed.
    let (mut s, mut ch2) = retried_hello(&pki);
    let at = find(&ch2) + marker.len() + 31;
    ch2[at] ^= 1;
    let err = s.read_tls(&ch2).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::IllegalParameter, "{err}");

    // The cookie extension turned into an unknown one, so no cookie at all.
    let (mut s, mut ch2) = retried_hello(&pki);
    let at = find(&ch2);
    ch2[at..at + 2].copy_from_slice(&[0xfa, 0xfa]);
    let err = s.read_tls(&ch2).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::IllegalParameter, "{err}");
}

#[test]
fn mutual_authentication_is_reported_on_both_sides() {
    let pki = Pki::new(KeyKind::Ed25519, "server.test");
    let client_id = pki.client_identity(KeyKind::EcdsaP384, "agent-7");
    let cc = pki.client_config(Profile::Default).with_identity(client_id);
    let sc = pki
        .server_config(Profile::Default)
        .with_client_auth(ClientAuth::Required(PeerVerification::Roots(pki.roots())));
    let (mut c, mut s) = connect(Arc::new(cc), Arc::new(sc), "server.test").unwrap();
    assert!(c.report().has(Property::MutualAuthentication));
    assert!(s.report().has(Property::MutualAuthentication));
    assert_eq!(s.report().peer_subject_cn.as_deref(), Some("agent-7"));
    assert_eq!(
        s.report().peer_signature_scheme,
        Some(SignatureScheme::EcdsaSecp384r1Sha384)
    );
    exchange(&mut c, &mut s);
}

#[test]
fn a_required_client_certificate_that_is_missing_fails_the_handshake() {
    let pki = Pki::new(KeyKind::EcdsaP256, "server.test");
    let sc = pki
        .server_config(Profile::Default)
        .with_client_auth(ClientAuth::Required(PeerVerification::Roots(pki.roots())));
    let err = connect(
        Arc::new(pki.client_config(Profile::Default)),
        Arc::new(sc),
        "server.test",
    )
    .unwrap_err();
    assert_eq!(
        err.server.map(|e| e.kind()),
        Some(ErrorKind::CertificateRequired)
    );
    assert_eq!(
        err.client.and_then(|e| e.peer_alert()),
        Some(AlertDescription::CertificateRequired)
    );
}

#[test]
fn the_wrong_name_is_refused_by_the_client() {
    let pki = Pki::new(KeyKind::EcdsaP256, "server.test");
    let err = connect(
        Arc::new(pki.client_config(Profile::Default)),
        Arc::new(pki.server_config(Profile::Default)),
        "other.test",
    )
    .unwrap_err();
    assert_eq!(
        err.client.map(|e| e.kind()),
        Some(ErrorKind::CertificateNameMismatch)
    );
    assert_eq!(
        err.server.and_then(|e| e.peer_alert()),
        Some(AlertDescription::BadCertificate)
    );
}

#[test]
fn an_untrusted_server_is_refused() {
    let pki = Pki::new(KeyKind::EcdsaP256, "server.test");
    let stranger = Pki::new(KeyKind::EcdsaP256, "server.test");
    let err = connect(
        Arc::new(stranger.client_config(Profile::Default)),
        Arc::new(pki.server_config(Profile::Default)),
        "server.test",
    )
    .unwrap_err();
    assert_eq!(err.client.map(|e| e.kind()), Some(ErrorKind::UnknownCa));
}

#[test]
fn pinning_accepts_the_pinned_key_and_nothing_else() {
    let pki = Pki::new(KeyKind::EcdsaP256, "server.test");
    let spki = pki.server_spki();
    let cc = ClientConfig::pinned(Profile::Default, &spki).unwrap();
    let (c, _) = connect(
        Arc::new(cc),
        Arc::new(pki.server_config(Profile::Default)),
        "server.test",
    )
    .unwrap();
    assert!(c.report().has(Property::PinnedPeer));
    let other = Pki::new(KeyKind::EcdsaP256, "server.test");
    let cc = ClientConfig::pinned(Profile::Default, &other.server_spki()).unwrap();
    let err = connect(
        Arc::new(cc),
        Arc::new(pki.server_config(Profile::Default)),
        "server.test",
    )
    .unwrap_err();
    assert_eq!(err.client.map(|e| e.kind()), Some(ErrorKind::UnknownCa));
}

#[test]
fn no_common_group_is_a_handshake_failure() {
    let pki = Pki::new(KeyKind::EcdsaP256, "server.test");
    let mut cc = pki.client_config(Profile::Default);
    cc.common.groups = vec![NamedGroup::X25519];
    let mut sc = pki.server_config(Profile::Default);
    sc.common.groups = vec![NamedGroup::Secp521r1];
    let err = connect(Arc::new(cc), Arc::new(sc), "server.test").unwrap_err();
    assert_eq!(
        err.server.map(|e| e.kind()),
        Some(ErrorKind::HandshakeFailure)
    );
    assert_eq!(
        err.client.and_then(|e| e.peer_alert()),
        Some(AlertDescription::HandshakeFailure)
    );
}

#[test]
fn alpn_is_negotiated_and_a_mismatch_is_refused() {
    let pki = Pki::new(KeyKind::EcdsaP256, "server.test");
    let cc = pki
        .client_config(Profile::Default)
        .with_alpn(&[b"h2", b"mcp/1"]);
    let sc = pki.server_config(Profile::Default).with_alpn(&[b"mcp/1"]);
    let (c, s) = connect(Arc::new(cc), Arc::new(sc), "server.test").unwrap();
    assert_eq!(c.alpn(), Some(&b"mcp/1"[..]));
    assert_eq!(s.alpn(), Some(&b"mcp/1"[..]));
    let cc = pki.client_config(Profile::Default).with_alpn(&[b"h2"]);
    let sc = pki.server_config(Profile::Default).with_alpn(&[b"mcp/1"]);
    let err = connect(Arc::new(cc), Arc::new(sc), "server.test").unwrap_err();
    assert_eq!(
        err.server.map(|e| e.kind()),
        Some(ErrorKind::NoApplicationProtocol)
    );
}

#[test]
fn key_updates_keep_data_flowing_in_both_directions() {
    let pki = Pki::new(KeyKind::EcdsaP256, "server.test");
    let (mut c, mut s) = connect(
        Arc::new(pki.client_config(Profile::Default)),
        Arc::new(pki.server_config(Profile::Default)),
        "server.test",
    )
    .unwrap();
    c.key_update(true).unwrap();
    exchange(&mut c, &mut s);
    assert_eq!(c.report().key_updates_sent, 1);
    assert_eq!(s.report().key_updates_received, 1);
    // The server answered the request with its own update.
    assert_eq!(s.report().key_updates_sent, 1);
    s.key_update(false).unwrap();
    exchange(&mut c, &mut s);
    assert_eq!(c.report().key_updates_received, 2);
}

#[test]
fn exporters_agree_and_differ_by_label() {
    let pki = Pki::new(KeyKind::EcdsaP256, "server.test");
    let (c, s) = connect(
        Arc::new(pki.client_config(Profile::Default)),
        Arc::new(pki.server_config(Profile::Default)),
        "server.test",
    )
    .unwrap();
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    c.export_keying_material(b"EXPORTER-Channel-Binding", b"", &mut a)
        .unwrap();
    s.export_keying_material(b"EXPORTER-Channel-Binding", b"", &mut b)
        .unwrap();
    assert_eq!(a, b);
    s.export_keying_material(b"EXPORTER-other", b"", &mut b)
        .unwrap();
    assert_ne!(a, b);
}

#[test]
fn close_notify_is_orderly() {
    let pki = Pki::new(KeyKind::EcdsaP256, "server.test");
    let (mut c, mut s) = connect(
        Arc::new(pki.client_config(Profile::Default)),
        Arc::new(pki.server_config(Profile::Default)),
        "server.test",
    )
    .unwrap();
    c.close();
    s.read_tls(&c.take_tls()).unwrap();
    assert!(s.peer_closed());
    assert_eq!(s.state(), HandshakeState::Closed);
    assert_eq!(c.send(b"x").unwrap_err().kind(), ErrorKind::Closed);
}

#[test]
fn a_tampered_record_is_fatal_and_latches() {
    let pki = Pki::new(KeyKind::EcdsaP256, "server.test");
    let (mut c, mut s) = connect(
        Arc::new(pki.client_config(Profile::Default)),
        Arc::new(pki.server_config(Profile::Default)),
        "server.test",
    )
    .unwrap();
    c.send(b"hello").unwrap();
    let mut wire = c.take_tls();
    let last = wire.len() - 1;
    wire[last] ^= 0x80;
    assert_eq!(
        s.read_tls(&wire).unwrap_err().kind(),
        ErrorKind::BadRecordMac
    );
    assert_eq!(s.read_tls(&[]).unwrap_err().kind(), ErrorKind::BadRecordMac);
    assert_eq!(s.state(), HandshakeState::Failed);
    assert_eq!(s.report().alert_sent, Some(AlertDescription::BadRecordMac));
}

#[test]
fn the_post_quantum_profile_refuses_a_classical_only_peer() {
    let pki = Pki::new(KeyKind::EcdsaP256, "server.test");
    let mut cc = pki.client_config(Profile::Default);
    cc.common.groups = vec![NamedGroup::X25519, NamedGroup::Secp256r1];
    let err = connect(
        Arc::new(cc),
        Arc::new(pki.server_config(Profile::PostQuantum)),
        "server.test",
    )
    .unwrap_err();
    assert_eq!(
        err.server.map(|e| e.kind()),
        Some(ErrorKind::HandshakeFailure)
    );
}

#[test]
fn every_profile_is_available_in_this_build() {
    // REQ-CFG-004's refusal applies only to a build that lacks an algorithm a
    // profile needs; this build lacks none (CNSA 2.0 was the last).
    for p in Profile::ALL {
        assert!(p.available(), "{p:?}");
    }
}

#[test]
fn the_server_picks_the_identity_that_matches_sni() {
    let a = Pki::new(KeyKind::EcdsaP256, "a.test");
    let b_key_pki = Pki::with_ca(&a, KeyKind::Ed25519, "b.test");
    let mut sc = a.server_config(Profile::Default);
    sc.identities.push(b_key_pki.server_identity());
    let (c, _) = connect(
        Arc::new(a.client_config(Profile::Default)),
        Arc::new(sc),
        "b.test",
    )
    .unwrap();
    assert_eq!(
        c.report().peer_signature_scheme,
        Some(SignatureScheme::Ed25519)
    );
}

#[test]
fn garbage_before_the_hello_is_refused_without_panicking() {
    let pki = Pki::new(KeyKind::EcdsaP256, "server.test");
    for junk in [
        &b"GET / HTTP/1.1\r\n\r\n"[..],
        &[0x16, 0x03, 0x03, 0x00, 0x01, 0x01][..],
        &[0x17; 64][..],
    ] {
        let mut s = Connection::server(Arc::new(pki.server_config(Profile::Default))).unwrap();
        assert!(s.read_tls(junk).is_err() || s.is_handshaking());
    }
}

#[test]
fn every_prefix_of_the_server_flight_is_safe() {
    let pki = Pki::new(KeyKind::EcdsaP256, "server.test");
    let cc = Arc::new(pki.client_config(Profile::Default));
    let sc = Arc::new(pki.server_config(Profile::Default));
    let mut c = Connection::client(cc.clone(), "server.test").unwrap();
    let mut s = Connection::server(sc).unwrap();
    s.read_tls(&c.take_tls()).unwrap();
    let flight = s.take_tls();
    // Feeding the flight in every split must reach the same place.
    for split in [1usize, 5, 6, 100, flight.len() / 2, flight.len() - 1] {
        let mut c2 = Connection::client(cc.clone(), "server.test").unwrap();
        let _ = c2.take_tls();
        // A fresh client has a different random, so its transcript differs:
        // the server's Finished must then fail, never panic.
        let _ = c2.read_tls(&flight[..split]);
        let _ = c2.read_tls(&flight[split..]);
        assert_ne!(c2.state(), HandshakeState::Connected);
    }
    c.read_tls(&flight[..7]).unwrap();
    c.read_tls(&flight[7..]).unwrap();
    assert_eq!(c.state(), HandshakeState::Connected);
}

#[test]
fn a_suite_the_client_did_not_offer_is_never_selected() {
    let pki = Pki::new(KeyKind::EcdsaP256, "server.test");
    let mut cc = pki.client_config(Profile::Default);
    cc.common.suites = vec![CipherSuite::TlsChaCha20Poly1305Sha256];
    let mut sc = pki.server_config(Profile::Default);
    sc.common.suites = vec![
        CipherSuite::TlsAes256GcmSha384,
        CipherSuite::TlsChaCha20Poly1305Sha256,
    ];
    let (c, _) = connect(Arc::new(cc), Arc::new(sc), "server.test").unwrap();
    assert_eq!(c.suite(), Some(CipherSuite::TlsChaCha20Poly1305Sha256));
}

/// REQ-CONN-002: bytes of a further handshake message in the same record as
/// the ServerHello would be read under the old key; the client must refuse.
#[test]
fn a_handshake_message_may_not_span_a_key_change() {
    let pki = Pki::new(KeyKind::EcdsaP256, "server.test");
    let mut c =
        Connection::client(Arc::new(pki.client_config(Profile::Default)), "server.test").unwrap();
    let mut s = Connection::server(Arc::new(pki.server_config(Profile::Default))).unwrap();
    s.read_tls(&c.take_tls()).unwrap();
    let mut flight = s.take_tls();
    // The first record is the plaintext ServerHello; extend it by two bytes
    // that begin an EncryptedExtensions header.
    let len = u16::from_be_bytes([flight[3], flight[4]]) as usize;
    flight.splice(5 + len..5 + len, [8u8, 0]);
    flight[3..5].copy_from_slice(&((len + 2) as u16).to_be_bytes());
    assert_eq!(
        c.read_tls(&flight).unwrap_err().kind(),
        ErrorKind::UnexpectedMessage
    );
}

/// REQ-CONN-004: a ChangeCipherSpec whose body is not 0x01 is fatal even
/// where one is tolerated.
#[test]
fn a_malformed_change_cipher_spec_is_fatal() {
    let pki = Pki::new(KeyKind::EcdsaP256, "server.test");
    let mut c =
        Connection::client(Arc::new(pki.client_config(Profile::Default)), "server.test").unwrap();
    let mut s = Connection::server(Arc::new(pki.server_config(Profile::Default))).unwrap();
    s.read_tls(&c.take_tls()).unwrap();
    let flight = s.take_tls();
    let len = u16::from_be_bytes([flight[3], flight[4]]) as usize;
    c.read_tls(&flight[..5 + len]).unwrap();
    assert_eq!(
        c.read_tls(&[20, 3, 3, 0, 1, 2]).unwrap_err().kind(),
        ErrorKind::UnexpectedMessage
    );
}

/// REQ-CFG-002: validation refuses anything this build cannot perform.
#[test]
fn unimplemented_parameters_are_refused_by_validation() {
    let pki = Pki::new(KeyKind::EcdsaP256, "server.test");
    let mut c = pki.client_config(Profile::Default);
    c.common.suites = vec![CipherSuite::TlsAes128CcmSha256];
    assert_eq!(c.validate().unwrap_err().kind(), ErrorKind::InvalidConfig);
    let mut c = pki.client_config(Profile::Default);
    c.common.groups = vec![NamedGroup::X448];
    assert_eq!(c.validate().unwrap_err().kind(), ErrorKind::InvalidConfig);
    let mut c = pki.client_config(Profile::Default);
    c.common.schemes = vec![SignatureScheme::Ed448];
    assert_eq!(c.validate().unwrap_err().kind(), ErrorKind::InvalidConfig);
    let mut c = pki.client_config(Profile::Default);
    c.common.schemes = vec![SignatureScheme::RsaPkcs1Sha256];
    assert_eq!(
        c.validate().unwrap_err().kind(),
        ErrorKind::InvalidConfig,
        "certificate-only schemes cannot sign a handshake"
    );
}

#[test]
fn server_config_without_matching_scheme_is_rejected() {
    let pki = Pki::new(KeyKind::Ed25519, "server.test");
    let mut sc: ServerConfig = pki.server_config(Profile::Default);
    sc.common.schemes = vec![SignatureScheme::EcdsaSecp256r1Sha256];
    assert_eq!(sc.validate().unwrap_err().kind(), ErrorKind::InvalidConfig);
}

/// Largest protected record body on the wire, less the AEAD tag.
fn largest_inner(wire: &[u8]) -> usize {
    let mut at = 0;
    let mut max = 0;
    while at + 5 <= wire.len() {
        let len = u16::from_be_bytes([wire[at + 3], wire[at + 4]]) as usize;
        if wire[at] == 23 {
            max = max.max(len - 16);
        }
        at += 5 + len;
    }
    max
}

/// REQ-RSL-003: each side sends records no larger than the limit the other
/// negotiated, and data still arrives intact.
#[test]
fn record_size_limits_are_honoured_in_both_directions() {
    let pki = Pki::new(KeyKind::EcdsaP256, "server.test");
    let mut cc = pki.client_config(Profile::Default);
    cc.common.record_size_limit = Some(256);
    let mut sc = pki.server_config(Profile::Default);
    sc.common.record_size_limit = Some(1024);
    let (mut c, mut s) = connect(Arc::new(cc), Arc::new(sc), "server.test").unwrap();
    // Deliver the post-handshake ticket first; it too must fit the limit.
    let tickets = s.take_tls();
    assert!(largest_inner(&tickets) <= 256);
    c.read_tls(&tickets).unwrap();
    s.send(&[1u8; 5000]).unwrap();
    let wire = s.take_tls();
    assert!(
        largest_inner(&wire) <= 256,
        "server sent {} > 256",
        largest_inner(&wire)
    );
    c.read_tls(&wire).unwrap();
    assert_eq!(c.available(), 5000);
    c.send(&[2u8; 5000]).unwrap();
    let wire = c.take_tls();
    assert!(largest_inner(&wire) <= 1024 && largest_inner(&wire) > 256);
    s.read_tls(&wire).unwrap();
    assert_eq!(s.available(), 5000);
}

#[test]
fn record_size_limit_is_not_sent_without_configuration_or_under_quic() {
    let pki = Pki::new(KeyKind::EcdsaP256, "server.test");
    let mut c =
        Connection::client(Arc::new(pki.client_config(Profile::Default)), "server.test").unwrap();
    let hello = c.take_tls();
    assert!(ironsocketlayer::msgs::ClientHello::decode(&hello[9..])
        .unwrap()
        .record_size_limit
        .is_none());
    let mut cc = pki.client_config(Profile::Default).with_alpn(&[b"h3"]);
    cc.common.record_size_limit = Some(512);
    let mut q = ironsocketlayer::quic::QuicConnection::client(
        Arc::new(cc),
        "server.test",
        b"p",
        ironsocketlayer::quic::Version::V1,
    )
    .unwrap();
    let (_, hello) = q.write_handshake().unwrap();
    assert!(ironsocketlayer::msgs::ClientHello::decode(&hello[4..])
        .unwrap()
        .record_size_limit
        .is_none());
}
