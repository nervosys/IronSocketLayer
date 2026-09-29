//! Encrypted Client Hello, end to end between this crate's client and server.

mod common;

use std::sync::Arc;

use common::*;
use iron_socket_layer::config::{ClientConfig, Profile, ServerConfig};
use iron_socket_layer::crypto::sign::KeyKind;
use iron_socket_layer::ech::EchServer;
use iron_socket_layer::enums::{AlertDescription, NamedGroup};
use iron_socket_layer::report::Property;
use iron_socket_layer::{Connection, ErrorKind};

const REAL: &str = "secret-backend.test";
const PUBLIC: &str = "public.test";

fn setup() -> (Pki, Arc<EchServer>, ServerConfig) {
    let pki = Pki::new(KeyKind::EcdsaP256, REAL);
    let ech = Arc::new(
        EchServer::generate(3, PUBLIC, 64, &mut ic_drbg::Rng::from_os().unwrap()).unwrap(),
    );
    let mut sc = ServerConfig::new(Profile::Default, pki.identity_for(&[REAL, PUBLIC])).unwrap();
    sc.ech = Some(ech.clone());
    (pki, ech, sc)
}

fn ech_client(pki: &Pki, list: &[u8]) -> ClientConfig {
    let mut cc = pki.client_config(Profile::Default);
    cc.ech_configs = Some(list.to_vec());
    cc
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

/// REQ-ECH-001, REQ-ECH-002: the server decrypts the inner hello and
/// confirms; the real name never crosses the wire in the clear.
#[test]
fn accepted_ech_hides_the_real_name() {
    let (pki, ech, sc) = setup();
    let cc = Arc::new(ech_client(&pki, ech.config_list()));
    let mut c = Connection::client(cc.clone(), REAL).unwrap();
    let hello = c.take_tls();
    assert!(
        !contains(&hello, REAL.as_bytes()),
        "the real name appears in the outer hello"
    );
    assert!(contains(&hello, PUBLIC.as_bytes()));

    let (mut c, mut s) = connect(cc, Arc::new(sc), REAL).unwrap();
    for r in [c.report(), s.report()] {
        assert_eq!(r.ech, "ech:accepted", "{}", r.to_json());
        assert!(r.has(Property::EncryptedClientHello));
    }
    assert_eq!(s.report().server_name.as_deref(), Some(REAL));
    exchange(&mut c, &mut s);
}

/// REQ-ECH-003: a server that cannot decrypt answers as the public name and
/// supplies retry configs; the client authenticates it, aborts with
/// ech_required, and the retry configs then work.
#[test]
fn rejected_ech_aborts_with_authenticated_retry_configs() {
    let (pki, ech, sc) = setup();
    let stale = EchServer::generate(3, PUBLIC, 64, &mut ic_drbg::Rng::from_os().unwrap()).unwrap();
    let sc = Arc::new(sc);
    let err_conn = {
        let cc = Arc::new(ech_client(&pki, stale.config_list()));
        let mut c = Connection::client(cc, REAL).unwrap();
        let mut s = Connection::server(sc.clone()).unwrap();
        for _ in 0..4 {
            let _ = s.read_tls(&c.take_tls());
            let _ = c.read_tls(&s.take_tls());
        }
        let _ = s.read_tls(&c.take_tls());
        assert_eq!(c.error().map(|e| e.kind()), Some(ErrorKind::EchRejected));
        assert_eq!(
            s.error().and_then(|e| e.peer_alert()),
            Some(AlertDescription::EchRequired)
        );
        assert_eq!(c.report().ech, "ech:rejected");
        assert_eq!(s.report().ech, "ech:rejected");
        c
    };
    let retry = err_conn
        .ech_retry_configs()
        .expect("retry configs")
        .to_vec();
    assert_eq!(retry, ech.config_list());
    let (c, _) = connect(Arc::new(ech_client(&pki, &retry)), sc, REAL).unwrap();
    assert_eq!(c.report().ech, "ech:accepted");
}

#[test]
fn ech_survives_a_hello_retry_request() {
    let (pki, ech, mut sc) = setup();
    sc.common.groups = vec![NamedGroup::Secp384r1];
    let mut cc = ech_client(&pki, ech.config_list());
    cc.common.groups = vec![NamedGroup::X25519, NamedGroup::Secp384r1];
    cc.initial_key_shares = 1;
    let (mut c, mut s) = connect(Arc::new(cc), Arc::new(sc), REAL).unwrap();
    assert!(c.report().hello_retry);
    assert_eq!(c.report().ech, "ech:accepted");
    assert_eq!(s.report().ech, "ech:accepted");
    exchange(&mut c, &mut s);
}

/// REQ-ECH-004: configured ECH that cannot be used fails before anything is sent.
#[test]
fn an_unusable_ech_config_never_falls_back_to_plaintext() {
    let pki = Pki::new(KeyKind::EcdsaP256, REAL);
    let err = Connection::client(Arc::new(ech_client(&pki, &[0, 0])), REAL).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::InvalidConfig);
    let (_, ech, _) = setup();
    let err =
        Connection::client(Arc::new(ech_client(&pki, ech.config_list())), "192.0.2.1").unwrap_err();
    assert_eq!(err.kind(), ErrorKind::InvalidConfig);
}

#[test]
fn a_server_with_ech_still_serves_clients_without_it() {
    let (pki, _, sc) = setup();
    let (c, s) = connect(
        Arc::new(pki.client_config(Profile::Default)),
        Arc::new(sc),
        REAL,
    )
    .unwrap();
    assert_eq!(c.report().ech, "ech:not-offered");
    assert_eq!(s.report().ech, "ech:not-offered");
}

#[test]
fn ech_works_over_quic() {
    use iron_socket_layer::quic::{QuicConnection, Version};
    let (pki, ech, sc) = setup();
    let cc = Arc::new(ech_client(&pki, ech.config_list()).with_alpn(&[b"h3"]));
    let sc = Arc::new(sc.with_alpn(&[b"h3"]));
    let mut c = QuicConnection::client(cc, REAL, b"c", Version::V1).unwrap();
    let mut s = QuicConnection::server(sc, b"s", Version::V1).unwrap();
    for _ in 0..6 {
        while let Some((l, d)) = c.write_handshake() {
            assert!(!contains(&d, REAL.as_bytes()) || l != iron_socket_layer::Level::Initial);
            let _ = s.read_handshake(l, &d);
        }
        while let Some((l, d)) = s.write_handshake() {
            let _ = c.read_handshake(l, &d);
        }
        while let Ok(Some(_)) = c.next_key_change() {}
        while let Ok(Some(_)) = s.next_key_change() {}
    }
    assert!(!c.is_handshaking(), "{:?}", c.error());
    assert_eq!(c.report().ech, "ech:accepted");
}
