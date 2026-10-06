//! Encrypted Client Hello, end to end between this crate's client and server.

mod common;

use std::sync::Arc;

use common::*;
use ironsocketlayer::config::{ClientConfig, Profile, ServerConfig};
use ironsocketlayer::crypto::sign::KeyKind;
use ironsocketlayer::ech::EchServer;
use ironsocketlayer::enums::{AlertDescription, NamedGroup};
use ironsocketlayer::report::Property;
use ironsocketlayer::{Connection, ErrorKind};

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
    use ironsocketlayer::quic::{QuicConnection, Version};
    let (pki, ech, sc) = setup();
    let cc = Arc::new(ech_client(&pki, ech.config_list()).with_alpn(&[b"h3"]));
    let sc = Arc::new(sc.with_alpn(&[b"h3"]));
    let mut c = QuicConnection::client(cc, REAL, b"c", Version::V1).unwrap();
    let mut s = QuicConnection::server(sc, b"s", Version::V1).unwrap();
    for _ in 0..6 {
        while let Some((l, d)) = c.write_handshake() {
            assert!(!contains(&d, REAL.as_bytes()) || l != ironsocketlayer::Level::Initial);
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

/// REQ-ECH-009: an accepted inner hello cannot receive outer retry configs.
#[test]
fn accepted_ech_refuses_retry_configurations() {
    use ironsocketlayer::codec::Reader;
    use ironsocketlayer::enums::HandshakeType;
    use ironsocketlayer::msgs::{self, EncryptedExtensions};
    use ironsocketlayer::quic::{QuicConnection, Version};
    use ironsocketlayer::report::HandshakeState;
    use ironsocketlayer::Level;

    let (pki, ech, sc) = setup();
    let cc = Arc::new(ech_client(&pki, ech.config_list()).with_alpn(&[b"h3"]));
    let sc = Arc::new(sc.with_alpn(&[b"h3"]));
    for version in [Version::V1, Version::V2] {
        for retry in [None, Some(ech.config_list().to_vec()), Some(vec![0, 0])] {
            let mut client = QuicConnection::client(cc.clone(), REAL, b"c", version).unwrap();
            let mut server = QuicConnection::server(sc.clone(), b"s", version).unwrap();
            let (level, hello) = client.write_handshake().unwrap();
            server.read_handshake(level, &hello).unwrap();
            let (level, hello) = server.write_handshake().unwrap();
            assert_eq!(level, Level::Initial);
            client.read_handshake(level, &hello).unwrap();
            assert_eq!(client.report().ech, "ech:accepted");
            let (level, flight) = server.write_handshake().unwrap();
            assert_eq!(level, Level::Handshake);
            if let Some(list) = retry {
                let mut reader = Reader::new(&flight);
                assert_eq!(
                    HandshakeType::from_wire(reader.u8().unwrap()),
                    HandshakeType::EncryptedExtensions
                );
                let mut ee = EncryptedExtensions::decode(reader.vec24().unwrap()).unwrap();
                assert!(ee.ech_retry_configs.is_none());
                ee.ech_retry_configs = Some(list);
                let message =
                    msgs::frame(HandshakeType::EncryptedExtensions, &ee.encode().unwrap()).unwrap();
                let err = client.read_handshake(level, &message).unwrap_err();
                assert_eq!(err.kind(), ErrorKind::UnsupportedExtension);
                assert!(err.to_string().contains("without ECH rejection"));
                assert_eq!(client.state(), HandshakeState::Failed);
                assert_eq!(client.alert(), Some(AlertDescription::UnsupportedExtension));
                assert_eq!(client.transport_error_code(), Some(0x016e));
                assert_eq!(
                    client.read_handshake(level, &flight).unwrap_err().kind(),
                    ErrorKind::UnsupportedExtension
                );
            } else {
                client.read_handshake(level, &flight).unwrap();
                while let Some((level, finished)) = client.write_handshake() {
                    server.read_handshake(level, &finished).unwrap();
                }
                for conn in [&client, &server] {
                    assert_eq!(conn.state(), HandshakeState::Connected);
                    assert!(conn.report().has(Property::EncryptedClientHello));
                }
            }
        }
    }
}
