//! 0-RTT early data: accepted only when fresh, once, and asked for.

mod common;

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use common::*;
use iron_socket_layer::config::{ClientConfig, EarlyDataPolicy, Profile, ServerConfig};
use iron_socket_layer::crypto::sign::KeyKind;
use iron_socket_layer::enums::NamedGroup;
use iron_socket_layer::report::HandshakeState;
use iron_socket_layer::Connection;

const REQUEST: &[u8] = b"GET /status HTTP/1.1\r\nHost: x\r\n\r\n";

fn configs(pki: &Pki, policy: bool) -> (Arc<ClientConfig>, Arc<ServerConfig>) {
    let mut cc = pki.client_config(Profile::Default);
    cc.early_data = true;
    let mut sc = pki.server_config(Profile::Default);
    if policy {
        sc.early_data = Some(EarlyDataPolicy::new(16_384));
    }
    (Arc::new(cc), Arc::new(sc))
}

fn get_ticket(cc: &Arc<ClientConfig>, sc: &Arc<ServerConfig>) {
    let (mut c, mut s) = connect(cc.clone(), sc.clone(), "server.test").unwrap();
    c.read_tls(&s.take_tls()).unwrap();
    assert_eq!(c.report().tickets_received, 1);
}

/// Drive a client made with early data to completion; return both ends and
/// how much 0-RTT data the server held before the client's Finished arrived.
fn early_handshake(c: &mut Connection, sc: &Arc<ServerConfig>) -> (Connection, usize) {
    let mut s = Connection::server(sc.clone()).unwrap();
    s.read_tls(&c.take_tls()).unwrap();
    let before_finished = s.available();
    for _ in 0..4 {
        let _ = c.read_tls(&s.take_tls());
        let _ = s.read_tls(&c.take_tls());
    }
    (s, before_finished)
}

/// REQ-0RTT-001, REQ-0RTT-003: early data arrives with the first flight.
#[test]
fn early_data_is_delivered_in_the_first_flight() {
    let pki = Pki::new(KeyKind::EcdsaP256, "server.test");
    let (cc, sc) = configs(&pki, true);
    get_ticket(&cc, &sc);
    let mut c = Connection::client_with_early_data(cc, "server.test", REQUEST).unwrap();
    let (mut s, before) = early_handshake(&mut c, &sc);
    assert_eq!(
        before,
        REQUEST.len(),
        "0-RTT data was not readable before the handshake finished"
    );
    assert_eq!(c.state(), HandshakeState::Connected);
    assert_eq!(s.state(), HandshakeState::Connected, "{:?}", s.error());
    for r in [c.report(), s.report()] {
        assert_eq!(r.early_data, "early-data:accepted", "{}", r.to_json());
        assert!(r.resumed);
    }
    let mut buf = [0u8; 64];
    let n = s.recv(&mut buf);
    assert_eq!(&buf[..n], REQUEST);
    assert!(c.take_rejected_early_data().is_none());
    exchange(&mut c, &mut s);
}

/// REQ-0RTT-002: a recorded first flight replayed to the server gets no
/// early data through, however many times it is replayed.
#[test]
fn a_replayed_first_flight_does_not_replay_its_early_data() {
    let pki = Pki::new(KeyKind::EcdsaP256, "server.test");
    let (cc, sc) = configs(&pki, true);
    get_ticket(&cc, &sc);
    let mut c = Connection::client_with_early_data(cc, "server.test", REQUEST).unwrap();
    let flight = c.take_tls();
    let mut first = Connection::server(sc.clone()).unwrap();
    first.read_tls(&flight).unwrap();
    assert_eq!(first.available(), REQUEST.len());
    for _ in 0..3 {
        let mut replay = Connection::server(sc.clone()).unwrap();
        replay
            .read_tls(&flight)
            .expect("a replay is skipped, not fatal");
        assert_eq!(replay.available(), 0, "replayed early data was delivered");
        assert_eq!(replay.report().early_data, "early-data:rejected");
    }
}

static NOW: AtomicU64 = AtomicU64::new(0);
fn fake_now() -> u64 {
    NOW.load(Ordering::SeqCst)
}

/// REQ-0RTT-002: a ticket age that does not match the server's view is
/// refused, and the client gets its data back.
#[test]
fn a_stale_first_flight_is_refused_and_returned() {
    NOW.store(now(), Ordering::SeqCst);
    let pki = Pki::new(KeyKind::EcdsaP256, "server.test");
    let (cc, _) = configs(&pki, true);
    let mut sc = pki.server_config(Profile::Default);
    sc.early_data = Some(EarlyDataPolicy::new(16_384));
    sc.common.clock = fake_now;
    let sc = Arc::new(sc);
    get_ticket(&cc, &sc);
    NOW.store(now() + 60, Ordering::SeqCst);
    let mut c = Connection::client_with_early_data(cc, "server.test", REQUEST).unwrap();
    let (s, before) = early_handshake(&mut c, &sc);
    assert_eq!(before, 0);
    assert_eq!(s.state(), HandshakeState::Connected, "{:?}", s.error());
    assert_eq!(c.report().early_data, "early-data:rejected");
    assert_eq!(c.take_rejected_early_data().as_deref(), Some(REQUEST));
}

/// REQ-0RTT-004: a server without a 0-RTT policy skips the data and the
/// handshake still completes.
#[test]
fn a_server_without_a_policy_skips_early_data() {
    let pki = Pki::new(KeyKind::EcdsaP256, "server.test");
    let (cc, sc_with) = configs(&pki, true);
    get_ticket(&cc, &sc_with);
    let mut plain = pki.server_config(Profile::Default);
    plain.tickets = sc_with.tickets.clone();
    let plain = Arc::new(plain);
    let mut c = Connection::client_with_early_data(cc, "server.test", REQUEST).unwrap();
    let (s, before) = early_handshake(&mut c, &plain);
    assert_eq!(before, 0);
    assert_eq!(s.state(), HandshakeState::Connected, "{:?}", s.error());
    assert!(s.report().resumed);
    assert_eq!(c.take_rejected_early_data().as_deref(), Some(REQUEST));
}

/// A HelloRetryRequest ends 0-RTT; the second hello goes in the clear.
#[test]
fn a_hello_retry_request_ends_early_data() {
    let pki = Pki::new(KeyKind::EcdsaP256, "server.test");
    let mut cc = pki.client_config(Profile::Default);
    cc.early_data = true;
    cc.common.groups = vec![NamedGroup::X25519, NamedGroup::Secp384r1];
    cc.initial_key_shares = 1;
    let cc = Arc::new(cc);
    let mut sc = pki.server_config(Profile::Default);
    sc.early_data = Some(EarlyDataPolicy::new(16_384));
    let first = Arc::new(sc.clone());
    get_ticket(&cc, &first);
    sc.common.groups = vec![NamedGroup::Secp384r1];
    let sc = Arc::new(sc);
    let mut c = Connection::client_with_early_data(cc, "server.test", REQUEST).unwrap();
    let (s, before) = early_handshake(&mut c, &sc);
    assert_eq!(before, 0);
    assert!(c.report().hello_retry);
    assert_eq!(s.state(), HandshakeState::Connected, "{:?}", s.error());
    assert_eq!(c.take_rejected_early_data().as_deref(), Some(REQUEST));
}

/// REQ-0RTT-001: without `early_data` in the client configuration, nothing
/// is sent early, and the data comes back.
#[test]
fn early_data_is_opt_in() {
    let pki = Pki::new(KeyKind::EcdsaP256, "server.test");
    let (_, sc) = configs(&pki, true);
    let cc = Arc::new(pki.client_config(Profile::Default));
    get_ticket(&cc, &sc);
    let mut c = Connection::client_with_early_data(cc, "server.test", REQUEST).unwrap();
    let (s, before) = early_handshake(&mut c, &sc);
    assert_eq!(before, 0);
    assert_eq!(s.report().early_data, "early-data:not-offered");
    assert_eq!(c.take_rejected_early_data().as_deref(), Some(REQUEST));
}

mod quic_0rtt {
    use super::*;
    use iron_socket_layer::quic::{KeyInstall, QuicConnection, Version};
    use iron_socket_layer::Level;

    const SERVER_PARAMS: &[u8] = b"\x04\x04\x80\x10\x00\x00";

    fn quic_configs(pki: &Pki) -> (Arc<ClientConfig>, Arc<ServerConfig>) {
        let mut cc = pki.client_config(Profile::Default).with_alpn(&[b"h3"]);
        cc.early_data = true;
        let mut sc = pki.server_config(Profile::Default).with_alpn(&[b"h3"]);
        sc.early_data = Some(EarlyDataPolicy::new(16_384));
        (Arc::new(cc), Arc::new(sc))
    }

    /// Run a QUIC handshake to completion, returning every key each side installed.
    fn run(c: &mut QuicConnection, s: &mut QuicConnection) -> (Vec<KeyInstall>, Vec<KeyInstall>) {
        let (mut ck, mut sk) = (Vec::new(), Vec::new());
        for _ in 0..8 {
            while let Ok(Some(k)) = c.next_key_change() {
                ck.push(k);
            }
            while let Some((l, d)) = c.write_handshake() {
                let _ = s.read_handshake(l, &d);
            }
            while let Ok(Some(k)) = s.next_key_change() {
                sk.push(k);
            }
            while let Some((l, d)) = s.write_handshake() {
                let _ = c.read_handshake(l, &d);
            }
        }
        (ck, sk)
    }

    fn first_session(cc: &Arc<ClientConfig>, sc: &Arc<ServerConfig>) {
        let mut c = QuicConnection::client(cc.clone(), "server.test", b"c", Version::V1).unwrap();
        let mut s = QuicConnection::server(sc.clone(), SERVER_PARAMS, Version::V1).unwrap();
        run(&mut c, &mut s);
        assert!(!c.is_handshaking(), "{:?}", c.error());
        assert_eq!(c.report().tickets_received, 1);
    }

    /// REQ-0RTT-005: 0-RTT keys go to the QUIC stack on both sides and agree;
    /// the client learns the transport parameters to reuse.
    #[test]
    fn quic_0rtt_keys_are_exported_and_agree() {
        let pki = Pki::new(KeyKind::EcdsaP256, "server.test");
        let (cc, sc) = quic_configs(&pki);
        first_session(&cc, &sc);
        let mut c =
            QuicConnection::client_with_early_data(cc, "server.test", b"c", Version::V1).unwrap();
        assert_eq!(c.early_transport_parameters(), Some(SERVER_PARAMS));
        let mut s = QuicConnection::server(sc, SERVER_PARAMS, Version::V1).unwrap();
        let (ck, sk) = run(&mut c, &mut s);
        let cw = ck
            .iter()
            .find(|k| k.level == Level::Early && k.write)
            .expect("client 0-RTT key");
        let sr = sk
            .iter()
            .find(|k| k.level == Level::Early && !k.write)
            .expect("server 0-RTT key");
        let mut p = *b"0-RTT STREAM frame";
        let tag = cw.keys.packet.seal(0, b"hdr", &mut p).unwrap();
        let mut both = p.to_vec();
        both.extend_from_slice(&tag);
        let n = sr.keys.packet.open(0, b"hdr", &mut both).unwrap();
        assert_eq!(&both[..n], b"0-RTT STREAM frame");
        assert!(!c.is_handshaking(), "{:?}", c.error());
        assert_eq!(c.report().early_data, "early-data:accepted");
        assert_eq!(s.report().early_data, "early-data:accepted");
    }

    /// REQ-0RTT-005: changed transport parameters mean no 0-RTT.
    #[test]
    fn changed_transport_parameters_reject_quic_0rtt() {
        let pki = Pki::new(KeyKind::EcdsaP256, "server.test");
        let (cc, sc) = quic_configs(&pki);
        first_session(&cc, &sc);
        let mut c =
            QuicConnection::client_with_early_data(cc, "server.test", b"c", Version::V1).unwrap();
        let mut s = QuicConnection::server(sc, b"\x04\x04\x80\x20\x00\x00", Version::V1).unwrap();
        let (_, sk) = run(&mut c, &mut s);
        assert!(!sk.iter().any(|k| k.level == Level::Early));
        assert!(!c.is_handshaking(), "{:?}", c.error());
        assert_eq!(c.report().early_data, "early-data:rejected");
    }

    /// REQ-0RTT-005: a ticket from TLS over TCP never enables QUIC 0-RTT.
    #[test]
    fn a_tcp_ticket_is_not_used_for_quic_0rtt() {
        let pki = Pki::new(KeyKind::EcdsaP256, "server.test");
        let (cc, sc) = quic_configs(&pki);
        let (mut c, mut s) = connect(cc.clone(), sc.clone(), "server.test").unwrap();
        c.read_tls(&s.take_tls()).unwrap();
        let q =
            QuicConnection::client_with_early_data(cc, "server.test", b"c", Version::V1).unwrap();
        assert_eq!(q.report().early_data, "early-data:not-offered");
        assert!(q.early_transport_parameters().is_none());
    }

    /// REQ-0RTT-002 over QUIC: a replayed Initial gets no 0-RTT key.
    #[test]
    fn a_replayed_quic_hello_gets_no_0rtt() {
        let pki = Pki::new(KeyKind::EcdsaP256, "server.test");
        let (cc, sc) = quic_configs(&pki);
        first_session(&cc, &sc);
        let mut c =
            QuicConnection::client_with_early_data(cc, "server.test", b"c", Version::V1).unwrap();
        while let Ok(Some(_)) = c.next_key_change() {}
        let (level, hello) = c.write_handshake().unwrap();
        let mut first = QuicConnection::server(sc.clone(), SERVER_PARAMS, Version::V1).unwrap();
        first.read_handshake(level, &hello).unwrap();
        let mut keys = Vec::new();
        while let Ok(Some(k)) = first.next_key_change() {
            keys.push(k.level);
        }
        assert!(keys.contains(&Level::Early));
        let mut replay = QuicConnection::server(sc, SERVER_PARAMS, Version::V1).unwrap();
        replay.read_handshake(level, &hello).unwrap();
        while let Ok(Some(k)) = replay.next_key_change() {
            assert_ne!(k.level, Level::Early, "a replay was given a 0-RTT key");
        }
    }
}
