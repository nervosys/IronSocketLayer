//! Session resumption: PSK with (EC)DHE from stateless tickets.

mod common;

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use common::*;
use ironsocketlayer::config::{ClientAuth, ClientConfig, PeerVerification, Profile, ServerConfig};
use ironsocketlayer::crypto::sign::KeyKind;
use ironsocketlayer::enums::{AlertDescription, NamedGroup};
use ironsocketlayer::report::Property;
use ironsocketlayer::resumption::{StoredTicket, TicketStore};
use ironsocketlayer::{Connection, ErrorKind};

/// Deliver the tickets a server queued after the handshake.
fn deliver_tickets(c: &mut Connection, s: &mut Connection) {
    let t = s.take_tls();
    if !t.is_empty() {
        c.read_tls(&t).unwrap();
    }
}

fn received(c: &Connection, id: &str) -> bool {
    c.report().events.iter().any(|e| e.event_matches(id))
}

trait EventExt {
    fn event_matches(&self, detail: &str) -> bool;
}

impl EventExt for ironsocketlayer::report::Event {
    fn event_matches(&self, detail: &str) -> bool {
        self.id == "event:received" && self.detail == detail
    }
}

/// A store that hands out whatever it holds, whatever the name or time, and
/// lets a test alter the ticket first: it plays a confused or hostile client.
#[derive(Debug, Default)]
struct Rigged {
    held: Mutex<Vec<StoredTicket>>,
}

impl TicketStore for Rigged {
    fn put(&self, t: StoredTicket) {
        self.held.lock().unwrap().push(t);
    }
    fn take(&self, _: &str, _: u64) -> Option<StoredTicket> {
        self.held.lock().unwrap().pop()
    }
}

fn first_session(cc: &Arc<ClientConfig>, sc: &Arc<ServerConfig>, name: &str) {
    let (mut c, mut s) = connect(cc.clone(), sc.clone(), name).unwrap();
    deliver_tickets(&mut c, &mut s);
    assert_eq!(c.report().tickets_received, 1);
    assert!(!c.report().resumed);
}

#[test]
fn a_ticket_resumes_without_certificates_and_keeps_post_quantum_key_exchange() {
    let pki = Pki::new(KeyKind::EcdsaP256, "server.test");
    let cc = Arc::new(pki.client_config(Profile::Default));
    let sc = Arc::new(pki.server_config(Profile::Default));
    first_session(&cc, &sc, "server.test");

    let (mut c, mut s) = connect(cc.clone(), sc.clone(), "server.test").unwrap();
    for r in [c.report(), s.report()] {
        assert!(r.resumed, "{}", r.to_json());
        // psk_dhe_ke: a fresh hybrid key exchange still ran.
        assert_eq!(r.group, Some(NamedGroup::X25519MlKem768));
        assert!(r.has(Property::ForwardSecrecy));
        assert!(r.has(Property::PostQuantumKeyExchange));
        assert!(r.has(Property::ServerAuthenticated));
    }
    assert!(
        !received(&c, "message:certificate"),
        "a resumed handshake carried a certificate"
    );
    // The report still describes the server the ticket came from.
    assert_eq!(c.report().peer_subject_cn.as_deref(), Some("server.test"));
    // REQ-RPT-003: including the names its certificate was issued for.
    assert_eq!(c.report().peer_names, ["server.test"]);
    assert!(c.report().to_json().contains(r#""resumed":true"#));
    exchange(&mut c, &mut s);
}

/// REQ-PSK-004: a ticket is used once; the next connection needs a new one.
#[test]
fn tickets_are_single_use() {
    let pki = Pki::new(KeyKind::EcdsaP256, "server.test");
    let cc = Arc::new(pki.client_config(Profile::Default));
    let sc = Arc::new(pki.server_config(Profile::Default));
    first_session(&cc, &sc, "server.test");
    let (c, _s) = connect(cc.clone(), sc.clone(), "server.test").unwrap();
    assert!(c.report().resumed);
    // The second session's ticket was not delivered, so none is left.
    let (c, _s) = connect(cc.clone(), sc.clone(), "server.test").unwrap();
    assert!(!c.report().resumed);
}

fn rigged_client(pki: &Pki) -> (Arc<ClientConfig>, Arc<Rigged>) {
    let store = Arc::new(Rigged::default());
    let mut cc = pki.client_config(Profile::Default);
    cc.tickets = Some(store.clone());
    (Arc::new(cc), store)
}

/// REQ-PSK-005: a ticket issued for one name does not resume another.
#[test]
fn a_ticket_for_another_name_falls_back_to_a_full_handshake() {
    let a = Pki::new(KeyKind::EcdsaP256, "a.test");
    let b = Pki::with_ca(&a, KeyKind::EcdsaP256, "b.test");
    let mut sc = a.server_config(Profile::Default);
    sc.identities.push(b.server_identity());
    let sc = Arc::new(sc);
    let (cc, _) = rigged_client(&a);
    first_session(&cc, &sc, "a.test");
    let (c, s) = connect(cc, sc, "b.test").unwrap();
    assert!(!c.report().resumed && !s.report().resumed);
    assert!(received(&c, "message:certificate"));
}

/// REQ-PSK-003: an altered ticket is not ours; the server ignores it.
#[test]
fn a_forged_ticket_falls_back_to_a_full_handshake() {
    let pki = Pki::new(KeyKind::EcdsaP256, "server.test");
    let sc = Arc::new(pki.server_config(Profile::Default));
    let (cc, store) = rigged_client(&pki);
    first_session(&cc, &sc, "server.test");
    let mut t = store.held.lock().unwrap().pop().unwrap();
    let n = t.ticket.len();
    t.ticket[n / 2] ^= 0x40;
    store.put(t);
    let (c, _) = connect(cc, sc, "server.test").unwrap();
    assert!(!c.report().resumed);
}

/// REQ-PSK-002: a valid ticket with a binder made from the wrong PSK is fatal.
#[test]
fn a_binder_from_the_wrong_psk_is_a_decrypt_error() {
    let pki = Pki::new(KeyKind::EcdsaP256, "server.test");
    let sc = Arc::new(pki.server_config(Profile::Default));
    let (cc, store) = rigged_client(&pki);
    first_session(&cc, &sc, "server.test");
    let mut t = store.held.lock().unwrap().pop().unwrap();
    let mut psk = t.psk.as_bytes().to_vec();
    psk[0] ^= 1;
    t.psk = ironsocketlayer::crypto::Output::from_slice(&psk).unwrap();
    store.put(t);
    let err = connect(cc, sc, "server.test").unwrap_err();
    assert_eq!(err.server.map(|e| e.kind()), Some(ErrorKind::DecryptError));
    assert_eq!(
        err.client.and_then(|e| e.peer_alert()),
        Some(AlertDescription::DecryptError)
    );
}

static NOW: AtomicU64 = AtomicU64::new(0);

fn fake_now() -> u64 {
    NOW.load(Ordering::SeqCst)
}

/// REQ-PSK-003: the server refuses a ticket past its lifetime even when the
/// client offers it.
#[test]
fn an_expired_ticket_is_not_accepted() {
    NOW.store(now(), Ordering::SeqCst);
    let pki = Pki::new(KeyKind::EcdsaP256, "server.test");
    let mut sc = pki.server_config(Profile::Default);
    sc.common.clock = fake_now;
    sc.ticket_lifetime = 600;
    let sc = Arc::new(sc);
    let (cc, _) = rigged_client(&pki);
    first_session(&cc, &sc, "server.test");
    NOW.store(now() + 601, Ordering::SeqCst);
    let (c, _) = connect(cc, sc, "server.test").unwrap();
    assert!(!c.report().resumed);
}

#[test]
fn resumption_survives_a_hello_retry_request() {
    let pki = Pki::new(KeyKind::EcdsaP256, "server.test");
    let mut cc = pki.client_config(Profile::Default);
    cc.common.groups = vec![NamedGroup::X25519, NamedGroup::Secp384r1];
    cc.initial_key_shares = 1;
    let cc = Arc::new(cc);
    let mut sc = pki.server_config(Profile::Default);
    sc.common.groups = vec![NamedGroup::Secp384r1];
    let sc = Arc::new(sc);
    first_session(&cc, &sc, "server.test");
    let (mut c, mut s) = connect(cc, sc, "server.test").unwrap();
    assert!(c.report().hello_retry && c.report().resumed && s.report().resumed);
    exchange(&mut c, &mut s);
}

/// REQ-PSK-005: a ticket from a session without client authentication does
/// not satisfy a server that requires it; one from an authenticated session
/// does, and the resumed report names the client.
#[test]
fn client_authentication_carries_over_and_is_not_invented() {
    let pki = Pki::new(KeyKind::EcdsaP256, "server.test");
    let id = pki.client_identity(KeyKind::Ed25519, "agent-9");
    let cc = Arc::new(pki.client_config(Profile::Default).with_identity(id));
    let open = pki.server_config(Profile::Default);
    let keys = open.tickets.clone();
    let open = Arc::new(open);
    let mut strict = pki
        .server_config(Profile::Default)
        .with_client_auth(ClientAuth::Required(PeerVerification::Roots(pki.roots())));
    strict.tickets = keys;
    let strict = Arc::new(strict);

    first_session(&cc, &open, "server.test");
    let (mut c, mut s) = connect(cc.clone(), strict.clone(), "server.test").unwrap();
    assert!(
        !s.report().resumed,
        "an unauthenticated ticket satisfied client authentication"
    );
    assert!(s.report().has(Property::MutualAuthentication));
    deliver_tickets(&mut c, &mut s);

    let (c, s) = connect(cc, strict, "server.test").unwrap();
    assert!(s.report().resumed && c.report().resumed);
    assert!(s.report().has(Property::MutualAuthentication));
    assert_eq!(s.report().peer_subject_cn.as_deref(), Some("agent-9"));
}

/// REQ-PSK-001: the client offers only psk_dhe_ke, and a server never
/// resumes on psk_ke alone -- even when the binder is valid for that hello.
#[test]
fn only_psk_with_key_exchange_is_offered_or_accepted() {
    use ironsocketlayer::crypto::HashAlg;
    use ironsocketlayer::key_schedule::EarlyStage;
    let pki = Pki::new(KeyKind::EcdsaP256, "server.test");
    let sc = Arc::new(pki.server_config(Profile::Default));
    let (cc, store) = rigged_client(&pki);
    first_session(&cc, &sc, "server.test");
    let ticket = store.held.lock().unwrap().last().cloned().unwrap();
    let mut c = Connection::client(cc, "server.test").unwrap();
    let mut hello = c.take_tls();
    let ch = ironsocketlayer::msgs::ClientHello::decode(&hello[9..]).unwrap();
    assert_eq!(ch.psk_modes, vec![1]);
    let binders_len = ch.psk.as_ref().unwrap().binders_len();
    // Rewrite the modes to psk_ke only (0) and re-bind the hello correctly, as
    // a client holding the PSK could: only the mode rule can refuse it now.
    let at = hello
        .windows(6)
        .position(|w| w == [0x00, 0x2d, 0x00, 0x02, 0x01, 0x01])
        .unwrap();
    hello[at + 5] = 0x00;
    let end = hello.len();
    let th = HashAlg::Sha256.digest(&hello[5..end - binders_len]);
    let binder = EarlyStage::new(HashAlg::Sha256, Some(ticket.psk.as_bytes()))
        .unwrap()
        .resumption_binder(th.as_bytes())
        .unwrap();
    hello[end - 32..].copy_from_slice(binder.as_bytes());
    let mut s = Connection::server(sc).unwrap();
    s.read_tls(&hello).unwrap();
    assert!(!s.report().resumed);
    assert!(!s
        .report()
        .events
        .iter()
        .any(|e| e.id == "event:session-resumed"));
}

#[test]
fn the_dal_a_profile_does_not_resume() {
    let pki = Pki::with_kinds(KeyKind::EcdsaP384, KeyKind::EcdsaP384, "fcc.test");
    assert!(pki.client_config(Profile::DalA).tickets.is_none());
    assert!(pki.server_config(Profile::DalA).tickets.is_none());
}

#[test]
fn quic_sessions_resume_too() {
    use ironsocketlayer::quic::{QuicConnection, Version};
    use ironsocketlayer::Level;
    let pki = Pki::new(KeyKind::EcdsaP256, "server.test");
    let cc = Arc::new(pki.client_config(Profile::Default).with_alpn(&[b"h3"]));
    let sc = Arc::new(pki.server_config(Profile::Default).with_alpn(&[b"h3"]));
    let run = || {
        let mut c = QuicConnection::client(cc.clone(), "server.test", b"c", Version::V1).unwrap();
        let mut s = QuicConnection::server(sc.clone(), b"s", Version::V1).unwrap();
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
        let _ = Level::Application;
        c.report().resumed
    };
    assert!(!run());
    assert!(run(), "second QUIC session did not resume");
}

/// A client that cannot resume is not sent tickets it would discard, and a
/// client that can advertises psk_dhe_ke even before it holds a ticket.
#[test]
fn tickets_go_only_to_clients_that_can_use_them() {
    let pki = Pki::new(KeyKind::EcdsaP256, "server.test");
    let sc = Arc::new(pki.server_config(Profile::Default));
    let mut cc = pki.client_config(Profile::Default);
    cc.tickets = None;
    let (mut c, mut s) = connect(Arc::new(cc), sc.clone(), "server.test").unwrap();
    deliver_tickets(&mut c, &mut s);
    assert_eq!(c.report().tickets_received, 0);
    let cc = Arc::new(pki.client_config(Profile::Default));
    let mut fresh = Connection::client(cc, "server.test").unwrap();
    let hello = fresh.take_tls();
    let ch = ironsocketlayer::msgs::ClientHello::decode(&hello[9..]).unwrap();
    assert_eq!(ch.psk_modes, vec![1]);
    assert!(ch.psk.is_none());
}
