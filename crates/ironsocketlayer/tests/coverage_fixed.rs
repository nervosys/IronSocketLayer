//! Fixed engine (`src/fixed.rs`) branch outcomes that the rest of the suite
//! never drove: configuration refusals, state checks, malformed or hostile
//! plaintext flights and alternative negotiated paths. Each test asserts the
//! specific outcome the requirement demands, not merely that something failed.
//! Peer misbehaviour inside encrypted flights is tested in `src/fixed.rs`'s
//! own test module, which can seal records with the peer's traffic secret.
mod common;
mod fixed_support;

use common::*;
use fixed_support::Buffers;
use ironsocketlayer::config::{
    ClientAuth, ClientConfig, PeerVerification, Profile, Revocation, ServerConfig,
};
use ironsocketlayer::crypto::sign::KeyKind;
use ironsocketlayer::enums::{CipherSuite, NamedGroup, SignatureScheme};
use ironsocketlayer::fixed::{Connection, Limits};
use ironsocketlayer::report::{HandshakeState, Property};
use ironsocketlayer::x509::ocsp::CertStatus;
use ironsocketlayer::{Error, ErrorKind, Result};
use std::sync::Arc;

const NAME: &str = "server.test";

fn rng() -> ic_drbg::Rng {
    ic_drbg::Rng::from_os().unwrap()
}

fn transfer(from: &mut Connection<'_>, to: &mut Connection<'_>) -> Result<bool> {
    let n = from.outgoing().len();
    if n != 0 {
        to.receive(from.outgoing())?;
    }
    from.consume_outgoing(n)?;
    Ok(n != 0)
}

fn pump(c: &mut Connection<'_>, s: &mut Connection<'_>) -> Result<()> {
    for _ in 0..12 {
        let a = transfer(c, s)?;
        let b = transfer(s, c)?;
        if c.is_connected() && s.is_connected() {
            return Ok(());
        }
        if !a && !b {
            break;
        }
    }
    Err(Error::new(ErrorKind::InvalidState, "test pump stalled"))
}

/// Everything queued, and the queue emptied.
fn take(conn: &mut Connection<'_>) -> Vec<u8> {
    let bytes = conn.outgoing().to_vec();
    conn.consume_outgoing(bytes.len()).unwrap();
    bytes
}

/// Client and server configurations without tickets (the fixed engine
/// refuses them), both on the default profile.
fn configs(pki: &Pki) -> (ClientConfig, ServerConfig) {
    let mut cc = pki.client_config(Profile::Default);
    cc.tickets = None;
    let mut sc = pki.server_config(Profile::Default);
    sc.tickets = None;
    (cc, sc)
}

/// Build both sides with these limits and buffers, pump the handshake and
/// hand the outcome and both connections to `f`.
fn handshake<R>(
    cc: &ClientConfig,
    sc: &ServerConfig,
    name: &str,
    limits: (Limits, Limits),
    f: impl FnOnce(Result<()>, &mut Connection<'_>, &mut Connection<'_>) -> R,
) -> R {
    let (mut cb, mut sb) = (Buffers::new(), Buffers::new());
    let (mut cr, mut sr) = (rng(), rng());
    let mut c = Connection::client(cc, name, &mut cr, cb.storage(), limits.0).unwrap();
    let mut s = Connection::server(sc, &mut sr, sb.storage(), limits.1).unwrap();
    let result = pump(&mut c, &mut s);
    f(result, &mut c, &mut s)
}

fn default_limits() -> (Limits, Limits) {
    (Limits::default(), Limits::default())
}

/// The error a failed side latched.
fn latched(conn: &Connection<'_>) -> Error {
    conn.report().error.expect("connection did not fail")
}

/// Assert a failure is latched: the same error again, nothing queued.
fn assert_latched(conn: &mut Connection<'_>, error: Error) {
    assert_eq!(conn.report().error, Some(error));
    assert_eq!(
        conn.receive(&[22]).unwrap_err(),
        error,
        "failure did not latch"
    );
    assert!(conn.outgoing().is_empty());
    assert!(!conn.is_connected());
    assert_eq!(conn.report().state, HandshakeState::Failed);
}

// ---------------------------------------------------------------------------
// Wire encoding helpers for hand-made plaintext flights.

fn v8(b: &[u8]) -> Vec<u8> {
    [&[b.len() as u8][..], b].concat()
}
fn v16(b: &[u8]) -> Vec<u8> {
    [&(b.len() as u16).to_be_bytes()[..], b].concat()
}
fn ext(ty: u16, body: &[u8]) -> Vec<u8> {
    [&ty.to_be_bytes()[..], &v16(body)].concat()
}
fn u16s(values: &[u16]) -> Vec<u8> {
    values.iter().flat_map(|v| v.to_be_bytes()).collect()
}
/// A handshake message in one plaintext record.
fn record(ty: u8, body: &[u8]) -> Vec<u8> {
    let len = body.len() as u32;
    let msg = [&[ty][..], &len.to_be_bytes()[1..], body].concat();
    [&[22, 3, 3][..], &(msg.len() as u16).to_be_bytes(), &msg].concat()
}

const X25519: u16 = 0x001d;
const P256: u16 = 0x0017;
const P384: u16 = 0x0018;
const AES128: u16 = 0x1301;
const AES256: u16 = 0x1302;
const ECDSA_P256: u16 = 0x0403;

fn versions() -> Vec<u8> {
    ext(43, &[2, 3, 4])
}
fn groups(list: &[u16]) -> Vec<u8> {
    ext(10, &v16(&u16s(list)))
}
fn schemes() -> Vec<u8> {
    ext(13, &v16(&u16s(&[ECDSA_P256])))
}
/// key_share entries with placeholder share bytes. The engine checks the
/// list's structure before it uses any share, which is what these tests reach.
fn shares(list: &[u16]) -> Vec<u8> {
    let entries: Vec<u8> = list
        .iter()
        .flat_map(|g| [&g.to_be_bytes()[..], &v16(&[4; 32])].concat())
        .collect();
    ext(51, &v16(&entries))
}

/// A ClientHello record with this random byte, suites and extensions.
fn client_hello(random: u8, suites: &[u8], exts: &[Vec<u8>]) -> Vec<u8> {
    let body = [
        &[3, 3][..],
        &[random; 32],
        &v8(&[7; 32]),
        &v16(suites),
        &[1, 0],
        &v16(&exts.concat()),
    ]
    .concat();
    record(1, &body)
}

/// A ServerHello (or, with HRR_RANDOM, HelloRetryRequest) record.
fn server_hello(random: &[u8; 32], sid: &[u8], suite: u16, comp: u8, exts: &[Vec<u8>]) -> Vec<u8> {
    let body = [
        &[3, 3][..],
        random,
        &v8(sid),
        &suite.to_be_bytes(),
        &[comp],
        &v16(&exts.concat()),
    ]
    .concat();
    record(2, &body)
}

/// The legacy session ID of a ClientHello record the client queued.
fn session_id(hello: &[u8]) -> Vec<u8> {
    let at = 5 + 4 + 2 + 32;
    hello[at + 1..at + 1 + usize::from(hello[at])].to_vec()
}

/// The ClientHello record a client with this configuration queues first.
fn first_hello(cc: &ClientConfig, name: &str) -> Vec<u8> {
    let (mut b, mut r) = (Buffers::new(), rng());
    let c = Connection::client(cc, name, &mut r, b.storage(), Limits::default()).unwrap();
    c.outgoing().to_vec()
}

/// One extension body from a ClientHello record, if present.
fn hello_extension(hello: &[u8], ty: u16) -> Option<Vec<u8>> {
    let mut at = 5 + 4 + 2 + 32;
    at += 1 + usize::from(hello[at]);
    at += 2 + usize::from(u16::from_be_bytes([hello[at], hello[at + 1]]));
    at += 1 + usize::from(hello[at]);
    let end = at + 2 + usize::from(u16::from_be_bytes([hello[at], hello[at + 1]]));
    at += 2;
    while at < end {
        let t = u16::from_be_bytes([hello[at], hello[at + 1]]);
        let n = usize::from(u16::from_be_bytes([hello[at + 2], hello[at + 3]]));
        if t == ty {
            return Some(hello[at + 4..at + 4 + n].to_vec());
        }
        at += 4 + n;
    }
    None
}

// ---------------------------------------------------------------------------
// Configuration and storage refusals.

/// REQ-FIX-005: slot limits outside their documented ranges (certificates
/// 1..=8, extensions and events 1..=64, names at most 253 bytes, at least
/// one ALPN slot) are refused as InvalidConfig, for client and server alike.
#[test]
fn slot_limits_outside_their_ranges_are_invalid_config() {
    let pki = Pki::new(KeyKind::EcdsaP256, NAME);
    let (cc, sc) = configs(&pki);
    let d = Limits::default();
    let cases = [
        (
            "no certificate slot",
            Limits {
                certificates: 0,
                ..d
            },
        ),
        (
            "nine certificate slots",
            Limits {
                certificates: 9,
                ..d
            },
        ),
        ("no extension slot", Limits { extensions: 0, ..d }),
        (
            "65 extension slots",
            Limits {
                extensions: 65,
                ..d
            },
        ),
        ("no event slot", Limits { events: 0, ..d }),
        ("65 event slots", Limits { events: 65, ..d }),
        ("254-byte names", Limits { name: 254, ..d }),
        (
            "no ALPN slot",
            Limits {
                alpn_protocols: 0,
                ..d
            },
        ),
    ];
    for (what, limits) in cases {
        let (mut b, mut r) = (Buffers::new(), rng());
        let e = Connection::client(&cc, NAME, &mut r, b.storage(), limits)
            .err()
            .unwrap_or_else(|| panic!("client accepted {what}"));
        assert_eq!(e.kind(), ErrorKind::InvalidConfig, "{what}: {e}");
        let (mut b, mut r) = (Buffers::new(), rng());
        let e = Connection::server(&sc, &mut r, b.storage(), limits)
            .err()
            .unwrap_or_else(|| panic!("server accepted {what}"));
        assert_eq!(e.kind(), ErrorKind::InvalidConfig, "{what}: {e}");
    }
    // The extreme legal values are accepted.
    let edge = Limits {
        certificates: 8,
        extensions: 64,
        events: 64,
        name: 253,
        alpn_protocols: 1,
    };
    let (mut b, mut r) = (Buffers::new(), rng());
    Connection::client(&cc, NAME, &mut r, b.storage(), edge).unwrap();
    let lowest = Limits {
        certificates: 1,
        extensions: 1,
        events: 1,
        ..edge
    };
    let (mut b, mut r) = (Buffers::new(), rng());
    Connection::server(&sc, &mut r, b.storage(), lowest).unwrap();
}

/// REQ-FIX-005: a configuration that does not fit the fixed slots (more than
/// 32 signature schemes, more than ten key-exchange groups, or a group listed
/// twice, which would need two key slots) is refused when the connection is
/// created.
#[test]
fn configuration_beyond_the_fixed_slots_is_refused() {
    let pki = Pki::new(KeyKind::EcdsaP256, NAME);
    let (cc, _) = configs(&pki);
    let attempt = |c: &ClientConfig| {
        let (mut b, mut r) = (Buffers::new(), rng());
        Connection::client(c, NAME, &mut r, b.storage(), Limits::default())
            .err()
            .expect("configuration accepted")
    };
    let mut c = cc.clone();
    c.common.schemes = vec![SignatureScheme::EcdsaSecp256r1Sha256; 33];
    let e = attempt(&c);
    assert_eq!(e.kind(), ErrorKind::CapacityExceeded, "{e}");
    assert_eq!(e.context(), "configuration slot capacity");
    // 32 schemes still fit.
    c.common.schemes.truncate(32);
    let (mut b, mut r) = (Buffers::new(), rng());
    Connection::client(&c, NAME, &mut r, b.storage(), Limits::default()).unwrap();

    let mut c = cc.clone();
    c.common.groups = vec![NamedGroup::X25519; 11];
    let e = attempt(&c);
    assert_eq!(e.kind(), ErrorKind::InvalidConfig, "{e}");
    assert_eq!(
        e.context(),
        "fixed key slot groups must be unique and fit ten slots"
    );

    let mut c = cc.clone();
    c.common.groups = vec![
        NamedGroup::X25519,
        NamedGroup::Secp256r1,
        NamedGroup::X25519,
    ];
    let e = attempt(&c);
    assert_eq!(e.kind(), ErrorKind::InvalidConfig, "{e}");
    assert_eq!(
        e.context(),
        "fixed key slot groups must be unique and fit ten slots"
    );
}

/// REQ-FIX-005: a vector longer than its wire length prefix can express
/// (an ALPN list over 65535 bytes) fails with CapacityExceeded rather than
/// being truncated into a malformed ClientHello.
#[test]
fn an_extension_longer_than_its_length_prefix_is_capacity() {
    let pki = Pki::new(KeyKind::EcdsaP256, NAME);
    let (mut cc, _) = configs(&pki);
    cc.common.alpn = (0..300u16)
        .map(|i| {
            let mut p = vec![b'a'; 255];
            p[..2].copy_from_slice(&i.to_be_bytes());
            p
        })
        .collect();
    let mut b = Buffers::new();
    b.scratch.resize(200_000, 0);
    let limits = Limits {
        alpn_protocols: 300,
        ..Limits::default()
    };
    let mut r = rng();
    let e = Connection::client(&cc, NAME, &mut r, b.storage(), limits)
        .err()
        .expect("an oversized ALPN list was encoded");
    assert_eq!(e.kind(), ErrorKind::CapacityExceeded, "{e}");
    assert_eq!(e.context(), "wire length prefix");
}

/// REQ-FIX-005: buffers too small for the configured key shares or for a
/// record, handshake or encoding header are refused at initialization.
#[test]
fn undersized_initial_storage_is_refused() {
    let pki = Pki::new(KeyKind::EcdsaP256, NAME);
    let (cc, sc) = configs(&pki);
    type Field = fn(&mut Buffers) -> &mut Vec<u8>;
    let fields: &[(&str, usize, Field)] = &[
        ("private key", 10, |b| &mut b.private_key),
        ("public key", 10, |b| &mut b.public_key),
        ("record", 4, |b| &mut b.record),
        ("handshake", 3, |b| &mut b.handshake),
        ("scratch", 3, |b| &mut b.scratch),
    ];
    for (what, size, field) in fields {
        let mut b = Buffers::new();
        field(&mut b).truncate(*size);
        let mut r = rng();
        let e = Connection::client(&cc, NAME, &mut r, b.storage(), Limits::default())
            .err()
            .unwrap_or_else(|| panic!("client accepted a {size}-byte {what} buffer"));
        assert_eq!(e.kind(), ErrorKind::CapacityExceeded, "{what}: {e}");
        assert_eq!(e.context(), "initial connection storage", "{what}");
        let mut b = Buffers::new();
        field(&mut b).truncate(*size);
        let mut r = rng();
        let e = Connection::server(&sc, &mut r, b.storage(), Limits::default())
            .err()
            .unwrap_or_else(|| panic!("server accepted a {size}-byte {what} buffer"));
        assert_eq!(e.kind(), ErrorKind::CapacityExceeded, "{what}: {e}");
    }
}

/// REQ-FIX-004: a server configured with ECH keys is refused, not run
/// without ECH.
#[test]
fn server_ech_configuration_is_refused() {
    let pki = Pki::new(KeyKind::EcdsaP256, NAME);
    let (_, mut sc) = configs(&pki);
    sc.ech = Some(Arc::new(
        ironsocketlayer::ech::EchServer::generate(3, "public.test", 64, &mut rng()).unwrap(),
    ));
    let (mut b, mut r) = (Buffers::new(), rng());
    let e = Connection::server(&sc, &mut r, b.storage(), Limits::default())
        .err()
        .expect("ECH server accepted");
    assert_eq!(e.kind(), ErrorKind::InvalidConfig);
    assert_eq!(
        e.context(),
        "requested server feature unavailable in fixed engine"
    );
}

/// REQ-FIX-005: a FIPS-profile connection whose IronCrypto module leaves
/// approved mode fails at its next operation with FipsModule, latches the
/// failure and erases its queued ClientHello. This is the only test in this
/// binary that touches the process-wide module mode.
#[test]
fn leaving_fips_approved_mode_latches_failure() {
    ironsocketlayer::policy::enable_fips().unwrap();
    let pki = Pki::new(KeyKind::EcdsaP256, NAME);
    let mut cc = pki.client_config(Profile::Fips140_3);
    cc.tickets = None;
    let (mut b, mut r) = (Buffers::new(), rng());
    let mut c = Connection::client(&cc, NAME, &mut r, b.storage(), Limits::default()).unwrap();
    assert!(!c.outgoing().is_empty());
    c.consume_outgoing(0).unwrap();
    ic_fips::set_mode(ic_fips::Mode::Unrestricted).unwrap();
    let e = c.consume_outgoing(0).unwrap_err();
    ic_fips::set_mode(ic_fips::Mode::Approved).unwrap();
    assert_eq!(e.kind(), ErrorKind::FipsModule, "{e}");
    assert_eq!(e.context(), "approved mode required");
    assert_latched(&mut c, e);
}

// ---------------------------------------------------------------------------
// Caller misuse and state checks.

/// REQ-FIX-005: consuming more outgoing bytes than are queued is refused
/// with InvalidState and latches, rather than slicing past the queue.
#[test]
fn consuming_beyond_the_outgoing_queue_latches() {
    let pki = Pki::new(KeyKind::EcdsaP256, NAME);
    let (cc, _) = configs(&pki);
    let (mut b, mut r) = (Buffers::new(), rng());
    let mut c = Connection::client(&cc, NAME, &mut r, b.storage(), Limits::default()).unwrap();
    let n = c.outgoing().len();
    let e = c.consume_outgoing(n + 1).unwrap_err();
    assert_eq!(e.kind(), ErrorKind::InvalidState);
    assert_eq!(e.context(), "outgoing consumption exceeds queue");
    assert_latched(&mut c, e);
}

/// REQ-FIX-004: application data, export, KeyUpdate and close need a
/// completed handshake, and nothing may be written after close_notify.
/// These caller errors are InvalidState and do not fail the connection; a
/// repeated close is a no-op that queues nothing.
#[test]
fn application_operations_respect_the_connection_state() {
    let pki = Pki::new(KeyKind::EcdsaP256, NAME);
    let (cc, sc) = configs(&pki);
    let (mut cb, mut sb) = (Buffers::new(), Buffers::new());
    let (mut cr, mut sr) = (rng(), rng());
    let mut c = Connection::client(&cc, NAME, &mut cr, cb.storage(), Limits::default()).unwrap();
    let mut s = Connection::server(&sc, &mut sr, sb.storage(), Limits::default()).unwrap();
    let state = |r: Result<()>, context: &str| {
        let e = r.expect_err(context);
        assert_eq!(e.kind(), ErrorKind::InvalidState, "{context}: {e}");
        assert_eq!(e.context(), context);
    };
    const WRITE: &str = "application write before handshake or after close";
    state(c.write_application(b"early"), WRITE);
    state(
        c.export(b"label", b"", &mut [0; 16]),
        "export before handshake",
    );
    state(c.key_update(false), "KeyUpdate unavailable");
    state(c.close(), "close before handshake");
    assert!(c.report().error.is_none());
    pump(&mut c, &mut s).unwrap();
    c.close().unwrap();
    let queued = c.outgoing().len();
    assert!(queued > 0);
    c.close().unwrap();
    assert_eq!(
        c.outgoing().len(),
        queued,
        "a second close_notify was queued"
    );
    state(c.write_application(b"late"), WRITE);
    state(c.key_update(true), "KeyUpdate unavailable");
    assert!(c.is_connected());
}

/// REQ-FIX-004: once the peer's close_notify arrives, further input (here
/// in the same call) is refused with Closed, and peer_closed() reports the
/// authenticated close.
#[test]
fn input_after_close_notify_is_refused() {
    let pki = Pki::new(KeyKind::EcdsaP256, NAME);
    let (cc, sc) = configs(&pki);
    handshake(&cc, &sc, NAME, default_limits(), |r, c, s| {
        r.unwrap();
        c.close().unwrap();
        let mut bytes = take(c);
        bytes.extend_from_slice(&[23, 3, 3, 0, 1, 0]);
        let e = s.receive(&bytes).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Closed, "{e}");
        assert!(s.peer_closed());
        assert_latched(s, e);
    });
}

// ---------------------------------------------------------------------------
// Record layer.

const CCS: [u8; 6] = [20, 3, 3, 0, 1, 1];

/// REQ-FIX-005: a change_cipher_spec record before the first ClientHello,
/// after the handshake, or a third one during it, is UnexpectedMessage
/// (RFC 8446 section 5); two during the handshake are tolerated.
#[test]
fn change_cipher_spec_outside_the_compatibility_window_is_unexpected() {
    let pki = Pki::new(KeyKind::EcdsaP256, NAME);
    let (cc, sc) = configs(&pki);
    // Before the first ClientHello.
    let (mut b, mut r) = (Buffers::new(), rng());
    let mut s = Connection::server(&sc, &mut r, b.storage(), Limits::default()).unwrap();
    let e = s.receive(&CCS).unwrap_err();
    assert_eq!(e.kind(), ErrorKind::UnexpectedMessage);
    assert_latched(&mut s, e);
    // A third during the handshake.
    let (mut b, mut r) = (Buffers::new(), rng());
    let mut c = Connection::client(&cc, NAME, &mut r, b.storage(), Limits::default()).unwrap();
    c.receive(&CCS).unwrap();
    c.receive(&CCS).unwrap();
    let e = c.receive(&CCS).unwrap_err();
    assert_eq!(e.kind(), ErrorKind::UnexpectedMessage);
    assert_latched(&mut c, e);
    // After the handshake.
    handshake(&cc, &sc, NAME, default_limits(), |r, c, _| {
        r.unwrap();
        let e = c.receive(&CCS).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::UnexpectedMessage);
        assert_latched(c, e);
    });
}

/// REQ-FIX-004: after a HelloRetryRequest a server accepts the client's
/// middlebox-compatibility change_cipher_spec before ClientHello2 (RFC 8446
/// appendix D.4) and completes the handshake.
#[test]
fn change_cipher_spec_after_a_retry_is_accepted() {
    let pki = Pki::new(KeyKind::EcdsaP256, NAME);
    let (mut cc, mut sc) = configs(&pki);
    cc.common.groups = vec![NamedGroup::X25519, NamedGroup::Secp256r1];
    cc.initial_key_shares = 1;
    sc.common.groups = vec![NamedGroup::Secp256r1];
    let (mut cb, mut sb) = (Buffers::new(), Buffers::new());
    let (mut cr, mut sr) = (rng(), rng());
    let mut c = Connection::client(&cc, NAME, &mut cr, cb.storage(), Limits::default()).unwrap();
    let mut s = Connection::server(&sc, &mut sr, sb.storage(), Limits::default()).unwrap();
    transfer(&mut c, &mut s).unwrap();
    assert_eq!(s.report().state, HandshakeState::WaitClientHello);
    transfer(&mut s, &mut c).unwrap();
    s.receive(&CCS).unwrap();
    pump(&mut c, &mut s).unwrap();
    assert_eq!(s.report().group, Some(NamedGroup::Secp256r1));
}

/// REQ-FIX-005: once record protection is on, a record whose legacy version
/// is not 0x0303 is UnexpectedMessage, refused before decryption.
#[test]
fn protected_record_with_another_legacy_version_is_unexpected() {
    let pki = Pki::new(KeyKind::EcdsaP256, NAME);
    let (cc, sc) = configs(&pki);
    handshake(&cc, &sc, NAME, default_limits(), |r, c, s| {
        r.unwrap();
        c.write_application(b"data").unwrap();
        let mut bytes = take(c);
        bytes[2] = 1;
        let e = s.receive(&bytes).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::UnexpectedMessage, "{e}");
        assert_latched(s, e);
    });
}

/// REQ-FIX-005: a plaintext record body over 2^14 bytes is RecordOverflow
/// (RFC 8446 section 5.1), even when the record buffer could hold it.
#[test]
fn oversized_plaintext_record_is_overflow() {
    let pki = Pki::new(KeyKind::EcdsaP256, NAME);
    let (_, sc) = configs(&pki);
    let (mut b, mut r) = (Buffers::new(), rng());
    let mut s = Connection::server(&sc, &mut r, b.storage(), Limits::default()).unwrap();
    let mut bytes = vec![22, 3, 3, 0x40, 0x01];
    bytes.resize(5 + (1 << 14) + 1, 1);
    let e = s.receive(&bytes).unwrap_err();
    assert_eq!(e.kind(), ErrorKind::RecordOverflow, "{e}");
    assert_eq!(e.context(), "plaintext record bound");
    assert_latched(&mut s, e);
}

/// REQ-FIX-005: an alert record that is not exactly two bytes is
/// UnexpectedMessage, and an alert other than close_notify fails the
/// connection with PeerAlert.
#[test]
fn alerts_are_parsed_strictly() {
    let pki = Pki::new(KeyKind::EcdsaP256, NAME);
    let (_, sc) = configs(&pki);
    for (input, kind) in [
        (
            &[21u8, 3, 3, 0, 3, 1, 0, 0][..],
            ErrorKind::UnexpectedMessage,
        ),
        (&[21, 3, 3, 0, 2, 2, 40][..], ErrorKind::PeerAlert),
    ] {
        let (mut b, mut r) = (Buffers::new(), rng());
        let mut s = Connection::server(&sc, &mut r, b.storage(), Limits::default()).unwrap();
        let e = s.receive(input).unwrap_err();
        assert_eq!(e.kind(), kind, "{input:?}: {e}");
        assert!(!s.peer_closed());
        assert_latched(&mut s, e);
    }
}

/// REQ-FIX-005: a handshake message larger than the configured
/// max_handshake_message is CapacityExceeded even when the handshake
/// buffer could hold it.
#[test]
fn handshake_message_over_the_configured_maximum_is_capacity() {
    let pki = Pki::new(KeyKind::EcdsaP256, NAME);
    let (mut cc, mut sc) = configs(&pki);
    cc.common.groups = vec![NamedGroup::X25519];
    sc.common.groups = vec![NamedGroup::X25519];
    // ServerHello and EncryptedExtensions fit; the Certificate does not.
    cc.common.max_handshake_message = 300;
    handshake(&cc, &sc, NAME, default_limits(), |r, c, _| {
        assert!(r.is_err());
        let e = latched(c);
        assert_eq!(e.kind(), ErrorKind::CapacityExceeded, "{e}");
        assert_eq!(e.context(), "handshake reassembly capacity");
        assert_eq!(
            c.report().events().last().map(|e| e.state),
            Some(HandshakeState::WaitCertificateRequest)
        );
    });
}

/// REQ-FIX-004: a handshake message whose four-byte header is split across
/// records is reassembled; the handshake then completes normally.
#[test]
fn handshake_header_split_across_records_is_reassembled() {
    let pki = Pki::new(KeyKind::EcdsaP256, NAME);
    let (cc, sc) = configs(&pki);
    let (mut cb, mut sb) = (Buffers::new(), Buffers::new());
    let (mut cr, mut sr) = (rng(), rng());
    let mut c = Connection::client(&cc, NAME, &mut cr, cb.storage(), Limits::default()).unwrap();
    let mut s = Connection::server(&sc, &mut sr, sb.storage(), Limits::default()).unwrap();
    let hello = take(&mut c);
    let msg = &hello[5..];
    for part in [&msg[..2], &msg[2..3], &msg[3..]] {
        let mut rec = vec![22, 3, 3];
        rec.extend_from_slice(&(part.len() as u16).to_be_bytes());
        rec.extend_from_slice(part);
        s.receive(&rec).unwrap();
    }
    assert!(
        !s.outgoing().is_empty(),
        "the reassembled ClientHello was not answered"
    );
    pump(&mut c, &mut s).unwrap();
}

// ---------------------------------------------------------------------------
// ClientHello contents and alternative negotiated paths.

/// REQ-FIX-004: with send_sni off, or for an IP address, the client sends
/// no server_name; the server then selects its default identity, sends no
/// SNI acknowledgement, and the handshake completes.
#[test]
fn server_name_is_omitted_when_disabled_or_for_an_address() {
    let pki = Pki::new(KeyKind::EcdsaP256, NAME);
    let (mut cc, sc) = configs(&pki);
    assert!(
        hello_extension(&first_hello(&cc, "127.0.0.1"), 0).is_none(),
        "SNI for an IP"
    );
    assert!(hello_extension(&first_hello(&cc, NAME), 0).is_some());
    cc.send_sni = false;
    assert!(
        hello_extension(&first_hello(&cc, NAME), 0).is_none(),
        "SNI with send_sni off"
    );
    handshake(&cc, &sc, NAME, default_limits(), |r, c, _| {
        r.unwrap();
        assert!(c.report().has(Property::ServerAuthenticated));
    });
}

/// REQ-FIX-004: ALPN is negotiated in the server's preference order from the
/// client's offer, reported on both sides; with no common protocol and no
/// requirement the handshake completes without ALPN.
#[test]
fn alpn_is_negotiated_from_the_offer() {
    let pki = Pki::new(KeyKind::EcdsaP256, NAME);
    let (cc, sc) = configs(&pki);
    let cc = cc.with_alpn(&[b"h2", b"http/1.1"]);
    let mut sc2 = sc.clone().with_alpn(&[b"spdy/3", b"http/1.1", b"h2"]);
    handshake(&cc, &sc2, NAME, default_limits(), |r, c, s| {
        r.unwrap();
        assert_eq!(c.report().alpn, Some(&b"http/1.1"[..]));
        assert_eq!(s.report().alpn, Some(&b"http/1.1"[..]));
    });
    // RFC 7301 §3.2: both sides use ALPN and share nothing, so the server
    // refuses even without require_alpn (ALPACA). It ignores the offer only
    // when it has no protocols configured.
    sc2.common.alpn = vec![b"spdy/3".to_vec()];
    handshake(&cc, &sc2, NAME, default_limits(), |r, _, s| {
        assert!(r.is_err());
        assert_eq!(latched(s).kind(), ErrorKind::NoApplicationProtocol);
    });
    sc2.common.alpn = Vec::new();
    handshake(&cc, &sc2, NAME, default_limits(), |r, c, s| {
        r.unwrap();
        assert_eq!(c.report().alpn, None);
        assert_eq!(s.report().alpn, None);
    });
}

/// REQ-FIX-005: a required ALPN fails closed with NoApplicationProtocol: a
/// server requiring it refuses a client that offers none or none in common,
/// and a client requiring it refuses a server that selects none.
#[test]
fn required_alpn_fails_closed() {
    let pki = Pki::new(KeyKind::EcdsaP256, NAME);
    let (cc, sc) = configs(&pki);
    let mut strict = sc.clone().with_alpn(&[b"h2"]);
    strict.common.require_alpn = true;
    for client in [cc.clone(), cc.clone().with_alpn(&[b"http/1.1"])] {
        handshake(&client, &strict, NAME, default_limits(), |r, _, s| {
            assert!(r.is_err());
            assert_eq!(latched(s).kind(), ErrorKind::NoApplicationProtocol);
        });
    }
    let mut demanding = cc.clone().with_alpn(&[b"h2"]);
    demanding.common.require_alpn = true;
    handshake(&demanding, &sc, NAME, default_limits(), |r, c, _| {
        assert!(r.is_err());
        let e = latched(c);
        assert_eq!(e.kind(), ErrorKind::NoApplicationProtocol);
        assert_eq!(e.context(), "server omitted ALPN");
    });
    let agreeing = sc.clone().with_alpn(&[b"h2"]);
    handshake(&demanding, &agreeing, NAME, default_limits(), |r, c, _| {
        r.unwrap();
        assert_eq!(c.report().alpn, Some(&b"h2"[..]));
    });
}

/// Records of `len` bytes each way after the handshake; Err names the side.
fn exchange_records(c: &mut Connection<'_>, s: &mut Connection<'_>, len: usize) -> Result<()> {
    let data = vec![0x5a; len];
    let mut out = vec![0; len];
    c.write_application(&data)?;
    transfer(c, s)?;
    assert_eq!(s.read_application(&mut out)?, len);
    s.write_application(&data)?;
    transfer(s, c)?;
    assert_eq!(c.read_application(&mut out)?, len);
    Ok(())
}

/// REQ-FIX-004: record_size_limit (RFC 8449) is negotiated when both sides
/// configure it, after which each sends only records the other accepts.
#[test]
fn record_size_limits_are_negotiated_and_honoured() {
    let pki = Pki::new(KeyKind::EcdsaP256, NAME);
    let (mut cc, mut sc) = configs(&pki);
    cc.common.record_size_limit = Some(64);
    sc.common.record_size_limit = Some(100);
    assert_eq!(
        hello_extension(&first_hello(&cc, NAME), 28),
        Some(vec![0, 64])
    );
    handshake(&cc, &sc, NAME, default_limits(), |r, c, s| {
        r.unwrap();
        exchange_records(c, s, 1000).unwrap();
    });
}

/// REQ-FIX-004: record_size_limit is answered, and enforced, only when both
/// endpoints sent it (RFC 8446 section 4.2, RFC 8449; REQ-RSL-002). A fixed
/// server configured with a limit used to answer a client that never offered
/// one (which the client refused as an unsolicited extension) and to enforce
/// its limit on a client that could not know it; a fixed client with a
/// limit enforced it on a server that never acknowledged it.
#[test]
fn record_size_limit_applies_only_when_both_sides_send_it() {
    let pki = Pki::new(KeyKind::EcdsaP256, NAME);
    let (cc, sc) = configs(&pki);
    let mut limited_server = sc.clone();
    limited_server.common.record_size_limit = Some(64);
    handshake(&cc, &limited_server, NAME, default_limits(), |r, c, s| {
        r.unwrap();
        exchange_records(c, s, 1000).unwrap();
    });
    let mut limited_client = cc.clone();
    limited_client.common.record_size_limit = Some(64);
    handshake(&limited_client, &sc, NAME, default_limits(), |r, c, s| {
        r.unwrap();
        exchange_records(c, s, 1000).unwrap();
    });
}

/// REQ-FIX-004: with revocation off the client requests no OCSP staple, the
/// server sends none even though it has one, and no revocation property is
/// claimed.
#[test]
fn revocation_off_requests_no_status() {
    let pki = Pki::new(KeyKind::EcdsaP256, NAME);
    let (mut cc, mut sc) = configs(&pki);
    sc.identities[0].ocsp = Some(Arc::new(pki.staple(
        CertStatus::Good,
        now() - 30,
        now() + 3600,
    )));
    assert!(hello_extension(&first_hello(&cc, NAME), 5).is_some());
    cc.revocation = Revocation::Off;
    assert!(hello_extension(&first_hello(&cc, NAME), 5).is_none());
    handshake(&cc, &sc, NAME, default_limits(), |r, c, _| {
        r.unwrap();
        assert!(!c.report().has(Property::RevocationChecked));
    });
}

/// REQ-FIX-004: a server that does not prefer its own order takes the
/// client's first mutually supported suite.
#[test]
fn client_suite_order_is_used_when_the_server_does_not_prefer_its_own() {
    let pki = Pki::new(KeyKind::EcdsaP256, NAME);
    let (mut cc, mut sc) = configs(&pki);
    cc.common.suites = vec![
        CipherSuite::TlsAes256GcmSha384,
        CipherSuite::TlsAes128GcmSha256,
    ];
    sc.common.suites = vec![
        CipherSuite::TlsAes128GcmSha256,
        CipherSuite::TlsAes256GcmSha384,
    ];
    handshake(&cc, &sc, NAME, default_limits(), |r, c, _| {
        r.unwrap();
        assert_eq!(c.report().suite, Some(CipherSuite::TlsAes128GcmSha256));
    });
    sc.prefer_server_order = false;
    handshake(&cc, &sc, NAME, default_limits(), |r, c, s| {
        r.unwrap();
        assert_eq!(c.report().suite, Some(CipherSuite::TlsAes256GcmSha384));
        assert_eq!(s.report().suite, Some(CipherSuite::TlsAes256GcmSha384));
    });
}

/// REQ-FIX-005: server-side slots are enforced on real client input: a name
/// longer than the name slot, more extensions than the extension slots, and
/// more offered ALPN protocols than the ALPN slots are CapacityExceeded.
#[test]
fn server_slot_limits_fail_closed_on_client_input() {
    let pki = Pki::new(KeyKind::EcdsaP256, NAME);
    let (cc, sc) = configs(&pki);
    let alpn = cc.clone().with_alpn(&[b"h2", b"http/1.1"]);
    let d = Limits::default();
    for (what, client, limits, context) in [
        ("name", &cc, Limits { name: 10, ..d }, "SNI name capacity"),
        (
            "extensions",
            &cc,
            Limits { extensions: 3, ..d },
            "extension slots",
        ),
        (
            "ALPN",
            &alpn,
            Limits {
                alpn_protocols: 1,
                ..d
            },
            "ALPN protocol slots",
        ),
    ] {
        handshake(client, &sc, NAME, (d, limits), |r, _, s| {
            assert!(r.is_err(), "{what}");
            let e = latched(s);
            assert_eq!(e.kind(), ErrorKind::CapacityExceeded, "{what}: {e}");
            assert_eq!(e.context(), context, "{what}");
        });
    }
}

/// REQ-FIX-005: a local certificate chain longer than the certificate slots
/// is CapacityExceeded before anything is sent.
#[test]
fn local_chain_beyond_the_certificate_slots_is_capacity() {
    let pki = Pki::new(KeyKind::EcdsaP256, NAME);
    let (cc, mut sc) = configs(&pki);
    sc.identities[0].chain.push(pki.ca_cert.clone());
    let one = Limits {
        certificates: 1,
        ..Limits::default()
    };
    handshake(&cc, &sc, NAME, (Limits::default(), one), |r, _, s| {
        assert!(r.is_err());
        let e = latched(s);
        assert_eq!(e.kind(), ErrorKind::CapacityExceeded, "{e}");
        assert_eq!(e.context(), "local certificate slots");
    });
}

/// REQ-FIX-005: a peer certificate with more extensions than the extension
/// slots is CapacityExceeded.
#[test]
fn peer_certificate_extensions_beyond_the_slots_is_capacity() {
    let pki = Pki::new(KeyKind::EcdsaP256, NAME);
    let (cc, sc) = configs(&pki);
    let two = Limits {
        extensions: 2,
        ..Limits::default()
    };
    handshake(&cc, &sc, NAME, (two, Limits::default()), |r, c, _| {
        assert!(r.is_err());
        let e = latched(c);
        assert_eq!(e.kind(), ErrorKind::CapacityExceeded, "{e}");
        assert_eq!(e.context(), "certificate extension slots");
    });
}

/// REQ-FIX-004: a client without an identity answers a certificate request
/// with an empty Certificate. Optional client authentication completes
/// without MutualAuthentication on either side; required authentication is
/// refused with CertificateRequired.
#[test]
fn client_without_identity_under_optional_and_required_auth() {
    let pki = Pki::new(KeyKind::EcdsaP256, NAME);
    let (cc, mut sc) = configs(&pki);
    sc.client_auth = ClientAuth::Optional(PeerVerification::Roots(pki.roots()));
    handshake(&cc, &sc, NAME, default_limits(), |r, c, s| {
        r.unwrap();
        assert!(c.report().has(Property::ServerAuthenticated));
        assert!(!c.report().has(Property::MutualAuthentication));
        assert!(!s.report().has(Property::MutualAuthentication));
        assert!(s.peer_certificate(0).is_none());
        assert_eq!(c.report().local_signature_scheme, None);
    });
    sc.client_auth = ClientAuth::Required(PeerVerification::Roots(pki.roots()));
    handshake(&cc, &sc, NAME, default_limits(), |r, _, s| {
        assert!(r.is_err());
        let e = latched(s);
        assert_eq!(e.kind(), ErrorKind::CertificateRequired, "{e}");
        assert_eq!(e.context(), "empty peer certificate chain");
    });
}

fn pin(spki: &[u8], check_names: bool) -> PeerVerification {
    match PeerVerification::pin_spki(spki) {
        PeerVerification::PinnedSpki { sha256, .. } => PeerVerification::PinnedSpki {
            sha256,
            check_names,
        },
        other => other,
    }
}

/// REQ-FIX-004: pinned-key verification. A matching pin connects with
/// PinnedPeer (and checks the name when asked); a different key is UnknownCa;
/// with check_names a certificate for another name is refused; a server can
/// pin client keys, where there is no name to check.
#[test]
fn pinned_peers_are_verified_by_key() {
    let pki = Pki::new(KeyKind::EcdsaP256, NAME);
    let (cc, sc) = configs(&pki);
    for check_names in [false, true] {
        let mut pinned = cc.clone();
        pinned.verification = pin(&pki.server_spki(), check_names);
        handshake(&pinned, &sc, NAME, default_limits(), |r, c, _| {
            r.unwrap();
            assert!(c.report().has(Property::PinnedPeer));
            assert!(c.report().has(Property::ServerAuthenticated));
        });
    }
    let other = Pki::new(KeyKind::EcdsaP256, NAME);
    let mut wrong = cc.clone();
    wrong.verification = pin(&other.server_spki(), false);
    handshake(&wrong, &sc, NAME, default_limits(), |r, c, _| {
        assert!(r.is_err());
        let e = latched(c);
        assert_eq!(e.kind(), ErrorKind::UnknownCa, "{e}");
    });
    // The name the client wants is not the certificate's; without SNI the
    // server still presents it.
    let mut named = cc.clone();
    named.send_sni = false;
    named.verification = pin(&pki.server_spki(), true);
    handshake(&named, &sc, "other.test", default_limits(), |r, c, _| {
        assert!(r.is_err());
        assert_eq!(latched(c).kind(), ErrorKind::CertificateNameMismatch);
    });
    named.verification = pin(&pki.server_spki(), false);
    handshake(&named, &sc, "other.test", default_limits(), |r, c, _| {
        r.unwrap();
        assert!(c.report().has(Property::PinnedPeer));
    });
    // With SNI, a name no identity covers is refused (REQ-NEG-002).
    let mut asks = cc.clone();
    asks.verification = pin(&pki.server_spki(), false);
    handshake(&asks, &sc, "other.test", default_limits(), |r, _, s| {
        assert!(r.is_err());
        assert_eq!(latched(s).kind(), ErrorKind::UnrecognizedName);
    });
    // A server pinning its client.
    let identity = pki.client_identity(KeyKind::EcdsaP256, "device");
    let mut mutual = cc.clone();
    let client_spki = identity.key.spki().to_vec();
    mutual.identity = Some(identity);
    let mut pinning = sc.clone();
    pinning.client_auth = ClientAuth::Required(pin(&client_spki, true));
    handshake(&mutual, &pinning, NAME, default_limits(), |r, c, s| {
        r.unwrap();
        assert!(s.report().has(Property::MutualAuthentication));
        assert!(s.report().has(Property::PinnedPeer));
        assert!(c.report().has(Property::MutualAuthentication));
        assert!(!c.report().has(Property::PinnedPeer));
    });
}

/// REQ-FIX-004: an OCSP staple whose status is not good establishes no
/// revocation property; RequireStaple refuses it, and refuses a server that
/// sends no staple, with BadCertificateStatus.
#[test]
fn staple_status_other_than_good_is_not_revocation_checked() {
    let pki = Pki::new(KeyKind::EcdsaP256, NAME);
    let (cc, sc) = configs(&pki);
    let mut stapling = sc.clone();
    stapling.identities[0].ocsp = Some(Arc::new(pki.staple(
        CertStatus::Unknown,
        now() - 30,
        now() + 3600,
    )));
    handshake(&cc, &stapling, NAME, default_limits(), |r, c, _| {
        r.unwrap();
        assert!(c.report().has(Property::ServerAuthenticated));
        assert!(!c.report().has(Property::RevocationChecked));
    });
    let mut strict = cc.clone();
    strict.revocation = Revocation::RequireStaple;
    handshake(&strict, &stapling, NAME, default_limits(), |r, c, _| {
        assert!(r.is_err());
        let e = latched(c);
        assert_eq!(e.kind(), ErrorKind::BadCertificateStatus, "{e}");
        assert_eq!(e.context(), "OCSP status unknown");
    });
    handshake(&strict, &sc, NAME, default_limits(), |r, c, _| {
        assert!(r.is_err());
        let e = latched(c);
        assert_eq!(e.kind(), ErrorKind::BadCertificateStatus, "{e}");
        assert_eq!(e.context(), "required OCSP staple absent");
    });
}

/// REQ-FIX-003: a server certificate that is itself the trust anchor has a
/// verified path of depth zero: no path signature was checked, so
/// PostQuantumAuthentication is not claimed even for an ML-DSA leaf and
/// CertificateVerify, while the same key under a CA does claim it.
#[test]
fn a_directly_trusted_leaf_claims_no_post_quantum_path() {
    let pki = Pki::with_kinds(KeyKind::MlDsa87, KeyKind::MlDsa87, NAME);
    let (cc, sc) = configs(&pki);
    handshake(&cc, &sc, NAME, default_limits(), |r, c, _| {
        r.unwrap();
        assert!(c.report().has(Property::PostQuantumAuthentication));
    });
    let mut anchored = cc.clone();
    let mut roots = ironsocketlayer::x509::RootStore::new();
    roots.add_der(&pki.server_chain[0]).unwrap();
    anchored.verification = PeerVerification::Roots(roots);
    handshake(&anchored, &sc, NAME, default_limits(), |r, c, _| {
        r.unwrap();
        assert!(c.report().has(Property::ServerAuthenticated));
        assert_eq!(
            c.report().peer_signature_scheme,
            Some(SignatureScheme::MlDsa87)
        );
        assert_eq!(c.report().peer_chain_schemes, [None; 8]);
        assert!(!c.report().has(Property::PostQuantumAuthentication));
    });
}

/// REQ-FIX-005: a client whose profile requires mutual authentication
/// refuses, with PolicyViolation, a server that never asked for its
/// certificate.
#[test]
fn mutual_profile_refuses_a_server_that_does_not_request_a_certificate() {
    let pki = Pki::new(KeyKind::EcdsaP256, NAME);
    let (mut cc, sc) = configs(&pki);
    cc.common.profile = Profile::DalA;
    cc.identity = Some(pki.client_identity(KeyKind::EcdsaP256, "device"));
    handshake(&cc, &sc, NAME, default_limits(), |r, c, _| {
        assert!(r.is_err());
        let e = latched(c);
        assert_eq!(e.kind(), ErrorKind::PolicyViolation, "{e}");
        assert!(!c.report().has(Property::Confidentiality));
    });
}

// ---------------------------------------------------------------------------
// Hand-made plaintext ServerHello and HelloRetryRequest.

/// A client offering one X25519 share, AES-128 and AES-256, and the groups
/// X25519, P-256 and P-384; its ClientHello is returned too.
fn retry_client(pki: &Pki) -> ClientConfig {
    let (mut cc, _) = configs(pki);
    cc.common.suites = vec![
        CipherSuite::TlsAes128GcmSha256,
        CipherSuite::TlsAes256GcmSha384,
    ];
    cc.common.groups = vec![
        NamedGroup::X25519,
        NamedGroup::Secp256r1,
        NamedGroup::Secp384r1,
    ];
    cc.initial_key_shares = 1;
    cc
}

fn hrr(sid: &[u8], suite: u16, exts: &[Vec<u8>]) -> Vec<u8> {
    server_hello(&ironsocketlayer::msgs::HRR_RANDOM, sid, suite, 0, exts)
}

/// REQ-FIX-005: the client refuses a ServerHello or HelloRetryRequest that
/// selects an unoffered suite, non-null compression, an unoffered, already
/// shared or unknown group, a suite other than the retry's, a second retry,
/// an empty cookie, or an extension it may not carry.
#[test]
fn malformed_server_hellos_are_refused() {
    let pki = Pki::new(KeyKind::EcdsaP256, NAME);
    let cc = retry_client(&pki);
    let mut aes128_only = cc.clone();
    aes128_only.common.suites = vec![CipherSuite::TlsAes128GcmSha256];
    let v = ext(43, &[3, 4]);
    let x25519_share = ext(51, &[&X25519.to_be_bytes()[..], &v16(&[9; 32])].concat());
    let hrr_p256 = ext(51, &P256.to_be_bytes());
    type Flight = fn(&[u8], &[Vec<u8>; 4]) -> Vec<Vec<u8>>;
    // Each case: config, the flights (built from the session ID and the
    // common extensions), the expected kind and context.
    let cases: Vec<(&str, &ClientConfig, Flight, ErrorKind, &str)> = vec![
        (
            "unoffered suite",
            &aes128_only,
            |sid, e| {
                vec![server_hello(
                    &[0x33; 32],
                    sid,
                    AES256,
                    0,
                    &[e[0].clone(), e[1].clone()],
                )]
            },
            ErrorKind::IllegalParameter,
            "ServerHello suite or compression",
        ),
        (
            "compression",
            &cc,
            |sid, e| {
                vec![server_hello(
                    &[0x33; 32],
                    sid,
                    AES128,
                    1,
                    &[e[0].clone(), e[1].clone()],
                )]
            },
            ErrorKind::IllegalParameter,
            "ServerHello suite or compression",
        ),
        (
            "unknown ServerHello extension",
            &cc,
            |sid, e| {
                vec![server_hello(
                    &[0x33; 32],
                    sid,
                    AES128,
                    0,
                    &[e[0].clone(), e[1].clone(), ext(0xfafa, &[])],
                )]
            },
            ErrorKind::UnsupportedExtension,
            "unsolicited ServerHello extension",
        ),
        (
            "retry for an existing share",
            &cc,
            |sid, e| {
                vec![hrr(
                    sid,
                    AES128,
                    &[e[0].clone(), ext(51, &X25519.to_be_bytes())],
                )]
            },
            ErrorKind::IllegalParameter,
            "retry requested unoffered or existing share",
        ),
        (
            "retry for an unoffered group",
            &cc,
            |sid, e| {
                vec![hrr(
                    sid,
                    AES128,
                    &[e[0].clone(), ext(51, &0x0019u16.to_be_bytes())],
                )]
            },
            ErrorKind::IllegalParameter,
            "retry requested unoffered or existing share",
        ),
        (
            "unknown retry extension",
            &cc,
            |sid, e| {
                vec![hrr(
                    sid,
                    AES128,
                    &[e[0].clone(), e[2].clone(), ext(0xfafa, &[])],
                )]
            },
            ErrorKind::UnsupportedExtension,
            "retry extension",
        ),
        (
            "empty cookie",
            &cc,
            |sid, e| {
                vec![hrr(
                    sid,
                    AES128,
                    &[e[0].clone(), e[2].clone(), ext(44, &[0, 0])],
                )]
            },
            ErrorKind::IllegalParameter,
            "empty retry cookie",
        ),
        (
            "second retry",
            &cc,
            |sid, e| {
                let h = hrr(sid, AES128, &[e[0].clone(), e[2].clone()]);
                vec![h.clone(), h]
            },
            ErrorKind::UnexpectedMessage,
            "fixed handshake state",
        ),
        (
            "suite changed after retry",
            &cc,
            |sid, e| {
                vec![
                    hrr(sid, AES128, &[e[0].clone(), e[2].clone()]),
                    server_hello(&[0x33; 32], sid, AES256, 0, &[e[0].clone(), e[3].clone()]),
                ]
            },
            ErrorKind::IllegalParameter,
            "ServerHello changed retry suite",
        ),
    ];
    for (what, config, flights, kind, context) in cases {
        let (mut b, mut r) = (Buffers::new(), rng());
        let mut c =
            Connection::client(config, NAME, &mut r, b.storage(), Limits::default()).unwrap();
        let sid = session_id(&take(&mut c));
        let p256_share = ext(51, &[&P256.to_be_bytes()[..], &v16(&[9; 65])].concat());
        let common = [
            v.clone(),
            x25519_share.clone(),
            hrr_p256.clone(),
            p256_share,
        ];
        let mut result = Ok(());
        for flight in flights(&sid, &common) {
            result = c.receive(&flight);
            if result.is_err() {
                break;
            }
            take(&mut c);
        }
        let e = result.expect_err(what);
        assert_eq!(e.kind(), kind, "{what}: {e}");
        assert_eq!(e.context(), context, "{what}");
        assert_latched(&mut c, e);
    }
}

/// REQ-FIX-004: a HelloRetryRequest cookie is echoed unchanged in the
/// second ClientHello (RFC 8446 section 4.2.2), with one share for the
/// requested group.
#[test]
fn retry_cookie_is_echoed_in_the_second_hello() {
    let pki = Pki::new(KeyKind::EcdsaP256, NAME);
    let cc = retry_client(&pki);
    let (mut b, mut r) = (Buffers::new(), rng());
    let mut c = Connection::client(&cc, NAME, &mut r, b.storage(), Limits::default()).unwrap();
    let first = take(&mut c);
    assert!(hello_extension(&first, 44).is_none());
    let cookie = v16(b"opaque server state");
    c.receive(&hrr(
        &session_id(&first),
        AES128,
        &[
            ext(43, &[3, 4]),
            ext(51, &P256.to_be_bytes()),
            ext(44, &cookie),
        ],
    ))
    .unwrap();
    let second = take(&mut c);
    assert_eq!(hello_extension(&second, 44), Some(cookie));
    let share = hello_extension(&second, 51).unwrap();
    assert_eq!(&share[2..4], &P256.to_be_bytes());
    assert_eq!(share.len(), 2 + 2 + 2 + 65);
    assert_eq!(c.report().state, HandshakeState::WaitServerHello);
}

// ---------------------------------------------------------------------------
// Hand-made plaintext ClientHello.

/// A server for P-256 key exchange only, so a ClientHello sharing X25519
/// draws a HelloRetryRequest.
fn retry_server(pki: &Pki) -> ServerConfig {
    let (_, mut sc) = configs(pki);
    sc.common.suites = vec![
        CipherSuite::TlsAes128GcmSha256,
        CipherSuite::TlsAes256GcmSha384,
    ];
    sc.common.groups = vec![NamedGroup::Secp256r1, NamedGroup::Secp384r1];
    sc
}

fn feed_server(sc: &ServerConfig, limits: Limits, flights: &[Vec<u8>]) -> (Result<()>, usize) {
    let (mut b, mut r) = (Buffers::new(), rng());
    let mut s = Connection::server(sc, &mut r, b.storage(), limits).unwrap();
    for (i, flight) in flights.iter().enumerate() {
        if let Err(e) = s.receive(flight) {
            assert_latched(&mut s, e);
            return (Err(e), i);
        }
        take(&mut s);
    }
    (Ok(()), flights.len())
}

/// REQ-FIX-005: the server refuses a malformed or hostile ClientHello with
/// the specific error: empty or odd suite lists, empty or odd group lists,
/// repeated or empty key shares, more shares than slots, an extension
/// forbidden in ClientHello or repeated, an unsolicited cookie, empty ALPN
/// names or lists, and an out-of-range record_size_limit.
#[test]
fn malformed_client_hellos_are_refused() {
    let pki = Pki::new(KeyKind::EcdsaP256, NAME);
    let sc = retry_server(&pki);
    let suites = u16s(&[AES128]);
    let base = |extra: &[Vec<u8>], share: &[u16]| {
        let mut e = vec![
            versions(),
            groups(&[X25519, P256, P384]),
            schemes(),
            shares(share),
        ];
        e.extend_from_slice(extra);
        e
    };
    let d = Limits::default();
    let cases: Vec<(&str, Vec<u8>, Limits, ErrorKind, &str)> = vec![
        (
            "empty suite list",
            client_hello(1, &[], &base(&[], &[P256])),
            d,
            ErrorKind::IllegalParameter,
            "cipher suite list",
        ),
        (
            "odd suite list",
            client_hello(1, &[0x13, 0x01, 0x13], &base(&[], &[P256])),
            d,
            ErrorKind::IllegalParameter,
            "cipher suite list",
        ),
        (
            "empty group list",
            client_hello(
                1,
                &suites,
                &[versions(), ext(10, &[0, 0]), schemes(), shares(&[P256])],
            ),
            d,
            ErrorKind::IllegalParameter,
            "empty or odd u16 list",
        ),
        (
            "odd group list",
            client_hello(
                1,
                &suites,
                &[
                    versions(),
                    ext(10, &[0, 3, 0, 0x17, 0]),
                    schemes(),
                    shares(&[P256]),
                ],
            ),
            d,
            ErrorKind::IllegalParameter,
            "empty or odd u16 list",
        ),
        (
            "repeated share",
            client_hello(1, &suites, &base(&[], &[P256, P256])),
            d,
            ErrorKind::IllegalParameter,
            "invalid ClientHello key share",
        ),
        (
            "empty share",
            client_hello(
                1,
                &suites,
                &[
                    versions(),
                    groups(&[X25519, P256, P384]),
                    schemes(),
                    ext(51, &v16(&[0, 0x17, 0, 0])),
                ],
            ),
            d,
            ErrorKind::IllegalParameter,
            "invalid ClientHello key share",
        ),
        (
            "more shares than slots",
            client_hello(
                1,
                &suites,
                &[
                    versions(),
                    groups(&[X25519, P256, P384, 0x0019, 0x001e]),
                    schemes(),
                    shares(&[X25519, P256, P384, 0x0019, 0x001e]),
                ],
            ),
            Limits { extensions: 4, ..d },
            ErrorKind::CapacityExceeded,
            "key share slots",
        ),
        (
            "extension forbidden in ClientHello",
            client_hello(1, &suites, &base(&[ext(48, &[])], &[P256])),
            d,
            ErrorKind::IllegalParameter,
            "extension forbidden in message",
        ),
        (
            "repeated extension",
            client_hello(
                1,
                &suites,
                &base(&[ext(0xfafa, &[]), ext(0xfafa, &[])], &[P256]),
            ),
            d,
            ErrorKind::IllegalParameter,
            "duplicate extension",
        ),
        (
            "unsolicited cookie",
            client_hello(1, &suites, &base(&[ext(44, &v16(b"cookie"))], &[P256])),
            d,
            ErrorKind::IllegalParameter,
            "unsolicited retry cookie",
        ),
        (
            "empty ALPN name",
            client_hello(
                1,
                &suites,
                &base(&[ext(16, &v16(&[2, b'h', b'2', 0]))], &[P256]),
            ),
            d,
            ErrorKind::IllegalParameter,
            "empty ALPN name",
        ),
        (
            "empty ALPN list",
            client_hello(1, &suites, &base(&[ext(16, &[0, 0])], &[P256])),
            d,
            ErrorKind::IllegalParameter,
            "empty ALPN list",
        ),
        (
            "record_size_limit below 64",
            client_hello(1, &suites, &base(&[ext(28, &[0, 63])], &[P256])),
            d,
            ErrorKind::IllegalParameter,
            "record_size_limit range",
        ),
        (
            "record_size_limit above 2^14 + 1",
            client_hello(1, &suites, &base(&[ext(28, &[0x40, 0x02])], &[P256])),
            d,
            ErrorKind::IllegalParameter,
            "record_size_limit range",
        ),
    ];
    for (what, hello, limits, kind, context) in cases {
        let (r, _) = feed_server(&sc, limits, &[hello]);
        let e = r.expect_err(what);
        assert_eq!(e.kind(), kind, "{what}: {e}");
        assert_eq!(e.context(), context, "{what}");
    }
    // The same structure with a real P-256 share is answered.
    let mut r = rng();
    let mut sk = vec![0; 64];
    let mut pk = vec![0; 133];
    let n =
        ironsocketlayer::crypto::kx::generate_into(NamedGroup::Secp256r1, &mut r, &mut sk, &mut pk)
            .unwrap();
    let share = ext(
        51,
        &v16(&[&P256.to_be_bytes()[..], &v16(&pk[..n])].concat()),
    );
    let hello = client_hello(
        1,
        &suites,
        &[
            versions(),
            groups(&[X25519, P256, P384]),
            schemes(),
            share,
            ext(28, &[0, 64]),
        ],
    );
    let (r, _) = feed_server(&sc, d, &[hello]);
    r.unwrap();
}

/// REQ-FIX-005: after a HelloRetryRequest the server refuses a second
/// ClientHello that changes the suite or any other field than key_share and
/// cookie, omits the requested share, shares another group, or adds shares
/// (RFC 8446 section 4.1.2).
#[test]
fn second_client_hellos_that_change_the_first_are_refused() {
    let pki = Pki::new(KeyKind::EcdsaP256, NAME);
    let sc = retry_server(&pki);
    let all = u16s(&[AES128, AES256]);
    let hello = |random: u8, suites: &[u8], share: &[u16]| {
        client_hello(
            random,
            suites,
            &[
                versions(),
                groups(&[X25519, P256, P384]),
                schemes(),
                shares(share),
            ],
        )
    };
    let first = hello(1, &all, &[X25519]);
    // The first is answered with a retry for P-256 and AES-128.
    let (r, n) = feed_server(&sc, Limits::default(), std::slice::from_ref(&first));
    r.unwrap();
    assert_eq!(n, 1);
    for (what, second, context) in [
        (
            "suite changed",
            hello(1, &u16s(&[AES256]), &[P256]),
            "ClientHello2 changed immutable fields",
        ),
        (
            "random changed",
            hello(2, &all, &[P256]),
            "ClientHello2 changed immutable fields",
        ),
        (
            "share omitted",
            hello(1, &all, &[X25519]),
            "ClientHello2 omitted requested share",
        ),
        (
            "other group",
            hello(1, &all, &[P384]),
            "ClientHello2 key share",
        ),
        (
            "extra share",
            hello(1, &all, &[P256, X25519]),
            "ClientHello2 key share",
        ),
    ] {
        let (r, at) = feed_server(&sc, Limits::default(), &[first.clone(), second]);
        let e = r.expect_err(what);
        assert_eq!(at, 1, "{what}: refused the first hello");
        assert_eq!(e.kind(), ErrorKind::IllegalParameter, "{what}: {e}");
        assert_eq!(e.context(), context, "{what}");
    }
}
