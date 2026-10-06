//! Fixed engine acceptance, with an allocator counter confined to this test
//! binary (see `fixed_support`).
mod common;
mod fixed_support;

use common::*;
use fixed_support::{no_alloc, Buffers};
use ironsocketlayer::config::{ClientAuth, PeerVerification, Profile};
use ironsocketlayer::crypto::{kx, sign::KeyKind};
use ironsocketlayer::fixed::{Connection, Limits};
use ironsocketlayer::record::IMPLEMENTED_SUITES;
use ironsocketlayer::report::Property;
use ironsocketlayer::ErrorKind;

fn transfer(
    from: &mut Connection<'_>,
    to: &mut Connection<'_>,
    fragment: usize,
) -> ironsocketlayer::Result<bool> {
    let n = from.outgoing().len();
    for bytes in from.outgoing().chunks(fragment) {
        to.receive(bytes)?;
    }
    from.consume_outgoing(n)?;
    Ok(n != 0)
}
fn pump(
    c: &mut Connection<'_>,
    s: &mut Connection<'_>,
    fragment: usize,
) -> ironsocketlayer::Result<()> {
    for _ in 0..12 {
        let a = transfer(c, s, fragment)?;
        let b = transfer(s, c, fragment)?;
        if c.is_connected() && s.is_connected() {
            return Ok(());
        }
        if !a && !b {
            break;
        }
    }
    Err(ironsocketlayer::Error::new(
        ErrorKind::InvalidState,
        "test pump stalled",
    ))
}

#[test]
fn fixed_full_handshake_and_records_do_not_allocate() {
    let pki = Pki::new(KeyKind::EcdsaP256, "server.test");
    for &suite in IMPLEMENTED_SUITES {
        for &group in kx::IMPLEMENTED_GROUPS {
            let mut cc = pki.client_config(Profile::Default);
            cc.tickets = None;
            cc.common.suites = vec![suite];
            cc.common.groups = vec![group];
            cc.identity = Some(pki.client_identity(KeyKind::EcdsaP256, "device"));
            let mut sc = pki.server_config(Profile::Default);
            sc.tickets = None;
            sc.common.suites = vec![suite];
            sc.common.groups = vec![group];
            sc.client_auth = ClientAuth::Required(PeerVerification::Roots(pki.roots()));
            let mut cb = Buffers::new();
            let mut sb = Buffers::new();
            let mut cr = ic_drbg::Rng::from_os().unwrap();
            let mut sr = ic_drbg::Rng::from_os().unwrap();
            let mut c =
                Connection::client(&cc, "server.test", &mut cr, cb.storage(), Limits::default())
                    .unwrap();
            let mut s = Connection::server(&sc, &mut sr, sb.storage(), Limits::default()).unwrap();
            no_alloc(|| {
                pump(&mut c, &mut s, 17).unwrap();
                assert!(c.report().has(Property::ServerAuthenticated));
                assert!(c.report().has(Property::MutualAuthentication));
                assert!(s.report().has(Property::MutualAuthentication));
                assert_eq!(
                    c.report().has(Property::PostQuantumKeyExchange),
                    kx::is_post_quantum(group)
                );
                assert!(!c.report().validated);
                c.write_application(b"client data").unwrap();
                transfer(&mut c, &mut s, 3).unwrap();
                let mut out = [0; 32];
                let n = s.read_application(&mut out).unwrap();
                assert_eq!(&out[..n], b"client data");
                c.key_update(true).unwrap();
                transfer(&mut c, &mut s, 7).unwrap();
                transfer(&mut s, &mut c, 7).unwrap();
                s.write_application(b"updated server data").unwrap();
                transfer(&mut s, &mut c, 1).unwrap();
                let n = c.read_application(&mut out).unwrap();
                assert_eq!(&out[..n], b"updated server data");
                let mut ce = [0; 32];
                let mut se = [0; 32];
                c.export(b"test", b"context", &mut ce).unwrap();
                s.export(b"test", b"context", &mut se).unwrap();
                assert_eq!(ce, se);
                assert!(!c.peer_closed() && !s.peer_closed());
                c.close().unwrap();
                transfer(&mut c, &mut s, 3).unwrap();
                assert!(s.peer_closed() && !c.peer_closed());
                s.close().unwrap();
                transfer(&mut s, &mut c, 3).unwrap();
                assert!(c.peer_closed());
            });
        }
    }
}

#[test]
fn fixed_every_signing_key_do_not_allocate() {
    for &kind in KeyKind::ALL {
        let pki = Pki::with_kinds(kind, kind, "server.test");
        let mut cc = pki.client_config(Profile::Default);
        cc.tickets = None;
        let mut sc = pki.server_config(Profile::Default);
        sc.tickets = None;
        for &scheme in sc.identities[0].key.schemes() {
            if !cc.common.schemes.contains(&scheme) {
                cc.common.schemes.push(scheme);
                sc.common.schemes.push(scheme);
            }
        }
        let mut cb = Buffers::new();
        let mut sb = Buffers::new();
        let mut cr = ic_drbg::Rng::from_os().unwrap();
        let mut sr = ic_drbg::Rng::from_os().unwrap();
        let mut c =
            Connection::client(&cc, "server.test", &mut cr, cb.storage(), Limits::default())
                .unwrap();
        let mut s = Connection::server(&sc, &mut sr, sb.storage(), Limits::default()).unwrap();
        no_alloc(|| pump(&mut c, &mut s, 4096).unwrap());
    }
}

#[test]
fn fixed_capacity_failure_latches_and_erases_queued_data() {
    let pki = Pki::new(KeyKind::EcdsaP256, "server.test");
    let mut cc = pki.client_config(Profile::Default);
    cc.tickets = None;
    let mut sc = pki.server_config(Profile::Default);
    sc.tickets = None;
    let mut cb = Buffers::new();
    let mut sb = Buffers::new();
    sb.application.resize(8, 0);
    let mut cr = ic_drbg::Rng::from_os().unwrap();
    let mut sr = ic_drbg::Rng::from_os().unwrap();
    let mut c =
        Connection::client(&cc, "server.test", &mut cr, cb.storage(), Limits::default()).unwrap();
    let mut s = Connection::server(&sc, &mut sr, sb.storage(), Limits::default()).unwrap();
    no_alloc(|| {
        pump(&mut c, &mut s, 4096).unwrap();
        c.write_application(b"12345678").unwrap();
        transfer(&mut c, &mut s, 4096).unwrap();
        c.write_application(b"9").unwrap();
        let error = s.receive(c.outgoing()).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::CapacityExceeded);
        assert_eq!(error.id(), "error:capacity-exceeded");
        assert!(!s.report().has(Property::Confidentiality));
        assert!(s.outgoing().is_empty());
        assert_eq!(s.receive(&[]).unwrap_err(), error);
        assert_eq!(s.read_application(&mut [0; 8]).unwrap_err(), error);
    });
}

#[test]
fn fixed_retry_revocation_and_named_profiles_do_not_allocate() {
    ironsocketlayer::policy::enable_fips().unwrap();
    for profile in [
        Profile::Default,
        Profile::PostQuantum,
        Profile::Cnsa1,
        Profile::Cnsa2,
        Profile::DalA,
    ] {
        let kind = if profile == Profile::Cnsa2 {
            KeyKind::MlDsa87
        } else {
            KeyKind::EcdsaP384
        };
        let pki = Pki::with_kinds(kind, kind, "server.test");
        let mut cc = pki.client_config(profile);
        cc.tickets = None;
        cc.identity = Some(pki.client_identity(kind, "device"));
        let mut sc = pki.server_config(profile);
        sc.tickets = None;
        sc.client_auth = ClientAuth::Required(PeerVerification::Roots(pki.roots()));
        if profile == Profile::Default {
            sc.common.groups = vec![ironsocketlayer::enums::NamedGroup::Secp384r1];
        }
        cc.revocation = ironsocketlayer::config::Revocation::RequireStaple;
        sc.identities[0].ocsp = Some(std::sync::Arc::new(pki.staple(
            ironsocketlayer::x509::ocsp::CertStatus::Good,
            now() - 30,
            now() + 3600,
        )));
        let mut store = ironsocketlayer::x509::crl::CrlStore::new();
        store.add_der(&pki.crl(&[])).unwrap();
        cc.common.crls = Some(std::sync::Arc::new(store));
        cc.common.require_crl = true;
        let mut cb = Buffers::new();
        let mut sb = Buffers::new();
        let mut cr = ic_drbg::Rng::from_os().unwrap();
        let mut sr = ic_drbg::Rng::from_os().unwrap();
        let mut c =
            Connection::client(&cc, "server.test", &mut cr, cb.storage(), Limits::default())
                .unwrap();
        let mut s = Connection::server(&sc, &mut sr, sb.storage(), Limits::default()).unwrap();
        no_alloc(|| {
            pump(&mut c, &mut s, 5).unwrap();
            assert!(c.report().has(Property::RevocationChecked));
            assert!(c.report().has(Property::MutualAuthentication));
            if profile.requires_fips() {
                assert!(c.report().has(Property::FipsApprovedAlgorithms));
            }
            if profile == Profile::Cnsa2 {
                assert!(c.report().has(Property::PostQuantumAuthentication));
            }
        });
    }
}

#[test]
fn fixed_engine_interoperates_with_owned_engine_in_both_directions() {
    let pki = Pki::new(KeyKind::EcdsaP384, "server.test");
    for client_fixed in [true, false] {
        let mut cc = pki.client_config(Profile::Default);
        cc.tickets = None;
        let mut sc = pki.server_config(Profile::Default);
        sc.tickets = None;
        let mut buffers = Buffers::new();
        let mut rng = ic_drbg::Rng::from_os().unwrap();
        let mut fixed = if client_fixed {
            Connection::client(
                &cc,
                "server.test",
                &mut rng,
                buffers.storage(),
                Limits::default(),
            )
            .unwrap()
        } else {
            Connection::server(&sc, &mut rng, buffers.storage(), Limits::default()).unwrap()
        };
        let mut owned = if client_fixed {
            ironsocketlayer::Connection::server(std::sync::Arc::new(sc.clone())).unwrap()
        } else {
            ironsocketlayer::Connection::client(std::sync::Arc::new(cc.clone()), "server.test")
                .unwrap()
        };
        for _ in 0..12 {
            let bytes = owned.take_tls();
            no_alloc(|| fixed.receive(&bytes).unwrap());
            owned.read_tls(fixed.outgoing()).unwrap();
            let n = fixed.outgoing().len();
            no_alloc(|| fixed.consume_outgoing(n).unwrap());
            if fixed.is_connected()
                && (owned.report().state
                    == Some(ironsocketlayer::report::HandshakeState::Connected))
            {
                break;
            }
        }
        assert!(fixed.is_connected());
        assert!((owned.report().state == Some(ironsocketlayer::report::HandshakeState::Connected)));
        owned.send(b"owned to fixed").unwrap();
        let bytes = owned.take_tls();
        no_alloc(|| fixed.receive(&bytes).unwrap());
        let mut out = [0; 32];
        let n = no_alloc(|| fixed.read_application(&mut out).unwrap());
        assert_eq!(&out[..n], b"owned to fixed");
        no_alloc(|| fixed.write_application(b"fixed to owned").unwrap());
        owned.read_tls(fixed.outgoing()).unwrap();
        let n = owned.recv(&mut out);
        assert_eq!(&out[..n], b"fixed to owned");
    }
}

/// A mutual-TLS pair of configurations, without tickets.
fn mtls(
    pki: &Pki,
) -> (
    ironsocketlayer::config::ClientConfig,
    ironsocketlayer::config::ServerConfig,
) {
    let mut cc = pki.client_config(Profile::Default);
    cc.tickets = None;
    cc.identity = Some(pki.client_identity(KeyKind::EcdsaP256, "device"));
    let mut sc = pki.server_config(Profile::Default);
    sc.tickets = None;
    sc.client_auth = ClientAuth::Required(PeerVerification::Roots(pki.roots()));
    (cc, sc)
}

/// Handshake and one record each way with these buffers and limits, under
/// the allocation gate. Construction errors are returned too.
fn run(
    cc: &ironsocketlayer::config::ClientConfig,
    sc: &ironsocketlayer::config::ServerConfig,
    cb: &mut Buffers,
    sb: &mut Buffers,
    cl: Limits,
    sl: Limits,
) -> ironsocketlayer::Result<()> {
    // Fixed seeds: every attempt produces byte-identical flights (randoms,
    // key shares and so signatures), so a capacity boundary is exact rather
    // than varying with DER signature lengths from run to run.
    let mut cr = ic_drbg::Rng::from_entropy(&[0x11; 48], b"fixed client").unwrap();
    let mut sr = ic_drbg::Rng::from_entropy(&[0x22; 48], b"fixed server").unwrap();
    let mut c = Connection::client(cc, "server.test", &mut cr, cb.storage(), cl)?;
    let mut s = Connection::server(sc, &mut sr, sb.storage(), sl)?;
    no_alloc(|| {
        pump(&mut c, &mut s, 4096)?;
        c.write_application(b"to server")?;
        transfer(&mut c, &mut s, 4096)?;
        s.write_application(b"to client")?;
        transfer(&mut s, &mut c, 4096)?;
        Ok(())
    })
}

type Field = fn(&mut Buffers) -> &mut Vec<u8>;

/// REQ-FIX-005: every byte capacity has a boundary. The smallest size that
/// completes a mutual-TLS handshake and data exchange is found by search;
/// one byte less fails with CapacityExceeded, without panic or allocation.
#[test]
fn every_byte_capacity_fails_exactly_one_below_its_boundary() {
    let pki = Pki::new(KeyKind::EcdsaP256, "server.test");
    let (cc, sc) = mtls(&pki);
    let fields: &[(&str, Field)] = &[
        ("record", |b| &mut b.record),
        ("handshake", |b| &mut b.handshake),
        ("outgoing", |b| &mut b.outgoing),
        ("application", |b| &mut b.application),
        ("certificates", |b| &mut b.certificates),
        ("scratch", |b| &mut b.scratch),
    ];
    for (name, field) in fields {
        for client_side in [true, false] {
            let attempt = |size: usize| {
                let (mut cb, mut sb) = (Buffers::new(), Buffers::new());
                field(if client_side { &mut cb } else { &mut sb }).truncate(size);
                run(
                    &cc,
                    &sc,
                    &mut cb,
                    &mut sb,
                    Limits::default(),
                    Limits::default(),
                )
            };
            let full = field(&mut Buffers::new()).len();
            attempt(full)
                .unwrap_or_else(|e| panic!("{name} (client {client_side}) at full size: {e}"));
            // Smallest working size, by binary search over [0, full].
            let (mut lo, mut hi) = (0usize, full);
            while lo < hi {
                let mid = (lo + hi) / 2;
                if attempt(mid).is_ok() {
                    hi = mid
                } else {
                    lo = mid + 1
                }
            }
            assert!(hi > 0, "{name} (client {client_side}) is never used");
            let e = attempt(hi - 1).unwrap_err();
            assert_eq!(
                e.kind(),
                ErrorKind::CapacityExceeded,
                "{name} (client {client_side}) one below its boundary {hi}: {e}"
            );
        }
    }
}

/// REQ-FIX-005: the slot limits fail closed, one over.
#[test]
fn slot_limits_fail_closed() {
    let pki = Pki::new(KeyKind::EcdsaP256, "server.test");
    let (cc, sc) = mtls(&pki);
    let cap = |r: ironsocketlayer::Result<()>, what: &str| {
        let e = r.expect_err(what);
        assert_eq!(e.kind(), ErrorKind::CapacityExceeded, "{what}: {e}");
    };
    let go =
        |cl: Limits, sl: Limits| run(&cc, &sc, &mut Buffers::new(), &mut Buffers::new(), cl, sl);
    // A server that sends its root after its leaf: two certificates, one slot.
    let mut sc2 = sc.clone();
    sc2.identities[0].chain.push(pki.ca_cert.clone());
    let one = Limits {
        certificates: 1,
        ..Limits::default()
    };
    cap(
        run(
            &cc,
            &sc2,
            &mut Buffers::new(),
            &mut Buffers::new(),
            one,
            Limits::default(),
        ),
        "peer certificate slots",
    );
    run(
        &cc,
        &sc2,
        &mut Buffers::new(),
        &mut Buffers::new(),
        Limits {
            certificates: 2,
            ..Limits::default()
        },
        Limits::default(),
    )
    .unwrap();
    // A handshake records more than two transitions.
    cap(
        go(
            Limits {
                events: 2,
                ..Limits::default()
            },
            Limits::default(),
        ),
        "audit event slots",
    );
    cap(
        go(
            Limits::default(),
            Limits {
                events: 2,
                ..Limits::default()
            },
        ),
        "server audit event slots",
    );
    // "server.test" is eleven bytes.
    cap(
        go(
            Limits {
                name: 10,
                ..Limits::default()
            },
            Limits::default(),
        ),
        "server name capacity",
    );
    go(
        Limits {
            name: 11,
            ..Limits::default()
        },
        Limits::default(),
    )
    .unwrap();
    // Two ALPN protocols against a one-slot limit.
    let cc2 = cc.clone().with_alpn(&[b"h2", b"http/1.1"]);
    let e = run(
        &cc2,
        &sc,
        &mut Buffers::new(),
        &mut Buffers::new(),
        Limits {
            alpn_protocols: 1,
            ..Limits::default()
        },
        Limits::default(),
    );
    cap(e, "configuration slot capacity");
}

/// REQ-FIX-004: features the fixed engine does not implement are refused
/// when the connection is created, never silently dropped.
#[test]
fn unsupported_features_are_refused_not_dropped() {
    let pki = Pki::new(KeyKind::EcdsaP256, "server.test");
    let (cc, sc) = mtls(&pki);
    let refused = |r: ironsocketlayer::Result<Connection<'_>>, what: &str| {
        let e = r.err().unwrap_or_else(|| panic!("{what} was accepted"));
        assert_eq!(e.kind(), ErrorKind::InvalidConfig, "{what}: {e}");
    };
    type ClientEdit = fn(&mut ironsocketlayer::config::ClientConfig);
    let client_cases: &[(&str, ClientEdit)] = &[
        ("tickets", |c| {
            c.tickets = Some(std::sync::Arc::new(
                ironsocketlayer::resumption::MemoryTicketStore::default(),
            ))
        }),
        ("early data", |c| c.early_data = true),
        ("post-handshake auth", |c| c.post_handshake_auth = true),
        ("ECH", |c| c.ech_configs = Some(vec![0, 0])),
        ("external PSK", |c| {
            c.external_psk = Some(
                ironsocketlayer::config::ExternalPsk::new(
                    b"id",
                    &[7; 32],
                    ironsocketlayer::crypto::HashAlg::Sha256,
                )
                .unwrap(),
            )
        }),
    ];
    for (what, edit) in client_cases {
        let mut c = cc.clone();
        edit(&mut c);
        let mut b = Buffers::new();
        let mut r = ic_drbg::Rng::from_os().unwrap();
        refused(
            Connection::client(&c, "server.test", &mut r, b.storage(), Limits::default()),
            what,
        );
    }
    type ServerEdit = fn(&mut ironsocketlayer::config::ServerConfig, &Pki);
    let server_cases: &[(&str, ServerEdit)] = &[
        ("tickets", |s, _| {
            s.tickets = Some(std::sync::Arc::new(
                ironsocketlayer::resumption::TicketKeys::generate(
                    &mut ic_drbg::Rng::from_os().unwrap(),
                )
                .unwrap(),
            ))
        }),
        ("early data", |s, _| {
            s.early_data = Some(ironsocketlayer::config::EarlyDataPolicy::new(16_384))
        }),
        ("retry cookie", |s, _| s.retry_cookie = true),
        ("on-demand client auth", |s, p| {
            s.client_auth = ClientAuth::OnDemand(PeerVerification::Roots(p.roots()))
        }),
        ("external PSKs", |s, _| {
            s.external_psks = vec![ironsocketlayer::config::ExternalPsk::new(
                b"id",
                &[7; 32],
                ironsocketlayer::crypto::HashAlg::Sha256,
            )
            .unwrap()]
        }),
    ];
    for (what, edit) in server_cases {
        let mut s = sc.clone();
        edit(&mut s, &pki);
        let mut b = Buffers::new();
        let mut r = ic_drbg::Rng::from_os().unwrap();
        refused(
            Connection::server(&s, &mut r, b.storage(), Limits::default()),
            what,
        );
    }
}

/// Fixed-seed RNGs, as in `run`, so a fresh peer reproduces a recorded flight.
fn seeded(client: bool) -> ic_drbg::Rng {
    if client {
        ic_drbg::Rng::from_entropy(&[0x11; 48], b"fixed client").unwrap()
    } else {
        ic_drbg::Rng::from_entropy(&[0x22; 48], b"fixed server").unwrap()
    }
}

/// Nothing panics on peer input, and a refusal latches. Every 5th byte of a
/// real ClientHello and of the server's answering flight is flipped, and both
/// are truncated at several points; each is fed to a fresh peer at the point
/// it would have arrived.
#[test]
fn mutated_flights_never_panic_and_failures_latch() {
    let pki = Pki::new(KeyKind::EcdsaP256, "server.test");
    let (cc, sc) = mtls(&pki);
    // Record the real flights.
    let (hello, answer) = {
        let (mut cb, mut sb) = (Buffers::new(), Buffers::new());
        let (mut cr, mut sr) = (seeded(true), seeded(false));
        let c = Connection::client(&cc, "server.test", &mut cr, cb.storage(), Limits::default())
            .unwrap();
        let mut s = Connection::server(&sc, &mut sr, sb.storage(), Limits::default()).unwrap();
        let hello = c.outgoing().to_vec();
        s.receive(&hello).unwrap();
        (hello, s.outgoing().to_vec())
    };
    let variants = |flight: &[u8]| {
        let mut v: Vec<Vec<u8>> = (0..flight.len())
            .step_by(5)
            .map(|i| {
                let mut m = flight.to_vec();
                m[i] ^= 0x41;
                m
            })
            .collect();
        for cut in [1, 4, 5, 6, 9, flight.len() / 2, flight.len() - 1] {
            v.push(flight[..cut].to_vec());
        }
        v
    };
    let latched = |r: ironsocketlayer::Result<()>, conn: &mut Connection<'_>| {
        if let Err(e) = r {
            assert_eq!(
                conn.receive(&[1, 2, 3]).unwrap_err(),
                e,
                "failure did not latch"
            );
            assert!(conn.outgoing().is_empty());
            assert!(!conn.is_connected());
        }
    };
    let mut refused = 0;
    for m in variants(&hello) {
        let mut sb = Buffers::new();
        let mut sr = seeded(false);
        let mut s = Connection::server(&sc, &mut sr, sb.storage(), Limits::default()).unwrap();
        let r = s.receive(&m);
        refused += r.is_err() as usize;
        latched(r, &mut s);
    }
    for m in variants(&answer) {
        let mut cb = Buffers::new();
        let mut cr = seeded(true);
        let mut c =
            Connection::client(&cc, "server.test", &mut cr, cb.storage(), Limits::default())
                .unwrap();
        let r = c.receive(&m);
        refused += r.is_err() as usize;
        latched(r, &mut c);
    }
    // Byte flips in authenticated data must mostly be refused.
    assert!(
        refused > (hello.len() + answer.len()) / 5 / 2,
        "only {refused} refused"
    );
}

/// A record or handshake-message header announcing an empty body must not
/// stall the engine. Found by fuzzing: both reassembly loops spun forever
/// without consuming input, a one-record denial of service. `REQ-FIX-005`.
#[test]
fn an_empty_record_does_not_stall_the_engine() {
    let pki = Pki::new(KeyKind::EcdsaP256, "server.test");
    let (_, sc) = mtls(&pki);
    // An empty-bodied ClientHello (type 1, length 0) and one more byte, in
    // one record, and the same split across two records.
    for input in [
        &[22u8, 3, 3, 0, 5, 1, 0, 0, 0, 1][..],
        &[22, 3, 3, 0, 4, 1, 0, 0, 0, 22, 3, 3, 0, 1, 1][..],
    ] {
        let (tx, rx) = std::sync::mpsc::channel();
        let (sc, owned) = (sc.clone(), input.to_vec());
        std::thread::spawn(move || {
            let mut sb = Buffers::new();
            let mut sr = seeded(false);
            let mut s = Connection::server(&sc, &mut sr, sb.storage(), Limits::default()).unwrap();
            let _ = tx.send(s.receive(&owned).map_err(|e| e.kind()));
        });
        let r = rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .unwrap_or_else(|_| panic!("an empty handshake message stalled the engine: {input:?}"));
        assert!(r.is_err(), "an empty ClientHello was accepted");
    }
    for body_type in [22u8, 21, 23, 20] {
        let (tx, rx) = std::sync::mpsc::channel();
        let sc = sc.clone();
        std::thread::spawn(move || {
            let mut sb = Buffers::new();
            let mut sr = seeded(false);
            let mut s = Connection::server(&sc, &mut sr, sb.storage(), Limits::default()).unwrap();
            let r = s.receive(&[body_type, 3, 3, 0, 0, 0x16]);
            let _ = tx.send(r.map_err(|e| e.kind()));
        });
        let r = rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .unwrap_or_else(|_| panic!("an empty record of type {body_type} stalled the engine"));
        assert!(
            r.is_err(),
            "an empty record of type {body_type} was accepted"
        );
    }
}

/// REQ-FIX-004: a long-lived connection rekeys any number of times, in both
/// directions and on the peer's request, without using up a bounded resource
/// (audit event slots in particular) and without allocating.
#[test]
fn key_updates_are_unbounded_in_number() {
    let pki = Pki::new(KeyKind::EcdsaP256, "server.test");
    let (cc, sc) = mtls(&pki);
    let (mut cb, mut sb) = (Buffers::new(), Buffers::new());
    let mut cr = seeded(true);
    let mut sr = seeded(false);
    let mut c =
        Connection::client(&cc, "server.test", &mut cr, cb.storage(), Limits::default()).unwrap();
    let mut s = Connection::server(&sc, &mut sr, sb.storage(), Limits::default()).unwrap();
    no_alloc(|| {
        pump(&mut c, &mut s, 4096).unwrap();
        let mut out = [0u8; 16];
        for round in 0..300u32 {
            // Each side in turn asks the other to update as well.
            let (a, b) = if round % 2 == 0 {
                (&mut c, &mut s)
            } else {
                (&mut s, &mut c)
            };
            a.key_update(true).unwrap();
            transfer(a, b, 4096).unwrap();
            transfer(b, a, 4096).unwrap();
            b.write_application(&round.to_be_bytes()).unwrap();
            transfer(b, a, 4096).unwrap();
            let n = a.read_application(&mut out).unwrap();
            assert_eq!(&out[..n], &round.to_be_bytes(), "round {round}");
        }
        assert!(c.is_connected() && s.is_connected());
    });
}
