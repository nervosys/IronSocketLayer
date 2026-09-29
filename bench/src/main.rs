//! IronSocketLayer against rustls (ring provider), in one process, in memory.
//!
//! What is measured, for each library, with client and server in the same
//! thread so every figure is the CPU cost of *both* ends:
//!
//! * full handshakes per second (X25519, AES-128-GCM, ECDSA P-256 certificate)
//! * resumed handshakes per second (PSK with X25519)
//! * bulk throughput: 64 MiB client to server in 16 KiB records
//! * IronSocketLayer only: full handshakes with X25519MLKEM768, which the ring
//!   provider does not offer
//!
//! Each figure is the median of `RUNS` runs, reported with the spread. Compare
//! results only from the same machine, under the same load, minutes apart;
//! a busy machine moves these numbers more than most code changes do.
//!
//! `cargo run --release` from this directory.

use std::io::{Read, Write};
use std::sync::Arc;
use std::time::Instant;

use iron_socket_layer::config::{ClientConfig, Identity, Profile, ServerConfig};
use iron_socket_layer::crypto::sign::SigningKey;
use iron_socket_layer::enums::{CipherSuite, NamedGroup};
use iron_socket_layer::x509::RootStore;
use iron_socket_layer::Connection;

const RUNS: usize = 7;
const NAME: &str = "bench.test";

struct Stats {
    median: f64,
    min: f64,
    max: f64,
}

fn measure(runs: usize, mut f: impl FnMut() -> f64) -> Stats {
    let _ = f(); // warm-up
    let mut v: Vec<f64> = (0..runs).map(|_| f()).collect();
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    Stats {
        median: v[v.len() / 2],
        min: v[0],
        max: v[v.len() - 1],
    }
}

// ---------------------------------------------------------------- material

struct Material {
    cert: Vec<u8>,
    key: Vec<u8>,
}

fn material() -> Material {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let mut params = rcgen::CertificateParams::new(vec![NAME.to_string()]).unwrap();
    params.is_ca = rcgen::IsCa::ExplicitNoCa;
    let cert = params.self_signed(&key).unwrap();
    Material {
        cert: cert.der().to_vec(),
        key: key.serialize_der(),
    }
}

// ------------------------------------------------------------ IronSocketLayer

fn isl_configs(m: &Material, group: NamedGroup) -> (Arc<ClientConfig>, Arc<ServerConfig>) {
    let mut roots = RootStore::new();
    roots.add_der(&m.cert).unwrap();
    let mut cc = ClientConfig::new(Profile::Default, roots).unwrap();
    cc.common.groups = vec![group];
    cc.common.suites = vec![CipherSuite::TlsAes128GcmSha256];
    cc.initial_key_shares = 1;
    let key = SigningKey::from_pkcs8_der(&m.key).unwrap();
    let mut sc = ServerConfig::new(
        Profile::Default,
        Identity::new(vec![m.cert.clone()], key).unwrap(),
    )
    .unwrap();
    sc.common.groups = vec![group];
    sc.common.suites = vec![CipherSuite::TlsAes128GcmSha256];
    (Arc::new(cc), Arc::new(sc))
}

fn isl_handshake(cc: &Arc<ClientConfig>, sc: &Arc<ServerConfig>) -> (Connection, Connection) {
    let mut c = Connection::client(cc.clone(), NAME).unwrap();
    let mut s = Connection::server(sc.clone()).unwrap();
    while c.is_handshaking() || s.is_handshaking() {
        s.read_tls(&c.take_tls()).unwrap();
        c.read_tls(&s.take_tls()).unwrap();
    }
    // Tickets and any trailing messages.
    let t = s.take_tls();
    if !t.is_empty() {
        c.read_tls(&t).unwrap();
    }
    (c, s)
}

fn isl_handshakes_per_sec(
    cc: &Arc<ClientConfig>,
    sc: &Arc<ServerConfig>,
    n: usize,
    expect_resumed: bool,
) -> f64 {
    let start = Instant::now();
    for _ in 0..n {
        let (c, _) = isl_handshake(cc, sc);
        assert_eq!(c.report().resumed, expect_resumed);
    }
    n as f64 / start.elapsed().as_secs_f64()
}

fn isl_bulk_mib_per_sec(cc: &Arc<ClientConfig>, sc: &Arc<ServerConfig>, total: usize) -> f64 {
    let (mut c, mut s) = isl_handshake(cc, sc);
    let chunk = vec![0x5au8; 16 * 1024];
    let mut buf = vec![0u8; 64 * 1024];
    let start = Instant::now();
    let mut sent = 0;
    while sent < total {
        c.send(&chunk).unwrap();
        s.read_tls(&c.take_tls()).unwrap();
        while s.recv(&mut buf) > 0 {}
        sent += chunk.len();
    }
    total as f64 / (1024.0 * 1024.0) / start.elapsed().as_secs_f64()
}

// ------------------------------------------------------------------- rustls

fn rustls_configs(m: &Material) -> (Arc<rustls::ClientConfig>, Arc<rustls::ServerConfig>) {
    use rustls::crypto::ring as provider;
    let mut p = provider::default_provider();
    p.kx_groups = vec![provider::kx_group::X25519];
    p.cipher_suites = vec![provider::cipher_suite::TLS13_AES_128_GCM_SHA256];
    let p = Arc::new(p);
    let cert = rustls::pki_types::CertificateDer::from(m.cert.clone());
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(m.key.clone().into());
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.clone()).unwrap();
    let cc = rustls::ClientConfig::builder_with_provider(p.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let sc = rustls::ServerConfig::builder_with_provider(p)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .unwrap();
    (Arc::new(cc), Arc::new(sc))
}

fn rustls_pump(from: &mut rustls::Connection, to: &mut rustls::Connection) {
    let mut buf = Vec::new();
    while from.wants_write() {
        from.write_tls(&mut buf).unwrap();
    }
    let mut rd = &buf[..];
    while !rd.is_empty() {
        to.read_tls(&mut rd).unwrap();
        to.process_new_packets().unwrap();
    }
}

fn rustls_handshake(
    cc: &Arc<rustls::ClientConfig>,
    sc: &Arc<rustls::ServerConfig>,
) -> (rustls::Connection, rustls::Connection) {
    let name = rustls::pki_types::ServerName::try_from(NAME).unwrap();
    let mut c =
        rustls::Connection::Client(rustls::ClientConnection::new(cc.clone(), name).unwrap());
    let mut s = rustls::Connection::Server(rustls::ServerConnection::new(sc.clone()).unwrap());
    while c.is_handshaking() || s.is_handshaking() {
        rustls_pump(&mut c, &mut s);
        rustls_pump(&mut s, &mut c);
    }
    rustls_pump(&mut s, &mut c);
    (c, s)
}

fn rustls_handshakes_per_sec(
    cc: &Arc<rustls::ClientConfig>,
    sc: &Arc<rustls::ServerConfig>,
    n: usize,
) -> f64 {
    let start = Instant::now();
    for _ in 0..n {
        let _ = rustls_handshake(cc, sc);
    }
    n as f64 / start.elapsed().as_secs_f64()
}

fn rustls_bulk_mib_per_sec(
    cc: &Arc<rustls::ClientConfig>,
    sc: &Arc<rustls::ServerConfig>,
    total: usize,
) -> f64 {
    let (mut c, mut s) = rustls_handshake(cc, sc);
    let chunk = vec![0x5au8; 16 * 1024];
    let mut buf = vec![0u8; 64 * 1024];
    let start = Instant::now();
    let mut sent = 0;
    while sent < total {
        c.writer().write_all(&chunk).unwrap();
        rustls_pump(&mut c, &mut s);
        loop {
            match s.reader().read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
        }
        sent += chunk.len();
    }
    total as f64 / (1024.0 * 1024.0) / start.elapsed().as_secs_f64()
}

// ---------------------------------------------------------------------- main

/// AES-128-GCM seal of 16 KiB buffers with no TLS around it: the ceiling the
/// record layer is measured against.
fn isl_aead_mib_per_sec(total: usize) -> f64 {
    use iron_socket_layer::crypto::{AeadAlg, AeadKey};
    let key = AeadKey::new(AeadAlg::Aes128Gcm, &[7u8; 16]).unwrap();
    let mut buf = vec![0x5au8; 16 * 1024];
    let mut tag = [0u8; 16];
    let start = Instant::now();
    let mut done = 0;
    let mut seq = 0u64;
    while done < total {
        let mut nonce = [0u8; 12];
        nonce[4..].copy_from_slice(&seq.to_be_bytes());
        key.seal(&nonce, &[23, 3, 3, 0x40, 0x11], &mut buf, &mut tag)
            .unwrap();
        done += buf.len();
        seq += 1;
    }
    total as f64 / (1024.0 * 1024.0) / start.elapsed().as_secs_f64()
}

fn ring_aead_mib_per_sec(total: usize) -> f64 {
    use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_128_GCM};
    let key = LessSafeKey::new(UnboundKey::new(&AES_128_GCM, &[7u8; 16]).unwrap());
    let mut buf = vec![0x5au8; 16 * 1024];
    let start = Instant::now();
    let mut done = 0;
    let mut seq = 0u64;
    while done < total {
        let mut nonce = [0u8; 12];
        nonce[4..].copy_from_slice(&seq.to_be_bytes());
        let aad = Aad::from([23u8, 3, 3, 0x40, 0x11]);
        let tag = key
            .seal_in_place_separate_tag(Nonce::assume_unique_for_key(nonce), aad, &mut buf)
            .unwrap();
        let _ = std::hint::black_box(tag);
        done += buf.len();
        seq += 1;
    }
    total as f64 / (1024.0 * 1024.0) / start.elapsed().as_secs_f64()
}

// ---------------------------------------------------------- primitives

fn ops_per_sec(n: usize, mut f: impl FnMut()) -> f64 {
    let start = Instant::now();
    for _ in 0..n {
        f();
    }
    n as f64 / start.elapsed().as_secs_f64()
}

fn isl_primitives(m: &Material, n: usize) -> (Stats, Stats, Stats) {
    use iron_socket_layer::crypto::kx::{respond, KeyShare};
    use iron_socket_layer::crypto::sign::{verify, PublicKey};
    use iron_socket_layer::enums::SignatureScheme;
    let (cc, _) = isl_configs(m, NamedGroup::X25519);
    let mut rng = cc.common.new_rng().unwrap();
    let key = SigningKey::from_pkcs8_der(&m.key).unwrap();
    let scheme = SignatureScheme::EcdsaSecp256r1Sha256;
    let msg = [0x20u8; 130];
    let sig = key.sign(scheme, &msg, &mut *rng).unwrap();
    let spki = key.spki().to_vec();
    let sign = measure(RUNS, || {
        ops_per_sec(n, || drop(key.sign(scheme, &msg, &mut *rng).unwrap()))
    });
    let ver = measure(RUNS, || {
        ops_per_sec(n, || {
            verify(scheme, &PublicKey::from_spki(&spki).unwrap(), &msg, &sig).unwrap()
        })
    });
    let kx = measure(RUNS, || {
        ops_per_sec(n, || {
            let share = KeyShare::generate(NamedGroup::X25519, &mut *rng).unwrap();
            let (reply, _) = respond(NamedGroup::X25519, share.public(), &mut *rng).unwrap();
            drop(share.complete(&reply).unwrap());
        })
    });
    (sign, ver, kx)
}

fn ring_primitives(m: &Material, n: usize) -> (Stats, Stats, Stats) {
    use ring::agreement::{
        agree_ephemeral, EphemeralPrivateKey, UnparsedPublicKey as KxPub, X25519,
    };
    use ring::signature::{
        EcdsaKeyPair, KeyPair, UnparsedPublicKey, ECDSA_P256_SHA256_ASN1,
        ECDSA_P256_SHA256_ASN1_SIGNING,
    };
    let rng = ring::rand::SystemRandom::new();
    let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &m.key, &rng).unwrap();
    let msg = [0x20u8; 130];
    let sig = key.sign(&rng, &msg).unwrap();
    let public = key.public_key().as_ref().to_vec();
    let sign = measure(RUNS, || {
        ops_per_sec(n, || {
            let _ = key.sign(&rng, &msg).unwrap();
        })
    });
    let ver = measure(RUNS, || {
        ops_per_sec(n, || {
            UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, &public)
                .verify(&msg, sig.as_ref())
                .unwrap()
        })
    });
    let kx = measure(RUNS, || {
        ops_per_sec(n, || {
            let c = EphemeralPrivateKey::generate(&X25519, &rng).unwrap();
            let cp = c.compute_public_key().unwrap();
            let s = EphemeralPrivateKey::generate(&X25519, &rng).unwrap();
            let sp = s.compute_public_key().unwrap();
            agree_ephemeral(s, &KxPub::new(&X25519, cp.as_ref()), |k| k.len()).unwrap();
            agree_ephemeral(c, &KxPub::new(&X25519, sp.as_ref()), |k| k.len()).unwrap();
        })
    });
    (sign, ver, kx)
}

/// `isl-bench parts`: the per-connection costs outside the big primitives,
/// microseconds per operation.
fn parts() {
    use iron_socket_layer::crypto::{hmac, HashAlg};
    let us = |n: usize, f: &mut dyn FnMut()| {
        let start = Instant::now();
        for _ in 0..n {
            f();
        }
        start.elapsed().as_secs_f64() * 1e6 / n as f64
    };
    let m = material();
    let (cc, sc) = isl_configs(&m, NamedGroup::X25519);
    let n = 2000;
    println!(
        "{:<44} {:>8.2} us",
        "new_rng (DRBG from OS entropy)",
        us(n, &mut || drop(cc.common.new_rng().unwrap()))
    );
    let key = [1u8; 32];
    let data = [2u8; 200];
    println!(
        "{:<44} {:>8.2} us",
        "HMAC-SHA256, 200 bytes [ironcrypto]",
        us(n, &mut || drop(
            hmac(HashAlg::Sha256, &key, &[&data]).unwrap()
        ))
    );
    let rk = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &key);
    println!(
        "{:<44} {:>8.2} us",
        "HMAC-SHA256, 200 bytes [ring]",
        us(n, &mut || {
            let _ = ring::hmac::sign(&rk, &data);
        })
    );
    let big = [3u8; 4096];
    println!(
        "{:<44} {:>8.2} us",
        "SHA-256, 4 KiB [ironcrypto]",
        us(n, &mut || {
            let _ = HashAlg::Sha256.digest(&big);
        })
    );
    println!(
        "{:<44} {:>8.2} us",
        "SHA-256, 4 KiB [ring]",
        us(n, &mut || {
            let _ = ring::digest::digest(&ring::digest::SHA256, &big);
        })
    );
    {
        use iron_socket_layer::crypto::kx::KeyShare;
        use iron_socket_layer::crypto::{AeadAlg, AeadKey};
        let mut rng = cc.common.new_rng().unwrap();
        for _ in 0..3 {
            let kx = us(n, &mut || {
                drop(KeyShare::generate(NamedGroup::X25519, &mut *rng).unwrap())
            });
            let a128 = us(n, &mut || {
                drop(AeadKey::new(AeadAlg::Aes128Gcm, &[1; 16]).unwrap())
            });
            let a256 = us(n, &mut || {
                drop(AeadKey::new(AeadAlg::Aes256Gcm, &[1; 32]).unwrap())
            });
            println!(
                "X25519 keygen {kx:.2} us | AeadKey::new aes128 {a128:.2} us, aes256 {a256:.2} us"
            );
        }
    }
    // Each flight of a handshake, full and resumed, timed separately.
    let flights = |cc: &Arc<ClientConfig>, label: &str| {
        let mut t = [0f64; 5];
        let reps = 400;
        for _ in 0..reps {
            let a = Instant::now();
            let mut c = Connection::client(cc.clone(), NAME).unwrap();
            let b = Instant::now();
            let mut s = Connection::server(sc.clone()).unwrap();
            s.read_tls(&c.take_tls()).unwrap();
            let d = Instant::now();
            c.read_tls(&s.take_tls()).unwrap();
            let e = Instant::now();
            s.read_tls(&c.take_tls()).unwrap();
            let f = Instant::now();
            let tail = s.take_tls();
            if !tail.is_empty() {
                c.read_tls(&tail).unwrap();
            }
            let g = Instant::now();
            assert!(!c.is_handshaking() && !s.is_handshaking());
            for (k, (x, y)) in [(a, b), (b, d), (d, e), (e, f), (f, g)].iter().enumerate() {
                t[k] += (*y - *x).as_secs_f64() * 1e6 / reps as f64;
            }
        }
        println!("{label}:");
        for (name, v) in [
            "client: build ClientHello",
            "server: ClientHello -> its flight",
            "client: server flight -> Finished",
            "server: client Finished (+ ticket)",
            "client: ticket",
        ]
        .iter()
        .zip(t)
        {
            println!("  {name:<42} {v:>8.2} us");
        }
        println!("  {:<42} {:>8.2} us", "total", t.iter().sum::<f64>());
    };
    let (mut full, _) = isl_configs(&m, NamedGroup::X25519);
    Arc::get_mut(&mut full).unwrap().tickets = None;
    flights(&full, "full handshake");
    let _ = isl_handshake(&cc, &sc);
    flights(&cc, "resumed handshake");
}

fn row(name: &str, unit: &str, s: &Stats) {
    println!(
        "{name:<48} {:>10.1} {unit:<6} (min {:.1}, max {:.1})",
        s.median, s.min, s.max
    );
}

fn main() {
    if std::env::args().nth(1).as_deref() == Some("parts") {
        return parts();
    }
    let m = material();
    let n = 200;
    let bulk = 64 * 1024 * 1024;
    println!("IronSocketLayer vs rustls 0.23 (ring), {RUNS} runs each, median (spread)\n");

    let (icc, isc) = isl_configs(&m, NamedGroup::X25519);
    let (rcc, rsc) = rustls_configs(&m);

    // Full handshakes: fresh configs each run so no resumption happens.
    let isl_full = measure(RUNS, || {
        let (mut cc, sc) = isl_configs(&m, NamedGroup::X25519);
        Arc::get_mut(&mut cc).unwrap().tickets = None;
        isl_handshakes_per_sec(&cc, &sc, n, false)
    });
    let rustls_full = measure(RUNS, || {
        let (mut cc, sc) = rustls_configs(&m);
        Arc::get_mut(&mut cc).unwrap().resumption = rustls::client::Resumption::disabled();
        rustls_handshakes_per_sec(&cc, &sc, n)
    });
    row(
        "full handshake, X25519 + P-256 cert  [isl]",
        "hs/s",
        &isl_full,
    );
    row(
        "full handshake, X25519 + P-256 cert  [rustls]",
        "hs/s",
        &rustls_full,
    );

    let isl_pq = measure(RUNS, || {
        let (mut cc, sc) = isl_configs(&m, NamedGroup::X25519MlKem768);
        Arc::get_mut(&mut cc).unwrap().tickets = None;
        isl_handshakes_per_sec(&cc, &sc, n, false)
    });
    row(
        "full handshake, X25519MLKEM768        [isl]",
        "hs/s",
        &isl_pq,
    );
    println!(
        "{:<48} {:>10}",
        "full handshake, X25519MLKEM768        [rustls]", "n/a (ring has no ML-KEM)"
    );

    // Resumed: prime once, then every handshake resumes (each ticket is new).
    let _ = isl_handshake(&icc, &isc);
    let isl_res = measure(RUNS, || isl_handshakes_per_sec(&icc, &isc, n, true));
    let _ = rustls_handshake(&rcc, &rsc);
    let rustls_res = measure(RUNS, || rustls_handshakes_per_sec(&rcc, &rsc, n));
    row(
        "resumed handshake, PSK + X25519      [isl]",
        "hs/s",
        &isl_res,
    );
    row(
        "resumed handshake, PSK + X25519      [rustls]",
        "hs/s",
        &rustls_res,
    );

    let isl_bulk = measure(RUNS, || isl_bulk_mib_per_sec(&icc, &isc, bulk));
    let rustls_bulk = measure(RUNS, || rustls_bulk_mib_per_sec(&rcc, &rsc, bulk));
    row(
        "bulk AES-128-GCM, 16 KiB records     [isl]",
        "MiB/s",
        &isl_bulk,
    );
    row(
        "bulk AES-128-GCM, 16 KiB records     [rustls]",
        "MiB/s",
        &rustls_bulk,
    );

    let isl_aead = measure(RUNS, || isl_aead_mib_per_sec(bulk));
    let ring_aead = measure(RUNS, || ring_aead_mib_per_sec(bulk));
    row(
        "raw AES-128-GCM seal, 16 KiB         [ironcrypto]",
        "MiB/s",
        &isl_aead,
    );
    row(
        "raw AES-128-GCM seal, 16 KiB         [ring]",
        "MiB/s",
        &ring_aead,
    );

    let (i_sign, i_ver, i_kx) = isl_primitives(&m, n);
    let (r_sign, r_ver, r_kx) = ring_primitives(&m, n);
    row(
        "ECDSA P-256 sign                     [ironcrypto]",
        "op/s",
        &i_sign,
    );
    row(
        "ECDSA P-256 sign                     [ring]",
        "op/s",
        &r_sign,
    );
    row(
        "ECDSA P-256 verify                   [ironcrypto]",
        "op/s",
        &i_ver,
    );
    row(
        "ECDSA P-256 verify                   [ring]",
        "op/s",
        &r_ver,
    );
    row(
        "X25519 exchange, both ends           [ironcrypto]",
        "op/s",
        &i_kx,
    );
    row("X25519 exchange, both ends           [ring]", "op/s", &r_kx);

    println!(
        "\nratios (isl / rustls): full {:.2}x, resumed {:.2}x, bulk {:.2}x",
        isl_full.median / rustls_full.median,
        isl_res.median / rustls_res.median,
        isl_bulk.median / rustls_bulk.median
    );
    println!(
        "bulk as a share of its seal+open ceiling (half the raw seal rate): isl {:.0}%, rustls {:.0}%",
        isl_bulk.median / (isl_aead.median / 2.0) * 100.0,
        rustls_bulk.median / (ring_aead.median / 2.0) * 100.0
    );
}
