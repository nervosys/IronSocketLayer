//! Measure, on this host, the smallest thread stack on which the fixed-capacity
//! engine completes a mutual-TLS session: both constructors, the handshake,
//! application data both ways, KeyUpdate, an exporter and close_notify.
//!
//! Each probe runs in a fresh child process, because a stack overflow aborts
//! the process and because IronCrypto's one-time table construction (inside
//! the constructors) must be included. Certificates and configuration are made
//! on the main thread first and are not counted. The figure is an upper bound
//! on the engine's own use: it includes thread start-up, and its resolution is
//! the platform's stack granularity (4 KiB pages on Linux; Windows reserves in
//! 64 KiB units, so measure on Linux), and requests under the platform minimum
//! are raised to it. Each session holds both endpoints' `fixed::Connection`
//! values on the measured stack (see the `footprint` example for their size);
//! the caller's storage buffers are on the heap here and not counted. It is a host measurement, not a target
//! one: code generation and stack frames differ on Cortex-M4.
//!
//! ```console
//! $ cargo run --release -p iron-socket-layer --example fixed_stack
//! ```

use iron_socket_layer::config::{
    ClientAuth, ClientConfig, Identity, PeerVerification, Profile, ServerConfig,
};
use iron_socket_layer::crypto::sign::{KeyKind, SigningKey};
use iron_socket_layer::enums::{NamedGroup, SignatureScheme};
use iron_socket_layer::fixed::{Connection, Limits, Storage};
use iron_socket_layer::x509::{self, CertificateParams, RootStore, Usage};
use std::process::Command;

/// What a probe runs on its measured thread.
#[derive(Clone, Copy, Debug)]
enum Case {
    /// Nothing: the platform's thread start-up cost.
    Idle,
    /// A whole session; the key kind is used for CA, server and client.
    Session(KeyKind, NamedGroup),
    /// One signature through the owned API: the primitive alone.
    Sign(KeyKind),
    /// One verification through the owned API: the primitive alone.
    Verify(KeyKind),
}

fn cases() -> Vec<Case> {
    let mut v = vec![Case::Idle];
    for &k in KeyKind::ALL {
        v.push(Case::Session(k, NamedGroup::SecP384r1MlKem1024));
    }
    for &g in iron_socket_layer::crypto::kx::IMPLEMENTED_GROUPS {
        v.push(Case::Session(KeyKind::EcdsaP256, g));
    }
    for &k in KeyKind::ALL {
        v.push(Case::Sign(k));
        v.push(Case::Verify(k));
    }
    v
}

fn label(case: Case) -> String {
    match case {
        Case::Idle => "thread start-up".into(),
        Case::Session(k, g) => format!("session {} {}", k.id(), g.id()),
        Case::Sign(k) => format!("sign only {}", k.id()),
        Case::Verify(k) => format!("verify only {}", k.id()),
    }
}

/// Prepare on the main thread; return the work for the measured thread.
fn prepare(case: Case) -> Box<dyn FnOnce() + Send> {
    match case {
        Case::Idle => Box::new(|| {}),
        Case::Session(kind, group) => {
            let (cc, sc) = configs(kind, group);
            Box::new(move || session(&cc, &sc))
        }
        Case::Sign(kind) | Case::Verify(kind) => {
            let key = SigningKey::generate(kind, &mut rng()).unwrap();
            let scheme = key.schemes()[0];
            let signature = key.sign(scheme, b"message", &mut rng()).unwrap();
            let sign = matches!(case, Case::Sign(_));
            let mut r = rng();
            Box::new(move || {
                if sign {
                    key.sign(scheme, b"message", &mut r).unwrap();
                } else {
                    let public =
                        iron_socket_layer::crypto::sign::PublicKey::from_spki(key.spki()).unwrap();
                    iron_socket_layer::crypto::sign::verify(
                        scheme, &public, b"message", &signature,
                    )
                    .unwrap();
                }
            })
        }
    }
}

fn rng() -> ic_drbg::Rng {
    ic_drbg::Rng::from_os().unwrap()
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn cert(
    cn: &str,
    names: &[&str],
    ca: bool,
    usage: &[Usage],
    spki: &[u8],
    issuer: Option<(&[u8], &SigningKey)>,
    key: &SigningKey,
) -> Vec<u8> {
    let t = now();
    let params = CertificateParams {
        subject_cn: cn,
        dns_names: names,
        ip_addresses: &[],
        not_before: t - 3600,
        not_after: t + 86_400,
        is_ca: ca,
        path_len: if ca { Some(1) } else { None },
        usage,
        serial: rng().random_array().unwrap(),
    };
    match issuer {
        None => x509::self_signed(&params, key, &mut rng()).unwrap(),
        Some((ca_cert, ca_key)) => x509::issue(&params, spki, ca_cert, ca_key, &mut rng()).unwrap(),
    }
}

fn configs(kind: KeyKind, group: NamedGroup) -> (ClientConfig, ServerConfig) {
    let ca_key = SigningKey::generate(kind, &mut rng()).unwrap();
    let ca = cert("Stack Root", &[], true, &[], &[], None, &ca_key);
    let leaf = |cn: &str, names: &[&str], usage: Usage| {
        let key = SigningKey::generate(kind, &mut rng()).unwrap();
        let c = cert(
            cn,
            names,
            false,
            &[usage],
            key.spki(),
            Some((&ca, &ca_key)),
            &key,
        );
        Identity::new(vec![c], key).unwrap()
    };
    let mut roots = RootStore::new();
    roots.add_der(&ca).unwrap();
    let mut cc = ClientConfig::new(Profile::Default, roots.clone()).unwrap();
    let mut sc = ServerConfig::new(
        Profile::Default,
        leaf("server.test", &["server.test"], Usage::ServerAuth),
    )
    .unwrap();
    cc.identity = Some(leaf("device", &[], Usage::ClientAuth));
    sc.client_auth = ClientAuth::Required(PeerVerification::Roots(roots));
    cc.tickets = None;
    sc.tickets = None;
    for common in [&mut cc.common, &mut sc.common] {
        common.groups = vec![group];
        // ML-DSA-44 is available by explicit configuration only.
        if kind == KeyKind::MlDsa44 {
            common.schemes.push(SignatureScheme::MlDsa44);
        }
    }
    (cc, sc)
}

fn flush(from: &mut Connection<'_>, to: &mut Connection<'_>) {
    let n = from.outgoing().len();
    to.receive(from.outgoing()).unwrap();
    from.consume_outgoing(n).unwrap();
}

struct Buffers([Vec<u8>; 8]);

impl Buffers {
    fn new() -> Self {
        let sizes = [16645, 32768, 65536, 32768, 32768, 3234, 1665, 32768];
        Self(sizes.map(|n| vec![0u8; n]))
    }
    fn storage(&mut self) -> Storage<'_> {
        let [record, handshake, outgoing, application, certificates, private_key, public_key, scratch] =
            &mut self.0;
        Storage {
            record,
            handshake,
            outgoing,
            application,
            certificates,
            private_key,
            public_key,
            scratch,
        }
    }
}

/// One session, on the current thread.
fn session(cc: &ClientConfig, sc: &ServerConfig) {
    let (mut cb, mut sb) = (Buffers::new(), Buffers::new());
    let (mut cr, mut sr) = (rng(), rng());
    let mut c =
        Connection::client(cc, "server.test", &mut cr, cb.storage(), Limits::default()).unwrap();
    let mut s = Connection::server(sc, &mut sr, sb.storage(), Limits::default()).unwrap();
    for _ in 0..4 {
        flush(&mut c, &mut s);
        flush(&mut s, &mut c);
    }
    assert!(c.is_connected() && s.is_connected());
    let mut out = [0u8; 16];
    c.write_application(b"to server").unwrap();
    flush(&mut c, &mut s);
    assert_eq!(s.read_application(&mut out).unwrap(), 9);
    c.key_update(true).unwrap();
    flush(&mut c, &mut s);
    flush(&mut s, &mut c);
    s.write_application(b"to client").unwrap();
    flush(&mut s, &mut c);
    assert_eq!(c.read_application(&mut out).unwrap(), 9);
    let (mut ce, mut se) = ([0u8; 32], [0u8; 32]);
    c.export(b"stack", b"", &mut ce).unwrap();
    s.export(b"stack", b"", &mut se).unwrap();
    assert_eq!(ce, se);
    c.close().unwrap();
    flush(&mut c, &mut s);
    s.close().unwrap();
    flush(&mut s, &mut c);
}

fn probe(case: usize, stack: usize) -> bool {
    Command::new(std::env::current_exe().unwrap())
        .args(["--child", &case.to_string(), &stack.to_string()])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("--child") {
        let case = cases()[args[2].parse::<usize>().unwrap()];
        let stack: usize = args[3].parse().unwrap();
        let work = prepare(case);
        let ok = std::thread::Builder::new()
            .stack_size(stack)
            .spawn(work)
            .unwrap()
            .join()
            .is_ok();
        std::process::exit(if ok { 0 } else { 1 });
    }
    const STEP: usize = 4096;
    for (i, case) in cases().into_iter().enumerate() {
        let (mut lo, mut hi) = (0, 16 << 20);
        assert!(probe(i, hi), "{case:?} fails even with {hi} bytes");
        while hi - lo > STEP {
            let mid = (lo + hi) / 2 / STEP * STEP;
            if probe(i, mid) {
                hi = mid;
            } else {
                lo = mid;
            }
        }
        // Requests below the platform minimum (glibc: 16 KiB) are raised to
        // it, so a result at or under it only bounds the use from above.
        if hi <= 16 << 10 {
            println!("{:>52}: <= 16 KiB (platform minimum)", label(case));
        } else {
            println!("{:>52}: {:>4} KiB", label(case), hi / 1024);
        }
    }
}
