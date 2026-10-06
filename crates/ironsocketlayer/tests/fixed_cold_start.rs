//! The fixed engine in a process where no curve operation has run yet.
//!
//! IronCrypto 0.2.5 to 0.2.7 built the NIST curve tables on the heap on first
//! use; from 0.2.8 they live in statics. This guards against that returning,
//! in IronCrypto or in how the engine initializes. (Ed25519's tables never
//! allocated.) Any key
//! generation in a process builds them, so the certificates are made here and
//! the fixed client runs in a fresh child process (this binary, re-run with an
//! environment variable). The child uses X25519, so a NIST curve or Ed25519 is
//! first used to verify the server's signatures, inside the allocation gate.

mod common;
mod fixed_support;

use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use common::Pki;
use fixed_support::{drive, no_alloc, send, Buffers};
use ironsocketlayer::config::{ClientConfig, Profile};
use ironsocketlayer::crypto::sign::KeyKind;
use ironsocketlayer::enums::NamedGroup;
use ironsocketlayer::fixed::{Connection, Limits};
use ironsocketlayer::report::Property;
use ironsocketlayer::stream::TlsStream;
use ironsocketlayer::x509::RootStore;

const KINDS: [KeyKind; 4] = [
    KeyKind::EcdsaP256,
    KeyKind::EcdsaP384,
    KeyKind::EcdsaP521,
    KeyKind::Ed25519,
];
const CHILD: &str = "ISL_COLD_START_CHILD";

/// REQ-FIX-002: verifying a peer's signature on a curve not yet used in the
/// process does not allocate inside a fixed-engine handshake.
#[test]
fn first_curve_use_in_a_fixed_handshake_does_not_allocate() {
    let dir = std::env::temp_dir().join(format!("isl-cold-start-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let mut ports = Vec::new();
    let mut servers = Vec::new();
    for (i, kind) in KINDS.into_iter().enumerate() {
        let pki = Pki::new(kind, "server.test");
        std::fs::write(dir.join(format!("ca{i}.der")), &pki.ca_cert).unwrap();
        let mut sc = pki.server_config(Profile::Default);
        sc.common.groups = vec![NamedGroup::X25519];
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        ports.push(listener.local_addr().unwrap().port().to_string());
        servers.push(std::thread::spawn(move || -> std::io::Result<()> {
            use std::io::{Read, Write};
            let (sock, _) = listener.accept()?;
            sock.set_read_timeout(Some(Duration::from_secs(20)))?;
            let mut tls = TlsStream::accept(sock, Arc::new(sc))?;
            let mut line = [0u8; 16];
            let n = tls.read(&mut line)?;
            tls.write_all(&line[..n])
        }));
    }
    let out = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "cold_child", "--ignored", "--nocapture"])
        .env(CHILD, format!("{}|{}", dir.display(), ports.join(",")))
        .output()
        .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    let text =
        String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success() && text.contains("1 passed"), "{text}");
    for s in servers {
        s.join().unwrap().unwrap();
    }
}

/// The cold child. Ignored, and inert unless run by the test above.
#[test]
#[ignore = "run by first_curve_use_in_a_fixed_handshake_does_not_allocate"]
fn cold_child() {
    let Ok(spec) = std::env::var(CHILD) else {
        return;
    };
    let (dir, ports) = spec.split_once('|').unwrap();
    for (i, port) in ports.split(',').enumerate() {
        let ca = std::fs::read(std::path::Path::new(dir).join(format!("ca{i}.der"))).unwrap();
        let mut roots = RootStore::new();
        roots.add_der(&ca).unwrap();
        let mut cfg = ClientConfig::new(Profile::Default, roots).unwrap();
        cfg.tickets = None;
        cfg.common.groups = vec![NamedGroup::X25519];
        let mut sock = TcpStream::connect(("127.0.0.1", port.parse::<u16>().unwrap())).unwrap();
        sock.set_read_timeout(Some(Duration::from_secs(20)))
            .unwrap();
        let mut buffers = Buffers::new();
        let mut rng = ic_drbg::Rng::from_os().unwrap();
        let mut conn = Connection::client(
            &cfg,
            "server.test",
            &mut rng,
            buffers.storage(),
            Limits::default(),
        )
        .unwrap();
        let mut app = Vec::new();
        drive(&mut conn, &mut sock, &mut app, |c, _| c.is_connected()).unwrap();
        assert!(
            conn.report().has(Property::ServerAuthenticated),
            "{:?}",
            KINDS[i]
        );
        send(&mut conn, &mut sock, b"ping").unwrap();
        drive(&mut conn, &mut sock, &mut app, |_, a| a == b"ping").unwrap();
        assert_eq!(app, b"ping");
        no_alloc(|| conn.close()).unwrap();
    }
}
