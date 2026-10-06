//! OpenSSL helpers shared by the interoperability test binaries.
#![allow(dead_code)]

use std::io::Write;
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use ironsocketlayer::enums::NamedGroup;

/// OpenSSL's names for the groups IronSocketLayer implements.
pub const GROUPS: &[(NamedGroup, &str)] = &[
    (NamedGroup::MlKem512, "MLKEM512"),
    (NamedGroup::X25519MlKem768, "X25519MLKEM768"),
    (NamedGroup::SecP256r1MlKem768, "SecP256r1MLKEM768"),
    (NamedGroup::MlKem768, "MLKEM768"),
    (NamedGroup::SecP384r1MlKem1024, "SecP384r1MLKEM1024"),
    (NamedGroup::MlKem1024, "MLKEM1024"),
    (NamedGroup::X25519, "x25519"),
    (NamedGroup::Secp256r1, "P-256"),
    (NamedGroup::Secp384r1, "P-384"),
    (NamedGroup::Secp521r1, "P-521"),
];

/// `openssl req -newkey` arguments for each key type.
pub const KEYS: &[(&str, &[&str])] = &[
    (
        "ecdsa-p256",
        &["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256"],
    ),
    (
        "ecdsa-p384",
        &["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-384"],
    ),
    (
        "ecdsa-p521",
        &["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-521"],
    ),
    ("ed25519", &["-newkey", "ed25519"]),
    ("rsa-2048", &["-newkey", "rsa:2048"]),
    ("ml-dsa-44", &["-newkey", "ML-DSA-44"]),
    ("ml-dsa-65", &["-newkey", "ML-DSA-65"]),
    ("ml-dsa-87", &["-newkey", "ML-DSA-87"]),
];

pub fn workdir(name: &str) -> PathBuf {
    let d = std::env::temp_dir()
        .join("ironsocketlayer-openssl")
        .join(name);
    std::fs::create_dir_all(&d).unwrap();
    d
}

pub fn openssl(args: &[&str], dir: &Path) -> std::process::Output {
    Command::new("openssl")
        .args(args)
        .current_dir(dir)
        .output()
        .expect("openssl on PATH")
}

pub fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Self-signed end-entity certificate for server.test, made by OpenSSL.
pub fn openssl_identity(dir: &Path, key_args: &[&str]) {
    let mut args = vec![
        "req", "-x509", "-nodes", "-days", "2", "-keyout", "key.pem", "-out", "cert.pem",
    ];
    args.extend_from_slice(key_args);
    args.extend_from_slice(&[
        "-subj",
        "/CN=server.test",
        "-addext",
        "subjectAltName=DNS:server.test",
        "-addext",
        "basicConstraints=critical,CA:FALSE",
        "-addext",
        "keyUsage=critical,digitalSignature",
        "-addext",
        "extendedKeyUsage=serverAuth,clientAuth",
    ]);
    let out = openssl(&args, dir);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

pub fn pem_to_der(pem: &str) -> Vec<u8> {
    let mut buf = vec![0u8; pem.len()];
    let n = ic_pkix::pem::decode(ic_pkix::pem::CERTIFICATE, pem.as_bytes(), &mut buf).unwrap();
    buf.truncate(n);
    buf
}

pub fn der_to_pem(der: &[u8]) -> String {
    let mut buf = vec![0u8; ic_pkix::pem::encoded_len(ic_pkix::pem::CERTIFICATE, der.len())];
    let n = ic_pkix::pem::encode(ic_pkix::pem::CERTIFICATE, der, &mut buf).unwrap();
    String::from_utf8(buf[..n].to_vec()).unwrap()
}

pub fn connect_retry(port: u16) -> TcpStream {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        match TcpStream::connect(("127.0.0.1", port)) {
            Ok(s) => {
                s.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
                return s;
            }
            Err(e) if Instant::now() > deadline => panic!("connect {port}: {e}"),
            Err(_) => std::thread::sleep(Duration::from_millis(50)),
        }
    }
}

pub fn s_client(dir: &Path, port: u16, group: &str, extra: &[&str]) -> String {
    let port_arg = format!("127.0.0.1:{port}");
    let mut args = vec![
        "s_client",
        "-connect",
        &port_arg,
        "-tls1_3",
        "-groups",
        group,
        "-CAfile",
        "ca.pem",
        "-verify_return_error",
        "-servername",
        "server.test",
        "-verify_hostname",
        "server.test",
        "-brief",
        // stdin is finite; wait for the server's echo and close_notify.
        "-ign_eof",
    ];
    args.extend_from_slice(extra);
    let mut child = Command::new("openssl")
        .args(&args)
        .current_dir(dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(b"hello\n").unwrap();
    let out = child.wait_with_output().unwrap();
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}
