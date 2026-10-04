//! CNSA 2.0 end to end against OpenSSL 3.5, in both directions:
//! `profile:cnsa-2` (ML-KEM-1024, ML-DSA-87, AES-256-GCM, FIPS gate on)
//! against an OpenSSL restricted to the same three parameters.
//!
//! Approved mode is process-global, so this is its own test binary, run in
//! one test with the module brought up first.
//!
//! ```console
//! $ cargo test -p iron-socket-layer --test openssl_cnsa2 -- --ignored
//! ```

mod common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use common::Pki;
use iron_socket_layer::config::{ClientConfig, Profile};
use iron_socket_layer::crypto::sign::KeyKind;
use iron_socket_layer::enums::{CipherSuite, NamedGroup, SignatureScheme};
use iron_socket_layer::report::Property;
use iron_socket_layer::stream::TlsStream;
use iron_socket_layer::x509::RootStore;

fn workdir(name: &str) -> PathBuf {
    let d = std::env::temp_dir()
        .join("iron-socket-layer-cnsa2")
        .join(name);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn openssl(args: &[&str], dir: &Path) -> std::process::Output {
    Command::new("openssl")
        .args(args)
        .current_dir(dir)
        .output()
        .expect("openssl on PATH")
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn connect_retry(port: u16) -> TcpStream {
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

fn pem_to_der(pem: &str) -> Vec<u8> {
    let mut buf = vec![0u8; pem.len()];
    let n = ic_pkix::pem::decode(ic_pkix::pem::CERTIFICATE, pem.as_bytes(), &mut buf).unwrap();
    buf.truncate(n);
    buf
}

fn der_to_pem(der: &[u8]) -> String {
    let mut buf = vec![0u8; ic_pkix::pem::encoded_len(ic_pkix::pem::CERTIFICATE, der.len())];
    let n = ic_pkix::pem::encode(ic_pkix::pem::CERTIFICATE, der, &mut buf).unwrap();
    String::from_utf8(buf[..n].to_vec()).unwrap()
}

/// The three CNSA 2.0 parameters, as OpenSSL names them.
const OSSL_CNSA2: &[&str] = &[
    "-tls1_3",
    "-groups",
    "MLKEM1024",
    "-ciphersuites",
    "TLS_AES_256_GCM_SHA384",
    "-sigalgs",
    "mldsa87",
];

#[test]
#[ignore = "needs openssl 3.5+ on PATH"]
fn cnsa2_interoperates_with_openssl_both_ways() {
    iron_socket_layer::policy::enable_fips().unwrap();

    // 1. Our CNSA 2.0 client against an OpenSSL server with an ML-DSA-87
    //    certificate OpenSSL generated.
    let dir = workdir("client");
    let out = openssl(
        &[
            "req",
            "-x509",
            "-nodes",
            "-days",
            "2",
            "-newkey",
            "ML-DSA-87",
            "-keyout",
            "key.pem",
            "-out",
            "cert.pem",
            "-subj",
            "/CN=server.test",
            "-addext",
            "subjectAltName=DNS:server.test",
            "-addext",
            "basicConstraints=critical,CA:FALSE",
            "-addext",
            "keyUsage=critical,digitalSignature",
            "-addext",
            "extendedKeyUsage=serverAuth",
        ],
        &dir,
    );
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let cert = pem_to_der(&std::fs::read_to_string(dir.join("cert.pem")).unwrap());
    let mut roots = RootStore::new();
    roots.add_der(&cert).unwrap();
    let cfg = ClientConfig::new(Profile::Cnsa2, roots).unwrap();

    let port = free_port();
    let port_s = port.to_string();
    let mut args = vec![
        "s_server", "-accept", &port_s, "-key", "key.pem", "-cert", "cert.pem",
    ];
    args.extend_from_slice(OSSL_CNSA2);
    args.extend_from_slice(&["-www", "-naccept", "1"]);
    let mut server = Command::new("openssl")
        .args(&args)
        .current_dir(&dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut tls = TlsStream::connect(connect_retry(port), Arc::new(cfg), "server.test")
        .unwrap_or_else(|e| panic!("CNSA 2.0 client against OpenSSL: {e}"));
    tls.write_all(b"GET / HTTP/1.0\r\n\r\n").unwrap();
    let mut body = Vec::new();
    let _ = tls.read_to_end(&mut body);
    assert!(String::from_utf8_lossy(&body).starts_with("HTTP/1.0 200"));
    let r = tls.report().clone();
    let _ = server.kill();
    let _ = server.wait();
    assert_eq!(r.profile, "profile:cnsa-2");
    assert_eq!(r.group, Some(NamedGroup::MlKem1024));
    assert_eq!(r.suite, Some(CipherSuite::TlsAes256GcmSha384));
    assert_eq!(r.peer_signature_scheme, Some(SignatureScheme::MlDsa87));
    assert!(r.has(Property::PostQuantumKeyExchange));
    assert!(r.has(Property::FipsApprovedAlgorithms), "{}", r.to_json());

    // 2. OpenSSL's client, restricted to CNSA 2.0, against our CNSA 2.0
    //    server with an all-ML-DSA-87 chain we issued.
    let pki = Pki::with_kinds(KeyKind::MlDsa87, KeyKind::MlDsa87, "server.test");
    let dir = workdir("server");
    std::fs::write(dir.join("ca.pem"), der_to_pem(&pki.ca_cert)).unwrap();
    let sc = Arc::new(pki.server_config(Profile::Cnsa2));
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let h = std::thread::spawn(move || {
        let (sock, _) = listener.accept().map_err(|e| e.to_string())?;
        sock.set_read_timeout(Some(Duration::from_secs(20)))
            .unwrap();
        let mut tls = TlsStream::accept(sock, sc).map_err(|e| e.to_string())?;
        let mut line = [0u8; 64];
        let n = tls.read(&mut line).map_err(|e| e.to_string())?;
        tls.write_all(&line[..n]).map_err(|e| e.to_string())?;
        let _ = tls.close();
        Ok::<_, String>(tls.report().clone())
    });
    let connect = format!("127.0.0.1:{port}");
    let mut args = vec![
        "s_client",
        "-connect",
        &connect,
        "-CAfile",
        "ca.pem",
        "-verify_return_error",
        "-servername",
        "server.test",
        "-verify_hostname",
        "server.test",
        "-brief",
        // Wait for the server echo and close after stdin reaches EOF.
        "-ign_eof",
    ];
    args.extend_from_slice(OSSL_CNSA2);
    let mut child = Command::new("openssl")
        .args(&args)
        .current_dir(&dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(b"hello\n").unwrap();
    let out = child.wait_with_output().unwrap();
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let r = h
        .join()
        .unwrap()
        .unwrap_or_else(|e| panic!("our server: {e}\n{text}"));
    assert!(
        text.contains("Verification: OK"),
        "OpenSSL did not verify our chain\n{text}"
    );
    assert!(text.contains("MLKEM1024"), "{text}");
    assert_eq!(r.group, Some(NamedGroup::MlKem1024));
    assert_eq!(r.suite, Some(CipherSuite::TlsAes256GcmSha384));
    assert!(r.has(Property::FipsApprovedAlgorithms), "{}", r.to_json());
}
