//! CNSA 1.0 as RFC 9151 profiles it, against OpenSSL 3.5: `profile:cnsa-1`
//! (P-384, AES-256-GCM, SHA-384, FIPS gate on) and an RSA-3072 chain whose
//! certificates OpenSSL signed with sha384WithRSAEncryption. RFC 9151
//! section 5.2 says that PKCS#1 v1.5 certificate signatures MUST be
//! supported in TLS 1.3, while the handshake signs with RSASSA-PSS.
//!
//! Approved mode is process-global, so this is its own test binary.
//!
//! ```console
//! $ cargo test -p ironsocketlayer --test openssl_cnsa1 -- --ignored
//! ```

mod openssl_support;

use std::io::{Read, Write};
use std::process::{Command, Stdio};
use std::sync::Arc;

use ironsocketlayer::config::{ClientConfig, Profile};
use ironsocketlayer::enums::{CipherSuite, NamedGroup, SignatureScheme};
use ironsocketlayer::report::Property;
use ironsocketlayer::stream::TlsStream;
use ironsocketlayer::x509::{Certificate, RootStore};
use openssl_support::{connect_retry, free_port, openssl, pem_to_der, workdir};

/// REQ-CFG-008: a CNSA 1.0 client accepts an RSA-3072 chain signed with
/// PKCS#1 v1.5 and SHA-384, and the server's handshake signature is
/// rsa_pss_rsae_sha384.
#[test]
#[ignore = "needs openssl 3.5+ on PATH"]
fn cnsa1_accepts_an_rsa_chain_signed_with_pkcs1_sha384() {
    ironsocketlayer::policy::enable_fips().unwrap();
    let dir = workdir("cnsa1-rsa");
    let run = |args: &[&str]| {
        let out = openssl(args, &dir);
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    };
    run(&[
        "req",
        "-x509",
        "-nodes",
        "-days",
        "2",
        "-newkey",
        "rsa:3072",
        "-sha384",
        "-keyout",
        "cakey.pem",
        "-out",
        "ca.pem",
        "-subj",
        "/CN=CNSA 1.0 Test CA",
        "-addext",
        "basicConstraints=critical,CA:TRUE",
        "-addext",
        "keyUsage=critical,keyCertSign,cRLSign",
    ]);
    run(&[
        "req",
        "-x509",
        "-nodes",
        "-days",
        "2",
        "-newkey",
        "rsa:3072",
        "-sha384",
        "-keyout",
        "key.pem",
        "-out",
        "cert.pem",
        "-CA",
        "ca.pem",
        "-CAkey",
        "cakey.pem",
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
    ]);
    let ca = pem_to_der(&std::fs::read_to_string(dir.join("ca.pem")).unwrap());
    let leaf = pem_to_der(&std::fs::read_to_string(dir.join("cert.pem")).unwrap());
    // What this test is about: OpenSSL signed the leaf with PKCS#1 v1.5.
    assert_eq!(
        Certificate::parse(&leaf)
            .unwrap()
            .signature_scheme()
            .unwrap(),
        SignatureScheme::RsaPkcs1Sha384
    );
    let mut roots = RootStore::new();
    roots.add_der(&ca).unwrap();
    let cfg = ClientConfig::new(Profile::Cnsa1, roots).unwrap();

    let port = free_port();
    let port_s = port.to_string();
    let mut server = Command::new("openssl")
        .args([
            "s_server",
            "-accept",
            &port_s,
            "-key",
            "key.pem",
            "-cert",
            "cert.pem",
            "-tls1_3",
            "-groups",
            "P-384",
            "-ciphersuites",
            "TLS_AES_256_GCM_SHA384",
            "-www",
            "-naccept",
            "1",
        ])
        .current_dir(&dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let outcome = TlsStream::connect(connect_retry(port), Arc::new(cfg), "server.test");
    let mut tls = match outcome {
        Ok(tls) => tls,
        Err(e) => {
            let _ = server.kill();
            let _ = server.wait();
            panic!("CNSA 1.0 client against OpenSSL's RSA chain: {e}");
        }
    };
    tls.write_all(b"GET / HTTP/1.0\r\n\r\n").unwrap();
    let mut body = Vec::new();
    let _ = tls.read_to_end(&mut body);
    let r = tls.report().clone();
    let _ = server.kill();
    let _ = server.wait();
    assert!(String::from_utf8_lossy(&body).starts_with("HTTP/1.0 200"));
    assert_eq!(r.profile, "profile:cnsa-1");
    assert_eq!(r.group, Some(NamedGroup::Secp384r1));
    assert_eq!(r.suite, Some(CipherSuite::TlsAes256GcmSha384));
    assert_eq!(
        r.peer_signature_scheme,
        Some(SignatureScheme::RsaPssRsaeSha384)
    );
    assert!(r.has(Property::ServerAuthenticated));
    assert!(r.has(Property::FipsApprovedAlgorithms), "{}", r.to_json());
}
