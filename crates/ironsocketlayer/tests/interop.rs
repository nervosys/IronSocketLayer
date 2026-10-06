//! Interoperability against independent TLS 1.3 implementations on the
//! public internet.
//!
//! The in-memory tests show the client and server agree with each other;
//! only a handshake with someone else's code shows they agree with RFC 8446.
//! A completed handshake here exercises, against an independent
//! implementation, the key schedule, transcript hashing, the record layer,
//! certificate path validation to a real root, and the named group.
//!
//! These need the network and a system trust store, so they are ignored by
//! default: `cargo test -p ironsocketlayer --test interop -- --ignored`.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

use ironsocketlayer::config::{ClientConfig, Profile};
use ironsocketlayer::enums::NamedGroup;
use ironsocketlayer::report::Property;
use ironsocketlayer::stream::TlsStream;
use ironsocketlayer::x509::RootStore;

fn get(host: &str, config: ClientConfig) -> (String, ironsocketlayer::report::SessionReport) {
    let sock = TcpStream::connect((host, 443)).expect("tcp connect");
    sock.set_read_timeout(Some(Duration::from_secs(15)))
        .unwrap();
    let mut tls =
        TlsStream::connect(sock, Arc::new(config), host).unwrap_or_else(|e| panic!("{host}: {e}"));
    write!(tls, "HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nUser-Agent: ironsocketlayer-interop\r\n\r\n").unwrap();
    let mut buf = Vec::new();
    let _ = tls.read_to_end(&mut buf);
    let head = String::from_utf8_lossy(&buf)
        .lines()
        .next()
        .unwrap_or_default()
        .to_string();
    (head, tls.report().clone())
}

fn roots() -> RootStore {
    RootStore::from_system().expect("a system CA bundle (set SSL_CERT_FILE)")
}

#[test]
#[ignore = "needs the network"]
fn hybrid_post_quantum_with_cloudflare() {
    let (status, report) = get(
        "cloudflare.com",
        ClientConfig::new(Profile::Default, roots()).unwrap(),
    );
    assert!(status.starts_with("HTTP/1.1"), "{status}");
    assert_eq!(
        report.group,
        Some(NamedGroup::X25519MlKem768),
        "{}",
        report.to_json()
    );
    assert!(report.has(Property::PostQuantumKeyExchange));
    println!("{}", report.to_json());
}

#[test]
#[ignore = "needs the network"]
fn classical_groups_and_every_suite_with_major_servers() {
    for host in ["www.google.com", "cloudflare.com", "github.com"] {
        for suite in ironsocketlayer::record::IMPLEMENTED_SUITES {
            for group in [NamedGroup::X25519, NamedGroup::Secp256r1] {
                let mut c = ClientConfig::new(Profile::Default, roots()).unwrap();
                c.common.suites = vec![*suite];
                c.common.groups = vec![group];
                c.initial_key_shares = 1;
                let (status, report) = get(host, c);
                assert!(
                    status.starts_with("HTTP/1.1"),
                    "{host} {suite} {group}: {status}"
                );
                assert_eq!(report.suite, Some(*suite));
                assert_eq!(report.group, Some(group));
            }
        }
    }
}

#[test]
#[ignore = "needs the network"]
fn hello_retry_request_against_a_real_server() {
    // Offer a share only for P-521 but also list X25519 in supported_groups:
    // servers that prefer X25519 answer with a HelloRetryRequest.
    let mut c = ClientConfig::new(Profile::Default, roots()).unwrap();
    c.common.groups = vec![NamedGroup::Secp521r1, NamedGroup::X25519];
    c.initial_key_shares = 1;
    let (status, report) = get("www.google.com", c);
    assert!(status.starts_with("HTTP/1.1"), "{status}");
    assert!(report.hello_retry, "{}", report.to_json());
    assert_eq!(report.group, Some(NamedGroup::X25519));
}

#[test]
#[ignore = "needs the network"]
fn session_resumption_with_cloudflare() {
    let config = ClientConfig::new(Profile::Default, roots()).unwrap();
    let store = config.tickets.clone();
    let config = Arc::new(config);
    let connect = |cfg: &Arc<ClientConfig>| {
        let sock = TcpStream::connect(("cloudflare.com", 443)).unwrap();
        sock.set_read_timeout(Some(Duration::from_secs(15)))
            .unwrap();
        let mut tls = TlsStream::connect(sock, cfg.clone(), "cloudflare.com").unwrap();
        write!(
            tls,
            "HEAD / HTTP/1.1\r\nHost: cloudflare.com\r\nConnection: close\r\n\r\n"
        )
        .unwrap();
        let mut buf = Vec::new();
        let _ = tls.read_to_end(&mut buf);
        assert!(buf.starts_with(b"HTTP/1.1"));
        tls.report().clone()
    };
    let first = connect(&config);
    assert!(!first.resumed);
    assert!(
        first.tickets_received > 0,
        "server issued no ticket: {}",
        first.to_json()
    );
    assert!(store.is_some());
    let second = connect(&config);
    assert!(second.resumed, "{}", second.to_json());
    assert_eq!(second.group, Some(NamedGroup::X25519MlKem768));
}

/// Fetch a host's ECHConfigList from its DNS HTTPS record, over DNS-over-HTTPS
/// with this crate's own client.
fn fetch_ech_config(host: &str) -> Vec<u8> {
    let (body, _) = get_path(
        "cloudflare-dns.com",
        &format!("/dns-query?name={host}&type=HTTPS"),
        "application/dns-json",
    );
    let at = body.find("ech=").expect("no ech= in the HTTPS record") + 4;
    let b64: String = body[at..]
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '+' || *c == '/' || *c == '=')
        .collect();
    let mut out = vec![0u8; b64.len()];
    let n = ic_core::codec::base64_decode(b64.as_bytes(), &mut out).expect("base64");
    out.truncate(n);
    out
}

fn get_path(
    host: &str,
    path: &str,
    accept: &str,
) -> (String, ironsocketlayer::report::SessionReport) {
    get_with(
        host,
        path,
        accept,
        ClientConfig::new(Profile::Default, roots()).unwrap(),
    )
}

fn get_with(
    host: &str,
    path: &str,
    accept: &str,
    config: ClientConfig,
) -> (String, ironsocketlayer::report::SessionReport) {
    let sock = TcpStream::connect((host, 443)).expect("tcp connect");
    sock.set_read_timeout(Some(Duration::from_secs(15)))
        .unwrap();
    let mut tls =
        TlsStream::connect(sock, Arc::new(config), host).unwrap_or_else(|e| panic!("{host}: {e}"));
    write!(
        tls,
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nAccept: {accept}\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut buf = Vec::new();
    let _ = tls.read_to_end(&mut buf);
    (
        String::from_utf8_lossy(&buf).into_owned(),
        tls.report().clone(),
    )
}

#[test]
#[ignore = "needs the network"]
fn encrypted_client_hello_with_cloudflare() {
    let list = fetch_ech_config("crypto.cloudflare.com");
    let mut config = ClientConfig::new(Profile::Default, roots()).unwrap();
    config.ech_configs = Some(list);
    let (body, report) = get_with(
        "crypto.cloudflare.com",
        "/cdn-cgi/trace",
        "text/plain",
        config,
    );
    assert_eq!(report.ech, "ech:accepted", "{}", report.to_json());
    assert!(report.has(Property::EncryptedClientHello));
    // Cloudflare's own view of the connection.
    assert!(body.contains("sni=encrypted"), "{body}");
    assert!(body.contains("tls=TLSv1.3"), "{body}");
}

#[test]
#[ignore = "needs the network"]
fn cloudflare_rejects_an_unknown_ech_key_and_its_retry_configs_work() {
    use ironsocketlayer::ech::EchServer;
    use ironsocketlayer::Connection;
    let real = ironsocketlayer::ech::parse_config_list(&fetch_ech_config("crypto.cloudflare.com"))
        .unwrap();
    // Same public name and config id, but a key Cloudflare does not hold.
    let fake = EchServer::generate(
        real[0].config_id,
        &real[0].public_name,
        real[0].maximum_name_length,
        &mut ic_drbg::Rng::from_os().unwrap(),
    )
    .unwrap();
    let mut config = ClientConfig::new(Profile::Default, roots()).unwrap();
    config.ech_configs = Some(fake.config_list().to_vec());
    let mut conn = Connection::client(Arc::new(config), "crypto.cloudflare.com").unwrap();
    let mut sock = TcpStream::connect(("crypto.cloudflare.com", 443)).unwrap();
    sock.set_read_timeout(Some(Duration::from_secs(15)))
        .unwrap();
    let mut buf = vec![0u8; 32 * 1024];
    while conn.error().is_none() && conn.is_handshaking() {
        sock.write_all(&conn.take_tls()).unwrap();
        let n = sock.read(&mut buf).unwrap();
        assert!(n > 0, "server closed");
        let _ = conn.read_tls(&buf[..n]);
    }
    let _ = sock.write_all(&conn.take_tls());
    assert_eq!(
        conn.error().map(|e| e.kind()),
        Some(ironsocketlayer::ErrorKind::EchRejected),
        "{}",
        conn.report().to_json()
    );
    assert_eq!(
        conn.report().alert_sent,
        Some(ironsocketlayer::enums::AlertDescription::EchRequired)
    );
    let retry = conn
        .ech_retry_configs()
        .expect("Cloudflare sent retry configs")
        .to_vec();

    let mut config = ClientConfig::new(Profile::Default, roots()).unwrap();
    config.ech_configs = Some(retry);
    let (body, report) = get_with(
        "crypto.cloudflare.com",
        "/cdn-cgi/trace",
        "text/plain",
        config,
    );
    assert_eq!(report.ech, "ech:accepted");
    assert!(body.contains("sni=encrypted"), "{body}");
}
