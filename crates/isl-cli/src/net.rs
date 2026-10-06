//! Live connections: `isl probe`, `isl serve`, and the `tls_probe` MCP tool.
//!
//! The probe drives the sans-I/O engine directly rather than through
//! `TlsStream`, so that a failed handshake still yields a full report — the
//! error id, the alert, the events up to the failure — joined with the
//! ontology's recovery steps for that error. An agent gets the diagnosis and
//! the remedy in one answer.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use ic_json::{parse, Json};
use ironsocketlayer::config::{ClientConfig, Identity, Profile, ServerConfig};
use ironsocketlayer::crypto::sign::SigningKey;
use ironsocketlayer::stream::TlsStream;
use ironsocketlayer::x509::{RootStore, ServerName};
use ironsocketlayer::Connection;

const TIMEOUT: Duration = Duration::from_secs(10);

fn parse_profile(p: Option<&str>) -> Result<Profile, String> {
    let Some(p) = p else {
        return Ok(Profile::Default);
    };
    let id = if p.starts_with("profile:") {
        p.to_string()
    } else {
        format!("profile:{p}")
    };
    Profile::from_id(&id).ok_or_else(|| format!("unknown profile '{p}'; run `isl profiles`"))
}

fn split_target(target: &str) -> Result<(String, u16), String> {
    let (host, port) = match target.rsplit_once(':') {
        Some((h, p)) if !h.contains(':') || h.starts_with('[') => {
            let port = p
                .parse::<u16>()
                .map_err(|_| format!("bad port in '{target}'"))?;
            (
                h.trim_start_matches('[').trim_end_matches(']').to_string(),
                port,
            )
        }
        _ => (target.to_string(), 443),
    };
    ServerName::parse(&host)
        .map_err(|_| format!("'{host}' is neither a DNS name nor an IP address"))?;
    Ok((host, port))
}

fn alpn_list(alpn: Option<&str>) -> Vec<Vec<u8>> {
    alpn.map(|a| {
        a.split(',')
            .filter(|s| !s.is_empty())
            .map(|s| s.as_bytes().to_vec())
            .collect()
    })
    .unwrap_or_default()
}

fn prepare(profile: Profile) -> Result<(), String> {
    if profile.requires_fips() {
        ironsocketlayer::policy::enable_fips().map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// Fetch `host`'s ECHConfigList from its DNS HTTPS record, over
/// DNS-over-HTTPS to Cloudflare's resolver, using IronSocketLayer itself.
pub fn fetch_ech_config(host: &str) -> Result<Vec<u8>, String> {
    let roots = RootStore::from_system().map_err(|e| e.to_string())?;
    let config = Arc::new(ClientConfig::new(Profile::Default, roots).map_err(|e| e.to_string())?);
    let resolver = "cloudflare-dns.com";
    let sock =
        TcpStream::connect((resolver, 443)).map_err(|e| format!("connect {resolver}: {e}"))?;
    sock.set_read_timeout(Some(TIMEOUT))
        .map_err(|e| e.to_string())?;
    let mut tls = TlsStream::connect(sock, config, resolver).map_err(|e| e.to_string())?;
    write!(
        tls,
        "GET /dns-query?name={host}&type=HTTPS HTTP/1.1
Host: {resolver}
Accept: application/dns-json
Connection: close

"
    )
    .map_err(|e| e.to_string())?;
    let mut body = Vec::new();
    // Bounded: a DNS JSON answer is small.
    let _ = (&mut tls).take(64 * 1024).read_to_end(&mut body);
    let body = String::from_utf8_lossy(&body);
    let at = body
        .find("ech=")
        .ok_or_else(|| format!("{host} publishes no ECH configuration in DNS"))?
        + 4;
    let b64: String = body[at..]
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '='))
        .collect();
    let mut out = vec![0u8; b64.len()];
    let n = ic_core::codec::base64_decode(b64.as_bytes(), &mut out).map_err(|e| e.to_string())?;
    out.truncate(n);
    Ok(out)
}

/// Whether an address is one an agent's probe should not reach without the
/// operator's say-so: loopback, private (RFC 1918, unique-local), link-local
/// (including cloud metadata at 169.254.169.254), shared, unspecified,
/// multicast or broadcast. IPv4-mapped IPv6 addresses are judged as IPv4.
pub fn is_internal(ip: std::net::IpAddr) -> bool {
    use std::net::IpAddr;
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_multicast()
                || v4.is_broadcast()
                || o[0] == 0
                || (o[0] == 100 && (64..128).contains(&o[1]))
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_internal(IpAddr::V4(v4));
            }
            let s = v6.segments();
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (s[0] & 0xfe00) == 0xfc00
                || (s[0] & 0xffc0) == 0xfe80
        }
    }
}

/// Run one handshake over TCP; returns the connection and any transport error.
fn handshake_once(
    addr: std::net::SocketAddr,
    host: &str,
    config: ClientConfig,
) -> Result<(Connection, Option<String>), String> {
    let mut sock =
        TcpStream::connect_timeout(&addr, TIMEOUT).map_err(|e| format!("connect {addr}: {e}"))?;
    sock.set_read_timeout(Some(TIMEOUT))
        .map_err(|e| e.to_string())?;
    sock.set_write_timeout(Some(TIMEOUT))
        .map_err(|e| e.to_string())?;
    let mut conn = Connection::client(Arc::new(config), host).map_err(|e| e.to_string())?;
    let mut buf = vec![0u8; 32 * 1024];
    // An absolute bound as well as the per-read one: a peer trickling a byte
    // just inside each read timeout cannot hold the probe indefinitely.
    let deadline = std::time::Instant::now() + 3 * TIMEOUT;
    let transport_error = loop {
        if std::time::Instant::now() > deadline {
            break Some("handshake deadline exceeded".into());
        }
        let out = conn.take_tls();
        if !out.is_empty() {
            if let Err(e) = sock.write_all(&out) {
                break Some(e.to_string());
            }
        }
        if !conn.is_handshaking() {
            break None;
        }
        match sock.read(&mut buf) {
            Ok(0) => break Some("peer closed the TCP connection".into()),
            Ok(n) => {
                if conn.read_tls(&buf[..n]).is_err() {
                    let _ = sock.write_all(&conn.take_tls());
                    break None;
                }
            }
            Err(e) => break Some(e.to_string()),
        }
    };
    conn.close();
    let _ = sock.write_all(&conn.take_tls());
    Ok((conn, transport_error))
}

/// Connect, complete the handshake, close, and report — success or failure.
///
/// With `ech`, the host's ECH configuration is fetched from DNS and the real
/// name is sent only encrypted; if the server rejects it and supplies retry
/// configurations, one retry is made with those.
pub fn tls_probe(
    target: &str,
    profile: Option<&str>,
    alpn: Option<&str>,
    ech: bool,
    allow_internal: bool,
) -> Result<Json, String> {
    let (host, port) = split_target(target)?;
    let profile = parse_profile(profile)?;
    prepare(profile)?;
    let roots =
        RootStore::from_system().map_err(|e| format!("{e}; set SSL_CERT_FILE to a PEM bundle"))?;
    let mut config = ClientConfig::new(profile, roots).map_err(|e| e.to_string())?;
    config.common.alpn = alpn_list(alpn);
    if ech {
        config.ech_configs = Some(fetch_ech_config(&host)?);
    }
    let addr = (host.as_str(), port)
        .to_socket_addrs()
        .map_err(|e| format!("resolve {host}: {e}"))?
        .next()
        .ok_or_else(|| format!("{host} did not resolve"))?;
    // The address checked is the address connected to, so a name that
    // resolves differently on a second lookup cannot slip past.
    if !allow_internal && is_internal(addr.ip()) {
        return Err(format!(
            "{host} resolves to {}, a loopback, private, link-local or otherwise internal address;              the MCP server does not probe those unless ISL_MCP_ALLOW_PRIVATE=1 is set",
            addr.ip()
        ));
    }
    let (mut conn, mut transport_error) = handshake_once(addr, &host, config.clone())?;
    let mut retried = false;
    if conn.error().map(|e| e.kind()) == Some(ironsocketlayer::ErrorKind::EchRejected) {
        if let Some(retry) = conn.ech_retry_configs().map(|r| r.to_vec()) {
            config.ech_configs = Some(retry);
            (conn, transport_error) = handshake_once(addr, &host, config)?;
            retried = true;
        }
    }
    let mut report = parse(&conn.report().to_json()).map_err(|e| format!("internal: {e}"))?;
    if let Json::Object(map) = &mut report {
        map.insert("target".into(), Json::str(format!("{host}:{port}")));
        map.insert("echRetried".into(), Json::Bool(retried));
        if let Some(t) = transport_error {
            map.insert("transportError".into(), Json::str(t));
        }
        // What the peer objected to, from the ontology, so an agent need not
        // look the alert up separately.
        let alert_meaning = match map.get("alertReceived") {
            Some(Json::String(id)) => isl_ontology::get(id).map(|e| e.summary),
            _ => None,
        };
        if let Some(m) = alert_meaning {
            map.insert("alertReceivedMeaning".into(), Json::str(m));
        }
        let alert = match map.get("alertReceived") {
            Some(Json::String(a)) => Some(a.clone()),
            _ => None,
        };
        if let Some(h) = downgrade_hint(profile, alert.as_deref(), conn.error().map(|e| e.kind())) {
            map.insert("hint".into(), Json::str(h));
        }
        if let Some(err) = conn.error() {
            if let Some(doc) = isl_ontology::errors::get(err.id()) {
                map.insert("meaning".into(), Json::str(doc.meaning));
                map.insert(
                    "recovery".into(),
                    Json::Array(doc.recovery.iter().map(|r| Json::str(*r)).collect()),
                );
                map.insert("retryable".into(), Json::Bool(doc.retryable));
            }
            // REQ-ERR-001: refined by this connection's state.
            if let Some(action) = conn.recovery() {
                map.insert("action".into(), Json::str(action.id()));
            }
        }
    }
    Ok(report)
}

/// A restrictive profile refused for want of common parameters invites a
/// retry with a weaker one: the downgrade the profile exists to prevent. Say
/// so, where the agent reads the failure.
fn downgrade_hint(
    profile: Profile,
    alert_received: Option<&str>,
    error: Option<ironsocketlayer::ErrorKind>,
) -> Option<String> {
    let no_common = alert_received == Some("alert:handshake-failure")
        || error == Some(ironsocketlayer::ErrorKind::HandshakeFailure);
    (no_common && profile != Profile::Default).then(|| {
        format!(
            "The server shares none of {}'s parameters. Report this to the user; do not retry with a weaker profile, which is the downgrade this profile exists to prevent.",
            profile.id()
        )
    })
}

pub(crate) fn pem_blocks(text: &str, label: &str) -> Result<Vec<Vec<u8>>, String> {
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find(&begin) {
        let after = &rest[start..];
        let stop = after.find(&end).ok_or("unterminated PEM block")? + end.len();
        let block = &after[..stop];
        let mut der = vec![0u8; block.len()];
        let n =
            ic_pkix::pem::decode(label, block.as_bytes(), &mut der).map_err(|e| e.to_string())?;
        der.truncate(n);
        out.push(der);
        rest = &after[stop..];
    }
    if out.is_empty() {
        return Err(format!("no {label} blocks"));
    }
    Ok(out)
}

/// Serve TLS on `port`, echoing each connection's first message and printing
/// its session report as one JSON line.
pub fn serve(
    cert_path: &str,
    key_path: &str,
    bind: &str,
    port: u16,
    profile: Option<&str>,
    alpn: Option<&str>,
    once: bool,
) -> Result<(), String> {
    let profile = parse_profile(profile)?;
    prepare(profile)?;
    let chain = pem_blocks(
        &std::fs::read_to_string(cert_path).map_err(|e| format!("{cert_path}: {e}"))?,
        "CERTIFICATE",
    )?;
    // The key file's text is the private key: wipe it once parsed.
    let mut pem = std::fs::read(key_path).map_err(|e| format!("{key_path}: {e}"))?;
    let key = std::str::from_utf8(&pem)
        .map_err(|_| format!("{key_path}: not UTF-8 PEM"))
        .and_then(|text| SigningKey::from_pem(text).map_err(|e| e.to_string()));
    ic_core::Zeroize::zeroize(pem.as_mut_slice());
    let key = key?;
    let identity = Identity::new(chain, key).map_err(|e| e.to_string())?;
    let mut config = ServerConfig::new(profile, identity).map_err(|e| e.to_string())?;
    config.common.alpn = alpn_list(alpn);
    let config = Arc::new(config);
    config.validate().map_err(|e| e.to_string())?;
    let listener =
        TcpListener::bind((bind, port)).map_err(|e| format!("bind {bind}:{port}: {e}"))?;
    eprintln!("isl: serving {} on {bind}:{port}", profile.id());
    for sock in listener.incoming() {
        let Ok(sock) = sock else { continue };
        let _ = sock.set_read_timeout(Some(TIMEOUT));
        let _ = sock.set_write_timeout(Some(TIMEOUT));
        let limits = ironsocketlayer::stream::Timeouts::new(TIMEOUT, TIMEOUT);
        match TlsStream::accept_with(sock, config.clone(), limits) {
            Ok(mut tls) => {
                // Echo what arrives until the peer closes or goes quiet for
                // half a second after its first message, so a request of
                // any size comes back whole.
                let mut buf = vec![0u8; 16 * 1024];
                let mut first = true;
                loop {
                    match tls.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if tls.write_all(&buf[..n]).is_err() {
                                break;
                            }
                        }
                    }
                    if first {
                        first = false;
                        tls.set_timeouts(ironsocketlayer::stream::Timeouts::new(
                            TIMEOUT,
                            Duration::from_millis(500),
                        ));
                    }
                }
                let _ = tls.close();
                println!("{}", tls.report().to_json());
            }
            Err(e) => eprintln!("isl: handshake failed: {e}"),
        }
        if once {
            break;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_refused_restrictive_profile_warns_against_downgrading() {
        use ironsocketlayer::ErrorKind;
        let h = downgrade_hint(
            Profile::Cnsa2,
            Some("alert:handshake-failure"),
            Some(ErrorKind::PeerAlert),
        )
        .unwrap();
        assert!(h.contains("profile:cnsa-2") && h.contains("do not retry with a weaker profile"));
        assert!(downgrade_hint(
            Profile::PostQuantum,
            None,
            Some(ErrorKind::HandshakeFailure)
        )
        .is_some());
        // The default profile has nothing weaker to fall back to, and other
        // failures are not a lack of common parameters.
        assert!(downgrade_hint(Profile::Default, Some("alert:handshake-failure"), None).is_none());
        assert!(downgrade_hint(
            Profile::Cnsa2,
            Some("alert:bad-certificate"),
            Some(ErrorKind::PeerAlert)
        )
        .is_none());
    }

    use super::*;

    #[test]
    fn internal_addresses_are_recognised() {
        for ip in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "0.0.0.0",
            "224.0.0.1",
            "255.255.255.255",
            "::1",
            "::",
            "fe80::1",
            "fc00::1",
            "fd12::1",
            "::ffff:10.0.0.1",
            "::ffff:127.0.0.1",
        ] {
            assert!(is_internal(ip.parse().unwrap()), "{ip}");
        }
        for ip in [
            "1.1.1.1",
            "8.8.8.8",
            "100.128.0.1",
            "2606:4700::1111",
            "::ffff:1.1.1.1",
        ] {
            assert!(!is_internal(ip.parse().unwrap()), "{ip}");
        }
    }

    /// The MCP server's probe refuses an internal target before connecting.
    #[test]
    fn the_mcp_probe_refuses_internal_targets() {
        let e = tls_probe("127.0.0.1:9", None, None, false, false).unwrap_err();
        assert!(e.contains("ISL_MCP_ALLOW_PRIVATE"), "{e}");
    }

    #[test]
    fn targets_parse_or_are_refused_without_touching_the_network() {
        assert_eq!(
            split_target("example.com").unwrap(),
            ("example.com".into(), 443)
        );
        assert_eq!(
            split_target("example.com:8443").unwrap(),
            ("example.com".into(), 8443)
        );
        assert_eq!(split_target("[::1]:853").unwrap(), ("::1".into(), 853));
        for bad in ["", "exa mple.com", "example.com:99999", "\u{0}", "a..b"] {
            assert!(tls_probe(bad, None, None, false, true).is_err(), "{bad:?}");
        }
        assert!(tls_probe("example.com", Some("no-such-profile"), None, false, true).is_err());
    }
}
