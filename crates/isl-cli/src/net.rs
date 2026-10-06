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
    let _ = tls.read_to_end(&mut body);
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
    let transport_error = loop {
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

fn pem_blocks(text: &str, label: &str) -> Result<Vec<Vec<u8>>, String> {
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
    let key = SigningKey::from_pem(
        &std::fs::read_to_string(key_path).map_err(|e| format!("{key_path}: {e}"))?,
    )
    .map_err(|e| e.to_string())?;
    let identity = Identity::new(chain, key).map_err(|e| e.to_string())?;
    let mut config = ServerConfig::new(profile, identity).map_err(|e| e.to_string())?;
    config.common.alpn = alpn_list(alpn);
    let config = Arc::new(config);
    config.validate().map_err(|e| e.to_string())?;
    let listener = TcpListener::bind(("0.0.0.0", port)).map_err(|e| e.to_string())?;
    eprintln!("isl: serving {} on port {port}", profile.id());
    for sock in listener.incoming() {
        let Ok(sock) = sock else { continue };
        let _ = sock.set_read_timeout(Some(TIMEOUT));
        match TlsStream::accept(sock, config.clone()) {
            Ok(mut tls) => {
                let mut buf = [0u8; 4096];
                if let Ok(n) = tls.read(&mut buf) {
                    let _ = tls.write_all(&buf[..n]);
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
            assert!(tls_probe(bad, None, None, false).is_err(), "{bad:?}");
        }
        assert!(tls_probe("example.com", Some("no-such-profile"), None, false).is_err());
    }
}
