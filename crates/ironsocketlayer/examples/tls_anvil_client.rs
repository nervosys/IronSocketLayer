//! The client under test for TLS-Anvil (scripts/tls-anvil.sh). TLS-Anvil
//! plays a server with generated certificates that carry no subject
//! alternative name, so the client pins their public keys (verification
//! stays on: the key, the certificate's validity and the CertificateVerify
//! signature are checked; the name is not). It connects, completes the
//! handshake, sends a request, reads until the server closes or goes idle,
//! closes with close_notify, and prints the outcome.
//!
//! `tls_anvil_client <host> <port> <spki-sha256-hex>...`
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

use ironsocketlayer::config::{ClientConfig, PeerVerification, Profile};
use ironsocketlayer::stream::{Timeouts, TlsStream};
use ironsocketlayer::x509::RootStore;

fn pin(hex: &str) -> Option<[u8; 32]> {
    let mut out = [0u8; 32];
    if hex.len() != 64 {
        return None;
    }
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(hex.get(2 * i..2 * i + 2)?, 16).ok()?;
    }
    Some(out)
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (Some(host), Some(port)) = (args.first(), args.get(1)) else {
        eprintln!("usage: tls_anvil_client <host> <port> <spki-sha256-hex>...");
        std::process::exit(2);
    };
    let sha256: Vec<[u8; 32]> = args[2..].iter().filter_map(|h| pin(h)).collect();
    if sha256.is_empty() || sha256.len() != args.len() - 2 {
        eprintln!("each pin must be 64 hex digits");
        std::process::exit(2);
    }
    let mut config =
        ClientConfig::new(Profile::Default, RootStore::new()).expect("default profile");
    config.verification = PeerVerification::PinnedSpki {
        sha256,
        check_names: false,
    };
    let outcome = (|| -> std::io::Result<usize> {
        let tcp = TcpStream::connect((host.as_str(), port.parse::<u16>().unwrap_or(8443)))?;
        let mut tls = TlsStream::connect_with(
            tcp,
            Arc::new(config),
            "tls-attacker.com",
            Timeouts::new(Duration::from_secs(10), Duration::from_secs(5)),
        )?;
        tls.write_all(b"GET / HTTP/1.0\r\n\r\n")?;
        tls.flush()?;
        let mut buf = Vec::new();
        let read = tls.read_to_end(&mut buf);
        // However reading ended, close as an application should: with
        // close_notify (RFC 8446 §6.1).
        let closed = tls.close();
        read?;
        closed?;
        Ok(buf.len())
    })();
    match outcome {
        Ok(n) => println!("ok: handshake completed, {n} bytes received"),
        Err(e) => {
            println!("refused: {e}");
            std::process::exit(1);
        }
    }
}
