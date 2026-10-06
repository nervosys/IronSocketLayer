//! Interoperability of the fixed-capacity engine (`ironsocketlayer::fixed`)
//! with OpenSSL (3.5 or later), in both directions, over TCP.
//!
//! The same matrix as `openssl_interop.rs`: every implemented group, every key
//! type OpenSSL generates or IronSocketLayer mints, client certificates both
//! ways, and KeyUpdate in both directions. Every call into the engine after
//! initialization runs under the counting allocator and must not allocate;
//! only the socket and test bookkeeping may. Ignored by default because it
//! needs `openssl` on PATH:
//! `cargo test -p ironsocketlayer --test openssl_fixed -- --ignored --test-threads=1`.

mod common;
mod fixed_support;
mod openssl_support;

use std::net::{TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::time::Duration;

use common::Pki;
use fixed_support::{drive, no_alloc, send, Buffers};
use ironsocketlayer::config::{ClientAuth, ClientConfig, PeerVerification, Profile, ServerConfig};
use ironsocketlayer::crypto::sign::KeyKind;
use ironsocketlayer::enums::{NamedGroup, SignatureScheme};
use ironsocketlayer::fixed::{Connection, Limits};
use ironsocketlayer::report::Property;
use ironsocketlayer::x509::RootStore;
use openssl_support::*;

/// What a fixed server thread learned, copied out of its borrowed report.
#[derive(Debug)]
struct Summary {
    group: Option<NamedGroup>,
    mutual: bool,
    peer_closed: bool,
}

/// Run a fixed server for one connection on a thread: echo the first line,
/// then close. Returns the port.
fn serve_fixed_once(
    config: ServerConfig,
) -> (u16, std::thread::JoinHandle<Result<Summary, String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let h = std::thread::spawn(move || {
        let (mut sock, _) = listener.accept().map_err(|e| e.to_string())?;
        sock.set_read_timeout(Some(Duration::from_secs(20)))
            .unwrap();
        let mut buffers = Buffers::new();
        let mut rng = ic_drbg::Rng::from_os().unwrap();
        let mut conn = Connection::server(&config, &mut rng, buffers.storage(), Limits::default())
            .map_err(|e| e.to_string())?;
        let mut line = Vec::new();
        drive(&mut conn, &mut sock, &mut line, |c, app| {
            c.is_connected() && app.contains(&b'\n')
        })?;
        if !conn.is_connected() {
            return Err(format!("server: {:?}", conn.report().error));
        }
        send(&mut conn, &mut sock, &line)?;
        no_alloc(|| conn.close()).map_err(|e| e.to_string())?;
        let mut rest = Vec::new();
        drive(&mut conn, &mut sock, &mut rest, |c, _| c.peer_closed())?;
        let r = conn.report();
        Ok(Summary {
            group: r.group,
            mutual: r.has(Property::MutualAuthentication),
            peer_closed: conn.peer_closed(),
        })
    });
    (port, h)
}

/// Connect a fixed client to `port`, send `request`, and read until the
/// transport ends or `done` holds.
fn fixed_client(
    config: &ClientConfig,
    port: u16,
    request: &[u8],
    done: impl FnMut(&Connection<'_>, &[u8]) -> bool,
    check: impl FnOnce(&mut Connection<'_>, &mut TcpStream, &[u8]) -> Result<(), String>,
) -> Result<(), String> {
    let mut sock = connect_retry(port);
    let mut buffers = Buffers::new();
    let mut rng = ic_drbg::Rng::from_os().unwrap();
    let mut conn = Connection::client(
        config,
        "server.test",
        &mut rng,
        buffers.storage(),
        Limits::default(),
    )
    .map_err(|e| e.to_string())?;
    let mut app = Vec::new();
    drive(&mut conn, &mut sock, &mut app, |c, _| c.is_connected())?;
    if !conn.is_connected() {
        return Err(format!("client: {:?}", conn.report().error));
    }
    send(&mut conn, &mut sock, request)?;
    drive(&mut conn, &mut sock, &mut app, done)?;
    check(&mut conn, &mut sock, &app)
}

/// `openssl s_server` for one connection, in `dir`, with `extra` options.
fn s_server(dir: &std::path::Path, port: u16, group: &str, extra: &[&str]) -> std::process::Child {
    let port_arg = port.to_string();
    let mut args = vec![
        "s_server", "-accept", &port_arg, "-tls1_3", "-groups", group, "-key", "key.pem", "-cert",
        "cert.pem", "-naccept", "1",
    ];
    args.extend_from_slice(extra);
    Command::new("openssl")
        .args(&args)
        .current_dir(dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
}

fn client_config_for(roots: RootStore, key_name: &str) -> ClientConfig {
    let mut cfg = ClientConfig::new(Profile::Default, roots).unwrap();
    cfg.tickets = None;
    cfg.initial_key_shares = 1;
    if key_name == "ml-dsa-44" {
        cfg.common.schemes.push(SignatureScheme::MlDsa44);
    }
    cfg
}

/// REQ-FIX-004: the fixed client completes a handshake with OpenSSL's server
/// for every key type OpenSSL generates and every implemented group, and
/// recognizes OpenSSL's authenticated close.
#[test]
#[ignore = "needs openssl 3.5+ on PATH"]
fn fixed_client_against_openssl_server_for_every_key_and_group() {
    for (key_name, key_args) in KEYS {
        let dir = workdir(&format!("fixed-{key_name}"));
        openssl_identity(&dir, key_args);
        let cert = pem_to_der(&std::fs::read_to_string(dir.join("cert.pem")).unwrap());
        let mut roots = RootStore::new();
        roots.add_der(&cert).unwrap();
        for (group, ossl_group) in GROUPS {
            let mut cfg = client_config_for(roots.clone(), key_name);
            cfg.common.groups = vec![*group];
            let port = free_port();
            let mut server = s_server(&dir, port, ossl_group, &["-www"]);
            let result = fixed_client(
                &cfg,
                port,
                b"GET / HTTP/1.0\r\n\r\n",
                |c, _| c.peer_closed(),
                |c, _, app| {
                    let text = String::from_utf8_lossy(app);
                    if !text.starts_with("HTTP/1.0 200") {
                        return Err(format!("response: {text}"));
                    }
                    let r = c.report();
                    if r.group != Some(*group) || !r.has(Property::ServerAuthenticated) {
                        return Err(format!("group {:?}", r.group));
                    }
                    if !c.peer_closed() {
                        return Err("no close_notify before the transport ended".into());
                    }
                    Ok(())
                },
            );
            let _ = server.kill();
            let _ = server.wait();
            result.unwrap_or_else(|e| panic!("{key_name} / {ossl_group}: {e}"));
        }
    }
}

/// REQ-FIX-004: OpenSSL's client verifies and completes a handshake with the
/// fixed server for every key type and every implemented group.
#[test]
#[ignore = "needs openssl 3.5+ on PATH"]
fn openssl_client_against_fixed_server_for_every_key_and_group() {
    for &kind in KeyKind::ALL {
        let pki = Pki::new(kind, "server.test");
        let dir = workdir(&format!("fixed-srv-{}", kind.id().replace(':', "-")));
        std::fs::write(dir.join("ca.pem"), der_to_pem(&pki.ca_cert)).unwrap();
        for (group, ossl_group) in GROUPS {
            let mut sc = pki.server_config(Profile::Default);
            sc.tickets = None;
            sc.common.groups = vec![*group];
            let (port, h) = serve_fixed_once(sc);
            let out = s_client(&dir, port, ossl_group, &[]);
            let summary = h
                .join()
                .unwrap()
                .unwrap_or_else(|e| panic!("{kind:?} / {ossl_group}: {e}\n{out}"));
            assert!(
                out.contains("Verification: OK") && out.contains("hello"),
                "{kind:?} / {ossl_group}: OpenSSL did not verify or receive the echo\n{out}"
            );
            assert_eq!(summary.group, Some(*group));
            assert!(summary.peer_closed, "{kind:?} / {ossl_group}: {summary:?}");
        }
    }
}

/// REQ-FIX-004: the fixed server requires and verifies OpenSSL's client
/// certificate, for every key type OpenSSL generates.
#[test]
#[ignore = "needs openssl 3.5+ on PATH"]
fn openssl_client_certificate_is_verified_by_fixed_server() {
    let pki = Pki::new(KeyKind::EcdsaP256, "server.test");
    for (key_name, key_args) in KEYS {
        let dir = workdir(&format!("fixed-mtls-{key_name}"));
        std::fs::write(dir.join("ca.pem"), der_to_pem(&pki.ca_cert)).unwrap();
        openssl_identity(&dir, key_args);
        let client_cert = pem_to_der(&std::fs::read_to_string(dir.join("cert.pem")).unwrap());
        let mut client_roots = RootStore::new();
        client_roots.add_der(&client_cert).unwrap();
        let mut sc = pki
            .server_config(Profile::Default)
            .with_client_auth(ClientAuth::Required(PeerVerification::Roots(client_roots)));
        sc.tickets = None;
        if *key_name == "ml-dsa-44" {
            sc.common.schemes.push(SignatureScheme::MlDsa44);
        }
        let (port, h) = serve_fixed_once(sc);
        let out = s_client(
            &dir,
            port,
            "X25519MLKEM768",
            &["-cert", "cert.pem", "-key", "key.pem"],
        );
        let summary = h
            .join()
            .unwrap()
            .unwrap_or_else(|e| panic!("{key_name}: {e}\n{out}"));
        assert!(summary.mutual, "{key_name}: {summary:?}");
    }
}

/// REQ-FIX-004: OpenSSL's server requires and verifies the fixed client's
/// certificate, for every key type IronSocketLayer can sign with.
#[test]
#[ignore = "needs openssl 3.5+ on PATH"]
fn fixed_client_certificate_is_verified_by_openssl() {
    let dir = workdir("fixed-client-cert");
    openssl_identity(&dir, KEYS[0].1);
    let server_cert = pem_to_der(&std::fs::read_to_string(dir.join("cert.pem")).unwrap());
    let mut roots = RootStore::new();
    roots.add_der(&server_cert).unwrap();
    for &kind in KeyKind::ALL {
        let pki = Pki::new(kind, "server.test");
        std::fs::write(dir.join("ca.pem"), der_to_pem(&pki.ca_cert)).unwrap();
        let name = if kind == KeyKind::MlDsa44 {
            "ml-dsa-44"
        } else {
            ""
        };
        let mut cfg = client_config_for(roots.clone(), name);
        cfg.identity = Some(pki.client_identity(kind, "device"));
        let port = free_port();
        let mut server = s_server(
            &dir,
            port,
            "X25519MLKEM768",
            &[
                "-www",
                "-Verify",
                "1",
                "-verify_return_error",
                "-CAfile",
                "ca.pem",
            ],
        );
        let result = fixed_client(
            &cfg,
            port,
            b"GET / HTTP/1.0\r\n\r\n",
            |c, _| c.peer_closed(),
            |c, _, app| {
                let text = String::from_utf8_lossy(app);
                if !text.starts_with("HTTP/1.0 200") {
                    return Err(format!("response: {text}"));
                }
                if !c.report().has(Property::MutualAuthentication) {
                    return Err("client certificate not sent".into());
                }
                Ok(())
            },
        );
        let _ = server.kill();
        let out = server.wait_with_output().unwrap();
        result
            .unwrap_or_else(|e| panic!("{kind:?}: {e}\n{}", String::from_utf8_lossy(&out.stderr)));
    }
}

/// REQ-FIX-004: KeyUpdate interoperates in both directions. The fixed client
/// rekeys and asks OpenSSL to rekey too, many times; OpenSSL's `-rev` server
/// answers each line reversed under the new keys.
#[test]
#[ignore = "needs openssl 3.5+ on PATH"]
fn fixed_client_key_updates_with_openssl() {
    let dir = workdir("fixed-key-update");
    openssl_identity(&dir, KEYS[0].1);
    let cert = pem_to_der(&std::fs::read_to_string(dir.join("cert.pem")).unwrap());
    let mut roots = RootStore::new();
    roots.add_der(&cert).unwrap();
    let cfg = client_config_for(roots, "");
    let port = free_port();
    let mut server = s_server(&dir, port, "X25519MLKEM768", &["-rev"]);
    let result = fixed_client(
        &cfg,
        port,
        b"start\n",
        |_, app| app.ends_with(b"trats\n"),
        |c, sock, _| {
            for round in 0..80u32 {
                no_alloc(|| c.key_update(true)).map_err(|e| e.to_string())?;
                let line = format!("round {round}\n");
                send(c, sock, line.as_bytes())?;
                let mut reversed: Vec<u8> = line.trim_end().bytes().rev().collect();
                reversed.push(b'\n');
                let mut app = Vec::new();
                drive(c, sock, &mut app, |_, a| a.ends_with(&reversed))?;
                if !app.ends_with(&reversed) {
                    return Err(format!("round {round}: {}", String::from_utf8_lossy(&app)));
                }
            }
            Ok(())
        },
    );
    let _ = server.kill();
    let _ = server.wait();
    result.unwrap();
}
