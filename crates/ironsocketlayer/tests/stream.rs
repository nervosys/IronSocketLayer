//! The blocking `TlsStream` over real localhost TCP.
//!
//! The stream only moves bytes between a socket and the sans-I/O engine, so
//! these check the moving: the handshake completes, data and close_notify
//! arrive, a key update round-trips through reads and writes, and failures
//! surface as the right `io::ErrorKind` on both ends.

mod common;

use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;

use common::*;
use ironsocketlayer::config::Profile;
use ironsocketlayer::crypto::sign::KeyKind;
use ironsocketlayer::stream::TlsStream;

fn listener() -> (TcpListener, std::net::SocketAddr) {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    (l, addr)
}

#[test]
fn request_and_response_with_close_notify() {
    let pki = Pki::new(KeyKind::EcdsaP256, "server.test");
    let sc = Arc::new(pki.server_config(Profile::Default));
    let cc = Arc::new(pki.client_config(Profile::Default));
    let (l, addr) = listener();
    let server = thread::spawn(move || {
        let mut s = TlsStream::accept(l.accept().unwrap().0, sc).unwrap();
        let mut req = [0u8; 5];
        s.read_exact(&mut req).unwrap();
        assert_eq!(&req, b"hello");
        s.write_all(b"world").unwrap();
        s.flush().unwrap();
        s.close().unwrap();
        s.report().resumed
    });

    let mut c = TlsStream::connect(TcpStream::connect(addr).unwrap(), cc, "server.test").unwrap();
    assert_eq!(c.get_ref().peer_addr().unwrap(), addr);
    assert!(c
        .report()
        .has(ironsocketlayer::report::Property::PostQuantumKeyExchange));
    let mut ekm = [0u8; 32];
    c.connection()
        .export_keying_material(b"stream test", b"", &mut ekm)
        .unwrap();
    c.write_all(b"hello").unwrap();
    let mut resp = Vec::new();
    // close_notify ends the stream: read_to_end returns rather than hanging.
    c.read_to_end(&mut resp).unwrap();
    assert_eq!(resp, b"world");
    assert!(!server.join().unwrap());
    // Reading on after close_notify keeps returning end of stream.
    assert_eq!(c.read(&mut [0u8; 8]).unwrap(), 0);
}

#[test]
fn a_key_update_round_trips_through_the_stream() {
    let pki = Pki::new(KeyKind::EcdsaP256, "server.test");
    let sc = Arc::new(pki.server_config(Profile::Default));
    let cc = Arc::new(pki.client_config(Profile::Default));
    let (l, addr) = listener();
    let server = thread::spawn(move || {
        let mut s = TlsStream::accept(l.accept().unwrap().0, sc).unwrap();
        let mut buf = [0u8; 4];
        for _ in 0..2 {
            // Reading the KeyUpdate queues the server's own; the stream must
            // flush it, or the client's next read would never decrypt.
            s.read_exact(&mut buf).unwrap();
            s.write_all(&buf).unwrap();
        }
        s.report().key_updates_sent
    });

    let mut c = TlsStream::connect(TcpStream::connect(addr).unwrap(), cc, "server.test").unwrap();
    let mut buf = [0u8; 4];
    c.write_all(b"ping").unwrap();
    c.read_exact(&mut buf).unwrap();
    c.connection().key_update(true).unwrap();
    c.write_all(b"pong").unwrap();
    c.read_exact(&mut buf).unwrap();
    assert_eq!(&buf, b"pong");
    assert_eq!(c.report().key_updates_sent, 1);
    assert_eq!(c.report().key_updates_received, 1);
    assert_eq!(server.join().unwrap(), 1);
}

#[test]
fn the_wrong_name_fails_on_both_ends() {
    let pki = Pki::new(KeyKind::EcdsaP256, "server.test");
    let sc = Arc::new(pki.server_config(Profile::Default));
    let cc = Arc::new(pki.client_config(Profile::Default));
    let (l, addr) = listener();
    let server = thread::spawn(move || TlsStream::accept(l.accept().unwrap().0, sc).map(drop));

    let err = TlsStream::connect(TcpStream::connect(addr).unwrap(), cc, "other.test").unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::InvalidData, "{err}");
    // The server refused the name with unrecognized_name (REQ-NEG-002);
    // both ends fail.
    let err = server.join().unwrap().unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::InvalidData, "{err}");
}

#[test]
fn a_peer_that_hangs_up_mid_handshake_is_unexpected_eof() {
    let pki = Pki::new(KeyKind::EcdsaP256, "server.test");
    let cc = Arc::new(pki.client_config(Profile::Default));
    let (l, addr) = listener();
    let server = thread::spawn(move || {
        let (mut sock, _) = l.accept().unwrap();
        // Read the whole ClientHello record, so closing sends FIN, not RST.
        let mut header = [0u8; 5];
        sock.read_exact(&mut header).unwrap();
        let len = u16::from_be_bytes([header[3], header[4]]) as usize;
        let mut body = vec![0u8; len];
        sock.read_exact(&mut body).unwrap();
        sock.shutdown(Shutdown::Both).unwrap();
    });
    let err = TlsStream::connect(TcpStream::connect(addr).unwrap(), cc, "server.test").unwrap_err();
    server.join().unwrap();
    assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof, "{err}");
}

#[test]
fn writing_after_close_is_a_broken_pipe() {
    let pki = Pki::new(KeyKind::EcdsaP256, "server.test");
    let sc = Arc::new(pki.server_config(Profile::Default));
    let cc = Arc::new(pki.client_config(Profile::Default));
    let (l, addr) = listener();
    let server = thread::spawn(move || {
        let mut s = TlsStream::accept(l.accept().unwrap().0, sc).unwrap();
        let mut rest = Vec::new();
        s.read_to_end(&mut rest).unwrap();
        rest
    });
    let mut c = TlsStream::connect(TcpStream::connect(addr).unwrap(), cc, "server.test").unwrap();
    c.write_all(b"last words").unwrap();
    c.close().unwrap();
    let err = c.write(b"too late").unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::BrokenPipe, "{err}");
    assert_eq!(server.join().unwrap(), b"last words");
}

#[test]
fn a_peer_that_only_reads_still_answers_a_key_update() {
    let pki = Pki::new(KeyKind::EcdsaP256, "server.test");
    let sc = Arc::new(pki.server_config(Profile::Default));
    let cc = Arc::new(pki.client_config(Profile::Default));
    let (l, addr) = listener();
    let server = thread::spawn(move || {
        let mut s = TlsStream::accept(l.accept().unwrap().0, sc).unwrap();
        let mut buf = [0u8; 4];
        s.read_exact(&mut buf).unwrap();
        // Never write: only reading may send the KeyUpdate response. Wait for
        // the client to go away.
        let _ = s.read(&mut buf);
    });

    let mut c = TlsStream::connect(TcpStream::connect(addr).unwrap(), cc, "server.test").unwrap();
    c.connection().key_update(true).unwrap();
    c.write_all(b"ping").unwrap();
    c.get_ref()
        .set_read_timeout(Some(std::time::Duration::from_millis(500)))
        .unwrap();
    // No application data is coming; the read gives up, having processed
    // whatever the server sent.
    let err = c.read(&mut [0u8; 4]).unwrap_err();
    assert!(
        matches!(
            err.kind(),
            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
        ),
        "{err}"
    );
    assert_eq!(c.report().key_updates_received, 1);
    drop(c);
    server.join().unwrap();
}

/// Run `f` on a thread and fail, rather than hang, if it takes longer than
/// `limit`.
fn within<T: Send + 'static>(
    limit: std::time::Duration,
    f: impl FnOnce() -> T + Send + 'static,
) -> T {
    let (tx, rx) = std::sync::mpsc::channel();
    thread::spawn(move || {
        let _ = tx.send(f());
    });
    rx.recv_timeout(limit)
        .expect("the call did not return in time")
}

/// REQ-CONN-014: a server that accepts the connection and then says nothing
/// fails the client's handshake at the deadline.
#[test]
fn a_silent_server_fails_the_handshake_deadline() {
    use ironsocketlayer::stream::Timeouts;
    use std::time::{Duration, Instant};
    let pki = Pki::new(KeyKind::EcdsaP256, "server.test");
    let cc = Arc::new(pki.client_config(Profile::Default));
    let (l, addr) = listener();
    let _keep = thread::spawn(move || {
        let (sock, _) = l.accept().unwrap();
        thread::sleep(Duration::from_secs(5));
        drop(sock);
    });
    let started = Instant::now();
    let err = within(Duration::from_secs(4), move || {
        let timeouts = Timeouts {
            handshake: Some(Duration::from_millis(300)),
            idle: None,
        };
        TlsStream::connect_with(
            TcpStream::connect(addr).unwrap(),
            cc,
            "server.test",
            timeouts,
        )
        .unwrap_err()
    });
    assert_eq!(err.kind(), io::ErrorKind::TimedOut, "{err}");
    assert!(started.elapsed() < Duration::from_secs(2));
}

/// REQ-CONN-014: the handshake limit is a deadline, so a peer that drips one
/// byte at a time (never idle long enough for a per-read timeout) is still
/// cut off. Here the client's own accept side is the victim.
#[test]
fn a_drip_feeding_peer_cannot_stretch_the_handshake() {
    use ironsocketlayer::stream::Timeouts;
    use std::time::{Duration, Instant};
    let pki = Pki::new(KeyKind::EcdsaP256, "server.test");
    let sc = Arc::new(pki.server_config(Profile::Default));
    let (l, addr) = listener();
    let _dripper = thread::spawn(move || {
        let mut sock = TcpStream::connect(addr).unwrap();
        // A record header announcing 16 KiB, then one byte every 50 ms.
        let _ = sock.write_all(&[22, 3, 1, 0x40, 0]);
        for _ in 0..100 {
            if sock.write_all(&[0]).is_err() {
                break;
            }
            thread::sleep(Duration::from_millis(50));
        }
    });
    let started = Instant::now();
    let err = within(Duration::from_secs(4), move || {
        let timeouts = Timeouts {
            handshake: Some(Duration::from_millis(500)),
            idle: Some(Duration::from_millis(200)),
        };
        TlsStream::accept_with(l.accept().unwrap().0, sc, timeouts).unwrap_err()
    });
    assert_eq!(err.kind(), io::ErrorKind::TimedOut, "{err}");
    let took = started.elapsed();
    assert!(
        took < Duration::from_millis(1500),
        "took {took:?}: the deadline was stretched"
    );
}

/// REQ-CONN-014: after the handshake, a read that waits longer than the
/// idle limit times out, and the stream stays usable: the data that
/// arrives later is still read.
#[test]
fn an_idle_read_times_out_and_the_stream_survives() {
    use ironsocketlayer::stream::Timeouts;
    use std::time::Duration;
    let pki = Pki::new(KeyKind::EcdsaP256, "server.test");
    let sc = Arc::new(pki.server_config(Profile::Default));
    let cc = Arc::new(pki.client_config(Profile::Default));
    let (l, addr) = listener();
    let server = thread::spawn(move || {
        let mut s = TlsStream::accept(l.accept().unwrap().0, sc).unwrap();
        thread::sleep(Duration::from_millis(700));
        s.write_all(b"late").unwrap();
        s.close().unwrap();
    });
    let got = within(Duration::from_secs(6), move || {
        let mut c = TlsStream::connect_with(
            TcpStream::connect(addr).unwrap(),
            cc,
            "server.test",
            Timeouts::new(Duration::from_secs(5), Duration::from_millis(200)),
        )
        .unwrap();
        let mut buf = [0u8; 4];
        let first = c.read(&mut buf).unwrap_err();
        assert_eq!(first.kind(), io::ErrorKind::TimedOut, "{first}");
        let mut c = c;
        let mut out = Vec::new();
        loop {
            match c.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => out.extend_from_slice(&buf[..n]),
                Err(e) if e.kind() == io::ErrorKind::TimedOut => continue,
                Err(e) => panic!("{e}"),
            }
        }
        out
    });
    assert_eq!(got, b"late");
    server.join().unwrap();
}

/// REQ-CONN-016: a server whose handshake fails while the client's bytes
/// are still unread closes gracefully, so the client reads the alert rather
/// than a connection reset.
#[test]
fn a_failed_handshake_delivers_its_alert_despite_unread_bytes() {
    use ironsocketlayer::stream::Timeouts;
    use std::time::Duration;
    let pki = Pki::new(KeyKind::EcdsaP256, "server.test");
    let sc = Arc::new(pki.server_config(Profile::Default));
    let (l, addr) = listener();
    let server = thread::spawn(move || {
        let (sock, _) = l.accept().unwrap();
        TlsStream::accept_with(
            sock,
            sc,
            Timeouts::new(Duration::from_secs(5), Duration::from_secs(5)),
        )
        .map(drop)
    });
    let mut sock = TcpStream::connect(addr).unwrap();
    sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    // A handshake record whose ClientHello is garbage, then a lot more that
    // the server will never read.
    let mut flight = vec![22, 3, 3, 0, 8, 1, 0, 0, 4, 9, 9, 9, 9];
    flight.extend(std::iter::repeat_n(0x16u8, 32 * 1024));
    let _ = sock.write_all(&flight);
    let mut got = Vec::new();
    let mut buf = [0u8; 64];
    loop {
        match sock.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => got.extend_from_slice(&buf[..n]),
            Err(e) => panic!("{e} after {got:?}: the alert was lost"),
        }
    }
    assert!(server.join().unwrap().is_err());
    assert_eq!(&got[..5], &[21, 3, 3, 0, 2], "{got:?}");
    assert_eq!(got[5], 2, "fatal");
}

/// REQ-CONN-014: the limits of an established stream can be changed.
#[test]
fn timeouts_can_be_changed_on_a_live_stream() {
    use ironsocketlayer::stream::Timeouts;
    use std::time::{Duration, Instant};
    let pki = Pki::new(KeyKind::EcdsaP256, "server.test");
    let sc = Arc::new(pki.server_config(Profile::Default));
    let cc = Arc::new(pki.client_config(Profile::Default));
    let (l, addr) = listener();
    let _server = thread::spawn(move || {
        let s = TlsStream::accept(l.accept().unwrap().0, sc).unwrap();
        thread::sleep(Duration::from_secs(3));
        drop(s);
    });
    let mut c = TlsStream::connect_with(
        TcpStream::connect(addr).unwrap(),
        cc,
        "server.test",
        Timeouts::new(Duration::from_secs(5), Duration::from_secs(5)),
    )
    .unwrap();
    c.set_timeouts(Timeouts::new(
        Duration::from_secs(5),
        Duration::from_millis(150),
    ));
    let started = Instant::now();
    let e = c.read(&mut [0u8; 8]).unwrap_err();
    assert_eq!(e.kind(), io::ErrorKind::TimedOut);
    assert!(started.elapsed() < Duration::from_secs(2));
}
