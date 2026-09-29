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
use iron_socket_layer::config::Profile;
use iron_socket_layer::crypto::sign::KeyKind;
use iron_socket_layer::stream::TlsStream;

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
        .has(iron_socket_layer::report::Property::PostQuantumKeyExchange));
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
    // The client sent its alert before failing, so the server hears why.
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
