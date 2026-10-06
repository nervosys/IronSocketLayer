//! Blocking TLS over any `Read + Write` transport (std only).
//!
//! A thin driver around the sans-I/O [`Connection`]: it moves bytes between
//! the socket and the engine and nothing else, so every protocol decision
//! stays in code that the in-memory tests exercise.

use std::io::{self, Read, Write};
use std::sync::Arc;

use crate::config::{ClientConfig, ServerConfig};
use crate::conn::Connection;
use crate::error::{Error, ErrorKind};
use crate::report::SessionReport;

/// A TLS 1.3 stream.
#[derive(Debug)]
pub struct TlsStream<S: Read + Write> {
    conn: Connection,
    sock: S,
    eof: bool,
}

fn to_io(e: Error) -> io::Error {
    let kind = match e.kind() {
        ErrorKind::Closed => io::ErrorKind::BrokenPipe,
        ErrorKind::InvalidConfig | ErrorKind::InvalidState => io::ErrorKind::InvalidInput,
        _ => io::ErrorKind::InvalidData,
    };
    io::Error::new(kind, e)
}

impl<S: Read + Write> TlsStream<S> {
    /// Connect as a client and complete the handshake.
    pub fn connect(sock: S, config: Arc<ClientConfig>, server_name: &str) -> io::Result<Self> {
        let conn = Connection::client(config, server_name).map_err(to_io)?;
        let mut s = Self {
            conn,
            sock,
            eof: false,
        };
        s.complete_handshake()?;
        Ok(s)
    }

    /// Accept as a server and complete the handshake.
    pub fn accept(sock: S, config: Arc<ServerConfig>) -> io::Result<Self> {
        let conn = Connection::server(config).map_err(to_io)?;
        let mut s = Self {
            conn,
            sock,
            eof: false,
        };
        s.complete_handshake()?;
        Ok(s)
    }

    fn flush_tls(&mut self) -> io::Result<()> {
        let out = self.conn.take_tls();
        if !out.is_empty() {
            self.sock.write_all(&out)?;
            self.sock.flush()?;
        }
        Ok(())
    }

    fn read_some(&mut self) -> io::Result<usize> {
        let mut buf = [0u8; 16 * 1024 + 512];
        let n = self.sock.read(&mut buf)?;
        if n == 0 {
            self.eof = true;
            return Ok(0);
        }
        let r = self.conn.read_tls(&buf[..n]);
        // Send any alert before reporting the failure.
        self.flush_tls()?;
        r.map_err(to_io)?;
        Ok(n)
    }

    fn complete_handshake(&mut self) -> io::Result<()> {
        self.flush_tls()?;
        while self.conn.is_handshaking() {
            if self.read_some()? == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "peer closed during the handshake",
                ));
            }
            self.flush_tls()?;
        }
        Ok(())
    }

    /// What was negotiated and what holds.
    pub fn report(&self) -> &SessionReport {
        self.conn.report()
    }

    /// The engine, for exporters, key updates and inspection.
    pub fn connection(&mut self) -> &mut Connection {
        &mut self.conn
    }

    /// Send close_notify and flush.
    pub fn close(&mut self) -> io::Result<()> {
        self.conn.close();
        self.flush_tls()
    }

    /// The underlying transport.
    pub fn get_ref(&self) -> &S {
        &self.sock
    }
}

impl<S: Read + Write> Read for TlsStream<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            if self.conn.available() > 0 {
                return Ok(self.conn.recv(buf));
            }
            if self.conn.peer_closed() {
                return Ok(0);
            }
            // REQ-CONN-011: the transport ended without close_notify. That
            // may be truncation by an attacker, so it is not reported as a
            // clean end of stream (RFC 8446 §6.1).
            if self.eof {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "the peer closed the transport without close_notify (possible truncation)",
                ));
            }
            self.read_some()?;
            // A KeyUpdate response may be waiting.
            self.flush_tls()?;
        }
    }
}

impl<S: Read + Write> Write for TlsStream<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.conn.send(buf).map_err(to_io)?;
        self.flush_tls()?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.flush_tls()
    }
}
