//! Blocking TLS over any `Read + Write` transport (std only).
//!
//! A thin driver around the sans-I/O [`Connection`]: it moves bytes between
//! the socket and the engine and nothing else, so every protocol decision
//! stays in code that the in-memory tests exercise.

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::config::{ClientConfig, ServerConfig};
use crate::conn::Connection;
use crate::error::{Error, ErrorKind};
use crate::report::SessionReport;

/// Time limits for a [`TlsStream`] over a TCP socket. REQ-CONN-014.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Timeouts {
    /// The whole handshake, from `connect_with` or `accept_with` to its
    /// completion. A deadline, not a per-read limit: a peer that sends one
    /// byte at a time cannot stretch it. `None` waits indefinitely.
    pub handshake: Option<Duration>,
    /// Each blocking read or write after the handshake. An idle timeout
    /// leaves the stream usable: the call can be repeated. `None` waits
    /// indefinitely.
    pub idle: Option<Duration>,
}

impl Timeouts {
    /// A handshake deadline and an idle limit.
    pub const fn new(handshake: Duration, idle: Duration) -> Self {
        Self {
            handshake: Some(handshake),
            idle: Some(idle),
        }
    }
}

/// Sets a transport's read and write timeouts.
type SetTimeout<S> = fn(&S, Option<Duration>) -> io::Result<()>;

fn tcp_timeout(sock: &TcpStream, limit: Option<Duration>) -> io::Result<()> {
    sock.set_read_timeout(limit)?;
    sock.set_write_timeout(limit)
}

/// Close a TCP connection gracefully after a failed handshake. Closing a
/// socket with the peer's bytes still unread makes the kernel send a reset,
/// which can destroy the alert just sent before the peer reads it; so send
/// FIN after the alert and drain briefly (at most 250 ms, 64 KiB) first.
/// REQ-CONN-016.
fn tcp_linger(sock: &TcpStream) {
    let _ = sock.shutdown(std::net::Shutdown::Write);
    let deadline = Instant::now() + Duration::from_millis(250);
    let mut sink = [0u8; 4096];
    let mut drained = 0usize;
    let mut s = sock;
    while drained < 64 * 1024 {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() || s.set_read_timeout(Some(left)).is_err() {
            break;
        }
        match s.read(&mut sink) {
            Ok(n) if n > 0 => drained += n,
            _ => break,
        }
    }
}

/// A TLS 1.3 stream.
pub struct TlsStream<S: Read + Write> {
    conn: Connection,
    sock: S,
    eof: bool,
    timeouts: Timeouts,
    set_timeout: Option<SetTimeout<S>>,
    linger: Option<fn(&S)>,
    deadline: Option<Instant>,
}

impl<S: Read + Write + core::fmt::Debug> core::fmt::Debug for TlsStream<S> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TlsStream")
            .field("conn", &self.conn)
            .field("sock", &self.sock)
            .field("eof", &self.eof)
            .field("timeouts", &self.timeouts)
            .finish()
    }
}

fn timed_out(handshaking: bool) -> io::Error {
    io::Error::new(
        io::ErrorKind::TimedOut,
        if handshaking {
            "the TLS handshake deadline passed"
        } else {
            "no TLS progress within the idle timeout"
        },
    )
}

/// A socket timeout surfaces as `WouldBlock` on Unix and `TimedOut` on
/// Windows; report both as `TimedOut`.
fn is_timeout(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    )
}

impl TlsStream<TcpStream> {
    /// Connect as a client and complete the handshake within
    /// `timeouts.handshake`; reads and writes afterwards wait at most
    /// `timeouts.idle`. A deadline that passes is `io::ErrorKind::TimedOut`.
    /// REQ-CONN-014.
    pub fn connect_with(
        sock: TcpStream,
        config: Arc<ClientConfig>,
        server_name: &str,
        timeouts: Timeouts,
    ) -> io::Result<Self> {
        let conn = Connection::client(config, server_name).map_err(to_io)?;
        Self::start(conn, sock, timeouts, Some(tcp_timeout), Some(tcp_linger))
    }

    /// Accept as a server within `timeouts.handshake`; as
    /// [`connect_with`](Self::connect_with). REQ-CONN-014.
    pub fn accept_with(
        sock: TcpStream,
        config: Arc<ServerConfig>,
        timeouts: Timeouts,
    ) -> io::Result<Self> {
        let conn = Connection::server(config).map_err(to_io)?;
        Self::start(conn, sock, timeouts, Some(tcp_timeout), Some(tcp_linger))
    }
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
    /// Connect as a client and complete the handshake. Waits as long as
    /// the transport does; over TCP, prefer
    /// [`connect_with`](TlsStream::connect_with) and its time limits.
    pub fn connect(sock: S, config: Arc<ClientConfig>, server_name: &str) -> io::Result<Self> {
        let conn = Connection::client(config, server_name).map_err(to_io)?;
        Self::start(conn, sock, Timeouts::default(), None, None)
    }

    /// Accept as a server and complete the handshake. Waits as long as the
    /// transport does; over TCP, prefer
    /// [`accept_with`](TlsStream::accept_with).
    pub fn accept(sock: S, config: Arc<ServerConfig>) -> io::Result<Self> {
        let conn = Connection::server(config).map_err(to_io)?;
        Self::start(conn, sock, Timeouts::default(), None, None)
    }

    fn start(
        conn: Connection,
        sock: S,
        timeouts: Timeouts,
        set_timeout: Option<SetTimeout<S>>,
        linger: Option<fn(&S)>,
    ) -> io::Result<Self> {
        let mut s = Self {
            conn,
            sock,
            eof: false,
            timeouts,
            set_timeout,
            linger,
            deadline: timeouts.handshake.map(|d| Instant::now() + d),
        };
        if let Err(e) = s.complete_handshake() {
            if let Some(linger) = s.linger {
                linger(&s.sock);
            }
            return Err(e);
        }
        Ok(s)
    }

    /// Change the time limits of an established stream; they apply from the
    /// next read or write. Has effect only on streams made with
    /// [`TlsStream::connect_with`] or [`TlsStream::accept_with`].
    /// REQ-CONN-014.
    pub fn set_timeouts(&mut self, timeouts: Timeouts) {
        self.timeouts = timeouts;
    }

    /// REQ-CONN-014: before each socket operation, limit it to what is left
    /// of the handshake deadline, or to the idle limit afterwards.
    fn arm(&mut self) -> io::Result<()> {
        let Some(set) = self.set_timeout else {
            return Ok(());
        };
        let handshaking = self.conn.is_handshaking();
        let limit = match (handshaking, self.deadline) {
            (true, Some(deadline)) => {
                let left = deadline.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    return Err(timed_out(true));
                }
                Some(left)
            }
            (true, None) => None,
            (false, _) => self.timeouts.idle,
        };
        set(&self.sock, limit)
    }

    fn flush_tls(&mut self) -> io::Result<()> {
        let out = self.conn.take_tls();
        if !out.is_empty() {
            self.arm()?;
            let handshaking = self.conn.is_handshaking();
            let sent = self.sock.write_all(&out).and_then(|()| self.sock.flush());
            sent.map_err(|e| {
                if self.set_timeout.is_some() && is_timeout(&e) {
                    timed_out(handshaking)
                } else {
                    e
                }
            })?;
        }
        Ok(())
    }

    fn read_some(&mut self) -> io::Result<usize> {
        let mut buf = [0u8; 16 * 1024 + 512];
        self.arm()?;
        let n = match self.sock.read(&mut buf) {
            Err(e) if self.set_timeout.is_some() && is_timeout(&e) => {
                return Err(timed_out(self.conn.is_handshaking()))
            }
            r => r?,
        };
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
