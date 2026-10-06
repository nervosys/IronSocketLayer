//! The sans-I/O connection engine shared by client, server, TCP and QUIC.
//!
//! A [`Connection`] never touches a socket. Bytes go in with
//! [`Connection::read_tls`] and come out of [`Connection::take_tls`]; the
//! caller moves them. That makes the engine deterministic — the same inputs
//! give the same outputs, which is what a DO-178C test harness needs to drive
//! it — and lets it run unchanged on an RTOS, in WebAssembly, or behind any
//! async runtime.
//!
//! Handshake logic lives in [`crate::client`] and [`crate::server`]; this
//! module owns the transcript, the record layer (or the QUIC level
//! bookkeeping), alerts, application data and key updates.
//!
//! Requirement trace:
//! `REQ-CONN-001` a failed connection stays failed (errors latch),
//! `REQ-CONN-002` handshake messages may not span a key change (§5.1),
//! `REQ-CONN-003` application data only after the handshake completes,
//! `REQ-CONN-004` a protected or malformed ChangeCipherSpec is fatal (§5),
//! `REQ-CONN-005` a fatal alert is sent for every local failure that maps to one,
//! `REQ-CONN-006` keys are updated before they reach their usage limit (§5.5).

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use ic_core::traits::RandomSource;

use crate::client::ClientHs;
use crate::config::{ClientConfig, Common, ServerConfig};
use crate::crypto::{Hash, HashAlg, Output};
use crate::enums::{AlertDescription, CipherSuite, ContentType, HandshakeType, KeyUpdateRequest};
use crate::error::{Error, ErrorKind, Result};
use crate::key_schedule;
use crate::msgs;
use crate::record::{self, Protector, MAX_PLAINTEXT};
use crate::report::{HandshakeState, SessionReport, Side};
use crate::server::ServerHs;

/// Encryption level (RFC 9001 §4.1.4). TLS over TCP uses the same stages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Level {
    /// Plaintext: ClientHello, ServerHello, HelloRetryRequest.
    Initial,
    /// Handshake traffic keys.
    Handshake,
    /// Application traffic keys (QUIC "1-RTT").
    Application,
    /// 0-RTT early data keys (TLS over TCP, and exported to the QUIC stack).
    Early,
}

impl Level {
    /// Stable identifier.
    pub const fn id(self) -> &'static str {
        match self {
            Self::Initial => "level:initial",
            Self::Handshake => "level:handshake",
            Self::Application => "level:application",
            Self::Early => "level:early",
        }
    }
}

/// The running handshake transcript (§4.4.1).
#[derive(Clone)]
pub(crate) struct Transcript {
    pending: Vec<u8>,
    hash: Option<Hash>,
}

impl Transcript {
    pub(crate) fn new() -> Self {
        Self {
            pending: Vec::new(),
            hash: None,
        }
    }

    pub(crate) fn add(&mut self, msg: &[u8]) {
        match &mut self.hash {
            Some(h) => h.update(msg),
            None => self.pending.extend_from_slice(msg),
        }
    }

    /// Fix the hash once the suite is known, absorbing what came before.
    pub(crate) fn start(&mut self, alg: HashAlg) -> Result<()> {
        match &self.hash {
            Some(h) if h.alg() == alg => Ok(()),
            Some(_) => Err(Error::new(
                ErrorKind::IllegalParameter,
                "hash changed mid-handshake",
            )),
            None => {
                let mut h = Hash::new(alg);
                h.update(&self.pending);
                self.pending.clear();
                self.hash = Some(h);
                Ok(())
            }
        }
    }

    /// The hash of the transcript so far plus `extra`, without absorbing
    /// `extra`: what a PSK binder covers (§4.2.11.2).
    pub(crate) fn hash_with(&self, alg: HashAlg, extra: &[u8]) -> Result<Output> {
        match &self.hash {
            Some(h) if h.alg() == alg => {
                let mut h = h.clone();
                h.update(extra);
                Ok(h.finish())
            }
            Some(_) => Err(Error::new(
                ErrorKind::Internal,
                "binder hash differs from the transcript hash",
            )),
            None => {
                let mut h = Hash::new(alg);
                h.update(&self.pending);
                h.update(extra);
                Ok(h.finish())
            }
        }
    }

    pub(crate) fn current(&self) -> Result<Output> {
        self.hash.as_ref().map(|h| h.peek()).ok_or(Error::new(
            ErrorKind::Internal,
            "transcript hash not started",
        ))
    }

    /// Replace ClientHello1 with `message_hash` after a HelloRetryRequest (§4.4.1).
    pub(crate) fn rollup_for_retry(&mut self) -> Result<()> {
        let h = self.current()?;
        let alg = self
            .hash
            .as_ref()
            .map(|h| h.alg())
            .ok_or(Error::new(ErrorKind::Internal, "transcript"))?;
        let mut fresh = Hash::new(alg);
        fresh.update(&[HandshakeType::MessageHash.to_wire(), 0, 0, h.len() as u8]);
        fresh.update(h.as_bytes());
        self.hash = Some(fresh);
        Ok(())
    }
}

/// A new key for QUIC to install, emitted as the handshake reaches each level.
pub struct KeyChange {
    /// Level the key protects.
    pub level: Level,
    /// `true` for the key this endpoint encrypts with.
    pub write: bool,
    /// The negotiated suite.
    pub suite: CipherSuite,
    /// The traffic secret, from which QUIC derives packet and header keys.
    pub secret: Output,
}

impl core::fmt::Debug for KeyChange {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "KeyChange({:?}, write={}, {})",
            self.level, self.write, self.suite
        )
    }
}

// The TLS variant holds two record protectors with their AEAD state inline
// (unboxed so the fixed-capacity engine can share them without allocating).
// A Transport is built once per connection and not moved on hot paths.
#[allow(clippy::large_enum_variant)]
pub(crate) enum Transport {
    Tls {
        read: Option<Protector>,
        write: Option<Protector>,
        incoming: Vec<u8>,
        outgoing: Vec<u8>,
        ccs_sent: bool,
        ccs_allowed: bool,
    },
    Quic {
        outgoing: VecDeque<(Level, Vec<u8>)>,
        keys: VecDeque<KeyChange>,
        write_level: Level,
        read_level: Level,
        local_params: Vec<u8>,
        peer_params: Option<Vec<u8>>,
    },
}

/// State every connection carries, whichever side and transport.
pub(crate) struct Core {
    pub(crate) side: Side,
    pub(crate) common: Common,
    pub(crate) rng: Box<dyn RandomSource + Send>,
    pub(crate) transport: Transport,
    pub(crate) transcript: Transcript,
    pub(crate) hs_buf: Vec<u8>,
    /// Compatibility ChangeCipherSpec records received.
    pub(crate) ccs_seen: u8,
    /// A KeyUpdate answering the peer's request has been sent, and no
    /// application data since.
    pub(crate) key_update_answered: bool,
    pub(crate) app_in: VecDeque<u8>,
    pub(crate) report: SessionReport,
    pub(crate) state: HandshakeState,
    pub(crate) suite: Option<CipherSuite>,
    pub(crate) exporter_secret: Option<Output>,
    pub(crate) error: Option<Error>,
    pub(crate) peer_closed: bool,
    pub(crate) sent_close: bool,
    pub(crate) peer_chain: Vec<Vec<u8>>,
    /// Negotiated record_size_limit the peer accepts (TLSInnerPlaintext bytes).
    pub(crate) peer_record_limit: Option<usize>,
    /// Negotiated record_size_limit this endpoint enforces.
    pub(crate) local_record_limit: Option<usize>,
    /// ECH retry configurations the server sent on rejection.
    pub(crate) ech_retry_configs: Option<Vec<u8>>,
    /// Server: 0-RTT bytes still acceptable before EndOfEarlyData.
    pub(crate) early_budget: Option<usize>,
    /// Server: bytes of rejected 0-RTT records still to skip.
    pub(crate) skip_early_budget: usize,
    /// Client: 0-RTT data the server rejected, returned to the caller.
    pub(crate) rejected_early_data: Option<Vec<u8>>,
    /// QUIC client: the server transport parameters remembered with the
    /// ticket, for the stack to apply to 0-RTT packets.
    pub(crate) remembered_quic_params: Option<Vec<u8>>,
}

impl Core {
    /// Seal application data under the current write key before the
    /// handshake completes (client 0-RTT).
    pub(crate) fn send_early(&mut self, data: &[u8]) -> Result<()> {
        if let Transport::Tls {
            write: Some(p),
            outgoing,
            ..
        } = &mut self.transport
        {
            for chunk in data.chunks(MAX_PLAINTEXT) {
                p.seal(ContentType::ApplicationData, chunk, 0, outgoing)?;
            }
            self.report.bytes_sent += data.len() as u64;
            Ok(())
        } else {
            Err(Error::new(ErrorKind::Internal, "no early data key"))
        }
    }

    /// QUIC: hand a key to the QUIC stack without moving the level CRYPTO
    /// data is read or written at (0-RTT keys never carry CRYPTO data).
    pub(crate) fn export_quic_key(
        &mut self,
        level: Level,
        write: bool,
        secret: &Output,
    ) -> Result<()> {
        let suite = self
            .suite
            .ok_or(Error::new(ErrorKind::Internal, "no suite"))?;
        match &mut self.transport {
            Transport::Quic { keys, .. } => {
                keys.push_back(KeyChange {
                    level,
                    write,
                    suite,
                    secret: secret.clone(),
                });
                self.report.event(
                    if write {
                        "event:write-key-installed"
                    } else {
                        "event:read-key-installed"
                    },
                    level.id(),
                );
                Ok(())
            }
            Transport::Tls { .. } => Err(Error::new(ErrorKind::Internal, "not QUIC")),
        }
    }

    /// QUIC: the peer's transport parameters, once received.
    pub(crate) fn peer_quic_params(&self) -> Option<Vec<u8>> {
        match &self.transport {
            Transport::Quic { peer_params, .. } => peer_params.clone(),
            Transport::Tls { .. } => None,
        }
    }

    /// Drop the write key: a HelloRetryRequest ends 0-RTT, and the second
    /// ClientHello goes in the clear.
    pub(crate) fn clear_write(&mut self) {
        if let Transport::Tls { write, .. } = &mut self.transport {
            *write = None;
        }
    }

    /// The current application traffic secret for one direction (TLS only):
    /// the base key of a post-handshake Finished.
    pub(crate) fn current_secret(&self, write: bool) -> Result<Output> {
        match &self.transport {
            Transport::Tls { write: Some(w), .. } if write => Ok(w.secret().clone()),
            Transport::Tls { read: Some(r), .. } if !write => Ok(r.secret().clone()),
            _ => Err(Error::new(
                ErrorKind::InvalidState,
                "no application traffic secret",
            )),
        }
    }
}

impl Core {
    fn new(side: Side, common: Common, quic: Option<Vec<u8>>) -> Result<Self> {
        let rng = common.new_rng()?;
        let transport = match quic {
            None => Transport::Tls {
                read: None,
                write: None,
                incoming: Vec::new(),
                outgoing: Vec::new(),
                ccs_sent: false,
                ccs_allowed: false,
            },
            Some(params) => Transport::Quic {
                outgoing: VecDeque::new(),
                keys: VecDeque::new(),
                write_level: Level::Initial,
                read_level: Level::Initial,
                local_params: params,
                peer_params: None,
            },
        };
        let mut report = SessionReport {
            side: Some(side),
            transport: if quic_transport(&transport) {
                "transport:quic"
            } else {
                "transport:tls-over-tcp"
            },
            profile: common.profile.id(),
            fips_enforced: common.fips,
            early_data: "early-data:not-offered",
            ech: "ech:not-offered",
            revocation: "revocation:not-checked",
            ..Default::default()
        };
        report.event("event:connection-created", common.profile.id());
        Ok(Self {
            side,
            common,
            rng,
            transport,
            transcript: Transcript::new(),
            hs_buf: Vec::new(),
            ccs_seen: 0,
            key_update_answered: false,
            app_in: VecDeque::new(),
            report,
            state: HandshakeState::Start,
            suite: None,
            exporter_secret: None,
            error: None,
            peer_closed: false,
            sent_close: false,
            peer_chain: Vec::new(),
            peer_record_limit: None,
            local_record_limit: None,
            ech_retry_configs: None,
            early_budget: None,
            skip_early_budget: 0,
            rejected_early_data: None,
            remembered_quic_params: None,
        })
    }

    pub(crate) fn is_quic(&self) -> bool {
        quic_transport(&self.transport)
    }

    pub(crate) fn rng(&mut self) -> &mut dyn RandomSource {
        &mut *self.rng
    }

    pub(crate) fn now(&self) -> u64 {
        (self.common.clock)()
    }

    pub(crate) fn set_state(&mut self, s: HandshakeState) {
        self.state = s;
        self.report.state = Some(s);
    }

    pub(crate) fn local_quic_params(&self) -> Option<Vec<u8>> {
        match &self.transport {
            Transport::Quic { local_params, .. } => Some(local_params.clone()),
            Transport::Tls { .. } => None,
        }
    }

    pub(crate) fn set_peer_quic_params(&mut self, p: Vec<u8>) {
        if let Transport::Quic { peer_params, .. } = &mut self.transport {
            *peer_params = Some(p);
        }
    }

    /// Frame, add to the transcript, and send a handshake message.
    pub(crate) fn emit(&mut self, ty: HandshakeType, body: &[u8]) -> Result<()> {
        let msg = msgs::frame(ty, body)?;
        self.transcript.add(&msg);
        self.send_handshake_bytes(&msg)?;
        self.report.event("event:sent", ty.id());
        Ok(())
    }

    /// Send already-framed handshake bytes without touching the transcript.
    pub(crate) fn send_handshake_bytes(&mut self, msg: &[u8]) -> Result<()> {
        match &mut self.transport {
            Transport::Tls {
                write, outgoing, ..
            } => match write {
                Some(p) => {
                    let frag = self.peer_record_limit.map_or(MAX_PLAINTEXT, |l| {
                        l.saturating_sub(1).clamp(1, MAX_PLAINTEXT)
                    });
                    for chunk in msg.chunks(frag) {
                        p.seal(ContentType::Handshake, chunk, 0, outgoing)?;
                    }
                }
                None => record::write_plaintext(ContentType::Handshake, msg, outgoing),
            },
            Transport::Quic {
                outgoing,
                write_level,
                ..
            } => match outgoing.back_mut() {
                Some((lvl, buf)) if lvl == write_level => buf.extend_from_slice(msg),
                _ => outgoing.push_back((*write_level, msg.to_vec())),
            },
        }
        Ok(())
    }

    /// Add already-framed bytes to the transcript and send them.
    pub(crate) fn emit_framed(&mut self, ty: HandshakeType, msg: &[u8]) -> Result<()> {
        self.transcript.add(msg);
        self.send_handshake_bytes(msg)?;
        self.report.event("event:sent", ty.id());
        Ok(())
    }

    /// Middlebox-compatibility ChangeCipherSpec (§D.4), once, TCP only.
    pub(crate) fn send_ccs(&mut self) {
        if let Transport::Tls {
            outgoing, ccs_sent, ..
        } = &mut self.transport
        {
            if !*ccs_sent {
                record::write_plaintext(ContentType::ChangeCipherSpec, &[1], outgoing);
                *ccs_sent = true;
            }
        }
    }

    pub(crate) fn allow_ccs(&mut self, allowed: bool) {
        if let Transport::Tls { ccs_allowed, .. } = &mut self.transport {
            *ccs_allowed = allowed;
        }
    }

    pub(crate) fn install_write(&mut self, level: Level, secret: &Output) -> Result<()> {
        let suite = self
            .suite
            .ok_or(Error::new(ErrorKind::Internal, "no suite"))?;
        match &mut self.transport {
            Transport::Tls { write, .. } => *write = Some(Protector::new(suite, secret)?),
            Transport::Quic {
                keys, write_level, ..
            } => {
                *write_level = level;
                keys.push_back(KeyChange {
                    level,
                    write: true,
                    suite,
                    secret: secret.clone(),
                });
            }
        }
        self.report.event("event:write-key-installed", level.id());
        Ok(())
    }

    /// `REQ-CONN-002`: nothing may be buffered across a read-key change.
    pub(crate) fn install_read(&mut self, level: Level, secret: &Output) -> Result<()> {
        if !self.hs_buf.is_empty() {
            return Err(Error::new(
                ErrorKind::UnexpectedMessage,
                "handshake message spans a key change",
            ));
        }
        let suite = self
            .suite
            .ok_or(Error::new(ErrorKind::Internal, "no suite"))?;
        match &mut self.transport {
            Transport::Tls { read, .. } => *read = Some(Protector::new(suite, secret)?),
            Transport::Quic {
                keys, read_level, ..
            } => {
                *read_level = level;
                keys.push_back(KeyChange {
                    level,
                    write: false,
                    suite,
                    secret: secret.clone(),
                });
            }
        }
        self.report.event("event:read-key-installed", level.id());
        Ok(())
    }

    fn send_alert(&mut self, desc: AlertDescription) {
        let level = if desc == AlertDescription::CloseNotify {
            1
        } else {
            2
        };
        if let Transport::Tls {
            write, outgoing, ..
        } = &mut self.transport
        {
            let body = [level, desc.to_wire()];
            let sealed = match write {
                Some(p) => p.seal(ContentType::Alert, &body, 0, outgoing).is_ok(),
                None => false,
            };
            if !sealed && write.is_none() {
                record::write_plaintext(ContentType::Alert, &body, outgoing);
            }
        }
        // QUIC carries the alert in CONNECTION_CLOSE; see QuicConnection::alert.
        if desc != AlertDescription::CloseNotify {
            self.report.alert_sent = Some(desc);
        }
        self.report.event("event:alert-sent", desc.id());
    }

    /// Latch a failure and send the alert it maps to. `REQ-CONN-001`, `REQ-CONN-005`.
    pub(crate) fn fail(&mut self, e: Error) -> Error {
        if self.error.is_none() {
            self.error = Some(e);
            self.report.error = Some(e.id());
            self.report.error_context = Some(e.context());
            if let Some(a) = e.kind().alert() {
                self.send_alert(a);
            }
            self.set_state(HandshakeState::Failed);
            self.report.event("event:failed", e.id());
        }
        e
    }

    fn check_live(&self) -> Result<()> {
        match self.error {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    fn on_alert(&mut self, body: &[u8]) -> Result<()> {
        if body.len() != 2 {
            return Err(Error::new(ErrorKind::Decode, "alert must be two bytes"));
        }
        let desc = AlertDescription::from_wire(body[1]);
        self.report.event("event:alert-received", desc.id());
        match desc {
            AlertDescription::CloseNotify => {
                self.peer_closed = true;
                if self.state == HandshakeState::Connected {
                    self.set_state(HandshakeState::Closed);
                    Ok(())
                } else {
                    Err(Error::new(
                        ErrorKind::HandshakeFailure,
                        "peer closed during the handshake",
                    ))
                }
            }
            AlertDescription::UserCanceled => Ok(()),
            other => {
                self.report.alert_received = Some(other);
                let e = Error::from_peer(other);
                self.error = Some(e);
                self.report.error = Some(e.id());
                self.report.error_context = Some(e.context());
                self.set_state(HandshakeState::Failed);
                Err(e)
            }
        }
    }

    /// Rotate the write key and tell the peer (§4.6.3). `REQ-CONN-006`.
    pub(crate) fn send_key_update(&mut self, request: KeyUpdateRequest) -> Result<()> {
        if self.state != HandshakeState::Connected || self.is_quic() {
            return Err(Error::new(
                ErrorKind::InvalidState,
                "KeyUpdate needs an established TLS-over-TCP connection",
            ));
        }
        let suite = self
            .suite
            .ok_or(Error::new(ErrorKind::Internal, "no suite"))?;
        let msg = msgs::frame(HandshakeType::KeyUpdate, &[request.to_wire()])?;
        self.send_handshake_bytes(&msg)?;
        if let Transport::Tls { write: Some(p), .. } = &mut self.transport {
            let next = p.next_generation(suite)?;
            *p = next;
        }
        self.report.key_updates_sent = self.report.key_updates_sent.saturating_add(1);
        self.report.event("event:key-update-sent", request.id());
        Ok(())
    }

    pub(crate) fn on_key_update(&mut self, msg: &[u8]) -> Result<()> {
        if self.is_quic() {
            return Err(Error::new(
                ErrorKind::UnexpectedMessage,
                // REQ-QUIC-006: RFC 9001 §6 replaces KeyUpdate with QUIC key phases.
                "QUIC forbids the TLS KeyUpdate message",
            ));
        }
        if self.state != HandshakeState::Connected {
            return Err(Error::new(
                ErrorKind::UnexpectedMessage,
                "KeyUpdate before the handshake completed",
            ));
        }
        let req = msgs::decode_key_update(msg.get(4..).unwrap_or(&[]))?;
        if !self.hs_buf.is_empty() {
            return Err(Error::new(
                ErrorKind::UnexpectedMessage,
                "handshake message spans a key change",
            ));
        }
        let suite = self
            .suite
            .ok_or(Error::new(ErrorKind::Internal, "no suite"))?;
        if let Transport::Tls { read: Some(p), .. } = &mut self.transport {
            let next = p.next_generation(suite)?;
            *p = next;
        }
        self.report.key_updates_received = self.report.key_updates_received.saturating_add(1);
        self.report.event("event:key-update-received", req.id());
        // RFC 8446 §4.6.3: a receiver that is silent answers any number of
        // requests with one update, so a peer cannot make each of its
        // KeyUpdates reflect another (REQ-CONN-010).
        if req == KeyUpdateRequest::UpdateRequested && !self.key_update_answered {
            self.send_key_update(KeyUpdateRequest::UpdateNotRequested)?;
            self.key_update_answered = true;
        }
        Ok(())
    }
}

fn quic_transport(t: &Transport) -> bool {
    matches!(t, Transport::Quic { .. })
}

pub(crate) enum Role {
    Client(Box<ClientHs>),
    Server(Box<ServerHs>),
}

/// A TLS 1.3 connection, client or server, over any byte transport.
///
/// ```no_run
/// # fn main() -> ironsocketlayer::Result<()> {
/// use std::sync::Arc;
/// use ironsocketlayer::{config::{ClientConfig, Profile}, x509::RootStore, Connection};
///
/// let config = Arc::new(ClientConfig::new(Profile::Default, RootStore::from_system()?)?);
/// let mut conn = Connection::client(config, "example.com")?;
/// let first_flight = conn.take_tls();   // write these bytes to the socket
/// # let _ = first_flight;
/// # Ok(()) }
/// ```
pub struct Connection {
    pub(crate) core: Core,
    pub(crate) role: Role,
}

impl core::fmt::Debug for Connection {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "Connection({}, {})",
            self.core.side.id(),
            self.core.state.id()
        )
    }
}

impl Connection {
    /// A client connecting to `server_name` (a DNS name or an IP address).
    /// The ClientHello is ready in [`Connection::take_tls`] on return.
    pub fn client(config: Arc<ClientConfig>, server_name: &str) -> Result<Self> {
        Self::client_inner(config, server_name, None)
    }

    /// A client that sends `data` as 0-RTT early data if it holds a ticket
    /// that permits it and `ClientConfig::early_data` is set.
    ///
    /// **Early data can be replayed** by an attacker within the server's
    /// freshness window and has no forward secrecy: send only requests that
    /// are safe to repeat. If the server rejects it, it is not resent; take
    /// it back with [`Connection::take_rejected_early_data`].
    pub fn client_with_early_data(
        config: Arc<ClientConfig>,
        server_name: &str,
        data: &[u8],
    ) -> Result<Self> {
        Self::client_inner_with(config, server_name, None, Some(data.to_vec()))
    }

    pub(crate) fn client_inner(
        config: Arc<ClientConfig>,
        server_name: &str,
        quic: Option<Vec<u8>>,
    ) -> Result<Self> {
        Self::client_inner_with(config, server_name, quic, None)
    }

    pub(crate) fn client_inner_with(
        config: Arc<ClientConfig>,
        server_name: &str,
        quic: Option<Vec<u8>>,
        early: Option<Vec<u8>>,
    ) -> Result<Self> {
        config.validate()?;
        let quic_early = quic.is_some() && early.is_some();
        let core = Core::new(Side::Client, config.common.clone(), quic)?;
        let mut hs = ClientHs::new(config, server_name)?;
        if quic_early {
            hs.set_quic_early();
        } else {
            hs.set_early_payload(early);
        }
        let mut conn = Self {
            core,
            role: Role::Client(Box::new(hs)),
        };
        if let Role::Client(hs) = &mut conn.role {
            if let Err(e) = hs.start(&mut conn.core) {
                return Err(conn.core.fail(e));
            }
        }
        Ok(conn)
    }

    /// A server awaiting a ClientHello.
    pub fn server(config: Arc<ServerConfig>) -> Result<Self> {
        Self::server_inner(config, None)
    }

    pub(crate) fn server_inner(config: Arc<ServerConfig>, quic: Option<Vec<u8>>) -> Result<Self> {
        config.validate()?;
        let mut core = Core::new(Side::Server, config.common.clone(), quic)?;
        core.set_state(HandshakeState::WaitClientHello);
        Ok(Self {
            core,
            role: Role::Server(Box::new(ServerHs::new(config))),
        })
    }

    /// Feed bytes received from the peer. Returns the first error, which
    /// latches: every later call returns it again.
    pub fn read_tls(&mut self, data: &[u8]) -> Result<()> {
        self.core.check_live()?;
        match &mut self.core.transport {
            Transport::Tls { incoming, .. } => {
                // Bound what a peer can make us buffer before we parse it.
                if incoming.len() + data.len()
                    > 4 * (record::HEADER_LEN + record::MAX_CIPHERTEXT) + 16 * 1024
                {
                    let e = Error::new(
                        ErrorKind::RecordOverflow,
                        "peer is sending faster than it is being read",
                    );
                    return Err(self.core.fail(e));
                }
                incoming.extend_from_slice(data);
            }
            Transport::Quic { .. } => {
                return Err(Error::new(
                    ErrorKind::InvalidState,
                    "QUIC connections take CRYPTO data via QuicConnection",
                ));
            }
        }
        match self.process_records() {
            Ok(()) => Ok(()),
            Err(e) => Err(self.core.fail(e)),
        }
    }

    fn process_records(&mut self) -> Result<()> {
        loop {
            if self.open_in_place()? {
                continue;
            }
            let rec = match &mut self.core.transport {
                Transport::Tls { incoming, .. } => match record::take_record(incoming)? {
                    Some(r) => r,
                    None => return Ok(()),
                },
                Transport::Quic { .. } => return Ok(()),
            };
            if self.core.peer_closed {
                // Anything after close_notify is ignored (§6.1). `REQ-CONN-007`.
                continue;
            }
            let ty = rec.content_type();
            if ty == ContentType::ChangeCipherSpec {
                // REQ-CONN-004.
                let allowed = matches!(
                    self.core.transport,
                    Transport::Tls {
                        ccs_allowed: true,
                        ..
                    }
                );
                // At most two compatibility CCS records (one per flight, and
                // one more around a HelloRetryRequest), as the fixed engine
                // allows: not an unbounded stream. REQ-CONN-004.
                self.core.ccs_seen = self.core.ccs_seen.saturating_add(1);
                if rec.body != [1] || !allowed || self.core.ccs_seen > 2 {
                    return Err(Error::new(
                        ErrorKind::UnexpectedMessage,
                        "unexpected ChangeCipherSpec",
                    ));
                }
                continue;
            }
            let (inner_ty, content) = match &mut self.core.transport {
                Transport::Tls { read: Some(p), .. } => {
                    if ty != ContentType::ApplicationData {
                        return Err(Error::new(
                            ErrorKind::UnexpectedMessage,
                            "plaintext record after keys were installed",
                        ));
                    }
                    // REQ-RSL-002: a protected record over the limit this
                    // endpoint negotiated is record_overflow, before decryption.
                    if let Some(limit) = self.core.local_record_limit {
                        if rec.body.len().saturating_sub(crate::crypto::TAG_LEN) > limit {
                            return Err(Error::new(
                                ErrorKind::RecordOverflow,
                                "record exceeds the negotiated record_size_limit",
                            ));
                        }
                    }
                    let mut body = rec.body;
                    let len = body.len();
                    match p.open(&rec.header, &mut body) {
                        Ok((inner, n)) => {
                            self.core.skip_early_budget = 0;
                            body.truncate(n);
                            (inner, body)
                        }
                        // REQ-0RTT-004: rejected 0-RTT records are skipped,
                        // within a bound, and nothing else is.
                        Err(e)
                            if e.kind() == ErrorKind::BadRecordMac
                                && self.core.skip_early_budget >= len =>
                        {
                            self.core.skip_early_budget -= len;
                            continue;
                        }
                        Err(e) => return Err(e),
                    }
                }
                Transport::Tls { read: None, .. } => {
                    if ty == ContentType::ApplicationData {
                        if self.core.skip_early_budget >= rec.body.len() {
                            self.core.skip_early_budget -= rec.body.len();
                            continue;
                        }
                        return Err(Error::new(
                            ErrorKind::UnexpectedMessage,
                            "application data before keys",
                        ));
                    }
                    if rec.body.len() > MAX_PLAINTEXT {
                        return Err(Error::new(
                            ErrorKind::RecordOverflow,
                            "plaintext record exceeds 2^14",
                        ));
                    }
                    (ty, rec.body)
                }
                Transport::Quic { .. } => return Ok(()),
            };
            self.deliver(inner_ty, &content)?;
        }
    }

    /// Hand a record's decrypted content to where its type goes.
    fn deliver(&mut self, inner_ty: ContentType, content: &[u8]) -> Result<()> {
        match inner_ty {
            ContentType::Handshake => {
                if content.is_empty() {
                    return Err(Error::new(
                        ErrorKind::UnexpectedMessage,
                        "zero-length handshake fragment",
                    ));
                }
                self.core.hs_buf.extend_from_slice(content);
                self.process_handshake()?;
            }
            // REQ-CONN-009: a handshake message split across records must
            // not have other content interleaved between its fragments.
            ContentType::Alert | ContentType::ApplicationData if !self.core.hs_buf.is_empty() => {
                return Err(Error::new(
                    ErrorKind::UnexpectedMessage,
                    "record interleaved with a fragmented handshake message",
                ))
            }
            ContentType::Alert => self.core.on_alert(content)?,
            ContentType::ApplicationData if self.core.early_budget.is_some() => {
                // Accepted 0-RTT data, within max_early_data. REQ-0RTT-003.
                let left = self.core.early_budget.unwrap_or(0);
                if content.len() > left {
                    return Err(Error::new(
                        ErrorKind::UnexpectedMessage,
                        "0-RTT data exceeds max_early_data_size",
                    ));
                }
                self.core.early_budget = Some(left - content.len());
                self.core.report.bytes_received += content.len() as u64;
                self.core.app_in.extend(content.iter());
            }
            ContentType::ApplicationData => {
                // REQ-CONN-003.
                if self.core.state != HandshakeState::Connected {
                    return Err(Error::new(
                        ErrorKind::UnexpectedMessage,
                        "application data during the handshake",
                    ));
                }
                self.core.report.bytes_received += content.len() as u64;
                self.core.app_in.extend(content.iter());
            }
            _ => {
                return Err(Error::new(
                    ErrorKind::UnexpectedMessage,
                    "unexpected inner content type",
                ))
            }
        }
        Ok(())
    }

    /// The bulk path: open the next record in place in the input buffer.
    ///
    /// It applies only when nothing unusual is in play: keys installed, the
    /// handshake over, no 0-RTT accounting, the peer not closed, and a
    /// protected record within the negotiated size. Application data then goes
    /// straight to the receive queue without the copy `take_record` makes;
    /// other content (KeyUpdate, NewSessionTicket, alerts) is copied out and
    /// delivered as usual. Returns whether it consumed a record. `false` leaves
    /// the record to the general path, which applies every check.
    fn open_in_place(&mut self) -> Result<bool> {
        let core = &mut self.core;
        if core.peer_closed
            || core.state != HandshakeState::Connected
            || core.early_budget.is_some()
            || core.skip_early_budget != 0
            || !core.hs_buf.is_empty()
        {
            return Ok(false);
        }
        let Transport::Tls {
            incoming,
            read: Some(p),
            ..
        } = &mut core.transport
        else {
            return Ok(false);
        };
        let Some((header, len)) = record::peek_record(incoming)? else {
            return Ok(false);
        };
        if header[0] != ContentType::ApplicationData.to_wire()
            || core
                .local_record_limit
                .is_some_and(|l| len.saturating_sub(crate::crypto::TAG_LEN) > l)
        {
            return Ok(false);
        }
        let end = record::HEADER_LEN + len;
        let (inner, n) = p.open(&header, &mut incoming[record::HEADER_LEN..end])?;
        let content = &incoming[record::HEADER_LEN..record::HEADER_LEN + n];
        if inner == ContentType::ApplicationData {
            core.report.bytes_received += n as u64;
            core.app_in.extend(content.iter());
            incoming.drain(..end);
            return Ok(true);
        }
        let content = content.to_vec();
        incoming.drain(..end);
        self.deliver(inner, &content)?;
        Ok(true)
    }

    pub(crate) fn process_handshake(&mut self) -> Result<()> {
        let max = self.core.common.max_handshake_message;
        while let Some((ty, msg)) = msgs::take_message(&mut self.core.hs_buf, max)? {
            self.core.report.event("event:received", ty.id());
            if ty == HandshakeType::KeyUpdate {
                self.core.on_key_update(&msg)?;
                continue;
            }
            match &mut self.role {
                Role::Client(hs) => hs.handle(&mut self.core, ty, &msg)?,
                Role::Server(hs) => hs.handle(&mut self.core, ty, &msg)?,
            }
        }
        Ok(())
    }

    /// Take the bytes to send to the peer.
    pub fn take_tls(&mut self) -> Vec<u8> {
        match &mut self.core.transport {
            Transport::Tls { outgoing, .. } => core::mem::take(outgoing),
            Transport::Quic { .. } => Vec::new(),
        }
    }

    /// Whether there are bytes waiting in [`Connection::take_tls`].
    /// `REQ-CONN-008`: true exactly when bytes are queued for the transport.
    pub fn wants_write(&self) -> bool {
        matches!(&self.core.transport, Transport::Tls { outgoing, .. } if !outgoing.is_empty())
    }

    /// Whether the handshake is still in progress.
    pub fn is_handshaking(&self) -> bool {
        !matches!(
            self.core.state,
            HandshakeState::Connected | HandshakeState::Closed | HandshakeState::Failed
        )
    }

    /// Current state.
    pub fn state(&self) -> HandshakeState {
        self.core.state
    }

    /// Encrypt and queue application data. `REQ-CONN-003`, `REQ-CONN-006`.
    pub fn send(&mut self, data: &[u8]) -> Result<()> {
        self.core.check_live()?;
        if self.core.state != HandshakeState::Connected {
            return Err(Error::new(
                ErrorKind::InvalidState,
                "handshake not complete",
            ));
        }
        if self.core.sent_close {
            return Err(Error::new(ErrorKind::Closed, "close_notify already sent"));
        }
        if self.core.is_quic() {
            return Err(Error::new(
                ErrorKind::InvalidState,
                "QUIC carries application data in STREAM frames",
            ));
        }
        // REQ-RSL-003: never send more than the peer's negotiated limit.
        let limit = self.core.peer_record_limit.unwrap_or(MAX_PLAINTEXT + 1);
        let frag = limit.saturating_sub(1).clamp(1, MAX_PLAINTEXT);
        for chunk in data.chunks(frag) {
            let pad = self.core.common.record_padding.min(frag - chunk.len());
            let due = matches!(&self.core.transport, Transport::Tls { write: Some(p), .. } if p.update_due());
            if due {
                self.core
                    .send_key_update(KeyUpdateRequest::UpdateNotRequested)?;
            }
            if let Transport::Tls {
                write: Some(p),
                outgoing,
                ..
            } = &mut self.core.transport
            {
                if let Err(e) = p.seal(ContentType::ApplicationData, chunk, pad, outgoing) {
                    return Err(self.core.fail(e));
                }
            }
            self.core.report.bytes_sent += chunk.len() as u64;
            self.core.key_update_answered = false;
        }
        Ok(())
    }

    /// Read decrypted application data into `buf`, returning how much.
    pub fn recv(&mut self, buf: &mut [u8]) -> usize {
        let n = buf.len().min(self.core.app_in.len());
        // Two slice copies rather than a byte-at-a-time drain: this is the
        // bulk receive path.
        let (front, back) = self.core.app_in.as_slices();
        let k = n.min(front.len());
        buf[..k].copy_from_slice(&front[..k]);
        buf[k..n].copy_from_slice(&back[..n - k]);
        self.core.app_in.drain(..n);
        n
    }

    /// Bytes of application data waiting in [`Connection::recv`].
    pub fn available(&self) -> usize {
        self.core.app_in.len()
    }

    /// Send close_notify. Further `send` calls fail with [`ErrorKind::Closed`].
    pub fn close(&mut self) {
        if !self.core.sent_close && self.core.error.is_none() {
            self.core.send_alert(AlertDescription::CloseNotify);
            self.core.sent_close = true;
        }
    }

    /// Whether the peer sent close_notify.
    pub fn peer_closed(&self) -> bool {
        self.core.peer_closed
    }

    /// Rotate this side's traffic key; with `request_peer`, ask the peer to
    /// rotate too.
    pub fn key_update(&mut self, request_peer: bool) -> Result<()> {
        self.core.check_live()?;
        let req = if request_peer {
            KeyUpdateRequest::UpdateRequested
        } else {
            KeyUpdateRequest::UpdateNotRequested
        };
        self.core.send_key_update(req)
    }

    /// Keying material bound to this connection (RFC 8446 §7.5). Use it for
    /// RFC 9266 channel binding: label `"EXPORTER-Channel-Binding"`, empty
    /// context, 32 bytes.
    pub fn export_keying_material(
        &self,
        label: &[u8],
        context: &[u8],
        out: &mut [u8],
    ) -> Result<()> {
        let secret = self.core.exporter_secret.as_ref().ok_or(Error::new(
            ErrorKind::InvalidState,
            "handshake not complete",
        ))?;
        let suite = self
            .core
            .suite
            .ok_or(Error::new(ErrorKind::Internal, "no suite"))?;
        let (_, hash) =
            record::suite_params(suite).ok_or(Error::new(ErrorKind::Internal, "suite"))?;
        key_schedule::export(hash, secret.as_bytes(), label, context, out)
    }

    /// What was negotiated and what holds.
    pub fn report(&self) -> &SessionReport {
        &self.core.report
    }

    /// The peer's certificate chain, end-entity first.
    pub fn peer_certificates(&self) -> &[Vec<u8>] {
        &self.core.peer_chain
    }

    /// The negotiated ALPN protocol.
    pub fn alpn(&self) -> Option<&[u8]> {
        self.core.report.alpn.as_deref()
    }

    /// The negotiated suite.
    pub fn suite(&self) -> Option<CipherSuite> {
        self.core.suite
    }

    /// Server: ask the client to authenticate now (RFC 8446 §4.6.2), for
    /// example before a privileged operation. Needs `ClientAuth::OnDemand`
    /// (or `Optional`/`Required`) and a client that offered
    /// `post_handshake_auth`. The answer is processed as it arrives; when it
    /// verifies, the report gains `property:mutual-authentication`.
    pub fn request_client_auth(&mut self) -> Result<()> {
        self.core.check_live()?;
        match &mut self.role {
            Role::Server(hs) => hs.request_client_auth(&mut self.core),
            Role::Client(_) => Err(Error::new(
                ErrorKind::InvalidState,
                "only a server requests client authentication",
            )),
        }
    }

    /// Client: the 0-RTT data the server did not accept, to resend now that
    /// the handshake is complete (only if it is safe to).
    pub fn take_rejected_early_data(&mut self) -> Option<Vec<u8>> {
        self.core.rejected_early_data.take()
    }

    /// After [`ErrorKind::EchRejected`], the `ECHConfigList` the server sent
    /// to retry with; reconnect with it in `ClientConfig::ech_configs`.
    ///
    /// `None` unless the handshake failed with exactly `EchRejected`: only
    /// then was the list authenticated, by a certificate for the public name
    /// and the server's Finished. A list from a handshake that failed in any
    /// other way may come from an attacker, and retrying with it would encrypt
    /// the real server name to them. `REQ-ECH-010`.
    pub fn ech_retry_configs(&self) -> Option<&[u8]> {
        match self.core.error {
            Some(e) if e.kind() == ErrorKind::EchRejected => self.core.ech_retry_configs.as_deref(),
            _ => None,
        }
    }

    /// The latched error, if the connection failed.
    pub fn error(&self) -> Option<Error> {
        self.core.error
    }

    /// Which side this is.
    pub fn side(&self) -> Side {
        self.core.side
    }

    /// Server: the SNI the client sent.
    pub fn server_name(&self) -> Option<&str> {
        self.core.report.server_name.as_deref()
    }

    /// For QUIC: feed handshake bytes from a CRYPTO frame at `level`.
    pub(crate) fn read_quic(&mut self, level: Level, data: &[u8]) -> Result<()> {
        self.core.check_live()?;
        let expected = match &self.core.transport {
            Transport::Quic { read_level, .. } => *read_level,
            Transport::Tls { .. } => {
                return Err(Error::new(ErrorKind::InvalidState, "not a QUIC connection"))
            }
        };
        if level != expected {
            let e = Error::new(
                ErrorKind::UnexpectedMessage,
                "CRYPTO data at the wrong encryption level",
            );
            return Err(self.core.fail(e));
        }
        if self.core.hs_buf.len() + data.len() > self.core.common.max_handshake_message + 4 {
            let e = Error::new(
                ErrorKind::IllegalParameter,
                "CRYPTO data exceeds the buffer limit",
            );
            return Err(self.core.fail(e));
        }
        self.core.hs_buf.extend_from_slice(data);
        match self.process_handshake() {
            Ok(()) => Ok(()),
            Err(e) => Err(self.core.fail(e)),
        }
    }

    pub(crate) fn take_quic_output(&mut self) -> Option<(Level, Vec<u8>)> {
        match &mut self.core.transport {
            Transport::Quic { outgoing, .. } => outgoing.pop_front(),
            Transport::Tls { .. } => None,
        }
    }

    pub(crate) fn take_quic_key(&mut self) -> Option<KeyChange> {
        match &mut self.core.transport {
            Transport::Quic { keys, .. } => keys.pop_front(),
            Transport::Tls { .. } => None,
        }
    }

    pub(crate) fn quic_peer_params(&self) -> Option<&[u8]> {
        match &self.core.transport {
            Transport::Quic { peer_params, .. } => peer_params.as_deref(),
            Transport::Tls { .. } => None,
        }
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use crate::config::{ClientConfig, Identity, Profile, ServerConfig};
    use crate::crypto::sign::{KeyKind, SigningKey};
    use crate::x509::{self, CertificateParams, RootStore, Usage};

    fn configs() -> (Arc<ClientConfig>, Arc<ServerConfig>) {
        let mut rng = ic_drbg::Rng::from_os().unwrap();
        let key = SigningKey::generate(KeyKind::EcdsaP256, &mut rng).unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let cert = x509::self_signed(
            &CertificateParams {
                subject_cn: "s.test",
                dns_names: &["s.test"],
                ip_addresses: &[],
                not_before: now - 60,
                not_after: now + 3600,
                is_ca: false,
                path_len: None,
                usage: &[Usage::ServerAuth],
                serial: [1; 16],
            },
            &key,
            &mut rng,
        )
        .unwrap();
        let mut roots = RootStore::new();
        roots.add_der(&cert).unwrap();
        let sc = ServerConfig::new(
            Profile::Default,
            Identity::new(alloc::vec![cert], key).unwrap(),
        )
        .unwrap();
        let cc = ClientConfig::new(Profile::Default, roots).unwrap();
        (Arc::new(cc), Arc::new(sc))
    }

    fn pair() -> (Connection, Connection) {
        let (cc, sc) = configs();
        let mut c = Connection::client(cc, "s.test").unwrap();
        let mut s = Connection::server(sc).unwrap();
        for _ in 0..4 {
            s.read_tls(&c.take_tls()).unwrap();
            c.read_tls(&s.take_tls()).unwrap();
        }
        s.read_tls(&c.take_tls()).unwrap();
        assert_eq!(c.state(), HandshakeState::Connected);
        (c, s)
    }

    /// Records opened in place and records taken the general way must agree:
    /// a stream of application data of every size, with a KeyUpdate in the
    /// middle and close_notify at the end, arrives intact however the bytes
    /// are split across reads.
    #[test]
    fn records_split_anywhere_arrive_intact() {
        for piece in [1usize, 5, 6, 997, 16_389, usize::MAX] {
            let (mut c, mut s) = pair();
            let mut sent = Vec::new();
            for (i, len) in [0usize, 1, 100, 16_384, 16_385, 40_000, 3]
                .iter()
                .enumerate()
            {
                let data: Vec<u8> = (0..*len).map(|j| (i * 31 + j) as u8).collect();
                c.send(&data).unwrap();
                sent.extend_from_slice(&data);
                if i == 3 {
                    c.key_update(true).unwrap();
                }
            }
            c.close();
            let wire = c.take_tls();
            let mut got = Vec::new();
            let mut buf = [0u8; 4096];
            for chunk in wire.chunks(piece.min(wire.len())) {
                s.read_tls(chunk).unwrap();
                loop {
                    let n = s.recv(&mut buf);
                    if n == 0 {
                        break;
                    }
                    got.extend_from_slice(&buf[..n]);
                }
            }
            assert_eq!(got, sent, "pieces of {piece}");
            assert!(s.peer_closed(), "pieces of {piece}");
            assert_eq!(s.report().key_updates_received, 1);
            assert_eq!(s.report().bytes_received, sent.len() as u64);
        }
    }

    /// `recv` copies from both halves of the receive ring: odd-sized reads
    /// interleaved with writes wrap it, and every byte arrives once, in order.
    #[test]
    fn recv_is_exact_across_ring_wraparound() {
        let (mut c, mut s) = pair();
        let mut expected = alloc::collections::VecDeque::new();
        let mut got = Vec::new();
        let mut next = 0u8;
        let mut buf = [0u8; 997];
        for round in 0..200usize {
            let chunk: Vec<u8> = (0..(round * 37) % 3001 + 1)
                .map(|_| {
                    next = next.wrapping_add(1);
                    next
                })
                .collect();
            expected.extend(chunk.iter().copied());
            c.send(&chunk).unwrap();
            s.read_tls(&c.take_tls()).unwrap();
            let want = (round * 13) % buf.len() + 1;
            let n = s.recv(&mut buf[..want]);
            got.extend_from_slice(&buf[..n]);
        }
        while s.available() > 0 {
            let n = s.recv(&mut buf);
            got.extend_from_slice(&buf[..n]);
        }
        assert_eq!(got, expected.into_iter().collect::<Vec<_>>());
        assert_eq!(s.recv(&mut buf), 0);
    }

    /// REQ-CONN-006: sending near a key's limit rotates it first, and the
    /// peer follows.
    #[test]
    fn a_key_near_its_limit_is_updated_before_use() {
        let (mut c, mut s) = pair();
        // Advance both ends of the client-to-server direction in step.
        let near = crate::crypto::AeadAlg::Aes128Gcm.confidentiality_limit() - 10;
        if let Transport::Tls { write: Some(p), .. } = &mut c.core.transport {
            p.set_seq_for_test(near);
        }
        if let Transport::Tls { read: Some(p), .. } = &mut s.core.transport {
            p.set_seq_for_test(near);
        }
        c.send(b"after the limit").unwrap();
        assert_eq!(c.report().key_updates_sent, 1);
        s.read_tls(&c.take_tls()).unwrap();
        let mut buf = [0u8; 32];
        let n = s.recv(&mut buf);
        assert_eq!(&buf[..n], b"after the limit");
        assert_eq!(s.report().key_updates_received, 1);
    }

    /// REQ-RSL-002: a protected record larger than the negotiated limit is
    /// record_overflow, even when it would authenticate.
    #[test]
    fn a_record_over_the_negotiated_limit_is_overflow() {
        let (mut c, mut s) = pair();
        c.core.local_record_limit = Some(100);
        s.send(&[7u8; 500]).unwrap();
        let err = c.read_tls(&s.take_tls()).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::RecordOverflow);
    }

    /// REQ-CONN-004: a ChangeCipherSpec after the handshake is fatal.
    #[test]
    fn change_cipher_spec_is_only_tolerated_in_the_handshake() {
        let (_c, mut s) = pair();
        let err = s.read_tls(&[20, 3, 3, 0, 1, 1]).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::UnexpectedMessage);
    }

    /// REQ-CONN-003: application data waits for the handshake, in both
    /// directions.
    #[test]
    fn application_data_waits_for_the_handshake() {
        let (cc, sc) = configs();
        let mut c = Connection::client(cc, "s.test").unwrap();
        assert_eq!(
            c.send(b"too early").unwrap_err().kind(),
            ErrorKind::InvalidState
        );
        let mut s = Connection::server(sc).unwrap();
        s.read_tls(&c.take_tls()).unwrap();
        // A plaintext application-data record before any keys.
        let err = c.read_tls(&[23, 3, 3, 0, 1, 0x41]).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::UnexpectedMessage);
    }

    /// Seal `content` as a protected record of `ty` from `c`'s side, as a
    /// misbehaving peer could.
    fn seal_raw(c: &mut Connection, ty: ContentType, content: &[u8]) -> Vec<u8> {
        if let Transport::Tls {
            write: Some(p),
            outgoing,
            ..
        } = &mut c.core.transport
        {
            p.seal(ty, content, 0, outgoing).unwrap();
        }
        c.take_tls()
    }

    fn refused(r: Result<()>, kind: ErrorKind, msg: &str) {
        let e = r.expect_err(msg);
        assert_eq!(e.kind(), kind, "{e}");
        assert!(e.to_string().contains(msg), "wanted {msg:?}, got {e}");
    }

    /// Record-layer refusals a peer can provoke, each identified by its own
    /// message: REQ-CONN-001 (the failure latches), REQ-REC-004 (sizes).
    #[test]
    fn peer_record_misbehaviour_is_refused() {
        // A plaintext alert of the wrong length, before any keys.
        let (_, sc) = configs();
        let mut s = Connection::server(sc.clone()).unwrap();
        refused(
            s.read_tls(&[21, 3, 3, 0, 3, 1, 0, 0]),
            ErrorKind::Decode,
            "alert must be two bytes",
        );
        // A plaintext record over 2^14 bytes, before any keys.
        let mut s = Connection::server(sc).unwrap();
        let mut big = alloc::vec![22, 3, 3];
        big.extend_from_slice(&((MAX_PLAINTEXT + 1) as u16).to_be_bytes());
        big.resize(5 + MAX_PLAINTEXT + 1, 0);
        refused(
            s.read_tls(&big),
            ErrorKind::RecordOverflow,
            "plaintext record exceeds 2^14",
        );

        // After the handshake: a plaintext record, an empty handshake
        // fragment, and a KeyUpdate sharing its record with the start of
        // another message.
        let (_, mut s) = pair();
        refused(
            s.read_tls(&[22, 3, 3, 0, 1, 0]),
            ErrorKind::UnexpectedMessage,
            "plaintext record after keys were installed",
        );
        let (mut c, mut s) = pair();
        let rec = seal_raw(&mut c, ContentType::Handshake, &[]);
        refused(
            s.read_tls(&rec),
            ErrorKind::UnexpectedMessage,
            "zero-length handshake fragment",
        );
        let (mut c, mut s) = pair();
        let rec = seal_raw(&mut c, ContentType::Handshake, &[24, 0, 0, 1, 0, 4]);
        refused(
            s.read_tls(&rec),
            ErrorKind::UnexpectedMessage,
            "handshake message spans a key change",
        );
        // The failure latches: nothing further is accepted.
        assert!(s.read_tls(&[]).is_err());
    }

    /// RFC 8446 §6.1: once close_notify arrives, anything after it is
    /// ignored, even bytes that would otherwise be fatal.
    #[test]
    fn records_after_close_notify_are_ignored() {
        let (mut c, mut s) = pair();
        c.send(b"last").unwrap();
        c.close();
        s.read_tls(&c.take_tls()).unwrap();
        assert!(s.peer_closed());
        s.read_tls(&[23, 3, 3, 0, 4, 0xde, 0xad, 0xbe, 0xef])
            .unwrap();
        let mut buf = [0u8; 16];
        assert_eq!(s.recv(&mut buf), 4);
        assert_eq!(&buf[..4], b"last");
        assert_eq!(s.recv(&mut buf), 0);
    }

    /// A client that has processed the ServerHello, and so writes under its
    /// handshake key, and the server that is waiting for its Finished: the
    /// client then stands in for a misbehaving peer of the server.
    fn client_writing_under_handshake_keys() -> (Connection, Connection) {
        let (cc, sc) = configs();
        let mut c = Connection::client(cc, "s.test").unwrap();
        let mut s = Connection::server(sc).unwrap();
        s.read_tls(&c.take_tls()).unwrap();
        let flight = s.take_tls();
        let len = u16::from_be_bytes([flight[3], flight[4]]) as usize;
        c.read_tls(&flight[..5 + len]).unwrap();
        let _ccs = c.take_tls();
        (c, s)
    }

    /// Give `cc`'s ticket store a ticket from `sc`.
    fn get_ticket(cc: &Arc<ClientConfig>, sc: &Arc<ServerConfig>) {
        let mut c = Connection::client(cc.clone(), "s.test").unwrap();
        let mut s = Connection::server(sc.clone()).unwrap();
        for _ in 0..4 {
            s.read_tls(&c.take_tls()).unwrap();
            c.read_tls(&s.take_tls()).unwrap();
        }
        assert!(c.report().tickets_received >= 1);
    }

    /// REQ-REC-005, REQ-0RTT-004: while a server skips the records of 0-RTT
    /// data it rejected, it skips only records that fail authentication; one
    /// that authenticates but has an all-zero inner plaintext is still
    /// unexpected_message.
    #[test]
    fn a_record_with_no_content_type_is_refused_while_skipping_early_data() {
        let (cc, sc) = configs();
        let mut ccfg = (*cc).clone();
        ccfg.early_data = true;
        let cc = Arc::new(ccfg);
        let mut with_policy = (*sc).clone();
        with_policy.early_data = Some(crate::config::EarlyDataPolicy::new(1024));
        get_ticket(&cc, &Arc::new(with_policy));
        // This server shares the ticket keys but has no 0-RTT policy, so it
        // resumes, rejects the data and skips it.
        let mut c = Connection::client_with_early_data(cc, "s.test", b"early").unwrap();
        let mut s = Connection::server(sc).unwrap();
        s.read_tls(&c.take_tls()).unwrap();
        assert_eq!(s.report().early_data, "early-data:rejected");
        assert!(s.core.skip_early_budget > 0);
        // The client reads up to EncryptedExtensions, which moves its writes
        // from the early key to the handshake key.
        let flight = s.take_tls();
        let mut at = 0;
        while c.report().early_data != "early-data:rejected" {
            let len = u16::from_be_bytes([flight[at + 3], flight[at + 4]]) as usize;
            c.read_tls(&flight[at..at + 5 + len]).unwrap();
            at += 5 + len;
        }
        let _ccs = c.take_tls();
        let rec = seal_raw(&mut c, ContentType::Invalid, &[]);
        refused(
            s.read_tls(&rec),
            ErrorKind::UnexpectedMessage,
            "record with no content type",
        );
        assert_eq!(
            s.report().alert_sent,
            Some(AlertDescription::UnexpectedMessage)
        );
    }

    /// REQ-CONN-003: application data protected under the handshake keys,
    /// before the handshake completes, is unexpected_message and is not
    /// delivered.
    #[test]
    fn application_data_under_handshake_keys_is_refused() {
        let (mut c, mut s) = client_writing_under_handshake_keys();
        let rec = seal_raw(&mut c, ContentType::ApplicationData, b"too early");
        refused(
            s.read_tls(&rec),
            ErrorKind::UnexpectedMessage,
            "application data during the handshake",
        );
        assert_eq!(s.available(), 0);
    }

    /// REQ-0RTT-003: accepted early data is bounded by max_early_data_size:
    /// a client may use all of it, and one byte more is unexpected_message.
    #[test]
    fn early_data_beyond_max_early_data_is_refused() {
        let (cc, sc) = configs();
        let mut ccfg = (*cc).clone();
        ccfg.early_data = true;
        let mut scfg = (*sc).clone();
        scfg.early_data = Some(crate::config::EarlyDataPolicy::new(1024));
        let (cc, sc) = (Arc::new(ccfg), Arc::new(scfg));
        for extra in [24usize, 25] {
            // A fresh ticket for each attempt: each is used once.
            let mut c = Connection::client(cc.clone(), "s.test").unwrap();
            let mut s = Connection::server(sc.clone()).unwrap();
            for _ in 0..4 {
                s.read_tls(&c.take_tls()).unwrap();
                c.read_tls(&s.take_tls()).unwrap();
            }
            assert!(c.report().tickets_received >= 1);

            let mut c =
                Connection::client_with_early_data(cc.clone(), "s.test", &[1; 1000]).unwrap();
            assert_eq!(c.report().early_data, "early-data:offered");
            let mut flight = c.take_tls();
            // More 0-RTT data under the same key, as a client ignoring the
            // ticket's limit could send.
            flight.extend(seal_raw(
                &mut c,
                ContentType::ApplicationData,
                &alloc::vec![2; extra],
            ));
            let mut s = Connection::server(sc.clone()).unwrap();
            let r = s.read_tls(&flight);
            assert_eq!(s.report().early_data, "early-data:accepted");
            if extra == 24 {
                r.unwrap();
                assert_eq!(s.available(), 1024);
            } else {
                refused(
                    r,
                    ErrorKind::UnexpectedMessage,
                    "0-RTT data exceeds max_early_data_size",
                );
            }
        }
    }

    /// A client, configured by `edit`, that has processed a real server's
    /// ServerHello and now expects its encrypted flight.
    fn client_after_server_hello(edit: impl FnOnce(&mut ClientConfig)) -> (Connection, Vec<u8>) {
        let (cc, sc) = configs();
        let leaf = sc.identities[0].chain[0].clone();
        let mut cfg = (*cc).clone();
        edit(&mut cfg);
        let mut c = Connection::client(Arc::new(cfg), "s.test").unwrap();
        let mut s = Connection::server(sc).unwrap();
        s.read_tls(&c.take_tls()).unwrap();
        let flight = s.take_tls();
        let len = u16::from_be_bytes([flight[3], flight[4]]) as usize;
        c.read_tls(&flight[..5 + len]).unwrap();
        (c, leaf)
    }

    /// Hand the client one handshake message as if it had arrived under the
    /// handshake keys: the checks under test are the client's, not the
    /// record layer's.
    fn deliver(c: &mut Connection, ty: HandshakeType, body: &[u8]) -> Result<()> {
        let m = msgs::frame(ty, body)?;
        c.core.hs_buf.extend_from_slice(&m);
        c.process_handshake()
    }

    fn refuses(r: Result<()>, want: &str) {
        let e = r.expect_err(want);
        assert!(e.to_string().contains(want), "wanted {want:?}, got {e}");
    }

    /// REQ-MSG-006: the client refuses EncryptedExtensions that answer what it
    /// did not ask, or omit what it required.
    #[test]
    fn the_client_refuses_unrequested_encrypted_extensions() {
        use crate::msgs::EncryptedExtensions as Ee;
        let ee = |e: Ee| e.encode().unwrap();
        let (mut c, _) = client_after_server_hello(|_| {});
        deliver(
            &mut c,
            HandshakeType::EncryptedExtensions,
            &ee(Ee::default()),
        )
        .unwrap();

        type Case = (fn(&mut ClientConfig), fn(&mut Ee), &'static str);
        let cases: &[Case] = &[
            (
                |_| {},
                |e| e.alpn = Some(b"h2".to_vec()),
                "server selected an ALPN protocol not offered",
            ),
            (
                |c| {
                    c.common.alpn = alloc::vec![b"h2".to_vec()];
                    c.common.require_alpn = true;
                },
                |_| {},
                "server selected no ALPN protocol",
            ),
            (
                |c| c.send_sni = false,
                |e| e.server_name_ack = true,
                "server_name acknowledged but not sent",
            ),
            (
                |_| {},
                |e| e.record_size_limit = Some(1000),
                "record_size_limit answered but not offered",
            ),
            (
                |_| {},
                |e| e.ech_retry_configs = Some(alloc::vec![0, 0]),
                "encrypted_client_hello in EncryptedExtensions but not offered",
            ),
            (
                |_| {},
                |e| e.early_data = true,
                "server accepted early data that was not sent",
            ),
            (
                |_| {},
                |e| e.quic_params = Some(alloc::vec![1]),
                "QUIC transport parameters over TCP",
            ),
        ];
        for (cfg, edit, want) in cases {
            let (mut c, _) = client_after_server_hello(cfg);
            let mut e = Ee::default();
            edit(&mut e);
            refuses(
                deliver(&mut c, HandshakeType::EncryptedExtensions, &ee(e)),
                want,
            );
        }
    }

    /// REQ-PHA-001: the client refuses a CertificateRequest with a context
    /// during the handshake; after it, one it did not agree to by offering
    /// post_handshake_auth, and one without a context to answer with.
    #[test]
    fn the_client_refuses_misplaced_certificate_requests() {
        use crate::msgs::{CertificateRequest, EncryptedExtensions};
        let cr = |context: Vec<u8>| {
            CertificateRequest {
                context,
                sig_algs: alloc::vec![crate::enums::SignatureScheme::EcdsaSecp256r1Sha256],
            }
            .encode()
            .unwrap()
        };
        // During the handshake.
        let (mut c, _) = client_after_server_hello(|_| {});
        deliver(
            &mut c,
            HandshakeType::EncryptedExtensions,
            &EncryptedExtensions::default().encode().unwrap(),
        )
        .unwrap();
        refuses(
            deliver(
                &mut c,
                HandshakeType::CertificateRequest,
                &cr(alloc::vec![1]),
            ),
            "handshake CertificateRequest must have an empty context",
        );
        // After it, from a client that did not offer post_handshake_auth.
        let (mut c, _) = pair();
        refuses(
            deliver(
                &mut c,
                HandshakeType::CertificateRequest,
                &cr(alloc::vec![1]),
            ),
            "CertificateRequest without post_handshake_auth",
        );
        // After it, with an empty context, to a client that did offer it.
        let (cc, sc) = configs();
        let mut cfg = (*cc).clone();
        cfg.post_handshake_auth = true;
        // A client offers post_handshake_auth only with an identity to answer
        // with; any identity will do here.
        cfg.identity = Some(sc.identities[0].clone());
        let mut c = Connection::client(Arc::new(cfg), "s.test").unwrap();
        let mut s = Connection::server(sc).unwrap();
        for _ in 0..4 {
            s.read_tls(&c.take_tls()).unwrap();
            c.read_tls(&s.take_tls()).unwrap();
        }
        assert_eq!(c.state(), HandshakeState::Connected);
        refuses(
            deliver(
                &mut c,
                HandshakeType::CertificateRequest,
                &cr(alloc::vec![]),
            ),
            "post-handshake CertificateRequest with an empty context",
        );
    }

    /// REQ-PHA-002: after a post-handshake request, the server refuses a
    /// client Certificate whose context answers some other request, or no
    /// request (the empty context of a handshake Certificate).
    #[test]
    fn the_server_refuses_step_up_answers_that_do_not_match() {
        use crate::config::{ClientAuth, PeerVerification};
        use crate::msgs::CertificateMsg;
        let (cc, sc) = configs();
        let roots = match &cc.verification {
            PeerVerification::Roots(r) => r.clone(),
            _ => unreachable!(),
        };
        let leaf = sc.identities[0].chain[0].clone();
        let mut ccfg = (*cc).clone();
        ccfg.post_handshake_auth = true;
        ccfg.identity = Some(sc.identities[0].clone());
        let scfg = (*sc)
            .clone()
            .with_client_auth(ClientAuth::OnDemand(PeerVerification::Roots(roots)));
        let (ccfg, scfg) = (Arc::new(ccfg), Arc::new(scfg));
        let asked = || {
            let mut c = Connection::client(ccfg.clone(), "s.test").unwrap();
            let mut s = Connection::server(scfg.clone()).unwrap();
            for _ in 0..4 {
                s.read_tls(&c.take_tls()).unwrap();
                c.read_tls(&s.take_tls()).unwrap();
            }
            s.read_tls(&c.take_tls()).unwrap();
            assert_eq!(s.state(), HandshakeState::Connected);
            s.request_client_auth().unwrap();
            let _request = s.take_tls();
            s
        };
        let answer = |s: &mut Connection, context: Vec<u8>, chain: Vec<Vec<u8>>| {
            let body = CertificateMsg {
                context,
                chain,
                ocsp: None,
            }
            .encode()
            .unwrap();
            let m = msgs::frame(HandshakeType::Certificate, &body).unwrap();
            s.core.hs_buf.extend_from_slice(&m);
            s.process_handshake()
        };
        let mut s = asked();
        refuses(
            answer(&mut s, alloc::vec![0xee; 8], alloc::vec![leaf.clone()]),
            "certificate_request_context does not match",
        );
        let mut s = asked();
        refuses(
            answer(&mut s, alloc::vec![], alloc::vec![leaf]),
            "certificate_request_context does not match",
        );
    }

    /// A pinned key still needs a certificate inside its validity period:
    /// pinning replaces the path, not the dates.
    #[test]
    fn a_pinned_certificate_must_be_current() {
        let (_, sc) = configs();
        let spki = x509::Certificate::parse(&sc.identities[0].chain[0])
            .unwrap()
            .spki_der()
            .to_vec();
        let mut cfg = ClientConfig::pinned(Profile::Default, &spki).unwrap();
        cfg.common.clock = || {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + 10 * 86_400
        };
        let mut c = Connection::client(Arc::new(cfg), "s.test").unwrap();
        let mut s = Connection::server(sc).unwrap();
        s.read_tls(&c.take_tls()).unwrap();
        let e = c.read_tls(&s.take_tls()).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::CertificateExpired, "{e}");
        // The same leaf check as on a validated path (REQ-X509-075).
        assert!(e.to_string().contains("certificate has expired"), "{e}");
    }

    /// REQ-MSG-006: the client refuses a server Certificate message with a
    /// context, with no certificate, or with a staple it did not request.
    #[test]
    fn the_client_refuses_malformed_server_certificates() {
        use crate::msgs::{CertificateMsg, EncryptedExtensions};
        let ee = EncryptedExtensions::default().encode().unwrap();
        type Case = (
            fn(&mut ClientConfig),
            fn(Vec<u8>) -> CertificateMsg,
            &'static str,
        );
        let cases: &[Case] = &[
            (
                |_| {},
                |leaf| CertificateMsg {
                    context: alloc::vec![1],
                    chain: alloc::vec![leaf],
                    ocsp: None,
                },
                "server Certificate must have an empty context",
            ),
            (
                |_| {},
                |_| CertificateMsg {
                    context: alloc::vec![],
                    chain: alloc::vec![],
                    ocsp: None,
                },
                "server sent an empty Certificate",
            ),
            (
                |c| c.revocation = crate::config::Revocation::Off,
                |leaf| CertificateMsg {
                    context: alloc::vec![],
                    chain: alloc::vec![leaf],
                    ocsp: Some(alloc::vec![0x30, 0x00]),
                },
                "OCSP staple sent but not requested",
            ),
        ];
        for (cfg, make, want) in cases {
            let (mut c, leaf) = client_after_server_hello(cfg);
            deliver(&mut c, HandshakeType::EncryptedExtensions, &ee).unwrap();
            let body = make(leaf).encode().unwrap();
            refuses(deliver(&mut c, HandshakeType::Certificate, &body), want);
        }
    }
}

/// Record a completed handshake's properties and indicators in the report.
pub(crate) fn finish_report(
    core: &mut Core,
    pq_auth: bool,
    mutual: bool,
    pinned: bool,
    cert_auth: bool,
) -> Result<()> {
    use crate::report::Property as P;
    let suite = core
        .suite
        .ok_or(Error::new(ErrorKind::Internal, "no suite"))?;
    let group = core
        .report
        .group
        .ok_or(Error::new(ErrorKind::Internal, "no group"))?;
    core.report.add(P::Confidentiality);
    core.report.add(P::ForwardSecrecy);
    if crate::crypto::kx::is_post_quantum(group) {
        core.report.add(P::PostQuantumKeyExchange);
    }
    if pq_auth {
        core.report.add(P::PostQuantumAuthentication);
    }
    // Certificate authentication of the server, or an external PSK that
    // authenticates both ends at once.
    if cert_auth {
        core.report.add(P::ServerAuthenticated);
    } else {
        core.report.add(P::PskAuthenticated);
    }
    if mutual {
        core.report.add(P::MutualAuthentication);
    }
    if pinned {
        core.report.add(P::PinnedPeer);
    }
    let mut schemes = Vec::new();
    if let Some(s) = core.report.peer_signature_scheme {
        schemes.push(s);
    }
    if let Some(s) = core.report.local_signature_scheme {
        schemes.push(s);
    }
    let ind = crate::policy::session_indicators(suite, group, &schemes, core.common.fips)?;
    if core.common.fips && ind.all_approved() {
        core.report.add(P::FipsApprovedAlgorithms);
    }
    core.report.fips_indicators = ind;
    core.set_state(HandshakeState::Connected);
    core.allow_ccs(false);
    core.report.event("event:handshake-complete", suite.id());
    Ok(())
}

/// Record a path shown good by current CRLs.
pub(crate) fn note_crl(core: &mut Core, checked: bool) {
    if checked {
        core.report.revocation = "revocation:good";
        core.report.add(crate::report::Property::RevocationChecked);
        core.report.event("event:crl-checked", "");
    }
}

/// Parse the peer's leaf for the report.
pub(crate) fn describe_peer(core: &mut Core, leaf: &[u8]) {
    if let Ok(cert) = crate::x509::Certificate::parse(leaf) {
        core.report.peer_not_after = Some(cert.not_after());
        core.report.peer_subject_cn = cert.common_name().map(String::from);
        // REQ-RPT-003.
        core.report.peer_names = cert.dns_names().into_iter().map(String::from).collect();
        core.report
            .peer_names
            .extend(cert.ip_addresses().iter().map(|ip| alloc::format!("{ip}")));
        if let Ok(k) = cert.subject_public_key() {
            core.report.peer_key = Some(k.kind_id());
        }
    }
}
