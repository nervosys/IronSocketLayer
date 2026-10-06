//! TLS 1.3 with caller-owned storage and no connection-time allocation.
//!
//! Initialize configuration, trust stores, identities and the FIPS module first.
//! Then lend this engine its buffers and an entropy source. The engine never
//! grows storage. Capacity failures latch the connection failed, erase secrets
//! and discard queued application data. The owned [`crate::Connection`] API is
//! independent of this backend.
//!
//! This backend performs full certificate handshakes, including mutual
//! authentication, all implemented suites/groups/signing keys, records,
//! exporters, KeyUpdate and close_notify. Optional ECH, PSK, resumption,
//! early data and post-handshake authentication require the owned API;
//! configuration requesting them is rejected, never silently downgraded.
//! `REQ-FIX-004`, `REQ-FIX-005`.

use crate::codec::Reader;
use crate::config::{ClientAuth, ClientConfig, Common, Identity, PeerVerification, ServerConfig};
use crate::crypto::{self, kx, sign, Hash, HashAlg, Output};
use crate::enums::{CipherSuite, ContentType, ExtensionType, NamedGroup, SignatureScheme};
use crate::error::{Error, ErrorKind, Result};
use crate::key_schedule::{self, MasterStage};
use crate::msgs::{extension_allowed, ExtensionContext};
use crate::record::{self, Protector};
use crate::report::{HandshakeState as State, Property};
use crate::x509::{self, Certificate, ServerName, Usage, VerifyOptions};
use ic_core::{traits::RandomSource, Zeroize, Zeroizing};

fn capacity(context: &'static str) -> Error {
    Error::new(ErrorKind::CapacityExceeded, context)
}
fn invalid(context: &'static str) -> Error {
    Error::new(ErrorKind::IllegalParameter, context)
}
fn unexpected() -> Error {
    Error::new(ErrorKind::UnexpectedMessage, "fixed handshake state")
}

/// Caller-owned buffers. Their lengths are the declared byte capacities.
/// Buffers are exclusively borrowed until the connection is dropped.
pub struct Storage<'a> {
    /// A single incoming record, including its five-byte header.
    pub record: &'a mut [u8],
    /// Reassembly of one handshake message, including its four-byte header.
    pub handshake: &'a mut [u8],
    /// Encoded records waiting for the transport to drain them.
    pub outgoing: &'a mut [u8],
    /// Decrypted application bytes waiting for the application to read them.
    pub application: &'a mut [u8],
    /// Peer certificate DER, retained through the connection lifetime.
    pub certificates: &'a mut [u8],
    /// Ephemeral private key storage; erased after exchange and on drop.
    pub private_key: &'a mut [u8],
    /// Ephemeral public share storage.
    pub public_key: &'a mut [u8],
    /// Encoding workspace for one outgoing handshake message/signature.
    pub scratch: &'a mut [u8],
}

/// Fixed slot and protocol-string capacities. Byte capacities are in [`Storage`].
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum certificate entries, 1..=8.
    pub certificates: usize,
    /// Maximum extensions in each handshake structure, 1..=64.
    pub extensions: usize,
    /// Maximum audit events, 1..=64. Exhaustion fails rather than dropping events.
    pub events: usize,
    /// Maximum DNS/SNI name bytes, at most 253.
    pub name: usize,
    /// Maximum ALPN protocols in an offered list.
    pub alpn_protocols: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            certificates: 8,
            extensions: 64,
            events: 64,
            name: 253,
            alpn_protocols: 16,
        }
    }
}

/// One audit event, using existing ontology identifiers without owned strings.
#[derive(Clone, Copy, Debug)]
pub struct Event {
    /// The handshake state reached.
    pub state: State,
}

/// Bounded session facts. `validated` is always false.
pub struct Report<'a> {
    /// Current handshake state.
    pub state: State,
    /// Negotiated cipher suite.
    pub suite: Option<CipherSuite>,
    /// Negotiated key exchange group.
    pub group: Option<NamedGroup>,
    /// Peer CertificateVerify algorithm.
    pub peer_signature_scheme: Option<SignatureScheme>,
    /// Local CertificateVerify algorithm.
    pub local_signature_scheme: Option<SignatureScheme>,
    /// Verified certificate-path signature schemes, leaf first.
    pub peer_chain_schemes: [Option<SignatureScheme>; 8],
    /// Selected ALPN, borrowed from configuration.
    pub alpn: Option<&'a [u8]>,
    /// Weakest verified certificate-path key strength.
    pub peer_chain_min_bits: Option<u16>,
    /// Failure, retained permanently.
    pub error: Option<Error>,
    /// No FIPS 140-3 validation or DO-178C certification is claimed.
    pub validated: bool,
    properties: u16,
    events: [Option<Event>; 64],
    event_len: usize,
}
impl Report<'_> {
    /// Whether the established session achieved a property.
    /// Failed connections never authorize a privileged operation.
    pub fn has(&self, property: Property) -> bool {
        self.error.is_none() && self.properties & property_bit(property) != 0
    }
    /// Recorded transitions, in order, without allocation.
    pub fn events(&self) -> impl Iterator<Item = &Event> {
        self.events[..self.event_len]
            .iter()
            .filter_map(Option::as_ref)
    }
}
fn property_bit(p: Property) -> u16 {
    Property::ALL
        .iter()
        .position(|v| *v == p)
        .map_or(0, |i| 1 << i)
}

enum Config<'a> {
    Client(&'a ClientConfig, ServerName<'a>),
    Server(&'a ServerConfig),
}
#[derive(Clone, Copy)]
struct KeySlot {
    group: NamedGroup,
    private: usize,
    private_len: usize,
    public: usize,
    public_len: usize,
}

/// A fixed-capacity TLS 1.3 client or server. `REQ-FIX-004`.
/// All buffers and initialized configuration are borrowed, never cloned.
pub struct Connection<'a> {
    config: Config<'a>,
    storage: Storage<'a>,
    limits: Limits,
    rng: &'a mut dyn RandomSource,
    report: Report<'a>,
    record_len: usize,
    hs_len: usize,
    out_len: usize,
    app_len: usize,
    cert_len: usize,
    chain: [Option<(usize, usize)>; 8],
    chain_len: usize,
    hash256: Hash,
    hash384: Hash,
    suite: Option<CipherSuite>,
    group: NamedGroup,
    key_slots: [Option<KeySlot>; 10],
    read: Option<Protector>,
    /// Incremented whenever the read key changes, so a record can be checked
    /// not to carry messages past a key change (RFC 8446 §5.1).
    read_epoch: u32,
    write: Option<Protector>,
    peer_hs_secret: Option<Output>,
    local_hs_secret: Option<Output>,
    master: Option<MasterStage>,
    client_app: Option<Output>,
    exporter: Option<Output>,
    random: [u8; 32],
    session_id: [u8; 32],
    session_id_len: usize,
    request_client: bool,
    request_schemes: [Option<SignatureScheme>; 32],
    request_scheme_len: usize,
    peer_authenticated: bool,
    pq_chain: bool,
    peer_pinned: bool,
    peer_record_limit: usize,
    /// The record_size_limit this endpoint enforces: set only once both
    /// sides sent the extension (RFC 8449, `REQ-RSL-002`).
    local_record_limit: Option<u16>,
    ccs_count: usize,
    sent_close: bool,
    peer_closed: bool,
    staple_requested: bool,
    revocation_checked: bool,
    retried: bool,
    /// Seed of this client's GREASE ECH extension, so a second ClientHello
    /// repeats it exactly without holding it. REQ-ECH-011.
    ech_grease: Option<[u8; 32]>,
    retry_fingerprint: Option<Output>,
    retry_cookie: [u8; 256],
    retry_cookie_len: usize,
}

/// Largest GREASE ECH payload: a 288-byte padded inner hello and its tag.
const GREASE_PAYLOAD_MAX: usize = 288 + 16;

impl<'a> Connection<'a> {
    /// Initialize a client and queue its ClientHello. `REQ-FIX-004`.
    /// Initialization may validate prepared configuration; subsequent methods
    /// (including handshake input) make no allocator calls.
    pub fn client(
        config: &'a ClientConfig,
        name: &'a str,
        rng: &'a mut dyn RandomSource,
        storage: Storage<'a>,
        limits: Limits,
    ) -> Result<Self> {
        config.validate()?;
        sign::prepare_tables()?;
        if config.ech_configs.is_some()
            || config.external_psk.is_some()
            || config.tickets.is_some()
            || config.early_data
            || config.post_handshake_auth
        {
            return Err(Error::new(
                ErrorKind::InvalidConfig,
                "requested client feature unavailable in fixed engine",
            ));
        }
        if config.revocation == crate::config::Revocation::RequireStaple
            && matches!(config.verification, PeerVerification::PinnedSpki { .. })
        {
            return Err(Error::new(
                ErrorKind::InvalidConfig,
                "RequireStaple needs an issuer verified through roots",
            ));
        }
        if name.len() > limits.name {
            return Err(capacity("server name capacity"));
        }
        let name = ServerName::parse(name)?;
        let mut c = Self::new(Config::Client(config, name), rng, storage, limits)?;
        c.session_id_len = 32;
        crypto::fill_random(c.rng, &mut c.random)?;
        crypto::fill_random(c.rng, &mut c.session_id)?;
        if config.ech_grease {
            let mut seed = [0u8; 32];
            crypto::fill_random(c.rng, &mut seed)?;
            c.ech_grease = Some(seed);
        }
        c.client_hello()?;
        c.transition(State::WaitServerHello)?;
        Ok(c)
    }

    /// Initialize a server awaiting ClientHello. `REQ-FIX-004`.
    /// Disable ticket issuance explicitly before using this backend.
    pub fn server(
        config: &'a ServerConfig,
        rng: &'a mut dyn RandomSource,
        storage: Storage<'a>,
        limits: Limits,
    ) -> Result<Self> {
        config.validate()?;
        sign::prepare_tables()?;
        if config.ech.is_some()
            || !config.external_psks.is_empty()
            || config.tickets.is_some()
            || config.early_data.is_some()
            || config.retry_cookie
            || matches!(config.client_auth, ClientAuth::OnDemand(_))
        {
            return Err(Error::new(
                ErrorKind::InvalidConfig,
                "requested server feature unavailable in fixed engine",
            ));
        }
        Self::new(Config::Server(config), rng, storage, limits)
    }

    fn new(
        config: Config<'a>,
        rng: &'a mut dyn RandomSource,
        storage: Storage<'a>,
        limits: Limits,
    ) -> Result<Self> {
        if !(1..=8).contains(&limits.certificates)
            || !(1..=64).contains(&limits.extensions)
            || !(1..=64).contains(&limits.events)
            || limits.name > 253
            || limits.alpn_protocols == 0
        {
            return Err(Error::new(
                ErrorKind::InvalidConfig,
                "fixed engine slot limits",
            ));
        }
        let common = match config {
            Config::Client(c, _) => &c.common,
            Config::Server(c) => &c.common,
        };
        if common.alpn.len() > limits.alpn_protocols || common.schemes.len() > 32 {
            return Err(capacity("configuration slot capacity"));
        }
        let mut max_private = 0;
        let mut max_public = 0;
        if common.groups.len() > 10
            || common
                .groups
                .iter()
                .enumerate()
                .any(|(i, group)| common.groups[..i].contains(group))
        {
            return Err(Error::new(
                ErrorKind::InvalidConfig,
                "fixed key slot groups must be unique and fit ten slots",
            ));
        }
        let mut initial_private = 0;
        let mut initial_public = 0;
        let initial = match config {
            Config::Client(c, _) => c.initial_key_shares.min(common.groups.len()),
            _ => 0,
        };
        for (i, &group) in common.groups.iter().enumerate() {
            let (sk, client, server, _) = kx::storage_lengths(group)?;
            max_private = max_private.max(sk);
            max_public = max_public.max(client.max(server));
            if i < initial {
                initial_private += sk;
                initial_public += client;
            }
        }
        max_private = max_private.max(initial_private);
        max_public = max_public.max(initial_public);
        if storage.private_key.len() < max_private
            || storage.public_key.len() < max_public
            || storage.record.len() < 5
            || storage.handshake.len() < 4
            || storage.scratch.len() < 4
        {
            return Err(capacity("initial connection storage"));
        }
        let state = if matches!(config, Config::Client(..)) {
            State::Start
        } else {
            State::WaitClientHello
        };
        let group = common.groups[0];
        Ok(Self {
            config,
            storage,
            limits,
            rng,
            report: Report {
                state,
                suite: None,
                group: None,
                peer_signature_scheme: None,
                local_signature_scheme: None,
                peer_chain_schemes: [None; 8],
                alpn: None,
                peer_chain_min_bits: None,
                error: None,
                validated: false,
                properties: 0,
                events: [None; 64],
                event_len: 0,
            },
            record_len: 0,
            hs_len: 0,
            out_len: 0,
            app_len: 0,
            cert_len: 0,
            chain: [None; 8],
            chain_len: 0,
            hash256: Hash::new(HashAlg::Sha256),
            hash384: Hash::new(HashAlg::Sha384),
            suite: None,
            group,
            key_slots: [None; 10],
            read: None,
            read_epoch: 0,
            write: None,
            peer_hs_secret: None,
            local_hs_secret: None,
            master: None,
            client_app: None,
            exporter: None,
            random: [0; 32],
            session_id: [0; 32],
            session_id_len: 0,
            request_client: false,
            request_schemes: [None; 32],
            request_scheme_len: 0,
            peer_authenticated: false,
            pq_chain: false,
            peer_pinned: false,
            peer_record_limit: record::MAX_PLAINTEXT + 1,
            local_record_limit: None,
            ccs_count: 0,
            sent_close: false,
            peer_closed: false,
            retried: false,
            ech_grease: None,
            retry_fingerprint: None,
            retry_cookie: [0; 256],
            retry_cookie_len: 0,
            staple_requested: false,
            revocation_checked: false,
        })
    }

    fn common(&self) -> &'a Common {
        match self.config {
            Config::Client(c, _) => &c.common,
            Config::Server(c) => &c.common,
        }
    }
    fn is_client(&self) -> bool {
        matches!(self.config, Config::Client(..))
    }
    fn check(&mut self) -> Result<()> {
        if let Some(error) = self.report.error {
            return Err(error);
        }
        if self.common().fips {
            let result = (|| {
                if ic_fips::mode() != Some(ic_fips::Mode::Approved) {
                    return Err(Error::new(ErrorKind::FipsModule, "approved mode required"));
                }
                for suite in &self.common().suites {
                    let (aead, hash) = record::suite_params(*suite).ok_or(unexpected())?;
                    for id in [
                        aead.ic_id(),
                        hash.ic_hash_id(),
                        hash.ic_hmac_id(),
                        hash.ic_hkdf_id(),
                    ] {
                        ic_fips::check(id).map_err(|_| {
                            Error::new(ErrorKind::FipsModule, "fixed engine service gate")
                        })?;
                    }
                }
                for group in &self.common().groups {
                    for id in kx::ic_ids(*group) {
                        ic_fips::check(id).map_err(|_| {
                            Error::new(ErrorKind::FipsModule, "fixed engine group gate")
                        })?;
                    }
                }
                for scheme in &self.common().schemes {
                    if let Some(id) = sign::ic_id(*scheme) {
                        ic_fips::check(id).map_err(|_| {
                            Error::new(ErrorKind::FipsModule, "fixed engine signature gate")
                        })?;
                    }
                }
                Ok(())
            })();
            if let Err(error) = result {
                return self.fail(error);
            }
        }
        Ok(())
    }
    fn hash_alg(&self) -> Result<HashAlg> {
        self.suite
            .and_then(record::suite_params)
            .map(|(_, h)| h)
            .ok_or(Error::new(ErrorKind::InvalidState, "no negotiated suite"))
    }
    fn hash(&self) -> Result<Output> {
        Ok(match self.hash_alg()? {
            HashAlg::Sha256 => self.hash256.peek(),
            HashAlg::Sha384 => self.hash384.peek(),
        })
    }
    fn add(&mut self, message: &[u8]) {
        self.hash256.update(message);
        self.hash384.update(message);
    }
    fn transition(&mut self, state: State) -> Result<()> {
        if self.report.event_len == self.limits.events {
            return Err(capacity("audit event slots"));
        }
        self.report.events[self.report.event_len] = Some(Event { state });
        self.report.event_len += 1;
        self.report.state = state;
        Ok(())
    }
    fn fail<T>(&mut self, error: Error) -> Result<T> {
        let error = *self.report.error.get_or_insert(error);
        self.report.state = State::Failed;
        self.report.properties = 0;
        self.storage.private_key.zeroize();
        self.storage.application.zeroize();
        self.storage.record.zeroize();
        self.storage.handshake.zeroize();
        self.storage.scratch.zeroize();
        self.storage.outgoing.zeroize();
        self.app_len = 0;
        self.out_len = 0;
        self.record_len = 0;
        self.hs_len = 0;
        self.read = None;
        self.write = None;
        self.peer_hs_secret = None;
        self.local_hs_secret = None;
        self.master = None;
        self.client_app = None;
        self.exporter = None;
        Err(error)
    }

    /// Borrow the report; reading it never allocates.
    pub fn report(&self) -> &Report<'a> {
        &self.report
    }
    /// Whether the handshake completed successfully.
    pub fn is_connected(&self) -> bool {
        self.report.state == State::Connected && self.report.error.is_none()
    }
    /// Whether the peer sent an authenticated close_notify. A transport that
    /// ends while this is false may have been truncated. `REQ-FIX-004`.
    pub fn peer_closed(&self) -> bool {
        self.peer_closed
    }
    /// Encoded records ready for the transport. Borrow ends before further mutation.
    pub fn outgoing(&self) -> &[u8] {
        &self.storage.outgoing[..self.out_len]
    }
    /// Mark exactly `n` queued bytes as sent. Invalid consumption latches failure.
    pub fn consume_outgoing(&mut self, n: usize) -> Result<()> {
        self.check()?;
        if n > self.out_len {
            return self.fail(Error::new(
                ErrorKind::InvalidState,
                "outgoing consumption exceeds queue",
            ));
        }
        self.storage.outgoing.copy_within(n..self.out_len, 0);
        self.out_len -= n;
        Ok(())
    }
    /// Copy decrypted application data into the caller's slice.
    pub fn read_application(&mut self, out: &mut [u8]) -> Result<usize> {
        self.check()?;
        let n = out.len().min(self.app_len);
        out[..n].copy_from_slice(&self.storage.application[..n]);
        self.storage.application.copy_within(n..self.app_len, 0);
        self.storage.application[self.app_len - n..self.app_len].zeroize();
        self.app_len -= n;
        Ok(n)
    }
    /// Retained peer certificate DER, borrowed until the next mutable operation.
    pub fn peer_certificate(&self, index: usize) -> Option<&[u8]> {
        let (start, len) = self.chain.get(index).copied().flatten()?;
        self.storage.certificates.get(start..start + len)
    }
    /// Feed an arbitrary transport fragment. All bytes are consumed or failure latches.
    /// `REQ-FIX-005`: no truncation, partial success or panic on capacity exhaustion.
    pub fn receive(&mut self, input: &[u8]) -> Result<()> {
        self.check()?;
        let result = self.receive_inner(input);
        match result {
            Ok(()) => Ok(()),
            Err(e) => self.fail(e),
        }
    }
    fn receive_inner(&mut self, mut input: &[u8]) -> Result<()> {
        while !input.is_empty() {
            if self.peer_closed {
                return Err(Error::new(ErrorKind::Closed, "input after close_notify"));
            }
            let reading_header = self.record_len < 5;
            let need = if reading_header {
                5
            } else {
                let n = usize::from(u16::from_be_bytes([
                    self.storage.record[3],
                    self.storage.record[4],
                ]));
                if n > record::MAX_CIPHERTEXT {
                    return Err(Error::new(
                        ErrorKind::RecordOverflow,
                        "record body exceeds TLS bound",
                    ));
                }
                5 + n
            };
            if need > self.storage.record.len() {
                return Err(capacity("incoming record capacity"));
            }
            let n = input.len().min(need - self.record_len);
            self.storage.record[self.record_len..self.record_len + n].copy_from_slice(&input[..n]);
            self.record_len += n;
            input = &input[n..];
            // The header just completed: compute the full length next pass.
            // Only on that pass: a record announcing an empty body also needs
            // exactly five bytes, and must then be processed (and refused),
            // not skipped forever without consuming input.
            if reading_header && self.record_len == 5 {
                continue;
            }
            if self.record_len != need {
                continue;
            }
            let bytes = core::mem::take(&mut self.storage.record);
            let result = self.process_record(&mut bytes[..need]);
            self.storage.record = bytes;
            self.record_len = 0;
            result?;
        }
        Ok(())
    }
    fn process_record(&mut self, bytes: &mut [u8]) -> Result<()> {
        let header: [u8; 5] = bytes[..5].try_into().map_err(|_| unexpected())?;
        if header[1] != 3 || !matches!(header[2], 1 | 3) {
            return Err(Error::new(
                ErrorKind::ProtocolVersion,
                "record legacy version",
            ));
        }
        let body = &mut bytes[5..];
        let outer = ContentType::from_wire(header[0]);
        if outer == ContentType::ChangeCipherSpec {
            if body != [1]
                || self.report.state == State::Connected
                || (self.report.state == State::WaitClientHello && !self.retried)
                || self.report.state == State::Start
                || self.ccs_count == 2
            {
                return Err(unexpected());
            }
            self.ccs_count += 1;
            return Ok(());
        }
        let (ty, n) = if let Some(read) = self.read.as_mut() {
            if outer != ContentType::ApplicationData || header[2] != 3 {
                return Err(unexpected());
            }
            let (ty, n) = read.open(&header, body)?;
            if let Some(limit) = self.local_record_limit {
                if body.len().saturating_sub(crypto::TAG_LEN) > usize::from(limit) {
                    return Err(Error::new(
                        ErrorKind::RecordOverflow,
                        "local record_size_limit",
                    ));
                }
            }
            (ty, n)
        } else {
            if outer != ContentType::Handshake && outer != ContentType::Alert {
                return Err(unexpected());
            }
            if body.is_empty() || body.len() > record::MAX_PLAINTEXT {
                return Err(Error::new(
                    ErrorKind::RecordOverflow,
                    "plaintext record bound",
                ));
            }
            (outer, body.len())
        };
        match ty {
            ContentType::Handshake => self.receive_handshake(&body[..n]),
            ContentType::ApplicationData
                if self.is_connected() && !self.peer_closed && self.hs_len == 0 =>
            {
                let end = self
                    .app_len
                    .checked_add(n)
                    .ok_or(capacity("application queue"))?;
                self.storage
                    .application
                    .get_mut(self.app_len..end)
                    .ok_or(capacity("application queue"))?
                    .copy_from_slice(&body[..n]);
                self.app_len = end;
                Ok(())
            }
            ContentType::Alert if n == 2 => {
                if body[1] == 0 {
                    self.peer_closed = true;
                    Ok(())
                } else {
                    Err(Error::new(ErrorKind::PeerAlert, "peer sent TLS alert"))
                }
            }
            _ => Err(unexpected()),
        }
    }
    fn receive_handshake(&mut self, mut bytes: &[u8]) -> Result<()> {
        while !bytes.is_empty() {
            let reading_header = self.hs_len < 4;
            let need = if reading_header {
                4
            } else {
                let b = &self.storage.handshake;
                4 + ((usize::from(b[1]) << 16) | (usize::from(b[2]) << 8) | usize::from(b[3]))
            };
            if need > self.storage.handshake.len()
                || need.saturating_sub(4) > self.common().max_handshake_message
            {
                return Err(capacity("handshake reassembly capacity"));
            }
            let n = bytes.len().min(need - self.hs_len);
            self.storage.handshake[self.hs_len..self.hs_len + n].copy_from_slice(&bytes[..n]);
            self.hs_len += n;
            bytes = &bytes[n..];
            // As for records: recompute only on the pass that completed the
            // header, so an empty-bodied message is processed, not skipped
            // forever.
            if reading_header && self.hs_len == 4 {
                continue;
            }
            if self.hs_len != need {
                continue;
            }
            let storage = core::mem::take(&mut self.storage.handshake);
            let epoch = self.read_epoch;
            let result = self.on_message(&storage[..need]);
            self.storage.handshake = storage;
            self.hs_len = 0;
            result?;
            // REQ-REC-008: a message that changes the read key (ServerHello,
            // Finished, KeyUpdate) must end its record; anything after it in
            // the same record was protected, or not, under the old key.
            if self.read_epoch != epoch && !bytes.is_empty() {
                return Err(unexpected());
            }
        }
        Ok(())
    }
    fn queue_record(&mut self, ty: ContentType, content: &[u8]) -> Result<()> {
        let max = record::MAX_PLAINTEXT.min(self.peer_record_limit.saturating_sub(1));
        if max == 0 {
            return Err(invalid("peer record size limit"));
        }
        for chunk in content.chunks(max) {
            let pad = self
                .common()
                .record_padding
                .min(self.peer_record_limit.saturating_sub(chunk.len() + 1));
            let out = &mut self.storage.outgoing[self.out_len..];
            let n = if let Some(write) = self.write.as_mut() {
                write.seal_into(ty, chunk, pad, out)?
            } else {
                let total = 5 + chunk.len();
                let out = out
                    .get_mut(..total)
                    .ok_or(capacity("outgoing flight capacity"))?;
                out[..5].copy_from_slice(&[
                    ty.to_wire(),
                    3,
                    3,
                    (chunk.len() >> 8) as u8,
                    chunk.len() as u8,
                ]);
                out[5..].copy_from_slice(chunk);
                total
            };
            self.out_len += n;
        }
        Ok(())
    }
    fn send_message(
        &mut self,
        ty: u8,
        encode: impl FnOnce(&mut Writer<'_>) -> Result<()>,
    ) -> Result<()> {
        let scratch = core::mem::take(&mut self.storage.scratch);
        let result = (|| {
            let mut w = Writer::new(scratch);
            w.u8(ty)?;
            let prefix = w.reserve(3)?;
            encode(&mut w)?;
            w.length(prefix, 3)?;
            let message = w.written();
            self.add(message);
            self.queue_record(ContentType::Handshake, message)
        })();
        self.storage.scratch = scratch;
        result
    }

    /// Queue application records. Overflow latches failure and clears the flight.
    pub fn write_application(&mut self, bytes: &[u8]) -> Result<()> {
        self.check()?;
        if !self.is_connected() || self.sent_close {
            return Err(Error::new(
                ErrorKind::InvalidState,
                "application write before handshake or after close",
            ));
        }
        let result = self.queue_record(ContentType::ApplicationData, bytes);
        match result {
            Ok(()) => Ok(()),
            Err(e) => self.fail(e),
        }
    }
    /// Derive an exporter into caller storage, without allocating.
    pub fn export(&mut self, label: &[u8], context: &[u8], out: &mut [u8]) -> Result<()> {
        self.check()?;
        if !self.is_connected() {
            return Err(Error::new(
                ErrorKind::InvalidState,
                "export before handshake",
            ));
        }
        key_schedule::export(
            self.hash_alg()?,
            self.exporter.as_ref().ok_or(unexpected())?.as_bytes(),
            label,
            context,
            out,
        )
    }
    /// Queue KeyUpdate and move the write direction to the next generation.
    pub fn key_update(&mut self, request_peer: bool) -> Result<()> {
        self.check()?;
        if !self.is_connected() || self.sent_close {
            return Err(Error::new(ErrorKind::InvalidState, "KeyUpdate unavailable"));
        }
        let result = self.key_update_inner(request_peer);
        match result {
            Ok(()) => Ok(()),
            Err(e) => self.fail(e),
        }
    }
    fn key_update_inner(&mut self, request_peer: bool) -> Result<()> {
        self.queue_record(
            ContentType::Handshake,
            &[24, 0, 0, 1, u8::from(request_peer)],
        )?;
        self.write = Some(
            self.write
                .as_ref()
                .ok_or(unexpected())?
                .next_generation(self.suite.ok_or(unexpected())?)?,
        );
        Ok(())
    }
    /// Queue authenticated close_notify. Reading already queued peer data remains possible.
    pub fn close(&mut self) -> Result<()> {
        self.check()?;
        if self.sent_close {
            return Ok(());
        }
        if !self.is_connected() {
            return Err(Error::new(
                ErrorKind::InvalidState,
                "close before handshake",
            ));
        }
        let result = self.queue_record(ContentType::Alert, &[1, 0]);
        match result {
            Ok(()) => {
                self.sent_close = true;
                Ok(())
            }
            Err(e) => self.fail(e),
        }
    }
}

impl Drop for Connection<'_> {
    fn drop(&mut self) {
        self.storage.private_key.zeroize();
        self.storage.record.zeroize();
        self.storage.handshake.zeroize();
        self.storage.application.zeroize();
        self.storage.scratch.zeroize();
        self.storage.outgoing.zeroize();
    }
}

impl<'a> Connection<'a> {
    fn client_hello(&mut self) -> Result<()> {
        let common = self.common();
        let (config, name) = match self.config {
            Config::Client(c, n) => (c, n),
            _ => return Err(unexpected()),
        };
        let public = core::mem::take(&mut self.storage.public_key);
        let result = (|| {
            let count = if self.retried {
                1
            } else {
                config.initial_key_shares.min(common.groups.len())
            };
            let mut private_at = 0;
            let mut public_at = 0;
            self.key_slots.fill(None);
            for i in 0..count {
                let group = if self.retried {
                    self.group
                } else {
                    common.groups[i]
                };
                let (private_len, _, _, _) = kx::storage_lengths(group)?;
                let public_len = kx::generate_into(
                    group,
                    self.rng,
                    &mut self.storage.private_key[private_at..],
                    &mut public[public_at..],
                )?;
                self.key_slots[i] = Some(KeySlot {
                    group,
                    private: private_at,
                    private_len,
                    public: public_at,
                    public_len,
                });
                private_at += private_len;
                public_at += public_len;
            }
            let slots = self.key_slots;
            let random = self.random;
            let sid = self.session_id;
            let cookie = self.retry_cookie;
            let cookie_len = self.retry_cookie_len;
            // REQ-ECH-011: GREASE as the owned client sends it (a real
            // suite, random configuration id, X25519-sized enc, a padded
            // inner-hello-sized payload), derived from the seed.
            let mut grease = [0u8; 2 + 32 + GREASE_PAYLOAD_MAX];
            let grease_len = match self.ech_grease {
                Some(seed) => {
                    crypto::hkdf_expand(HashAlg::Sha256, &seed, b"isl ech grease", &mut grease)?;
                    2 + 32 + 192 + 32 * usize::from(grease[1] % 4) + 16
                }
                None => 0,
            };
            self.send_message(1, |w| {
                w.u16(0x0303)?;
                w.put(&random)?;
                w.vector(1, &sid)?;
                w.nested(2, |w| {
                    for suite in &common.suites {
                        w.u16(suite.to_wire())?;
                    }
                    Ok(())
                })?;
                w.put(&[1, 0])?;
                w.nested(2, |w| {
                    w.ext(43, |w| w.put(&[2, 3, 4]))?;
                    w.ext(10, |w| {
                        w.nested(2, |w| {
                            for group in &common.groups {
                                w.u16(group.to_wire())?;
                            }
                            Ok(())
                        })
                    })?;
                    w.ext(13, |w| {
                        w.nested(2, |w| {
                            for scheme in &common.schemes {
                                w.u16(scheme.to_wire())?;
                            }
                            Ok(())
                        })
                    })?;
                    w.ext(51, |w| {
                        w.nested(2, |w| {
                            for slot in slots.iter().flatten() {
                                w.u16(slot.group.to_wire())?;
                                w.vector(2, &public[slot.public..slot.public + slot.public_len])?;
                            }
                            Ok(())
                        })
                    })?;
                    if cookie_len != 0 {
                        w.ext(44, |w| w.vector(2, &cookie[..cookie_len]))?;
                    }
                    if config.send_sni {
                        if let ServerName::Dns(name) = name {
                            w.ext(0, |w| {
                                w.nested(2, |w| {
                                    w.u8(0)?;
                                    w.vector(2, name.as_bytes())
                                })
                            })?;
                        }
                    }
                    if !common.alpn.is_empty() {
                        w.ext(16, |w| {
                            w.nested(2, |w| {
                                for p in &common.alpn {
                                    w.vector(1, p)?;
                                }
                                Ok(())
                            })
                        })?;
                    }
                    if let Some(limit) = common.record_size_limit {
                        w.ext(28, |w| w.u16(limit))?;
                    }
                    if grease_len != 0 {
                        w.ext(0xfe0d, |w| {
                            w.u8(0)?;
                            w.u16(0x0001)?;
                            w.u16(0x0001)?;
                            w.u8(grease[0])?;
                            w.vector(2, &grease[2..34])?;
                            w.vector(2, &grease[34..grease_len])
                        })?;
                    }
                    if config.revocation != crate::config::Revocation::Off
                        && matches!(config.verification, PeerVerification::Roots(_))
                    {
                        w.ext(5, |w| w.put(&[1, 0, 0, 0, 0]))?;
                    }
                    Ok(())
                })
            })
        })();
        self.storage.public_key = public;
        result
    }
    fn on_message(&mut self, message: &[u8]) -> Result<()> {
        let ty = message[0];
        let body = &message[4..];
        match (self.report.state, ty, self.is_client()) {
            (State::WaitClientHello, 1, false) => self.on_client_hello(body, message),
            (State::WaitServerHello, 2, true) => self.on_server_hello(body, message),
            (State::WaitEncryptedExtensions, 8, true) => {
                self.on_encrypted_extensions(body, message)
            }
            (State::WaitCertificateRequest, 13, true) => self.on_certificate_request(body, message),
            (State::WaitCertificateRequest | State::WaitCertificate, 11, _) => {
                self.on_certificate(body, message)
            }
            (State::WaitCertificateVerify, 15, _) => self.on_certificate_verify(body, message),
            (State::WaitFinished, 20, _) => self.on_finished(body, message),
            (State::Connected, 24, _) => {
                if body.len() != 1 || body[0] > 1 {
                    return Err(invalid("KeyUpdate request"));
                }
                self.read_epoch = self.read_epoch.wrapping_add(1);
                self.read = Some(
                    self.read
                        .as_ref()
                        .ok_or(unexpected())?
                        .next_generation(self.suite.ok_or(unexpected())?)?,
                );
                if body[0] == 1 {
                    self.key_update_inner(false)?;
                }
                // Not a transition: recording one per update would let a peer
                // (or a long-lived session) exhaust the audit event slots.
                Ok(())
            }
            (State::Connected, 4, true) => {
                // Tickets were not enabled. Validate framing before discarding an unsolicited ticket.
                let mut r = Reader::new(body);
                let lifetime = r.u32()?;
                r.u32()?;
                r.vec8()?;
                if lifetime > 604800 || r.vec16()?.is_empty() {
                    return Err(invalid("session ticket framing"));
                }
                Extensions::parse(
                    &mut r,
                    ExtensionContext::NewSessionTicket,
                    self.limits.extensions,
                )?;
                r.finish()
            }
            _ => Err(unexpected()),
        }
    }
    fn on_client_hello(&mut self, body: &[u8], message: &[u8]) -> Result<()> {
        let config = match self.config {
            Config::Server(c) => c,
            _ => return Err(unexpected()),
        };
        let common = &config.common;
        let mut r = Reader::new(body);
        if r.u16()? != 0x0303 {
            return Err(invalid("ClientHello legacy version"));
        }
        r.take(32)?;
        let sid = r.vec8()?;
        if sid.len() > 32 {
            return Err(invalid("session ID length"));
        }
        self.session_id[..sid.len()].copy_from_slice(sid);
        self.session_id_len = sid.len();
        let suites = r.vec16()?;
        if suites.is_empty() || suites.len() % 2 != 0 {
            return Err(invalid("cipher suite list"));
        }
        if r.vec8()? != [0] {
            return Err(invalid("TLS 1.3 compression"));
        }
        let ext = Extensions::parse(
            &mut r,
            ExtensionContext::ClientHello,
            self.limits.extensions,
        )?;
        r.finish()?;
        if !contains_u16(u16_list(ext.required(43)?, 1)?, 0x0304) {
            return Err(Error::new(
                ErrorKind::ProtocolVersion,
                "TLS 1.3 not offered",
            ));
        }
        let groups = u16_list(ext.required(10)?, 2)?;
        let schemes = u16_list(ext.required(13)?, 2)?;
        let mut sr = Reader::new(ext.required(51)?);
        let shares = sr.vec16()?;
        sr.finish()?;
        let mut selected = None;
        let mut offered = Reader::new(shares);
        let mut seen = [None; 64];
        let mut count = 0;
        while !offered.is_empty() {
            let group = offered.u16()?;
            let share = offered.vec16()?;
            if count == self.limits.extensions {
                return Err(capacity("key share slots"));
            }
            if seen[..count].contains(&Some(group))
                || !contains_u16(groups, group)
                || share.is_empty()
            {
                return Err(invalid("invalid ClientHello key share"));
            }
            seen[count] = Some(group);
            count += 1;
        }
        for &group in &common.groups {
            let mut offered = Reader::new(shares);
            while !offered.is_empty() {
                let g = offered.u16()?;
                let share = offered.vec16()?;
                if g == group.to_wire() {
                    selected = Some((group, share));
                    break;
                }
            }
            if selected.is_some() {
                break;
            }
        }
        let suite = if config.prefer_server_order {
            common
                .suites
                .iter()
                .copied()
                .find(|s| contains_u16(suites, s.to_wire()))
        } else {
            suites
                .as_chunks::<2>()
                .0
                .iter()
                .map(|s| CipherSuite::from_wire(u16::from_be_bytes(*s)))
                .find(|s| common.suites.contains(s))
        }
        .ok_or(Error::new(ErrorKind::HandshakeFailure, "no shared suite"))?;
        let fingerprint = hello_fingerprint(body, ext)?;
        if self.retried
            && (self.suite != Some(suite)
                || !self
                    .retry_fingerprint
                    .as_ref()
                    .is_some_and(|h| ic_core::ct::verify(h.as_bytes(), fingerprint.as_bytes())))
        {
            return Err(invalid("ClientHello2 changed immutable fields"));
        }
        if selected.is_none() {
            if self.retried {
                return Err(invalid("ClientHello2 omitted requested share"));
            }
            let group = common
                .groups
                .iter()
                .copied()
                .find(|g| contains_u16(groups, g.to_wire()))
                .ok_or(Error::new(ErrorKind::HandshakeFailure, "no shared group"))?;
            self.suite = Some(suite);
            self.group = group;
            self.retried = true;
            self.retry_fingerprint = Some(fingerprint);
            self.add(message);
            self.rollup();
            let sid = self.session_id;
            let sid_len = self.session_id_len;
            self.send_message(2, |w| {
                w.u16(0x0303)?;
                w.put(&crate::msgs::HRR_RANDOM)?;
                w.vector(1, &sid[..sid_len])?;
                w.u16(suite.to_wire())?;
                w.u8(0)?;
                w.nested(2, |w| {
                    w.ext(43, |w| w.u16(0x0304))?;
                    w.ext(51, |w| w.u16(group.to_wire()))
                })
            })?;
            return self.transition(State::WaitClientHello);
        }
        let (group, peer_share) = selected.ok_or(unexpected())?;
        if self.retried && (group != self.group || count != 1) {
            return Err(invalid("ClientHello2 key share"));
        }
        if ext.get(44)?.is_some() {
            return Err(invalid("unsolicited retry cookie"));
        }
        self.suite = Some(suite);
        self.group = group;
        self.report.suite = Some(suite);
        self.report.group = Some(group);
        let name = if let Some(bytes) = ext.get(0)? {
            let mut nr = Reader::new(bytes);
            let mut names = nr.sub16()?;
            nr.finish()?;
            if names.u8()? != 0 {
                return Err(invalid("SNI name type"));
            }
            let bytes = names.vec16()?;
            names.finish()?;
            if bytes.len() > self.limits.name {
                return Err(capacity("SNI name capacity"));
            }
            let name = core::str::from_utf8(bytes).map_err(|_| invalid("SNI ASCII"))?;
            match ServerName::parse(name)? {
                ServerName::Dns(_) => Some(name),
                _ => return Err(invalid("IP address in SNI")),
            }
        } else {
            None
        };
        let identity = config
            .identities
            .iter()
            .find(|id| {
                name.is_none_or(|n| x509::verify_name(&id.chain[0], &ServerName::Dns(n)).is_ok())
            })
            .ok_or(Error::new(
                ErrorKind::UnrecognizedName,
                "no identity for requested name",
            ))?;
        let scheme = common
            .schemes
            .iter()
            .copied()
            .find(|s| {
                s.allowed_in_handshake()
                    && identity.key.schemes().contains(s)
                    && contains_u16(schemes, s.to_wire())
            })
            .ok_or(Error::new(
                ErrorKind::HandshakeFailure,
                "no signing scheme for identity",
            ))?;
        self.select_alpn(ext.get(16)?)?;
        // RFC 8446 section 4.2: answer record_size_limit, and so enforce
        // ours, only for a client that offered it (RFC 8449, `REQ-RSL-002`).
        let offered_limit = ext.get(28)?;
        self.record_limit(offered_limit)?;
        self.local_record_limit = common.record_size_limit.filter(|_| offered_limit.is_some());
        if let Some(status) = ext.get(5)? {
            let mut r = Reader::new(status);
            if r.u8()? == 1 {
                r.vec16()?;
                r.vec16()?;
                r.finish()?;
                self.staple_requested = true;
            }
        }
        self.add(message);
        let public = core::mem::take(&mut self.storage.public_key);
        let result = (|| {
            let mut secret = Zeroizing::new([0u8; 98]);
            let (n, ss) = kx::respond_into(
                group,
                peer_share,
                self.rng,
                self.storage.private_key,
                public,
                secret.get_mut(),
            )?;
            self.storage.private_key.zeroize();
            crypto::fill_random(self.rng, &mut self.random)?;
            let random = self.random;
            let sid = self.session_id;
            let sid_len = self.session_id_len;
            self.send_message(2, |w| {
                w.u16(0x0303)?;
                w.put(&random)?;
                w.vector(1, &sid[..sid_len])?;
                w.u16(suite.to_wire())?;
                w.u8(0)?;
                w.nested(2, |w| {
                    w.ext(43, |w| w.u16(0x0304))?;
                    w.ext(51, |w| {
                        w.u16(group.to_wire())?;
                        w.vector(2, &public[..n])
                    })
                })
            })?;
            self.install_handshake(&secret.get()[..ss])?;
            let alpn = self.report.alpn;
            let local_limit = self.local_record_limit;
            self.send_message(8, |w| {
                w.nested(2, |w| {
                    if name.is_some() {
                        w.ext(0, |_| Ok(()))?;
                    }
                    if let Some(alpn) = alpn {
                        w.ext(16, |w| w.nested(2, |w| w.vector(1, alpn)))?;
                    }
                    if let Some(limit) = local_limit {
                        w.ext(28, |w| w.u16(limit))?;
                    }
                    Ok(())
                })
            })?;
            self.request_client = !matches!(config.client_auth, ClientAuth::None);
            if self.request_client {
                self.send_message(13, |w| {
                    w.u8(0)?;
                    w.nested(2, |w| {
                        w.ext(13, |w| {
                            w.nested(2, |w| {
                                for s in &common.schemes {
                                    w.u16(s.to_wire())?;
                                }
                                Ok(())
                            })
                        })
                    })
                })?;
            }
            self.send_certificate(Some(identity))?;
            self.send_certificate_verify(identity, scheme)?;
            self.send_finished()?;
            self.install_server_application()?;
            self.transition(if self.request_client {
                State::WaitCertificate
            } else {
                State::WaitFinished
            })
        })();
        self.storage.public_key = public;
        result
    }
    fn on_server_hello(&mut self, body: &[u8], message: &[u8]) -> Result<()> {
        let mut r = Reader::new(body);
        if r.u16()? != 0x0303 {
            return Err(invalid("ServerHello legacy version"));
        }
        let random = r.take(32)?;
        if r.vec8()? != &self.session_id[..self.session_id_len] {
            return Err(invalid("ServerHello session ID echo"));
        }
        let suite = CipherSuite::from_wire(r.u16()?);
        if !self.common().suites.contains(&suite) || r.u8()? != 0 {
            return Err(invalid("ServerHello suite or compression"));
        }
        if self.retried && self.suite != Some(suite) {
            return Err(invalid("ServerHello changed retry suite"));
        }
        let retry = random == crate::msgs::HRR_RANDOM;
        let ext = Extensions::parse(
            &mut r,
            if retry {
                ExtensionContext::HelloRetryRequest
            } else {
                ExtensionContext::ServerHello
            },
            self.limits.extensions,
        )?;
        r.finish()?;
        if ext.required(43)? != [3, 4] {
            return Err(Error::new(
                ErrorKind::ProtocolVersion,
                "ServerHello TLS version",
            ));
        }
        if retry {
            if self.retried {
                return Err(unexpected());
            }
            let mut kr = Reader::new(ext.required(51)?);
            let group = NamedGroup::from_wire(kr.u16()?);
            kr.finish()?;
            if self.key_slots.iter().flatten().any(|s| s.group == group)
                || !self.common().groups.contains(&group)
            {
                return Err(invalid("retry requested unoffered or existing share"));
            }
            let mut er = Reader::new(ext.bytes);
            while !er.is_empty() {
                let ty = er.u16()?;
                er.vec16()?;
                if ty != 43 && ty != 51 && ty != 44 {
                    return Err(Error::new(
                        ErrorKind::UnsupportedExtension,
                        "retry extension",
                    ));
                }
            }
            if let Some(cookie) = ext.get(44)? {
                let mut cr = Reader::new(cookie);
                let cookie = cr.vec16()?;
                cr.finish()?;
                if cookie.is_empty() {
                    return Err(invalid("empty retry cookie"));
                }
                self.retry_cookie
                    .get_mut(..cookie.len())
                    .ok_or(capacity("retry cookie capacity"))?
                    .copy_from_slice(cookie);
                self.retry_cookie_len = cookie.len();
            }
            self.suite = Some(suite);
            self.group = group;
            self.retried = true;
            self.storage.private_key.zeroize();
            self.rollup();
            self.add(message);
            self.client_hello()?;
            return self.transition(State::WaitServerHello);
        }
        let mut kr = Reader::new(ext.required(51)?);
        let group = NamedGroup::from_wire(kr.u16()?);
        let slot = self
            .key_slots
            .iter()
            .flatten()
            .find(|s| s.group == group)
            .copied()
            .ok_or(invalid("server selected unoffered share"))?;
        let share = kr.vec16()?;
        kr.finish()?;
        let mut er = Reader::new(ext.bytes);
        while !er.is_empty() {
            let ty = er.u16()?;
            er.vec16()?;
            if ty != 43 && ty != 51 {
                return Err(Error::new(
                    ErrorKind::UnsupportedExtension,
                    "unsolicited ServerHello extension",
                ));
            }
        }
        let mut secret = Zeroizing::new([0u8; 98]);
        let n = kx::complete_into(
            group,
            &self.storage.private_key[slot.private..slot.private + slot.private_len],
            share,
            secret.get_mut(),
        )?;
        self.storage.private_key.zeroize();
        self.key_slots.fill(None);
        self.group = group;
        self.suite = Some(suite);
        self.report.suite = Some(suite);
        self.report.group = Some(self.group);
        self.add(message);
        self.install_handshake(&secret.get()[..n])?;
        self.transition(State::WaitEncryptedExtensions)
    }
    fn install_handshake(&mut self, secret: &[u8]) -> Result<()> {
        let suite = self.suite.ok_or(unexpected())?;
        let hash = self.hash()?;
        let hs = key_schedule::KeySchedule::handshake(self.hash_alg()?, secret)?;
        let client = hs.client_traffic(hash.as_bytes())?;
        let server = hs.server_traffic(hash.as_bytes())?;
        let (read, write) = if self.is_client() {
            (server, client)
        } else {
            (client, server)
        };
        self.read_epoch = self.read_epoch.wrapping_add(1);
        self.read = Some(Protector::new(suite, &read)?);
        self.write = Some(Protector::new(suite, &write)?);
        self.peer_hs_secret = Some(read);
        self.local_hs_secret = Some(write);
        self.master = Some(hs.into_master()?);
        Ok(())
    }
    fn rollup(&mut self) {
        for hash in [&mut self.hash256, &mut self.hash384] {
            let alg = hash.alg();
            let digest = hash.peek();
            *hash = Hash::new(alg);
            hash.update(&[254, 0, 0, alg.len() as u8]);
            hash.update(digest.as_bytes());
        }
    }
    fn select_alpn(&mut self, offered: Option<&[u8]>) -> Result<()> {
        let Some(offered) = offered else {
            if self.common().require_alpn {
                return Err(Error::new(
                    ErrorKind::NoApplicationProtocol,
                    "ALPN required",
                ));
            }
            return Ok(());
        };
        let mut r = Reader::new(offered);
        let bytes = r.vec16()?;
        r.finish()?;
        let mut p = Reader::new(bytes);
        let mut count = 0;
        while !p.is_empty() {
            if p.vec8()?.is_empty() {
                return Err(invalid("empty ALPN name"));
            }
            count += 1;
            if count > self.limits.alpn_protocols {
                return Err(capacity("ALPN protocol slots"));
            }
        }
        if count == 0 {
            return Err(invalid("empty ALPN list"));
        }
        for protocol in &self.common().alpn {
            let mut p = Reader::new(bytes);
            while !p.is_empty() {
                if p.vec8()? == protocol {
                    self.report.alpn = Some(protocol);
                    return Ok(());
                }
            }
        }
        // RFC 7301 §3.2: when both sides use ALPN and share no protocol, the
        // server refuses, whether or not it requires ALPN of every client
        // (ALPACA). A server with no protocols configured ignores the offer.
        if self.common().require_alpn || !self.common().alpn.is_empty() {
            return Err(Error::new(
                ErrorKind::NoApplicationProtocol,
                "no shared ALPN",
            ));
        }
        Ok(())
    }
    fn record_limit(&mut self, extension: Option<&[u8]>) -> Result<()> {
        if let Some(bytes) = extension {
            let mut r = Reader::new(bytes);
            let limit = r.u16()?;
            r.finish()?;
            if !(64..=16385).contains(&limit) {
                return Err(invalid("record_size_limit range"));
            }
            self.peer_record_limit = usize::from(limit);
        }
        Ok(())
    }
    fn on_encrypted_extensions(&mut self, body: &[u8], message: &[u8]) -> Result<()> {
        let mut r = Reader::new(body);
        let ext = Extensions::parse(
            &mut r,
            ExtensionContext::EncryptedExtensions,
            self.limits.extensions,
        )?;
        r.finish()?;
        let mut e = Reader::new(ext.bytes);
        while !e.is_empty() {
            let ty = e.u16()?;
            let bytes = e.vec16()?;
            match ty {
                0 => {
                    let offered =
                        matches!(self.config, Config::Client(c, ServerName::Dns(_)) if c.send_sni);
                    if !offered || !bytes.is_empty() {
                        return Err(invalid("SNI acknowledgement"));
                    }
                }
                16 => {
                    let mut r = Reader::new(bytes);
                    let mut p = r.sub16()?;
                    r.finish()?;
                    let name = p.vec8()?;
                    p.finish()?;
                    let protocol = self
                        .common()
                        .alpn
                        .iter()
                        .find(|p| p.as_slice() == name)
                        .ok_or(Error::new(
                            ErrorKind::NoApplicationProtocol,
                            "server selected unoffered ALPN",
                        ))?;
                    self.report.alpn = Some(protocol);
                }
                28 if self.common().record_size_limit.is_some() => {
                    self.record_limit(Some(bytes))?;
                    self.local_record_limit = self.common().record_size_limit;
                }
                10 => {
                    u16_list(bytes, 2)?;
                }
                // REQ-ECH-011: retry configurations answering GREASE are
                // ignored (RFC 9849 §6.2).
                0xfe0d if self.ech_grease.is_some() => {}
                _ => {
                    return Err(Error::new(
                        ErrorKind::UnsupportedExtension,
                        "unsolicited EncryptedExtensions extension",
                    ))
                }
            }
        }
        if self.common().require_alpn && self.report.alpn.is_none() {
            return Err(Error::new(
                ErrorKind::NoApplicationProtocol,
                "server omitted ALPN",
            ));
        }
        self.add(message);
        self.transition(State::WaitCertificateRequest)
    }
    fn on_certificate_request(&mut self, body: &[u8], message: &[u8]) -> Result<()> {
        let mut r = Reader::new(body);
        if !r.vec8()?.is_empty() {
            return Err(invalid("handshake CertificateRequest context"));
        }
        let ext = Extensions::parse(
            &mut r,
            ExtensionContext::CertificateRequest,
            self.limits.extensions,
        )?;
        r.finish()?;
        let schemes = u16_list(ext.required(13)?, 2)?;
        if schemes.len() / 2 > self.request_schemes.len() {
            return Err(capacity("CertificateRequest signature slots"));
        }
        for (i, bytes) in schemes.as_chunks::<2>().0.iter().enumerate() {
            self.request_schemes[i] = Some(SignatureScheme::from_wire(u16::from_be_bytes([
                bytes[0], bytes[1],
            ])));
        }
        self.request_scheme_len = schemes.len() / 2;
        self.request_client = true;
        self.add(message);
        self.transition(State::WaitCertificate)
    }
    fn send_certificate(&mut self, identity: Option<&Identity>) -> Result<()> {
        if identity.is_some_and(|id| id.chain.len() > self.limits.certificates) {
            return Err(capacity("local certificate slots"));
        }
        let staple = if !self.is_client() && self.staple_requested {
            identity
                .and_then(|id| id.ocsp.as_deref())
                .map(|s| s.as_slice())
        } else {
            None
        };
        self.send_message(11, |w| {
            w.u8(0)?;
            w.nested(3, |w| {
                if let Some(id) = identity {
                    for (i, der) in id.chain.iter().enumerate() {
                        w.vector(3, der)?;
                        w.nested(2, |w| {
                            if i == 0 {
                                if let Some(staple) = staple {
                                    w.ext(5, |w| {
                                        w.u8(1)?;
                                        w.vector(3, staple)
                                    })?;
                                }
                            }
                            Ok(())
                        })?;
                    }
                }
                Ok(())
            })
        })
    }
    fn send_certificate_verify(
        &mut self,
        identity: &Identity,
        scheme: SignatureScheme,
    ) -> Result<()> {
        let hash = self.hash()?;
        let mut input = [0u8; 146];
        let n = cv_input(!self.is_client(), hash.as_bytes(), &mut input);
        let scratch = core::mem::take(&mut self.storage.scratch);
        let result = (|| {
            let sig = scratch
                .get_mut(8..)
                .ok_or(capacity("signature workspace"))?;
            let len = identity.key.sign_into(scheme, &input[..n], self.rng, sig)?;
            self.report.local_signature_scheme = Some(scheme);
            if len > 65535 {
                return Err(capacity("signature wire length"));
            }
            let body = len + 4;
            scratch[..8].copy_from_slice(&[
                15,
                (body >> 16) as u8,
                (body >> 8) as u8,
                body as u8,
                (scheme.to_wire() >> 8) as u8,
                scheme.to_wire() as u8,
                (len >> 8) as u8,
                len as u8,
            ]);
            self.add(&scratch[..len + 8]);
            self.queue_record(ContentType::Handshake, &scratch[..len + 8])
        })();
        self.storage.scratch = scratch;
        result
    }
    fn on_certificate(&mut self, body: &[u8], message: &[u8]) -> Result<()> {
        let mut r = Reader::new(body);
        if !r.vec8()?.is_empty() {
            return Err(invalid("Certificate context"));
        }
        let mut entries = r.sub24()?;
        r.finish()?;
        let mut staple = None;
        while !entries.is_empty() {
            let der = entries.vec24()?;
            if der.is_empty() {
                return Err(invalid("empty certificate entry"));
            }
            if Certificate::parse(der)?.extension_count() > self.limits.extensions {
                return Err(capacity("certificate extension slots"));
            }
            if self.chain_len == self.limits.certificates {
                return Err(capacity("peer certificate slots"));
            }
            let ext = Extensions::parse(
                &mut entries,
                ExtensionContext::CertificateEntry,
                self.limits.extensions,
            )?;
            if !ext.bytes.is_empty() {
                let requested = self.is_client()
                    && matches!(self.config, Config::Client(c, _) if c.revocation != crate::config::Revocation::Off && matches!(c.verification, PeerVerification::Roots(_)));
                let mut er = Reader::new(ext.bytes);
                while !er.is_empty() {
                    let ty = er.u16()?;
                    let bytes = er.vec16()?;
                    if ty != 5 || !requested || self.chain_len != 0 {
                        return Err(Error::new(
                            ErrorKind::UnsupportedExtension,
                            "certificate entry extension not requested",
                        ));
                    }
                    let mut sr = Reader::new(bytes);
                    if sr.u8()? != 1 {
                        return Err(invalid("certificate status type"));
                    }
                    staple = Some(sr.vec24()?);
                    sr.finish()?;
                }
            }
            let end = self
                .cert_len
                .checked_add(der.len())
                .ok_or(capacity("peer certificate DER capacity"))?;
            self.storage
                .certificates
                .get_mut(self.cert_len..end)
                .ok_or(capacity("peer certificate DER capacity"))?
                .copy_from_slice(der);
            self.chain[self.chain_len] = Some((self.cert_len, der.len()));
            self.chain_len += 1;
            self.cert_len = end;
        }
        if self.chain_len == 0 {
            let optional = matches!(self.config, Config::Server(c) if matches!(c.client_auth, ClientAuth::Optional(_)));
            if !optional {
                return Err(Error::new(
                    ErrorKind::CertificateRequired,
                    "empty peer certificate chain",
                ));
            }
            self.add(message);
            return self.transition(State::WaitFinished);
        }
        let (verification, name, usage) = match self.config {
            Config::Client(c, name) => (&c.verification, Some(name), Usage::ServerAuth),
            Config::Server(c) => match &c.client_auth {
                ClientAuth::Optional(v) | ClientAuth::Required(v) => (v, None, Usage::ClientAuth),
                _ => return Err(unexpected()),
            },
        };
        let mut opts = VerifyOptions::new((self.common().clock)(), usage, &self.common().schemes);
        opts.min_rsa_bits = self.common().profile.min_rsa_bits();
        opts.crls = self.common().crls.as_deref();
        opts.require_crl = self.common().require_crl;
        let leaf = self.peer_certificate(0).ok_or(unexpected())?;
        x509::check_leaf_fixed(leaf, &opts)?;
        let cert = Certificate::parse(leaf)?;
        let (bits, pq, pinned, schemes, revoked_checked) = match verification {
            PeerVerification::PinnedSpki {
                sha256,
                check_names,
            } => {
                let hash = HashAlg::Sha256.digest(cert.spki_der());
                let mut matches = false;
                for pin in sha256 {
                    matches |= ic_core::ct::verify(pin, hash.as_bytes());
                }
                if !matches {
                    return Err(Error::new(
                        ErrorKind::UnknownCa,
                        "peer SPKI does not match pin",
                    ));
                }
                if *check_names {
                    if let Some(name) = name {
                        x509::verify_name(leaf, &name)?;
                    }
                }
                (
                    cert.subject_public_key()?.classical_bits(),
                    true,
                    true,
                    [None; 8],
                    false,
                )
            }
            PeerVerification::Roots(roots) => {
                let mut inter = [&[][..]; 7];
                for (i, slot) in inter.iter_mut().enumerate().take(self.chain_len - 1) {
                    *slot = self.peer_certificate(i + 1).ok_or(unexpected())?;
                }
                let report =
                    x509::verify_chain_fixed(leaf, &inter[..self.chain_len - 1], roots, &opts)?;
                if let Some(name) = name {
                    x509::verify_name(leaf, &name)?;
                }
                let mut revocation = report.crl_checked;
                if let Config::Client(c, _) = self.config {
                    if let Some(staple) = staple {
                        let verified = x509::ocsp::verify_response(
                            staple,
                            leaf,
                            report.issuer_subject,
                            report.issuer_spki,
                            opts.now,
                            opts.allowed_schemes,
                        )?;
                        if verified.status == x509::ocsp::CertStatus::Good {
                            revocation = true;
                        } else if c.revocation == crate::config::Revocation::RequireStaple {
                            return Err(Error::new(
                                ErrorKind::BadCertificateStatus,
                                "OCSP status unknown",
                            ));
                        }
                    } else if c.revocation == crate::config::Revocation::RequireStaple {
                        return Err(Error::new(
                            ErrorKind::BadCertificateStatus,
                            "required OCSP staple absent",
                        ));
                    }
                }
                (
                    report.min_classical_bits,
                    report.depth != 0
                        && report.schemes[..report.depth]
                            .iter()
                            .all(|s| s.is_some_and(SignatureScheme::is_post_quantum)),
                    false,
                    report.schemes,
                    revocation,
                )
            }
        };
        self.report.peer_chain_min_bits = Some(bits);
        self.report.peer_chain_schemes = schemes;
        self.pq_chain = pq;
        self.peer_pinned = pinned;
        self.revocation_checked = revoked_checked;
        self.add(message);
        self.transition(State::WaitCertificateVerify)
    }
    fn on_certificate_verify(&mut self, body: &[u8], message: &[u8]) -> Result<()> {
        let mut r = Reader::new(body);
        let scheme = SignatureScheme::from_wire(r.u16()?);
        let signature = r.vec16()?;
        r.finish()?;
        if !scheme.allowed_in_handshake() || !self.common().schemes.contains(&scheme) {
            return Err(invalid("unoffered CertificateVerify scheme"));
        }
        let cert = Certificate::parse(self.peer_certificate(0).ok_or(unexpected())?)?;
        let hash = self.hash()?;
        let mut input = [0u8; 146];
        let n = cv_input(self.is_client(), hash.as_bytes(), &mut input);
        sign::verify(scheme, &cert.subject_public_key()?, &input[..n], signature)?;
        self.pq_chain &= scheme.is_post_quantum();
        self.peer_authenticated = true;
        self.report.peer_signature_scheme = Some(scheme);
        self.add(message);
        self.transition(State::WaitFinished)
    }
    fn send_finished(&mut self) -> Result<()> {
        let hash = self.hash()?;
        let secret = self.local_hs_secret.as_ref().ok_or(unexpected())?;
        let mac = key_schedule::finished_mac(self.hash_alg()?, secret.as_bytes(), hash.as_bytes())?;
        self.send_message(20, |w| w.put(mac.as_bytes()))
    }
    fn install_server_application(&mut self) -> Result<()> {
        let hash = self.hash()?;
        let master = self.master.as_ref().ok_or(unexpected())?;
        let client = master.client_traffic(hash.as_bytes())?;
        let server = master.server_traffic(hash.as_bytes())?;
        self.exporter = Some(master.exporter(hash.as_bytes())?);
        self.client_app = Some(client);
        let protector = Protector::new(self.suite.ok_or(unexpected())?, &server)?;
        if self.is_client() {
            self.read_epoch = self.read_epoch.wrapping_add(1);
            self.read = Some(protector);
        } else {
            self.write = Some(protector);
        }
        Ok(())
    }
    fn on_finished(&mut self, body: &[u8], message: &[u8]) -> Result<()> {
        let hash = self.hash()?;
        key_schedule::verify_finished(
            self.hash_alg()?,
            self.peer_hs_secret.as_ref().ok_or(unexpected())?.as_bytes(),
            hash.as_bytes(),
            body,
        )?;
        self.add(message);
        if self.is_client() {
            if !self.peer_authenticated {
                return Err(Error::new(
                    ErrorKind::CertificateRequired,
                    "server did not authenticate",
                ));
            }
            self.install_server_application()?;
            let config = match self.config {
                Config::Client(c, _) => c,
                _ => return Err(unexpected()),
            };
            if self.request_client {
                self.send_certificate(config.identity.as_ref())?;
                if let Some(identity) = &config.identity {
                    let scheme = self
                        .common()
                        .schemes
                        .iter()
                        .copied()
                        .find(|s| {
                            identity.key.schemes().contains(s)
                                && s.allowed_in_handshake()
                                && self.request_schemes[..self.request_scheme_len]
                                    .contains(&Some(*s))
                        })
                        .ok_or(Error::new(
                            ErrorKind::HandshakeFailure,
                            "no client authentication signing scheme",
                        ))?;
                    self.send_certificate_verify(identity, scheme)?;
                }
            }
            self.send_finished()?;
            self.write = Some(Protector::new(
                self.suite.ok_or(unexpected())?,
                self.client_app.as_ref().ok_or(unexpected())?,
            )?);
        } else {
            self.read_epoch = self.read_epoch.wrapping_add(1);
            self.read = Some(Protector::new(
                self.suite.ok_or(unexpected())?,
                self.client_app.as_ref().ok_or(unexpected())?,
            )?);
        }
        self.complete()
    }
    fn complete(&mut self) -> Result<()> {
        let common = self.common();
        if common.profile.requires_mutual_auth()
            && (!self.request_client
                || !self.peer_authenticated
                || (self.is_client()
                    && !matches!(self.config, Config::Client(c, _) if c.identity.is_some())))
        {
            return Err(Error::new(
                ErrorKind::PolicyViolation,
                "profile requires mutual authentication",
            ));
        }
        if common.fips {
            let (aead, hash) =
                record::suite_params(self.suite.ok_or(unexpected())?).ok_or(unexpected())?;
            for id in [
                aead.ic_id(),
                hash.ic_hash_id(),
                hash.ic_hmac_id(),
                hash.ic_hkdf_id(),
            ]
            .into_iter()
            .chain(kx::ic_ids(self.group).iter().copied())
            .chain(self.report.peer_signature_scheme.and_then(sign::ic_id))
            {
                ic_fips::check(id).map_err(|_| {
                    Error::new(
                        ErrorKind::FipsModule,
                        "negotiated fixed engine service not approved",
                    )
                })?;
            }
        }
        self.report.properties =
            property_bit(Property::Confidentiality) | property_bit(Property::ForwardSecrecy);
        if kx::is_post_quantum(self.group) {
            self.report.properties |= property_bit(Property::PostQuantumKeyExchange);
        }
        if self.peer_authenticated && self.pq_chain {
            self.report.properties |= property_bit(Property::PostQuantumAuthentication);
        }
        self.report.properties |= property_bit(Property::ServerAuthenticated);
        if self.revocation_checked {
            self.report.properties |= property_bit(Property::RevocationChecked);
        }
        if self.request_client
            && self.peer_authenticated
            && (!self.is_client()
                || matches!(self.config, Config::Client(c, _) if c.identity.is_some()))
        {
            self.report.properties |= property_bit(Property::MutualAuthentication);
        }
        if self.peer_pinned {
            self.report.properties |= property_bit(Property::PinnedPeer);
        }
        if common.fips {
            self.report.properties |= property_bit(Property::FipsApprovedAlgorithms);
        }
        // REQ-CONN-013: before the connection may carry application data.
        if let Some(missing) = common
            .required_properties
            .iter()
            .find(|p| self.report.properties & property_bit(**p) == 0)
        {
            return Err(Error::new(ErrorKind::PolicyViolation, missing.id()));
        }
        self.peer_hs_secret = None;
        self.local_hs_secret = None;
        self.master = None;
        self.client_app = None;
        self.storage.private_key.zeroize();
        self.transition(State::Connected)
    }
}

struct Writer<'a> {
    bytes: &'a mut [u8],
    len: usize,
}
impl<'a> Writer<'a> {
    fn new(bytes: &'a mut [u8]) -> Self {
        Self { bytes, len: 0 }
    }
    fn put(&mut self, bytes: &[u8]) -> Result<()> {
        let end = self
            .len
            .checked_add(bytes.len())
            .ok_or(capacity("encoding workspace"))?;
        self.bytes
            .get_mut(self.len..end)
            .ok_or(capacity("encoding workspace"))?
            .copy_from_slice(bytes);
        self.len = end;
        Ok(())
    }
    fn u8(&mut self, n: u8) -> Result<()> {
        self.put(&[n])
    }
    fn u16(&mut self, n: u16) -> Result<()> {
        self.put(&n.to_be_bytes())
    }
    fn reserve(&mut self, n: usize) -> Result<usize> {
        let at = self.len;
        for _ in 0..n {
            self.u8(0)?;
        }
        Ok(at)
    }
    fn length(&mut self, at: usize, size: usize) -> Result<()> {
        let n = self.len - at - size;
        if n >= (1usize << (8 * size)) {
            return Err(capacity("wire length prefix"));
        }
        for i in 0..size {
            self.bytes[at + i] = (n >> (8 * (size - i - 1))) as u8;
        }
        Ok(())
    }
    fn vector(&mut self, size: usize, bytes: &[u8]) -> Result<()> {
        let at = self.reserve(size)?;
        self.put(bytes)?;
        self.length(at, size)
    }
    fn nested(&mut self, size: usize, encode: impl FnOnce(&mut Self) -> Result<()>) -> Result<()> {
        let at = self.reserve(size)?;
        encode(self)?;
        self.length(at, size)
    }
    fn ext(&mut self, ty: u16, encode: impl FnOnce(&mut Self) -> Result<()>) -> Result<()> {
        self.u16(ty)?;
        self.nested(2, encode)
    }
    fn written(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

#[derive(Clone, Copy)]
struct Extensions<'a> {
    bytes: &'a [u8],
}
impl<'a> Extensions<'a> {
    fn parse(reader: &mut Reader<'a>, context: ExtensionContext, limit: usize) -> Result<Self> {
        let bytes = reader.vec16()?;
        let mut r = Reader::new(bytes);
        let mut count = 0;
        while !r.is_empty() {
            let consumed = bytes.len() - r.remaining();
            let ty = r.u16()?;
            r.vec16()?;
            count += 1;
            if count > limit {
                return Err(capacity("extension slots"));
            }
            if !extension_allowed(ExtensionType::from_wire(ty), context) {
                return Err(invalid("extension forbidden in message"));
            }
            let mut prev = Reader::new(&bytes[..consumed]);
            while !prev.is_empty() {
                let old = prev.u16()?;
                prev.vec16()?;
                if old == ty {
                    return Err(invalid("duplicate extension"));
                }
            }
        }
        Ok(Self { bytes })
    }
    fn get(self, ty: u16) -> Result<Option<&'a [u8]>> {
        let mut r = Reader::new(self.bytes);
        while !r.is_empty() {
            let found = r.u16()?;
            let body = r.vec16()?;
            if found == ty {
                return Ok(Some(body));
            }
        }
        Ok(None)
    }
    fn required(self, ty: u16) -> Result<&'a [u8]> {
        self.get(ty)?.ok_or(Error::new(
            ErrorKind::MissingExtension,
            "required handshake extension",
        ))
    }
}
fn u16_list(bytes: &[u8], prefix: usize) -> Result<&[u8]> {
    let mut r = Reader::new(bytes);
    let list = if prefix == 1 { r.vec8()? } else { r.vec16()? };
    r.finish()?;
    if list.is_empty() || list.len() % 2 != 0 {
        return Err(invalid("empty or odd u16 list"));
    }
    Ok(list)
}
fn contains_u16(bytes: &[u8], n: u16) -> bool {
    bytes.as_chunks::<2>().0.contains(&n.to_be_bytes())
}
fn hello_fingerprint(body: &[u8], ext: Extensions<'_>) -> Result<Output> {
    let mut h = Hash::new(HashAlg::Sha256);
    h.update(&body[..body.len() - ext.bytes.len() - 2]);
    let mut r = Reader::new(ext.bytes);
    while !r.is_empty() {
        let ty = r.u16()?;
        let bytes = r.vec16()?;
        if !matches!(ty, 51 | 44 | 21) {
            h.update(&ty.to_be_bytes());
            h.update(&(bytes.len() as u16).to_be_bytes());
            h.update(bytes);
        }
    }
    Ok(h.finish())
}
fn cv_input(server: bool, hash: &[u8], out: &mut [u8; 146]) -> usize {
    let context = if server {
        b"TLS 1.3, server CertificateVerify"
    } else {
        b"TLS 1.3, client CertificateVerify"
    };
    out[..64].fill(32);
    out[64..97].copy_from_slice(context);
    out[97] = 0;
    out[98..98 + hash.len()].copy_from_slice(hash);
    98 + hash.len()
}

/// The Finished check cannot be reached by mutating flights: a changed
/// ClientHello changes the keys, and a changed encrypted flight fails AEAD
/// first. So the server's Finished handler is given a wrong verify_data
/// directly, at the point a real handshake reaches it.
#[cfg(all(test, feature = "std"))]
mod finished_tests {
    use super::*;
    use crate::config::Profile;
    use crate::crypto::sign::{KeyKind, SigningKey};
    use crate::x509::{CertificateParams, RootStore};
    use alloc::vec;
    use alloc::vec::Vec;

    fn pair() -> (ClientConfig, ServerConfig) {
        let mut rng = ic_drbg::Rng::from_os().unwrap();
        let key = SigningKey::generate(KeyKind::EcdsaP256, &mut rng).unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let cert = x509::self_signed(
            &CertificateParams {
                subject_cn: "server.test",
                dns_names: &["server.test"],
                ip_addresses: &[],
                not_before: now - 3600,
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
        let mut cc = ClientConfig::new(Profile::Default, roots).unwrap();
        cc.tickets = None;
        let identity = Identity::new(vec![cert], key).unwrap();
        let mut sc = ServerConfig::new(Profile::Default, identity).unwrap();
        sc.tickets = None;
        (cc, sc)
    }

    fn buffers() -> [Vec<u8>; 8] {
        [16645, 32768, 65536, 32768, 32768, 3234, 1665, 32768].map(|n| vec![0u8; n])
    }

    fn storage(b: &mut [Vec<u8>; 8]) -> Storage<'_> {
        let [record, handshake, outgoing, application, certificates, private_key, public_key, scratch] =
            b;
        Storage {
            record,
            handshake,
            outgoing,
            application,
            certificates,
            private_key,
            public_key,
            scratch,
        }
    }

    fn flush(from: &mut Connection<'_>, to: &mut Connection<'_>) {
        let n = from.outgoing().len();
        to.receive(from.outgoing()).unwrap();
        from.consume_outgoing(n).unwrap();
    }

    /// REQ-ECH-011: an encrypted_client_hello in EncryptedExtensions is
    /// ignored by a client that sent GREASE, and refused by one that sent no
    /// ECH extension at all.
    #[test]
    fn encrypted_extensions_with_ech_follow_grease() {
        let (cc, sc) = pair();
        for grease in [true, false] {
            let mut cc = cc.clone();
            cc.ech_grease = grease;
            let (mut cb, mut sb) = (buffers(), buffers());
            let (mut cr, mut sr) = (
                ic_drbg::Rng::from_os().unwrap(),
                ic_drbg::Rng::from_os().unwrap(),
            );
            let mut c = Connection::client(
                &cc,
                "server.test",
                &mut cr,
                storage(&mut cb),
                Limits::default(),
            )
            .unwrap();
            let mut s =
                Connection::server(&sc, &mut sr, storage(&mut sb), Limits::default()).unwrap();
            flush(&mut c, &mut s);
            // Only the ServerHello record.
            let out = s.outgoing();
            let len = usize::from(u16::from_be_bytes([out[3], out[4]]));
            c.receive(&out[..5 + len]).unwrap();
            assert_eq!(c.report().state, State::WaitEncryptedExtensions);
            let ext = [0xfe, 0x0d, 0, 2, 0, 0];
            let mut message = vec![8, 0, 0, 8, 0, 6];
            message.extend_from_slice(&ext);
            let r = c.on_encrypted_extensions(&message[4..], &message);
            if grease {
                r.unwrap();
            } else {
                assert_eq!(r.unwrap_err().kind(), ErrorKind::UnsupportedExtension);
            }
        }
    }

    /// REQ-FIX-004: a client Finished whose verify_data does not match the
    /// transcript is refused with decrypt_error, and the genuine one is
    /// accepted at the same point.
    #[test]
    fn a_wrong_client_finished_is_refused() {
        let (cc, sc) = pair();
        for wrong in [false, true] {
            let (mut cb, mut sb) = (buffers(), buffers());
            let (mut cr, mut sr) = (
                ic_drbg::Rng::from_os().unwrap(),
                ic_drbg::Rng::from_os().unwrap(),
            );
            let mut c = Connection::client(
                &cc,
                "server.test",
                &mut cr,
                storage(&mut cb),
                Limits::default(),
            )
            .unwrap();
            let mut s =
                Connection::server(&sc, &mut sr, storage(&mut sb), Limits::default()).unwrap();
            flush(&mut c, &mut s);
            flush(&mut s, &mut c);
            assert!(c.is_connected());
            assert_eq!(s.report().state, State::WaitFinished);
            if wrong {
                let len = s.hash_alg().unwrap().len();
                let mut message = vec![20, 0, 0, len as u8];
                message.resize(4 + len, 0x5a);
                let error = s.on_finished(&message[4..], &message).unwrap_err();
                assert_eq!(error.kind(), ErrorKind::DecryptError);
                assert!(!s.is_connected());
            } else {
                flush(&mut c, &mut s);
                assert!(s.is_connected());
            }
        }
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    //! Peer misbehaviour inside protected flights. A real fixed client and
    //! server run the handshake; a test then seals hand-made messages with the
    //! sending peer's own traffic secret, so the receiver sees exactly what a
    //! broken or hostile peer holding those keys would send.
    use super::*;
    use crate::crypto::sign::{KeyKind, SigningKey};
    use crate::x509::{CertificateParams, RootStore};

    const NAME: &str = "server.test";

    fn rng() -> ic_drbg::Rng {
        ic_drbg::Rng::from_os().unwrap()
    }

    fn now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    struct Pki {
        ca: Vec<u8>,
        cc: ClientConfig,
        sc: ServerConfig,
    }

    fn params<'a>(
        cn: &'a str,
        dns: &'a [&'a str],
        usage: &'a [Usage],
        serial: u8,
    ) -> CertificateParams<'a> {
        let t = now();
        CertificateParams {
            subject_cn: cn,
            dns_names: dns,
            ip_addresses: &[],
            not_before: t - 3600,
            not_after: t + 86_400,
            is_ca: usage.is_empty(),
            path_len: if usage.is_empty() { Some(1) } else { None },
            usage,
            serial: [serial; 16],
        }
    }

    /// A CA, a server identity for NAME and a client identity, all P-256,
    /// with X25519 key exchange and no tickets.
    fn pki() -> Pki {
        let mut r = rng();
        let ca_key = SigningKey::generate(KeyKind::EcdsaP256, &mut r).unwrap();
        let ca =
            x509::self_signed(&params("Fixed Test Root", &[], &[], 1), &ca_key, &mut r).unwrap();
        let server_key = SigningKey::generate(KeyKind::EcdsaP256, &mut r).unwrap();
        let server = x509::issue(
            &params(NAME, &[NAME], &[Usage::ServerAuth], 2),
            server_key.spki(),
            &ca,
            &ca_key,
            &mut r,
        )
        .unwrap();
        let client_key = SigningKey::generate(KeyKind::EcdsaP256, &mut r).unwrap();
        let client = x509::issue(
            &params("device", &[], &[Usage::ClientAuth], 3),
            client_key.spki(),
            &ca,
            &ca_key,
            &mut r,
        )
        .unwrap();
        let mut roots = RootStore::new();
        roots.add_der(&ca).unwrap();
        let mut cc = ClientConfig::new(crate::config::Profile::Default, roots).unwrap();
        cc.tickets = None;
        cc.common.groups = vec![NamedGroup::X25519];
        cc.identity = Some(Identity::new(vec![client], client_key).unwrap());
        let mut sc = ServerConfig::new(
            crate::config::Profile::Default,
            Identity::new(vec![server], server_key).unwrap(),
        )
        .unwrap();
        sc.tickets = None;
        sc.common.groups = vec![NamedGroup::X25519];
        Pki { ca, cc, sc }
    }

    struct Buffers([Vec<u8>; 8]);
    impl Buffers {
        fn new() -> Self {
            Self([16645, 32768, 65536, 32768, 32768, 3234, 1665, 32768].map(|n| vec![0; n]))
        }
        fn storage(&mut self) -> Storage<'_> {
            let [record, handshake, outgoing, application, certificates, private_key, public_key, scratch] =
                &mut self.0;
            Storage {
                record,
                handshake,
                outgoing,
                application,
                certificates,
                private_key,
                public_key,
                scratch,
            }
        }
    }

    fn take(conn: &mut Connection<'_>) -> Vec<u8> {
        let bytes = conn.outgoing().to_vec();
        conn.consume_outgoing(bytes.len()).unwrap();
        bytes
    }

    /// Split a flight into records.
    fn records(mut bytes: &[u8]) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        while !bytes.is_empty() {
            let n = 5 + usize::from(u16::from_be_bytes([bytes[3], bytes[4]]));
            out.push(bytes[..n].to_vec());
            bytes = &bytes[n..];
        }
        out
    }

    /// One protected record carrying `content` of type `ty`.
    fn seal(key: &mut Protector, ty: ContentType, content: &[u8]) -> Vec<u8> {
        let mut out = vec![0; content.len() + 5 + 1 + crypto::TAG_LEN];
        let n = key.seal_into(ty, content, 0, &mut out).unwrap();
        out.truncate(n);
        out
    }

    /// Decrypt protected handshake records and split them into messages.
    fn messages(key: &mut Protector, recs: &[Vec<u8>]) -> Vec<Vec<u8>> {
        let mut plain = Vec::new();
        for rec in recs {
            let mut rec = rec.clone();
            let header: [u8; 5] = rec[..5].try_into().unwrap();
            let (ty, n) = key.open(&header, &mut rec[5..]).unwrap();
            assert_eq!(ty, ContentType::Handshake);
            plain.extend_from_slice(&rec[5..5 + n]);
        }
        let mut out = Vec::new();
        let mut at = 0;
        while at < plain.len() {
            let n = 4
                + ((usize::from(plain[at + 1]) << 16)
                    | (usize::from(plain[at + 2]) << 8)
                    | usize::from(plain[at + 3]));
            out.push(plain[at..at + n].to_vec());
            at += n;
        }
        out
    }

    fn msg(ty: u8, body: &[u8]) -> Vec<u8> {
        let n = body.len() as u32;
        [&[ty][..], &n.to_be_bytes()[1..], body].concat()
    }
    fn v8(b: &[u8]) -> Vec<u8> {
        [&[b.len() as u8][..], b].concat()
    }
    fn v16(b: &[u8]) -> Vec<u8> {
        [&(b.len() as u16).to_be_bytes()[..], b].concat()
    }
    fn v24(b: &[u8]) -> Vec<u8> {
        [&(b.len() as u32).to_be_bytes()[1..], b].concat()
    }
    fn ext(ty: u16, body: &[u8]) -> Vec<u8> {
        [&ty.to_be_bytes()[..], &v16(body)].concat()
    }

    /// The client has processed only the server's real ServerHello. `f` gets
    /// the client, the server's remaining messages (EncryptedExtensions,
    /// Certificate, CertificateVerify, Finished) and a key sealing as the
    /// server at the client's next handshake sequence number.
    fn after_server_hello<R>(
        cc: &ClientConfig,
        sc: &ServerConfig,
        f: impl FnOnce(&mut Connection<'_>, Vec<Vec<u8>>, Protector) -> R,
    ) -> R {
        let (mut cb, mut sb) = (Buffers::new(), Buffers::new());
        let (mut cr, mut sr) = (rng(), rng());
        let mut c = Connection::client(cc, NAME, &mut cr, cb.storage(), Limits::default()).unwrap();
        let mut s = Connection::server(sc, &mut sr, sb.storage(), Limits::default()).unwrap();
        s.receive(&take(&mut c)).unwrap();
        let recs = records(&take(&mut s));
        c.receive(&recs[0]).unwrap();
        assert_eq!(c.report.state, State::WaitEncryptedExtensions);
        let suite = s.suite.unwrap();
        let secret = s.local_hs_secret.clone().unwrap();
        let msgs = messages(&mut Protector::new(suite, &secret).unwrap(), &recs[1..]);
        assert_eq!(
            msgs.iter().map(|m| m[0]).collect::<Vec<_>>(),
            [8, 11, 15, 20]
        );
        f(&mut c, msgs, Protector::new(suite, &secret).unwrap())
    }

    /// The server has sent its flight and waits for the client's; `f` gets
    /// the server and a key sealing as the client.
    fn server_awaiting_client<R>(
        cc: &ClientConfig,
        sc: &ServerConfig,
        f: impl FnOnce(&mut Connection<'_>, Protector) -> R,
    ) -> R {
        let (mut cb, mut sb) = (Buffers::new(), Buffers::new());
        let (mut cr, mut sr) = (rng(), rng());
        let mut c = Connection::client(cc, NAME, &mut cr, cb.storage(), Limits::default()).unwrap();
        let mut s = Connection::server(sc, &mut sr, sb.storage(), Limits::default()).unwrap();
        s.receive(&take(&mut c)).unwrap();
        let recs = records(&take(&mut s));
        c.receive(&recs[0]).unwrap();
        let key = Protector::new(s.suite.unwrap(), c.local_hs_secret.as_ref().unwrap()).unwrap();
        f(&mut s, key)
    }

    /// A completed handshake; `f` gets both sides.
    fn connected<R>(
        cc: &ClientConfig,
        sc: &ServerConfig,
        f: impl FnOnce(&mut Connection<'_>, &mut Connection<'_>) -> R,
    ) -> R {
        let (mut cb, mut sb) = (Buffers::new(), Buffers::new());
        let (mut cr, mut sr) = (rng(), rng());
        let mut c = Connection::client(cc, NAME, &mut cr, cb.storage(), Limits::default()).unwrap();
        let mut s = Connection::server(sc, &mut sr, sb.storage(), Limits::default()).unwrap();
        for _ in 0..4 {
            s.receive(&take(&mut c)).unwrap();
            c.receive(&take(&mut s)).unwrap();
        }
        assert!(c.is_connected() && s.is_connected());
        f(&mut c, &mut s)
    }

    /// Seal as the connected server, with its current write key.
    fn from_server(s: &mut Connection<'_>, ty: ContentType, content: &[u8]) -> Vec<u8> {
        seal(s.write.as_mut().unwrap(), ty, content)
    }

    /// The failure is latched: the same error again, everything erased.
    fn assert_latched(conn: &mut Connection<'_>, error: Error) {
        assert_eq!(conn.report.error, Some(error));
        assert_eq!(conn.receive(&[22]).unwrap_err(), error);
        assert_eq!(conn.report.state, State::Failed);
        assert!(conn.outgoing().is_empty() && conn.read.is_none() && conn.write.is_none());
    }

    fn refused(conn: &mut Connection<'_>, input: &[u8], kind: ErrorKind, context: &str) {
        let e = conn.receive(input).unwrap_err();
        assert_eq!(e.kind(), kind, "{e}");
        assert_eq!(e.context(), context);
        assert_latched(conn, e);
    }

    /// REQ-FIX-005: application data protected under handshake keys, before
    /// the handshake completes, is UnexpectedMessage.
    #[test]
    fn application_data_before_the_handshake_completes_is_unexpected() {
        let p = pki();
        after_server_hello(&p.cc, &p.sc, |c, _, mut key| {
            let rec = seal(&mut key, ContentType::ApplicationData, b"too early");
            refused(
                c,
                &rec,
                ErrorKind::UnexpectedMessage,
                "fixed handshake state",
            );
        });
    }

    /// REQ-FIX-005: application data arriving between the fragments of a
    /// handshake message is UnexpectedMessage (RFC 8446 section 5.1).
    #[test]
    fn application_data_inside_a_fragmented_handshake_message_is_unexpected() {
        let p = pki();
        connected(&p.cc, &p.sc, |c, s| {
            let first = from_server(s, ContentType::Handshake, &[24, 0]);
            c.receive(&first).unwrap();
            let data = from_server(s, ContentType::ApplicationData, b"interleaved");
            refused(
                c,
                &data,
                ErrorKind::UnexpectedMessage,
                "fixed handshake state",
            );
        });
    }

    /// REQ-FIX-005: handshake bytes after the peer's Finished in the same
    /// record, which would be protected under the wrong key, are
    /// UnexpectedMessage (RFC 8446 section 5.1).
    #[test]
    fn handshake_bytes_after_finished_in_one_record_are_unexpected() {
        let p = pki();
        after_server_hello(&p.cc, &p.sc, |c, msgs, mut key| {
            let mut flight = msgs.concat();
            flight.extend_from_slice(&[24, 0, 0, 1, 0]);
            let rec = seal(&mut key, ContentType::Handshake, &flight);
            refused(
                c,
                &rec,
                ErrorKind::UnexpectedMessage,
                "fixed handshake state",
            );
        });
        // The same flight without the trailing message completes.
        after_server_hello(&p.cc, &p.sc, |c, msgs, mut key| {
            let rec = seal(&mut key, ContentType::Handshake, &msgs.concat());
            c.receive(&rec).unwrap();
            assert!(c.is_connected());
        });
    }

    /// REQ-FIX-005: once record_size_limit is negotiated, a protected record
    /// whose inner plaintext exceeds this endpoint's limit is RecordOverflow
    /// (RFC 8449, REQ-RSL-002).
    #[test]
    fn a_record_over_the_negotiated_limit_is_overflow() {
        let mut p = pki();
        p.cc.common.record_size_limit = Some(64);
        p.sc.common.record_size_limit = Some(64);
        connected(&p.cc, &p.sc, |c, s| {
            let fits = from_server(s, ContentType::ApplicationData, &[1; 63]);
            c.receive(&fits).unwrap();
            let over = from_server(s, ContentType::ApplicationData, &[1; 64]);
            refused(
                c,
                &over,
                ErrorKind::RecordOverflow,
                "local record_size_limit",
            );
        });
    }

    /// REQ-FIX-005: a KeyUpdate whose body is not exactly one byte of value
    /// 0 or 1 is IllegalParameter (RFC 8446 section 4.6.3).
    #[test]
    fn malformed_key_update_is_illegal_parameter() {
        let p = pki();
        for body in [&[24, 0, 0, 2, 0, 0][..], &[24, 0, 0, 1, 2][..]] {
            connected(&p.cc, &p.sc, |c, s| {
                let rec = from_server(s, ContentType::Handshake, body);
                refused(c, &rec, ErrorKind::IllegalParameter, "KeyUpdate request");
            });
        }
    }

    fn ticket(lifetime: u32, ticket: &[u8]) -> Vec<u8> {
        let body = [
            &lifetime.to_be_bytes()[..],
            &[0, 0, 0, 7],
            &v8(&[1]),
            &v16(ticket),
            &v16(&[]),
        ]
        .concat();
        msg(4, &body)
    }

    /// REQ-FIX-005: a client without tickets checks an unsolicited
    /// NewSessionTicket's framing before discarding it: a lifetime over seven
    /// days or an empty ticket is IllegalParameter (RFC 8446 section 4.6.1);
    /// a well-formed one is ignored and the connection stays usable.
    #[test]
    fn unsolicited_session_tickets_are_validated_then_discarded() {
        let p = pki();
        connected(&p.cc, &p.sc, |c, s| {
            let rec = from_server(s, ContentType::Handshake, &ticket(604_800, b"ticket"));
            c.receive(&rec).unwrap();
            let data = from_server(s, ContentType::ApplicationData, b"still here");
            c.receive(&data).unwrap();
            assert!(c.is_connected());
            let mut out = [0; 16];
            assert_eq!(c.read_application(&mut out).unwrap(), 10);
        });
        for (lifetime, t) in [(604_801, &b"ticket"[..]), (3600, &b""[..])] {
            connected(&p.cc, &p.sc, |c, s| {
                let rec = from_server(s, ContentType::Handshake, &ticket(lifetime, t));
                refused(
                    c,
                    &rec,
                    ErrorKind::IllegalParameter,
                    "session ticket framing",
                );
            });
        }
    }

    fn encrypted_extensions(exts: &[Vec<u8>]) -> Vec<u8> {
        msg(8, &v16(&exts.concat()))
    }

    /// REQ-FIX-005: EncryptedExtensions may acknowledge server_name only
    /// with an empty body and only when the client sent it, and may carry
    /// record_size_limit only when the client offered it (RFC 8446 section
    /// 4.2, RFC 6066 section 3, RFC 8449).
    #[test]
    fn unrequested_or_malformed_encrypted_extensions_are_refused() {
        let p = pki();
        let mut no_sni = p.cc.clone();
        no_sni.send_sni = false;
        for (cc, exts, kind, context) in [
            (
                &no_sni,
                vec![ext(0, &[])],
                ErrorKind::IllegalParameter,
                "SNI acknowledgement",
            ),
            (
                &p.cc,
                vec![ext(0, &[0, 0])],
                ErrorKind::IllegalParameter,
                "SNI acknowledgement",
            ),
            (
                &p.cc,
                vec![ext(28, &[0, 64])],
                ErrorKind::UnsupportedExtension,
                "unsolicited EncryptedExtensions extension",
            ),
        ] {
            after_server_hello(cc, &p.sc, |c, _, mut key| {
                let ee = encrypted_extensions(&exts);
                let rec = seal(&mut key, ContentType::Handshake, &ee);
                refused(c, &rec, kind, context);
            });
        }
        // The client that sent SNI accepts the empty acknowledgement.
        after_server_hello(&p.cc, &p.sc, |c, _, mut key| {
            let ee = encrypted_extensions(&[ext(0, &[])]);
            c.receive(&seal(&mut key, ContentType::Handshake, &ee))
                .unwrap();
            assert_eq!(c.report.state, State::WaitCertificateRequest);
        });
    }

    /// REQ-FIX-005: a CertificateRequest with a non-empty context during the
    /// handshake is IllegalParameter (RFC 8446 section 4.3.2), and one with
    /// more signature schemes than the 32 slots is CapacityExceeded.
    #[test]
    fn malformed_certificate_requests_are_refused() {
        let p = pki();
        let schemes = |n: usize| ext(13, &v16(&[4, 3].repeat(n)));
        for (request, kind, context) in [
            (
                msg(13, &[v8(&[1]), v16(&schemes(1))].concat()),
                ErrorKind::IllegalParameter,
                "handshake CertificateRequest context",
            ),
            (
                msg(13, &[v8(&[]), v16(&schemes(33))].concat()),
                ErrorKind::CapacityExceeded,
                "CertificateRequest signature slots",
            ),
        ] {
            after_server_hello(&p.cc, &p.sc, |c, msgs, mut key| {
                c.receive(&seal(&mut key, ContentType::Handshake, &msgs[0]))
                    .unwrap();
                let rec = seal(&mut key, ContentType::Handshake, &request);
                refused(c, &rec, kind, context);
            });
        }
        // 32 schemes fit.
        after_server_hello(&p.cc, &p.sc, |c, msgs, mut key| {
            c.receive(&seal(&mut key, ContentType::Handshake, &msgs[0]))
                .unwrap();
            let request = msg(13, &[v8(&[]), v16(&schemes(32))].concat());
            c.receive(&seal(&mut key, ContentType::Handshake, &request))
                .unwrap();
            assert_eq!(c.report.state, State::WaitCertificate);
        });
    }

    fn certificate(context: &[u8], entries: &[(&[u8], Vec<u8>)]) -> Vec<u8> {
        let list: Vec<u8> = entries
            .iter()
            .flat_map(|(der, exts)| [v24(der), v16(exts)].concat())
            .collect();
        msg(11, &[v8(context), v24(&list)].concat())
    }

    fn status(ty: u8) -> Vec<u8> {
        ext(5, &[&[ty][..], &v24(b"not an OCSP response")].concat())
    }

    /// REQ-FIX-005: the client refuses a server Certificate with a request
    /// context, an empty entry, or entry extensions it did not request: SCT,
    /// a status when revocation checking is off, a status on any but the end
    /// entity, or a status of a type other than OCSP (RFC 8446 section 4.4.2,
    /// RFC 6066 section 8).
    #[test]
    fn malformed_server_certificates_are_refused() {
        let p = pki();
        let leaf = p.sc.identities[0].chain[0].clone();
        let mut off = p.cc.clone();
        off.revocation = crate::config::Revocation::Off;
        let unsupported = (
            ErrorKind::UnsupportedExtension,
            "certificate entry extension not requested",
        );
        let cases: [(&ClientConfig, Vec<u8>, (ErrorKind, &str)); 6] = [
            (
                &p.cc,
                certificate(&[1], &[(&leaf, vec![])]),
                (ErrorKind::IllegalParameter, "Certificate context"),
            ),
            (
                &p.cc,
                certificate(&[], &[(&[], vec![])]),
                (ErrorKind::IllegalParameter, "empty certificate entry"),
            ),
            (
                &p.cc,
                certificate(&[], &[(&leaf, ext(18, &[0, 0]))]),
                unsupported,
            ),
            (&off, certificate(&[], &[(&leaf, status(1))]), unsupported),
            (
                &p.cc,
                certificate(&[], &[(&leaf, vec![]), (&p.ca, status(1))]),
                unsupported,
            ),
            (
                &p.cc,
                certificate(&[], &[(&leaf, status(2))]),
                (ErrorKind::IllegalParameter, "certificate status type"),
            ),
        ];
        for (cc, cert, (kind, context)) in cases {
            after_server_hello(cc, &p.sc, |c, msgs, mut key| {
                c.receive(&seal(&mut key, ContentType::Handshake, &msgs[0]))
                    .unwrap();
                let rec = seal(&mut key, ContentType::Handshake, &cert);
                refused(c, &rec, kind, context);
            });
        }
    }

    /// REQ-FIX-005: a server never requests certificate status from its
    /// client, so a client Certificate entry carrying one is
    /// UnsupportedExtension.
    #[test]
    fn client_certificate_entry_extensions_are_refused() {
        let mut p = pki();
        let mut roots = RootStore::new();
        roots.add_der(&p.ca).unwrap();
        p.sc.client_auth = ClientAuth::Required(PeerVerification::Roots(roots));
        let leaf = p.cc.identity.as_ref().unwrap().chain[0].clone();
        server_awaiting_client(&p.cc, &p.sc, |s, mut key| {
            assert_eq!(s.report.state, State::WaitCertificate);
            let cert = certificate(&[], &[(&leaf, status(1))]);
            let rec = seal(&mut key, ContentType::Handshake, &cert);
            refused(
                s,
                &rec,
                ErrorKind::UnsupportedExtension,
                "certificate entry extension not requested",
            );
        });
    }

    /// REQ-FIX-005: a CertificateVerify with a scheme that may not sign a
    /// TLS 1.3 handshake (RSASSA-PKCS1-v1_5), or one the client did not
    /// offer, is IllegalParameter before any signature check (RFC 8446
    /// section 4.4.3).
    #[test]
    fn certificate_verify_with_an_unoffered_scheme_is_refused() {
        let p = pki();
        let mut no_ed25519 = p.cc.clone();
        no_ed25519
            .common
            .schemes
            .retain(|s| *s != SignatureScheme::Ed25519);
        for (cc, scheme) in [
            (&p.cc, SignatureScheme::RsaPkcs1Sha256),
            (&no_ed25519, SignatureScheme::Ed25519),
        ] {
            // Offered but not for handshakes, or allowed but not offered.
            assert_ne!(
                cc.common.schemes.contains(&scheme),
                scheme.allowed_in_handshake()
            );
            after_server_hello(cc, &p.sc, |c, msgs, mut key| {
                for m in &msgs[..2] {
                    c.receive(&seal(&mut key, ContentType::Handshake, m))
                        .unwrap();
                }
                assert_eq!(c.report.state, State::WaitCertificateVerify);
                let cv = msg(
                    15,
                    &[&scheme.to_wire().to_be_bytes()[..], &v16(&[0x30; 64])].concat(),
                );
                let rec = seal(&mut key, ContentType::Handshake, &cv);
                refused(
                    c,
                    &rec,
                    ErrorKind::IllegalParameter,
                    "unoffered CertificateVerify scheme",
                );
            });
        }
    }
}
