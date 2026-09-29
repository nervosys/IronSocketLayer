//! Handshake messages (RFC 8446 §4) and their wire encodings.
//!
//! Decoders validate the structural rules RFC 8446 states as MUSTs at parse
//! time — duplicate extensions, `pre_shared_key` not last, a non-null
//! compression method — so the state machines only ever see well-formed
//! messages. Semantic checks that depend on what was offered (was this group
//! in our key_share? was ALPN requested?) belong to the state machines.
//!
//! Requirement trace: `REQ-MSG-001` (duplicate extensions rejected),
//! `REQ-MSG-002` (`pre_shared_key` must be last),
//! `REQ-MSG-003` (legacy compression must be null),
//! `REQ-MSG-004` (every length is bounds-checked; see `codec`).

use alloc::string::String;
use alloc::vec::Vec;

use crate::codec::{nested, put_u16, put_u24, put_u32, put_u8, put_vec, Prefix, Reader};
use crate::enums::{
    CipherSuite, ExtensionType, HandshakeType, KeyUpdateRequest, NamedGroup, ProtocolVersion,
    SignatureScheme,
};
use crate::error::{Error, ErrorKind, Result};

/// `ServerHello.random` that marks a HelloRetryRequest: SHA-256 of
/// `"HelloRetryRequest"` (RFC 8446 §4.1.3). A test recomputes it.
pub const HRR_RANDOM: [u8; 32] = [
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
];

/// Frame a handshake message: `HandshakeType ‖ uint24 length ‖ body`.
pub fn frame(ty: HandshakeType, body: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(4 + body.len());
    put_u8(&mut out, ty.to_wire());
    put_u24(&mut out, body.len() as u32)?;
    out.extend_from_slice(body);
    Ok(out)
}

fn decode_err(ctx: &'static str) -> Error {
    Error::new(ErrorKind::Decode, ctx)
}

fn illegal(ctx: &'static str) -> Error {
    Error::new(ErrorKind::IllegalParameter, ctx)
}

/// Parse an extension block into `(type, body)` pairs. `REQ-MSG-001`.
fn parse_extensions<'a>(r: &mut Reader<'a>) -> Result<Vec<(ExtensionType, &'a [u8])>> {
    let mut block = r.sub16()?;
    let mut out: Vec<(ExtensionType, &'a [u8])> = Vec::new();
    while !block.is_empty() {
        let ty = ExtensionType::from_wire(block.u16()?);
        let body = block.vec16()?;
        if out.iter().any(|(t, _)| *t == ty) {
            return Err(illegal("duplicate extension"));
        }
        out.push((ty, body));
    }
    Ok(out)
}

fn write_ext<F>(out: &mut Vec<u8>, ty: ExtensionType, f: F) -> Result<()>
where
    F: FnOnce(&mut Vec<u8>) -> Result<()>,
{
    put_u16(out, ty.to_wire());
    nested(out, Prefix::U16, f)
}

fn read_u16_list(body: &[u8], prefix: Prefix) -> Result<Vec<u16>> {
    let mut r = Reader::new(body);
    let mut list = match prefix {
        Prefix::U8 => r.sub8()?,
        _ => r.sub16()?,
    };
    r.finish()?;
    if list.remaining() % 2 != 0 {
        return Err(decode_err("odd-length u16 list"));
    }
    let mut out = Vec::with_capacity(list.remaining() / 2);
    while !list.is_empty() {
        out.push(list.u16()?);
    }
    Ok(out)
}

fn read_alpn_list(body: &[u8]) -> Result<Vec<Vec<u8>>> {
    let mut r = Reader::new(body);
    let mut list = r.sub16()?;
    r.finish()?;
    let mut out = Vec::new();
    while !list.is_empty() {
        let p = list.vec8()?;
        if p.is_empty() {
            return Err(decode_err("empty ALPN protocol name"));
        }
        out.push(p.to_vec());
    }
    if out.is_empty() {
        return Err(decode_err("empty ALPN list"));
    }
    Ok(out)
}

fn write_alpn_list(out: &mut Vec<u8>, protos: &[Vec<u8>]) -> Result<()> {
    nested(out, Prefix::U16, |o| {
        for p in protos {
            put_vec(o, Prefix::U8, p)?;
        }
        Ok(())
    })
}

/// The `encrypted_client_hello` extension in a ClientHello.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EchHello {
    /// In ClientHelloOuter: the encrypted inner hello.
    Outer {
        /// `(kdf_id, aead_id)`.
        suite: (u16, u16),
        /// Which server configuration.
        config_id: u8,
        /// HPKE encapsulated key; empty in a second (post-retry) hello.
        enc: Vec<u8>,
        /// Sealed EncodedClientHelloInner.
        payload: Vec<u8>,
    },
    /// In ClientHelloInner: a marker with no body.
    Inner,
}

impl EchHello {
    fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        match self {
            Self::Inner => put_u8(out, 1),
            Self::Outer {
                suite,
                config_id,
                enc,
                payload,
            } => {
                put_u8(out, 0);
                put_u16(out, suite.0);
                put_u16(out, suite.1);
                put_u8(out, *config_id);
                put_vec(out, Prefix::U16, enc)?;
                put_vec(out, Prefix::U16, payload)?;
            }
        }
        Ok(())
    }

    /// Decode, returning the payload slice for an outer hello so its
    /// position can be found for the AAD.
    fn decode(body: &[u8]) -> Result<(Self, Option<&[u8]>)> {
        let mut r = Reader::new(body);
        let v = match r.u8()? {
            1 => (Self::Inner, None),
            0 => {
                let suite = (r.u16()?, r.u16()?);
                let config_id = r.u8()?;
                let enc = r.vec16()?.to_vec();
                let payload = r.vec16()?;
                if payload.is_empty() {
                    return Err(decode_err("empty ECH payload"));
                }
                (
                    Self::Outer {
                        suite,
                        config_id,
                        enc,
                        payload: payload.to_vec(),
                    },
                    Some(payload),
                )
            }
            _ => return Err(illegal("unknown ECHClientHelloType")),
        };
        r.finish()?;
        Ok(v)
    }
}

/// Smallest `record_size_limit` a peer may state (RFC 8449 §4).
pub const MIN_RECORD_SIZE_LIMIT: u16 = 64;
/// Largest meaningful `record_size_limit` in TLS 1.3: 2^14 plus the content
/// type byte.
pub const MAX_RECORD_SIZE_LIMIT: u16 = (1 << 14) + 1;

/// Read a `record_size_limit` body. `REQ-RSL-001`: below 64 is illegal.
fn read_record_size_limit(body: &[u8]) -> Result<u16> {
    let mut r = Reader::new(body);
    let v = r.u16()?;
    r.finish()?;
    if v < MIN_RECORD_SIZE_LIMIT {
        return Err(illegal("record_size_limit below 64"));
    }
    Ok(v)
}

/// ClientHello (§4.1.2), decoded into the fields TLS 1.3 uses.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClientHello {
    /// 32 random bytes.
    pub random: [u8; 32],
    /// `legacy_session_id`: 32 random bytes in middlebox-compatibility mode,
    /// empty under QUIC.
    pub session_id: Vec<u8>,
    /// Offered suites, in the client's preference order.
    pub suites: Vec<CipherSuite>,
    /// SNI host name.
    pub server_name: Option<String>,
    /// `supported_groups`.
    pub groups: Vec<NamedGroup>,
    /// `signature_algorithms`.
    pub sig_algs: Vec<SignatureScheme>,
    /// `signature_algorithms_cert`, if sent.
    pub sig_algs_cert: Option<Vec<SignatureScheme>>,
    /// `supported_versions`.
    pub versions: Vec<ProtocolVersion>,
    /// `key_share` entries.
    pub key_shares: Vec<(NamedGroup, Vec<u8>)>,
    /// ALPN protocol names.
    pub alpn: Vec<Vec<u8>>,
    /// Cookie echoed from a HelloRetryRequest.
    pub cookie: Option<Vec<u8>>,
    /// QUIC transport parameters (raw).
    pub quic_params: Option<Vec<u8>>,
    /// `record_size_limit` (RFC 8449): largest TLSInnerPlaintext accepted.
    pub record_size_limit: Option<u16>,
    /// `status_request` for OCSP (RFC 6066 §8, RFC 8446 §4.4.2.1).
    pub status_request: bool,
    /// `encrypted_client_hello`.
    pub ech: Option<EchHello>,
    /// `post_handshake_auth`: the client will answer a CertificateRequest
    /// after the handshake.
    pub post_handshake_auth: bool,
    /// Where the ECH payload sits in the decoded body: `(start, len)`.
    pub ech_payload_at: Option<(usize, usize)>,
    /// `psk_key_exchange_modes`.
    pub psk_modes: Vec<u8>,
    /// `pre_shared_key`, always the last extension.
    pub psk: Option<OfferedPsks>,
    /// Whether `early_data` was present.
    pub early_data: bool,
    /// Every other extension type seen, for reports.
    pub other_extensions: Vec<ExtensionType>,
}

impl ClientHello {
    /// Encode the body (without the handshake header).
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(512);
        put_u16(&mut out, ProtocolVersion::Tls12.to_wire());
        out.extend_from_slice(&self.random);
        put_vec(&mut out, Prefix::U8, &self.session_id)?;
        nested(&mut out, Prefix::U16, |o| {
            for s in &self.suites {
                put_u16(o, s.to_wire());
            }
            Ok(())
        })?;
        put_vec(&mut out, Prefix::U8, &[0])?;
        nested(&mut out, Prefix::U16, |o| {
            if let Some(name) = &self.server_name {
                write_ext(o, ExtensionType::ServerName, |o| {
                    nested(o, Prefix::U16, |o| {
                        put_u8(o, 0);
                        put_vec(o, Prefix::U16, name.as_bytes())
                    })
                })?;
            }
            write_ext(o, ExtensionType::SupportedVersions, |o| {
                nested(o, Prefix::U8, |o| {
                    for v in &self.versions {
                        put_u16(o, v.to_wire());
                    }
                    Ok(())
                })
            })?;
            write_ext(o, ExtensionType::SupportedGroups, |o| {
                nested(o, Prefix::U16, |o| {
                    for g in &self.groups {
                        put_u16(o, g.to_wire());
                    }
                    Ok(())
                })
            })?;
            write_ext(o, ExtensionType::SignatureAlgorithms, |o| {
                nested(o, Prefix::U16, |o| {
                    for s in &self.sig_algs {
                        put_u16(o, s.to_wire());
                    }
                    Ok(())
                })
            })?;
            if let Some(cert) = &self.sig_algs_cert {
                write_ext(o, ExtensionType::SignatureAlgorithmsCert, |o| {
                    nested(o, Prefix::U16, |o| {
                        for s in cert {
                            put_u16(o, s.to_wire());
                        }
                        Ok(())
                    })
                })?;
            }
            if !self.alpn.is_empty() {
                write_ext(o, ExtensionType::ApplicationLayerProtocolNegotiation, |o| {
                    write_alpn_list(o, &self.alpn)
                })?;
            }
            if let Some(cookie) = &self.cookie {
                write_ext(o, ExtensionType::Cookie, |o| {
                    put_vec(o, Prefix::U16, cookie)
                })?;
            }
            if let Some(limit) = self.record_size_limit {
                write_ext(o, ExtensionType::RecordSizeLimit, |o| {
                    put_u16(o, limit);
                    Ok(())
                })?;
            }
            if self.status_request {
                // CertificateStatusRequest: ocsp(1), no responder ids, no extensions.
                write_ext(o, ExtensionType::StatusRequest, |o| {
                    o.extend_from_slice(&[1, 0, 0, 0, 0]);
                    Ok(())
                })?;
            }
            if !self.psk_modes.is_empty() {
                write_ext(o, ExtensionType::PskKeyExchangeModes, |o| {
                    put_vec(o, Prefix::U8, &self.psk_modes)
                })?;
            }
            if let Some(params) = &self.quic_params {
                write_ext(o, ExtensionType::QuicTransportParameters, |o| {
                    o.extend_from_slice(params);
                    Ok(())
                })?;
            }
            write_ext(o, ExtensionType::KeyShare, |o| {
                nested(o, Prefix::U16, |o| {
                    for (g, share) in &self.key_shares {
                        put_u16(o, g.to_wire());
                        put_vec(o, Prefix::U16, share)?;
                    }
                    Ok(())
                })
            })?;
            if self.post_handshake_auth {
                write_ext(o, ExtensionType::PostHandshakeAuth, |_| Ok(()))?;
            }
            if self.early_data {
                write_ext(o, ExtensionType::EarlyData, |_| Ok(()))?;
            }
            if let Some(ech) = &self.ech {
                write_ext(o, ExtensionType::EncryptedClientHello, |o| ech.encode(o))?;
            }
            // REQ-MSG-002: pre_shared_key goes last, so its binders are the
            // final bytes of the message and the truncated transcript is a prefix.
            if let Some(psk) = &self.psk {
                write_ext(o, ExtensionType::PreSharedKey, |o| psk.encode(o))?;
            }
            Ok(())
        })?;
        Ok(out)
    }

    /// Decode a body. `REQ-MSG-001..003`.
    pub fn decode(body: &[u8]) -> Result<Self> {
        let whole = body;
        let mut r = Reader::new(body);
        let _legacy_version = r.u16()?;
        let random = r.array::<32>()?;
        let session_id = r.vec8()?;
        if session_id.len() > 32 {
            return Err(illegal("legacy_session_id longer than 32 bytes"));
        }
        let suites_raw = r.vec16()?;
        if suites_raw.is_empty() || suites_raw.len() % 2 != 0 {
            return Err(decode_err("cipher_suites"));
        }
        let suites = suites_raw
            .chunks_exact(2)
            .map(|c| CipherSuite::from_wire(u16::from_be_bytes([c[0], c[1]])))
            .collect();
        let compression = r.vec8()?;
        if compression != [0] {
            return Err(illegal("legacy_compression_methods must be exactly null"));
        }
        let mut ch = ClientHello {
            random,
            session_id: session_id.to_vec(),
            suites,
            ..Default::default()
        };
        if r.is_empty() {
            // A hello without extensions cannot be TLS 1.3.
            return Ok(ch);
        }
        let exts = parse_extensions(&mut r)?;
        r.finish()?;
        let last = exts.len().saturating_sub(1);
        for (i, (ty, body)) in exts.iter().enumerate() {
            match ty {
                ExtensionType::ServerName => {
                    let mut er = Reader::new(body);
                    let mut list = er.sub16()?;
                    er.finish()?;
                    while !list.is_empty() {
                        let name_type = list.u8()?;
                        let name = list.vec16()?;
                        if name_type == 0 {
                            if ch.server_name.is_some() {
                                return Err(illegal("two host names in server_name"));
                            }
                            let s = core::str::from_utf8(name)
                                .map_err(|_| illegal("server_name is not ASCII"))?;
                            if !s.is_ascii() || s.is_empty() {
                                return Err(illegal("server_name is not ASCII"));
                            }
                            ch.server_name = Some(String::from(s));
                        }
                    }
                }
                ExtensionType::SupportedGroups => {
                    ch.groups = read_u16_list(body, Prefix::U16)?
                        .into_iter()
                        .map(NamedGroup::from_wire)
                        .collect();
                }
                ExtensionType::SignatureAlgorithms => {
                    ch.sig_algs = read_u16_list(body, Prefix::U16)?
                        .into_iter()
                        .map(SignatureScheme::from_wire)
                        .collect();
                }
                ExtensionType::SignatureAlgorithmsCert => {
                    ch.sig_algs_cert = Some(
                        read_u16_list(body, Prefix::U16)?
                            .into_iter()
                            .map(SignatureScheme::from_wire)
                            .collect(),
                    );
                }
                ExtensionType::SupportedVersions => {
                    ch.versions = read_u16_list(body, Prefix::U8)?
                        .into_iter()
                        .map(ProtocolVersion::from_wire)
                        .collect();
                }
                ExtensionType::KeyShare => {
                    let mut er = Reader::new(body);
                    let mut list = er.sub16()?;
                    er.finish()?;
                    while !list.is_empty() {
                        let g = NamedGroup::from_wire(list.u16()?);
                        let share = list.vec16()?;
                        if share.is_empty() {
                            return Err(decode_err("empty key_exchange"));
                        }
                        if ch.key_shares.iter().any(|(x, _)| *x == g) {
                            return Err(illegal("two key shares for one group"));
                        }
                        ch.key_shares.push((g, share.to_vec()));
                    }
                }
                ExtensionType::ApplicationLayerProtocolNegotiation => {
                    ch.alpn = read_alpn_list(body)?
                }
                ExtensionType::Cookie => {
                    let mut er = Reader::new(body);
                    let c = er.vec16()?;
                    er.finish()?;
                    if c.is_empty() {
                        return Err(decode_err("empty cookie"));
                    }
                    ch.cookie = Some(c.to_vec());
                }
                ExtensionType::PskKeyExchangeModes => {
                    let mut er = Reader::new(body);
                    ch.psk_modes = er.vec8()?.to_vec();
                    er.finish()?;
                }
                ExtensionType::QuicTransportParameters => ch.quic_params = Some(body.to_vec()),
                ExtensionType::RecordSizeLimit => {
                    ch.record_size_limit = Some(read_record_size_limit(body)?)
                }
                ExtensionType::PostHandshakeAuth => {
                    if !body.is_empty() {
                        return Err(decode_err("post_handshake_auth must be empty"));
                    }
                    ch.post_handshake_auth = true;
                }
                ExtensionType::EncryptedClientHello => {
                    let (ech, payload) = EchHello::decode(body)?;
                    if let Some(p) = payload {
                        // Offset of the payload within this ClientHello body.
                        let start = (p.as_ptr() as usize).wrapping_sub(whole.as_ptr() as usize);
                        ch.ech_payload_at = Some((start, p.len()));
                    }
                    ch.ech = Some(ech);
                }
                ExtensionType::StatusRequest => {
                    let mut er = Reader::new(body);
                    if er.u8()? == 1 {
                        let _responder_ids = er.vec16()?;
                        let _request_extensions = er.vec16()?;
                        er.finish()?;
                        ch.status_request = true;
                    }
                }
                ExtensionType::PreSharedKey => {
                    if i != last {
                        return Err(illegal("pre_shared_key is not the last extension"));
                    }
                    ch.psk = Some(OfferedPsks::decode(body)?);
                }
                ExtensionType::EarlyData => ch.early_data = true,
                other => ch.other_extensions.push(*other),
            }
        }
        Ok(ch)
    }
}

/// One offered PSK identity (§4.2.11).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PskIdentity {
    /// The ticket (or external PSK identity).
    pub identity: Vec<u8>,
    /// Ticket age in milliseconds plus the ticket's `age_add`, mod 2^32.
    pub obfuscated_ticket_age: u32,
}

/// `OfferedPsks` (§4.2.11): identities and one binder per identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OfferedPsks {
    /// Identities, in client preference order.
    pub identities: Vec<PskIdentity>,
    /// Binders, one per identity, in the same order.
    pub binders: Vec<Vec<u8>>,
}

impl OfferedPsks {
    /// Encoded length of the binders list, length prefix included. These are
    /// the final bytes of a ClientHello carrying this extension.
    pub fn binders_len(&self) -> usize {
        2 + self.binders.iter().map(|b| 1 + b.len()).sum::<usize>()
    }

    fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        nested(out, Prefix::U16, |o| {
            for id in &self.identities {
                put_vec(o, Prefix::U16, &id.identity)?;
                put_u32(o, id.obfuscated_ticket_age);
            }
            Ok(())
        })?;
        nested(out, Prefix::U16, |o| {
            for b in &self.binders {
                put_vec(o, Prefix::U8, b)?;
            }
            Ok(())
        })
    }

    fn decode(body: &[u8]) -> Result<Self> {
        let mut r = Reader::new(body);
        let mut ids = r.sub16()?;
        let mut binders_r = r.sub16()?;
        r.finish()?;
        let mut identities = Vec::new();
        while !ids.is_empty() {
            let identity = ids.vec16()?;
            if identity.is_empty() {
                return Err(decode_err("empty PSK identity"));
            }
            identities.push(PskIdentity {
                identity: identity.to_vec(),
                obfuscated_ticket_age: ids.u32()?,
            });
        }
        let mut binders = Vec::new();
        while !binders_r.is_empty() {
            let b = binders_r.vec8()?;
            if b.len() < 32 {
                return Err(decode_err("PSK binder shorter than 32 bytes"));
            }
            binders.push(b.to_vec());
        }
        if identities.is_empty() || identities.len() != binders.len() {
            return Err(illegal("PSK identities and binders do not pair up"));
        }
        Ok(Self {
            identities,
            binders,
        })
    }
}

/// ServerHello or HelloRetryRequest (§4.1.3, §4.1.4).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ServerHello {
    /// Random; [`HRR_RANDOM`] for a retry request.
    pub random: [u8; 32],
    /// Echo of the client's `legacy_session_id`.
    pub session_id: Vec<u8>,
    /// Selected suite.
    pub suite: Option<CipherSuite>,
    /// `supported_versions.selected_version`.
    pub selected_version: Option<ProtocolVersion>,
    /// Server key share (ServerHello).
    pub key_share: Option<(NamedGroup, Vec<u8>)>,
    /// Selected group (HelloRetryRequest).
    pub hrr_group: Option<NamedGroup>,
    /// Cookie (HelloRetryRequest).
    pub cookie: Option<Vec<u8>>,
    /// Index of the PSK identity the server accepted.
    pub selected_psk: Option<u16>,
    /// ECH acceptance confirmation (HelloRetryRequest only).
    pub ech_confirmation: Option<[u8; 8]>,
    /// Offset of that confirmation within the decoded body.
    pub ech_confirmation_at: Option<usize>,
    /// Any other extension, which a TLS 1.3 client must reject.
    pub other_extensions: Vec<ExtensionType>,
}

impl ServerHello {
    /// Whether this is a HelloRetryRequest.
    pub fn is_retry(&self) -> bool {
        self.random == HRR_RANDOM
    }

    /// Encode the body.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let suite = self.suite.ok_or(Error::new(
            ErrorKind::Internal,
            "server hello without suite",
        ))?;
        let mut out = Vec::with_capacity(160);
        put_u16(&mut out, ProtocolVersion::Tls12.to_wire());
        out.extend_from_slice(&self.random);
        put_vec(&mut out, Prefix::U8, &self.session_id)?;
        put_u16(&mut out, suite.to_wire());
        put_u8(&mut out, 0);
        nested(&mut out, Prefix::U16, |o| {
            write_ext(o, ExtensionType::SupportedVersions, |o| {
                put_u16(o, ProtocolVersion::Tls13.to_wire());
                Ok(())
            })?;
            if let Some(g) = self.hrr_group {
                write_ext(o, ExtensionType::KeyShare, |o| {
                    put_u16(o, g.to_wire());
                    Ok(())
                })?;
            }
            if let Some((g, share)) = &self.key_share {
                write_ext(o, ExtensionType::KeyShare, |o| {
                    put_u16(o, g.to_wire());
                    put_vec(o, Prefix::U16, share)
                })?;
            }
            if let Some(c) = &self.cookie {
                write_ext(o, ExtensionType::Cookie, |o| put_vec(o, Prefix::U16, c))?;
            }
            if let Some(i) = self.selected_psk {
                write_ext(o, ExtensionType::PreSharedKey, |o| {
                    put_u16(o, i);
                    Ok(())
                })?;
            }
            if let Some(c) = &self.ech_confirmation {
                write_ext(o, ExtensionType::EncryptedClientHello, |o| {
                    o.extend_from_slice(c);
                    Ok(())
                })?;
            }
            Ok(())
        })?;
        Ok(out)
    }

    /// Decode a body.
    pub fn decode(body: &[u8]) -> Result<Self> {
        let whole = body;
        let mut r = Reader::new(body);
        let _legacy = r.u16()?;
        let random = r.array::<32>()?;
        let session_id = r.vec8()?;
        if session_id.len() > 32 {
            return Err(illegal("legacy_session_id_echo longer than 32 bytes"));
        }
        let suite = CipherSuite::from_wire(r.u16()?);
        if r.u8()? != 0 {
            return Err(illegal("legacy_compression_method must be null"));
        }
        let mut sh = ServerHello {
            random,
            session_id: session_id.to_vec(),
            suite: Some(suite),
            ..Default::default()
        };
        if r.is_empty() {
            return Ok(sh);
        }
        let retry = sh.is_retry();
        let exts = parse_extensions(&mut r)?;
        r.finish()?;
        for (ty, body) in exts {
            let mut er = Reader::new(body);
            match ty {
                ExtensionType::SupportedVersions => {
                    sh.selected_version = Some(ProtocolVersion::from_wire(er.u16()?));
                }
                ExtensionType::KeyShare if retry => {
                    sh.hrr_group = Some(NamedGroup::from_wire(er.u16()?));
                }
                ExtensionType::KeyShare => {
                    let g = NamedGroup::from_wire(er.u16()?);
                    let share = er.vec16()?;
                    if share.is_empty() {
                        return Err(decode_err("empty key_exchange"));
                    }
                    sh.key_share = Some((g, share.to_vec()));
                }
                ExtensionType::Cookie if retry => {
                    let c = er.vec16()?;
                    if c.is_empty() {
                        return Err(decode_err("empty cookie"));
                    }
                    sh.cookie = Some(c.to_vec());
                }
                ExtensionType::PreSharedKey if !retry => {
                    sh.selected_psk = Some(er.u16()?);
                }
                ExtensionType::EncryptedClientHello if retry => {
                    sh.ech_confirmation_at =
                        Some((body.as_ptr() as usize).wrapping_sub(whole.as_ptr() as usize));
                    sh.ech_confirmation = Some(er.array::<8>()?);
                }
                other => {
                    sh.other_extensions.push(other);
                    continue;
                }
            }
            er.finish()?;
        }
        Ok(sh)
    }
}

/// EncryptedExtensions (§4.3.1).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EncryptedExtensions {
    /// Selected ALPN protocol.
    pub alpn: Option<Vec<u8>>,
    /// Whether the server acknowledged SNI with an empty `server_name`.
    pub server_name_ack: bool,
    /// QUIC transport parameters (raw).
    pub quic_params: Option<Vec<u8>>,
    /// `record_size_limit` (RFC 8449).
    pub record_size_limit: Option<u16>,
    /// ECH `retry_configs`: an ECHConfigList, sent when ECH was rejected.
    pub ech_retry_configs: Option<Vec<u8>>,
    /// The server accepted the client's 0-RTT data.
    pub early_data: bool,
    /// Server's supported groups, a hint for next time.
    pub groups: Vec<NamedGroup>,
    /// Every other extension type.
    pub other_extensions: Vec<ExtensionType>,
}

impl EncryptedExtensions {
    /// Encode the body.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        nested(&mut out, Prefix::U16, |o| {
            if self.server_name_ack {
                write_ext(o, ExtensionType::ServerName, |_| Ok(()))?;
            }
            if let Some(p) = &self.alpn {
                write_ext(o, ExtensionType::ApplicationLayerProtocolNegotiation, |o| {
                    write_alpn_list(o, core::slice::from_ref(p))
                })?;
            }
            if self.early_data {
                write_ext(o, ExtensionType::EarlyData, |_| Ok(()))?;
            }
            if let Some(list) = &self.ech_retry_configs {
                write_ext(o, ExtensionType::EncryptedClientHello, |o| {
                    o.extend_from_slice(list);
                    Ok(())
                })?;
            }
            if let Some(limit) = self.record_size_limit {
                write_ext(o, ExtensionType::RecordSizeLimit, |o| {
                    put_u16(o, limit);
                    Ok(())
                })?;
            }
            if let Some(params) = &self.quic_params {
                write_ext(o, ExtensionType::QuicTransportParameters, |o| {
                    o.extend_from_slice(params);
                    Ok(())
                })?;
            }
            Ok(())
        })?;
        Ok(out)
    }

    /// Decode a body.
    pub fn decode(body: &[u8]) -> Result<Self> {
        let mut r = Reader::new(body);
        let exts = parse_extensions(&mut r)?;
        r.finish()?;
        let mut ee = EncryptedExtensions::default();
        for (ty, body) in exts {
            match ty {
                ExtensionType::ApplicationLayerProtocolNegotiation => {
                    let mut list = read_alpn_list(body)?;
                    if list.len() != 1 {
                        return Err(illegal("server selected more than one ALPN protocol"));
                    }
                    ee.alpn = list.pop();
                }
                ExtensionType::ServerName => {
                    if !body.is_empty() {
                        return Err(decode_err("server_name acknowledgement must be empty"));
                    }
                    ee.server_name_ack = true;
                }
                ExtensionType::QuicTransportParameters => ee.quic_params = Some(body.to_vec()),
                ExtensionType::RecordSizeLimit => {
                    ee.record_size_limit = Some(read_record_size_limit(body)?)
                }
                ExtensionType::EncryptedClientHello => ee.ech_retry_configs = Some(body.to_vec()),
                ExtensionType::EarlyData => {
                    if !body.is_empty() {
                        return Err(decode_err(
                            "early_data in EncryptedExtensions must be empty",
                        ));
                    }
                    ee.early_data = true;
                }
                ExtensionType::SupportedGroups => {
                    ee.groups = read_u16_list(body, Prefix::U16)?
                        .into_iter()
                        .map(NamedGroup::from_wire)
                        .collect();
                }
                other => ee.other_extensions.push(other),
            }
        }
        Ok(ee)
    }
}

/// CertificateRequest (§4.3.2).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CertificateRequest {
    /// `certificate_request_context`; empty during the handshake.
    pub context: Vec<u8>,
    /// Schemes the server accepts in CertificateVerify.
    pub sig_algs: Vec<SignatureScheme>,
}

impl CertificateRequest {
    /// Encode the body.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        put_vec(&mut out, Prefix::U8, &self.context)?;
        nested(&mut out, Prefix::U16, |o| {
            write_ext(o, ExtensionType::SignatureAlgorithms, |o| {
                nested(o, Prefix::U16, |o| {
                    for s in &self.sig_algs {
                        put_u16(o, s.to_wire());
                    }
                    Ok(())
                })
            })
        })?;
        Ok(out)
    }

    /// Decode a body.
    pub fn decode(body: &[u8]) -> Result<Self> {
        let mut r = Reader::new(body);
        let context = r.vec8()?.to_vec();
        let exts = parse_extensions(&mut r)?;
        r.finish()?;
        let mut sig_algs = None;
        for (ty, body) in exts {
            if ty == ExtensionType::SignatureAlgorithms {
                sig_algs = Some(
                    read_u16_list(body, Prefix::U16)?
                        .into_iter()
                        .map(SignatureScheme::from_wire)
                        .collect(),
                );
            }
        }
        let sig_algs = sig_algs.ok_or(Error::new(
            ErrorKind::MissingExtension,
            "CertificateRequest without signature_algorithms",
        ))?;
        Ok(Self { context, sig_algs })
    }
}

/// Certificate (§4.4.2). Per-entry extensions are parsed for structure and
/// otherwise ignored; none are requested.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CertificateMsg {
    /// `certificate_request_context`.
    pub context: Vec<u8>,
    /// DER certificates, end-entity first.
    pub chain: Vec<Vec<u8>>,
    /// A stapled OCSP response for the end-entity certificate.
    pub ocsp: Option<Vec<u8>>,
}

/// Most certificates accepted in one chain.
pub const MAX_CHAIN_LEN: usize = 10;

impl CertificateMsg {
    /// Encode the body.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        put_vec(&mut out, Prefix::U8, &self.context)?;
        nested(&mut out, Prefix::U24, |o| {
            for (i, cert) in self.chain.iter().enumerate() {
                put_vec(o, Prefix::U24, cert)?;
                match (&self.ocsp, i) {
                    (Some(resp), 0) => nested(o, Prefix::U16, |o| {
                        write_ext(o, ExtensionType::StatusRequest, |o| {
                            // CertificateStatus { ocsp(1), OCSPResponse<1..2^24-1> }
                            put_u8(o, 1);
                            put_vec(o, Prefix::U24, resp)
                        })
                    })?,
                    _ => put_u16(o, 0),
                }
            }
            Ok(())
        })?;
        Ok(out)
    }

    /// Decode a body.
    pub fn decode(body: &[u8]) -> Result<Self> {
        let mut r = Reader::new(body);
        let context = r.vec8()?.to_vec();
        let mut list = r.sub24()?;
        r.finish()?;
        let mut chain = Vec::new();
        let mut ocsp = None;
        while !list.is_empty() {
            let cert = list.vec24()?;
            if cert.is_empty() {
                return Err(decode_err("empty certificate entry"));
            }
            let mut ext = Reader::new(list.vec16()?);
            // Each entry extension is a (type, vec16) pair; only the leaf's
            // status_request is used.
            while !ext.is_empty() {
                let ty = ExtensionType::from_wire(ext.u16()?);
                let body = ext.vec16()?;
                if ty == ExtensionType::StatusRequest && chain.is_empty() {
                    let mut r = Reader::new(body);
                    if r.u8()? != 1 {
                        return Err(decode_err("unknown CertificateStatusType"));
                    }
                    let resp = r.vec24()?;
                    r.finish()?;
                    if resp.is_empty() {
                        return Err(decode_err("empty OCSP response"));
                    }
                    ocsp = Some(resp.to_vec());
                }
            }
            if chain.len() == MAX_CHAIN_LEN {
                return Err(Error::new(
                    ErrorKind::BadCertificate,
                    "certificate chain too long",
                ));
            }
            chain.push(cert.to_vec());
        }
        Ok(Self {
            context,
            chain,
            ocsp,
        })
    }
}

/// CertificateVerify (§4.4.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateVerify {
    /// Scheme.
    pub scheme: SignatureScheme,
    /// Signature, wire form.
    pub signature: Vec<u8>,
}

impl CertificateVerify {
    /// Encode the body.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(4 + self.signature.len());
        put_u16(&mut out, self.scheme.to_wire());
        put_vec(&mut out, Prefix::U16, &self.signature)?;
        Ok(out)
    }

    /// Decode a body.
    pub fn decode(body: &[u8]) -> Result<Self> {
        let mut r = Reader::new(body);
        let scheme = SignatureScheme::from_wire(r.u16()?);
        let signature = r.vec16()?.to_vec();
        r.finish()?;
        Ok(Self { scheme, signature })
    }
}

/// The content a CertificateVerify signs (§4.4.3): 64 spaces, a context
/// string, a zero byte, and the transcript hash.
pub fn certificate_verify_input(server: bool, transcript_hash: &[u8]) -> Vec<u8> {
    let context: &[u8] = if server {
        b"TLS 1.3, server CertificateVerify"
    } else {
        b"TLS 1.3, client CertificateVerify"
    };
    let mut m = Vec::with_capacity(64 + context.len() + 1 + transcript_hash.len());
    m.extend_from_slice(&[0x20; 64]);
    m.extend_from_slice(context);
    m.push(0);
    m.extend_from_slice(transcript_hash);
    m
}

/// NewSessionTicket (§4.6.1).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NewSessionTicket {
    /// Lifetime in seconds.
    pub lifetime: u32,
    /// Obfuscation value for the ticket age.
    pub age_add: u32,
    /// Per-ticket nonce.
    pub nonce: Vec<u8>,
    /// Opaque ticket.
    pub ticket: Vec<u8>,
    /// `early_data` extension: the most 0-RTT bytes the server will accept
    /// on this ticket.
    pub max_early_data: Option<u32>,
}

impl NewSessionTicket {
    /// Decode a body.
    pub fn decode(body: &[u8]) -> Result<Self> {
        let mut r = Reader::new(body);
        let lifetime = r.u32()?;
        let age_add = r.u32()?;
        let nonce = r.vec8()?.to_vec();
        let ticket = r.vec16()?.to_vec();
        if ticket.is_empty() {
            return Err(decode_err("empty ticket"));
        }
        let mut max_early_data = None;
        for (ty, body) in parse_extensions(&mut r)? {
            if ty == ExtensionType::EarlyData {
                let mut er = Reader::new(body);
                max_early_data = Some(er.u32()?);
                er.finish()?;
            }
        }
        r.finish()?;
        if lifetime > 604_800 {
            return Err(illegal("ticket lifetime exceeds seven days"));
        }
        Ok(Self {
            lifetime,
            age_add,
            nonce,
            ticket,
            max_early_data,
        })
    }

    /// Encode the body.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        put_u32(&mut out, self.lifetime);
        put_u32(&mut out, self.age_add);
        put_vec(&mut out, Prefix::U8, &self.nonce)?;
        put_vec(&mut out, Prefix::U16, &self.ticket)?;
        nested(&mut out, Prefix::U16, |o| {
            if let Some(max) = self.max_early_data {
                write_ext(o, ExtensionType::EarlyData, |o| {
                    put_u32(o, max);
                    Ok(())
                })?;
            }
            Ok(())
        })?;
        Ok(out)
    }
}

/// Decode a KeyUpdate body (§4.6.3).
pub fn decode_key_update(body: &[u8]) -> Result<KeyUpdateRequest> {
    let mut r = Reader::new(body);
    let v = KeyUpdateRequest::from_wire(r.u8()?);
    r.finish()?;
    if let KeyUpdateRequest::Unknown(_) = v {
        return Err(illegal("KeyUpdate request value"));
    }
    Ok(v)
}

/// Pull one complete handshake message off the front of `buf`, if present.
///
/// Returns `(type, whole message including header)`. `max` bounds the body a
/// peer may make this endpoint buffer.
pub fn take_message(buf: &mut Vec<u8>, max: usize) -> Result<Option<(HandshakeType, Vec<u8>)>> {
    if buf.len() < 4 {
        return Ok(None);
    }
    let len = u32::from_be_bytes([0, buf[1], buf[2], buf[3]]) as usize;
    if len > max {
        return Err(Error::new(
            ErrorKind::IllegalParameter,
            "handshake message exceeds the size limit",
        ));
    }
    if buf.len() < 4 + len {
        return Ok(None);
    }
    let ty = HandshakeType::from_wire(buf[0]);
    let msg: Vec<u8> = buf.drain(..4 + len).collect();
    Ok(Some((ty, msg)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::HashAlg;

    #[test]
    fn hrr_random_is_the_hash_rfc8446_defines() {
        assert_eq!(
            HashAlg::Sha256.digest(b"HelloRetryRequest").as_bytes(),
            &HRR_RANDOM[..]
        );
    }

    fn sample_hello() -> ClientHello {
        ClientHello {
            random: [9; 32],
            session_id: alloc::vec![1; 32],
            suites: alloc::vec![
                CipherSuite::TlsAes128GcmSha256,
                CipherSuite::Unknown(0xabcd)
            ],
            server_name: Some("example.com".into()),
            groups: alloc::vec![NamedGroup::X25519MlKem768, NamedGroup::X25519],
            sig_algs: alloc::vec![SignatureScheme::EcdsaSecp256r1Sha256],
            sig_algs_cert: None,
            versions: alloc::vec![ProtocolVersion::Tls13],
            key_shares: alloc::vec![(NamedGroup::X25519, alloc::vec![5; 32])],
            alpn: alloc::vec![b"h2".to_vec()],
            cookie: Some(alloc::vec![3, 3]),
            quic_params: Some(alloc::vec![0x01, 0x02]),
            psk_modes: alloc::vec![1],
            psk: Some(OfferedPsks {
                identities: alloc::vec![PskIdentity {
                    identity: alloc::vec![7; 40],
                    obfuscated_ticket_age: 99
                }],
                binders: alloc::vec![alloc::vec![3; 48]],
            }),
            ..Default::default()
        }
    }

    #[test]
    fn client_hello_round_trips() {
        let ch = sample_hello();
        let back = ClientHello::decode(&ch.encode().unwrap()).unwrap();
        assert_eq!(back, ch);
    }

    #[test]
    fn every_truncation_of_a_client_hello_fails_cleanly() {
        let bytes = sample_hello().encode().unwrap();
        // A hello cut off exactly before its extension block is well formed
        // (and then refused by the state machine for lacking supported_versions).
        let no_extensions = 2 + 32 + 1 + 32 + 2 + 4 + 2;
        for n in 0..bytes.len() {
            if n != no_extensions {
                assert!(
                    ClientHello::decode(&bytes[..n]).is_err(),
                    "prefix {n} accepted"
                );
            }
        }
    }

    #[test]
    fn duplicate_extensions_are_illegal() {
        let mut bytes = sample_hello().encode().unwrap();
        // Append a second, empty early_data twice by rewriting the block.
        let ext_len_at = bytes.len() - {
            let mut r = Reader::new(&bytes);
            r.u16().unwrap();
            r.take(32).unwrap();
            r.vec8().unwrap();
            r.vec16().unwrap();
            r.vec8().unwrap();
            r.remaining()
        };
        bytes.extend_from_slice(&[0x00, 0x2a, 0x00, 0x00, 0x00, 0x2a, 0x00, 0x00]);
        let n = u16::from_be_bytes([bytes[ext_len_at], bytes[ext_len_at + 1]]) + 8;
        bytes[ext_len_at..ext_len_at + 2].copy_from_slice(&n.to_be_bytes());
        assert_eq!(
            ClientHello::decode(&bytes).unwrap_err().kind(),
            ErrorKind::IllegalParameter
        );
    }

    #[test]
    fn server_hello_and_retry_round_trip() {
        let sh = ServerHello {
            random: [4; 32],
            session_id: alloc::vec![1; 32],
            suite: Some(CipherSuite::TlsAes256GcmSha384),
            selected_version: Some(ProtocolVersion::Tls13),
            key_share: Some((NamedGroup::Secp256r1, alloc::vec![4; 65])),
            ..Default::default()
        };
        assert_eq!(ServerHello::decode(&sh.encode().unwrap()).unwrap(), sh);
        let hrr = ServerHello {
            random: HRR_RANDOM,
            session_id: alloc::vec![],
            suite: Some(CipherSuite::TlsAes128GcmSha256),
            selected_version: Some(ProtocolVersion::Tls13),
            hrr_group: Some(NamedGroup::Secp384r1),
            cookie: Some(alloc::vec![7; 10]),
            ..Default::default()
        };
        let back = ServerHello::decode(&hrr.encode().unwrap()).unwrap();
        assert!(back.is_retry());
        assert_eq!(back, hrr);
    }

    #[test]
    fn other_messages_round_trip() {
        let ee = EncryptedExtensions {
            alpn: Some(b"h3".to_vec()),
            server_name_ack: true,
            quic_params: Some(alloc::vec![1]),
            ..Default::default()
        };
        assert_eq!(
            EncryptedExtensions::decode(&ee.encode().unwrap()).unwrap(),
            ee
        );
        let cr = CertificateRequest {
            context: alloc::vec![],
            sig_algs: alloc::vec![SignatureScheme::Ed25519],
        };
        assert_eq!(
            CertificateRequest::decode(&cr.encode().unwrap()).unwrap(),
            cr
        );
        let c = CertificateMsg {
            context: alloc::vec![],
            chain: alloc::vec![alloc::vec![1, 2, 3], alloc::vec![4]],
            ocsp: Some(alloc::vec![0x30, 0x03, 0x0a, 0x01, 0x00]),
        };
        assert_eq!(CertificateMsg::decode(&c.encode().unwrap()).unwrap(), c);
        let cv = CertificateVerify {
            scheme: SignatureScheme::MlDsa65,
            signature: alloc::vec![8; 3309],
        };
        assert_eq!(
            CertificateVerify::decode(&cv.encode().unwrap()).unwrap(),
            cv
        );
        let t = NewSessionTicket {
            lifetime: 7200,
            age_add: 5,
            nonce: alloc::vec![0],
            ticket: alloc::vec![1; 16],
            max_early_data: Some(16384),
        };
        assert_eq!(NewSessionTicket::decode(&t.encode().unwrap()).unwrap(), t);
    }

    /// REQ-MSG-002: pre_shared_key anywhere but last is illegal_parameter.
    #[test]
    fn pre_shared_key_must_be_last() {
        let mut hello = sample_hello();
        hello.psk = None;
        let bytes = hello.encode().unwrap();
        let ext_at = 2 + 32 + 1 + 32 + 2 + 4 + 2;
        let with = |tail: &[u8]| {
            let mut b = bytes.clone();
            b.extend_from_slice(tail);
            let n = u16::from_be_bytes([b[ext_at], b[ext_at + 1]]) as usize + tail.len();
            b[ext_at..ext_at + 2].copy_from_slice(&(n as u16).to_be_bytes());
            b
        };
        // pre_shared_key (41) then early_data (42): illegal. The reverse is fine.
        let bad = with(&[0x00, 0x29, 0x00, 0x00, 0x00, 0x2a, 0x00, 0x00]);
        assert_eq!(
            ClientHello::decode(&bad).unwrap_err().kind(),
            ErrorKind::IllegalParameter
        );
        // early_data then a well-formed pre_shared_key (one identity, one binder).
        let mut psk_body = alloc::vec![0x00, 0x07, 0x00, 0x01, 0xaa, 0, 0, 0, 5, 0x00, 0x21, 0x20];
        psk_body.extend_from_slice(&[0x5b; 32]);
        let mut tail = alloc::vec![0x00, 0x2a, 0x00, 0x00, 0x00, 0x29];
        tail.extend_from_slice(&(psk_body.len() as u16).to_be_bytes());
        tail.extend_from_slice(&psk_body);
        let good = with(&tail);
        let ch = ClientHello::decode(&good).unwrap();
        assert!(ch.early_data);
        let psk = ch.psk.unwrap();
        assert_eq!(psk.identities[0].identity, [0xaa]);
        assert_eq!(psk.identities[0].obfuscated_ticket_age, 5);
        // The binders are the message's final bytes.
        assert_eq!(
            &good[good.len() - psk.binders_len()..][..3],
            &[0x00, 0x21, 0x20]
        );
    }

    /// REQ-RSL-001: a record_size_limit below 64 is illegal_parameter, and
    /// the extension round-trips in both messages.
    #[test]
    fn record_size_limit_is_bounded_and_round_trips() {
        let mut ch = sample_hello();
        ch.record_size_limit = Some(512);
        assert_eq!(
            ClientHello::decode(&ch.encode().unwrap())
                .unwrap()
                .record_size_limit,
            Some(512)
        );
        ch.record_size_limit = Some(63);
        assert_eq!(
            ClientHello::decode(&ch.encode().unwrap())
                .unwrap_err()
                .kind(),
            ErrorKind::IllegalParameter
        );
        let ee = EncryptedExtensions {
            record_size_limit: Some(64),
            ..Default::default()
        };
        assert_eq!(
            EncryptedExtensions::decode(&ee.encode().unwrap()).unwrap(),
            ee
        );
        let ee = EncryptedExtensions {
            record_size_limit: Some(10),
            ..Default::default()
        };
        assert_eq!(
            EncryptedExtensions::decode(&ee.encode().unwrap())
                .unwrap_err()
                .kind(),
            ErrorKind::IllegalParameter
        );
    }

    #[test]
    fn a_bad_compression_method_is_illegal() {
        let ch = sample_hello();
        let mut bytes = ch.encode().unwrap();
        // legacy_compression_methods sits after version, random, session id and suites.
        let at = 2 + 32 + 1 + 32 + 2 + 4;
        assert_eq!(&bytes[at..at + 2], &[1, 0]);
        bytes[at + 1] = 1;
        assert_eq!(
            ClientHello::decode(&bytes).unwrap_err().kind(),
            ErrorKind::IllegalParameter
        );
    }

    #[test]
    fn message_reassembly_waits_for_the_whole_body() {
        let msg = frame(HandshakeType::Finished, &[1, 2, 3]).unwrap();
        let mut buf = msg[..5].to_vec();
        assert!(take_message(&mut buf, 100).unwrap().is_none());
        buf.extend_from_slice(&msg[5..]);
        let (ty, whole) = take_message(&mut buf, 100).unwrap().unwrap();
        assert_eq!(ty, HandshakeType::Finished);
        assert_eq!(whole, msg);
        assert!(buf.is_empty());
        let mut big = frame(HandshakeType::Certificate, &[0; 200]).unwrap();
        assert!(take_message(&mut big, 100).is_err());
    }

    /// Every field-level check in the decoders refuses its case, each
    /// identified by its own message. Random bytes fail earlier, at framing,
    /// so these are reached only from otherwise well-formed messages.
    /// `REQ-MSG-004`.
    #[test]
    fn every_field_check_refuses_its_case() {
        fn expect<T: core::fmt::Debug>(r: Result<T>, want: &str) {
            let e = r.expect_err(want);
            assert!(e.to_string().contains(want), "wanted {want:?}, got {e}");
        }
        type Ch = fn(&mut ClientHello);
        let hello_cases: &[(Ch, &str)] = &[
            (
                |c| c.session_id = alloc::vec![1; 33],
                "legacy_session_id longer than 32 bytes",
            ),
            (|c| c.suites.clear(), "cipher_suites"),
            (
                |c| c.server_name = Some("exämple.com".into()),
                "server_name is not ASCII",
            ),
            (
                |c| c.server_name = Some(String::new()),
                "server_name is not ASCII",
            ),
            (
                |c| c.key_shares = alloc::vec![(NamedGroup::X25519, alloc::vec![])],
                "empty key_exchange",
            ),
            (
                |c| c.key_shares.push((NamedGroup::X25519, alloc::vec![6; 32])),
                "two key shares for one group",
            ),
            (
                |c| c.alpn = alloc::vec![alloc::vec![]],
                "empty ALPN protocol name",
            ),
            (|c| c.cookie = Some(alloc::vec![]), "empty cookie"),
            (
                |c| c.psk.as_mut().unwrap().identities[0].identity.clear(),
                "empty PSK identity",
            ),
            (
                |c| c.psk.as_mut().unwrap().binders[0] = alloc::vec![3; 31],
                "PSK binder shorter than 32 bytes",
            ),
            (
                |c| c.psk.as_mut().unwrap().binders.push(alloc::vec![3; 32]),
                "PSK identities and binders do not pair up",
            ),
        ];
        for (edit, want) in hello_cases {
            let mut ch = sample_hello();
            edit(&mut ch);
            expect(ch.encode().and_then(|b| ClientHello::decode(&b)), want);
        }

        let server_hello = || ServerHello {
            random: [1; 32],
            session_id: alloc::vec![2; 32],
            suite: Some(CipherSuite::TlsAes128GcmSha256),
            selected_version: Some(ProtocolVersion::Tls13),
            key_share: Some((NamedGroup::X25519, alloc::vec![5; 32])),
            ..Default::default()
        };
        let good = server_hello().encode().unwrap();
        assert!(ServerHello::decode(&good).is_ok());
        let mut sh = server_hello();
        sh.session_id = alloc::vec![2; 33];
        expect(
            sh.encode().and_then(|b| ServerHello::decode(&b)),
            "legacy_session_id_echo longer than 32 bytes",
        );
        let mut sh = server_hello();
        sh.key_share = Some((NamedGroup::X25519, alloc::vec![]));
        expect(
            sh.encode().and_then(|b| ServerHello::decode(&b)),
            "empty key_exchange",
        );
        // legacy_compression_method follows version, random, session ID, suite.
        let mut bad = good.clone();
        bad[2 + 32 + 1 + 32 + 2] = 1;
        expect(
            ServerHello::decode(&bad),
            "legacy_compression_method must be null",
        );
        let hrr = ServerHello {
            random: HRR_RANDOM,
            key_share: None,
            hrr_group: Some(NamedGroup::X25519),
            cookie: Some(alloc::vec![]),
            ..server_hello()
        };
        expect(
            hrr.encode().and_then(|b| ServerHello::decode(&b)),
            "empty cookie",
        );

        let cert = |chain: Vec<Vec<u8>>, ocsp: Option<Vec<u8>>| {
            CertificateMsg {
                context: alloc::vec![],
                chain,
                ocsp,
            }
            .encode()
            .and_then(|b| CertificateMsg::decode(&b))
        };
        expect(
            cert(alloc::vec![alloc::vec![]], None),
            "empty certificate entry",
        );
        expect(
            cert(alloc::vec![alloc::vec![0x30]; MAX_CHAIN_LEN + 1], None),
            "certificate chain too long",
        );
        expect(
            cert(alloc::vec![alloc::vec![0x30]], Some(alloc::vec![])),
            "empty OCSP response",
        );
        assert!(cert(alloc::vec![alloc::vec![0x30]; MAX_CHAIN_LEN], None).is_ok());

        let ticket = |lifetime: u32, ticket: Vec<u8>| {
            NewSessionTicket {
                lifetime,
                age_add: 1,
                nonce: alloc::vec![0],
                ticket,
                max_early_data: None,
            }
            .encode()
            .and_then(|b| NewSessionTicket::decode(&b))
        };
        expect(ticket(3600, alloc::vec![]), "empty ticket");
        expect(
            ticket(604_801, alloc::vec![1]),
            "ticket lifetime exceeds seven days",
        );
        assert!(ticket(604_800, alloc::vec![1]).is_ok());
    }
}
