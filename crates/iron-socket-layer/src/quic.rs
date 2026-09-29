//! TLS for QUIC (RFC 9001), QUIC version 1 and version 2 (RFC 9369).
//!
//! QUIC uses the TLS handshake but not the TLS record layer: handshake bytes
//! travel in CRYPTO frames at an encryption level, and each level's traffic
//! secret becomes packet-protection and header-protection keys. This module
//! provides both halves:
//!
//! * [`QuicConnection`] drives the same handshake engine as TLS over TCP, with
//!   [`QuicConnection::read_handshake`] / [`QuicConnection::write_handshake`]
//!   in place of records, and [`QuicConnection::next_key_change`] announcing
//!   each new key as the handshake reaches it.
//! * [`initial_keys`], [`PacketKey`], [`HeaderKey`] and [`KeyUpdate`] derive
//!   and apply the packet protection of RFC 9001 §5.
//!
//! QUIC-specific rules enforced here or in the engine: no middlebox
//! compatibility mode (§8.4), ALPN is mandatory (§8.1), the transport
//! parameters extension is mandatory and QUIC-only (§8.2), and the TLS
//! KeyUpdate message is forbidden (§6).
//!
//! Requirement trace: `REQ-QUIC-001` (initial secrets per §5.2 / RFC 9369
//! §3.3.1), `REQ-QUIC-002` (header protection masks 4 bits of a long header
//! and 5 of a short one, §5.4.1), `REQ-QUIC-003` (key update per §6.1, header
//! key unchanged), `REQ-QUIC-004` (a CRYPTO error maps to 0x0100 + alert, §4.8).

use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::config::{ClientConfig, ServerConfig};
use crate::conn::{Connection, KeyChange, Level};
use crate::crypto::{
    self, AeadAlg, AeadKey, HashAlg, HeaderProtectionKey, Output, NONCE_LEN, TAG_LEN,
};
use crate::enums::{AlertDescription, CipherSuite};
use crate::error::{Error, ErrorKind, Result};
use crate::record::suite_params;
use crate::report::{HandshakeState, SessionReport, Side};

/// A QUIC version whose packet protection this module implements.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Version {
    /// QUIC version 1, RFC 9000 / RFC 9001.
    V1,
    /// QUIC version 2, RFC 9369.
    V2,
}

impl Version {
    /// The version number on the wire.
    pub const fn wire(self) -> u32 {
        match self {
            Self::V1 => 0x0000_0001,
            Self::V2 => 0x6b33_43cf,
        }
    }

    /// Stable identifier.
    pub const fn id(self) -> &'static str {
        match self {
            Self::V1 => "quic:v1",
            Self::V2 => "quic:v2",
        }
    }

    /// The Initial salt (RFC 9001 §5.2, RFC 9369 §3.3.1).
    pub const fn initial_salt(self) -> &'static [u8; 20] {
        match self {
            Self::V1 => &[
                0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8,
                0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
            ],
            Self::V2 => &[
                0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26,
                0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9,
            ],
        }
    }

    const fn key_label(self) -> &'static [u8] {
        match self {
            Self::V1 => b"quic key",
            Self::V2 => b"quicv2 key",
        }
    }

    const fn iv_label(self) -> &'static [u8] {
        match self {
            Self::V1 => b"quic iv",
            Self::V2 => b"quicv2 iv",
        }
    }

    const fn hp_label(self) -> &'static [u8] {
        match self {
            Self::V1 => b"quic hp",
            Self::V2 => b"quicv2 hp",
        }
    }

    const fn ku_label(self) -> &'static [u8] {
        match self {
            Self::V1 => b"quic ku",
            Self::V2 => b"quicv2 ku",
        }
    }
}

/// Packet protection for one direction at one level (RFC 9001 §5.3).
pub struct PacketKey {
    aead: AeadKey,
    iv: [u8; NONCE_LEN],
}

impl core::fmt::Debug for PacketKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "PacketKey({:?})", self.aead.alg())
    }
}

impl PacketKey {
    fn derive(version: Version, aead: AeadAlg, hash: HashAlg, secret: &[u8]) -> Result<Self> {
        let mut key = crypto::SecretVec::new(alloc::vec![0u8; aead.key_len()]);
        crypto::hkdf_expand_label(hash, secret, version.key_label(), b"", key.get_mut())?;
        let mut iv = [0u8; NONCE_LEN];
        crypto::hkdf_expand_label(hash, secret, version.iv_label(), b"", &mut iv)?;
        Ok(Self {
            aead: AeadKey::new(aead, key.get())?,
            iv,
        })
    }

    /// The AEAD.
    pub fn alg(&self) -> AeadAlg {
        self.aead.alg()
    }

    /// Tag length appended to every packet payload.
    pub const fn tag_len(&self) -> usize {
        TAG_LEN
    }

    /// Packets one key may protect (RFC 9001 §6.6).
    pub fn confidentiality_limit(&self) -> u64 {
        match self.aead.alg() {
            AeadAlg::Aes128Gcm | AeadAlg::Aes256Gcm => 1 << 23,
            AeadAlg::ChaCha20Poly1305 => 1 << 62,
        }
    }

    /// Failed decryptions tolerated per key (RFC 9001 §6.6).
    pub fn integrity_limit(&self) -> u64 {
        self.aead.alg().integrity_limit()
    }

    /// Encrypt `payload` in place; `header` is the unprotected header, used as
    /// associated data. Returns the tag to append.
    pub fn seal(
        &self,
        packet_number: u64,
        header: &[u8],
        payload: &mut [u8],
    ) -> Result<[u8; TAG_LEN]> {
        let nonce = crypto::nonce_for(&self.iv, packet_number);
        let mut tag = [0u8; TAG_LEN];
        self.aead.seal(&nonce, header, payload, &mut tag)?;
        Ok(tag)
    }

    /// Decrypt `payload_and_tag` in place, returning the plaintext length.
    pub fn open(
        &self,
        packet_number: u64,
        header: &[u8],
        payload_and_tag: &mut [u8],
    ) -> Result<usize> {
        if payload_and_tag.len() < TAG_LEN {
            return Err(Error::new(
                ErrorKind::BadRecordMac,
                "packet shorter than its tag",
            ));
        }
        let nonce = crypto::nonce_for(&self.iv, packet_number);
        let n = payload_and_tag.len() - TAG_LEN;
        let (ct, tag) = payload_and_tag.split_at_mut(n);
        self.aead.open(&nonce, header, ct, tag)?;
        Ok(n)
    }
}

/// Header protection for one direction (RFC 9001 §5.4).
#[derive(Debug)]
pub struct HeaderKey(HeaderProtectionKey);

impl HeaderKey {
    fn derive(version: Version, aead: AeadAlg, hash: HashAlg, secret: &[u8]) -> Result<Self> {
        let mut key = crypto::SecretVec::new(alloc::vec![0u8; aead.key_len()]);
        crypto::hkdf_expand_label(hash, secret, version.hp_label(), b"", key.get_mut())?;
        Ok(Self(HeaderProtectionKey::new(aead, key.get())?))
    }

    /// Bytes of ciphertext sampled.
    pub const fn sample_len(&self) -> usize {
        crypto::HP_SAMPLE_LEN
    }

    fn first_byte_mask(first: u8) -> u8 {
        // REQ-QUIC-002: long header (top bit set) masks 4 bits, short masks 5.
        if first & 0x80 != 0 {
            0x0f
        } else {
            0x1f
        }
    }

    /// Apply protection: `first` is the header's first byte and `packet_number`
    /// the encoded packet number (1–4 bytes), both unprotected on entry.
    pub fn protect(&self, sample: &[u8], first: &mut u8, packet_number: &mut [u8]) -> Result<()> {
        if packet_number.is_empty() || packet_number.len() > 4 {
            return Err(Error::new(
                ErrorKind::InvalidState,
                "packet number is 1 to 4 bytes",
            ));
        }
        let mask = self.0.mask(sample)?;
        *first ^= mask[0] & Self::first_byte_mask(*first);
        for (b, m) in packet_number.iter_mut().zip(&mask[1..]) {
            *b ^= m;
        }
        Ok(())
    }

    /// Remove protection. `packet_number` must hold the 4 bytes following the
    /// header's packet-number offset; returns the actual packet-number length,
    /// and only that many bytes are unmasked.
    pub fn unprotect(
        &self,
        sample: &[u8],
        first: &mut u8,
        packet_number: &mut [u8],
    ) -> Result<usize> {
        if packet_number.len() < 4 {
            return Err(Error::new(
                ErrorKind::Decode,
                "need four bytes after the packet-number offset",
            ));
        }
        let mask = self.0.mask(sample)?;
        *first ^= mask[0] & Self::first_byte_mask(*first);
        let len = (*first & 0x03) as usize + 1;
        for (b, m) in packet_number[..len].iter_mut().zip(&mask[1..]) {
            *b ^= m;
        }
        Ok(len)
    }
}

/// Packet and header protection for one direction.
#[derive(Debug)]
pub struct DirectionalKeys {
    /// Packet protection.
    pub packet: PacketKey,
    /// Header protection.
    pub header: HeaderKey,
}

impl DirectionalKeys {
    fn derive(version: Version, suite: CipherSuite, secret: &[u8]) -> Result<Self> {
        let (aead, hash) = suite_params(suite).ok_or(Error::new(ErrorKind::Internal, "suite"))?;
        Ok(Self {
            packet: PacketKey::derive(version, aead, hash, secret)?,
            header: HeaderKey::derive(version, aead, hash, secret)?,
        })
    }
}

/// Both directions' keys.
#[derive(Debug)]
pub struct Keys {
    /// Keys this endpoint sends with.
    pub local: DirectionalKeys,
    /// Keys this endpoint receives with.
    pub remote: DirectionalKeys,
}

/// Initial keys from the client's Destination Connection ID. `REQ-QUIC-001`.
pub fn initial_keys(version: Version, client_dcid: &[u8], side: Side) -> Result<Keys> {
    if client_dcid.len() > 20 {
        return Err(Error::new(
            ErrorKind::IllegalParameter,
            "connection ID longer than 20 bytes",
        ));
    }
    let hash = HashAlg::Sha256;
    let initial = crypto::hkdf_extract(hash, version.initial_salt(), client_dcid)?;
    let client = crypto::expand_label_secret(hash, initial.as_bytes(), b"client in", b"")?;
    let server = crypto::expand_label_secret(hash, initial.as_bytes(), b"server in", b"")?;
    let suite = CipherSuite::TlsAes128GcmSha256;
    let c = DirectionalKeys::derive(version, suite, client.as_bytes())?;
    let s = DirectionalKeys::derive(version, suite, server.as_bytes())?;
    Ok(match side {
        Side::Client => Keys {
            local: c,
            remote: s,
        },
        Side::Server => Keys {
            local: s,
            remote: c,
        },
    })
}

/// 1-RTT key update state (RFC 9001 §6). `REQ-QUIC-003`.
pub struct KeyUpdate {
    version: Version,
    suite: CipherSuite,
    local: Output,
    remote: Output,
    generation: u64,
}

impl core::fmt::Debug for KeyUpdate {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "KeyUpdate(generation {})", self.generation)
    }
}

impl KeyUpdate {
    /// Derive the next generation's packet keys. Header keys do not change.
    pub fn next_keys(&mut self) -> Result<(PacketKey, PacketKey)> {
        let (aead, hash) =
            suite_params(self.suite).ok_or(Error::new(ErrorKind::Internal, "suite"))?;
        self.local =
            crypto::expand_label_secret(hash, self.local.as_bytes(), self.version.ku_label(), b"")?;
        self.remote = crypto::expand_label_secret(
            hash,
            self.remote.as_bytes(),
            self.version.ku_label(),
            b"",
        )?;
        self.generation += 1;
        Ok((
            PacketKey::derive(self.version, aead, hash, self.local.as_bytes())?,
            PacketKey::derive(self.version, aead, hash, self.remote.as_bytes())?,
        ))
    }

    /// Updates performed so far.
    pub fn generation(&self) -> u64 {
        self.generation
    }
}

/// A key the QUIC stack should install.
#[derive(Debug)]
pub struct KeyInstall {
    /// Level.
    pub level: Level,
    /// `true` for the sending direction.
    pub write: bool,
    /// Packet and header protection.
    pub keys: DirectionalKeys,
}

/// The TLS half of a QUIC connection.
pub struct QuicConnection {
    conn: Connection,
    version: Version,
    app_local: Option<Output>,
    app_remote: Option<Output>,
}

impl core::fmt::Debug for QuicConnection {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "QuicConnection({:?}, {:?})", self.version, self.conn)
    }
}

impl QuicConnection {
    /// A QUIC client. `transport_params` is the encoded transport parameters
    /// (RFC 9000 §18), carried opaquely. The ClientHello is ready in
    /// [`QuicConnection::write_handshake`] on return, at [`Level::Initial`].
    pub fn client(
        config: Arc<ClientConfig>,
        server_name: &str,
        transport_params: &[u8],
        version: Version,
    ) -> Result<Self> {
        let mut conn =
            Connection::client_inner(config, server_name, Some(transport_params.to_vec()))?;
        conn.core.report.event("event:quic-version", version.id());
        Ok(Self {
            conn,
            version,
            app_local: None,
            app_remote: None,
        })
    }

    /// A QUIC client that offers 0-RTT if it holds a ticket permitting it
    /// and `ClientConfig::early_data` is set. The 0-RTT write key then
    /// appears first from [`QuicConnection::next_key_change`] at
    /// [`Level::Early`], and [`QuicConnection::early_transport_parameters`]
    /// gives the server parameters to apply to 0-RTT packets. Whether the
    /// server took the data is in `report().early_data`.
    ///
    /// **0-RTT data can be replayed and has no forward secrecy**: send only
    /// requests that are safe to repeat.
    pub fn client_with_early_data(
        config: Arc<ClientConfig>,
        server_name: &str,
        transport_params: &[u8],
        version: Version,
    ) -> Result<Self> {
        let mut conn = Connection::client_inner_with(
            config,
            server_name,
            Some(transport_params.to_vec()),
            Some(Vec::new()),
        )?;
        conn.core.report.event("event:quic-version", version.id());
        Ok(Self {
            conn,
            version,
            app_local: None,
            app_remote: None,
        })
    }

    /// The server transport parameters remembered with the ticket, when
    /// 0-RTT is being attempted (RFC 9001 §7.4.1).
    pub fn early_transport_parameters(&self) -> Option<&[u8]> {
        self.conn.core.remembered_quic_params.as_deref()
    }

    /// A QUIC server.
    pub fn server(
        config: Arc<ServerConfig>,
        transport_params: &[u8],
        version: Version,
    ) -> Result<Self> {
        let mut conn = Connection::server_inner(config, Some(transport_params.to_vec()))?;
        conn.core.report.event("event:quic-version", version.id());
        Ok(Self {
            conn,
            version,
            app_local: None,
            app_remote: None,
        })
    }

    /// Feed CRYPTO frame data, in order, received at `level`.
    pub fn read_handshake(&mut self, level: Level, data: &[u8]) -> Result<()> {
        self.conn.read_quic(level, data)
    }

    /// Take the next handshake bytes to send in CRYPTO frames, with their level.
    pub fn write_handshake(&mut self) -> Option<(Level, Vec<u8>)> {
        self.conn.take_quic_output()
    }

    /// The next key the handshake produced, derived for QUIC.
    ///
    /// Call after every [`QuicConnection::read_handshake`]; keys appear in
    /// the order they must be installed.
    pub fn next_key_change(&mut self) -> Result<Option<KeyInstall>> {
        let Some(KeyChange {
            level,
            write,
            suite,
            secret,
        }) = self.conn.take_quic_key()
        else {
            return Ok(None);
        };
        if level == Level::Application {
            if write {
                self.app_local = Some(secret.clone());
            } else {
                self.app_remote = Some(secret.clone());
            }
        }
        let keys = DirectionalKeys::derive(self.version, suite, secret.as_bytes())?;
        Ok(Some(KeyInstall { level, write, keys }))
    }

    /// Key update state for 1-RTT, once both application secrets exist.
    pub fn key_update(&self) -> Result<KeyUpdate> {
        match (&self.app_local, &self.app_remote, self.conn.suite()) {
            (Some(l), Some(r), Some(suite)) => Ok(KeyUpdate {
                version: self.version,
                suite,
                local: l.clone(),
                remote: r.clone(),
                generation: 0,
            }),
            _ => Err(Error::new(
                ErrorKind::InvalidState,
                "1-RTT keys not yet available",
            )),
        }
    }

    /// The peer's transport parameters, once received.
    pub fn peer_transport_parameters(&self) -> Option<&[u8]> {
        self.conn.quic_peer_params()
    }

    /// Whether the handshake is still running.
    pub fn is_handshaking(&self) -> bool {
        self.conn.is_handshaking()
    }

    /// Handshake state.
    pub fn state(&self) -> HandshakeState {
        self.conn.state()
    }

    /// The alert to report in CONNECTION_CLOSE, if the handshake failed.
    pub fn alert(&self) -> Option<AlertDescription> {
        self.conn.error().and_then(|e| e.kind().alert())
    }

    /// The QUIC transport error code for a failure: `0x0100 + alert`
    /// (RFC 9001 §4.8). `REQ-QUIC-004`.
    pub fn transport_error_code(&self) -> Option<u64> {
        self.alert().map(|a| 0x0100 + u64::from(a.to_wire()))
    }

    /// The version.
    pub fn version(&self) -> Version {
        self.version
    }

    /// What was negotiated and what holds.
    pub fn report(&self) -> &SessionReport {
        self.conn.report()
    }

    /// Negotiated ALPN protocol.
    pub fn alpn(&self) -> Option<&[u8]> {
        self.conn.alpn()
    }

    /// Exporter (RFC 8446 §7.5), as for TLS.
    pub fn export_keying_material(
        &self,
        label: &[u8],
        context: &[u8],
        out: &mut [u8],
    ) -> Result<()> {
        self.conn.export_keying_material(label, context, out)
    }

    /// The latched error, if any.
    pub fn error(&self) -> Option<Error> {
        self.conn.error()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// RFC 9001 Appendix A.1 key derivation and A.2/A.3 header protection.
    /// The header-protection keys match those IronCrypto's QUIC tests check
    /// independently; packet key and IV come from the same appendix.
    #[test]
    fn initial_keys_match_rfc9001_appendix_a() {
        let dcid = hex("8394c8f03e515708");
        let k = initial_keys(Version::V1, &dcid, Side::Client).unwrap();
        // Client's packet protection: check by sealing and opening across sides.
        let s = initial_keys(Version::V1, &dcid, Side::Server).unwrap();
        let mut payload = *b"crypto frame";
        let tag = k.local.packet.seal(2, b"hdr", &mut payload).unwrap();
        let mut both = payload.to_vec();
        both.extend_from_slice(&tag);
        let n = s.remote.packet.open(2, b"hdr", &mut both).unwrap();
        assert_eq!(&both[..n], b"crypto frame");

        // A.2: client Initial header protection.
        let mut first = 0xc3u8;
        let mut pn = hex("00000002");
        k.local
            .header
            .protect(
                &hex("d1b1c98dd7689fb8ec11d242b123dc9b"),
                &mut first,
                &mut pn,
            )
            .unwrap();
        assert_eq!(first, 0xc0);
        assert_eq!(pn, hex("7b9aec34"));
        // A.3: server Initial.
        let mut first = 0xc1u8;
        let mut pn = hex("0001");
        s.local
            .header
            .protect(
                &hex("2cd0991cd25b0aac406a5816b6394100"),
                &mut first,
                &mut pn,
            )
            .unwrap();
        assert_eq!(first, 0xcf);
        assert_eq!(pn, hex("c0d9"));
    }

    #[test]
    fn initial_packet_key_and_iv_match_rfc9001_a1() {
        let dcid = hex("8394c8f03e515708");
        let hash = HashAlg::Sha256;
        let initial = crypto::hkdf_extract(hash, Version::V1.initial_salt(), &dcid).unwrap();
        assert_eq!(
            initial.as_bytes(),
            &hex("7db5df06e7a69e432496adedb00851923595221596ae2ae9fb8115c1e9ed0a44")[..]
        );
        let client =
            crypto::expand_label_secret(hash, initial.as_bytes(), b"client in", b"").unwrap();
        let mut key = [0u8; 16];
        crypto::hkdf_expand_label(hash, client.as_bytes(), b"quic key", b"", &mut key).unwrap();
        assert_eq!(key.to_vec(), hex("1f369613dd76d5467730efcbe3b1a22d"));
        let mut iv = [0u8; 12];
        crypto::hkdf_expand_label(hash, client.as_bytes(), b"quic iv", b"", &mut iv).unwrap();
        assert_eq!(iv.to_vec(), hex("fa044b2f42a3fd3b46fb255c"));
        let server =
            crypto::expand_label_secret(hash, initial.as_bytes(), b"server in", b"").unwrap();
        crypto::hkdf_expand_label(hash, server.as_bytes(), b"quic key", b"", &mut key).unwrap();
        assert_eq!(key.to_vec(), hex("cf3a5331653c364c88f0f379b6067e37"));
        crypto::hkdf_expand_label(hash, server.as_bytes(), b"quic iv", b"", &mut iv).unwrap();
        assert_eq!(iv.to_vec(), hex("0ac1493ca1905853b0bba03e"));
    }

    #[test]
    fn a_short_header_masks_five_bits_and_a_long_header_four() {
        let k = initial_keys(Version::V1, &[1, 2, 3, 4], Side::Client).unwrap();
        let sample = [7u8; 16];
        let mask = k.local.header.0.mask(&sample).unwrap();
        for (first, bits) in [(0x40u8, 0x1f), (0xc0u8, 0x0f)] {
            let mut f = first;
            let mut pn = [0u8; 1];
            k.local.header.protect(&sample, &mut f, &mut pn).unwrap();
            assert_eq!(f ^ first, mask[0] & bits);
            // Round trip.
            let mut pn4 = [pn[0], 0, 0, 0];
            let n = k.local.header.unprotect(&sample, &mut f, &mut pn4).unwrap();
            assert_eq!(f, first);
            assert_eq!(n, 1);
            assert_eq!(pn4[0], 0);
        }
    }
}
