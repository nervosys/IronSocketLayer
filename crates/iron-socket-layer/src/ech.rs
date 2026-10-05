//! Encrypted Client Hello (draft-ietf-tls-esni, codepoint 0xfe0d).
//!
//! ECH hides the real server name, and every other ClientHello extension,
//! from the network. The client sends a *ClientHelloOuter* naming only the
//! server's public name, carrying the real *ClientHelloInner* encrypted with
//! HPKE to a key the server published in its `ECHConfigList` (usually in a DNS
//! HTTPS record). A server that can decrypt it continues with the inner hello
//! and proves so with an 8-byte confirmation in its ServerHello random; one
//! that cannot completes a handshake as the public name and hands the client
//! fresh `retry_configs`, and the client aborts with `ech_required` rather than
//! continue with the real name exposed. IronSocketLayer never falls back to
//! sending the real name in the clear.
//!
//! Supported: ECHConfig version 0xfe0d, KEM `DHKEM(X25519, HKDF-SHA256)`,
//! KDF `HKDF-SHA256`, AEADs AES-128-GCM, AES-256-GCM and ChaCha20-Poly1305.
//! Servers expand `ech_outer_extensions`; this client does not compress.
//! A ClientHelloInner carries no resumption PSK.
//!
//! Requirement trace: `REQ-ECH-001` (the real name never appears outside the
//! encrypted inner hello), `REQ-ECH-002` (acceptance is decided only by the
//! confirmation value, compared in constant time), `REQ-ECH-003` (on
//! rejection the client authenticates the public name, then aborts with
//! `ech_required` and exposes `retry_configs`), `REQ-ECH-004` (an ECH
//! configuration the client cannot use is an error, never a silent
//! plaintext fallback), `REQ-ECH-005` (a reconstructed inner hello must be
//! exactly the client's bytes: padding must be zero and outer references
//! must resolve).

use alloc::string::String;
use alloc::vec::Vec;

use ic_core::traits::RandomSource;

use crate::codec::{nested, put_u16, put_u8, put_vec, Prefix, Reader};
use crate::crypto::hpke::{self, KemKeyPair};
use crate::crypto::{self, HashAlg, Output};
use crate::error::{Error, ErrorKind, Result};

/// ECHConfig version this module implements.
pub const ECH_VERSION: u16 = 0xfe0d;
/// `encrypted_client_hello` extension type.
pub const EXT_ECH: u16 = 0xfe0d;
/// `ech_outer_extensions` extension type.
pub const EXT_ECH_OUTER_EXTENSIONS: u16 = 0xfd00;

fn bad(ctx: &'static str) -> Error {
    Error::new(ErrorKind::Decode, ctx)
}

/// One parsed `ECHConfig`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EchConfig {
    /// The whole `ECHConfig` encoding (version, length and contents): the
    /// HPKE `info` binds to it.
    pub raw: Vec<u8>,
    /// Identifies the key to the server.
    pub config_id: u8,
    /// HPKE KEM.
    pub kem_id: u16,
    /// HPKE public key.
    pub public_key: Vec<u8>,
    /// `(kdf_id, aead_id)` pairs.
    pub cipher_suites: Vec<(u16, u16)>,
    /// Longest name the server expects clients to hide, for padding.
    pub maximum_name_length: u8,
    /// The name the outer ClientHello carries.
    pub public_name: String,
    /// Whether an extension the client must understand was not understood.
    pub has_unknown_mandatory_extension: bool,
}

impl EchConfig {
    /// The first cipher suite this build supports, if the KEM is supported.
    pub fn usable_suite(&self) -> Option<(u16, u16)> {
        if self.kem_id != hpke::KEM_X25519_SHA256
            || self.has_unknown_mandatory_extension
            || self.public_key.len() != 32
        {
            return None;
        }
        self.cipher_suites
            .iter()
            .copied()
            .find(|(kdf, aead)| *kdf == hpke::KDF_HKDF_SHA256 && hpke::aead_for(*aead).is_some())
    }

    /// HPKE `info`: `"tls ech" || 0x00 || ECHConfig`.
    pub fn hpke_info(&self) -> Vec<u8> {
        let mut info = Vec::with_capacity(8 + self.raw.len());
        info.extend_from_slice(b"tls ech\0");
        info.extend_from_slice(&self.raw);
        info
    }
}

/// Parse an `ECHConfigList`, skipping versions other than 0xfe0d.
/// REQ-ECH-008: configuration and cipher-suite lists are nonempty, and
/// configuration extension types are unique (RFC 9849 sections 4 and 4.2).
pub fn parse_config_list(list: &[u8]) -> Result<Vec<EchConfig>> {
    let mut r = Reader::new(list);
    let mut body = r.sub16()?;
    r.finish()?;
    if body.is_empty() {
        return Err(bad("empty ECHConfigList"));
    }
    let mut out = Vec::new();
    while !body.is_empty() {
        let start = body.rest();
        let version = body.u16()?;
        let contents = body.vec16()?;
        let raw = &start[..4 + contents.len()];
        if version != ECH_VERSION {
            continue;
        }
        let mut c = Reader::new(contents);
        let config_id = c.u8()?;
        let kem_id = c.u16()?;
        let public_key = c.vec16()?.to_vec();
        if public_key.is_empty() {
            return Err(bad("ECHConfig with an empty public key"));
        }
        let mut suites_r = c.sub16()?;
        if suites_r.is_empty() {
            return Err(bad("ECHConfig with an empty cipher_suites list"));
        }
        let mut cipher_suites = Vec::new();
        while !suites_r.is_empty() {
            cipher_suites.push((suites_r.u16()?, suites_r.u16()?));
        }
        let maximum_name_length = c.u8()?;
        let name = c.vec8()?;
        let public_name = core::str::from_utf8(name)
            .ok()
            .filter(|n| !n.is_empty() && n.is_ascii())
            .ok_or(bad("ECHConfig public_name"))?;
        let mut exts = c.sub16()?;
        c.finish()?;
        let mut has_unknown_mandatory_extension = false;
        let mut extension_types = Vec::new();
        while !exts.is_empty() {
            let ty = exts.u16()?;
            let _ = exts.vec16()?;
            if extension_types.contains(&ty) {
                return Err(bad("duplicate ECHConfig extension"));
            }
            extension_types.push(ty);
            // The high bit marks an extension a client must understand.
            if ty & 0x8000 != 0 {
                has_unknown_mandatory_extension = true;
            }
        }
        out.push(EchConfig {
            raw: raw.to_vec(),
            config_id,
            kem_id,
            public_key,
            cipher_suites,
            maximum_name_length,
            public_name: String::from(public_name),
            has_unknown_mandatory_extension,
        });
    }
    Ok(out)
}

/// The first configuration in `list` this client can use, with its suite.
/// `REQ-ECH-004`: none usable is an error.
pub fn select_config(list: &[u8]) -> Result<(EchConfig, (u16, u16))> {
    parse_config_list(list)
        .map_err(|_| Error::new(ErrorKind::InvalidConfig, "ECHConfigList does not parse"))?
        .into_iter()
        .find_map(|c| c.usable_suite().map(|s| (c, s)))
        .ok_or(Error::new(
            ErrorKind::InvalidConfig,
            "no ECH configuration this build supports; refusing to send the server name in the clear",
        ))
}

/// Padding for an EncodedClientHelloInner (§6.1.3): hide the name's length up
/// to `maximum_name_length`, then round the whole to a multiple of 32.
pub fn padding_len(
    encoded_len: usize,
    server_name_len: Option<usize>,
    maximum_name_length: u8,
) -> usize {
    let l = match server_name_len {
        Some(n) => usize::from(maximum_name_length).saturating_sub(n),
        None => usize::from(maximum_name_length) + 9,
    };
    let total = encoded_len + l;
    let rounded = total.div_ceil(32) * 32;
    rounded - encoded_len
}

/// The acceptance confirmation (§7.2): the first 8 bytes of
/// `HKDF-Expand-Label(HKDF-Extract(0, inner_random), label, transcript_hash, 8)`.
pub fn confirmation(
    hash: HashAlg,
    inner_random: &[u8; 32],
    label: &[u8],
    transcript_hash: &[u8],
) -> Result<[u8; 8]> {
    let zeros = Output::zeros(hash.len());
    let prk = crypto::hkdf_extract(hash, zeros.as_bytes(), inner_random)?;
    let mut out = [0u8; 8];
    crypto::hkdf_expand_label(hash, prk.as_bytes(), label, transcript_hash, &mut out)?;
    Ok(out)
}

/// Label for the ServerHello confirmation.
pub const ACCEPT_LABEL: &[u8] = b"ech accept confirmation";
/// Label for the HelloRetryRequest confirmation.
pub const HRR_ACCEPT_LABEL: &[u8] = b"hrr ech accept confirmation";

/// A server's ECH keys and the `ECHConfigList` it publishes.
pub struct EchServer {
    entries: Vec<(EchConfig, KemKeyPair)>,
    list: Vec<u8>,
}

impl core::fmt::Debug for EchServer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "EchServer({} configs)", self.entries.len())
    }
}

impl EchServer {
    /// Generate one X25519 configuration for `public_name`, offering all three
    /// AEADs.
    pub fn generate(
        config_id: u8,
        public_name: &str,
        maximum_name_length: u8,
        rng: &mut dyn RandomSource,
    ) -> Result<Self> {
        let key = KemKeyPair::generate(rng)?;
        Self::from_key(config_id, public_name, maximum_name_length, key)
    }

    /// Build from an existing X25519 key.
    pub fn from_key(
        config_id: u8,
        public_name: &str,
        maximum_name_length: u8,
        key: KemKeyPair,
    ) -> Result<Self> {
        if public_name.is_empty() || public_name.len() > 255 || !public_name.is_ascii() {
            return Err(Error::new(ErrorKind::InvalidConfig, "ECH public_name"));
        }
        let mut contents = Vec::new();
        put_u8(&mut contents, config_id);
        put_u16(&mut contents, hpke::KEM_X25519_SHA256);
        put_vec(&mut contents, Prefix::U16, key.public())?;
        nested(&mut contents, Prefix::U16, |o| {
            for aead in [
                hpke::AEAD_AES_128_GCM,
                hpke::AEAD_AES_256_GCM,
                hpke::AEAD_CHACHA20_POLY1305,
            ] {
                put_u16(o, hpke::KDF_HKDF_SHA256);
                put_u16(o, aead);
            }
            Ok(())
        })?;
        put_u8(&mut contents, maximum_name_length);
        put_vec(&mut contents, Prefix::U8, public_name.as_bytes())?;
        put_u16(&mut contents, 0);
        let mut config = Vec::new();
        put_u16(&mut config, ECH_VERSION);
        put_vec(&mut config, Prefix::U16, &contents)?;
        let mut list = Vec::new();
        put_vec(&mut list, Prefix::U16, &config)?;
        let parsed = parse_config_list(&list)?
            .pop()
            .ok_or(Error::new(ErrorKind::Internal, "ECH config"))?;
        Ok(Self {
            entries: alloc::vec![(parsed, key)],
            list,
        })
    }

    /// The `ECHConfigList` to publish (and to send as `retry_configs`).
    pub fn config_list(&self) -> &[u8] {
        &self.list
    }

    /// The key for `config_id`, if its suite is supported.
    pub(crate) fn find(
        &self,
        config_id: u8,
        suite: (u16, u16),
    ) -> Option<(&EchConfig, &KemKeyPair)> {
        self.entries
            .iter()
            .find(|(c, _)| c.config_id == config_id && c.cipher_suites.contains(&suite))
            .map(|(c, k)| (c, k))
    }
}

/// `(type, body)` pairs of a raw extension block.
type RawExtensions<'a> = Vec<(u16, &'a [u8])>;

/// Raw `(type, body)` extension list of a ClientHello body, with the offset
/// of the extensions block.
fn raw_parts(body: &[u8]) -> Result<(usize, RawExtensions<'_>)> {
    let mut r = Reader::new(body);
    r.take(2 + 32)?;
    r.vec8()?;
    r.vec16()?;
    r.vec8()?;
    let at = body.len() - r.remaining();
    let mut block = r.sub16()?;
    let mut exts = Vec::new();
    while !block.is_empty() {
        exts.push((block.u16()?, block.vec16()?));
    }
    Ok((at, exts))
}

/// Rebuild the ClientHelloInner body from its encoding (§5.1): restore the
/// outer `legacy_session_id`, expand `ech_outer_extensions` from the outer
/// hello, and require the padding to be zero. `REQ-ECH-005`.
/// REQ-ECH-006: reject duplicate ech_outer_extensions before expansion can
/// erase them (RFC 9849 section 5.1 and RFC 8446 section 4.2).
pub fn reconstruct_inner(
    encoded: &[u8],
    outer_body: &[u8],
    outer_session_id: &[u8],
) -> Result<Vec<u8>> {
    let illegal = |c| Error::new(ErrorKind::IllegalParameter, c);
    let mut r = Reader::new(encoded);
    let head = r.take(2 + 32)?;
    if !r.vec8()?.is_empty() {
        return Err(illegal("EncodedClientHelloInner with a legacy_session_id"));
    }
    let suites = r.vec16()?;
    let comp = r.vec8()?;
    let mut block = r.sub16()?;
    if r.rest().iter().any(|b| *b != 0) {
        return Err(illegal("ClientHelloInner padding is not zero"));
    }
    let (_, outer_exts) = raw_parts(outer_body)?;
    let mut exts = Vec::new();
    let mut outer_at = 0usize;
    let mut saw_outer_extensions = false;
    while !block.is_empty() {
        let ty = block.u16()?;
        let body = block.vec16()?;
        if ty != EXT_ECH_OUTER_EXTENSIONS {
            exts.push((ty, body));
            continue;
        }
        if saw_outer_extensions {
            return Err(illegal("duplicate ech_outer_extensions"));
        }
        saw_outer_extensions = true;
        let mut refs = Reader::new(body);
        let mut list = refs.sub8()?;
        refs.finish()?;
        if list.is_empty() {
            return Err(illegal("empty ech_outer_extensions"));
        }
        while !list.is_empty() {
            let want = list.u16()?;
            if want == EXT_ECH {
                return Err(illegal(
                    "ech_outer_extensions references encrypted_client_hello",
                ));
            }
            // References must appear in the outer hello in the same order.
            let found = outer_exts[outer_at..]
                .iter()
                .position(|(t, _)| *t == want)
                .ok_or(illegal(
                    "ech_outer_extensions references a missing extension",
                ))?;
            outer_at += found;
            exts.push(outer_exts[outer_at]);
            outer_at += 1;
        }
    }
    let mut out = Vec::with_capacity(encoded.len() + 64);
    out.extend_from_slice(head);
    put_vec(&mut out, Prefix::U8, outer_session_id)?;
    put_vec(&mut out, Prefix::U16, suites)?;
    put_vec(&mut out, Prefix::U8, comp)?;
    nested(&mut out, Prefix::U16, |o| {
        for (ty, body) in &exts {
            put_u16(o, *ty);
            put_vec(o, Prefix::U16, body)?;
        }
        Ok(())
    })?;
    Ok(out)
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;

    #[test]
    fn a_generated_config_parses_and_is_usable() {
        let mut rng = ic_drbg::Rng::from_os().unwrap();
        let s = EchServer::generate(7, "public.test", 32, &mut rng).unwrap();
        let (c, suite) = select_config(s.config_list()).unwrap();
        assert_eq!(c.config_id, 7);
        assert_eq!(c.public_name, "public.test");
        assert_eq!(suite, (hpke::KDF_HKDF_SHA256, hpke::AEAD_AES_128_GCM));
        assert!(s.find(7, suite).is_some());
        assert!(s.find(8, suite).is_none());
    }

    /// REQ-ECH-004: an unusable configuration is an error.
    #[test]
    fn unusable_configurations_are_refused() {
        let mut rng = ic_drbg::Rng::from_os().unwrap();
        let s = EchServer::generate(1, "p.test", 0, &mut rng).unwrap();
        let mut list = s.config_list().to_vec();
        // Switch the KEM to P-256 (0x0010), which this build does not implement.
        list[8] = 0x10;
        assert_eq!(
            select_config(&list).unwrap_err().kind(),
            ErrorKind::InvalidConfig
        );
        // A mandatory extension the client does not understand.
        let mut contents = s.config_list()[6..].to_vec();
        let n = contents.len();
        contents[n - 2..].copy_from_slice(&[0, 4]);
        contents.extend_from_slice(&[0x80, 0x01, 0, 0]);
        let mut cfg = Vec::new();
        put_u16(&mut cfg, ECH_VERSION);
        put_vec(&mut cfg, Prefix::U16, &contents).unwrap();
        let mut l = Vec::new();
        put_vec(&mut l, Prefix::U16, &cfg).unwrap();
        assert!(parse_config_list(&l).unwrap()[0].has_unknown_mandatory_extension);
        assert!(select_config(&l).is_err());
        assert!(select_config(&[0, 0]).is_err());
    }

    #[test]
    fn padding_hides_the_name_length_and_rounds_to_32() {
        for name in [1usize, 5, 20, 31] {
            let a = 200 + padding_len(200, Some(name), 32);
            assert_eq!(a % 32, 0);
            assert!(a >= 200 + 32 - name);
        }
        assert_eq!((101 + padding_len(101, None, 0)) % 32, 0);
    }

    // RFC 9849 section 4's ECHConfigContents, with caller-controlled vectors.
    fn config_list_with(suites: &[u8], extensions: &[(u16, &[u8])]) -> Vec<u8> {
        let mut contents = alloc::vec![7];
        put_u16(&mut contents, hpke::KEM_X25519_SHA256);
        put_vec(&mut contents, Prefix::U16, &[9; 32]).unwrap();
        put_vec(&mut contents, Prefix::U16, suites).unwrap();
        put_u8(&mut contents, 0);
        put_vec(&mut contents, Prefix::U8, b"public.test").unwrap();
        nested(&mut contents, Prefix::U16, |out| {
            for &(ty, value) in extensions {
                put_u16(out, ty);
                put_vec(out, Prefix::U16, value)?;
            }
            Ok(())
        })
        .unwrap();
        let mut config = Vec::new();
        put_u16(&mut config, ECH_VERSION);
        put_vec(&mut config, Prefix::U16, &contents).unwrap();
        let mut list = Vec::new();
        put_vec(&mut list, Prefix::U16, &config).unwrap();
        list
    }

    /// REQ-ECH-008: nonempty wire lists can contain unsupported identifiers.
    #[test]
    fn ech_configuration_vectors_require_entries() {
        let err = parse_config_list(&[0, 0]).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Decode);
        assert!(err.to_string().contains("empty ECHConfigList"));
        assert_eq!(
            select_config(&[0, 0]).unwrap_err().kind(),
            ErrorKind::InvalidConfig
        );
        let err = parse_config_list(&config_list_with(&[], &[])).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Decode);
        assert!(err.to_string().contains("empty cipher_suites list"));
        for length in [1, 2, 3, 5, 6, 7] {
            assert_eq!(
                parse_config_list(&config_list_with(&alloc::vec![0; length], &[]))
                    .unwrap_err()
                    .kind(),
                ErrorKind::Decode
            );
        }
        let supported = [0, 1, 0, 1]; // HKDF-SHA256 and AES-128-GCM (RFC 9180).
        assert_eq!(
            parse_config_list(&config_list_with(&supported, &[])).unwrap()[0].cipher_suites,
            [(1, 1)]
        );
        let mixed = [0xbe, 0xef, 0xbe, 0xef, 0, 1, 0, 1];
        let list = config_list_with(&mixed, &[]);
        assert_eq!(
            parse_config_list(&list).unwrap()[0].cipher_suites,
            [(0xbeef, 0xbeef), (1, 1)]
        );
        assert_eq!(select_config(&list).unwrap().1, (1, 1));
        // A nonempty list with an unknown version and opaque contents remains
        // structurally valid; unsupported versions are skipped before decoding.
        assert!(parse_config_list(&[0, 5, 0xbe, 0xef, 0, 1, 7])
            .unwrap()
            .is_empty());
        assert_eq!(
            select_config(&[0, 5, 0xbe, 0xef, 0, 1, 7])
                .unwrap_err()
                .kind(),
            ErrorKind::InvalidConfig
        );
    }

    /// REQ-ECH-008: duplicate types are forbidden within a configuration,
    /// including unknown optional and mandatory types with different bodies.
    #[test]
    fn ech_configuration_extensions_require_unique_types() {
        let suites = [0, 1, 0, 1];
        for ty in [1, 0x8001, 0xffff] {
            for separated in [false, true] {
                let mut extensions: Vec<(u16, &[u8])> = alloc::vec![(ty, &[])];
                if separated {
                    extensions.push((2, b"other"));
                }
                extensions.push((ty, b"different"));
                let err = parse_config_list(&config_list_with(&suites, &extensions)).unwrap_err();
                assert_eq!(err.kind(), ErrorKind::Decode);
                assert!(err.to_string().contains("duplicate ECHConfig extension"));
            }
            let list = config_list_with(&suites, &[(ty, b"opaque"), (2, &[])]);
            let parsed = parse_config_list(&list).unwrap();
            assert_eq!(parsed[0].has_unknown_mandatory_extension, ty & 0x8000 != 0);
            if ty & 0x8000 == 0 {
                select_config(&list).unwrap();
            } else {
                assert_eq!(
                    select_config(&list).unwrap_err().kind(),
                    ErrorKind::InvalidConfig
                );
            }
            // The same type in separate configurations is allowed.
            let mut configs = list[2..].to_vec();
            configs.extend_from_slice(&list[2..]);
            let mut combined = Vec::new();
            put_vec(&mut combined, Prefix::U16, &configs).unwrap();
            assert_eq!(parse_config_list(&combined).unwrap().len(), 2);
        }
    }

    fn hello_body(session_id: &[u8], exts: &[(u16, &[u8])], pad: usize) -> Vec<u8> {
        let mut b = alloc::vec![3, 3];
        b.extend_from_slice(&[9; 32]);
        put_vec(&mut b, Prefix::U8, session_id).unwrap();
        put_vec(&mut b, Prefix::U16, &[0x13, 0x01]).unwrap();
        put_vec(&mut b, Prefix::U8, &[0]).unwrap();
        nested(&mut b, Prefix::U16, |o| {
            for (t, body) in exts {
                put_u16(o, *t);
                put_vec(o, Prefix::U16, body)?;
            }
            Ok(())
        })
        .unwrap();
        b.resize(b.len() + pad, 0);
        b
    }

    /// REQ-ECH-005.
    #[test]
    fn inner_reconstruction_expands_references_and_checks_padding() {
        let outer = hello_body(
            &[5; 32],
            &[
                (10, b"groups"),
                (13, b"sigs"),
                (EXT_ECH, b"x"),
                (51, b"shares"),
            ],
            0,
        );
        let encoded = hello_body(
            &[],
            &[
                (0, b"sni"),
                (EXT_ECH_OUTER_EXTENSIONS, &[4, 0, 10, 0, 51]),
                (EXT_ECH, &[1]),
            ],
            7,
        );
        let inner = reconstruct_inner(&encoded, &outer, &[5; 32]).unwrap();
        assert_eq!(
            inner,
            hello_body(
                &[5; 32],
                &[
                    (0, b"sni"),
                    (10, b"groups"),
                    (51, b"shares"),
                    (EXT_ECH, &[1])
                ],
                0
            )
        );
        let mut bad = encoded.clone();
        let n = bad.len();
        bad[n - 1] = 1;
        assert!(
            reconstruct_inner(&bad, &outer, &[5; 32]).is_err(),
            "nonzero padding accepted"
        );
        let wrong_order = hello_body(&[], &[(EXT_ECH_OUTER_EXTENSIONS, &[4, 0, 51, 0, 10])], 0);
        assert!(reconstruct_inner(&wrong_order, &outer, &[5; 32]).is_err());
        let self_ref = hello_body(&[], &[(EXT_ECH_OUTER_EXTENSIONS, &[2, 0xfe, 0x0d])], 0);
        assert!(reconstruct_inner(&self_ref, &outer, &[5; 32]).is_err());
        let with_sid = hello_body(&[1], &[], 0);
        assert!(reconstruct_inner(&with_sid, &outer, &[5; 32]).is_err());
    }

    /// REQ-ECH-006: disjoint references do not hide duplicate compression markers.
    #[test]
    fn inner_reconstruction_refuses_duplicate_compression_markers() {
        let outer = hello_body(&[5; 32], &[(10, b"groups"), (51, b"shares")], 0);
        for pad in [0, 7, 32] {
            for separated in [false, true] {
                let mut exts: Vec<(u16, &[u8])> =
                    alloc::vec![(EXT_ECH_OUTER_EXTENSIONS, &[2, 0, 10]),];
                if separated {
                    exts.push((0xbeef, b"opaque"));
                }
                exts.push((EXT_ECH_OUTER_EXTENSIONS, &[2, 0, 51]));
                exts.push((EXT_ECH, &[1]));
                let encoded = hello_body(&[], &exts, pad);
                let err = reconstruct_inner(&encoded, &outer, &[5; 32]).unwrap_err();
                assert_eq!(err.kind(), ErrorKind::IllegalParameter);
                assert!(err.to_string().contains("duplicate ech_outer_extensions"));
            }
            // One marker can reference both extensions, with or without padding.
            let encoded = hello_body(
                &[],
                &[
                    (EXT_ECH_OUTER_EXTENSIONS, &[4, 0, 10, 0, 51]),
                    (EXT_ECH, &[1]),
                ],
                pad,
            );
            assert_eq!(
                reconstruct_inner(&encoded, &outer, &[5; 32]).unwrap(),
                hello_body(
                    &[5; 32],
                    &[(10, b"groups"), (51, b"shares"), (EXT_ECH, &[1])],
                    0
                )
            );
            // No compression marker remains legal too.
            let encoded = hello_body(&[], &[(EXT_ECH, &[1])], pad);
            assert_eq!(
                reconstruct_inner(&encoded, &outer, &[5; 32]).unwrap(),
                hello_body(&[5; 32], &[(EXT_ECH, &[1])], 0)
            );
        }
    }
}
