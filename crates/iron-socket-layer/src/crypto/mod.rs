//! The seam between the protocol and IronCrypto.
//!
//! Nothing in IronSocketLayer implements a primitive. This module adapts
//! IronCrypto's hashes, HMAC, HKDF and AEADs to the shapes TLS 1.3 needs, and
//! is the only place in the crate that names an IronCrypto cipher or hash type
//! directly (key exchange and signatures live in [`kx`] and [`sign`]).
//!
//! Every function here reports the IronCrypto ontology identifiers of the
//! primitives it uses, so the FIPS gate in [`crate::policy`] can check them
//! with `ic_fips::check` before they run.

pub mod hpke;
pub mod kx;
pub mod sign;

use alloc::boxed::Box;
use alloc::vec::Vec;

use ic_core::traits::{Aead as _, BlockCipher as _, Digest as _, Mac as _};
use ic_core::Zeroize;

use crate::error::{Error, ErrorKind, Result};

/// Largest hash output any suite uses (SHA-384 uses 48; room for SHA-512).
pub const MAX_HASH_LEN: usize = 64;

/// The hash a cipher suite is defined over.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HashAlg {
    /// SHA-256.
    Sha256,
    /// SHA-384.
    Sha384,
}

impl HashAlg {
    /// Output length in bytes.
    #[allow(clippy::len_without_is_empty)]
    pub const fn len(self) -> usize {
        match self {
            Self::Sha256 => 32,
            Self::Sha384 => 48,
        }
    }

    /// IronCrypto ontology identifier of the hash.
    pub const fn ic_hash_id(self) -> &'static str {
        match self {
            Self::Sha256 => "sha2-256",
            Self::Sha384 => "sha2-384",
        }
    }

    /// IronCrypto ontology identifier of HMAC over this hash.
    pub const fn ic_hmac_id(self) -> &'static str {
        match self {
            Self::Sha256 => "hmac-sha2-256",
            Self::Sha384 => "hmac-sha2-384",
        }
    }

    /// IronCrypto ontology identifier of HKDF over this hash.
    pub const fn ic_hkdf_id(self) -> &'static str {
        match self {
            Self::Sha256 => "hkdf-sha2-256",
            Self::Sha384 => "hkdf-sha2-384",
        }
    }

    /// Hash `data` in one call.
    pub fn digest(self, data: &[u8]) -> Output {
        let mut h = Hash::new(self);
        h.update(data);
        h.finish()
    }
}

/// A hash or HMAC output, or a secret of hash length. Zeroized on drop.
#[derive(Clone)]
pub struct Output {
    bytes: [u8; MAX_HASH_LEN],
    len: usize,
}

impl Output {
    /// An output of `len` zero bytes; the "0" of RFC 8446 §7.1.
    pub fn zeros(len: usize) -> Self {
        Self {
            bytes: [0; MAX_HASH_LEN],
            len: len.min(MAX_HASH_LEN),
        }
    }

    /// Copy from a slice. Longer slices are an internal error.
    pub fn from_slice(s: &[u8]) -> Result<Self> {
        if s.len() > MAX_HASH_LEN {
            return Err(Error::new(
                ErrorKind::Internal,
                "secret longer than any hash",
            ));
        }
        let mut out = Self::zeros(s.len());
        out.bytes[..s.len()].copy_from_slice(s);
        Ok(out)
    }

    /// The bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    /// Length in bytes.
    pub fn len(&self) -> usize {
        self.len
    }

    /// True for a zero-length output.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl AsRef<[u8]> for Output {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl core::fmt::Debug for Output {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Never print secret material.
        write!(f, "Output({} bytes)", self.len)
    }
}

impl Drop for Output {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

/// A running hash; cloneable, so the transcript can be read mid-stream.
// SHA-384's state is larger than SHA-256's; boxing one would put an
// allocation on every transcript clone, which happens per message.
#[allow(clippy::large_enum_variant)]
#[derive(Clone)]
pub enum Hash {
    /// SHA-256 state.
    Sha256(ic_hash::Sha256),
    /// SHA-384 state.
    Sha384(ic_hash::Sha384),
}

impl Hash {
    /// A fresh hash.
    pub fn new(alg: HashAlg) -> Self {
        match alg {
            HashAlg::Sha256 => Self::Sha256(ic_hash::Sha256::new()),
            HashAlg::Sha384 => Self::Sha384(ic_hash::Sha384::new()),
        }
    }

    /// Which hash.
    pub fn alg(&self) -> HashAlg {
        match self {
            Self::Sha256(_) => HashAlg::Sha256,
            Self::Sha384(_) => HashAlg::Sha384,
        }
    }

    /// Absorb data.
    pub fn update(&mut self, data: &[u8]) {
        match self {
            Self::Sha256(h) => h.update(data),
            Self::Sha384(h) => h.update(data),
        }
    }

    /// Finish.
    pub fn finish(self) -> Output {
        let mut out = Output::zeros(self.alg().len());
        match self {
            Self::Sha256(h) => out.bytes[..32].copy_from_slice(h.finalize().as_ref()),
            Self::Sha384(h) => out.bytes[..48].copy_from_slice(h.finalize().as_ref()),
        }
        out
    }

    /// The digest so far, leaving the running state intact.
    pub fn peek(&self) -> Output {
        self.clone().finish()
    }
}

/// HMAC under `alg`.
pub fn hmac(alg: HashAlg, key: &[u8], parts: &[&[u8]]) -> Result<Output> {
    let mut out = Output::zeros(alg.len());
    match alg {
        HashAlg::Sha256 => {
            let mut m = ic_mac::HmacSha256::new(key)?;
            for p in parts {
                m.update(p);
            }
            out.bytes[..32].copy_from_slice(m.finalize().as_ref());
        }
        HashAlg::Sha384 => {
            let mut m = ic_mac::HmacSha384::new(key)?;
            for p in parts {
                m.update(p);
            }
            out.bytes[..48].copy_from_slice(m.finalize().as_ref());
        }
    }
    Ok(out)
}

/// HKDF-Extract (RFC 5869 §2.2).
pub fn hkdf_extract(alg: HashAlg, salt: &[u8], ikm: &[u8]) -> Result<Output> {
    let mut out = Output::zeros(alg.len());
    let len = alg.len();
    match alg {
        HashAlg::Sha256 => {
            ic_kdf::Hkdf::<ic_mac::HmacSha256>::extract(salt, ikm, &mut out.bytes[..len])?
        }
        HashAlg::Sha384 => {
            ic_kdf::Hkdf::<ic_mac::HmacSha384>::extract(salt, ikm, &mut out.bytes[..len])?
        }
    }
    Ok(out)
}

/// HKDF-Expand (RFC 5869 §2.3).
pub fn hkdf_expand(alg: HashAlg, prk: &[u8], info: &[u8], out: &mut [u8]) -> Result<()> {
    match alg {
        HashAlg::Sha256 => ic_kdf::Hkdf::<ic_mac::HmacSha256>::expand(prk, info, out)?,
        HashAlg::Sha384 => ic_kdf::Hkdf::<ic_mac::HmacSha384>::expand(prk, info, out)?,
    }
    Ok(())
}

/// Longest label HKDF-Expand-Label accepts: 255 minus the "tls13 " prefix.
pub const MAX_LABEL_LEN: usize = 255 - 6;

/// HKDF-Expand-Label (RFC 8446 §7.1). `REQ-KS-001`.
///
/// `label` is given without the `"tls13 "` prefix, which is added here. QUIC
/// labels (`"quic key"`) use the same function (RFC 9001 §5.1).
pub fn hkdf_expand_label(
    alg: HashAlg,
    secret: &[u8],
    label: &[u8],
    context: &[u8],
    out: &mut [u8],
) -> Result<()> {
    if label.len() > MAX_LABEL_LEN || context.len() > 255 || out.len() > 0xffff {
        return Err(Error::new(
            ErrorKind::Internal,
            "hkdf label parameters out of range",
        ));
    }
    // struct { uint16 length; opaque label<7..255>; opaque context<0..255>; }
    let mut info = [0u8; 514];
    info[..2].copy_from_slice(&(out.len() as u16).to_be_bytes());
    info[2] = (6 + label.len()) as u8;
    info[3..9].copy_from_slice(b"tls13 ");
    let end = 9 + label.len();
    info[9..end].copy_from_slice(label);
    info[end] = context.len() as u8;
    info[end + 1..end + 1 + context.len()].copy_from_slice(context);
    hkdf_expand(alg, secret, &info[..end + 1 + context.len()], out)
}

/// HKDF-Expand-Label producing a hash-length secret.
pub fn expand_label_secret(
    alg: HashAlg,
    secret: &[u8],
    label: &[u8],
    context: &[u8],
) -> Result<Output> {
    let mut out = Output::zeros(alg.len());
    let len = alg.len();
    hkdf_expand_label(alg, secret, label, context, &mut out.bytes[..len])?;
    Ok(out)
}

/// An AEAD algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AeadAlg {
    /// AES-128-GCM.
    Aes128Gcm,
    /// AES-256-GCM.
    Aes256Gcm,
    /// ChaCha20-Poly1305.
    ChaCha20Poly1305,
}

/// AEAD nonce length for every TLS 1.3 suite.
pub const NONCE_LEN: usize = 12;
/// AEAD tag length for every suite implemented here.
pub const TAG_LEN: usize = 16;

impl AeadAlg {
    /// Key length in bytes.
    pub const fn key_len(self) -> usize {
        match self {
            Self::Aes128Gcm => 16,
            Self::Aes256Gcm | Self::ChaCha20Poly1305 => 32,
        }
    }

    /// IronCrypto ontology identifier.
    pub const fn ic_id(self) -> &'static str {
        match self {
            Self::Aes128Gcm => "aes-128-gcm",
            Self::Aes256Gcm => "aes-256-gcm",
            Self::ChaCha20Poly1305 => "chacha20-poly1305",
        }
    }

    /// IronCrypto identifier of the header-protection primitive QUIC pairs
    /// with this AEAD (RFC 9001 §5.4.3, §5.4.4).
    pub const fn ic_header_protection_id(self) -> &'static str {
        match self {
            Self::Aes128Gcm => "aes-128",
            Self::Aes256Gcm => "aes-256",
            Self::ChaCha20Poly1305 => "chacha20-poly1305",
        }
    }

    /// Records one key may protect before it must be updated.
    ///
    /// AES-GCM: 2^24.5 full-size records (RFC 8446 §5.5), rounded down to
    /// 2^24 so the bound is a power of two a reviewer can check at a glance.
    /// ChaCha20-Poly1305: the sequence number space is the only limit that
    /// binds in practice; 2^62 keeps well clear of it.
    pub const fn confidentiality_limit(self) -> u64 {
        match self {
            Self::Aes128Gcm | Self::Aes256Gcm => 1 << 24,
            Self::ChaCha20Poly1305 => 1 << 62,
        }
    }

    /// Failed decryptions tolerated under one key before the connection must
    /// be closed (RFC 9001 §6.6). Record-layer TLS closes on the first.
    pub const fn integrity_limit(self) -> u64 {
        match self {
            Self::Aes128Gcm | Self::Aes256Gcm => 1 << 52,
            Self::ChaCha20Poly1305 => 1 << 36,
        }
    }
}

#[allow(clippy::large_enum_variant)]
enum AeadImpl {
    Aes128(ic_cipher::Aes128Gcm),
    Aes256(ic_cipher::Aes256Gcm),
    ChaCha(ic_cipher::ChaCha20Poly1305),
}

/// A keyed AEAD.
pub struct AeadKey {
    alg: AeadAlg,
    inner: AeadImpl,
}

impl core::fmt::Debug for AeadKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "AeadKey({:?})", self.alg)
    }
}

impl AeadKey {
    /// Key an AEAD.
    pub fn new(alg: AeadAlg, key: &[u8]) -> Result<Self> {
        if key.len() != alg.key_len() {
            return Err(Error::new(ErrorKind::Internal, "aead key length"));
        }
        let inner = match alg {
            AeadAlg::Aes128Gcm => AeadImpl::Aes128(ic_cipher::Aes128Gcm::new(key)?),
            AeadAlg::Aes256Gcm => AeadImpl::Aes256(ic_cipher::Aes256Gcm::new(key)?),
            AeadAlg::ChaCha20Poly1305 => AeadImpl::ChaCha(ic_cipher::ChaCha20Poly1305::new(key)?),
        };
        Ok(Self { alg, inner })
    }

    /// Which algorithm.
    pub fn alg(&self) -> AeadAlg {
        self.alg
    }

    /// Encrypt `in_out` in place and write the tag.
    pub fn seal(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        in_out: &mut [u8],
        tag: &mut [u8; TAG_LEN],
    ) -> Result<()> {
        match &self.inner {
            AeadImpl::Aes128(k) => k.seal_detached(nonce, aad, in_out, tag)?,
            AeadImpl::Aes256(k) => k.seal_detached(nonce, aad, in_out, tag)?,
            AeadImpl::ChaCha(k) => k.seal_detached(nonce, aad, in_out, tag)?,
        }
        Ok(())
    }

    /// Authenticate and decrypt `in_out` in place. On failure `in_out` must be
    /// treated as garbage.
    pub fn open(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        in_out: &mut [u8],
        tag: &[u8],
    ) -> Result<()> {
        let r = match &self.inner {
            AeadImpl::Aes128(k) => k.open_detached(nonce, aad, in_out, tag),
            AeadImpl::Aes256(k) => k.open_detached(nonce, aad, in_out, tag),
            AeadImpl::ChaCha(k) => k.open_detached(nonce, aad, in_out, tag),
        };
        r.map_err(|_| Error::new(ErrorKind::BadRecordMac, "aead authentication failed"))
    }
}

/// Derive the per-record nonce: the IV XORed with the left-padded sequence
/// number (RFC 8446 §5.3; RFC 9001 §5.3 uses the packet number the same way).
pub fn nonce_for(iv: &[u8; NONCE_LEN], seq: u64) -> [u8; NONCE_LEN] {
    let mut n = *iv;
    let s = seq.to_be_bytes();
    for (i, b) in s.iter().enumerate() {
        n[NONCE_LEN - 8 + i] ^= b;
    }
    n
}

/// A header-protection key (RFC 9001 §5.4).
pub enum HeaderProtectionKey {
    /// AES-128 in ECB on the sample.
    Aes128(Box<ic_cipher::Aes128>),
    /// AES-256 in ECB on the sample.
    Aes256(Box<ic_cipher::Aes256>),
    /// ChaCha20 keyed by the HP key, counter and nonce from the sample.
    ChaCha20(Box<[u8; 32]>),
}

impl core::fmt::Debug for HeaderProtectionKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("HeaderProtectionKey")
    }
}

impl Drop for HeaderProtectionKey {
    fn drop(&mut self) {
        if let Self::ChaCha20(k) = self {
            k.zeroize();
        }
    }
}

/// Length of the ciphertext sample header protection consumes.
pub const HP_SAMPLE_LEN: usize = 16;

impl HeaderProtectionKey {
    /// Key header protection for the AEAD `alg`.
    pub fn new(alg: AeadAlg, key: &[u8]) -> Result<Self> {
        if key.len() != alg.key_len() {
            return Err(Error::new(ErrorKind::Internal, "hp key length"));
        }
        Ok(match alg {
            AeadAlg::Aes128Gcm => Self::Aes128(Box::new(ic_cipher::Aes128::new(key)?)),
            AeadAlg::Aes256Gcm => Self::Aes256(Box::new(ic_cipher::Aes256::new(key)?)),
            AeadAlg::ChaCha20Poly1305 => {
                let mut k = Box::new([0u8; 32]);
                k.copy_from_slice(key);
                Self::ChaCha20(k)
            }
        })
    }

    /// The five-byte mask for `sample`.
    pub fn mask(&self, sample: &[u8]) -> Result<[u8; 5]> {
        if sample.len() != HP_SAMPLE_LEN {
            return Err(Error::new(
                ErrorKind::Decode,
                "header protection sample length",
            ));
        }
        let mut block = [0u8; 16];
        block.copy_from_slice(sample);
        match self {
            Self::Aes128(k) => k.encrypt_block(&mut block)?,
            Self::Aes256(k) => k.encrypt_block(&mut block)?,
            Self::ChaCha20(k) => {
                let counter = u32::from_le_bytes([sample[0], sample[1], sample[2], sample[3]]);
                let mut m = [0u8; 16];
                ic_cipher::chacha20_xor(&k[..], &sample[4..16], counter, &mut m)?;
                block = m;
            }
        }
        let mut out = [0u8; 5];
        out.copy_from_slice(&block[..5]);
        Ok(out)
    }
}

/// Variable-length secret bytes, zeroized on drop.
pub struct SecretVec(Vec<u8>);

impl SecretVec {
    /// Take ownership of `v`.
    pub fn new(v: Vec<u8>) -> Self {
        Self(v)
    }

    /// The bytes.
    pub fn get(&self) -> &[u8] {
        &self.0
    }

    /// The bytes, mutably.
    pub fn get_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl Clone for SecretVec {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl Drop for SecretVec {
    fn drop(&mut self) {
        self.0.as_mut_slice().zeroize();
    }
}

impl core::fmt::Debug for SecretVec {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "SecretVec({} bytes)", self.0.len())
    }
}

/// Fill `out` from `rng`.
pub fn fill_random(rng: &mut dyn ic_core::traits::RandomSource, out: &mut [u8]) -> Result<()> {
    rng.fill(out)
        .map_err(|_| Error::new(ErrorKind::Entropy, "random source failed"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// REQ-KS-001, REQ-QUIC-005: the protocol-to-crypto boundary validates
    /// TLS vector sizes and exact header-protection key/sample lengths.
    #[test]
    fn crypto_interface_length_bounds() {
        for (label, context, length) in [
            (vec![0; MAX_LABEL_LEN + 1], vec![], 32),
            (vec![], vec![0; 256], 32),
            (vec![], vec![], 65_536),
        ] {
            let mut output = vec![0x5a; length];
            assert_eq!(
                hkdf_expand_label(HashAlg::Sha256, &[0; 32], &label, &context, &mut output)
                    .unwrap_err()
                    .kind(),
                ErrorKind::Internal
            );
            assert!(output.iter().all(|b| *b == 0x5a));
        }
        hkdf_expand_label(
            HashAlg::Sha256,
            &[0; 32],
            &vec![0; MAX_LABEL_LEN],
            &[0; 255],
            &mut [0; 32],
        )
        .unwrap();
        for alg in [
            AeadAlg::Aes128Gcm,
            AeadAlg::Aes256Gcm,
            AeadAlg::ChaCha20Poly1305,
        ] {
            for length in [0, alg.key_len() - 1, alg.key_len() + 1] {
                assert_eq!(
                    HeaderProtectionKey::new(alg, &vec![0; length])
                        .unwrap_err()
                        .kind(),
                    ErrorKind::Internal
                );
            }
            let key = HeaderProtectionKey::new(alg, &vec![0; alg.key_len()]).unwrap();
            for length in [0, HP_SAMPLE_LEN - 1, HP_SAMPLE_LEN + 1] {
                assert_eq!(
                    key.mask(&vec![0; length]).unwrap_err().kind(),
                    ErrorKind::Decode
                );
            }
            key.mask(&[0; HP_SAMPLE_LEN]).unwrap();
        }
    }

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// RFC 9001 Appendix A.5: the ChaCha20-Poly1305 short-header packet.
    /// `secret` is the 1-RTT secret the appendix gives; key, IV, HP key and
    /// the next-generation secret below are the values it derives from it.
    /// The HP key matches the one IronCrypto's own QUIC tests check, which
    /// cross-checks this transcription.
    #[test]
    fn expand_label_matches_rfc9001_a5() {
        let secret = hex("9ac312a7f877468ebe69422748ad00a15443f18203a07d6060f688f30f21632b");
        let mut key = [0u8; 32];
        hkdf_expand_label(HashAlg::Sha256, &secret, b"quic key", b"", &mut key).unwrap();
        assert_eq!(
            key.to_vec(),
            hex("c6d98ff3441c3fe1b2182094f69caa2ed4b716b65488960a7a984979fb23e1c8")
        );
        let mut iv = [0u8; 12];
        hkdf_expand_label(HashAlg::Sha256, &secret, b"quic iv", b"", &mut iv).unwrap();
        assert_eq!(iv.to_vec(), hex("e0459b3474bdd0e44a41c144"));
        let mut hp = [0u8; 32];
        hkdf_expand_label(HashAlg::Sha256, &secret, b"quic hp", b"", &mut hp).unwrap();
        assert_eq!(
            hp.to_vec(),
            hex("25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4")
        );
        let mut ku = [0u8; 32];
        hkdf_expand_label(HashAlg::Sha256, &secret, b"quic ku", b"", &mut ku).unwrap();
        assert_eq!(
            ku.to_vec(),
            hex("1223504755036d556342ee9361d253421a826c9ecdf3c7148684b36b714881f9")
        );
    }

    /// RFC 9001 Appendix A.5 again: the header-protection mask for the
    /// sample, which exercises the ChaCha20 path end to end.
    #[test]
    fn chacha_header_protection_matches_rfc9001_a5() {
        let hp = HeaderProtectionKey::new(
            AeadAlg::ChaCha20Poly1305,
            &hex("25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4"),
        )
        .unwrap();
        let mask = hp.mask(&hex("5e5cd55c41f69080575d7999c25a5bfb")).unwrap();
        assert_eq!(mask.to_vec(), hex("aefefe7d03"));
    }

    #[test]
    fn nonce_xors_the_low_bytes() {
        let iv = [0u8; 12];
        let n = nonce_for(&iv, 0x0102);
        assert_eq!(&n[10..], &[1, 2]);
        assert_eq!(&n[..10], &[0; 10]);
    }

    #[test]
    fn aead_round_trips_and_detects_tampering() {
        for alg in [
            AeadAlg::Aes128Gcm,
            AeadAlg::Aes256Gcm,
            AeadAlg::ChaCha20Poly1305,
        ] {
            let key = AeadKey::new(alg, &vec![7u8; alg.key_len()]).unwrap();
            let nonce = [1u8; 12];
            let mut data = *b"attack at dawn";
            let mut tag = [0u8; 16];
            key.seal(&nonce, b"hdr", &mut data, &mut tag).unwrap();
            let mut copy = data;
            key.open(&nonce, b"hdr", &mut copy, &tag).unwrap();
            assert_eq!(&copy, b"attack at dawn");
            let mut bad = data;
            bad[0] ^= 1;
            assert_eq!(
                key.open(&nonce, b"hdr", &mut bad, &tag).unwrap_err().kind(),
                ErrorKind::BadRecordMac
            );
        }
    }
}
