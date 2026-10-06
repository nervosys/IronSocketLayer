//! The TLS 1.3 record layer (RFC 8446 §5).
//!
//! Framing, protection and deprotection. Handshake logic never touches a
//! sequence number or a nonce; it installs traffic secrets and hands content
//! over, and this module does the rest.
//!
//! Requirement trace:
//! `REQ-REC-001` a sequence number never wraps: the key is exhausted first,
//! `REQ-REC-002` per-record nonce is `iv XOR seq` (§5.3),
//! `REQ-REC-003` the additional data is the record header (§5.2),
//! `REQ-REC-004` plaintext ≤ 2^14, ciphertext ≤ 2^14 + 256 (§5.1, §5.2),
//! `REQ-REC-005` an all-zero inner plaintext is `unexpected_message`,
//! `REQ-REC-006` AES-GCM keys are retired before 2^24 records (§5.5).

use alloc::vec::Vec;

use crate::crypto::{self, AeadAlg, AeadKey, HashAlg, Output, NONCE_LEN, TAG_LEN};
use crate::enums::{CipherSuite, ContentType};
use crate::error::{Error, ErrorKind, Result};
use crate::key_schedule;

/// Largest plaintext fragment (§5.1).
pub const MAX_PLAINTEXT: usize = 1 << 14;
/// Largest protected record body (§5.2).
pub const MAX_CIPHERTEXT: usize = MAX_PLAINTEXT + 256;
/// Record header length.
pub const HEADER_LEN: usize = 5;

/// The AEAD and hash a TLS 1.3 suite uses, or `None` if not implemented.
pub fn suite_params(suite: CipherSuite) -> Option<(AeadAlg, HashAlg)> {
    Some(match suite {
        CipherSuite::TlsAes128GcmSha256 => (AeadAlg::Aes128Gcm, HashAlg::Sha256),
        CipherSuite::TlsAes256GcmSha384 => (AeadAlg::Aes256Gcm, HashAlg::Sha384),
        CipherSuite::TlsChaCha20Poly1305Sha256 => (AeadAlg::ChaCha20Poly1305, HashAlg::Sha256),
        _ => return None,
    })
}

/// Suites this build implements, default preference order.
pub const IMPLEMENTED_SUITES: &[CipherSuite] = &[
    CipherSuite::TlsAes128GcmSha256,
    CipherSuite::TlsAes256GcmSha384,
    CipherSuite::TlsChaCha20Poly1305Sha256,
];

/// One direction's protection state.
pub struct Protector {
    key: AeadKey,
    iv: [u8; NONCE_LEN],
    seq: u64,
    hash: HashAlg,
    secret: Output,
}

/// REQ-REC-009: the static IV is key material (it fixes every nonce), so it
/// is wiped with the key when the direction is dropped or rekeyed; the key
/// and traffic secret wipe themselves.
impl Drop for Protector {
    fn drop(&mut self) {
        ic_core::Zeroize::zeroize(&mut self.iv[..]);
    }
}

impl core::fmt::Debug for Protector {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Protector({:?}, seq {})", self.key.alg(), self.seq)
    }
}

impl Protector {
    /// Key a direction from a traffic secret.
    pub fn new(suite: CipherSuite, secret: &Output) -> Result<Self> {
        let (aead, hash) = suite_params(suite).ok_or(Error::new(ErrorKind::Internal, "suite"))?;
        let mut key = ic_core::Zeroizing::new([0u8; 32]);
        crypto::hkdf_expand_label(
            hash,
            secret.as_bytes(),
            b"key",
            b"",
            &mut key.get_mut()[..aead.key_len()],
        )?;
        let mut iv = [0u8; NONCE_LEN];
        crypto::hkdf_expand_label(hash, secret.as_bytes(), b"iv", b"", &mut iv)?;
        Ok(Self {
            key: AeadKey::new(aead, &key.get()[..aead.key_len()])?,
            iv,
            seq: 0,
            hash,
            secret: secret.clone(),
        })
    }

    /// The traffic secret this key was derived from.
    pub(crate) fn secret(&self) -> &Output {
        &self.secret
    }

    /// Records protected so far under this key.
    pub fn seq(&self) -> u64 {
        self.seq
    }

    #[cfg(test)]
    pub(crate) fn set_seq_for_test(&mut self, seq: u64) {
        self.seq = seq;
    }

    /// Whether the key has reached its confidentiality limit. `REQ-REC-006`.
    pub fn exhausted(&self) -> bool {
        self.seq >= self.key.alg().confidentiality_limit()
    }

    /// Whether the key is close enough to its limit that a KeyUpdate is due.
    pub fn update_due(&self) -> bool {
        self.seq
            >= self.key.alg().confidentiality_limit()
                - (1 << 16).min(self.key.alg().confidentiality_limit() / 2)
    }

    /// Derive the next generation (§7.2), resetting the sequence number.
    pub fn next_generation(&self, suite: CipherSuite) -> Result<Self> {
        let next = key_schedule::next_traffic_secret(self.hash, self.secret.as_bytes())?;
        Self::new(suite, &next)
    }

    fn next_nonce(&mut self) -> Result<[u8; NONCE_LEN]> {
        // REQ-REC-001.
        if self.exhausted() || self.seq == u64::MAX {
            return Err(Error::new(
                ErrorKind::KeyExhausted,
                "traffic key reached its record limit",
            ));
        }
        let n = crypto::nonce_for(&self.iv, self.seq);
        self.seq += 1;
        Ok(n)
    }

    /// Protect `content` of `ty`, appending the record to `out`.
    ///
    /// `pad` zero bytes are appended to the inner plaintext to hide length.
    pub fn seal(
        &mut self,
        ty: ContentType,
        content: &[u8],
        pad: usize,
        out: &mut Vec<u8>,
    ) -> Result<()> {
        if content.len() > MAX_PLAINTEXT {
            return Err(Error::new(ErrorKind::Internal, "fragment exceeds 2^14"));
        }
        let pad = pad.min(MAX_PLAINTEXT - content.len());
        let inner_len = content.len() + 1 + pad;
        let body_len = inner_len + TAG_LEN;
        let nonce = self.next_nonce()?;
        // One allocation for the whole record: growing piecemeal would copy
        // the content again when the tag no longer fits.
        out.reserve(HEADER_LEN + body_len);
        let start = out.len();
        out.push(ContentType::ApplicationData.to_wire());
        out.extend_from_slice(&[0x03, 0x03]);
        out.extend_from_slice(&(body_len as u16).to_be_bytes());
        out.extend_from_slice(content);
        out.push(ty.to_wire());
        out.resize(out.len() + pad, 0);
        let mut header = [0u8; HEADER_LEN];
        header.copy_from_slice(&out[start..start + HEADER_LEN]);
        let mut tag = [0u8; TAG_LEN];
        let body = &mut out[start + HEADER_LEN..];
        // REQ-REC-002, REQ-REC-003.
        self.key.seal(&nonce, &header, body, &mut tag)?;
        out.extend_from_slice(&tag);
        Ok(())
    }

    /// Protect into a caller's slice without allocating. `REQ-FIX-001`.
    /// Insufficient storage does not consume a sequence number.
    pub fn seal_into(
        &mut self,
        ty: ContentType,
        content: &[u8],
        pad: usize,
        out: &mut [u8],
    ) -> Result<usize> {
        if content.len() > MAX_PLAINTEXT {
            return Err(Error::new(
                ErrorKind::RecordOverflow,
                "fragment exceeds 2^14",
            ));
        }
        let pad = pad.min(MAX_PLAINTEXT - content.len());
        let inner_len = content.len() + 1 + pad;
        let body_len = inner_len + TAG_LEN;
        let total = HEADER_LEN + body_len;
        let out = out.get_mut(..total).ok_or(Error::new(
            ErrorKind::CapacityExceeded,
            "record output capacity",
        ))?;
        let nonce = self.next_nonce()?;
        let header = [
            ContentType::ApplicationData.to_wire(),
            3,
            3,
            (body_len >> 8) as u8,
            body_len as u8,
        ];
        out[..HEADER_LEN].copy_from_slice(&header);
        let (body, tag_out) = out[HEADER_LEN..].split_at_mut(inner_len);
        body[..content.len()].copy_from_slice(content);
        body[content.len()] = ty.to_wire();
        body[content.len() + 1..].fill(0);
        let mut tag = [0u8; TAG_LEN];
        self.key.seal(&nonce, &header, body, &mut tag)?;
        tag_out.copy_from_slice(&tag);
        Ok(total)
    }

    /// Deprotect a record body in place, returning the inner type and the
    /// length of the content (at the front of `body`).
    pub fn open(
        &mut self,
        header: &[u8; HEADER_LEN],
        body: &mut [u8],
    ) -> Result<(ContentType, usize)> {
        if body.len() > MAX_CIPHERTEXT {
            return Err(Error::new(
                ErrorKind::RecordOverflow,
                "protected record exceeds 2^14 + 256",
            ));
        }
        if body.len() < TAG_LEN + 1 {
            return Err(Error::new(
                ErrorKind::BadRecordMac,
                "protected record shorter than its tag",
            ));
        }
        // The sequence number advances only on success, so a record skipped
        // as undecryptable (rejected 0-RTT) does not desynchronise the next.
        if self.exhausted() || self.seq == u64::MAX {
            return Err(Error::new(
                ErrorKind::KeyExhausted,
                "traffic key reached its record limit",
            ));
        }
        let nonce = crypto::nonce_for(&self.iv, self.seq);
        let (ct, tag) = body.split_at_mut(body.len() - TAG_LEN);
        self.key.open(&nonce, header, ct, tag)?;
        self.seq += 1;
        // Strip padding: the content type is the last non-zero byte.
        let end = content_end(ct);
        if end == 0 {
            // REQ-REC-005.
            return Err(Error::new(
                ErrorKind::UnexpectedMessage,
                "record with no content type",
            ));
        }
        let ty = ContentType::from_wire(ct[end - 1]);
        let len = end - 1;
        if len > MAX_PLAINTEXT {
            return Err(Error::new(
                ErrorKind::RecordOverflow,
                "inner plaintext exceeds 2^14",
            ));
        }
        Ok((ty, len))
    }
}

/// A complete record lifted off the wire.
#[derive(Debug)]
pub struct RawRecord {
    /// The five header bytes.
    pub header: [u8; HEADER_LEN],
    /// The body.
    pub body: Vec<u8>,
}

impl RawRecord {
    /// Outer content type.
    pub fn content_type(&self) -> ContentType {
        ContentType::from_wire(self.header[0])
    }
}

/// One past the last non-zero byte of a decrypted inner plaintext, or 0.
///
/// The whole buffer is scanned with no branch on its contents, so how long
/// this takes depends on the record's length, which is on the wire anyway,
/// and not on how much of it is padding, which is what padding hides.
/// Scanning backwards and stopping early would reveal the content length to
/// anyone who can time it. `REQ-REC-007`.
///
/// It follows IronCrypto's constant-time convention: every data-dependent
/// decision is an `ic_core::ct::Choice` built arithmetically and released
/// only through `black_box`, so the compiler cannot turn a mask back into a
/// branch. `leading_zeros` is avoided, since without LZCNT (and on cores with
/// no count-leading-zeros instruction) it need not be constant time. For
/// speed the scan goes a 32-byte block at a time, keeping the last block with
/// a non-zero byte, and searches inside that one block at the end: about
/// 0.8 µs per 16 KiB record on Zen 5, where a per-byte select took 5 µs.
///
/// Kept out of line so that its machine code can be audited on its own:
/// `cargo rustc -p ironsocketlayer --release -- --emit asm`, then look for
/// `content_end`. On x86-64 the only branches are on the length (the loop,
/// the tail copy, and the overflow check on the public block offset).
#[inline(never)]
fn content_end(inner: &[u8]) -> usize {
    use ic_core::ct::{self, Choice};

    const LOW7: u64 = 0x7f7f_7f7f_7f7f_7f7f;
    // Whether any byte of `v` is non-zero.
    fn any(v: u64) -> Choice {
        let v = v | (v >> 32);
        let v = v | (v >> 16);
        let v = v | (v >> 8);
        Choice::from_u8(v as u8)
    }
    // The top bit of each byte set exactly when that byte is non-zero. No
    // carry crosses a byte: (b & 0x7f) + 0x7f is at most 0xfe.
    fn marks(w: u64) -> u64 {
        ((w & LOW7).wrapping_add(LOW7) | w) & !LOW7
    }

    let mut last = [0u64; 4];
    let mut last_base = 0u32;
    let mut step = |block: &[u8; 32], base: u32| {
        let mut m4 = [0u64; 4];
        for (k, m) in m4.iter_mut().enumerate() {
            let mut w = [0u8; 8];
            w.copy_from_slice(&block[8 * k..8 * k + 8]);
            *m = marks(u64::from_le_bytes(w));
        }
        let m = u64::from(any(m4[0] | m4[1] | m4[2] | m4[3]).unwrap_u8()).wrapping_neg();
        for (l, n) in last.iter_mut().zip(m4) {
            *l ^= m & (n ^ *l);
        }
        last_base ^= (m as u32) & (base ^ last_base);
    };
    // `inner` is at most MAX_CIPHERTEXT bytes, checked by the caller, so
    // offsets fit a u32.
    let mut base = 0u32;
    // Kept as reviewed: this loop's Cortex-M4 assembly and its timing were
    // checked (see the verification report), so it is not rewritten to
    // satisfy a style lint.
    #[allow(clippy::chunks_exact_to_as_chunks)]
    let mut blocks = inner.chunks_exact(32);
    for block in &mut blocks {
        let mut b = [0u8; 32];
        b.copy_from_slice(block);
        step(&b, base);
        base += 32;
    }
    // The tail, zero-extended: the added zeros count as padding.
    let rest = blocks.remainder();
    let mut b = [0u8; 32];
    b[..rest.len()].copy_from_slice(rest);
    step(&b, base);

    // In the last non-zero block: the last non-zero word, then its highest
    // non-zero byte, by branch-free binary search.
    let hi = any(last[2] | last[3]);
    let lo_pair = ct::select_u64(hi, last[2], last[0]);
    let hi_pair = ct::select_u64(hi, last[3], last[1]);
    // Sums of secret-derived positions use wrapping arithmetic: they are far
    // below 2^32, and a checked add would compile to a branch on them.
    let mut pos = ct::select_u32(hi, 16, 0);
    let hi = any(hi_pair);
    let mut x = ct::select_u64(hi, hi_pair, lo_pair);
    pos = ct::select_u32(hi, pos.wrapping_add(8), pos);
    for shift in [32u32, 16, 8] {
        let hi = any(x >> shift);
        pos = ct::select_u32(hi, pos.wrapping_add(shift / 8), pos);
        x = ct::select_u64(hi, x >> shift, x);
    }
    let found = any(last[0] | last[1] | last[2] | last[3]);
    ct::select_u32(found, last_base.wrapping_add(pos).wrapping_add(1), 0) as usize
}

/// Validate the record header at the front of `buf` and return it with the
/// body length, if the whole record is present. `REQ-REC-004`.
pub(crate) fn peek_record(buf: &[u8]) -> Result<Option<([u8; HEADER_LEN], usize)>> {
    if buf.len() < HEADER_LEN {
        return Ok(None);
    }
    let ty = ContentType::from_wire(buf[0]);
    if matches!(ty, ContentType::Unknown(_) | ContentType::Invalid) {
        return Err(Error::new(
            ErrorKind::UnexpectedMessage,
            "unknown record content type",
        ));
    }
    // legacy_record_version: 0x0303, or 0x0301 on an initial ClientHello.
    if buf[1] != 0x03 || !(0x01..=0x03).contains(&buf[2]) {
        return Err(Error::new(ErrorKind::Decode, "record version is not TLS"));
    }
    let len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    if len > MAX_CIPHERTEXT {
        return Err(Error::new(
            ErrorKind::RecordOverflow,
            "record exceeds 2^14 + 256",
        ));
    }
    if len == 0 && ty != ContentType::ApplicationData {
        return Err(Error::new(ErrorKind::Decode, "zero-length record"));
    }
    if buf.len() < HEADER_LEN + len {
        return Ok(None);
    }
    let mut header = [0u8; HEADER_LEN];
    header.copy_from_slice(&buf[..HEADER_LEN]);
    Ok(Some((header, len)))
}

/// Take one complete record off the front of `buf`, if present. `REQ-REC-004`.
pub fn take_record(buf: &mut Vec<u8>) -> Result<Option<RawRecord>> {
    let Some((header, len)) = peek_record(buf)? else {
        return Ok(None);
    };
    let body = buf[HEADER_LEN..HEADER_LEN + len].to_vec();
    buf.drain(..HEADER_LEN + len);
    Ok(Some(RawRecord { header, body }))
}

/// Append a plaintext record (before keys exist).
pub fn write_plaintext(ty: ContentType, content: &[u8], out: &mut Vec<u8>) {
    for chunk in content.chunks(MAX_PLAINTEXT) {
        out.push(ty.to_wire());
        out.extend_from_slice(&[0x03, 0x03]);
        out.extend_from_slice(&(chunk.len() as u16).to_be_bytes());
        out.extend_from_slice(chunk);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// REQ-REC-007: empirical Welch comparison of equal-length records with
    /// short and long padding. This host measurement is evidence, not proof
    /// of constant-time execution. Run an optimized build on a quiet machine.
    #[test]
    #[ignore = "statistical timing experiment; run in release mode on an idle host"]
    fn padding_scan_timing_experiment() {
        use std::time::Instant;
        let mut rng = ic_drbg::Rng::from_os().unwrap();
        let mut classes = [vec![0u8; 16_384], vec![0u8; 16_384]];
        classes[0][0] = 23;
        classes[1][16_383] = 23;
        for class in &classes {
            for _ in 0..1000 {
                core::hint::black_box(content_end(core::hint::black_box(class)));
            }
        }
        let mut count = [0u32; 2];
        let mut mean = [0f64; 2];
        let mut m2 = [0f64; 2];
        for _ in 0..20_000 {
            let mut choice = [0u8; 1];
            rng.fill(&mut choice).unwrap();
            let class = usize::from(choice[0] & 1);
            let input = &classes[class];
            let start = Instant::now();
            for _ in 0..64 {
                core::hint::black_box(content_end(core::hint::black_box(input)));
            }
            let elapsed = start.elapsed().as_nanos() as f64 / 64.0;
            count[class] += 1;
            let delta = elapsed - mean[class];
            mean[class] += delta / f64::from(count[class]);
            m2[class] += delta * (elapsed - mean[class]);
        }
        let variance = [
            m2[0] / f64::from(count[0] - 1),
            m2[1] / f64::from(count[1] - 1),
        ];
        let denominator =
            (variance[0] / f64::from(count[0]) + variance[1] / f64::from(count[1])).sqrt();
        assert!(denominator > 0.0);
        let t = (mean[0] - mean[1]) / denominator;
        println!("padding scan: samples={count:?}, mean_ns={mean:?}, Welch_t={t:.4}");
        assert!(
            t.abs() < 4.5,
            "timing difference detected; investigate and repeat on an idle host"
        );
    }

    fn pair(suite: CipherSuite) -> (Protector, Protector) {
        let secret =
            Output::from_slice(&[0x42; 48][..suite_params(suite).unwrap().1.len()]).unwrap();
        (
            Protector::new(suite, &secret).unwrap(),
            Protector::new(suite, &secret).unwrap(),
        )
    }

    #[test]
    fn records_round_trip_with_padding_for_every_suite() {
        for &suite in IMPLEMENTED_SUITES {
            let (mut w, mut r) = pair(suite);
            for pad in [0usize, 1, 100] {
                let mut wire = Vec::new();
                w.seal(ContentType::Handshake, b"hello", pad, &mut wire)
                    .unwrap();
                let rec = take_record(&mut wire).unwrap().unwrap();
                assert_eq!(rec.content_type(), ContentType::ApplicationData);
                let mut body = rec.body.clone();
                let (ty, n) = r.open(&rec.header, &mut body).unwrap();
                assert_eq!(ty, ContentType::Handshake);
                assert_eq!(&body[..n], b"hello");
            }
        }
    }

    #[test]
    fn a_modified_header_fails_authentication() {
        let (mut w, mut r) = pair(CipherSuite::TlsAes128GcmSha256);
        let mut wire = Vec::new();
        w.seal(ContentType::ApplicationData, b"x", 0, &mut wire)
            .unwrap();
        let rec = take_record(&mut wire).unwrap().unwrap();
        let mut header = rec.header;
        header[2] = 0x01;
        let mut body = rec.body.clone();
        assert_eq!(
            r.open(&header, &mut body).unwrap_err().kind(),
            ErrorKind::BadRecordMac
        );
    }

    #[test]
    fn a_replayed_record_fails_because_the_sequence_advanced() {
        let (mut w, mut r) = pair(CipherSuite::TlsChaCha20Poly1305Sha256);
        let mut wire = Vec::new();
        w.seal(ContentType::ApplicationData, b"once", 0, &mut wire)
            .unwrap();
        let rec = take_record(&mut wire).unwrap().unwrap();
        let mut b1 = rec.body.clone();
        r.open(&rec.header, &mut b1).unwrap();
        let mut b2 = rec.body.clone();
        assert!(r.open(&rec.header, &mut b2).is_err());
    }

    #[test]
    fn oversized_and_malformed_records_are_refused() {
        let mut buf = alloc::vec![23, 3, 3, 0x48, 0x01];
        assert_eq!(
            take_record(&mut buf).unwrap_err().kind(),
            ErrorKind::RecordOverflow
        );
        let mut buf = alloc::vec![99, 3, 3, 0, 1, 0];
        assert!(take_record(&mut buf).is_err());
        let mut buf = alloc::vec![22, 3, 3, 0, 4, 1];
        assert!(take_record(&mut buf).unwrap().is_none());
    }

    /// `REQ-FIX-001`: sealing into a caller's slice produces the same record
    /// as the allocating path, and a slice one byte short is refused without
    /// consuming a sequence number or writing past the check.
    #[test]
    fn seal_into_matches_seal_and_refuses_short_output() {
        for &suite in IMPLEMENTED_SUITES {
            let (mut owned, _) = pair(suite);
            let (mut fixed, mut r) = pair(suite);
            for (content, pad) in [(&b""[..], 0), (&b"hello"[..], 7), (&[0xA5; 300][..], 0)] {
                let mut wire = Vec::new();
                owned
                    .seal(ContentType::Handshake, content, pad, &mut wire)
                    .unwrap();
                let mut short = vec![0u8; wire.len() - 1];
                let seq = fixed.seq();
                assert_eq!(
                    fixed
                        .seal_into(ContentType::Handshake, content, pad, &mut short)
                        .unwrap_err()
                        .kind(),
                    ErrorKind::CapacityExceeded
                );
                assert_eq!(fixed.seq(), seq, "a refused seal must not use a nonce");
                assert!(short.iter().all(|&b| b == 0));
                let mut out = vec![0u8; wire.len() + 3];
                let n = fixed
                    .seal_into(ContentType::Handshake, content, pad, &mut out)
                    .unwrap();
                assert_eq!(&out[..n], &wire[..]);
                let header: [u8; HEADER_LEN] = out[..HEADER_LEN].try_into().unwrap();
                let (ty, len) = r.open(&header, &mut out[HEADER_LEN..n]).unwrap();
                assert_eq!(
                    (ty, &out[HEADER_LEN..HEADER_LEN + len]),
                    (ContentType::Handshake, content)
                );
            }
            let mut out = vec![0u8; MAX_CIPHERTEXT + HEADER_LEN];
            assert_eq!(
                fixed
                    .seal_into(
                        ContentType::ApplicationData,
                        &vec![0; MAX_PLAINTEXT + 1],
                        0,
                        &mut out
                    )
                    .unwrap_err()
                    .kind(),
                ErrorKind::RecordOverflow
            );
        }
    }

    /// REQ-REC-001, REQ-REC-004, REQ-REC-006: callers of the record API get
    /// the same size and exhaustion checks as connections using the framer.
    #[test]
    fn record_boundaries_are_checked_directly() {
        for &suite in IMPLEMENTED_SUITES {
            let (mut w, mut r) = pair(suite);
            let mut wire = Vec::new();
            assert_eq!(
                w.seal(
                    ContentType::ApplicationData,
                    &vec![0; MAX_PLAINTEXT + 1],
                    0,
                    &mut wire
                )
                .unwrap_err()
                .kind(),
                ErrorKind::Internal
            );
            assert!(wire.is_empty());
            let header = [23, 3, 3, 0, 0];
            assert_eq!(
                r.open(&header, &mut vec![0; MAX_CIPHERTEXT + 1])
                    .unwrap_err()
                    .kind(),
                ErrorKind::RecordOverflow
            );
            for length in 0..=TAG_LEN {
                assert_eq!(
                    r.open(&header, &mut vec![0; length]).unwrap_err().kind(),
                    ErrorKind::BadRecordMac
                );
            }
            // Refuse before AEAD processing, on both encryption and decryption.
            let limit = w.key.alg().confidentiality_limit();
            for sequence in [limit, u64::MAX] {
                w.set_seq_for_test(sequence);
                r.set_seq_for_test(sequence);
                assert_eq!(
                    w.seal(ContentType::ApplicationData, b"x", 0, &mut wire)
                        .unwrap_err()
                        .kind(),
                    ErrorKind::KeyExhausted
                );
                assert_eq!(
                    r.open(&header, &mut [0; TAG_LEN + 1]).unwrap_err().kind(),
                    ErrorKind::KeyExhausted
                );
                assert!(wire.is_empty());
            }
        }
    }

    /// REQ-REC-001, REQ-REC-006: the key is retired at its limit, before the
    /// sequence number could wrap, and a KeyUpdate is due well before that.
    #[test]
    fn sequence_exhaustion_refuses_before_wrapping() {
        let (mut w, _) = pair(CipherSuite::TlsAes128GcmSha256);
        let limit = AeadAlg::Aes128Gcm.confidentiality_limit();
        w.set_seq_for_test(limit - (1 << 16));
        assert!(w.update_due());
        assert!(!w.exhausted());
        w.set_seq_for_test(limit - 1);
        let mut out = Vec::new();
        w.seal(ContentType::ApplicationData, b"last", 0, &mut out)
            .unwrap();
        assert!(w.exhausted());
        assert_eq!(
            w.seal(ContentType::ApplicationData, b"x", 0, &mut out)
                .unwrap_err()
                .kind(),
            ErrorKind::KeyExhausted
        );
        let (mut c, _) = pair(CipherSuite::TlsChaCha20Poly1305Sha256);
        c.set_seq_for_test(u64::MAX);
        assert_eq!(
            c.seal(ContentType::ApplicationData, b"x", 0, &mut out)
                .unwrap_err()
                .kind(),
            ErrorKind::KeyExhausted
        );
    }

    /// REQ-REC-005: a record whose inner plaintext is all zeros has no
    /// content type and is `unexpected_message`.
    #[test]
    fn an_all_zero_inner_plaintext_is_unexpected() {
        let (mut w, mut r) = pair(CipherSuite::TlsAes256GcmSha384);
        let mut wire = Vec::new();
        w.seal(ContentType::Invalid, b"", 7, &mut wire).unwrap();
        let rec = take_record(&mut wire).unwrap().unwrap();
        let mut body = rec.body.clone();
        assert_eq!(
            r.open(&rec.header, &mut body).unwrap_err().kind(),
            ErrorKind::UnexpectedMessage
        );
    }

    /// REQ-REC-007: the branch-free scan finds the same end as the obvious
    /// backward scan, and padding of every length round-trips.
    #[test]
    fn padding_of_every_length_is_removed_exactly() {
        let backward = |b: &[u8]| {
            let mut end = b.len();
            while end > 0 && b[end - 1] == 0 {
                end -= 1;
            }
            end
        };
        let mut cases: Vec<Vec<u8>> =
            vec![vec![], vec![0], vec![1], vec![0, 0, 0], vec![0x80, 0, 0]];
        // Every short length with the padding starting at every position, and
        // a lone non-zero byte in every position: all word/remainder splits.
        for len in 0..=70usize {
            for zeros_from in 0..=len {
                let mut v: Vec<u8> = (0..len).map(|i| (i * 37 % 255 + 1) as u8).collect();
                v[zeros_from..].fill(0);
                cases.push(v);
                for value in [0x01, 0x7f, 0x80, 0xff] {
                    let mut lone = vec![0u8; len];
                    if zeros_from < len {
                        lone[zeros_from] = value;
                    }
                    cases.push(lone);
                }
            }
        }
        for len in [1usize, 2, 15, 16, 17, 31, 32, 33, 255, 4096, 16_385] {
            for zeros_from in [0, len / 2, len.saturating_sub(1), len] {
                let mut v: Vec<u8> = (0..len).map(|i| (i % 255 + 1) as u8).collect();
                v[zeros_from..].fill(0);
                cases.push(v.clone());
                // Zeros inside the content are content, not padding.
                if len > 4 {
                    v[1] = 0;
                    v[2] = 0;
                    cases.push(v);
                }
            }
        }
        for c in &cases {
            assert_eq!(content_end(c), backward(c), "{} bytes", c.len());
        }

        let (mut w, mut r) = pair(CipherSuite::TlsAes128GcmSha256);
        for pad in (0..300).chain([MAX_PLAINTEXT - 3]) {
            let mut wire = Vec::new();
            w.seal(ContentType::ApplicationData, b"abc\0", pad, &mut wire)
                .unwrap();
            let rec = take_record(&mut wire).unwrap().unwrap();
            let mut body = rec.body.clone();
            let (ty, len) = r.open(&rec.header, &mut body).unwrap();
            assert_eq!(
                (ty, &body[..len]),
                (ContentType::ApplicationData, &b"abc\0"[..])
            );
        }
    }

    #[test]
    fn next_generation_changes_the_key() {
        let (w, _) = pair(CipherSuite::TlsAes256GcmSha384);
        let mut w2 = w.next_generation(CipherSuite::TlsAes256GcmSha384).unwrap();
        let (_, mut r) = pair(CipherSuite::TlsAes256GcmSha384);
        let mut wire = Vec::new();
        w2.seal(ContentType::ApplicationData, b"x", 0, &mut wire)
            .unwrap();
        let rec = take_record(&mut wire).unwrap().unwrap();
        let mut body = rec.body.clone();
        assert!(r.open(&rec.header, &mut body).is_err());
    }

    /// REQ-REC-004: a protected record that authenticates but whose inner
    /// plaintext holds more than 2^14 bytes of content (possible within the
    /// 2^14 + 256 ciphertext bound) is record_overflow; exactly 2^14 opens.
    #[test]
    fn authentic_content_over_2_14_is_record_overflow() {
        for (content_len, want) in [
            (MAX_PLAINTEXT, None),
            (MAX_PLAINTEXT + 1, Some(ErrorKind::RecordOverflow)),
            (MAX_PLAINTEXT + 200, Some(ErrorKind::RecordOverflow)),
        ] {
            let (w, mut r) = pair(CipherSuite::TlsAes128GcmSha256);
            // Seal by hand: `seal` itself refuses such a fragment.
            let mut body = alloc::vec![0x41u8; content_len];
            body.push(ContentType::ApplicationData.to_wire());
            let body_len = (body.len() + TAG_LEN) as u16;
            let [hi, lo] = body_len.to_be_bytes();
            let header = [23, 3, 3, hi, lo];
            let mut tag = [0u8; TAG_LEN];
            w.key
                .seal(&crypto::nonce_for(&w.iv, 0), &header, &mut body, &mut tag)
                .unwrap();
            body.extend_from_slice(&tag);
            match want {
                None => {
                    let (ty, n) = r.open(&header, &mut body).unwrap();
                    assert_eq!((ty, n), (ContentType::ApplicationData, content_len));
                }
                Some(kind) => {
                    assert_eq!(r.open(&header, &mut body).unwrap_err().kind(), kind)
                }
            }
        }
    }

    /// REQ-REC-004: a zero-length record is a decode error unless it carries
    /// application data (RFC 8446 §5.1 permits zero-length fragments of
    /// application data only); a zero-length application data record is
    /// framed and left for the AEAD to refuse.
    #[test]
    fn only_application_data_records_may_be_empty() {
        for ty in [20u8, 21, 22] {
            let mut buf = alloc::vec![ty, 3, 3, 0, 0];
            assert_eq!(
                take_record(&mut buf).unwrap_err().kind(),
                ErrorKind::Decode,
                "type {ty}"
            );
        }
        let mut buf = alloc::vec![23, 3, 3, 0, 0, 0xff];
        let rec = take_record(&mut buf).unwrap().unwrap();
        assert_eq!(rec.header, [23, 3, 3, 0, 0]);
        assert!(rec.body.is_empty());
        assert_eq!(buf, [0xff]);
    }
}
