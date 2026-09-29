//! HPKE, base mode (RFC 9180), as Encrypted Client Hello uses it.
//!
//! A composition over IronCrypto's X25519, HKDF-SHA256 and AEADs, in the way
//! the TLS key schedule is a composition over HKDF: no primitive is
//! implemented here.
//!
//! Supported: KEM `DHKEM(X25519, HKDF-SHA256)` (0x0020), KDF `HKDF-SHA256`
//! (0x0001), AEADs `AES-128-GCM` (0x0001), `AES-256-GCM` (0x0002) and
//! `ChaCha20-Poly1305` (0x0003). Base mode only (no PSK, no sender auth).
//!
//! Requirement trace: `REQ-HPKE-001` (the RFC 9180 key schedule and nonce
//! sequence, checked against Appendix A.1.1), `REQ-HPKE-002` (an all-zero DH
//! output is refused), `REQ-HPKE-003` (a context never reuses a nonce: the
//! sequence number is checked before it could wrap).

use alloc::vec::Vec;

use ic_core::traits::{KeyAgreement, RandomSource};

use super::{AeadAlg, AeadKey, HashAlg, Output, SecretVec, NONCE_LEN, TAG_LEN};
use crate::error::{Error, ErrorKind, Result};

/// `DHKEM(X25519, HKDF-SHA256)`.
pub const KEM_X25519_SHA256: u16 = 0x0020;
/// `HKDF-SHA256`.
pub const KDF_HKDF_SHA256: u16 = 0x0001;
/// `AES-128-GCM`.
pub const AEAD_AES_128_GCM: u16 = 0x0001;
/// `AES-256-GCM`.
pub const AEAD_AES_256_GCM: u16 = 0x0002;
/// `ChaCha20-Poly1305`.
pub const AEAD_CHACHA20_POLY1305: u16 = 0x0003;

/// Length of an X25519 encapsulated key.
pub const ENC_LEN: usize = 32;

/// An HPKE AEAD identifier this module implements.
pub fn aead_for(id: u16) -> Option<AeadAlg> {
    Some(match id {
        AEAD_AES_128_GCM => AeadAlg::Aes128Gcm,
        AEAD_AES_256_GCM => AeadAlg::Aes256Gcm,
        AEAD_CHACHA20_POLY1305 => AeadAlg::ChaCha20Poly1305,
        _ => return None,
    })
}

fn labeled_extract(suite_id: &[u8], salt: &[u8], label: &[u8], ikm: &[u8]) -> Result<Output> {
    let mut input = Vec::with_capacity(7 + suite_id.len() + label.len() + ikm.len());
    input.extend_from_slice(b"HPKE-v1");
    input.extend_from_slice(suite_id);
    input.extend_from_slice(label);
    input.extend_from_slice(ikm);
    let r = super::hkdf_extract(HashAlg::Sha256, salt, &input);
    ic_core::Zeroize::zeroize(input.as_mut_slice());
    r
}

fn labeled_expand(
    suite_id: &[u8],
    prk: &[u8],
    label: &[u8],
    info: &[u8],
    out: &mut [u8],
) -> Result<()> {
    let len = u16::try_from(out.len())
        .map_err(|_| Error::new(ErrorKind::Internal, "hpke expand length"))?;
    let mut labeled = Vec::with_capacity(2 + 7 + suite_id.len() + label.len() + info.len());
    labeled.extend_from_slice(&len.to_be_bytes());
    labeled.extend_from_slice(b"HPKE-v1");
    labeled.extend_from_slice(suite_id);
    labeled.extend_from_slice(label);
    labeled.extend_from_slice(info);
    super::hkdf_expand(HashAlg::Sha256, prk, &labeled, out)
}

const KEM_SUITE: [u8; 5] = [b'K', b'E', b'M', 0x00, 0x20];

/// `ExtractAndExpand(dh, kem_context)` of DHKEM (RFC 9180 §4.1).
fn kem_shared_secret(dh: &[u8], enc: &[u8], pk_r: &[u8]) -> Result<SecretVec> {
    // REQ-HPKE-002.
    if ic_core::ct::is_zero(dh).unwrap_u8() == 1 {
        return Err(Error::new(
            ErrorKind::IllegalParameter,
            "HPKE: all-zero X25519 output",
        ));
    }
    let eae_prk = labeled_extract(&KEM_SUITE, b"", b"eae_prk", dh)?;
    let mut ctx = Vec::with_capacity(enc.len() + pk_r.len());
    ctx.extend_from_slice(enc);
    ctx.extend_from_slice(pk_r);
    let mut ss = SecretVec::new(alloc::vec![0u8; 32]);
    labeled_expand(
        &KEM_SUITE,
        eae_prk.as_bytes(),
        b"shared_secret",
        &ctx,
        ss.get_mut(),
    )?;
    Ok(ss)
}

/// A key pair for the receiving side.
pub struct KemKeyPair {
    private: SecretVec,
    public: [u8; 32],
}

impl core::fmt::Debug for KemKeyPair {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("KemKeyPair(x25519)")
    }
}

impl KemKeyPair {
    /// Generate a fresh key pair.
    pub fn generate(rng: &mut dyn RandomSource) -> Result<Self> {
        let mut sk = SecretVec::new(alloc::vec![0u8; 32]);
        super::fill_random(rng, sk.get_mut())?;
        Self::from_private(sk.get())
    }

    /// From a 32-byte X25519 private key.
    pub fn from_private(sk: &[u8]) -> Result<Self> {
        if sk.len() != 32 {
            return Err(Error::new(
                ErrorKind::InvalidConfig,
                "HPKE X25519 private key must be 32 bytes",
            ));
        }
        let mut public = [0u8; 32];
        ic_ec::X25519::public_key(sk, &mut public)?;
        Ok(Self {
            private: SecretVec::new(sk.to_vec()),
            public,
        })
    }

    /// The public key.
    pub fn public(&self) -> &[u8; 32] {
        &self.public
    }
}

/// An established HPKE context.
pub struct Context {
    aead: AeadKey,
    base_nonce: [u8; NONCE_LEN],
    seq: u64,
    exporter: Output,
}

impl core::fmt::Debug for Context {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "hpke::Context(seq {})", self.seq)
    }
}

fn key_schedule(shared_secret: &[u8], info: &[u8], aead_id: u16) -> Result<Context> {
    let alg = aead_for(aead_id).ok_or(Error::new(
        ErrorKind::HandshakeFailure,
        "HPKE AEAD not supported",
    ))?;
    let mut suite = [0u8; 10];
    suite[..4].copy_from_slice(b"HPKE");
    suite[4..6].copy_from_slice(&KEM_X25519_SHA256.to_be_bytes());
    suite[6..8].copy_from_slice(&KDF_HKDF_SHA256.to_be_bytes());
    suite[8..10].copy_from_slice(&aead_id.to_be_bytes());
    let psk_id_hash = labeled_extract(&suite, b"", b"psk_id_hash", b"")?;
    let info_hash = labeled_extract(&suite, b"", b"info_hash", info)?;
    let mut ksc = Vec::with_capacity(1 + 64);
    ksc.push(0x00); // mode_base
    ksc.extend_from_slice(psk_id_hash.as_bytes());
    ksc.extend_from_slice(info_hash.as_bytes());
    let secret = labeled_extract(&suite, shared_secret, b"secret", b"")?;
    let mut key = SecretVec::new(alloc::vec![0u8; alg.key_len()]);
    labeled_expand(&suite, secret.as_bytes(), b"key", &ksc, key.get_mut())?;
    let mut base_nonce = [0u8; NONCE_LEN];
    labeled_expand(
        &suite,
        secret.as_bytes(),
        b"base_nonce",
        &ksc,
        &mut base_nonce,
    )?;
    let mut exp = [0u8; 32];
    labeled_expand(&suite, secret.as_bytes(), b"exp", &ksc, &mut exp)?;
    let exporter = Output::from_slice(&exp)?;
    ic_core::Zeroize::zeroize(&mut exp[..]);
    Ok(Context {
        aead: AeadKey::new(alg, key.get())?,
        base_nonce,
        seq: 0,
        exporter,
    })
}

/// `SetupBaseS`: encapsulate to `pk_r`, returning `enc` and the sender context.
pub fn setup_sender(
    pk_r: &[u8],
    info: &[u8],
    aead_id: u16,
    rng: &mut dyn RandomSource,
) -> Result<(Vec<u8>, Context)> {
    let eph = KemKeyPair::generate(rng)?;
    setup_sender_with(pk_r, info, aead_id, &eph)
}

/// `SetupBaseS` with a given ephemeral key (for the known-answer test).
fn setup_sender_with(
    pk_r: &[u8],
    info: &[u8],
    aead_id: u16,
    eph: &KemKeyPair,
) -> Result<(Vec<u8>, Context)> {
    if pk_r.len() != 32 {
        return Err(Error::new(
            ErrorKind::IllegalParameter,
            "HPKE X25519 public key must be 32 bytes",
        ));
    }
    let mut dh = SecretVec::new(alloc::vec![0u8; 32]);
    ic_ec::X25519::agree(eph.private.get(), pk_r, dh.get_mut())
        .map_err(|_| Error::new(ErrorKind::IllegalParameter, "HPKE: bad recipient key"))?;
    let enc = eph.public.to_vec();
    let ss = kem_shared_secret(dh.get(), &enc, pk_r)?;
    Ok((enc, key_schedule(ss.get(), info, aead_id)?))
}

/// `SetupBaseR`: decapsulate `enc` with `key`, returning the receiver context.
pub fn setup_receiver(enc: &[u8], key: &KemKeyPair, info: &[u8], aead_id: u16) -> Result<Context> {
    if enc.len() != ENC_LEN {
        return Err(Error::new(
            ErrorKind::IllegalParameter,
            "HPKE enc must be 32 bytes",
        ));
    }
    let mut dh = SecretVec::new(alloc::vec![0u8; 32]);
    ic_ec::X25519::agree(key.private.get(), enc, dh.get_mut())
        .map_err(|_| Error::new(ErrorKind::IllegalParameter, "HPKE: bad enc"))?;
    let ss = kem_shared_secret(dh.get(), enc, &key.public)?;
    key_schedule(ss.get(), info, aead_id)
}

impl Context {
    fn next_nonce(&mut self) -> Result<[u8; NONCE_LEN]> {
        // REQ-HPKE-003.
        if self.seq == u64::MAX {
            return Err(Error::new(
                ErrorKind::KeyExhausted,
                "HPKE sequence number exhausted",
            ));
        }
        let n = super::nonce_for(&self.base_nonce, self.seq);
        self.seq += 1;
        Ok(n)
    }

    /// Encrypt `pt` with `aad`, returning ciphertext followed by the tag.
    pub fn seal(&mut self, aad: &[u8], pt: &[u8]) -> Result<Vec<u8>> {
        let nonce = self.next_nonce()?;
        let mut out = pt.to_vec();
        let mut tag = [0u8; TAG_LEN];
        self.aead.seal(&nonce, aad, &mut out, &mut tag)?;
        out.extend_from_slice(&tag);
        Ok(out)
    }

    /// Decrypt `ct` (ciphertext followed by the tag). The sequence number
    /// advances whether or not it authenticates, as RFC 9180 §5.2 specifies
    /// only on success; a failed open leaves it unchanged.
    pub fn open(&mut self, aad: &[u8], ct: &[u8]) -> Result<Vec<u8>> {
        if ct.len() < TAG_LEN {
            return Err(Error::new(
                ErrorKind::DecryptError,
                "HPKE ciphertext shorter than its tag",
            ));
        }
        if self.seq == u64::MAX {
            return Err(Error::new(
                ErrorKind::KeyExhausted,
                "HPKE sequence number exhausted",
            ));
        }
        let nonce = super::nonce_for(&self.base_nonce, self.seq);
        let (body, tag) = ct.split_at(ct.len() - TAG_LEN);
        let mut out = body.to_vec();
        self.aead
            .open(&nonce, aad, &mut out, tag)
            .map_err(|_| Error::new(ErrorKind::DecryptError, "HPKE open failed"))?;
        self.seq += 1;
        Ok(out)
    }

    /// The exporter secret (RFC 9180 §5.3), for tests and diagnostics.
    pub fn exporter_secret(&self) -> &[u8] {
        self.exporter.as_bytes()
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

    /// RFC 9180 Appendix A.1.1: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256,
    /// AES-128-GCM, base mode. `REQ-HPKE-001`.
    ///
    /// Provenance: `pkR` is derived here from `skRm` rather than asserted,
    /// because the transcription of `pkRm` could not be confirmed. Every
    /// output below (`enc`, `base_nonce`, the exporter secret and the
    /// ciphertext) is the appendix's value and depends on `pkR`, so they
    /// cross-check it: a wrong `pkR` could not reproduce all four.
    #[test]
    fn base_mode_matches_rfc9180_a1_1() {
        let info = hex("4f6465206f6e2061204772656369616e2055726e");
        let sk_e = hex("52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736");
        let sk_r = hex("4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8");
        let eph = KemKeyPair::from_private(&sk_e).unwrap();
        assert_eq!(
            eph.public().to_vec(),
            hex("37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431")
        );
        let recipient = KemKeyPair::from_private(&sk_r).unwrap();
        let pk_r = recipient.public().to_vec();

        let (enc, mut sender) = setup_sender_with(&pk_r, &info, AEAD_AES_128_GCM, &eph).unwrap();
        assert_eq!(
            enc,
            hex("37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431")
        );
        assert_eq!(sender.base_nonce.to_vec(), hex("56d890e5accaaf011cff4b7d"));
        assert_eq!(
            sender.exporter_secret().to_vec(),
            hex("45ff1c2e220db587171952c0592d5f5ebe103f1561a2614e38f2ffd47e99e3f8")
        );
        let pt = hex("4265617574792069732074727574682c20747275746820626561757479");
        let ct = sender.seal(&hex("436f756e742d30"), &pt).unwrap();
        assert_eq!(
            ct,
            hex("f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218a355a96d8770ac83d07bea87e13c512a")
        );
        let mut receiver = setup_receiver(&enc, &recipient, &info, AEAD_AES_128_GCM).unwrap();
        assert_eq!(receiver.open(&hex("436f756e742d30"), &ct).unwrap(), pt);
    }

    #[test]
    fn contexts_stay_in_step_and_detect_tampering() {
        let mut rng = ic_drbg::Rng::from_os().unwrap();
        for aead in [AEAD_AES_128_GCM, AEAD_AES_256_GCM, AEAD_CHACHA20_POLY1305] {
            let kp = KemKeyPair::generate(&mut rng).unwrap();
            let (enc, mut s) = setup_sender(kp.public(), b"info", aead, &mut rng).unwrap();
            let mut r = setup_receiver(&enc, &kp, b"info", aead).unwrap();
            for i in 0..3u8 {
                let ct = s.seal(&[i], b"hello").unwrap();
                let mut bad = ct.clone();
                bad[0] ^= 1;
                assert!(r.open(&[i], &bad).is_err());
                assert_eq!(r.open(&[i], &ct).unwrap(), b"hello");
            }
            let mut wrong = setup_receiver(&enc, &kp, b"other info", aead).unwrap();
            assert!(wrong.open(&[3], &s.seal(&[3], b"x").unwrap()).is_err());
        }
    }

    /// REQ-HPKE-002.
    #[test]
    fn a_low_order_key_is_refused() {
        let mut rng = ic_drbg::Rng::from_os().unwrap();
        assert!(setup_sender(&[0u8; 32], b"", AEAD_AES_128_GCM, &mut rng).is_err());
        let kp = KemKeyPair::generate(&mut rng).unwrap();
        assert!(setup_receiver(&[0u8; 32], &kp, b"", AEAD_AES_128_GCM).is_err());
    }
}
