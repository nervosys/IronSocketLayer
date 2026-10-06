//! HPKE, base mode (RFC 9180), as Encrypted Client Hello uses it.
//!
//! An adapter over IronCrypto's `ic-hpke`, which implements the scheme: this
//! module only names the identifiers ECH uses, maps IronCrypto's errors to
//! this crate's, and keeps the interface the ECH code was written against.
//!
//! Supported: KEM `DHKEM(X25519, HKDF-SHA256)` (0x0020), KDF `HKDF-SHA256`
//! (0x0001), AEADs `AES-128-GCM` (0x0001), `AES-256-GCM` (0x0002) and
//! `ChaCha20-Poly1305` (0x0003). Base mode only (no PSK, no sender auth).
//!
//! Requirement trace: `REQ-HPKE-001` (the RFC 9180 key schedule and nonce
//! sequence, checked here against Appendix A.1.1), `REQ-HPKE-002` (an
//! all-zero DH output is refused), `REQ-HPKE-003` (a context never reuses a
//! nonce: `ic-hpke` refuses at the last sequence number, and this adapter
//! keeps no sequence of its own).

use alloc::vec::Vec;

use ic_core::traits::RandomSource;

use crate::error::{Error, ErrorKind, Result};

/// `DHKEM(X25519, HKDF-SHA256)`.
pub const KEM_X25519_SHA256: u16 = ic_hpke::KEM_ID;
/// `HKDF-SHA256`.
pub const KDF_HKDF_SHA256: u16 = ic_hpke::KDF_ID;
/// `AES-128-GCM`.
pub const AEAD_AES_128_GCM: u16 = ic_hpke::Aead::Aes128Gcm.id();
/// `AES-256-GCM`.
pub const AEAD_AES_256_GCM: u16 = ic_hpke::Aead::Aes256Gcm.id();
/// `ChaCha20-Poly1305`.
pub const AEAD_CHACHA20_POLY1305: u16 = ic_hpke::Aead::ChaCha20Poly1305.id();

/// Length of an X25519 encapsulated key.
pub const ENC_LEN: usize = ic_hpke::ENC_LEN;

const TAG_LEN: usize = ic_hpke::TAG_LEN;

/// The HPKE AEAD with this identifier, if implemented.
pub fn aead_for(id: u16) -> Option<ic_hpke::Aead> {
    ic_hpke::Aead::from_id(id)
}

fn aead(id: u16) -> Result<ic_hpke::Aead> {
    aead_for(id).ok_or(Error::new(
        ErrorKind::HandshakeFailure,
        "HPKE AEAD not supported",
    ))
}

/// Map IronCrypto's error for a value the peer supplied (a public key or an
/// encapsulation): it is the peer's parameter that is wrong.
fn peer_error(e: ic_core::Error) -> Error {
    match e.kind() {
        ic_core::ErrorKind::AuthenticationFailed => {
            Error::new(ErrorKind::DecryptError, "HPKE open failed")
        }
        ic_core::ErrorKind::CounterExhausted => {
            Error::new(ErrorKind::KeyExhausted, "HPKE sequence number exhausted")
        }
        _ => Error::new(
            ErrorKind::IllegalParameter,
            "HPKE: bad key or encapsulation",
        ),
    }
}

/// A key pair for the receiving side.
pub struct KemKeyPair(ic_hpke::KeyPair);

impl core::fmt::Debug for KemKeyPair {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("KemKeyPair(x25519)")
    }
}

impl KemKeyPair {
    /// Generate a fresh key pair.
    pub fn generate(rng: &mut dyn RandomSource) -> Result<Self> {
        ic_hpke::KeyPair::generate(rng)
            .map(Self)
            .map_err(|_| Error::new(ErrorKind::Entropy, "HPKE key generation"))
    }

    /// From a 32-byte X25519 private key.
    pub fn from_private(sk: &[u8]) -> Result<Self> {
        ic_hpke::KeyPair::from_private(sk).map(Self).map_err(|_| {
            Error::new(
                ErrorKind::InvalidConfig,
                "HPKE X25519 private key must be 32 bytes",
            )
        })
    }

    /// The public key.
    pub fn public(&self) -> &[u8; 32] {
        self.0.public()
    }
}

/// An established HPKE context.
pub struct Context(ic_hpke::Context);

impl core::fmt::Debug for Context {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "hpke::Context(seq {})", self.0.sequence())
    }
}

/// `SetupBaseS`: encapsulate to `pk_r`, returning `enc` and the sender context.
pub fn setup_sender(
    pk_r: &[u8],
    info: &[u8],
    aead_id: u16,
    rng: &mut dyn RandomSource,
) -> Result<(Vec<u8>, Context)> {
    let (enc, ctx) = ic_hpke::setup_sender(pk_r, info, aead(aead_id)?, rng).map_err(peer_error)?;
    Ok((enc.to_vec(), Context(ctx)))
}

/// `SetupBaseR`: decapsulate `enc` with `key`, returning the receiver context.
pub fn setup_receiver(enc: &[u8], key: &KemKeyPair, info: &[u8], aead_id: u16) -> Result<Context> {
    ic_hpke::setup_receiver(enc, &key.0, info, aead(aead_id)?)
        .map(Context)
        .map_err(peer_error)
}

impl Context {
    /// Encrypt `pt` with `aad`, returning ciphertext followed by the tag.
    pub fn seal(&mut self, aad: &[u8], pt: &[u8]) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(pt.len() + TAG_LEN);
        out.extend_from_slice(pt);
        let mut tag = [0u8; TAG_LEN];
        self.0
            .seal_in_place(aad, &mut out, &mut tag)
            .map_err(peer_error)?;
        out.extend_from_slice(&tag);
        Ok(out)
    }

    /// Decrypt `ct` (ciphertext followed by the tag). The sequence number
    /// advances only when it authenticates (RFC 9180 §5.2).
    pub fn open(&mut self, aad: &[u8], ct: &[u8]) -> Result<Vec<u8>> {
        if ct.len() < TAG_LEN {
            return Err(Error::new(
                ErrorKind::DecryptError,
                "HPKE ciphertext shorter than its tag",
            ));
        }
        let (body, tag) = ct.split_at(ct.len() - TAG_LEN);
        let tag: &[u8; TAG_LEN] = tag
            .try_into()
            .map_err(|_| Error::new(ErrorKind::Internal, "HPKE tag length"))?;
        let mut out = body.to_vec();
        self.0
            .open_in_place(aad, &mut out, tag)
            .map_err(peer_error)?;
        Ok(out)
    }

    /// The sequence number of the next seal or open.
    pub fn sequence(&self) -> u64 {
        self.0.sequence()
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
    /// AES-128-GCM, base mode, through this adapter. `REQ-HPKE-001`.
    ///
    /// Provenance: `pkR` is derived from `skRm` rather than asserted, because
    /// the transcription of `pkRm` could not be confirmed. `enc` and the
    /// ciphertext are the appendix's values and depend on `pkR`, the key
    /// schedule and the nonce, so they cross-check all three.
    #[test]
    fn base_mode_matches_rfc9180_a1_1() {
        let info = hex("4f6465206f6e2061204772656369616e2055726e");
        let sk_e = hex("52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736");
        let sk_r = hex("4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8");
        let eph = ic_hpke::KeyPair::from_private(&sk_e).unwrap();
        let recipient = KemKeyPair::from_private(&sk_r).unwrap();
        let pk_r = recipient.public().to_vec();

        let (enc, sender) = ic_hpke::setup_sender_with_ephemeral(
            &pk_r,
            &info,
            aead_for(AEAD_AES_128_GCM).unwrap(),
            &eph,
        )
        .unwrap();
        let mut sender = Context(sender);
        assert_eq!(
            enc.to_vec(),
            hex("37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431")
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

    /// REQ-HPKE-003, as ECH relies on it: one context is used across a
    /// HelloRetryRequest, so sender and receiver must stay in step over
    /// several messages, a forgery must not advance the receiver, and the
    /// wrong `info` must not open.
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
                assert_eq!(
                    r.open(&[i], &bad).unwrap_err().kind(),
                    ErrorKind::DecryptError
                );
                assert_eq!(r.sequence(), u64::from(i));
                assert_eq!(r.open(&[i], &ct).unwrap(), b"hello");
            }
            let mut wrong = setup_receiver(&enc, &kp, b"other info", aead).unwrap();
            assert!(wrong.open(&[3], &s.seal(&[3], b"x").unwrap()).is_err());
        }
    }

    /// REQ-HPKE-002: a low-order key, whose X25519 output would be all
    /// zeros, is refused as the peer's error, on both sides.
    #[test]
    fn a_low_order_key_is_refused() {
        let mut rng = ic_drbg::Rng::from_os().unwrap();
        let e = setup_sender(&[0u8; 32], b"", AEAD_AES_128_GCM, &mut rng).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::IllegalParameter, "{e}");
        let kp = KemKeyPair::generate(&mut rng).unwrap();
        let e = setup_receiver(&[0u8; 32], &kp, b"", AEAD_AES_128_GCM).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::IllegalParameter, "{e}");
    }

    /// Keys and encapsulations of the wrong length are refused, not
    /// truncated or padded; a ciphertext shorter than its tag is a decrypt
    /// error that leaves the sequence unchanged; an unimplemented AEAD is a
    /// handshake failure.
    #[test]
    fn wrong_lengths_are_refused() {
        let mut rng = ic_drbg::Rng::from_os().unwrap();
        for len in [0usize, 31, 33] {
            let v = alloc::vec![9u8; len];
            assert_eq!(
                KemKeyPair::from_private(&v).unwrap_err().kind(),
                ErrorKind::InvalidConfig,
                "private key of {len}"
            );
            assert_eq!(
                setup_sender(&v, b"", AEAD_AES_128_GCM, &mut rng)
                    .unwrap_err()
                    .kind(),
                ErrorKind::IllegalParameter,
                "pk of {len}"
            );
            let kp = KemKeyPair::generate(&mut rng).unwrap();
            assert_eq!(
                setup_receiver(&v, &kp, b"", AEAD_AES_128_GCM)
                    .unwrap_err()
                    .kind(),
                ErrorKind::IllegalParameter,
                "enc of {len}"
            );
        }
        let kp = KemKeyPair::generate(&mut rng).unwrap();
        assert_eq!(
            setup_receiver(&[1u8; 32], &kp, b"", 0xffff)
                .unwrap_err()
                .kind(),
            ErrorKind::HandshakeFailure
        );
        let (enc, mut tx) = setup_sender(kp.public(), b"info", AEAD_AES_128_GCM, &mut rng).unwrap();
        let mut rx = setup_receiver(&enc, &kp, b"info", AEAD_AES_128_GCM).unwrap();
        for length in 0..TAG_LEN {
            assert_eq!(
                rx.open(b"", &alloc::vec![0; length]).unwrap_err().kind(),
                ErrorKind::DecryptError
            );
            assert_eq!(rx.sequence(), 0);
        }
        let ciphertext = tx.seal(b"", b"after invalid lengths").unwrap();
        assert_eq!(rx.open(b"", &ciphertext).unwrap(), b"after invalid lengths");
    }
}
