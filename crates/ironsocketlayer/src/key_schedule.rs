//! The TLS 1.3 key schedule (RFC 8446 §7.1) and exporters (§7.5).
//!
//! ```text
//!        0 -> HKDF-Extract = Early Secret
//!                   |
//!             Derive-Secret(., "derived", "")
//!                   v
//! (EC)DHE -> HKDF-Extract = Handshake Secret --> c/s hs traffic
//!                   |
//!             Derive-Secret(., "derived", "")
//!                   v
//!        0 -> HKDF-Extract = Master Secret ----> c/s ap traffic, exp master, res master
//! ```
//!
//! The schedule is a small typestate: [`KeySchedule::handshake`] consumes the
//! shared secret and yields the handshake stage; `into_master` consumes that.
//! A secret from one stage cannot be fed to another stage's derivation.
//!
//! Requirement trace: `REQ-KS-001` (HKDF-Expand-Label per §7.1),
//! `REQ-KS-002` (secrets zeroized on drop via [`Output`]),
//! `REQ-KS-003` (Finished MAC compared in constant time).

use crate::crypto::{self, HashAlg, Output};
use crate::error::{Error, ErrorKind, Result};

/// `Derive-Secret(Secret, Label, Messages)` given the transcript hash.
pub fn derive_secret(
    alg: HashAlg,
    secret: &[u8],
    label: &[u8],
    transcript_hash: &[u8],
) -> Result<Output> {
    crypto::expand_label_secret(alg, secret, label, transcript_hash)
}

fn empty_hash(alg: HashAlg) -> Output {
    alg.digest(&[])
}

/// The handshake stage: holds the Handshake Secret.
pub struct HandshakeStage {
    alg: HashAlg,
    handshake_secret: Output,
}

/// The application stage: holds the Master Secret.
pub struct MasterStage {
    alg: HashAlg,
    master_secret: Output,
}

/// Entry point.
pub struct KeySchedule;

impl KeySchedule {
    /// Early Secret (no PSK) then Handshake Secret from the (EC)DHE/KEM output.
    pub fn handshake(alg: HashAlg, shared_secret: &[u8]) -> Result<HandshakeStage> {
        EarlyStage::new(alg, None)?.into_handshake(shared_secret)
    }
}

/// The early stage: holds the Early Secret, from a resumption PSK or zeros.
pub struct EarlyStage {
    alg: HashAlg,
    early_secret: Output,
}

impl EarlyStage {
    /// `HKDF-Extract(0, PSK)`, with a zero PSK when none is in use.
    pub fn new(alg: HashAlg, psk: Option<&[u8]>) -> Result<Self> {
        let zeros = Output::zeros(alg.len());
        let ikm = psk.unwrap_or(zeros.as_bytes());
        let early_secret = crypto::hkdf_extract(alg, zeros.as_bytes(), ikm)?;
        Ok(Self { alg, early_secret })
    }

    /// The PSK binder for a resumption PSK (§4.2.11.2): HMAC under the
    /// Finished key of `binder_key`, over the hash of the transcript up to and
    /// excluding the binders. `REQ-PSK-002`.
    pub fn resumption_binder(&self, truncated_transcript_hash: &[u8]) -> Result<Output> {
        self.binder(b"res binder", truncated_transcript_hash)
    }

    /// The PSK binder for an external PSK: the same construction under the
    /// label `"ext binder"`, so an external PSK can never be presented as a
    /// resumption PSK or the reverse. `REQ-EPSK-002`.
    pub fn external_binder(&self, truncated_transcript_hash: &[u8]) -> Result<Output> {
        self.binder(b"ext binder", truncated_transcript_hash)
    }

    fn binder(&self, label: &[u8], truncated_transcript_hash: &[u8]) -> Result<Output> {
        let binder_key = derive_secret(
            self.alg,
            self.early_secret.as_bytes(),
            label,
            empty_hash(self.alg).as_bytes(),
        )?;
        finished_mac(self.alg, binder_key.as_bytes(), truncated_transcript_hash)
    }

    /// `client_early_traffic_secret` over the ClientHello (§7.1): the key
    /// 0-RTT data is sent under. It has no forward secrecy.
    pub fn client_early_traffic(&self, client_hello_hash: &[u8]) -> Result<Output> {
        derive_secret(
            self.alg,
            self.early_secret.as_bytes(),
            b"c e traffic",
            client_hello_hash,
        )
    }

    /// Advance to the Handshake Secret.
    pub fn into_handshake(self, shared_secret: &[u8]) -> Result<HandshakeStage> {
        let derived = derive_secret(
            self.alg,
            self.early_secret.as_bytes(),
            b"derived",
            empty_hash(self.alg).as_bytes(),
        )?;
        let handshake_secret = crypto::hkdf_extract(self.alg, derived.as_bytes(), shared_secret)?;
        Ok(HandshakeStage {
            alg: self.alg,
            handshake_secret,
        })
    }
}

/// The PSK a ticket stands for (§4.6.1):
/// `HKDF-Expand-Label(resumption_master_secret, "resumption", ticket_nonce, Hash.length)`.
pub fn resumption_psk(alg: HashAlg, resumption_master: &[u8], nonce: &[u8]) -> Result<Output> {
    crypto::expand_label_secret(alg, resumption_master, b"resumption", nonce)
}

impl HandshakeStage {
    /// `client_handshake_traffic_secret` over ClientHello..ServerHello.
    pub fn client_traffic(&self, hello_hash: &[u8]) -> Result<Output> {
        derive_secret(
            self.alg,
            self.handshake_secret.as_bytes(),
            b"c hs traffic",
            hello_hash,
        )
    }

    /// `server_handshake_traffic_secret` over ClientHello..ServerHello.
    pub fn server_traffic(&self, hello_hash: &[u8]) -> Result<Output> {
        derive_secret(
            self.alg,
            self.handshake_secret.as_bytes(),
            b"s hs traffic",
            hello_hash,
        )
    }

    /// Advance to the Master Secret.
    pub fn into_master(self) -> Result<MasterStage> {
        let derived = derive_secret(
            self.alg,
            self.handshake_secret.as_bytes(),
            b"derived",
            empty_hash(self.alg).as_bytes(),
        )?;
        let zeros = Output::zeros(self.alg.len());
        let master_secret = crypto::hkdf_extract(self.alg, derived.as_bytes(), zeros.as_bytes())?;
        Ok(MasterStage {
            alg: self.alg,
            master_secret,
        })
    }
}

impl MasterStage {
    /// `client_application_traffic_secret_0` over ClientHello..server Finished.
    pub fn client_traffic(&self, hash: &[u8]) -> Result<Output> {
        derive_secret(
            self.alg,
            self.master_secret.as_bytes(),
            b"c ap traffic",
            hash,
        )
    }

    /// `server_application_traffic_secret_0` over ClientHello..server Finished.
    pub fn server_traffic(&self, hash: &[u8]) -> Result<Output> {
        derive_secret(
            self.alg,
            self.master_secret.as_bytes(),
            b"s ap traffic",
            hash,
        )
    }

    /// `exporter_master_secret` over ClientHello..server Finished.
    pub fn exporter(&self, hash: &[u8]) -> Result<Output> {
        derive_secret(self.alg, self.master_secret.as_bytes(), b"exp master", hash)
    }

    /// `resumption_master_secret` over ClientHello..client Finished.
    pub fn resumption(&self, hash: &[u8]) -> Result<Output> {
        derive_secret(self.alg, self.master_secret.as_bytes(), b"res master", hash)
    }
}

/// `verify_data` for a Finished message (§4.4.4).
pub fn finished_mac(alg: HashAlg, base_key: &[u8], transcript_hash: &[u8]) -> Result<Output> {
    let finished_key = crypto::expand_label_secret(alg, base_key, b"finished", b"")?;
    crypto::hmac(alg, finished_key.as_bytes(), &[transcript_hash])
}

/// Check a peer's Finished in constant time. `REQ-KS-003`.
pub fn verify_finished(
    alg: HashAlg,
    base_key: &[u8],
    transcript_hash: &[u8],
    received: &[u8],
) -> Result<()> {
    let expected = finished_mac(alg, base_key, transcript_hash)?;
    if ic_core::ct::verify(expected.as_bytes(), received) {
        Ok(())
    } else {
        Err(Error::new(
            ErrorKind::DecryptError,
            "Finished did not verify",
        ))
    }
}

/// The next application traffic secret (§7.2).
pub fn next_traffic_secret(alg: HashAlg, secret: &[u8]) -> Result<Output> {
    crypto::expand_label_secret(alg, secret, b"traffic upd", b"")
}

/// Traffic key and IV for a record-layer AEAD (§7.3).
pub fn traffic_key_iv(
    alg: HashAlg,
    aead: crypto::AeadAlg,
    secret: &[u8],
) -> Result<(crypto::SecretVec, [u8; crypto::NONCE_LEN])> {
    let mut key = crypto::SecretVec::new(alloc::vec![0u8; aead.key_len()]);
    crypto::hkdf_expand_label(alg, secret, b"key", b"", key.get_mut())?;
    let mut iv = [0u8; crypto::NONCE_LEN];
    crypto::hkdf_expand_label(alg, secret, b"iv", b"", &mut iv)?;
    Ok((key, iv))
}

/// `TLS-Exporter(label, context_value, key_length)` (§7.5).
///
/// This is how an agent binds an application-layer credential to *this*
/// connection (RFC 9266 `tls-exporter` channel binding): a token signed over
/// the exporter output cannot be replayed on another TLS session.
pub fn export(
    alg: HashAlg,
    exporter_master: &[u8],
    label: &[u8],
    context: &[u8],
    out: &mut [u8],
) -> Result<()> {
    let secret = derive_secret(alg, exporter_master, label, empty_hash(alg).as_bytes())?;
    let ctx_hash = alg.digest(context);
    crypto::hkdf_expand_label(
        alg,
        secret.as_bytes(),
        b"exporter",
        ctx_hash.as_bytes(),
        out,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stages_differ_and_are_deterministic() {
        let alg = HashAlg::Sha256;
        let hs = KeySchedule::handshake(alg, &[7u8; 32]).unwrap();
        let h = alg.digest(b"hello");
        let c = hs.client_traffic(h.as_bytes()).unwrap();
        let s = hs.server_traffic(h.as_bytes()).unwrap();
        assert_ne!(c.as_bytes(), s.as_bytes());
        let hs2 = KeySchedule::handshake(alg, &[7u8; 32]).unwrap();
        assert_eq!(
            hs2.client_traffic(h.as_bytes()).unwrap().as_bytes(),
            c.as_bytes()
        );
        let m = hs.into_master().unwrap();
        assert_ne!(
            m.client_traffic(h.as_bytes()).unwrap().as_bytes(),
            c.as_bytes()
        );
    }

    /// REQ-PSK-002: the binder depends on the PSK and the transcript, and a
    /// zero PSK gives the same schedule as no PSK.
    #[test]
    fn binders_bind_the_psk_and_the_transcript() {
        let alg = HashAlg::Sha256;
        let th = alg.digest(b"truncated hello");
        let a = EarlyStage::new(alg, Some(&[1u8; 32])).unwrap();
        let b = EarlyStage::new(alg, Some(&[2u8; 32])).unwrap();
        let ba = a.resumption_binder(th.as_bytes()).unwrap();
        assert_ne!(
            ba.as_bytes(),
            b.resumption_binder(th.as_bytes()).unwrap().as_bytes()
        );
        let other = alg.digest(b"another hello");
        assert_ne!(
            ba.as_bytes(),
            a.resumption_binder(other.as_bytes()).unwrap().as_bytes()
        );
        let zero = EarlyStage::new(alg, Some(&[0u8; 32]))
            .unwrap()
            .into_handshake(&[5; 32])
            .unwrap();
        let none = KeySchedule::handshake(alg, &[5; 32]).unwrap();
        assert_eq!(
            zero.client_traffic(th.as_bytes()).unwrap().as_bytes(),
            none.client_traffic(th.as_bytes()).unwrap().as_bytes()
        );
    }

    /// REQ-EPSK-002: the same key and transcript give different binders as
    /// an external and as a resumption PSK.
    #[test]
    fn external_and_resumption_binders_are_separated() {
        let alg = HashAlg::Sha256;
        let th = alg.digest(b"hello");
        let e = EarlyStage::new(alg, Some(&[9u8; 32])).unwrap();
        assert_ne!(
            e.external_binder(th.as_bytes()).unwrap().as_bytes(),
            e.resumption_binder(th.as_bytes()).unwrap().as_bytes()
        );
    }

    #[test]
    fn finished_rejects_a_single_flipped_bit() {
        let alg = HashAlg::Sha384;
        let key = [1u8; 48];
        let th = alg.digest(b"t");
        let mac = finished_mac(alg, &key, th.as_bytes()).unwrap();
        verify_finished(alg, &key, th.as_bytes(), mac.as_bytes()).unwrap();
        let mut bad = mac.as_bytes().to_vec();
        bad[47] ^= 1;
        assert_eq!(
            verify_finished(alg, &key, th.as_bytes(), &bad)
                .unwrap_err()
                .kind(),
            ErrorKind::DecryptError
        );
        assert!(verify_finished(alg, &key, th.as_bytes(), &bad[..47]).is_err());
    }
}
