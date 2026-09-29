//! Key exchange for every implemented `NamedGroup`, over IronCrypto.
//!
//! Classical ECDHE (X25519, P-256, P-384, P-521), pure ML-KEM-768, and the two
//! hybrids that carry post-quantum security today: X25519MLKEM768 and
//! SecP256r1MLKEM768 (draft-ietf-tls-ecdhe-mlkem).
//!
//! # Hybrid encodings
//!
//! The two hybrids do not order their components the same way, and getting it
//! wrong produces a handshake that fails only against other implementations:
//!
//! | group              | client share      | server share       | secret        |
//! |--------------------|-------------------|--------------------|---------------|
//! | X25519MLKEM768     | ek ‖ x25519       | ct ‖ x25519        | ss_kem ‖ ss_ec |
//! | SecP256r1MLKEM768  | p256 ‖ ek         | p256 ‖ ct          | ss_ec ‖ ss_kem |
//!
//! Requirement trace: `REQ-KX-001` (reject invalid peer shares),
//! `REQ-KX-002` (reject an all-zero X25519 output, RFC 8446 §7.4.2),
//! `REQ-KX-003` (ephemeral private keys are zeroized).

use alloc::boxed::Box;
use alloc::vec::Vec;

use ic_core::traits::{KeyAgreement, RandomSource};
use ic_core::Zeroizing;
use ic_mlkem::kem::{CIPHERTEXT_LEN, DECAPS_KEY_LEN, ENCAPS_KEY_LEN, SHARED_SECRET_LEN};
use ic_mlkem::MlKem768;

use crate::enums::NamedGroup;
use crate::error::{Error, ErrorKind, Result};

/// A shared secret, zeroized on drop.
pub type SharedSecret = super::SecretVec;

/// Groups this build can negotiate, in the default preference order.
pub const IMPLEMENTED_GROUPS: &[NamedGroup] = &[
    NamedGroup::X25519MlKem768,
    NamedGroup::SecP256r1MlKem768,
    NamedGroup::X25519,
    NamedGroup::Secp256r1,
    NamedGroup::Secp384r1,
    NamedGroup::Secp521r1,
    NamedGroup::MlKem768,
];

/// Whether this build implements `group`.
pub fn is_implemented(group: NamedGroup) -> bool {
    IMPLEMENTED_GROUPS.contains(&group)
}

/// IronCrypto ontology identifiers of the primitives `group` uses.
pub fn ic_ids(group: NamedGroup) -> &'static [&'static str] {
    match group {
        NamedGroup::X25519 => &["x25519"],
        NamedGroup::Secp256r1 => &["ecdh-p256"],
        NamedGroup::Secp384r1 => &["ecdh-p384"],
        NamedGroup::Secp521r1 => &["ecdh-p521"],
        NamedGroup::MlKem768 => &["ml-kem-768"],
        NamedGroup::X25519MlKem768 => &["ml-kem-768", "x25519"],
        NamedGroup::SecP256r1MlKem768 => &["ecdh-p256", "ml-kem-768"],
        _ => &[],
    }
}

/// Whether the group resists a quantum adversary (has an ML-KEM component).
pub fn is_post_quantum(group: NamedGroup) -> bool {
    matches!(
        group,
        NamedGroup::MlKem768 | NamedGroup::X25519MlKem768 | NamedGroup::SecP256r1MlKem768
    )
}

/// Whether the group is a hybrid of classical and post-quantum.
pub fn is_hybrid(group: NamedGroup) -> bool {
    matches!(
        group,
        NamedGroup::X25519MlKem768 | NamedGroup::SecP256r1MlKem768
    )
}

#[derive(Clone, Copy)]
enum Ec {
    X25519,
    P256,
    P384,
    P521,
}

impl Ec {
    const fn private_len(self) -> usize {
        match self {
            Self::X25519 | Self::P256 => 32,
            Self::P384 => 48,
            Self::P521 => 66,
        }
    }

    const fn public_len(self) -> usize {
        match self {
            Self::X25519 => 32,
            Self::P256 => 65,
            Self::P384 => 97,
            Self::P521 => 133,
        }
    }

    const fn secret_len(self) -> usize {
        match self {
            Self::X25519 | Self::P256 => 32,
            Self::P384 => 48,
            Self::P521 => 66,
        }
    }

    fn public_key(self, sk: &[u8], out: &mut [u8]) -> ic_core::Result<()> {
        match self {
            Self::X25519 => ic_ec::X25519::public_key(sk, out),
            Self::P256 => ic_ec::EcdhP256::public_key(sk, out),
            Self::P384 => ic_ec::EcdhP384::public_key(sk, out),
            Self::P521 => ic_ec::p521::EcdhP521::public_key(sk, out),
        }
    }

    fn agree(self, sk: &[u8], peer: &[u8], out: &mut [u8]) -> Result<()> {
        // REQ-KX-001: exact length, and uncompressed form for the NIST curves
        // (RFC 8446 §4.2.8.2 permits only the uncompressed encoding).
        if peer.len() != self.public_len() {
            return Err(Error::new(
                ErrorKind::IllegalParameter,
                "key share has the wrong length",
            ));
        }
        if !matches!(self, Self::X25519) && peer.first() != Some(&0x04) {
            return Err(Error::new(
                ErrorKind::IllegalParameter,
                "key share is not an uncompressed point",
            ));
        }
        let r = match self {
            Self::X25519 => ic_ec::X25519::agree(sk, peer, out),
            Self::P256 => ic_ec::EcdhP256::agree(sk, peer, out),
            Self::P384 => ic_ec::EcdhP384::agree(sk, peer, out),
            Self::P521 => ic_ec::p521::EcdhP521::agree(sk, peer, out),
        };
        r.map_err(|_| Error::new(ErrorKind::IllegalParameter, "peer key share rejected"))?;
        // REQ-KX-002.
        if ic_core::ct::is_zero(out).unwrap_u8() == 1 {
            return Err(Error::new(
                ErrorKind::IllegalParameter,
                "all-zero shared secret",
            ));
        }
        Ok(())
    }

    /// Generate a private key and its public key.
    fn generate(self, rng: &mut dyn RandomSource) -> Result<(super::SecretVec, Vec<u8>)> {
        let mut public = alloc::vec![0u8; self.public_len()];
        // A uniformly random string is a valid NIST scalar with overwhelming
        // probability; the bound on attempts turns a broken RNG into an error
        // rather than a loop.
        for _ in 0..64 {
            let mut sk = super::SecretVec::new(alloc::vec![0u8; self.private_len()]);
            super::fill_random(rng, sk.get_mut())?;
            if let Self::P521 = self {
                // n is a 521-bit number: clear the 7 bits above it.
                sk.get_mut()[0] &= 0x01;
            }
            if self.public_key(sk.get(), &mut public).is_ok() {
                return Ok((sk, public));
            }
        }
        Err(Error::new(
            ErrorKind::Entropy,
            "could not generate an ephemeral key",
        ))
    }
}

fn ec_of(group: NamedGroup) -> Option<Ec> {
    Some(match group {
        NamedGroup::X25519 => Ec::X25519,
        NamedGroup::Secp256r1 => Ec::P256,
        NamedGroup::Secp384r1 => Ec::P384,
        NamedGroup::Secp521r1 => Ec::P521,
        _ => return None,
    })
}

enum Private {
    Ec(Ec, super::SecretVec),
    Kem(DecapsKey),
    X25519Kem(super::SecretVec, DecapsKey),
    P256Kem(super::SecretVec, DecapsKey),
}

/// A client's ephemeral key share, awaiting the server's.
pub struct KeyShare {
    group: NamedGroup,
    public: Vec<u8>,
    private: Private,
}

impl core::fmt::Debug for KeyShare {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "KeyShare({})", self.group)
    }
}

type DecapsKey = Box<Zeroizing<[u8; DECAPS_KEY_LEN]>>;

fn kem_keygen(rng: &mut dyn RandomSource) -> Result<(Vec<u8>, DecapsKey)> {
    let mut ek = alloc::vec![0u8; ENCAPS_KEY_LEN];
    let mut dk = Box::new(Zeroizing::new([0u8; DECAPS_KEY_LEN]));
    let ek_arr: &mut [u8; ENCAPS_KEY_LEN] = ek
        .as_mut_slice()
        .try_into()
        .map_err(|_| Error::new(ErrorKind::Internal, "ek length"))?;
    let mut rng = DynRng(rng);
    MlKem768::keygen(&mut rng, ek_arr, dk.get_mut())
        .map_err(|_| Error::new(ErrorKind::Crypto, "ml-kem key generation failed"))?;
    Ok((ek, dk))
}

/// Adapts `&mut dyn RandomSource` to the `R: RandomSource + ?Sized` bound.
struct DynRng<'a>(&'a mut dyn RandomSource);

impl RandomSource for DynRng<'_> {
    fn fill(&mut self, out: &mut [u8]) -> ic_core::Result<()> {
        self.0.fill(out)
    }
}

fn kem_encapsulate(
    rng: &mut dyn RandomSource,
    ek: &[u8],
) -> Result<(Vec<u8>, Zeroizing<[u8; 32]>)> {
    let ek: &[u8; ENCAPS_KEY_LEN] = ek.try_into().map_err(|_| {
        Error::new(
            ErrorKind::IllegalParameter,
            "ml-kem encapsulation key length",
        )
    })?;
    let mut ct = alloc::vec![0u8; CIPHERTEXT_LEN];
    let ct_arr: &mut [u8; CIPHERTEXT_LEN] = ct
        .as_mut_slice()
        .try_into()
        .map_err(|_| Error::new(ErrorKind::Internal, "ct length"))?;
    let mut ss = Zeroizing::new([0u8; SHARED_SECRET_LEN]);
    let mut rng = DynRng(rng);
    MlKem768::encapsulate(&mut rng, ek, ct_arr, ss.get_mut()).map_err(|_| {
        Error::new(
            ErrorKind::IllegalParameter,
            "ml-kem encapsulation key rejected",
        )
    })?;
    Ok((ct, ss))
}

fn kem_decapsulate(dk: &[u8; DECAPS_KEY_LEN], ct: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let ct: &[u8; CIPHERTEXT_LEN] = ct
        .try_into()
        .map_err(|_| Error::new(ErrorKind::IllegalParameter, "ml-kem ciphertext length"))?;
    let mut ss = Zeroizing::new([0u8; SHARED_SECRET_LEN]);
    MlKem768::decapsulate(dk, ct, ss.get_mut())
        .map_err(|_| Error::new(ErrorKind::IllegalParameter, "ml-kem ciphertext rejected"))?;
    Ok(ss)
}

fn concat(a: &[u8], b: &[u8]) -> SharedSecret {
    let mut v = Vec::with_capacity(a.len() + b.len());
    v.extend_from_slice(a);
    v.extend_from_slice(b);
    super::SecretVec::new(v)
}

impl KeyShare {
    /// Generate a client key share for `group`.
    pub fn generate(group: NamedGroup, rng: &mut dyn RandomSource) -> Result<Self> {
        let (public, private) = if let Some(ec) = ec_of(group) {
            let (sk, pk) = ec.generate(rng)?;
            (pk, Private::Ec(ec, sk))
        } else {
            match group {
                NamedGroup::MlKem768 => {
                    let (ek, dk) = kem_keygen(rng)?;
                    (ek, Private::Kem(dk))
                }
                NamedGroup::X25519MlKem768 => {
                    let (ek, dk) = kem_keygen(rng)?;
                    let (sk, pk) = Ec::X25519.generate(rng)?;
                    let mut public = ek;
                    public.extend_from_slice(&pk);
                    (public, Private::X25519Kem(sk, dk))
                }
                NamedGroup::SecP256r1MlKem768 => {
                    let (ek, dk) = kem_keygen(rng)?;
                    let (sk, pk) = Ec::P256.generate(rng)?;
                    let mut public = pk;
                    public.extend_from_slice(&ek);
                    (public, Private::P256Kem(sk, dk))
                }
                _ => {
                    return Err(Error::new(
                        ErrorKind::HandshakeFailure,
                        "group not implemented",
                    ));
                }
            }
        };
        Ok(Self {
            group,
            public,
            private,
        })
    }

    /// The group.
    pub fn group(&self) -> NamedGroup {
        self.group
    }

    /// The share to send.
    pub fn public(&self) -> &[u8] {
        &self.public
    }

    /// Combine with the server's share (client side).
    pub fn complete(self, server_share: &[u8]) -> Result<SharedSecret> {
        match &self.private {
            Private::Ec(ec, sk) => {
                let mut out = super::SecretVec::new(alloc::vec![0u8; ec.secret_len()]);
                ec.agree(sk.get(), server_share, out.get_mut())?;
                Ok(out)
            }
            Private::Kem(dk) => {
                let ss = kem_decapsulate(dk.get(), server_share)?;
                Ok(concat(ss.get(), &[]))
            }
            Private::X25519Kem(sk, dk) => {
                if server_share.len() != CIPHERTEXT_LEN + 32 {
                    return Err(Error::new(
                        ErrorKind::IllegalParameter,
                        "hybrid share length",
                    ));
                }
                let (ct, pk) = server_share.split_at(CIPHERTEXT_LEN);
                let kem = kem_decapsulate(dk.get(), ct)?;
                let mut ec = Zeroizing::new([0u8; 32]);
                Ec::X25519.agree(sk.get(), pk, ec.get_mut())?;
                Ok(concat(kem.get(), ec.get()))
            }
            Private::P256Kem(sk, dk) => {
                if server_share.len() != 65 + CIPHERTEXT_LEN {
                    return Err(Error::new(
                        ErrorKind::IllegalParameter,
                        "hybrid share length",
                    ));
                }
                let (pk, ct) = server_share.split_at(65);
                let mut ec = Zeroizing::new([0u8; 32]);
                Ec::P256.agree(sk.get(), pk, ec.get_mut())?;
                let kem = kem_decapsulate(dk.get(), ct)?;
                Ok(concat(ec.get(), kem.get()))
            }
        }
    }
}

/// Answer a client's share (server side): the share to send back and the
/// shared secret.
pub fn respond(
    group: NamedGroup,
    client_share: &[u8],
    rng: &mut dyn RandomSource,
) -> Result<(Vec<u8>, SharedSecret)> {
    if let Some(ec) = ec_of(group) {
        let (sk, pk) = ec.generate(rng)?;
        let mut out = super::SecretVec::new(alloc::vec![0u8; ec.secret_len()]);
        ec.agree(sk.get(), client_share, out.get_mut())?;
        return Ok((pk, out));
    }
    match group {
        NamedGroup::MlKem768 => {
            let (ct, ss) = kem_encapsulate(rng, client_share)?;
            Ok((ct, concat(ss.get(), &[])))
        }
        NamedGroup::X25519MlKem768 => {
            if client_share.len() != ENCAPS_KEY_LEN + 32 {
                return Err(Error::new(
                    ErrorKind::IllegalParameter,
                    "hybrid share length",
                ));
            }
            let (ek, peer) = client_share.split_at(ENCAPS_KEY_LEN);
            let (ct, kem) = kem_encapsulate(rng, ek)?;
            let (sk, pk) = Ec::X25519.generate(rng)?;
            let mut ec = Zeroizing::new([0u8; 32]);
            Ec::X25519.agree(sk.get(), peer, ec.get_mut())?;
            let mut share = ct;
            share.extend_from_slice(&pk);
            Ok((share, concat(kem.get(), ec.get())))
        }
        NamedGroup::SecP256r1MlKem768 => {
            if client_share.len() != 65 + ENCAPS_KEY_LEN {
                return Err(Error::new(
                    ErrorKind::IllegalParameter,
                    "hybrid share length",
                ));
            }
            let (peer, ek) = client_share.split_at(65);
            let (sk, pk) = Ec::P256.generate(rng)?;
            let mut ec = Zeroizing::new([0u8; 32]);
            Ec::P256.agree(sk.get(), peer, ec.get_mut())?;
            let (ct, kem) = kem_encapsulate(rng, ek)?;
            let mut share = pk;
            share.extend_from_slice(&ct);
            Ok((share, concat(ec.get(), kem.get())))
        }
        _ => Err(Error::new(
            ErrorKind::HandshakeFailure,
            "group not implemented",
        )),
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;

    #[test]
    fn every_group_agrees_with_itself() {
        let mut rng = ic_drbg::Rng::from_os().unwrap();
        for &g in IMPLEMENTED_GROUPS {
            let client = KeyShare::generate(g, &mut rng).unwrap();
            let (server_share, server_secret) = respond(g, client.public(), &mut rng).unwrap();
            let client_secret = client.complete(&server_share).unwrap();
            assert_eq!(client_secret.get(), server_secret.get(), "{g}");
            assert!(!client_secret.get().is_empty());
        }
    }

    #[test]
    fn malformed_shares_are_rejected_not_panicked_on() {
        let mut rng = ic_drbg::Rng::from_os().unwrap();
        for &g in IMPLEMENTED_GROUPS {
            for bad in [&[][..], &[0x04][..], &[0u8; 32][..], &[0xffu8; 200][..]] {
                assert!(
                    respond(g, bad, &mut rng).is_err(),
                    "{g} accepted a bad share"
                );
            }
            let client = KeyShare::generate(g, &mut rng).unwrap();
            assert!(client.complete(&[1, 2, 3]).is_err());
        }
    }

    /// REQ-KX-002: the all-zero X25519 public key forces an all-zero shared
    /// secret; it must be refused whichever layer notices first.
    #[test]
    fn an_all_zero_x25519_secret_is_refused() {
        let mut rng = ic_drbg::Rng::from_os().unwrap();
        let err = respond(NamedGroup::X25519, &[0u8; 32], &mut rng).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::IllegalParameter);
        let client = KeyShare::generate(NamedGroup::X25519, &mut rng).unwrap();
        assert_eq!(
            client.complete(&[0u8; 32]).unwrap_err().kind(),
            ErrorKind::IllegalParameter
        );
    }

    #[test]
    fn a_compressed_point_is_refused() {
        let mut rng = ic_drbg::Rng::from_os().unwrap();
        let mut share = alloc::vec![0x02u8; 65];
        share[0] = 0x02;
        assert_eq!(
            respond(NamedGroup::Secp256r1, &share, &mut rng)
                .unwrap_err()
                .kind(),
            ErrorKind::IllegalParameter
        );
    }
}
