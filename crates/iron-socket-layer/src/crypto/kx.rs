//! Key exchange for every implemented `NamedGroup`, over IronCrypto.
//!
//! Classical ECDHE (X25519, P-256, P-384, P-521), pure ML-KEM-768 and
//! ML-KEM-1024 (draft-ietf-tls-mlkem), and three hybrids
//! (draft-ietf-tls-ecdhe-mlkem): X25519MLKEM768, SecP256r1MLKEM768 and
//! SecP384r1MLKEM1024.
//!
//! # Hybrid encodings
//!
//! The two hybrids do not order their components the same way, and getting it
//! wrong produces a handshake that fails only against other implementations:
//!
//! | group               | client share      | server share       | secret        |
//! |---------------------|-------------------|--------------------|---------------|
//! | X25519MLKEM768      | ek ‖ x25519       | ct ‖ x25519        | ss_kem ‖ ss_ec |
//! | SecP256r1MLKEM768   | p256 ‖ ek         | p256 ‖ ct          | ss_ec ‖ ss_kem |
//! | SecP384r1MLKEM1024  | p384 ‖ ek         | p384 ‖ ct          | ss_ec ‖ ss_kem |
//!
//! Requirement trace: `REQ-KX-001` (reject invalid peer shares),
//! `REQ-KX-002` (reject an all-zero X25519 output, RFC 8446 §7.4.2),
//! `REQ-KX-003` (ephemeral private keys are zeroized), `REQ-KX-004` (hybrid
//! component order).

use alloc::vec::Vec;

use ic_core::traits::{KeyAgreement, RandomSource};
use ic_core::Zeroizing;
use ic_mlkem::{MlKem1024, MlKem768};

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
    // The CNSA 2.0 sizes: offered only where a profile or caller asks, since
    // their shares are over 1.5 KB.
    NamedGroup::SecP384r1MlKem1024,
    NamedGroup::MlKem1024,
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
        NamedGroup::MlKem1024 => &["ml-kem-1024"],
        NamedGroup::SecP384r1MlKem1024 => &["ecdh-p384", "ml-kem-1024"],
        _ => &[],
    }
}

/// Whether the group resists a quantum adversary (has an ML-KEM component).
pub fn is_post_quantum(group: NamedGroup) -> bool {
    pure_kem_of(group).is_some() || hybrid_of(group).is_some()
}

/// Whether the group is a hybrid of classical and post-quantum.
pub fn is_hybrid(group: NamedGroup) -> bool {
    hybrid_of(group).is_some()
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

/// An ML-KEM parameter set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kem {
    K768,
    K1024,
}

/// Run `$body` with `$m` bound to the parameter set's module (for its sizes)
/// and `$t` to its type (for its functions).
macro_rules! with_kem {
    ($kem:expr, $m:ident, $t:ident, $body:expr) => {
        match $kem {
            Kem::K768 => {
                use ic_mlkem::kem as $m;
                type $t = MlKem768;
                $body
            }
            Kem::K1024 => {
                use ic_mlkem::kem1024 as $m;
                type $t = MlKem1024;
                $body
            }
        }
    };
}

impl Kem {
    fn ek_len(self) -> usize {
        with_kem!(self, m, _T, m::ENCAPS_KEY_LEN)
    }

    fn ct_len(self) -> usize {
        with_kem!(self, m, _T, m::CIPHERTEXT_LEN)
    }

    fn keygen(self, rng: &mut dyn RandomSource) -> Result<(Vec<u8>, super::SecretVec)> {
        let mut rng = DynRng(rng);
        with_kem!(self, m, T, {
            let mut ek = alloc::vec![0u8; m::ENCAPS_KEY_LEN];
            let mut dk = super::SecretVec::new(alloc::vec![0u8; m::DECAPS_KEY_LEN]);
            let ek_arr: &mut [u8; m::ENCAPS_KEY_LEN] = ek
                .as_mut_slice()
                .try_into()
                .map_err(|_| Error::new(ErrorKind::Internal, "ek length"))?;
            let dk_arr: &mut [u8; m::DECAPS_KEY_LEN] = dk
                .get_mut()
                .try_into()
                .map_err(|_| Error::new(ErrorKind::Internal, "dk length"))?;
            T::keygen(&mut rng, ek_arr, dk_arr)
                .map_err(|_| Error::new(ErrorKind::Crypto, "ml-kem key generation failed"))?;
            Ok((ek, dk))
        })
    }

    fn encapsulate(
        self,
        rng: &mut dyn RandomSource,
        ek: &[u8],
    ) -> Result<(Vec<u8>, super::SecretVec)> {
        let mut rng = DynRng(rng);
        with_kem!(self, m, T, {
            let ek: &[u8; m::ENCAPS_KEY_LEN] = ek.try_into().map_err(|_| {
                Error::new(
                    ErrorKind::IllegalParameter,
                    "ml-kem encapsulation key length",
                )
            })?;
            let mut ct = alloc::vec![0u8; m::CIPHERTEXT_LEN];
            let ct_arr: &mut [u8; m::CIPHERTEXT_LEN] = ct
                .as_mut_slice()
                .try_into()
                .map_err(|_| Error::new(ErrorKind::Internal, "ct length"))?;
            let mut ss = Zeroizing::new([0u8; m::SHARED_SECRET_LEN]);
            T::encapsulate(&mut rng, ek, ct_arr, ss.get_mut()).map_err(|_| {
                Error::new(
                    ErrorKind::IllegalParameter,
                    "ml-kem encapsulation key rejected",
                )
            })?;
            Ok((ct, super::SecretVec::new(ss.get().to_vec())))
        })
    }

    fn decapsulate(self, dk: &[u8], ct: &[u8]) -> Result<super::SecretVec> {
        with_kem!(self, m, T, {
            let dk: &[u8; m::DECAPS_KEY_LEN] = dk
                .try_into()
                .map_err(|_| Error::new(ErrorKind::Internal, "dk length"))?;
            let ct: &[u8; m::CIPHERTEXT_LEN] = ct
                .try_into()
                .map_err(|_| Error::new(ErrorKind::IllegalParameter, "ml-kem ciphertext length"))?;
            let mut ss = Zeroizing::new([0u8; m::SHARED_SECRET_LEN]);
            T::decapsulate(dk, ct, ss.get_mut()).map_err(|_| {
                Error::new(ErrorKind::IllegalParameter, "ml-kem ciphertext rejected")
            })?;
            Ok(super::SecretVec::new(ss.get().to_vec()))
        })
    }
}

/// The parameter set of a pure ML-KEM group.
fn pure_kem_of(group: NamedGroup) -> Option<Kem> {
    match group {
        NamedGroup::MlKem768 => Some(Kem::K768),
        NamedGroup::MlKem1024 => Some(Kem::K1024),
        _ => None,
    }
}

/// A hybrid group's components, and whether ML-KEM comes first in the
/// shares and the secret (only in X25519MLKEM768). `REQ-KX-004`.
fn hybrid_of(group: NamedGroup) -> Option<(Ec, Kem, bool)> {
    match group {
        NamedGroup::X25519MlKem768 => Some((Ec::X25519, Kem::K768, true)),
        NamedGroup::SecP256r1MlKem768 => Some((Ec::P256, Kem::K768, false)),
        NamedGroup::SecP384r1MlKem1024 => Some((Ec::P384, Kem::K1024, false)),
        _ => None,
    }
}

enum Private {
    Ec(Ec, super::SecretVec),
    Kem(Kem, super::SecretVec),
    Hybrid {
        ec: Ec,
        kem: Kem,
        kem_first: bool,
        ec_private: super::SecretVec,
        decaps_key: super::SecretVec,
    },
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

/// Adapts `&mut dyn RandomSource` to the `R: RandomSource + ?Sized` bound.
struct DynRng<'a>(&'a mut dyn RandomSource);

impl RandomSource for DynRng<'_> {
    fn fill(&mut self, out: &mut [u8]) -> ic_core::Result<()> {
        self.0.fill(out)
    }
}

/// Join a hybrid's two parts in the group's order.
fn ordered(kem_first: bool, kem: &[u8], ec: &[u8]) -> Vec<u8> {
    let (a, b) = if kem_first { (kem, ec) } else { (ec, kem) };
    let mut v = Vec::with_capacity(a.len() + b.len());
    v.extend_from_slice(a);
    v.extend_from_slice(b);
    v
}

/// Split a hybrid share into its (KEM part, EC part), checking the length.
fn split_hybrid(
    share: &[u8],
    kem_first: bool,
    kem_len: usize,
    ec_len: usize,
) -> Result<(&[u8], &[u8])> {
    if share.len() != kem_len + ec_len {
        return Err(Error::new(
            ErrorKind::IllegalParameter,
            "hybrid share length",
        ));
    }
    Ok(if kem_first {
        share.split_at(kem_len)
    } else {
        let (ec, kem) = share.split_at(ec_len);
        (kem, ec)
    })
}

impl KeyShare {
    /// Generate a client key share for `group`.
    pub fn generate(group: NamedGroup, rng: &mut dyn RandomSource) -> Result<Self> {
        let (public, private) = if let Some(ec) = ec_of(group) {
            let (sk, pk) = ec.generate(rng)?;
            (pk, Private::Ec(ec, sk))
        } else if let Some(kem) = pure_kem_of(group) {
            let (ek, dk) = kem.keygen(rng)?;
            (ek, Private::Kem(kem, dk))
        } else if let Some((ec, kem, kem_first)) = hybrid_of(group) {
            let (ek, decaps_key) = kem.keygen(rng)?;
            let (ec_private, pk) = ec.generate(rng)?;
            (
                ordered(kem_first, &ek, &pk),
                Private::Hybrid {
                    ec,
                    kem,
                    kem_first,
                    ec_private,
                    decaps_key,
                },
            )
        } else {
            return Err(Error::new(
                ErrorKind::HandshakeFailure,
                "group not implemented",
            ));
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
            Private::Kem(kem, dk) => kem.decapsulate(dk.get(), server_share),
            Private::Hybrid {
                ec,
                kem,
                kem_first,
                ec_private,
                decaps_key,
            } => {
                let (ct, pk) =
                    split_hybrid(server_share, *kem_first, kem.ct_len(), ec.public_len())?;
                let mut ec_secret = super::SecretVec::new(alloc::vec![0u8; ec.secret_len()]);
                ec.agree(ec_private.get(), pk, ec_secret.get_mut())?;
                let kem_secret = kem.decapsulate(decaps_key.get(), ct)?;
                Ok(super::SecretVec::new(ordered(
                    *kem_first,
                    kem_secret.get(),
                    ec_secret.get(),
                )))
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
    if let Some(kem) = pure_kem_of(group) {
        return kem.encapsulate(rng, client_share);
    }
    let Some((ec, kem, kem_first)) = hybrid_of(group) else {
        return Err(Error::new(
            ErrorKind::HandshakeFailure,
            "group not implemented",
        ));
    };
    let (ek, peer) = split_hybrid(client_share, kem_first, kem.ek_len(), ec.public_len())?;
    let (sk, pk) = ec.generate(rng)?;
    let mut ec_secret = super::SecretVec::new(alloc::vec![0u8; ec.secret_len()]);
    ec.agree(sk.get(), peer, ec_secret.get_mut())?;
    let (ct, kem_secret) = kem.encapsulate(rng, ek)?;
    Ok((
        ordered(kem_first, &ct, &pk),
        super::SecretVec::new(ordered(kem_first, kem_secret.get(), ec_secret.get())),
    ))
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
