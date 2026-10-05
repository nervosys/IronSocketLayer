//! Signatures: producing `CertificateVerify`, and checking it and certificates.
//!
//! # Formats
//!
//! TLS carries ECDSA signatures as a DER `Ecdsa-Sig-Value`; IronCrypto works in
//! fixed-width `r ‖ s`. `ic_pkix::ecdsa_signature` converts in both
//! directions. IronCrypto's signers hash internally, so messages are passed
//! unhashed — handing them a digest would sign the hash of the hash.
//!
//! RSA-PSS uses a salt the length of the digest, which is what TLS 1.3
//! requires (RFC 8446 §4.2.3) and what `ic_rsa::pss` produces.
//!
//! Requirement trace: `REQ-SIG-001` (the scheme must match the key type),
//! `REQ-SIG-002` (PKCS#1 v1.5 and SHA-1 never sign a handshake),
//! `REQ-SIG-003` (private keys are zeroized), `REQ-SIG-004` (PKCS#8 loading).

use alloc::boxed::Box;
use alloc::vec::Vec;

use ic_core::traits::{RandomSource, SignatureScheme as _};
use ic_core::{Zeroize, Zeroizing};
use ic_pkix::der::{self, Reader};

use super::SecretVec;
use crate::enums::SignatureScheme;
use crate::error::{Error, ErrorKind, Result};

/// OID content bytes for id-ml-dsa-44, 2.16.840.1.101.3.4.3.17 (RFC 9881).
pub const OID_ML_DSA_44: &[u8] = ic_pkix::oid::ML_DSA_44;
/// OID content bytes for id-ml-dsa-65, 2.16.840.1.101.3.4.3.18.
pub const OID_ML_DSA_65: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12];
/// OID content bytes for id-ml-dsa-87, 2.16.840.1.101.3.4.3.19.
pub const OID_ML_DSA_87: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x13];

/// An ML-DSA parameter set (FIPS 204).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MlDsa {
    /// Category 2, available by explicit configuration.
    P44,
    /// Category 3.
    P65,
    /// Category 5, required by CNSA 2.0.
    P87,
}

/// Run `$body` with `$m` bound to the parameter set's IronCrypto module.
macro_rules! with_mldsa {
    ($p:expr, $m:ident, $body:expr) => {
        match $p {
            MlDsa::P44 => {
                use ic_mldsa::sign44 as $m;
                $body
            }
            MlDsa::P65 => {
                use ic_mldsa::sign as $m;
                $body
            }
            MlDsa::P87 => {
                use ic_mldsa::sign87 as $m;
                $body
            }
        }
    };
}

impl MlDsa {
    fn from_oid(oid: &[u8]) -> Option<Self> {
        if oid == OID_ML_DSA_44 {
            Some(Self::P44)
        } else if oid == OID_ML_DSA_65 {
            Some(Self::P65)
        } else if oid == OID_ML_DSA_87 {
            Some(Self::P87)
        } else {
            None
        }
    }

    fn oid(self) -> &'static [u8] {
        match self {
            Self::P44 => OID_ML_DSA_44,
            Self::P65 => OID_ML_DSA_65,
            Self::P87 => OID_ML_DSA_87,
        }
    }

    fn scheme(self) -> SignatureScheme {
        match self {
            Self::P44 => SignatureScheme::MlDsa44,
            Self::P65 => SignatureScheme::MlDsa65,
            Self::P87 => SignatureScheme::MlDsa87,
        }
    }

    fn kind_id(self) -> &'static str {
        match self {
            Self::P44 => "key:ml-dsa-44",
            Self::P65 => "key:ml-dsa-65",
            Self::P87 => "key:ml-dsa-87",
        }
    }

    fn public_len(self) -> usize {
        with_mldsa!(self, m, m::PUBLIC_KEY_LEN)
    }

    /// Key pair from the 32-byte seed `ξ` (FIPS 204): SPKI key bytes and the
    /// expanded secret key.
    fn keygen(self, seed: &[u8; 32]) -> Result<(Vec<u8>, SecretVec)> {
        with_mldsa!(self, m, {
            let mut pk = alloc::vec![0u8; m::PUBLIC_KEY_LEN];
            let mut sk = SecretVec::new(alloc::vec![0u8; m::SECRET_KEY_LEN]);
            let pk_arr: &mut [u8; m::PUBLIC_KEY_LEN] = pk
                .as_mut_slice()
                .try_into()
                .map_err(|_| Error::new(ErrorKind::Internal, "ml-dsa pk length"))?;
            let sk_arr: &mut [u8; m::SECRET_KEY_LEN] = sk
                .get_mut()
                .try_into()
                .map_err(|_| Error::new(ErrorKind::Internal, "ml-dsa sk length"))?;
            if !m::keygen(seed, pk_arr, sk_arr) {
                return Err(Error::new(
                    ErrorKind::Crypto,
                    "ml-dsa pairwise consistency test failed",
                ));
            }
            Ok((pk, sk))
        })
    }

    fn sign(self, sk: &[u8], message: &[u8], rnd: &[u8; 32]) -> Result<Vec<u8>> {
        with_mldsa!(self, m, {
            let sk: &[u8; m::SECRET_KEY_LEN] = sk
                .try_into()
                .map_err(|_| Error::new(ErrorKind::Internal, "ml-dsa sk length"))?;
            let mut sig = alloc::vec![0u8; m::SIGNATURE_LEN];
            let sig_arr: &mut [u8; m::SIGNATURE_LEN] = sig
                .as_mut_slice()
                .try_into()
                .map_err(|_| Error::new(ErrorKind::Internal, "ml-dsa signature length"))?;
            if !m::sign(sk, message, b"", rnd, sig_arr) {
                return Err(Error::new(ErrorKind::Crypto, "ml-dsa signing failed"));
            }
            Ok(sig)
        })
    }

    fn verify(self, pk: &[u8], message: &[u8], signature: &[u8]) -> Result<()> {
        with_mldsa!(self, m, {
            let pk: &[u8; m::PUBLIC_KEY_LEN] = pk
                .try_into()
                .map_err(|_| Error::new(ErrorKind::BadCertificate, "ml-dsa public key length"))?;
            let sig: &[u8; m::SIGNATURE_LEN] = signature
                .try_into()
                .map_err(|_| Error::new(ErrorKind::DecryptError, "ml-dsa signature length"))?;
            if m::verify(pk, message, b"", sig) {
                Ok(())
            } else {
                Err(Error::new(
                    ErrorKind::DecryptError,
                    "signature did not verify",
                ))
            }
        })
    }
}
/// OID content bytes for secp521r1, 1.3.132.0.35.
pub const OID_P521: &[u8] = &[0x2b, 0x81, 0x04, 0x00, 0x23];

/// Every scheme this build can verify, in the default preference order.
pub const VERIFY_SCHEMES: &[SignatureScheme] = &[
    SignatureScheme::MlDsa65,
    SignatureScheme::MlDsa87,
    SignatureScheme::Ed25519,
    SignatureScheme::EcdsaSecp256r1Sha256,
    SignatureScheme::EcdsaSecp384r1Sha384,
    SignatureScheme::EcdsaSecp521r1Sha512,
    SignatureScheme::RsaPssRsaeSha256,
    SignatureScheme::RsaPssRsaeSha384,
    SignatureScheme::RsaPssRsaeSha512,
    SignatureScheme::RsaPkcs1Sha256,
    SignatureScheme::RsaPkcs1Sha384,
    SignatureScheme::RsaPkcs1Sha512,
    SignatureScheme::MlDsa44,
];

/// IronCrypto ontology identifier of the primitive a scheme uses.
pub fn ic_id(scheme: SignatureScheme) -> Option<&'static str> {
    Some(match scheme {
        SignatureScheme::EcdsaSecp256r1Sha256 => "ecdsa-p256-sha256",
        SignatureScheme::EcdsaSecp384r1Sha384 => "ecdsa-p384-sha384",
        SignatureScheme::EcdsaSecp521r1Sha512 => "ecdsa-p521-sha512",
        SignatureScheme::Ed25519 => "ed25519",
        SignatureScheme::RsaPssRsaeSha256 => "rsa-pss-sha256",
        SignatureScheme::RsaPssRsaeSha384 => "rsa-pss-sha384",
        SignatureScheme::RsaPssRsaeSha512 => "rsa-pss-sha512",
        SignatureScheme::RsaPkcs1Sha256 => "rsa-pkcs1-sha256",
        SignatureScheme::RsaPkcs1Sha384 => "rsa-pkcs1-sha384",
        SignatureScheme::RsaPkcs1Sha512 => "rsa-pkcs1-sha512",
        SignatureScheme::MlDsa44 => "ml-dsa-44",
        SignatureScheme::MlDsa65 => "ml-dsa-65",
        SignatureScheme::MlDsa87 => "ml-dsa-87",
        _ => return None,
    })
}

/// A parsed public key, borrowing from its `SubjectPublicKeyInfo`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublicKey<'a> {
    /// P-256, SEC1 uncompressed.
    EcP256(&'a [u8]),
    /// P-384, SEC1 uncompressed.
    EcP384(&'a [u8]),
    /// P-521, SEC1 uncompressed.
    EcP521(&'a [u8]),
    /// Ed25519, 32 bytes.
    Ed25519(&'a [u8]),
    /// RSA modulus and exponent.
    Rsa {
        /// Big-endian modulus.
        modulus: &'a [u8],
        /// Public exponent.
        exponent: u64,
    },
    /// ML-DSA-44, 1312 bytes.
    MlDsa44(&'a [u8]),
    /// ML-DSA-65, 1952 bytes.
    MlDsa65(&'a [u8]),
    /// ML-DSA-87, 2592 bytes.
    MlDsa87(&'a [u8]),
}

impl<'a> PublicKey<'a> {
    /// Parse a DER `SubjectPublicKeyInfo`.
    ///
    /// P-256, P-384, Ed25519 and RSA go through `ic_pkix`; P-521 and ML-DSA,
    /// which it does not name, are read here with its DER reader.
    pub fn from_spki(spki: &'a [u8]) -> Result<Self> {
        let bad = |_| Error::new(ErrorKind::BadCertificate, "malformed SubjectPublicKeyInfo");
        // ic_pkix refuses curves it does not name (P-521) with an error rather
        // than `Unsupported`, so any failure falls through to the reader below,
        // which is the stricter of the two for the forms it accepts.
        match ic_pkix::PublicKeyInfo::from_der(spki) {
            Ok(ic_pkix::PublicKeyInfo::Rsa { modulus, exponent }) => {
                return Ok(Self::Rsa { modulus, exponent })
            }
            Ok(ic_pkix::PublicKeyInfo::Ec { algorithm, point }) => {
                return match algorithm {
                    ic_pkix::KeyAlgorithm::EcP256 => Ok(Self::EcP256(point)),
                    ic_pkix::KeyAlgorithm::EcP384 => Ok(Self::EcP384(point)),
                    ic_pkix::KeyAlgorithm::EcP521 => Ok(Self::EcP521(point)),
                    _ => Err(Error::new(
                        ErrorKind::UnsupportedCertificate,
                        "unsupported curve",
                    )),
                }
            }
            Ok(ic_pkix::PublicKeyInfo::Ed25519(k)) => return Ok(Self::Ed25519(k)),
            _ => {}
        }
        // Not one ic_pkix names: read the AlgorithmIdentifier ourselves.
        let mut outer = Reader::new(spki);
        let mut seq = outer.sequence().map_err(bad)?;
        outer.finish().map_err(bad)?;
        let mut alg = seq.sequence().map_err(bad)?;
        let oid = alg.oid().map_err(bad)?;
        let key = seq.bit_string().map_err(bad)?;
        seq.finish().map_err(bad)?;
        if let Some(p) = MlDsa::from_oid(oid) {
            // Parameters MUST be absent for ML-DSA.
            alg.finish().map_err(bad)?;
            if key.len() != p.public_len() {
                return Err(Error::new(
                    ErrorKind::BadCertificate,
                    "ml-dsa public key length",
                ));
            }
            return Ok(match p {
                MlDsa::P44 => Self::MlDsa44(key),
                MlDsa::P65 => Self::MlDsa65(key),
                MlDsa::P87 => Self::MlDsa87(key),
            });
        }
        if oid == ic_pkix::oid::EC_PUBLIC_KEY {
            let curve = alg.oid().map_err(bad)?;
            alg.finish().map_err(bad)?;
            if curve == OID_P521 {
                if key.len() != 133 || key[0] != 0x04 {
                    return Err(Error::new(
                        ErrorKind::BadCertificate,
                        "P-521 point encoding",
                    ));
                }
                return Ok(Self::EcP521(key));
            }
        }
        Err(Error::new(
            ErrorKind::UnsupportedCertificate,
            "unsupported public key algorithm",
        ))
    }

    /// Whether `scheme` is usable with this key. `REQ-SIG-001`.
    pub fn matches(&self, scheme: SignatureScheme) -> bool {
        use SignatureScheme as S;
        matches!(
            (self, scheme),
            (Self::EcP256(_), S::EcdsaSecp256r1Sha256)
                | (Self::EcP384(_), S::EcdsaSecp384r1Sha384)
                | (Self::EcP521(_), S::EcdsaSecp521r1Sha512)
                | (Self::Ed25519(_), S::Ed25519)
                | (Self::MlDsa44(_), S::MlDsa44)
                | (Self::MlDsa65(_), S::MlDsa65)
                | (Self::MlDsa87(_), S::MlDsa87)
                | (
                    Self::Rsa { .. },
                    S::RsaPssRsaeSha256
                        | S::RsaPssRsaeSha384
                        | S::RsaPssRsaeSha512
                        | S::RsaPkcs1Sha256
                        | S::RsaPkcs1Sha384
                        | S::RsaPkcs1Sha512
                )
        )
    }

    /// A short identifier for reports.
    pub fn kind_id(&self) -> &'static str {
        match self {
            Self::EcP256(_) => "key:ecdsa-p256",
            Self::EcP384(_) => "key:ecdsa-p384",
            Self::EcP521(_) => "key:ecdsa-p521",
            Self::Ed25519(_) => "key:ed25519",
            Self::Rsa { .. } => "key:rsa",
            Self::MlDsa44(_) => "key:ml-dsa-44",
            Self::MlDsa65(_) => "key:ml-dsa-65",
            Self::MlDsa87(_) => "key:ml-dsa-87",
        }
    }

    /// Security strength in bits against a classical adversary. ML-DSA-65 is
    /// NIST category 3 (AES-192) and ML-DSA-87 category 5 (AES-256).
    pub fn classical_bits(&self) -> u16 {
        match self {
            Self::EcP256(_) | Self::Ed25519(_) | Self::MlDsa44(_) => 128,
            Self::EcP384(_) | Self::MlDsa65(_) => 192,
            Self::EcP521(_) | Self::MlDsa87(_) => 256,
            Self::Rsa { modulus, .. } => match modulus.len() * 8 {
                n if n >= 15360 => 256,
                n if n >= 7680 => 192,
                n if n >= 3072 => 128,
                n if n >= 2048 => 112,
                _ => 0,
            },
        }
    }
}

/// Verify `signature` over `message` with `key` under `scheme`.
///
/// `signature` is in TLS/X.509 form: DER for ECDSA, raw for everything else.
pub fn verify(
    scheme: SignatureScheme,
    key: &PublicKey<'_>,
    message: &[u8],
    signature: &[u8],
) -> Result<()> {
    if !key.matches(scheme) {
        return Err(Error::new(
            ErrorKind::IllegalParameter,
            "signature scheme does not match the key",
        ));
    }
    let fail = |_| Error::new(ErrorKind::DecryptError, "signature did not verify");
    match (scheme, *key) {
        (SignatureScheme::EcdsaSecp256r1Sha256, PublicKey::EcP256(pk)) => {
            let mut fixed = [0u8; 64];
            ic_pkix::ecdsa_signature::from_der(signature, &mut fixed).map_err(fail)?;
            ic_ec::EcdsaP256Sha256::verify(pk, message, &fixed).map_err(fail)
        }
        (SignatureScheme::EcdsaSecp384r1Sha384, PublicKey::EcP384(pk)) => {
            let mut fixed = [0u8; 96];
            ic_pkix::ecdsa_signature::from_der(signature, &mut fixed).map_err(fail)?;
            ic_ec::EcdsaP384Sha384::verify(pk, message, &fixed).map_err(fail)
        }
        (SignatureScheme::EcdsaSecp521r1Sha512, PublicKey::EcP521(pk)) => {
            let mut fixed = [0u8; 132];
            ic_pkix::ecdsa_signature::from_der(signature, &mut fixed).map_err(fail)?;
            ic_ec::p521::EcdsaP521Sha512::verify(pk, message, &fixed).map_err(fail)
        }
        (SignatureScheme::Ed25519, PublicKey::Ed25519(pk)) => {
            ic_ec::Ed25519::verify(pk, message, signature).map_err(fail)
        }
        (SignatureScheme::MlDsa44, PublicKey::MlDsa44(pk)) => {
            MlDsa::P44.verify(pk, message, signature)
        }
        (SignatureScheme::MlDsa65, PublicKey::MlDsa65(pk)) => {
            MlDsa::P65.verify(pk, message, signature)
        }
        (SignatureScheme::MlDsa87, PublicKey::MlDsa87(pk)) => {
            MlDsa::P87.verify(pk, message, signature)
        }
        (s, PublicKey::Rsa { modulus, exponent }) => {
            let key = ic_rsa::RsaPublicKey::from_components(modulus, exponent).map_err(|_| {
                Error::new(
                    ErrorKind::UnsupportedCertificate,
                    "rsa key outside 2048..4096 bits",
                )
            })?;
            let r = match s {
                SignatureScheme::RsaPssRsaeSha256 => {
                    ic_rsa::PssSha256::verify(&key, message, signature)
                }
                SignatureScheme::RsaPssRsaeSha384 => {
                    ic_rsa::PssSha384::verify(&key, message, signature)
                }
                SignatureScheme::RsaPssRsaeSha512 => {
                    ic_rsa::PssSha512::verify(&key, message, signature)
                }
                SignatureScheme::RsaPkcs1Sha256 => {
                    ic_rsa::Pkcs1Sha256::verify(&key, message, signature)
                }
                SignatureScheme::RsaPkcs1Sha384 => {
                    ic_rsa::Pkcs1Sha384::verify(&key, message, signature)
                }
                SignatureScheme::RsaPkcs1Sha512 => {
                    ic_rsa::Pkcs1Sha512::verify(&key, message, signature)
                }
                _ => return Err(Error::new(ErrorKind::IllegalParameter, "scheme")),
            };
            r.map_err(fail)
        }
        _ => Err(Error::new(
            ErrorKind::IllegalParameter,
            "signature scheme does not match the key",
        )),
    }
}

enum KeyImpl {
    P256(Zeroizing<[u8; 32]>),
    P384(Zeroizing<[u8; 48]>),
    P521(Zeroizing<[u8; 66]>),
    Ed25519(Box<ic_ec::Ed25519Key>),
    Rsa(Box<ic_rsa::RsaPrivateKey>),
    /// The expanded secret key; `SecretVec` zeroizes it.
    MlDsa(MlDsa, SecretVec),
}

/// A private key that can sign handshakes. `REQ-SIG-003`: key bytes are
/// zeroized on drop.
pub struct SigningKey {
    inner: KeyImpl,
    /// DER `SubjectPublicKeyInfo` of the matching public key.
    spki: Vec<u8>,
}

impl core::fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "SigningKey({})", self.kind_id())
    }
}

fn copy_fixed<const N: usize>(src: &[u8]) -> Result<Zeroizing<[u8; N]>> {
    if src.len() > N {
        return Err(Error::new(
            ErrorKind::InvalidConfig,
            "private scalar too long",
        ));
    }
    // Left-pad: some encoders drop leading zero bytes from the scalar.
    let mut out = Zeroizing::new([0u8; N]);
    out.get_mut()[N - src.len()..].copy_from_slice(src);
    Ok(out)
}

fn ec_spki(curve_oid: &[u8], point: &[u8]) -> Result<Vec<u8>> {
    let mut alg = Vec::new();
    push_tlv(&mut alg, der::OID, ic_pkix::oid::EC_PUBLIC_KEY);
    push_tlv(&mut alg, der::OID, curve_oid);
    spki_from_parts(&alg, point)
}

/// Build `SEQUENCE { SEQUENCE { alg }, BIT STRING key }`.
fn spki_from_parts(alg_body: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    let mut body = Vec::new();
    push_tlv(&mut body, der::SEQUENCE, alg_body);
    let mut bits = Vec::with_capacity(key.len() + 1);
    bits.push(0);
    bits.extend_from_slice(key);
    push_tlv(&mut body, der::BIT_STRING, &bits);
    let mut out = Vec::new();
    push_tlv(&mut out, der::SEQUENCE, &body);
    Ok(out)
}

/// Append a DER TLV with a definite length.
pub fn push_tlv(out: &mut Vec<u8>, tag: u8, body: &[u8]) {
    out.push(tag);
    let n = body.len();
    if n < 0x80 {
        out.push(n as u8);
    } else if n <= 0xff {
        out.extend_from_slice(&[0x81, n as u8]);
    } else if n <= 0xffff {
        out.extend_from_slice(&[0x82, (n >> 8) as u8, n as u8]);
    } else {
        out.extend_from_slice(&[0x83, (n >> 16) as u8, (n >> 8) as u8, n as u8]);
    }
    out.extend_from_slice(body);
}

impl SigningKey {
    /// Sign into caller storage using the initialized key. `REQ-FIX-002`.
    /// No allocation occurs; `out` must accommodate the scheme's largest signature.
    pub fn sign_into(
        &self,
        scheme: SignatureScheme,
        message: &[u8],
        rng: &mut dyn RandomSource,
        out: &mut [u8],
    ) -> Result<usize> {
        if !self.schemes().contains(&scheme) {
            return Err(Error::new(
                ErrorKind::InvalidConfig,
                "scheme does not fit signing key",
            ));
        }
        let capacity = || Error::new(ErrorKind::CapacityExceeded, "signature storage");
        match &self.inner {
            KeyImpl::P256(sk) => {
                if out.len() < ic_pkix::ecdsa_signature::max_der_len(64) {
                    return Err(capacity());
                }
                let mut sig = [0u8; 64];
                ic_ec::EcdsaP256Sha256::sign(sk.get(), message, &mut sig)?;
                Ok(ic_pkix::ecdsa_signature::to_der(&sig, out)?)
            }
            KeyImpl::P384(sk) => {
                if out.len() < ic_pkix::ecdsa_signature::max_der_len(96) {
                    return Err(capacity());
                }
                let mut sig = [0u8; 96];
                ic_ec::EcdsaP384Sha384::sign(sk.get(), message, &mut sig)?;
                Ok(ic_pkix::ecdsa_signature::to_der(&sig, out)?)
            }
            KeyImpl::P521(sk) => {
                if out.len() < ic_pkix::ecdsa_signature::max_der_len(132) {
                    return Err(capacity());
                }
                let mut sig = [0u8; 132];
                ic_ec::p521::EcdsaP521Sha512::sign(sk.get(), message, &mut sig)?;
                Ok(ic_pkix::ecdsa_signature::to_der(&sig, out)?)
            }
            KeyImpl::Ed25519(k) => {
                k.sign(message, out.get_mut(..64).ok_or_else(capacity)?)?;
                Ok(64)
            }
            KeyImpl::Rsa(k) => {
                let sig = out.get_mut(..k.size()).ok_or_else(capacity)?;
                let mut rng = RngRef(rng);
                match scheme {
                    SignatureScheme::RsaPssRsaeSha256 => {
                        ic_rsa::PssSha256::sign(k, message, &mut rng, sig)?
                    }
                    SignatureScheme::RsaPssRsaeSha384 => {
                        ic_rsa::PssSha384::sign(k, message, &mut rng, sig)?
                    }
                    SignatureScheme::RsaPssRsaeSha512 => {
                        ic_rsa::PssSha512::sign(k, message, &mut rng, sig)?
                    }
                    _ => return Err(Error::new(ErrorKind::InvalidConfig, "TLS RSA scheme")),
                }
                Ok(sig.len())
            }
            KeyImpl::MlDsa(p, sk) => {
                let mut rnd = Zeroizing::new([0u8; 32]);
                super::fill_random(rng, rnd.get_mut())?;
                with_mldsa!(*p, m, {
                    let sig = out.get_mut(..m::SIGNATURE_LEN).ok_or_else(capacity)?;
                    let sig_arr = (&mut *sig).try_into().map_err(|_| capacity())?;
                    let sk = sk
                        .get()
                        .try_into()
                        .map_err(|_| Error::new(ErrorKind::Internal, "ML-DSA key length"))?;
                    if !m::sign(sk, message, b"", rnd.get(), sig_arr) {
                        return Err(Error::new(ErrorKind::Crypto, "ML-DSA signing failed"));
                    }
                    Ok(m::SIGNATURE_LEN)
                })
            }
        }
    }

    /// Load a PKCS#8 `PrivateKeyInfo` (DER).
    ///
    /// Accepts P-256, P-384, P-521, Ed25519, RSA (2048–4096 bits), and
    /// ML-DSA-65 in the seed form of draft-ietf-lamps-dilithium-certificates,
    /// or seed and expanded key together, which must agree. `REQ-SIG-004`.
    pub fn from_pkcs8_der(der_bytes: &[u8]) -> Result<Self> {
        // As for SPKI: ic_pkix errors on curves it does not name (P-521)
        // instead of reporting them unsupported, so an error falls through to
        // the reader for the forms it cannot handle.
        let parsed = match ic_pkix::PrivateKeyInfo::from_der(der_bytes) {
            Ok(p) => p,
            Err(_) => return Self::from_pkcs8_fallback(der_bytes),
        };
        match parsed {
            ic_pkix::PrivateKeyInfo::Ec {
                algorithm,
                private_key,
                ..
            } => match algorithm {
                ic_pkix::KeyAlgorithm::EcP256 => Self::ecdsa_p256(private_key),
                ic_pkix::KeyAlgorithm::EcP384 => Self::ecdsa_p384(private_key),
                ic_pkix::KeyAlgorithm::EcP521 => Self::ecdsa_p521(private_key),
                _ => Err(Error::new(ErrorKind::InvalidConfig, "unsupported curve")),
            },
            ic_pkix::PrivateKeyInfo::Ed25519(seed) => Self::ed25519(seed),
            ic_pkix::PrivateKeyInfo::Rsa {
                prime1,
                prime2,
                public_exponent,
                ..
            } => {
                // From the primes, so a file whose CRT values disagree with them
                // cannot produce a faulty signature that leaks the factorization.
                let key = ic_rsa::RsaPrivateKey::from_primes(prime1, prime2, public_exponent)
                    .map_err(|_| Error::new(ErrorKind::InvalidConfig, "rsa key rejected"))?;
                Self::rsa(key)
            }
            ic_pkix::PrivateKeyInfo::X25519(_) => Err(Error::new(
                ErrorKind::InvalidConfig,
                "an X25519 key agrees keys; it cannot sign",
            )),
            ic_pkix::PrivateKeyInfo::Unsupported { .. } => Self::from_pkcs8_fallback(der_bytes),
        }
    }

    /// Load a PEM `PRIVATE KEY` (PKCS#8) block.
    pub fn from_pem(text: &str) -> Result<Self> {
        let mut der_buf = Zeroizing::new([0u8; 8192]);
        let n = ic_pkix::pem::decode(
            ic_pkix::pem::PRIVATE_KEY,
            text.as_bytes(),
            der_buf.get_mut(),
        )
        .map_err(|_| {
            Error::new(
                ErrorKind::InvalidConfig,
                "no PEM PRIVATE KEY block (PKCS#8 expected)",
            )
        })?;
        Self::from_pkcs8_der(&der_buf.get()[..n])
    }

    /// PKCS#8 forms `ic_pkix` does not name: P-521, ML-DSA-44, ML-DSA-65 and ML-DSA-87.
    fn from_pkcs8_fallback(der_bytes: &[u8]) -> Result<Self> {
        let bad = |_| Error::new(ErrorKind::InvalidConfig, "malformed PKCS#8 private key");
        let mut outer = Reader::new(der_bytes);
        let mut seq = outer.sequence().map_err(bad)?;
        seq.expect_version(0).map_err(bad)?;
        let mut alg = seq.sequence().map_err(bad)?;
        let oid = alg.oid().map_err(bad)?;
        let key = seq.octet_string().map_err(bad)?;
        if let Some(p) = MlDsa::from_oid(oid) {
            // Seed form: [0] IMPLICIT OCTET STRING (SIZE (32)), i.e. 0x80 0x20.
            if key.len() == 34 && key[0] == 0x80 && key[1] == 0x20 {
                let mut seed = Zeroizing::new([0u8; 32]);
                seed.get_mut().copy_from_slice(&key[2..]);
                return Self::mldsa_from_seed(p, seed.get());
            }
            // Both form: SEQUENCE { seed OCTET STRING (32), expandedKey OCTET STRING }.
            // OpenSSL 3.5 writes this by default. The key is rebuilt from the
            // seed and the expanded copy must match it, so a file whose two
            // halves disagree is refused rather than half-trusted.
            if key.first() == Some(&der::SEQUENCE) {
                let mut inner = Reader::new(key);
                let mut both = inner.sequence().map_err(bad)?;
                inner.finish().map_err(bad)?;
                let seed_bytes = both.octet_string().map_err(bad)?;
                let expanded = both.octet_string().map_err(bad)?;
                both.finish().map_err(bad)?;
                let seed: &[u8; 32] = seed_bytes.try_into().map_err(|_| {
                    Error::new(ErrorKind::InvalidConfig, "ML-DSA seed must be 32 bytes")
                })?;
                let key = Self::mldsa_from_seed(p, seed)?;
                if let KeyImpl::MlDsa(_, sk) = &key.inner {
                    if !ic_core::ct::verify(sk.get(), expanded) {
                        return Err(Error::new(
                            ErrorKind::InvalidConfig,
                            "ML-DSA expanded key does not match its seed",
                        ));
                    }
                }
                return Ok(key);
            }
            return Err(Error::new(
                ErrorKind::InvalidConfig,
                "unrecognised ML-DSA private key form",
            ));
        }
        if oid == ic_pkix::oid::EC_PUBLIC_KEY && alg.oid().map_err(bad)? == OID_P521 {
            // ECPrivateKey ::= SEQUENCE { version 1, privateKey OCTET STRING, ... }
            let mut ec = Reader::new(key);
            let mut body = ec.sequence().map_err(bad)?;
            body.expect_version(1).map_err(bad)?;
            let scalar = body.octet_string().map_err(bad)?;
            return Self::ecdsa_p521(scalar);
        }
        Err(Error::new(
            ErrorKind::InvalidConfig,
            "unsupported private key algorithm",
        ))
    }

    /// An ECDSA P-256 key from its 32-byte scalar.
    pub fn ecdsa_p256(scalar: &[u8]) -> Result<Self> {
        let sk = copy_fixed::<32>(scalar)?;
        let mut pk = [0u8; 65];
        ic_ec::EcdsaP256Sha256::public_key(sk.get(), &mut pk)
            .map_err(|_| Error::new(ErrorKind::InvalidConfig, "invalid P-256 scalar"))?;
        Ok(Self {
            spki: ec_spki(ic_pkix::oid::P256, &pk)?,
            inner: KeyImpl::P256(sk),
        })
    }

    /// An ECDSA P-384 key from its 48-byte scalar.
    pub fn ecdsa_p384(scalar: &[u8]) -> Result<Self> {
        let sk = copy_fixed::<48>(scalar)?;
        let mut pk = [0u8; 97];
        ic_ec::EcdsaP384Sha384::public_key(sk.get(), &mut pk)
            .map_err(|_| Error::new(ErrorKind::InvalidConfig, "invalid P-384 scalar"))?;
        Ok(Self {
            spki: ec_spki(ic_pkix::oid::P384, &pk)?,
            inner: KeyImpl::P384(sk),
        })
    }

    /// An ECDSA P-521 key from its 66-byte scalar.
    pub fn ecdsa_p521(scalar: &[u8]) -> Result<Self> {
        let sk = copy_fixed::<66>(scalar)?;
        let mut pk = [0u8; 133];
        ic_ec::p521::EcdsaP521Sha512::public_key(sk.get(), &mut pk)
            .map_err(|_| Error::new(ErrorKind::InvalidConfig, "invalid P-521 scalar"))?;
        Ok(Self {
            spki: ec_spki(OID_P521, &pk)?,
            inner: KeyImpl::P521(sk),
        })
    }

    /// An Ed25519 key from its 32-byte seed.
    pub fn ed25519(seed: &[u8]) -> Result<Self> {
        let key = ic_ec::Ed25519Key::from_seed(seed)
            .map_err(|_| Error::new(ErrorKind::InvalidConfig, "invalid Ed25519 seed"))?;
        let mut alg = Vec::new();
        push_tlv(&mut alg, der::OID, ic_pkix::oid::ED25519);
        let spki = spki_from_parts(&alg, key.public_key())?;
        Ok(Self {
            spki,
            inner: KeyImpl::Ed25519(Box::new(key)),
        })
    }

    /// An RSA key.
    pub fn rsa(key: ic_rsa::RsaPrivateKey) -> Result<Self> {
        let size = key.size();
        let mut modulus = alloc::vec![0u8; size];
        key.public_key().modulus_bytes(&mut modulus)?;
        let mut rsa_pub = alloc::vec![0u8; size + 32];
        let n = ic_pkix::write_rsa_public_key(&modulus, key.public_key().exponent(), &mut rsa_pub)?;
        let mut alg = Vec::new();
        push_tlv(&mut alg, der::OID, ic_pkix::oid::RSA_ENCRYPTION);
        push_tlv(&mut alg, der::NULL, &[]);
        // ic_pkix's writer builds from the end of the buffer, and `finish`
        // then moves the result to the front.
        let spki = spki_from_parts(&alg, &rsa_pub[..n])?;
        Ok(Self {
            spki,
            inner: KeyImpl::Rsa(Box::new(key)),
        })
    }

    /// An ML-DSA-44 key from its 32-byte seed (FIPS 204 `ξ`).
    /// REQ-SIG-005: ML-DSA-44 generation, key loading, signing and verification
    /// use IronCrypto's category 2 parameter set and RFC 9881 identifiers.
    pub fn mldsa44_from_seed(seed: &[u8; 32]) -> Result<Self> {
        Self::mldsa_from_seed(MlDsa::P44, seed)
    }

    /// An ML-DSA-65 key from its 32-byte seed (FIPS 204 `ξ`).
    pub fn mldsa65_from_seed(seed: &[u8; 32]) -> Result<Self> {
        Self::mldsa_from_seed(MlDsa::P65, seed)
    }

    /// An ML-DSA-87 key from its 32-byte seed (FIPS 204 `ξ`).
    pub fn mldsa87_from_seed(seed: &[u8; 32]) -> Result<Self> {
        Self::mldsa_from_seed(MlDsa::P87, seed)
    }

    fn mldsa_from_seed(p: MlDsa, seed: &[u8; 32]) -> Result<Self> {
        let (pk, sk) = p.keygen(seed)?;
        let mut alg = Vec::new();
        push_tlv(&mut alg, der::OID, p.oid());
        let spki = spki_from_parts(&alg, &pk)?;
        Ok(Self {
            spki,
            inner: KeyImpl::MlDsa(p, sk),
        })
    }

    /// Generate a fresh key of the given kind. Used by tests and by agents
    /// provisioning ephemeral identities.
    pub fn generate(kind: KeyKind, rng: &mut dyn RandomSource) -> Result<Self> {
        let mut seed = SecretVec::new(alloc::vec![0u8; 66]);
        for _ in 0..64 {
            super::fill_random(rng, seed.get_mut())?;
            let s = seed.get();
            let r = match kind {
                KeyKind::EcdsaP256 => Self::ecdsa_p256(&s[..32]),
                KeyKind::EcdsaP384 => Self::ecdsa_p384(&s[..48]),
                KeyKind::EcdsaP521 => {
                    let mut k = [0u8; 66];
                    k.copy_from_slice(&s[..66]);
                    k[0] &= 0x01;
                    let r = Self::ecdsa_p521(&k);
                    k.zeroize();
                    r
                }
                KeyKind::Ed25519 => Self::ed25519(&s[..32]),
                KeyKind::MlDsa44 | KeyKind::MlDsa65 | KeyKind::MlDsa87 => {
                    let p = match kind {
                        KeyKind::MlDsa44 => MlDsa::P44,
                        KeyKind::MlDsa65 => MlDsa::P65,
                        _ => MlDsa::P87,
                    };
                    let mut k = [0u8; 32];
                    k.copy_from_slice(&s[..32]);
                    let r = Self::mldsa_from_seed(p, &k);
                    k.zeroize();
                    r
                }
            };
            if let Ok(key) = r {
                return Ok(key);
            }
        }
        Err(Error::new(ErrorKind::Entropy, "could not generate a key"))
    }

    /// DER `SubjectPublicKeyInfo` of the public half.
    pub fn spki(&self) -> &[u8] {
        &self.spki
    }

    /// A short identifier for reports.
    pub fn kind_id(&self) -> &'static str {
        match &self.inner {
            KeyImpl::P256(_) => "key:ecdsa-p256",
            KeyImpl::P384(_) => "key:ecdsa-p384",
            KeyImpl::P521(_) => "key:ecdsa-p521",
            KeyImpl::Ed25519(_) => "key:ed25519",
            KeyImpl::Rsa(_) => "key:rsa",
            KeyImpl::MlDsa(p, _) => p.kind_id(),
        }
    }

    /// Schemes this key can sign a handshake with, most preferred first.
    /// `REQ-SIG-002`: never PKCS#1 v1.5.
    pub fn schemes(&self) -> &'static [SignatureScheme] {
        use SignatureScheme as S;
        match &self.inner {
            KeyImpl::P256(_) => &[S::EcdsaSecp256r1Sha256],
            KeyImpl::P384(_) => &[S::EcdsaSecp384r1Sha384],
            KeyImpl::P521(_) => &[S::EcdsaSecp521r1Sha512],
            KeyImpl::Ed25519(_) => &[S::Ed25519],
            KeyImpl::Rsa(_) => &[
                S::RsaPssRsaeSha256,
                S::RsaPssRsaeSha384,
                S::RsaPssRsaeSha512,
            ],
            KeyImpl::MlDsa(MlDsa::P44, _) => &[S::MlDsa44],
            KeyImpl::MlDsa(MlDsa::P65, _) => &[S::MlDsa65],
            KeyImpl::MlDsa(MlDsa::P87, _) => &[S::MlDsa87],
        }
    }

    /// The first scheme this key supports that the peer offered and `allowed`
    /// permits, in this key's preference order.
    pub fn choose_scheme(
        &self,
        offered: &[SignatureScheme],
        allowed: &[SignatureScheme],
    ) -> Option<SignatureScheme> {
        self.schemes()
            .iter()
            .copied()
            .find(|s| offered.contains(s) && allowed.contains(s))
    }

    /// Sign `message` under `scheme`, producing TLS wire form.
    pub fn sign(
        &self,
        scheme: SignatureScheme,
        message: &[u8],
        rng: &mut dyn RandomSource,
    ) -> Result<Vec<u8>> {
        if !self.schemes().contains(&scheme) {
            return Err(Error::new(
                ErrorKind::Internal,
                "scheme not supported by this key",
            ));
        }
        let ecdsa_der = |fixed: &[u8]| -> Result<Vec<u8>> {
            let mut der_buf = alloc::vec![0u8; ic_pkix::ecdsa_signature::max_der_len(fixed.len())];
            let n = ic_pkix::ecdsa_signature::to_der(fixed, &mut der_buf)?;
            der_buf.truncate(n);
            Ok(der_buf)
        };
        match &self.inner {
            KeyImpl::P256(sk) => {
                let mut sig = [0u8; 64];
                ic_ec::EcdsaP256Sha256::sign(sk.get(), message, &mut sig)?;
                ecdsa_der(&sig)
            }
            KeyImpl::P384(sk) => {
                let mut sig = [0u8; 96];
                ic_ec::EcdsaP384Sha384::sign(sk.get(), message, &mut sig)?;
                ecdsa_der(&sig)
            }
            KeyImpl::P521(sk) => {
                let mut sig = [0u8; 132];
                ic_ec::p521::EcdsaP521Sha512::sign(sk.get(), message, &mut sig)?;
                ecdsa_der(&sig)
            }
            KeyImpl::Ed25519(k) => {
                let mut sig = alloc::vec![0u8; 64];
                k.sign(message, &mut sig)?;
                Ok(sig)
            }
            KeyImpl::Rsa(k) => {
                let mut sig = alloc::vec![0u8; k.size()];
                let mut rng = RngRef(rng);
                match scheme {
                    SignatureScheme::RsaPssRsaeSha256 => {
                        ic_rsa::PssSha256::sign(k, message, &mut rng, &mut sig)?
                    }
                    SignatureScheme::RsaPssRsaeSha384 => {
                        ic_rsa::PssSha384::sign(k, message, &mut rng, &mut sig)?
                    }
                    SignatureScheme::RsaPssRsaeSha512 => {
                        ic_rsa::PssSha512::sign(k, message, &mut rng, &mut sig)?
                    }
                    _ => return Err(Error::new(ErrorKind::Internal, "rsa scheme")),
                }
                Ok(sig)
            }
            KeyImpl::MlDsa(p, sk) => {
                // Hedged signing: fresh randomness per FIPS 204 §3.4.
                let mut rnd = Zeroizing::new([0u8; 32]);
                super::fill_random(rng, rnd.get_mut())?;
                debug_assert_eq!(p.scheme(), scheme);
                p.sign(sk.get(), message, rnd.get())
            }
        }
    }
}

struct RngRef<'a>(&'a mut dyn RandomSource);

impl RandomSource for RngRef<'_> {
    fn fill(&mut self, out: &mut [u8]) -> ic_core::Result<()> {
        self.0.fill(out)
    }
}

/// Key types [`SigningKey::generate`] can create.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyKind {
    /// ECDSA P-256.
    EcdsaP256,
    /// ECDSA P-384.
    EcdsaP384,
    /// ECDSA P-521.
    EcdsaP521,
    /// Ed25519.
    Ed25519,
    /// ML-DSA-44.
    MlDsa44,
    /// ML-DSA-65.
    MlDsa65,
    /// ML-DSA-87.
    MlDsa87,
}

impl KeyKind {
    /// Every kind.
    pub const ALL: &'static [KeyKind] = &[
        Self::EcdsaP256,
        Self::EcdsaP384,
        Self::EcdsaP521,
        Self::Ed25519,
        Self::MlDsa44,
        Self::MlDsa65,
        Self::MlDsa87,
    ];

    /// Stable identifier.
    pub const fn id(self) -> &'static str {
        match self {
            Self::EcdsaP256 => "key:ecdsa-p256",
            Self::EcdsaP384 => "key:ecdsa-p384",
            Self::EcdsaP521 => "key:ecdsa-p521",
            Self::Ed25519 => "key:ed25519",
            Self::MlDsa44 => "key:ml-dsa-44",
            Self::MlDsa65 => "key:ml-dsa-65",
            Self::MlDsa87 => "key:ml-dsa-87",
        }
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;

    #[test]
    fn every_key_kind_signs_and_its_spki_verifies() {
        let mut rng = ic_drbg::Rng::from_os().unwrap();
        for &kind in KeyKind::ALL {
            let key = SigningKey::generate(kind, &mut rng).unwrap();
            let pk = PublicKey::from_spki(key.spki()).unwrap();
            assert_eq!(pk.kind_id(), kind.id());
            for &scheme in key.schemes() {
                let sig = key.sign(scheme, b"transcript", &mut rng).unwrap();
                verify(scheme, &pk, b"transcript", &sig).unwrap();
                assert_eq!(
                    verify(scheme, &pk, b"transcripT", &sig).unwrap_err().kind(),
                    ErrorKind::DecryptError,
                    "{kind:?} accepted a signature over another message"
                );
            }
        }
    }

    #[test]
    fn a_scheme_that_does_not_fit_the_key_is_refused() {
        let mut rng = ic_drbg::Rng::from_os().unwrap();
        let key = SigningKey::generate(KeyKind::EcdsaP256, &mut rng).unwrap();
        let pk = PublicKey::from_spki(key.spki()).unwrap();
        let sig = key
            .sign(SignatureScheme::EcdsaSecp256r1Sha256, b"m", &mut rng)
            .unwrap();
        assert_eq!(
            verify(SignatureScheme::EcdsaSecp384r1Sha384, &pk, b"m", &sig)
                .unwrap_err()
                .kind(),
            ErrorKind::IllegalParameter
        );
        assert!(key
            .sign(SignatureScheme::RsaPkcs1Sha256, b"m", &mut rng)
            .is_err());
    }

    /// Malformed public and private keys are refused rather than truncated
    /// or padded: ML-DSA keys of the wrong length, P-521 points that are
    /// short or compressed, over-long EC scalars, and ML-DSA PKCS#8 in neither
    /// the seed nor the seed-and-expanded form. `REQ-SIG-004`.
    #[test]
    fn malformed_keys_are_refused() {
        for oid in [OID_ML_DSA_44, OID_ML_DSA_65, OID_ML_DSA_87] {
            let mut alg = Vec::new();
            push_tlv(&mut alg, der::OID, oid);
            let spki = spki_from_parts(&alg, &[7u8; 100]).unwrap();
            let e = PublicKey::from_spki(&spki).unwrap_err();
            assert_eq!(e.kind(), ErrorKind::BadCertificate, "{e}");

            // PKCS#8 whose key is an OCTET STRING: neither accepted form.
            let mut inner = Vec::new();
            push_tlv(&mut inner, der::OCTET_STRING, &[1u8; 32]);
            let mut body = Vec::new();
            push_tlv(&mut body, der::INTEGER, &[0]);
            push_tlv(&mut body, der::SEQUENCE, &alg);
            push_tlv(&mut body, der::OCTET_STRING, &inner);
            let mut pkcs8 = Vec::new();
            push_tlv(&mut pkcs8, der::SEQUENCE, &body);
            let e = SigningKey::from_pkcs8_der(&pkcs8).err().unwrap();
            assert!(
                e.to_string()
                    .contains("unrecognised ML-DSA private key form"),
                "{e}"
            );
        }
        let mut alg = Vec::new();
        push_tlv(&mut alg, der::OID, ic_pkix::oid::EC_PUBLIC_KEY);
        push_tlv(&mut alg, der::OID, OID_P521);
        let mut point = alloc::vec![0x04u8; 133];
        assert!(PublicKey::from_spki(&spki_from_parts(&alg, &point).unwrap()).is_ok());
        point[0] = 0x02;
        assert!(PublicKey::from_spki(&spki_from_parts(&alg, &point).unwrap()).is_err());
        assert!(PublicKey::from_spki(&spki_from_parts(&alg, &[0x04; 132]).unwrap()).is_err());
        assert_eq!(
            SigningKey::ecdsa_p256(&[1u8; 33]).err().map(|e| e.kind()),
            Some(ErrorKind::InvalidConfig)
        );
    }

    /// Classical strength follows SP 800-57 for RSA moduli, and FIPS 204's
    /// categories for ML-DSA.
    #[test]
    fn classical_strength_tiers() {
        let rsa = |bytes: usize| PublicKey::Rsa {
            modulus: alloc::vec![0xffu8; bytes].leak(),
            exponent: 65537,
        };
        assert_eq!(rsa(128).classical_bits(), 0);
        assert_eq!(rsa(256).classical_bits(), 112);
        assert_eq!(rsa(384).classical_bits(), 128);
        assert_eq!(rsa(960).classical_bits(), 192);
        assert_eq!(rsa(1920).classical_bits(), 256);
        assert_eq!(PublicKey::MlDsa44(&[]).classical_bits(), 128);
        assert_eq!(PublicKey::MlDsa65(&[]).classical_bits(), 192);
        assert_eq!(PublicKey::MlDsa87(&[]).classical_bits(), 256);
    }
}
