//! OCSP responses (RFC 6960) for TLS certificate-status stapling.
//!
//! [`verify_response`] checks a stapled response for an end-entity
//! certificate; [`build_response`] produces one, so an operator of a private
//! CA — an agent fleet's issuer, for instance — can staple fresh status without
//! running a responder.
//!
//! # What a response must satisfy
//!
//! * It is signed by the leaf's issuer, or by a responder certificate the
//!   issuer signed, that is currently valid and carries `id-kp-OCSPSigning`
//!   (RFC 6960 §4.2.2.2). `REQ-OCSP-001`.
//! * It is current: `thisUpdate` is not in the future and `nextUpdate` has not
//!   passed, with five minutes of allowed clock skew; a response without
//!   `nextUpdate` is accepted for four days from `thisUpdate`. `REQ-OCSP-002`.
//! * One of its `SingleResponse`s names the leaf. `REQ-OCSP-004`.
//! * A revoked status is always fatal. `REQ-OCSP-003`.
//!
//! # SHA-1 CertIDs
//!
//! Most responders identify certificates with SHA-1 hashes of the issuer's
//! name and key. IronCrypto implements no SHA-1, so for a SHA-1 CertID only the
//! serial number is compared; the issuer is bound instead by the response's
//! signature, which must come from the leaf's issuer or its certified
//! delegate — the only parties that can speak for serials under that issuer.
//! SHA-256, SHA-384 and SHA-512 CertIDs are checked in full.

use alloc::vec::Vec;

use ic_core::traits::RandomSource;

use super::{
    alg_id, civil_from_days, hash_alg_id, parse_time, push_tlv, scheme_from_alg, whole_bits,
    Certificate, Der, OID_SHA256, OID_SHA384, OID_SHA512, T_BIT_STRING, T_CTX0, T_CTX1, T_CTX2,
    T_GENERALIZED_TIME, T_INTEGER, T_OCTET_STRING, T_OID, T_SEQUENCE,
};
use crate::crypto::sign::{self, PublicKey, SigningKey};
use crate::crypto::HashAlg;
use crate::enums::SignatureScheme;
use crate::error::{Error, ErrorKind, Result};

/// id-pkix-ocsp-basic, 1.3.6.1.5.5.7.48.1.1.
const OID_OCSP_BASIC: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01];
/// id-kp-OCSPSigning, 1.3.6.1.5.5.7.3.9.
const OID_KP_OCSP_SIGNING: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x09];
/// id-sha1, 1.3.14.3.2.26.
const OID_SHA1: &[u8] = &[0x2b, 0x0e, 0x03, 0x02, 0x1a];
const T_ENUMERATED: u8 = 0x0a;
const T_GOOD: u8 = 0x80;
const T_REVOKED: u8 = 0xa1;
const T_UNKNOWN: u8 = 0x82;

/// Clock skew tolerated on `thisUpdate` and `nextUpdate`.
pub const MAX_SKEW: u64 = 300;
/// How long a response without `nextUpdate` is accepted.
pub const MAX_AGE_WITHOUT_NEXT_UPDATE: u64 = 4 * 86_400;

/// A certificate's status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertStatus {
    /// Not revoked.
    Good,
    /// Revoked at the given Unix time.
    Revoked {
        /// Revocation time.
        at: u64,
    },
    /// The responder does not know the certificate.
    Unknown,
}

impl CertStatus {
    /// Stable identifier.
    pub const fn id(self) -> &'static str {
        match self {
            Self::Good => "revocation:good",
            Self::Revoked { .. } => "revocation:revoked",
            Self::Unknown => "revocation:unknown",
        }
    }
}

/// What a verified response established.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OcspVerified {
    /// The leaf's status (never `Revoked`: that is an error).
    pub status: CertStatus,
    /// `thisUpdate`.
    pub this_update: u64,
    /// `nextUpdate`, if present.
    pub next_update: Option<u64>,
    /// Whether a delegated responder, not the issuer, signed it.
    pub delegated: bool,
    /// Whether the CertID's issuer hashes were checked (false for SHA-1).
    pub cert_id_hashes_checked: bool,
}

fn bad(context: &'static str) -> Error {
    Error::new(ErrorKind::BadCertificateStatus, context)
}

fn cert_id_hash(oid: &[u8]) -> Option<Option<HashAlg>> {
    // Some(Some(h)): hash we can compute; Some(None): SHA-1; None: unknown.
    match oid {
        OID_SHA256 => Some(Some(HashAlg::Sha256)),
        OID_SHA384 => Some(Some(HashAlg::Sha384)),
        OID_SHA1 => Some(None),
        _ => None,
    }
}

fn digest(oid: &[u8], data: &[u8]) -> Option<Vec<u8>> {
    use ic_core::traits::Digest;
    Some(match oid {
        OID_SHA256 => ic_hash::Sha256::digest(data).as_ref().to_vec(),
        OID_SHA384 => ic_hash::Sha384::digest(data).as_ref().to_vec(),
        OID_SHA512 => ic_hash::Sha512::digest(data).as_ref().to_vec(),
        _ => return None,
    })
}

/// The `subjectPublicKey` bits of an SPKI: what `issuerKeyHash` hashes.
fn spki_key_bits(spki: &[u8]) -> Result<&[u8]> {
    let mut outer = Der::new(spki);
    let mut seq = outer.nested(T_SEQUENCE)?;
    let _alg = seq.expect(T_SEQUENCE)?;
    let bits = whole_bits(seq.expect(T_BIT_STRING)?)?;
    seq.finish()?;
    Ok(bits)
}

struct Single<'a> {
    hash_oid: &'a [u8],
    name_hash: &'a [u8],
    key_hash: &'a [u8],
    serial: &'a [u8],
    status: CertStatus,
    this_update: u64,
    next_update: Option<u64>,
}

fn parse_single(body: &[u8]) -> Result<Single<'_>> {
    let mut r = Der::new(body);
    let mut id = r.nested(T_SEQUENCE)?;
    let mut alg = id.nested(T_SEQUENCE)?;
    let hash_oid = alg.expect(T_OID)?;
    alg.optional_null()?;
    alg.finish()?;
    let name_hash = id.expect(T_OCTET_STRING)?;
    let key_hash = id.expect(T_OCTET_STRING)?;
    let serial = id.expect(T_INTEGER)?;
    id.finish()?;
    let (tag, content, _) = r.tlv()?;
    let status = match tag {
        T_GOOD if content.is_empty() => CertStatus::Good,
        T_UNKNOWN if content.is_empty() => CertStatus::Unknown,
        T_REVOKED => {
            let mut rev = Der::new(content);
            let (t, v, _) = rev.tlv()?;
            CertStatus::Revoked {
                at: parse_time(t, v)?,
            }
        }
        _ => return Err(bad("unknown certStatus")),
    };
    let (t, v, _) = r.tlv()?;
    if t != T_GENERALIZED_TIME {
        return Err(bad("thisUpdate is not GeneralizedTime"));
    }
    let this_update = parse_time(t, v)?;
    let mut next_update = None;
    if let Some(n) = r.optional(T_CTX0)? {
        let mut n = Der::new(n);
        let (t, v, _) = n.tlv()?;
        next_update = Some(parse_time(t, v)?);
        n.finish()?;
    }
    let _ = r.optional(T_CTX1)?;
    r.finish()?;
    Ok(Single {
        hash_oid,
        name_hash,
        key_hash,
        serial,
        status,
        this_update,
        next_update,
    })
}

/// Verify a stapled OCSP response for `leaf_der`, whose issuer has subject
/// `issuer_subject` and key `issuer_spki` (from [`super::ChainReport`]).
///
/// Returns `Ok` for `Good` and `Unknown`; a revoked certificate is
/// [`ErrorKind::CertificateRevoked`]; anything invalid, stale or unrelated is
/// [`ErrorKind::BadCertificateStatus`]. Only a successful, basic response
/// signed under one of `allowed_schemes` is considered (`REQ-OCSP-006`); a
/// scheme outside them is [`ErrorKind::PolicyViolation`].
pub fn verify_response(
    response_der: &[u8],
    leaf_der: &[u8],
    issuer_subject: &[u8],
    issuer_spki: &[u8],
    now: u64,
    allowed_schemes: &[SignatureScheme],
) -> Result<OcspVerified> {
    let leaf = Certificate::parse(leaf_der)?;
    let wrap = |e: Error| {
        if e.kind() == ErrorKind::BadCertificate {
            bad(e.context())
        } else {
            e
        }
    };

    // OCSPResponse
    let mut outer = Der::new(response_der);
    let mut resp = outer.nested(T_SEQUENCE).map_err(wrap)?;
    outer.finish().map_err(wrap)?;
    if resp.expect(T_ENUMERATED).map_err(wrap)? != [0] {
        return Err(bad("OCSP responseStatus is not successful"));
    }
    let mut bytes = Der::new(resp.expect(T_CTX0).map_err(wrap)?)
        .nested(T_SEQUENCE)
        .map_err(wrap)?;
    resp.finish().map_err(wrap)?;
    if bytes.expect(T_OID).map_err(wrap)? != OID_OCSP_BASIC {
        return Err(bad("not a basic OCSP response"));
    }
    let basic = bytes.expect(T_OCTET_STRING).map_err(wrap)?;
    bytes.finish().map_err(wrap)?;

    // BasicOCSPResponse
    let mut b = Der::new(basic).nested(T_SEQUENCE).map_err(wrap)?;
    let tbs = b.expect_raw(T_SEQUENCE).map_err(wrap)?;
    let sig_alg = b.expect(T_SEQUENCE).map_err(wrap)?;
    let signature = whole_bits(b.expect(T_BIT_STRING).map_err(wrap)?).map_err(wrap)?;
    let certs = b.optional(T_CTX0).map_err(wrap)?;
    b.finish().map_err(wrap)?;
    let scheme =
        scheme_from_alg(sig_alg).map_err(|_| bad("unsupported OCSP signature algorithm"))?;
    if !allowed_schemes.contains(&scheme) {
        return Err(Error::new(
            ErrorKind::PolicyViolation,
            "OCSP signature scheme not allowed by policy",
        ));
    }

    // REQ-OCSP-001: the issuer, or a delegate the issuer certified.
    let issuer_key = PublicKey::from_spki(issuer_spki)?;
    let mut delegated = false;
    let mut signed = sign::verify(scheme, &issuer_key, tbs, signature).is_ok();
    if !signed {
        if let Some(certs) = certs {
            let mut list = Der::new(certs).nested(T_SEQUENCE).map_err(wrap)?;
            while !list.is_empty() && !signed {
                let (_, _, whole) = list.tlv().map_err(wrap)?;
                let Ok(responder) = Certificate::parse(whole) else {
                    continue;
                };
                if responder_authorized(
                    &responder,
                    issuer_subject,
                    &issuer_key,
                    now,
                    allowed_schemes,
                )
                .is_ok()
                {
                    let key = responder.subject_public_key()?;
                    signed = sign::verify(scheme, &key, tbs, signature).is_ok();
                    delegated = signed;
                }
            }
        }
    }
    if !signed {
        return Err(bad(
            "OCSP response is not signed by the issuer or an authorized responder",
        ));
    }

    // ResponseData
    let mut t = Der::new(tbs).nested(T_SEQUENCE).map_err(wrap)?;
    let _version = t.optional(T_CTX0).map_err(wrap)?;
    let (rid_tag, _, _) = t.tlv().map_err(wrap)?;
    if rid_tag != T_CTX1 && rid_tag != T_CTX2 {
        return Err(bad("unknown responderID form"));
    }
    let (pt, pv, _) = t.tlv().map_err(wrap)?;
    if pt != T_GENERALIZED_TIME {
        return Err(bad("producedAt is not GeneralizedTime"));
    }
    parse_time(pt, pv).map_err(wrap)?;
    let mut responses = t.nested(T_SEQUENCE).map_err(wrap)?;
    let _ = t.optional(T_CTX1).map_err(wrap)?;
    t.finish().map_err(wrap)?;

    // REQ-OCSP-004: find the SingleResponse for this leaf.
    let key_bits = spki_key_bits(issuer_spki)?;
    let mut found = None;
    while !responses.is_empty() {
        let body = responses.expect(T_SEQUENCE).map_err(wrap)?;
        let single = parse_single(body).map_err(wrap)?;
        if single.serial != leaf.serial() {
            continue;
        }
        let checked = match cert_id_hash(single.hash_oid) {
            None => continue,
            Some(None) => false,
            Some(Some(_)) => {
                let (Some(n), Some(k)) = (
                    digest(single.hash_oid, issuer_subject),
                    digest(single.hash_oid, key_bits),
                ) else {
                    continue;
                };
                if !ic_core::ct::verify(&n, single.name_hash)
                    || !ic_core::ct::verify(&k, single.key_hash)
                {
                    continue;
                }
                true
            }
        };
        found = Some((single, checked));
        break;
    }
    let (single, checked) = found.ok_or(bad("OCSP response does not cover this certificate"))?;

    // REQ-OCSP-002: currency.
    if single.this_update > now.saturating_add(MAX_SKEW) {
        return Err(bad("OCSP response is from the future"));
    }
    match single.next_update {
        Some(next) if now > next.saturating_add(MAX_SKEW) => {
            return Err(bad("OCSP response is stale"))
        }
        None if now
            > single
                .this_update
                .saturating_add(MAX_AGE_WITHOUT_NEXT_UPDATE) =>
        {
            return Err(bad("OCSP response without nextUpdate is too old"))
        }
        _ => {}
    }

    // REQ-OCSP-003.
    if let CertStatus::Revoked { .. } = single.status {
        return Err(Error::new(
            ErrorKind::CertificateRevoked,
            "the certificate has been revoked",
        ));
    }
    Ok(OcspVerified {
        status: single.status,
        this_update: single.this_update,
        next_update: single.next_update,
        delegated,
        cert_id_hashes_checked: checked,
    })
}

/// A delegated responder must be issued by the leaf's issuer, valid now, and
/// carry id-kp-OCSPSigning explicitly (anyExtendedKeyUsage does not count).
fn responder_authorized(
    responder: &Certificate<'_>,
    issuer_subject: &[u8],
    issuer_key: &PublicKey<'_>,
    now: u64,
    allowed: &[SignatureScheme],
) -> Result<()> {
    if responder.issuer != issuer_subject {
        return Err(bad("responder not issued by the certificate's issuer"));
    }
    responder.check_validity(now)?;
    let scheme = responder.signature_scheme()?;
    if !allowed.contains(&scheme) {
        return Err(bad("responder certificate scheme not allowed"));
    }
    sign::verify(scheme, issuer_key, responder.tbs, responder.signature)
        .map_err(|_| bad("responder certificate not signed by the issuer"))?;
    let eku = responder
        .ext
        .eku
        .ok_or(bad("responder lacks id-kp-OCSPSigning"))?;
    let mut r = Der::new(eku);
    while !r.is_empty() {
        let oid = r.expect(T_OID)?;
        // anyExtendedKeyUsage does not authorise OCSP signing (RFC 6960 §4.2.2.2).
        if oid == OID_KP_OCSP_SIGNING {
            return Ok(());
        }
    }
    Err(bad("responder lacks id-kp-OCSPSigning"))
}

fn generalized_time(out: &mut Vec<u8>, t: u64) {
    let (y, m, d) = civil_from_days((t / 86_400) as i64);
    let rem = t % 86_400;
    let body = alloc::format!(
        "{:04}{:02}{:02}{:02}{:02}{:02}Z",
        y,
        m,
        d,
        rem / 3600,
        (rem / 60) % 60,
        rem % 60
    );
    push_tlv(out, T_GENERALIZED_TIME, body.as_bytes());
}

/// Build a signed OCSP response for `leaf_der`, signed directly by its issuer
/// (`issuer_der`, `issuer_key`), with a SHA-256 CertID and the responder
/// identified by name.
///
/// The CertID is SHA-256 because IronCrypto has no SHA-1. IronSocketLayer and
/// verifiers that match on the response's own hash algorithm accept it;
/// clients that look a certificate up only by a SHA-1 CertID (OpenSSL's
/// default lookup, for one) find no status for it.
pub fn build_response(
    leaf_der: &[u8],
    issuer_der: &[u8],
    issuer_key: &SigningKey,
    status: CertStatus,
    this_update: u64,
    next_update: u64,
    rng: &mut dyn RandomSource,
) -> Result<Vec<u8>> {
    let issuer = Certificate::parse(issuer_der)?;
    if issuer.spki != issuer_key.spki() {
        return Err(Error::new(
            ErrorKind::InvalidConfig,
            "issuer does not match the key",
        ));
    }
    build_signed(
        leaf_der,
        issuer_der,
        issuer_key,
        None,
        status,
        this_update,
        next_update,
        rng,
    )
}

/// Build a response signed by `signer`; with `responder_cert`, a delegated
/// responder whose certificate is included in `certs`.
#[allow(clippy::too_many_arguments)]
fn build_signed(
    leaf_der: &[u8],
    issuer_der: &[u8],
    signer: &SigningKey,
    responder_cert: Option<&[u8]>,
    status: CertStatus,
    this_update: u64,
    next_update: u64,
    rng: &mut dyn RandomSource,
) -> Result<Vec<u8>> {
    let leaf = Certificate::parse(leaf_der)?;
    let issuer = Certificate::parse(issuer_der)?;
    if leaf.issuer != issuer.subject {
        return Err(Error::new(
            ErrorKind::InvalidConfig,
            "issuer does not match the certificate",
        ));
    }
    let responder_name = match responder_cert {
        Some(c) => Certificate::parse(c)?.subject,
        None => issuer.subject,
    };
    let name_hash =
        digest(OID_SHA256, issuer.subject).ok_or(Error::new(ErrorKind::Internal, "hash"))?;
    let key_hash = digest(OID_SHA256, spki_key_bits(issuer.spki)?)
        .ok_or(Error::new(ErrorKind::Internal, "hash"))?;

    let mut cert_id = hash_alg_id(OID_SHA256);
    push_tlv(&mut cert_id, T_OCTET_STRING, &name_hash);
    push_tlv(&mut cert_id, T_OCTET_STRING, &key_hash);
    push_tlv(&mut cert_id, T_INTEGER, leaf.serial);
    let mut single = Vec::new();
    push_tlv(&mut single, T_SEQUENCE, &cert_id);
    match status {
        CertStatus::Good => push_tlv(&mut single, T_GOOD, &[]),
        CertStatus::Unknown => push_tlv(&mut single, T_UNKNOWN, &[]),
        CertStatus::Revoked { at } => {
            let mut rev = Vec::new();
            generalized_time(&mut rev, at);
            push_tlv(&mut single, T_REVOKED, &rev);
        }
    }
    generalized_time(&mut single, this_update);
    let mut next = Vec::new();
    generalized_time(&mut next, next_update);
    push_tlv(&mut single, T_CTX0, &next);
    let mut responses = Vec::new();
    push_tlv(&mut responses, T_SEQUENCE, &single);

    let mut data = Vec::new();
    push_tlv(&mut data, T_CTX1, responder_name);
    generalized_time(&mut data, this_update);
    push_tlv(&mut data, T_SEQUENCE, &responses);
    let mut tbs = Vec::new();
    push_tlv(&mut tbs, T_SEQUENCE, &data);

    let scheme = *signer
        .schemes()
        .first()
        .ok_or(Error::new(ErrorKind::InvalidConfig, "key"))?;
    let signature = signer.sign(scheme, &tbs, rng)?;
    let mut basic_body = tbs;
    basic_body.extend_from_slice(&alg_id(scheme)?);
    let mut bits = alloc::vec![0u8];
    bits.extend_from_slice(&signature);
    push_tlv(&mut basic_body, T_BIT_STRING, &bits);
    if let Some(c) = responder_cert {
        // certs [0] EXPLICIT SEQUENCE OF Certificate
        let mut list = Vec::new();
        push_tlv(&mut list, T_SEQUENCE, c);
        push_tlv(&mut basic_body, T_CTX0, &list);
    }
    let mut basic = Vec::new();
    push_tlv(&mut basic, T_SEQUENCE, &basic_body);

    let mut rb = Vec::new();
    push_tlv(&mut rb, T_OID, OID_OCSP_BASIC);
    push_tlv(&mut rb, T_OCTET_STRING, &basic);
    let mut response_bytes = Vec::new();
    push_tlv(&mut response_bytes, T_SEQUENCE, &rb);
    let mut body = Vec::new();
    push_tlv(&mut body, T_ENUMERATED, &[0]);
    push_tlv(&mut body, T_CTX0, &response_bytes);
    let mut out = Vec::new();
    push_tlv(&mut out, T_SEQUENCE, &body);
    Ok(out)
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use crate::crypto::sign::KeyKind;
    use crate::x509::{self, CertificateParams, Usage};

    struct Fixture {
        ca: Vec<u8>,
        ca_key: SigningKey,
        leaf: Vec<u8>,
        now: u64,
    }

    fn fixture() -> Fixture {
        let mut rng = ic_drbg::Rng::from_os().unwrap();
        let now = 1_800_000_000;
        let ca_key = SigningKey::generate(KeyKind::EcdsaP256, &mut rng).unwrap();
        let ca = x509::self_signed(
            &CertificateParams {
                subject_cn: "OCSP Test CA",
                dns_names: &[],
                ip_addresses: &[],
                not_before: now - 86_400,
                not_after: now + 86_400 * 30,
                is_ca: true,
                path_len: Some(0),
                usage: &[],
                serial: [9; 16],
            },
            &ca_key,
            &mut rng,
        )
        .unwrap();
        let leaf_key = SigningKey::generate(KeyKind::EcdsaP256, &mut rng).unwrap();
        let leaf = x509::issue(
            &CertificateParams {
                subject_cn: "leaf",
                dns_names: &["leaf.test"],
                ip_addresses: &[],
                not_before: now - 3600,
                not_after: now + 86_400,
                is_ca: false,
                path_len: None,
                usage: &[Usage::ServerAuth],
                serial: [4; 16],
            },
            leaf_key.spki(),
            &ca,
            &ca_key,
            &mut rng,
        )
        .unwrap();
        Fixture {
            ca,
            ca_key,
            leaf,
            now,
        }
    }

    const ALL: &[SignatureScheme] = crate::crypto::sign::VERIFY_SCHEMES;

    fn check(f: &Fixture, resp: &[u8], now: u64) -> Result<OcspVerified> {
        let ca = Certificate::parse(&f.ca).unwrap();
        verify_response(resp, &f.leaf, ca.subject, ca.spki, now, ALL)
    }

    fn make(f: &Fixture, status: CertStatus, this: u64, next: u64) -> Vec<u8> {
        let mut rng = ic_drbg::Rng::from_os().unwrap();
        build_response(&f.leaf, &f.ca, &f.ca_key, status, this, next, &mut rng).unwrap()
    }

    /// REQ-OCSP-001, REQ-OCSP-004: a good response from the issuer verifies,
    /// with the SHA-256 CertID checked in full.
    #[test]
    fn a_good_response_verifies() {
        let f = fixture();
        let r = make(&f, CertStatus::Good, f.now - 60, f.now + 3600);
        let v = check(&f, &r, f.now).unwrap();
        assert_eq!(v.status, CertStatus::Good);
        assert!(v.cert_id_hashes_checked && !v.delegated);
        let r = make(&f, CertStatus::Unknown, f.now - 60, f.now + 3600);
        assert_eq!(check(&f, &r, f.now).unwrap().status, CertStatus::Unknown);
    }

    /// REQ-OCSP-006: only a successful, basic response signed under a scheme
    /// the caller allows is considered at all.
    #[test]
    fn unsuccessful_non_basic_and_disallowed_responses_are_refused() {
        let f = fixture();
        // malformedRequest, internalError, tryLater, sigRequired, unauthorized.
        for status in [1u8, 2, 3, 5, 6] {
            let e = check(&f, &[0x30, 0x03, T_ENUMERATED, 0x01, status], f.now).unwrap_err();
            assert!(
                e.to_string().contains("responseStatus is not successful"),
                "{status}: {e}"
            );
        }
        let good = make(&f, CertStatus::Good, f.now - 60, f.now + 3600);
        // The same response with a response type other than id-pkix-ocsp-basic.
        let at = good
            .windows(OID_OCSP_BASIC.len())
            .position(|w| w == OID_OCSP_BASIC)
            .unwrap();
        let mut other = good.clone();
        other[at + OID_OCSP_BASIC.len() - 1] = 0x02;
        let e = check(&f, &other, f.now).unwrap_err();
        assert!(e.to_string().contains("not a basic OCSP response"), "{e}");
        // Validly signed, but with a scheme the caller does not allow.
        let ca = Certificate::parse(&f.ca).unwrap();
        let e = verify_response(
            &good,
            &f.leaf,
            ca.subject,
            ca.spki,
            f.now,
            &[SignatureScheme::Ed25519],
        )
        .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::PolicyViolation, "{e}");
        assert!(check(&f, &good, f.now).is_ok());
    }

    /// REQ-OCSP-003.
    #[test]
    fn a_revoked_certificate_is_fatal() {
        let f = fixture();
        let r = make(
            &f,
            CertStatus::Revoked { at: f.now - 10 },
            f.now - 5,
            f.now + 3600,
        );
        assert_eq!(
            check(&f, &r, f.now).unwrap_err().kind(),
            ErrorKind::CertificateRevoked
        );
    }

    /// REQ-OCSP-002.
    #[test]
    fn stale_and_future_responses_are_refused() {
        let f = fixture();
        let r = make(&f, CertStatus::Good, f.now - 7200, f.now - 3600);
        assert_eq!(
            check(&f, &r, f.now).unwrap_err().kind(),
            ErrorKind::BadCertificateStatus
        );
        let r = make(&f, CertStatus::Good, f.now + 3600, f.now + 7200);
        assert_eq!(
            check(&f, &r, f.now).unwrap_err().kind(),
            ErrorKind::BadCertificateStatus
        );
        // Inside the skew window both ways.
        let r = make(&f, CertStatus::Good, f.now + 200, f.now + 7200);
        assert!(check(&f, &r, f.now).is_ok());
        let r = make(&f, CertStatus::Good, f.now - 7200, f.now - 200);
        assert!(check(&f, &r, f.now).is_ok());
    }

    /// REQ-OCSP-001: a response signed by anyone else is refused, and so is a
    /// response whose signature bytes were altered.
    #[test]
    fn only_the_issuer_may_sign() {
        let f = fixture();
        let other = fixture();
        // Signed by another CA for a certificate with the same serial.
        let mut rng = ic_drbg::Rng::from_os().unwrap();
        let foreign = build_response(
            &other.leaf,
            &other.ca,
            &other.ca_key,
            CertStatus::Good,
            f.now,
            f.now + 60,
            &mut rng,
        )
        .unwrap();
        assert_eq!(
            check(&f, &foreign, f.now).unwrap_err().kind(),
            ErrorKind::BadCertificateStatus
        );
        let mut r = make(&f, CertStatus::Good, f.now, f.now + 60);
        let n = r.len();
        r[n - 3] ^= 1;
        assert!(check(&f, &r, f.now).is_err());
    }

    /// REQ-OCSP-004: a response about another certificate does not cover this one.
    #[test]
    fn a_response_for_another_certificate_does_not_count() {
        let f = fixture();
        let mut rng = ic_drbg::Rng::from_os().unwrap();
        let key = SigningKey::generate(KeyKind::Ed25519, &mut rng).unwrap();
        let sibling = x509::issue(
            &CertificateParams {
                subject_cn: "sibling",
                dns_names: &["sibling.test"],
                ip_addresses: &[],
                not_before: f.now - 60,
                not_after: f.now + 3600,
                is_ca: false,
                path_len: None,
                usage: &[Usage::ServerAuth],
                serial: [5; 16],
            },
            key.spki(),
            &f.ca,
            &f.ca_key,
            &mut rng,
        )
        .unwrap();
        let r = build_response(
            &sibling,
            &f.ca,
            &f.ca_key,
            CertStatus::Good,
            f.now,
            f.now + 60,
            &mut rng,
        )
        .unwrap();
        assert_eq!(
            check(&f, &r, f.now).unwrap_err().kind(),
            ErrorKind::BadCertificateStatus
        );
    }

    /// A CA with its own key: under `name`, which may be the fixture CA's.
    fn other_ca(f: &Fixture, name: &str) -> (Vec<u8>, SigningKey) {
        let mut rng = ic_drbg::Rng::from_os().unwrap();
        let key = SigningKey::generate(KeyKind::EcdsaP256, &mut rng).unwrap();
        let cert = x509::self_signed(
            &CertificateParams {
                subject_cn: name,
                dns_names: &[],
                ip_addresses: &[],
                not_before: f.now - 86_400,
                not_after: f.now + 86_400,
                is_ca: true,
                path_len: Some(0),
                usage: &[],
                serial: [3; 16],
            },
            &key,
            &mut rng,
        )
        .unwrap();
        (cert, key)
    }

    /// REQ-OCSP-004: the CertID must name the leaf's issuer by its key as well
    /// as its name. A CA that shares the issuer's name but not its key does not
    /// speak for this certificate, even in a response the real issuer signed.
    #[test]
    fn a_cert_id_for_another_key_under_the_same_name_does_not_count() {
        let f = fixture();
        let (twin, _) = other_ca(&f, "OCSP Test CA");
        let mut rng = ic_drbg::Rng::from_os().unwrap();
        // CertID hashes from the twin; signature from the real issuer.
        let r = build_signed(
            &f.leaf,
            &twin,
            &f.ca_key,
            None,
            CertStatus::Good,
            f.now - 60,
            f.now + 3600,
            &mut rng,
        )
        .unwrap();
        assert_eq!(
            check(&f, &r, f.now).unwrap_err().kind(),
            ErrorKind::BadCertificateStatus
        );
    }

    /// REQ-OCSP-001: a delegated responder must be certified by the leaf's own
    /// issuer; one certified by another CA is refused.
    #[test]
    fn a_responder_certified_by_another_ca_is_refused() {
        let f = fixture();
        let (other, other_key) = other_ca(&f, "Other CA");
        let mut rng = ic_drbg::Rng::from_os().unwrap();
        let key = SigningKey::generate(KeyKind::EcdsaP256, &mut rng).unwrap();
        let oc = Certificate::parse(&other).unwrap();
        let mut seq = Vec::new();
        push_tlv(&mut seq, T_OID, OID_KP_OCSP_SIGNING);
        let mut v = Vec::new();
        push_tlv(&mut v, T_SEQUENCE, &seq);
        let mut eku = Vec::new();
        super::super::push_ext(&mut eku, super::super::OID_EXT_EKU, false, &v);
        let cert = super::super::build(
            &CertificateParams {
                subject_cn: "Stranger Responder",
                dns_names: &[],
                ip_addresses: &[],
                not_before: f.now - 60,
                not_after: f.now + 3600,
                is_ca: false,
                path_len: None,
                usage: &[],
                serial: [8; 16],
            },
            key.spki(),
            oc.subject,
            &super::super::key_identifier(oc.spki).unwrap(),
            &other_key,
            &mut rng,
            &[eku],
        )
        .unwrap();
        let r = build_signed(
            &f.leaf,
            &f.ca,
            &key,
            Some(&cert),
            CertStatus::Good,
            f.now - 60,
            f.now + 3600,
            &mut rng,
        )
        .unwrap();
        assert_eq!(
            check(&f, &r, f.now).unwrap_err().kind(),
            ErrorKind::BadCertificateStatus
        );
        // The verifier tries every candidate signer and reports only that none
        // was authorized, so the issuer rule itself is checked directly: the
        // later signature check would also refuse this responder, and this
        // pins which rule refuses first.
        let ca = Certificate::parse(&f.ca).unwrap();
        let e = responder_authorized(
            &Certificate::parse(&cert).unwrap(),
            ca.subject,
            &PublicKey::from_spki(ca.spki).unwrap(),
            f.now,
            ALL,
        )
        .unwrap_err();
        assert!(
            e.to_string()
                .contains("responder not issued by the certificate's issuer"),
            "{e}"
        );
    }

    fn responder(f: &Fixture, eku: Option<&[u8]>) -> (Vec<u8>, SigningKey) {
        let mut rng = ic_drbg::Rng::from_os().unwrap();
        let key = SigningKey::generate(KeyKind::EcdsaP256, &mut rng).unwrap();
        let ca = Certificate::parse(&f.ca).unwrap();
        let mut extra = Vec::new();
        if let Some(oid) = eku {
            let mut seq = Vec::new();
            push_tlv(&mut seq, T_OID, oid);
            let mut v = Vec::new();
            push_tlv(&mut v, T_SEQUENCE, &seq);
            let mut ext = Vec::new();
            super::super::push_ext(&mut ext, super::super::OID_EXT_EKU, false, &v);
            extra.push(ext);
        }
        let cert = super::super::build(
            &CertificateParams {
                subject_cn: "OCSP Responder",
                dns_names: &[],
                ip_addresses: &[],
                not_before: f.now - 60,
                not_after: f.now + 3600,
                is_ca: false,
                path_len: None,
                usage: &[],
                serial: [7; 16],
            },
            key.spki(),
            ca.subject,
            &super::super::key_identifier(ca.spki).unwrap(),
            &f.ca_key,
            &mut rng,
            &extra,
        )
        .unwrap();
        (cert, key)
    }

    /// REQ-OCSP-001: a delegate the issuer certified for OCSP signing may
    /// sign; one without id-kp-OCSPSigning, or with only anyExtendedKeyUsage,
    /// may not.
    #[test]
    fn delegated_responders_need_the_ocsp_signing_purpose() {
        let f = fixture();
        let mut rng = ic_drbg::Rng::from_os().unwrap();
        let (cert, key) = responder(&f, Some(OID_KP_OCSP_SIGNING));
        let r = build_signed(
            &f.leaf,
            &f.ca,
            &key,
            Some(&cert),
            CertStatus::Good,
            f.now,
            f.now + 60,
            &mut rng,
        )
        .unwrap();
        let v = check(&f, &r, f.now).unwrap();
        assert!(v.delegated);
        for eku in [
            None,
            Some(super::super::OID_ANY_EKU),
            Some(super::super::OID_KP_SERVER_AUTH),
        ] {
            let (cert, key) = responder(&f, eku);
            let r = build_signed(
                &f.leaf,
                &f.ca,
                &key,
                Some(&cert),
                CertStatus::Good,
                f.now,
                f.now + 60,
                &mut rng,
            )
            .unwrap();
            assert_eq!(
                check(&f, &r, f.now).unwrap_err().kind(),
                ErrorKind::BadCertificateStatus,
                "{eku:?}"
            );
        }
        // A delegate certified by some other CA is not authorised either.
        let other = fixture();
        let (cert, key) = responder(&other, Some(OID_KP_OCSP_SIGNING));
        let r = build_signed(
            &f.leaf,
            &f.ca,
            &key,
            Some(&cert),
            CertStatus::Good,
            f.now,
            f.now + 60,
            &mut rng,
        )
        .unwrap();
        assert!(check(&f, &r, f.now).is_err());
    }

    #[test]
    fn garbage_is_refused_without_panicking() {
        let f = fixture();
        let r = make(&f, CertStatus::Good, f.now, f.now + 60);
        for n in 0..r.len() {
            assert!(check(&f, &r[..n], f.now).is_err());
        }
        for i in 0..r.len() {
            let mut m = r.clone();
            m[i] ^= 0x55;
            // Most flips fail; none may panic or turn into a revocation.
            if let Err(e) = check(&f, &m, f.now) {
                assert_ne!(e.kind(), ErrorKind::CertificateRevoked, "flip at {i}");
            }
        }
    }
}
