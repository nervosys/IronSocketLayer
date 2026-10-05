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
    alg_id, check_algorithm_identifier_encoding, check_oid_encoding, check_rdn_sequence,
    civil_from_days, hash_alg_id, parse_time, push_tlv, scheme_from_alg, whole_bits, Certificate,
    Der, OID_SHA256, OID_SHA384, OID_SHA512, T_BIT_STRING, T_BOOLEAN, T_CTX0, T_CTX1, T_CTX2,
    T_GENERALIZED_TIME, T_INTEGER, T_OCTET_STRING, T_OID, T_SEQUENCE,
};
use crate::crypto::sign::{self, PublicKey, SigningKey};
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

fn digest(oid: &[u8], data: &[u8]) -> Option<Vec<u8>> {
    use ic_core::traits::Digest;
    Some(match oid {
        OID_SHA256 => ic_hash::Sha256::digest(data).as_ref().to_vec(),
        OID_SHA384 => ic_hash::Sha384::digest(data).as_ref().to_vec(),
        OID_SHA512 => ic_hash::Sha512::digest(data).as_ref().to_vec(),
        _ => return None,
    })
}

fn digest_fixed(oid: &[u8], data: &[u8]) -> Option<crate::crypto::Output> {
    use ic_core::traits::Digest;
    match oid {
        OID_SHA256 => {
            crate::crypto::Output::from_slice(ic_hash::Sha256::digest(data).as_ref()).ok()
        }
        OID_SHA384 => {
            crate::crypto::Output::from_slice(ic_hash::Sha384::digest(data).as_ref()).ok()
        }
        OID_SHA512 => {
            crate::crypto::Output::from_slice(ic_hash::Sha512::digest(data).as_ref()).ok()
        }
        _ => None,
    }
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

/// REQ-OCSP-012: extension wrappers and entries are fully consumed with unique OIDs. No OCSP
/// extension semantics are implemented, so critical extensions are refused;
/// structurally valid non-critical extensions can be ignored (RFC 6960 §4.4).
/// REQ-OCSP-026: extension identifiers use complete, minimal OBJECT IDENTIFIER encodings.
fn check_extensions(encoded: &[u8]) -> Result<()> {
    let mut outer = Der::new(encoded);
    let mut list = outer.nested(T_SEQUENCE)?;
    outer.finish()?;
    if list.is_empty() {
        return Err(bad("empty OCSP extensions list"));
    }
    let encoded_list = list.rest();
    while !list.is_empty() {
        let consumed = encoded_list.len() - list.rest().len();
        let mut extension = list.nested(T_SEQUENCE)?;
        let oid = extension.expect(T_OID)?;
        check_oid_encoding(oid)?;
        let mut previous = Der::new(&encoded_list[..consumed]);
        while !previous.is_empty() {
            let mut entry = previous.nested(T_SEQUENCE)?;
            if entry.expect(T_OID)? == oid {
                return Err(bad("duplicate OCSP extension"));
            }
        }
        let critical = match extension.optional(T_BOOLEAN)? {
            None | Some([0]) => false,
            Some([0xff]) => true,
            Some(_) => return Err(bad("malformed OCSP extension critical flag")),
        };
        let _value = extension.expect(T_OCTET_STRING)?;
        extension.finish()?;
        if critical {
            return Err(bad("unsupported critical OCSP extension"));
        }
    }
    Ok(())
}

/// REQ-OCSP-007, REQ-OCSP-009: RevokedInfo contains a GeneralizedTime and
/// optionally one explicitly wrapped CRLReason (RFC 6960 §4.2.1). Consume
/// the whole structure and accept only the RFC 5280 §5.3.1 reason codes.
fn parse_revoked(content: &[u8]) -> Result<CertStatus> {
    let mut rev = Der::new(content);
    let (t, v, _) = rev.tlv()?;
    if t != T_GENERALIZED_TIME {
        return Err(bad("revocationTime is not GeneralizedTime"));
    }
    let at = parse_time(t, v)?;
    if let Some(reason) = rev.optional(T_CTX0)? {
        let mut reason = Der::new(reason);
        if !matches!(reason.expect(T_ENUMERATED)?, [0..=6] | [8..=10]) {
            return Err(bad("invalid OCSP revocation reason"));
        }
        reason.finish()?;
    }
    rev.finish()?;
    Ok(CertStatus::Revoked { at })
}

/// REQ-OCSP-007: nextUpdate and revocationTime are GeneralizedTime, not the
/// UTCTime alternative accepted for X.509 certificate validity (RFC 6960 §4.2.1).
/// REQ-OCSP-018: CertID serial numbers are nonempty minimal DER INTEGERs.
/// REQ-OCSP-020: known CertID hash algorithms have exact digest lengths.
/// REQ-OCSP-023: good and unknown CertStatus encode implicit NULL with no payload.
/// REQ-OCSP-027: every CertID hash OID is complete and minimal before matching.
fn parse_single(body: &[u8]) -> Result<Single<'_>> {
    let mut r = Der::new(body);
    let mut id = r.nested(T_SEQUENCE)?;
    let mut alg = id.nested(T_SEQUENCE)?;
    let hash_oid = alg.expect(T_OID)?;
    check_oid_encoding(hash_oid)?;
    alg.optional_null()?;
    alg.finish()?;
    let name_hash = id.expect(T_OCTET_STRING)?;
    let key_hash = id.expect(T_OCTET_STRING)?;
    let expected_len = match hash_oid {
        OID_SHA1 => Some(20),
        OID_SHA256 => Some(32),
        OID_SHA384 => Some(48),
        OID_SHA512 => Some(64),
        _ => None,
    };
    if expected_len.is_some_and(|n| name_hash.len() != n || key_hash.len() != n) {
        return Err(bad("incorrect OCSP CertID digest length"));
    }
    let serial = id.expect(T_INTEGER)?;
    if serial.is_empty() {
        return Err(bad("empty OCSP serial number"));
    }
    if let [first, second, ..] = serial {
        if (*first == 0 && second & 0x80 == 0) || (*first == 0xff && second & 0x80 != 0) {
            return Err(bad("nonminimal OCSP serial number"));
        }
    }
    id.finish()?;
    let (tag, content, _) = r.tlv()?;
    let status = match tag {
        T_GOOD if content.is_empty() => CertStatus::Good,
        T_UNKNOWN if content.is_empty() => CertStatus::Unknown,
        T_REVOKED => parse_revoked(content)?,
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
        if t != T_GENERALIZED_TIME {
            return Err(bad("nextUpdate is not GeneralizedTime"));
        }
        next_update = Some(parse_time(t, v)?);
        n.finish()?;
    }
    if next_update.is_some_and(|next| next < this_update) {
        return Err(bad("OCSP nextUpdate precedes thisUpdate"));
    }
    if let Some(extensions) = r.optional(T_CTX1)? {
        check_extensions(extensions)?;
    }
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
/// Only v1 response versions are accepted; malformed or unknown versions
/// are [`ErrorKind::BadCertificateStatus`] (`REQ-OCSP-008`).
/// ResponseBytes, BasicOCSPResponse and attached-certificate wrappers contain
/// exactly one complete sequence; trailing bytes are refused (`REQ-OCSP-010`).
/// REQ-OCSP-013: every SingleResponse is parsed, including entries after the
/// matching certificate, so malformed trailing entries cannot be ignored.
/// A by-name ResponderID identifies the issuer or authorized delegate whose
/// key verifies the signature (`REQ-OCSP-011`).
/// By-key ResponderIDs contain exactly one 20-byte OCTET STRING (`REQ-OCSP-015`).
/// Their SHA-1 hash is not compared because IronCrypto does not provide SHA-1.
/// Conflicting matching status or freshness fields are refused (`REQ-OCSP-016`).
/// REQ-OCSP-019: only a canonical successful outer response status is accepted.
/// REQ-OCSP-028: malformed signature identifiers retain structural error contexts.
/// REQ-OCSP-029: every attached certificate list element is a complete SEQUENCE,
/// even when the issuer signs directly or an earlier candidate verifies.
/// REQ-OCSP-030: responseType has a complete minimal OID encoding before matching.
/// REQ-OCSP-032: unusable delegated public keys do not prevent trying later candidates.
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
    let mut response_bytes_der = Der::new(resp.expect(T_CTX0).map_err(wrap)?);
    let mut bytes = response_bytes_der.nested(T_SEQUENCE).map_err(wrap)?;
    response_bytes_der.finish().map_err(wrap)?;
    resp.finish().map_err(wrap)?;
    let response_type = bytes.expect(T_OID).map_err(wrap)?;
    check_oid_encoding(response_type).map_err(wrap)?;
    if response_type != OID_OCSP_BASIC {
        return Err(bad("not a basic OCSP response"));
    }
    let basic = bytes.expect(T_OCTET_STRING).map_err(wrap)?;
    bytes.finish().map_err(wrap)?;

    // BasicOCSPResponse
    let mut basic_der = Der::new(basic);
    let mut b = basic_der.nested(T_SEQUENCE).map_err(wrap)?;
    basic_der.finish().map_err(wrap)?;
    let tbs = b.expect_raw(T_SEQUENCE).map_err(wrap)?;
    let sig_alg = b.expect(T_SEQUENCE).map_err(wrap)?;
    let signature = whole_bits(b.expect(T_BIT_STRING).map_err(wrap)?).map_err(wrap)?;
    let certs = b.optional(T_CTX0).map_err(wrap)?;
    b.finish().map_err(wrap)?;
    let certs = match certs {
        Some(encoded) => {
            let mut certs_der = Der::new(encoded);
            let body = certs_der.expect(T_SEQUENCE).map_err(wrap)?;
            certs_der.finish().map_err(wrap)?;
            check_attached_certificate_list(body).map_err(wrap)?;
            Some(Der::new(body))
        }
        None => None,
    };
    check_algorithm_identifier_encoding(sig_alg).map_err(wrap)?;
    let scheme = scheme_from_alg(sig_alg).map_err(|error| {
        if error.kind() == ErrorKind::UnsupportedCertificate {
            bad("unsupported OCSP signature algorithm")
        } else {
            wrap(error)
        }
    })?;
    if !allowed_schemes.contains(&scheme) {
        return Err(Error::new(
            ErrorKind::PolicyViolation,
            "OCSP signature scheme not allowed by policy",
        ));
    }

    // ResponseData: identify the signer before selecting its certificate.
    let mut t = Der::new(tbs).nested(T_SEQUENCE).map_err(wrap)?;
    // REQ-OCSP-008: only v1(0); an explicit version must contain exactly
    // one INTEGER, not arbitrary bytes or additional fields.
    if let Some(version) = t.optional(T_CTX0).map_err(wrap)? {
        let mut version = Der::new(version);
        if version.expect(T_INTEGER).map_err(wrap)? != [0] {
            return Err(bad("unsupported OCSP response version"));
        }
        version.finish().map_err(wrap)?;
    }
    let (rid_tag, rid_value, _) = t.tlv().map_err(wrap)?;
    if rid_tag != T_CTX1 && rid_tag != T_CTX2 {
        return Err(bad("unknown responderID form"));
    }
    // REQ-OCSP-025: byName explicitly wraps one complete Name, with valid
    // RDN attributes and DER SET ordering, before signer identity is checked.
    if rid_tag == T_CTX1 {
        let mut name = Der::new(rid_value);
        check_rdn_sequence(name.expect(T_SEQUENCE).map_err(wrap)?).map_err(wrap)?;
        name.finish().map_err(wrap)?;
    }
    // REQ-OCSP-015: byKey explicitly wraps exactly one 20-byte SHA-1 hash.
    // The hash is not compared with the signer's key: IronCrypto excludes
    // SHA-1 permanently, by its maintainers' decision. Identity rests on the
    // signature, which must verify under the issuer's key or a delegate the
    // issuer certified for OCSP signing (REQ-OCSP-001).
    if rid_tag == T_CTX2 {
        let mut key_hash = Der::new(rid_value);
        if key_hash.expect(T_OCTET_STRING).map_err(wrap)?.len() != 20 {
            return Err(bad("invalid by-key responder hash length"));
        }
        key_hash.finish().map_err(wrap)?;
    }

    // REQ-OCSP-001: the issuer, or a delegate the issuer certified.
    let issuer_key = PublicKey::from_spki(issuer_spki)?;
    let mut delegated = false;
    let identifies_issuer = rid_tag != T_CTX1 || rid_value == issuer_subject;
    let mut signed = identifies_issuer && sign::verify(scheme, &issuer_key, tbs, signature).is_ok();
    if !signed {
        if let Some(mut list) = certs {
            while !list.is_empty() && !signed {
                let (_, _, whole) = list.tlv().map_err(wrap)?;
                let Ok(responder) = Certificate::parse(whole) else {
                    continue;
                };
                if rid_tag == T_CTX1 && rid_value != responder.subject {
                    continue;
                }
                if responder_authorized(
                    &responder,
                    issuer_subject,
                    &issuer_key,
                    now,
                    allowed_schemes,
                )
                .is_ok()
                {
                    let Ok(key) = responder.subject_public_key() else {
                        continue;
                    };
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

    let (pt, pv, _) = t.tlv().map_err(wrap)?;
    if pt != T_GENERALIZED_TIME {
        return Err(bad("producedAt is not GeneralizedTime"));
    }
    parse_time(pt, pv).map_err(wrap)?;
    let mut responses = t.nested(T_SEQUENCE).map_err(wrap)?;
    if let Some(extensions) = t.optional(T_CTX1).map_err(wrap)? {
        check_extensions(extensions).map_err(wrap)?;
    }
    t.finish().map_err(wrap)?;

    // REQ-OCSP-004: find the SingleResponse for this leaf.
    let key_bits = spki_key_bits(issuer_spki)?;
    let mut found: Option<(Single<'_>, bool)> = None;
    while !responses.is_empty() {
        let body = responses.expect(T_SEQUENCE).map_err(wrap)?;
        let single = parse_single(body).map_err(wrap)?;
        if single.serial != leaf.serial() {
            continue;
        }
        let checked = match single.hash_oid {
            OID_SHA1 => false,
            OID_SHA256 | OID_SHA384 | OID_SHA512 => {
                let (Some(n), Some(k)) = (
                    digest_fixed(single.hash_oid, issuer_subject),
                    digest_fixed(single.hash_oid, key_bits),
                ) else {
                    continue;
                };
                if !ic_core::ct::verify(n.as_bytes(), single.name_hash)
                    || !ic_core::ct::verify(k.as_bytes(), single.key_hash)
                {
                    continue;
                }
                true
            }
            _ => continue,
        };
        // REQ-OCSP-016: duplicate matches cannot make acceptance order-dependent.
        if let Some((previous, _)) = &found {
            if previous.status != single.status
                || previous.this_update != single.this_update
                || previous.next_update != single.next_update
            {
                return Err(bad("conflicting OCSP responses for the certificate"));
            }
        } else {
            found = Some((single, checked));
        }
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

/// REQ-OCSP-029: validate all Certificate SEQUENCE boundaries before candidate
/// selection. A structurally bounded candidate may still be an unusable certificate.
fn check_attached_certificate_list(body: &[u8]) -> Result<()> {
    let mut list = Der::new(body);
    while !list.is_empty() {
        list.expect_raw(T_SEQUENCE)?;
    }
    Ok(())
}

/// A delegated responder must be issued by the leaf's issuer, valid now, and
/// carry id-kp-OCSPSigning explicitly (anyExtendedKeyUsage does not count).
/// REQ-OCSP-017: when KeyUsage is present, it permits digitalSignature.
/// REQ-OCSP-031: unknown critical certificate extensions cannot authorize a delegate.
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
    if responder.ext.unknown_critical {
        return Err(bad("responder has an unknown critical extension"));
    }
    responder.check_validity(now)?;
    if responder
        .ext
        .key_usage
        .is_some_and(|ku| ku & super::KU_DIGITAL_SIGNATURE == 0)
    {
        return Err(bad(
            "responder key usage does not permit digital signatures",
        ));
    }
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

/// REQ-OCSP-024: issuance refuses times that exceed the four-digit year range.
fn generalized_time(out: &mut Vec<u8>, t: u64) -> Result<()> {
    let (y, m, d) = civil_from_days((t / 86_400) as i64);
    if y > 9999 {
        return Err(Error::new(
            ErrorKind::InvalidConfig,
            "OCSP time beyond year 9999",
        ));
    }
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
    Ok(())
}

/// Build a signed OCSP response for `leaf_der`, signed directly by its issuer
/// (`issuer_der`, `issuer_key`), with a SHA-256 CertID and the responder
/// identified by name.
///
/// The CertID is SHA-256 because IronCrypto has no SHA-1. IronSocketLayer and
/// verifiers that match on the response's own hash algorithm accept it;
/// clients that look a certificate up only by a SHA-1 CertID (OpenSSL's
/// default lookup, for one) find no status for it.
/// REQ-OCSP-021: issuance refuses nextUpdate earlier than thisUpdate.
/// REQ-OCSP-022: the signing key matches the issuer certificate.
pub fn build_response(
    leaf_der: &[u8],
    issuer_der: &[u8],
    issuer_key: &SigningKey,
    status: CertStatus,
    this_update: u64,
    next_update: u64,
    rng: &mut dyn RandomSource,
) -> Result<Vec<u8>> {
    if next_update < this_update {
        return Err(Error::new(
            ErrorKind::InvalidConfig,
            "OCSP nextUpdate precedes thisUpdate",
        ));
    }
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
    build_signed_with_cert_id(
        OID_SHA256,
        &name_hash,
        &key_hash,
        leaf.serial,
        responder_name,
        signer,
        responder_cert,
        status,
        this_update,
        Some(next_update),
        rng,
    )
}

/// Assemble and sign a response for the given CertID parts. Split out so
/// tests can build responses whose CertID does not match the issuer or whose
/// nextUpdate is absent (`REQ-OCSP-002`).
#[allow(clippy::too_many_arguments)]
fn build_signed_with_cert_id(
    hash_oid: &[u8],
    name_hash: &[u8],
    key_hash: &[u8],
    serial: &[u8],
    responder_name: &[u8],
    signer: &SigningKey,
    responder_cert: Option<&[u8]>,
    status: CertStatus,
    this_update: u64,
    next_update: Option<u64>,
    rng: &mut dyn RandomSource,
) -> Result<Vec<u8>> {
    let mut cert_id = hash_alg_id(hash_oid);
    push_tlv(&mut cert_id, T_OCTET_STRING, name_hash);
    push_tlv(&mut cert_id, T_OCTET_STRING, key_hash);
    push_tlv(&mut cert_id, T_INTEGER, serial);
    let mut single = Vec::new();
    push_tlv(&mut single, T_SEQUENCE, &cert_id);
    match status {
        CertStatus::Good => push_tlv(&mut single, T_GOOD, &[]),
        CertStatus::Unknown => push_tlv(&mut single, T_UNKNOWN, &[]),
        CertStatus::Revoked { at } => {
            let mut rev = Vec::new();
            generalized_time(&mut rev, at)?;
            push_tlv(&mut single, T_REVOKED, &rev);
        }
    }
    generalized_time(&mut single, this_update)?;
    if let Some(next_update) = next_update {
        let mut next = Vec::new();
        generalized_time(&mut next, next_update)?;
        push_tlv(&mut single, T_CTX0, &next);
    }
    let mut responses = Vec::new();
    push_tlv(&mut responses, T_SEQUENCE, &single);

    let mut data = Vec::new();
    push_tlv(&mut data, T_CTX1, responder_name);
    generalized_time(&mut data, this_update)?;
    push_tlv(&mut data, T_SEQUENCE, &responses);
    let mut tbs = Vec::new();
    push_tlv(&mut tbs, T_SEQUENCE, &data);

    sign_response(tbs, signer, responder_cert, rng)
}

/// Sign and wrap ResponseData, allowing tests to vary its fields without
/// invalidating the response signature.
fn sign_response(
    tbs: Vec<u8>,
    signer: &SigningKey,
    responder_cert: Option<&[u8]>,
    rng: &mut dyn RandomSource,
) -> Result<Vec<u8>> {
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

    #[test]
    fn ocsp_issuance_refuses_times_beyond_year_9999() {
        let f = fixture();
        let mut rng = ic_drbg::Rng::from_os().unwrap();
        let last = parse_time(T_GENERALIZED_TIME, b"99991231235959Z").unwrap();
        for time in [0, f.now, last] {
            let mut encoded = Vec::new();
            generalized_time(&mut encoded, time).unwrap();
            let mut der = Der::new(&encoded);
            let content = der.expect(T_GENERALIZED_TIME).unwrap();
            assert_eq!(content.len(), 15);
            assert_eq!(parse_time(T_GENERALIZED_TIME, content).unwrap(), time);
            der.finish().unwrap();
        }
        for time in [last, last + 1, u64::MAX] {
            for field in 0..3 {
                let (status, this, next) = match field {
                    0 => (CertStatus::Good, time, time),
                    1 => (CertStatus::Unknown, f.now, time),
                    _ => (CertStatus::Revoked { at: time }, f.now, f.now + 60),
                };
                let result =
                    build_response(&f.leaf, &f.ca, &f.ca_key, status, this, next, &mut rng);
                if time > last {
                    let error = result.unwrap_err();
                    assert_eq!(error.kind(), ErrorKind::InvalidConfig);
                    assert_eq!(error.context(), "OCSP time beyond year 9999");
                } else {
                    let response = result.unwrap();
                    if field == 2 {
                        assert_eq!(
                            check(&f, &response, this).unwrap_err().kind(),
                            ErrorKind::CertificateRevoked
                        );
                    } else {
                        let verified = check(&f, &response, this).unwrap();
                        assert_eq!(verified.status, status);
                        assert_eq!(verified.this_update, this);
                        assert_eq!(verified.next_update, Some(next));
                    }
                }
            }
        }
    }

    fn check(f: &Fixture, resp: &[u8], now: u64) -> Result<OcspVerified> {
        let ca = Certificate::parse(&f.ca).unwrap();
        verify_response(resp, &f.leaf, ca.subject, ca.spki, now, ALL)
    }

    fn make(f: &Fixture, status: CertStatus, this: u64, next: u64) -> Vec<u8> {
        let mut rng = ic_drbg::Rng::from_os().unwrap();
        build_response(&f.leaf, &f.ca, &f.ca_key, status, this, next, &mut rng).unwrap()
    }

    /// REQ-OCSP-030: malformed responseType OIDs retain structural errors;
    /// complete unknown types retain the non-basic response context. The signed
    /// BasicOCSPResponse is unchanged across all outer-identifier cases.
    #[test]
    fn response_type_oids_require_complete_minimal_encoding() {
        let wrap = |tag, body: &[u8]| {
            let mut encoded = Vec::new();
            push_tlv(&mut encoded, tag, body);
            encoded
        };
        let f = fixture();
        let good = make(&f, CertStatus::Good, f.now, f.now + 60);
        let mut outer = Der::new(&good).nested(T_SEQUENCE).unwrap();
        outer.expect(T_ENUMERATED).unwrap();
        let mut bytes = Der::new(outer.expect(T_CTX0).unwrap())
            .nested(T_SEQUENCE)
            .unwrap();
        bytes.expect(T_OID).unwrap();
        let payload = bytes.expect_raw(T_OCTET_STRING).unwrap();
        let mut basic = Der::new(Der::new(payload).expect(T_OCTET_STRING).unwrap())
            .nested(T_SEQUENCE)
            .unwrap();
        let tbs = basic.expect_raw(T_SEQUENCE).unwrap();
        let scheme = scheme_from_alg(basic.expect(T_SEQUENCE).unwrap()).unwrap();
        let signature = whole_bits(basic.expect(T_BIT_STRING).unwrap()).unwrap();
        sign::verify(
            scheme,
            &PublicKey::from_spki(f.ca_key.spki()).unwrap(),
            tbs,
            signature,
        )
        .unwrap();
        let mut wide = alloc::vec![0x81; 40];
        wide.push(1);
        for (oid, expected) in [
            (OID_OCSP_BASIC.to_vec(), None),
            (alloc::vec![0], Some("not a basic OCSP response")),
            (alloc::vec![0x2a, 3], Some("not a basic OCSP response")),
            (wide, Some("not a basic OCSP response")),
            (Vec::new(), Some("empty OBJECT IDENTIFIER")),
            (
                alloc::vec![0x80, 0],
                Some("nonminimal OBJECT IDENTIFIER subidentifier"),
            ),
            (
                alloc::vec![0x2a, 0x80, 0],
                Some("nonminimal OBJECT IDENTIFIER subidentifier"),
            ),
            (
                alloc::vec![0x2a, 0x80, 1],
                Some("nonminimal OBJECT IDENTIFIER subidentifier"),
            ),
            (
                alloc::vec![0x81],
                Some("truncated OBJECT IDENTIFIER subidentifier"),
            ),
            (
                alloc::vec![0x2a, 0x81],
                Some("truncated OBJECT IDENTIFIER subidentifier"),
            ),
            (
                [OID_OCSP_BASIC, &[0x81][..]].concat(),
                Some("truncated OBJECT IDENTIFIER subidentifier"),
            ),
            (
                [OID_OCSP_BASIC, &[0x80, 0][..]].concat(),
                Some("nonminimal OBJECT IDENTIFIER subidentifier"),
            ),
        ] {
            let response_bytes = wrap(T_SEQUENCE, &[wrap(T_OID, &oid), payload.to_vec()].concat());
            let der = wrap(
                T_SEQUENCE,
                &[wrap(T_ENUMERATED, &[0]), wrap(T_CTX0, &response_bytes)].concat(),
            );
            let result = check(&f, &der, f.now);
            if let Some(context) = expected {
                let error = result.unwrap_err();
                assert_eq!(error.kind(), ErrorKind::BadCertificateStatus);
                assert_eq!(error.context(), context);
            } else {
                assert_eq!(result.unwrap().status, CertStatus::Good);
            }
        }
    }

    /// REQ-OCSP-028: malformed identifiers report structural failures rather
    /// than unsupported algorithms, without changing signed valid responses.
    #[test]
    fn signature_identifiers_preserve_structural_error_contexts() {
        let wrap = |tag, body: &[u8]| {
            let mut encoded = Vec::new();
            push_tlv(&mut encoded, tag, body);
            encoded
        };
        let f = fixture();
        let good = make(&f, CertStatus::Good, f.now, f.now + 60);
        let mut outer = Der::new(&good);
        let mut response = outer.nested(T_SEQUENCE).unwrap();
        response.expect(T_ENUMERATED).unwrap();
        let mut bytes = Der::new(response.expect(T_CTX0).unwrap())
            .nested(T_SEQUENCE)
            .unwrap();
        bytes.expect(T_OID).unwrap();
        let mut basic = Der::new(bytes.expect(T_OCTET_STRING).unwrap())
            .nested(T_SEQUENCE)
            .unwrap();
        let tbs = basic.expect_raw(T_SEQUENCE).unwrap();
        let original_algorithm = basic.expect(T_SEQUENCE).unwrap();
        let signature = basic.expect_raw(T_BIT_STRING).unwrap();
        sign::verify(
            f.ca_key.schemes()[0],
            &PublicKey::from_spki(f.ca_key.spki()).unwrap(),
            tbs,
            whole_bits(Der::new(signature).expect(T_BIT_STRING).unwrap()).unwrap(),
        )
        .unwrap();
        let unknown = wrap(T_OID, &[0x2a, 3]);
        for (algorithm, expected) in [
            (original_algorithm.to_vec(), None),
            (
                unknown.clone(),
                Some("unsupported OCSP signature algorithm"),
            ),
            (
                [unknown.clone(), alloc::vec![0x05, 0]].concat(),
                Some("unsupported OCSP signature algorithm"),
            ),
            (
                [unknown.clone(), alloc::vec![0x9f, 31, 0]].concat(),
                Some("unsupported OCSP signature algorithm"),
            ),
            (wrap(T_OID, &[]), Some("empty OBJECT IDENTIFIER")),
            (
                wrap(T_OID, &[0x2a, 0x80, 1]),
                Some("nonminimal OBJECT IDENTIFIER subidentifier"),
            ),
            (
                wrap(T_OID, &[0x2a, 0x81]),
                Some("truncated OBJECT IDENTIFIER subidentifier"),
            ),
            (
                [unknown.clone(), alloc::vec![0x05, 0, 0x05, 0]].concat(),
                Some("trailing DER data"),
            ),
            (
                [unknown.clone(), alloc::vec![T_OCTET_STRING, 2, 1]].concat(),
                Some("DER value runs past its parent"),
            ),
            (
                [unknown, alloc::vec![0x9f, 30, 0]].concat(),
                Some("nonminimal DER tag number"),
            ),
            (
                [original_algorithm, &[0x05, 0][..]].concat(),
                Some("trailing DER data"),
            ),
        ] {
            let basic = wrap(
                T_SEQUENCE,
                &[tbs, wrap(T_SEQUENCE, &algorithm).as_slice(), signature].concat(),
            );
            let response_bytes = wrap(
                T_SEQUENCE,
                &[wrap(T_OID, OID_OCSP_BASIC), wrap(T_OCTET_STRING, &basic)].concat(),
            );
            let der = wrap(
                T_SEQUENCE,
                &[wrap(T_ENUMERATED, &[0]), wrap(T_CTX0, &response_bytes)].concat(),
            );
            let result = check(&f, &der, f.now);
            if let Some(context) = expected {
                let error = result.unwrap_err();
                assert_eq!(error.kind(), ErrorKind::BadCertificateStatus);
                assert_eq!(error.context(), context);
            } else {
                assert_eq!(result.unwrap().status, CertStatus::Good);
            }
        }
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

    /// REQ-OCSP-004: every supported SHA-2 CertID checks both issuer hashes,
    /// not only the serial or the signature on the response.
    #[test]
    fn sha2_cert_ids_check_both_issuer_hashes() {
        let f = fixture();
        let ca = Certificate::parse(&f.ca).unwrap();
        let leaf = Certificate::parse(&f.leaf).unwrap();
        let mut rng = ic_drbg::Rng::from_os().unwrap();
        for hash_oid in [OID_SHA256, OID_SHA384, OID_SHA512] {
            let name_hash = digest(hash_oid, ca.subject).unwrap();
            let key_hash = digest(hash_oid, spki_key_bits(ca.spki).unwrap()).unwrap();
            for altered in [None, Some(0), Some(1)] {
                let mut name = name_hash.clone();
                let mut key = key_hash.clone();
                match altered {
                    Some(0) => name[0] ^= 1,
                    Some(_) => key[0] ^= 1,
                    None => {}
                }
                let response = build_signed_with_cert_id(
                    hash_oid,
                    &name,
                    &key,
                    leaf.serial,
                    ca.subject,
                    &f.ca_key,
                    None,
                    CertStatus::Good,
                    f.now,
                    Some(f.now + 60),
                    &mut rng,
                )
                .unwrap();
                let result = check(&f, &response, f.now);
                if altered.is_none() {
                    assert!(result.unwrap().cert_id_hashes_checked);
                } else {
                    let e = result.unwrap_err();
                    assert_eq!(e.kind(), ErrorKind::BadCertificateStatus);
                    assert_eq!(e.context(), "OCSP response does not cover this certificate");
                }
            }
        }
    }

    /// REQ-OCSP-004: SHA-1 CertIDs report unchecked issuer hashes but still
    /// require the correct serial and an issuer-authorized response signature.
    /// An unsupported hash identifier cannot enter this compatibility path.
    #[test]
    fn sha1_cert_ids_remain_issuer_bound_and_unknown_hashes_are_refused() {
        let f = fixture();
        let foreign = fixture();
        let ca = Certificate::parse(&f.ca).unwrap();
        let leaf = Certificate::parse(&f.leaf).unwrap();
        let mut rng = ic_drbg::Rng::from_os().unwrap();
        // These are deliberately synthetic hashes, not SHA-1 test vectors:
        // the implementation cannot compute SHA-1 and does not compare them.
        let build = |oid: &[u8], serial: &[u8], signer: &SigningKey, rng: &mut ic_drbg::Rng| {
            build_signed_with_cert_id(
                oid,
                &[0; 20],
                &[0; 20],
                serial,
                ca.subject,
                signer,
                None,
                CertStatus::Good,
                f.now,
                Some(f.now + 60),
                rng,
            )
            .unwrap()
        };
        let response = build(OID_SHA1, leaf.serial, &f.ca_key, &mut rng);
        let verified = check(&f, &response, f.now).unwrap();
        assert_eq!(verified.status, CertStatus::Good);
        assert!(!verified.cert_id_hashes_checked && !verified.delegated);
        let wrong_serial = build(OID_SHA1, &[5; 16], &f.ca_key, &mut rng);
        let e = check(&f, &wrong_serial, f.now).unwrap_err();
        assert_eq!(e.context(), "OCSP response does not cover this certificate");
        let foreign_signature = build(OID_SHA1, leaf.serial, &foreign.ca_key, &mut rng);
        let e = check(&f, &foreign_signature, f.now).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::BadCertificateStatus);
        assert_eq!(
            e.context(),
            "OCSP response is not signed by the issuer or an authorized responder"
        );
        // A known OID that does not identify a supported CertID hash.
        let unknown_hash = build(OID_OCSP_BASIC, leaf.serial, &f.ca_key, &mut rng);
        let e = check(&f, &unknown_hash, f.now).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::BadCertificateStatus);
        assert_eq!(e.context(), "OCSP response does not cover this certificate");
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

    /// REQ-OCSP-015: malformed by-key IDs are rejected even when signed.
    #[test]
    fn by_key_responder_ids_require_a_complete_sha1_encoding() {
        let f = fixture();
        let good = make(&f, CertStatus::Good, f.now, f.now + 60);
        let mut outer = Der::new(&good);
        let mut response = outer.nested(T_SEQUENCE).unwrap();
        response.expect(T_ENUMERATED).unwrap();
        let mut bytes = Der::new(response.expect(T_CTX0).unwrap())
            .nested(T_SEQUENCE)
            .unwrap();
        bytes.expect(T_OID).unwrap();
        let mut basic = Der::new(bytes.expect(T_OCTET_STRING).unwrap())
            .nested(T_SEQUENCE)
            .unwrap();
        let mut fields = Der::new(basic.expect(T_SEQUENCE).unwrap());
        fields.expect(T_CTX1).unwrap();
        let produced = fields.expect_raw(T_GENERALIZED_TIME).unwrap();
        let responses = fields.expect_raw(T_SEQUENCE).unwrap();
        let mut valid = Vec::new();
        // Synthetic hash tests encoding only, not a SHA-1 vector or identity check.
        push_tlv(&mut valid, T_OCTET_STRING, &[0; 20]);
        let mut short = Vec::new();
        push_tlv(&mut short, T_OCTET_STRING, &[0; 19]);
        let mut long = Vec::new();
        push_tlv(&mut long, T_OCTET_STRING, &[0; 21]);
        let mut trailing = valid.clone();
        trailing.extend_from_slice(&[0x05, 0]);
        let mut rng = ic_drbg::Rng::from_os().unwrap();
        for (encoded, accepted) in [
            (valid, true),
            (short, false),
            (long, false),
            (trailing, false),
            (Vec::new(), false),
            (alloc::vec![0; 20], false),
        ] {
            let mut body = Vec::new();
            push_tlv(&mut body, T_CTX2, &encoded);
            body.extend_from_slice(produced);
            body.extend_from_slice(responses);
            let mut tbs = Vec::new();
            push_tlv(&mut tbs, T_SEQUENCE, &body);
            let signed = sign_response(tbs, &f.ca_key, None, &mut rng).unwrap();
            let result = check(&f, &signed, f.now);
            if accepted {
                assert_eq!(result.unwrap().status, CertStatus::Good);
            } else {
                assert_eq!(result.unwrap_err().kind(), ErrorKind::BadCertificateStatus);
            }
        }
    }

    /// REQ-OCSP-016: conflicting matching entries fail in both orders;
    /// identical entries remain accepted.
    #[test]
    fn conflicting_matching_responses_are_refused() {
        fn parts(response: &[u8]) -> (&[u8], &[u8], &[u8]) {
            let mut outer = Der::new(response);
            let mut response = outer.nested(T_SEQUENCE).unwrap();
            response.expect(T_ENUMERATED).unwrap();
            let mut bytes = Der::new(response.expect(T_CTX0).unwrap())
                .nested(T_SEQUENCE)
                .unwrap();
            bytes.expect(T_OID).unwrap();
            let mut basic = Der::new(bytes.expect(T_OCTET_STRING).unwrap())
                .nested(T_SEQUENCE)
                .unwrap();
            let mut fields = Der::new(basic.expect(T_SEQUENCE).unwrap());
            (
                fields.expect_raw(T_CTX1).unwrap(),
                fields.expect_raw(T_GENERALIZED_TIME).unwrap(),
                fields.expect(T_SEQUENCE).unwrap(),
            )
        }
        let f = fixture();
        let good = make(&f, CertStatus::Good, f.now, f.now + 60);
        let (responder, produced, original) = parts(&good);
        let mut rng = ic_drbg::Rng::from_os().unwrap();
        for (status, this, next, accepted) in [
            (CertStatus::Good, f.now, f.now + 60, true),
            (CertStatus::Unknown, f.now, f.now + 60, false),
            (
                CertStatus::Revoked { at: f.now - 1 },
                f.now,
                f.now + 60,
                false,
            ),
            (CertStatus::Good, f.now - 1, f.now + 60, false),
            (CertStatus::Good, f.now, f.now + 61, false),
        ] {
            let extra = make(&f, status, this, next);
            let (_, _, extra) = parts(&extra);
            for before in [false, true] {
                let mut entries = Vec::new();
                let (first, second) = if before {
                    (extra, original)
                } else {
                    (original, extra)
                };
                entries.extend_from_slice(first);
                entries.extend_from_slice(second);
                let mut body = Vec::new();
                body.extend_from_slice(responder);
                body.extend_from_slice(produced);
                push_tlv(&mut body, T_SEQUENCE, &entries);
                let mut tbs = Vec::new();
                push_tlv(&mut tbs, T_SEQUENCE, &body);
                let signed = sign_response(tbs, &f.ca_key, None, &mut rng).unwrap();
                let result = check(&f, &signed, f.now);
                if accepted {
                    assert_eq!(result.unwrap().status, CertStatus::Good);
                } else {
                    assert_eq!(result.unwrap_err().kind(), ErrorKind::BadCertificateStatus);
                }
            }
        }
    }

    /// REQ-OCSP-013: signed lists are fully parsed even after a matching entry.
    #[test]
    fn all_single_responses_are_parsed() {
        let f = fixture();
        let good = make(&f, CertStatus::Good, f.now, f.now + 60);
        let mut outer = Der::new(&good);
        let mut response = outer.nested(T_SEQUENCE).unwrap();
        response.expect(T_ENUMERATED).unwrap();
        let mut bytes = Der::new(response.expect(T_CTX0).unwrap())
            .nested(T_SEQUENCE)
            .unwrap();
        bytes.expect(T_OID).unwrap();
        let mut basic = Der::new(bytes.expect(T_OCTET_STRING).unwrap())
            .nested(T_SEQUENCE)
            .unwrap();
        let mut fields = Der::new(basic.expect(T_SEQUENCE).unwrap());
        let responder = fields.expect_raw(T_CTX1).unwrap();
        let produced = fields.expect_raw(T_GENERALIZED_TIME).unwrap();
        let original = fields.expect(T_SEQUENCE).unwrap();
        let mut rng = ic_drbg::Rng::from_os().unwrap();
        for extra in [
            original,
            &[T_SEQUENCE, 0],
            &[0x05, 0],
            &[T_SEQUENCE, 3, T_INTEGER, 1],
        ] {
            for before in [false, true] {
                let mut entries = Vec::new();
                if before {
                    entries.extend_from_slice(extra);
                }
                entries.extend_from_slice(original);
                if !before {
                    entries.extend_from_slice(extra);
                }
                let mut body = Vec::new();
                body.extend_from_slice(responder);
                body.extend_from_slice(produced);
                push_tlv(&mut body, T_SEQUENCE, &entries);
                let mut tbs = Vec::new();
                push_tlv(&mut tbs, T_SEQUENCE, &body);
                let signed = sign_response(tbs, &f.ca_key, None, &mut rng).unwrap();
                let result = check(&f, &signed, f.now);
                if extra == original {
                    assert_eq!(result.unwrap().status, CertStatus::Good);
                } else {
                    assert_eq!(result.unwrap_err().kind(), ErrorKind::BadCertificateStatus);
                }
            }
        }
    }

    /// REQ-OCSP-027: malformed hash OIDs cannot be skipped as unsupported,
    /// including nonmatching serials and entries after a matching response.
    #[test]
    fn cert_id_hash_oids_require_complete_minimal_encodings() {
        let f = fixture();
        let leaf = Certificate::parse(&f.leaf).unwrap();
        let good = make(&f, CertStatus::Good, f.now, f.now + 60);
        let mut outer = Der::new(&good);
        let mut response = outer.nested(T_SEQUENCE).unwrap();
        response.expect(T_ENUMERATED).unwrap();
        let mut bytes = Der::new(response.expect(T_CTX0).unwrap())
            .nested(T_SEQUENCE)
            .unwrap();
        bytes.expect(T_OID).unwrap();
        let mut basic = Der::new(bytes.expect(T_OCTET_STRING).unwrap())
            .nested(T_SEQUENCE)
            .unwrap();
        let mut fields = Der::new(basic.expect(T_SEQUENCE).unwrap());
        let responder = fields.expect_raw(T_CTX1).unwrap();
        let produced = fields.expect_raw(T_GENERALIZED_TIME).unwrap();
        let original = fields.expect(T_SEQUENCE).unwrap();
        let mut rng = ic_drbg::Rng::from_os().unwrap();
        for (oid, structural_error) in [
            (&[][..], Some("empty OBJECT IDENTIFIER")),
            (
                &[0x80, 0][..],
                Some("nonminimal OBJECT IDENTIFIER subidentifier"),
            ),
            (
                &[0x2a, 0x80, 1][..],
                Some("nonminimal OBJECT IDENTIFIER subidentifier"),
            ),
            (
                &[0x81][..],
                Some("truncated OBJECT IDENTIFIER subidentifier"),
            ),
            (
                &[0x2a, 0x81][..],
                Some("truncated OBJECT IDENTIFIER subidentifier"),
            ),
            (&[0][..], None),
            (&[0x2a, 0x81, 0][..], None),
            (&[0x88, 0x80, 0x80, 0x80, 0x80, 0][..], None),
        ] {
            for null_parameters in [false, true] {
                for serial in [leaf.serial, &[0x7e][..]] {
                    let mut algorithm = Vec::new();
                    push_tlv(&mut algorithm, T_OID, oid);
                    if null_parameters {
                        algorithm.extend_from_slice(&[super::super::T_NULL, 0]);
                    }
                    let mut cert_id = Vec::new();
                    push_tlv(&mut cert_id, T_SEQUENCE, &algorithm);
                    push_tlv(&mut cert_id, T_OCTET_STRING, &[0; 32]);
                    push_tlv(&mut cert_id, T_OCTET_STRING, &[0; 32]);
                    push_tlv(&mut cert_id, T_INTEGER, serial);
                    let mut single = Vec::new();
                    push_tlv(&mut single, T_SEQUENCE, &cert_id);
                    push_tlv(&mut single, T_GOOD, &[]);
                    generalized_time(&mut single, f.now).unwrap();
                    let mut extra = Vec::new();
                    push_tlv(&mut extra, T_SEQUENCE, &single);
                    for position in 0..3 {
                        let entries = match position {
                            0 => extra.clone(),
                            1 => [extra.as_slice(), original].concat(),
                            _ => [original, extra.as_slice()].concat(),
                        };
                        let mut body = Vec::new();
                        body.extend_from_slice(responder);
                        body.extend_from_slice(produced);
                        push_tlv(&mut body, T_SEQUENCE, &entries);
                        let mut tbs = Vec::new();
                        push_tlv(&mut tbs, T_SEQUENCE, &body);
                        let signed = sign_response(tbs, &f.ca_key, None, &mut rng).unwrap();
                        let result = check(&f, &signed, f.now);
                        let expected_error = structural_error.or((position == 0)
                            .then_some("OCSP response does not cover this certificate"));
                        if let Some(context) = expected_error {
                            let error = result.err().unwrap();
                            assert_eq!(error.kind(), ErrorKind::BadCertificateStatus);
                            assert_eq!(error.context(), context,
                                "oid={oid:?}, position={position}, serial={serial:?}, null={null_parameters}");
                        } else {
                            let verified = result.unwrap();
                            assert_eq!(verified.status, CertStatus::Good);
                            assert!(verified.cert_id_hashes_checked);
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn ocsp_issuance_requires_the_issuers_key() {
        let f = fixture();
        let other = fixture();
        let mut rng = ic_drbg::Rng::from_os().unwrap();
        let good = build_response(
            &f.leaf,
            &f.ca,
            &f.ca_key,
            CertStatus::Good,
            f.now,
            f.now + 60,
            &mut rng,
        )
        .unwrap();
        assert_eq!(check(&f, &good, f.now).unwrap().status, CertStatus::Good);
        let error = build_response(
            &f.leaf,
            &f.ca,
            &other.ca_key,
            CertStatus::Good,
            f.now,
            f.now + 60,
            &mut rng,
        )
        .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidConfig);
        assert_eq!(error.context(), "issuer does not match the key");
    }

    #[test]
    fn ocsp_issuance_refuses_reversed_update_intervals() {
        let f = fixture();
        let mut rng = ic_drbg::Rng::from_os().unwrap();
        for next in [f.now - 1, f.now, f.now + 1] {
            let result = build_response(
                &f.leaf,
                &f.ca,
                &f.ca_key,
                CertStatus::Good,
                f.now,
                next,
                &mut rng,
            );
            if next < f.now {
                let error = result.unwrap_err();
                assert_eq!(error.kind(), ErrorKind::InvalidConfig);
                assert_eq!(error.context(), "OCSP nextUpdate precedes thisUpdate");
            } else {
                let verified = check(&f, &result.unwrap(), f.now).unwrap();
                assert_eq!(verified.this_update, f.now);
                assert_eq!(verified.next_update, Some(next));
            }
        }
    }

    #[test]
    fn cert_id_hashes_require_the_algorithms_digest_length() {
        let f = fixture();
        let ca = Certificate::parse(&f.ca).unwrap();
        let leaf = Certificate::parse(&f.leaf).unwrap();
        let mut rng = ic_drbg::Rng::from_os().unwrap();
        for (oid, length) in [
            (OID_SHA1, 20),
            (OID_SHA256, 32),
            (OID_SHA384, 48),
            (OID_SHA512, 64),
        ] {
            for name_len in [0, length - 1, length, length + 1] {
                for key_len in [0, length - 1, length, length + 1] {
                    let mut name = digest(oid, ca.subject).unwrap_or(alloc::vec![0; 20]);
                    let mut key =
                        digest(oid, spki_key_bits(ca.spki).unwrap()).unwrap_or(alloc::vec![0; 20]);
                    name.resize(name_len, 0);
                    key.resize(key_len, 0);
                    let der = build_signed_with_cert_id(
                        oid,
                        &name,
                        &key,
                        leaf.serial,
                        ca.subject,
                        &f.ca_key,
                        None,
                        CertStatus::Good,
                        f.now,
                        Some(f.now + 60),
                        &mut rng,
                    )
                    .unwrap();
                    let result = check(&f, &der, f.now);
                    if name_len == length && key_len == length {
                        assert_eq!(result.unwrap().status, CertStatus::Good);
                    } else {
                        let error = result.unwrap_err();
                        assert_eq!(error.kind(), ErrorKind::BadCertificateStatus);
                        assert_eq!(error.context(), "incorrect OCSP CertID digest length");
                    }
                }
            }
        }
    }

    #[test]
    fn only_canonical_successful_response_status_is_accepted() {
        let f = fixture();
        let good = make(&f, CertStatus::Good, f.now, f.now + 60);
        let mut response = Der::new(&good).nested(T_SEQUENCE).unwrap();
        response.expect(T_ENUMERATED).unwrap();
        let bytes = response.expect_raw(T_CTX0).unwrap();
        for tag in [T_ENUMERATED, T_INTEGER] {
            for status in [
                &[][..],
                &[0],
                &[1],
                &[2],
                &[3],
                &[4],
                &[5],
                &[6],
                &[7],
                &[0xff],
                &[0, 0],
                &[0, 1],
            ] {
                let mut body = Vec::new();
                push_tlv(&mut body, tag, status);
                body.extend_from_slice(bytes);
                let mut der = Vec::new();
                push_tlv(&mut der, T_SEQUENCE, &body);
                let result = check(&f, &der, f.now);
                if tag == T_ENUMERATED && status == [0] {
                    assert_eq!(result.unwrap().status, CertStatus::Good);
                } else {
                    assert_eq!(result.unwrap_err().kind(), ErrorKind::BadCertificateStatus);
                }
            }
        }
    }

    #[test]
    fn good_and_unknown_statuses_require_empty_implicit_null() {
        let mut algorithm = Vec::new();
        push_tlv(&mut algorithm, T_OID, OID_SHA256);
        let mut id = Vec::new();
        push_tlv(&mut id, T_SEQUENCE, &algorithm);
        push_tlv(&mut id, T_OCTET_STRING, &[0; 32]);
        push_tlv(&mut id, T_OCTET_STRING, &[0; 32]);
        push_tlv(&mut id, T_INTEGER, &[1]);
        for tag in [T_GOOD, T_UNKNOWN, 0xa0, 0xa2, 0x81, 0x83, 0x05] {
            for payload in [&[][..], &[0], &[5, 0]] {
                let mut single = Vec::new();
                push_tlv(&mut single, T_SEQUENCE, &id);
                push_tlv(&mut single, tag, payload);
                push_tlv(&mut single, T_GENERALIZED_TIME, b"20270115080000Z");
                let result = parse_single(&single);
                if payload.is_empty() && matches!(tag, T_GOOD | T_UNKNOWN) {
                    let expected = if tag == T_GOOD {
                        CertStatus::Good
                    } else {
                        CertStatus::Unknown
                    };
                    assert_eq!(result.unwrap().status, expected);
                } else {
                    assert!(result.is_err(), "tag={tag:x}, payload={payload:?}");
                }
            }
        }
    }

    #[test]
    fn cert_id_serials_require_minimal_integer_encoding() {
        for serial in [
            &[][..],
            &[0],
            &[0x7f],
            &[0x80],
            &[0xff],
            &[0, 0x80],
            &[0xff, 0x7f],
            &[0, 0],
            &[0, 0x7f],
            &[0xff, 0xff],
            &[0xff, 0x80],
        ] {
            let mut algorithm = Vec::new();
            push_tlv(&mut algorithm, T_OID, OID_SHA256);
            let mut id = Vec::new();
            push_tlv(&mut id, T_SEQUENCE, &algorithm);
            push_tlv(&mut id, T_OCTET_STRING, &[0; 32]);
            push_tlv(&mut id, T_OCTET_STRING, &[0; 32]);
            push_tlv(&mut id, T_INTEGER, serial);
            let mut single = Vec::new();
            push_tlv(&mut single, T_SEQUENCE, &id);
            push_tlv(&mut single, T_GOOD, &[]);
            push_tlv(&mut single, T_GENERALIZED_TIME, b"20270115080000Z");
            let valid = matches!(
                serial,
                [0] | [0x7f] | [0x80] | [0xff] | [0, 0x80] | [0xff, 0x7f]
            );
            if valid {
                assert_eq!(parse_single(&single).unwrap().serial, serial);
            } else {
                assert!(parse_single(&single).is_err());
            }
        }
    }

    /// REQ-OCSP-012: both extension locations reject unsupported critical
    /// extensions and malformed encodings, even with a valid response signature.
    /// REQ-OCSP-026: unknown noncritical extension OIDs are validated at both levels.
    #[test]
    fn ocsp_extensions_are_validated_at_both_levels() {
        let f = fixture();
        let good = make(&f, CertStatus::Good, f.now, f.now + 60);
        let mut outer = Der::new(&good);
        let mut response = outer.nested(T_SEQUENCE).unwrap();
        response.expect(T_ENUMERATED).unwrap();
        let mut bytes = Der::new(response.expect(T_CTX0).unwrap())
            .nested(T_SEQUENCE)
            .unwrap();
        bytes.expect(T_OID).unwrap();
        let mut basic = Der::new(bytes.expect(T_OCTET_STRING).unwrap())
            .nested(T_SEQUENCE)
            .unwrap();
        let data = basic.expect(T_SEQUENCE).unwrap();
        let mut fields = Der::new(data);
        let responder = fields.expect_raw(T_CTX1).unwrap();
        let produced = fields.expect_raw(T_GENERALIZED_TIME).unwrap();
        let responses = fields.expect(T_SEQUENCE).unwrap();
        let single = Der::new(responses).expect(T_SEQUENCE).unwrap();
        let extension_with_oid = |oid: &[u8], critical: Option<u8>| {
            let mut entry = Vec::new();
            // This OID is intentionally not an implemented OCSP extension.
            push_tlv(&mut entry, T_OID, oid);
            if let Some(flag) = critical {
                push_tlv(&mut entry, T_BOOLEAN, &[flag]);
            }
            push_tlv(&mut entry, T_OCTET_STRING, &[0x05, 0]);
            let mut entries = Vec::new();
            push_tlv(&mut entries, T_SEQUENCE, &entry);
            let mut encoded = Vec::new();
            push_tlv(&mut encoded, T_SEQUENCE, &entries);
            encoded
        };
        let extension = |critical| extension_with_oid(OID_OCSP_BASIC, critical);
        let mut trailing = extension(None);
        trailing.extend_from_slice(&[0x05, 0]);
        let pair = |distinct: bool| {
            let encoded = extension(None);
            let entry = Der::new(&encoded).expect(T_SEQUENCE).unwrap();
            let mut entries = entry.to_vec();
            let mut other = entry.to_vec();
            if distinct {
                // Replace only the final OID arc, preserving its DER length.
                let position = other
                    .windows(OID_OCSP_BASIC.len())
                    .position(|w| w == OID_OCSP_BASIC)
                    .unwrap();
                other[position + OID_OCSP_BASIC.len() - 1] = 2;
            }
            entries.extend_from_slice(&other);
            let mut encoded = Vec::new();
            push_tlv(&mut encoded, T_SEQUENCE, &entries);
            encoded
        };
        let mut cases = alloc::vec![
            (pair(false), false),
            (pair(true), true),
            (extension(None), true),
            (extension(Some(0)), true),
            (extension(Some(0xff)), false),
            (extension(Some(1)), false),
            (alloc::vec![0x05, 0], false),
            (alloc::vec![T_SEQUENCE, 0], false),
            (trailing, false),
        ];
        for (oid, valid) in [
            (&[][..], false),
            (&[0x80, 0][..], false),
            (&[0x2a, 0x80, 1][..], false),
            (&[0x81][..], false),
            (&[0x2a, 0x81][..], false),
            (&[0][..], true),
            (&[0x2a, 0x81, 0][..], true),
            (&[0x88, 0x80, 0x80, 0x80, 0x80, 0][..], true),
        ] {
            cases.push((extension_with_oid(oid, None), valid));
            cases.push((extension_with_oid(oid, Some(0)), valid));
            cases.push((extension_with_oid(oid, Some(0xff)), false));
        }
        let mut rng = ic_drbg::Rng::from_os().unwrap();
        for at_single in [false, true] {
            for (extensions, valid) in &cases {
                let mut body = Vec::new();
                if at_single {
                    let mut altered = single.to_vec();
                    push_tlv(&mut altered, T_CTX1, extensions);
                    let mut responses = Vec::new();
                    push_tlv(&mut responses, T_SEQUENCE, &altered);
                    body.extend_from_slice(responder);
                    body.extend_from_slice(produced);
                    push_tlv(&mut body, T_SEQUENCE, &responses);
                } else {
                    body.extend_from_slice(data);
                    push_tlv(&mut body, T_CTX1, extensions);
                }
                let mut tbs = Vec::new();
                push_tlv(&mut tbs, T_SEQUENCE, &body);
                let signed = sign_response(tbs, &f.ca_key, None, &mut rng).unwrap();
                let result = check(&f, &signed, f.now);
                if *valid {
                    assert_eq!(result.unwrap().status, CertStatus::Good);
                } else {
                    assert_eq!(
                        result.unwrap_err().kind(),
                        ErrorKind::BadCertificateStatus,
                        "at_single={at_single}, extensions={extensions:?}"
                    );
                }
            }
        }
    }

    /// REQ-OCSP-011: by-name responder identity binds the actual signing
    /// certificate, for both direct issuer signatures and authorized delegates.
    #[test]
    fn by_name_responder_ids_identify_the_signing_certificate() {
        let f = fixture();
        let ca = Certificate::parse(&f.ca).unwrap();
        let leaf = Certificate::parse(&f.leaf).unwrap();
        let (cert, key) = responder(&f, Some(OID_KP_OCSP_SIGNING));
        let delegate = Certificate::parse(&cert).unwrap();
        let name_hash = digest(OID_SHA256, ca.subject).unwrap();
        let key_hash = digest(OID_SHA256, spki_key_bits(ca.spki).unwrap()).unwrap();
        let mut rng = ic_drbg::Rng::from_os().unwrap();
        for (signer, attached, expected, delegated) in [
            (&f.ca_key, None, ca.subject, false),
            (&key, Some(cert.as_slice()), delegate.subject, true),
        ] {
            for name in [expected, leaf.subject] {
                let signed = build_signed_with_cert_id(
                    OID_SHA256,
                    &name_hash,
                    &key_hash,
                    leaf.serial,
                    name,
                    signer,
                    attached,
                    CertStatus::Good,
                    f.now,
                    Some(f.now + 60),
                    &mut rng,
                )
                .unwrap();
                let result = check(&f, &signed, f.now);
                if name == expected {
                    assert_eq!(result.unwrap().delegated, delegated);
                } else {
                    let e = result.unwrap_err();
                    assert_eq!(e.kind(), ErrorKind::BadCertificateStatus);
                    assert_eq!(
                        e.context(),
                        "OCSP response is not signed by the issuer or an authorized responder"
                    );
                }
            }
        }
    }

    /// REQ-OCSP-025: malformed byName encodings produce structural status
    /// errors even when signed by the issuer or an authorized delegate.
    #[test]
    fn by_name_responder_ids_require_a_complete_well_formed_name() {
        let f = fixture();
        let ca = Certificate::parse(&f.ca).unwrap();
        let leaf = Certificate::parse(&f.leaf).unwrap();
        let (cert, key) = responder(&f, Some(OID_KP_OCSP_SIGNING));
        let delegate = Certificate::parse(&cert).unwrap();
        let name_hash = digest(OID_SHA256, ca.subject).unwrap();
        let key_hash = digest(OID_SHA256, spki_key_bits(ca.spki).unwrap()).unwrap();
        let mut rng = ic_drbg::Rng::from_os().unwrap();
        let wrap_name = |attributes: &[u8]| {
            let mut rdn = Vec::new();
            push_tlv(&mut rdn, super::super::T_SET, attributes);
            let mut name = Vec::new();
            push_tlv(&mut name, T_SEQUENCE, &rdn);
            name
        };
        let attribute = |oid: &[u8], value: &[u8]| {
            let mut body = Vec::new();
            push_tlv(&mut body, T_OID, oid);
            body.extend_from_slice(value);
            let mut encoded = Vec::new();
            push_tlv(&mut encoded, T_SEQUENCE, &body);
            encoded
        };
        let first = attribute(&[0x2a], &[0x0c, 1, b'a']);
        let second = attribute(&[0x2b], &[0x0c, 1, b'b']);
        let mut unsorted = second;
        unsorted.extend_from_slice(&first);
        let mut trailing = ca.subject.to_vec();
        trailing.extend_from_slice(&[0x05, 0]);
        let cases = [
            (vec![0x31, 0], "unexpected DER tag"),
            (trailing, "trailing DER data"),
            (wrap_name(&[]), "empty Name RDN"),
            (
                wrap_name(&attribute(&[], &[0x05, 0])),
                "empty OBJECT IDENTIFIER",
            ),
            (
                wrap_name(&attribute(&[0x80, 0], &[0x05, 0])),
                "nonminimal OBJECT IDENTIFIER subidentifier",
            ),
            (
                wrap_name(&attribute(&[0x2a, 0x81], &[0x05, 0])),
                "truncated OBJECT IDENTIFIER subidentifier",
            ),
            (
                wrap_name(&attribute(&[0x2a], &[0x05, 0, 0x05, 0])),
                "trailing DER data",
            ),
            (
                wrap_name(&attribute(&[0x2a], &[0, 0])),
                "end-of-contents is not a DER value",
            ),
            (
                wrap_name(&unsorted),
                "Name RDN attributes are not in DER order",
            ),
        ];
        for (signer, attached, expected_name, delegated) in [
            (&f.ca_key, None, ca.subject, false),
            (&key, Some(cert.as_slice()), delegate.subject, true),
        ] {
            for (name, expected_error) in core::iter::once((expected_name, None))
                .chain(
                    cases
                        .iter()
                        .map(|(name, context)| (name.as_slice(), Some(*context))),
                )
                .chain(core::iter::once((
                    &[0x30, 0][..],
                    Some("OCSP response is not signed by the issuer or an authorized responder"),
                )))
            {
                let signed = build_signed_with_cert_id(
                    OID_SHA256,
                    &name_hash,
                    &key_hash,
                    leaf.serial,
                    name,
                    signer,
                    attached,
                    CertStatus::Good,
                    f.now,
                    Some(f.now + 60),
                    &mut rng,
                )
                .unwrap();
                let result = check(&f, &signed, f.now);
                if let Some(context) = expected_error {
                    let error = result.err().unwrap();
                    assert_eq!(error.kind(), ErrorKind::BadCertificateStatus);
                    assert_eq!(error.context(), context, "name={name:?}");
                } else {
                    assert_eq!(result.unwrap().delegated, delegated);
                }
            }
        }
    }

    /// REQ-OCSP-010: bytes outside the nested response sequences cannot be
    /// ignored, even when the enclosed response signature still verifies.
    #[test]
    fn response_wrappers_refuse_trailing_bytes() {
        let f = fixture();
        let (cert, key) = responder(&f, Some(OID_KP_OCSP_SIGNING));
        let mut rng = ic_drbg::Rng::from_os().unwrap();
        let good = build_signed(
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
        let mut outer = Der::new(&good);
        let mut response = outer.nested(T_SEQUENCE).unwrap();
        response.expect(T_ENUMERATED).unwrap();
        let mut bytes = Der::new(response.expect(T_CTX0).unwrap())
            .nested(T_SEQUENCE)
            .unwrap();
        bytes.expect(T_OID).unwrap();
        let basic = bytes.expect(T_OCTET_STRING).unwrap();
        for (basic_tail, wrapper_tail, certs_tail) in [
            (false, false, false),
            (true, false, false),
            (false, true, false),
            (false, false, true),
        ] {
            let mut basic = basic.to_vec();
            if certs_tail {
                let mut fields = Der::new(&basic).nested(T_SEQUENCE).unwrap();
                let mut altered = fields.expect_raw(T_SEQUENCE).unwrap().to_vec();
                altered.extend_from_slice(fields.expect_raw(T_SEQUENCE).unwrap());
                altered.extend_from_slice(fields.expect_raw(T_BIT_STRING).unwrap());
                let mut certs = fields.expect(T_CTX0).unwrap().to_vec();
                certs.extend_from_slice(&[0x05, 0]);
                push_tlv(&mut altered, T_CTX0, &certs);
                let mut encoded = Vec::new();
                push_tlv(&mut encoded, T_SEQUENCE, &altered);
                basic = encoded;
            }
            if basic_tail {
                basic.extend_from_slice(&[0x05, 0]);
            }
            let mut response_bytes = Vec::new();
            push_tlv(&mut response_bytes, T_OID, OID_OCSP_BASIC);
            push_tlv(&mut response_bytes, T_OCTET_STRING, &basic);
            let mut explicit = Vec::new();
            push_tlv(&mut explicit, T_SEQUENCE, &response_bytes);
            if wrapper_tail {
                explicit.extend_from_slice(&[0x05, 0]);
            }
            let mut body = Vec::new();
            push_tlv(&mut body, T_ENUMERATED, &[0]);
            push_tlv(&mut body, T_CTX0, &explicit);
            let mut encoded = Vec::new();
            push_tlv(&mut encoded, T_SEQUENCE, &body);
            let result = check(&f, &encoded, f.now);
            if basic_tail || wrapper_tail || certs_tail {
                assert_eq!(
                    result.unwrap_err().kind(),
                    ErrorKind::BadCertificateStatus,
                    "basic_tail={basic_tail}, wrapper_tail={wrapper_tail}, certs_tail={certs_tail}"
                );
            } else {
                assert_eq!(encoded, good);
                let verified = result.unwrap();
                assert_eq!(verified.status, CertStatus::Good);
                assert!(verified.delegated);
            }
        }
    }

    /// REQ-OCSP-009: a revocation reason is optional, but when present is a
    /// single valid CRLReason; malformed wrappers and trailing fields fail.
    #[test]
    fn revoked_info_validates_reasons_and_consumes_every_field() {
        let now = 1_800_000_000;
        let mut time = Vec::new();
        generalized_time(&mut time, now).unwrap();
        assert_eq!(
            parse_revoked(&time).unwrap(),
            CertStatus::Revoked { at: now }
        );
        for code in [0, 1, 2, 3, 4, 5, 6, 8, 9, 10] {
            let mut content = time.clone();
            push_tlv(&mut content, T_CTX0, &[T_ENUMERATED, 1, code]);
            assert_eq!(
                parse_revoked(&content).unwrap(),
                CertStatus::Revoked { at: now }
            );
        }
        for tail in [
            alloc::vec![0x05, 0],
            alloc::vec![T_CTX0, 0],
            alloc::vec![T_CTX0, 3, T_INTEGER, 1, 1],
            alloc::vec![T_CTX0, 4, T_ENUMERATED, 2, 0, 1],
            alloc::vec![T_CTX0, 3, T_ENUMERATED, 1, 7],
            alloc::vec![T_CTX0, 3, T_ENUMERATED, 1, 11],
            alloc::vec![T_CTX0, 3, T_ENUMERATED, 1, 0xff],
            alloc::vec![T_CTX0, 5, T_ENUMERATED, 1, 1, 0x05, 0],
            alloc::vec![T_CTX0, 3, T_ENUMERATED, 1, 1, T_CTX0, 3, T_ENUMERATED, 1, 2],
        ] {
            let mut content = time.clone();
            content.extend_from_slice(&tail);
            assert!(parse_revoked(&content).is_err(), "tail {tail:?}");
        }
    }

    /// REQ-OCSP-008: a valid signature does not authorize unknown or malformed
    /// response versions; omitted and explicit v1 identify the supported format.
    #[test]
    fn response_versions_are_validated() {
        let f = fixture();
        let good = make(&f, CertStatus::Good, f.now, f.now + 60);
        assert!(check(&f, &good, f.now).is_ok());
        let mut outer = Der::new(&good);
        let mut response = outer.nested(T_SEQUENCE).unwrap();
        response.expect(T_ENUMERATED).unwrap();
        let mut bytes = Der::new(response.expect(T_CTX0).unwrap())
            .nested(T_SEQUENCE)
            .unwrap();
        bytes.expect(T_OID).unwrap();
        let mut basic = Der::new(bytes.expect(T_OCTET_STRING).unwrap())
            .nested(T_SEQUENCE)
            .unwrap();
        let data = basic.expect(T_SEQUENCE).unwrap();
        let mut rng = ic_drbg::Rng::from_os().unwrap();
        for version in [
            alloc::vec![T_INTEGER, 1, 0],
            alloc::vec![T_INTEGER, 1, 1],
            alloc::vec![],
            alloc::vec![0x05, 0],
            alloc::vec![T_INTEGER, 2, 0, 0],
            alloc::vec![T_INTEGER, 1, 0, 0x05, 0],
        ] {
            let mut body = Vec::new();
            push_tlv(&mut body, T_CTX0, &version);
            body.extend_from_slice(data);
            let mut tbs = Vec::new();
            push_tlv(&mut tbs, T_SEQUENCE, &body);
            let signed = sign_response(tbs, &f.ca_key, None, &mut rng).unwrap();
            let result = check(&f, &signed, f.now);
            if version == [T_INTEGER, 1, 0] {
                assert_eq!(result.unwrap().status, CertStatus::Good);
            } else {
                assert_eq!(
                    result.unwrap_err().kind(),
                    ErrorKind::BadCertificateStatus,
                    "version {version:?}"
                );
            }
        }
    }

    /// REQ-OCSP-007: nextUpdate and revocationTime reject UTCTime even when
    /// the shared X.509 time decoder accepts its valid representation.
    #[test]
    fn ocsp_optional_times_require_generalized_time() {
        let f = fixture();
        let mut encoded = Vec::new();
        generalized_time(&mut encoded, f.now).unwrap();
        let mut time_der = Der::new(&encoded);
        let time = time_der.expect(T_GENERALIZED_TIME).unwrap();
        let utc = &time[2..];
        assert_eq!(parse_time(super::super::T_UTC_TIME, utc).unwrap(), f.now);
        for revoked in [false, true] {
            for tag in [T_GENERALIZED_TIME, super::super::T_UTC_TIME] {
                let mut cert_id = hash_alg_id(OID_SHA256);
                push_tlv(&mut cert_id, T_OCTET_STRING, &[0; 32]);
                push_tlv(&mut cert_id, T_OCTET_STRING, &[0; 32]);
                push_tlv(&mut cert_id, T_INTEGER, &[1]);
                let mut body = Vec::new();
                push_tlv(&mut body, T_SEQUENCE, &cert_id);
                let mut selected_time = Vec::new();
                push_tlv(
                    &mut selected_time,
                    tag,
                    if tag == T_GENERALIZED_TIME { time } else { utc },
                );
                if revoked {
                    push_tlv(&mut body, T_REVOKED, &selected_time);
                } else {
                    push_tlv(&mut body, T_GOOD, &[]);
                }
                generalized_time(&mut body, f.now).unwrap();
                if !revoked {
                    push_tlv(&mut body, T_CTX0, &selected_time);
                }
                if tag == T_GENERALIZED_TIME {
                    let parsed = parse_single(&body).unwrap();
                    if revoked {
                        assert_eq!(parsed.status, CertStatus::Revoked { at: f.now });
                    } else {
                        assert_eq!(parsed.next_update, Some(f.now));
                    }
                } else {
                    let e = match parse_single(&body) {
                        Ok(_) => panic!("UTCTime accepted, revoked={revoked}"),
                        Err(e) => e,
                    };
                    assert_eq!(e.kind(), ErrorKind::BadCertificateStatus);
                    assert_eq!(
                        e.context(),
                        if revoked {
                            "revocationTime is not GeneralizedTime"
                        } else {
                            "nextUpdate is not GeneralizedTime"
                        }
                    );
                }
            }
        }
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

    /// REQ-OCSP-002: the five-minute clock-skew allowance is inclusive for
    /// REQ-OCSP-014: inverted validity intervals are refused independently of
    /// clock skew; equal endpoints and forward intervals remain accepted.
    #[test]
    fn next_update_cannot_precede_this_update() {
        let f = fixture();
        for this in [f.now - 1, f.now, f.now + 1] {
            for next in [this - 1, this, this + 1] {
                let mut rng = ic_drbg::Rng::from_os().unwrap();
                // Bypass the public issuance guard to exercise verifier refusals.
                let response = build_signed(
                    &f.leaf,
                    &f.ca,
                    &f.ca_key,
                    None,
                    CertStatus::Good,
                    this,
                    next,
                    &mut rng,
                )
                .unwrap();
                let result = check(&f, &response, f.now);
                if next < this {
                    assert_eq!(result.unwrap_err().kind(), ErrorKind::BadCertificateStatus);
                } else {
                    let verified = result.unwrap();
                    assert_eq!(verified.this_update, this);
                    assert_eq!(verified.next_update, Some(next));
                }
            }
        }
    }

    /// REQ-OCSP-002: the five-minute clock-skew allowance is inclusive for
    /// both thisUpdate and nextUpdate, and one second beyond it is refused.
    #[test]
    fn freshness_skew_boundaries_are_inclusive() {
        let f = fixture();
        // Use the documented duration independently of MAX_SKEW so changing
        // the verifier's allowance cannot silently change the expected limit.
        for skew in [299, 300, 301] {
            let future = make(&f, CertStatus::Good, f.now + skew, f.now + 7200);
            let stale = make(&f, CertStatus::Good, f.now - 7200, f.now - skew);
            for (response, context) in [
                (&future, "OCSP response is from the future"),
                (&stale, "OCSP response is stale"),
            ] {
                let result = check(&f, response, f.now);
                if skew <= 300 {
                    assert_eq!(result.unwrap().status, CertStatus::Good);
                } else {
                    let e = result.unwrap_err();
                    assert_eq!(e.kind(), ErrorKind::BadCertificateStatus);
                    assert_eq!(e.context(), context);
                }
            }
        }
    }

    /// REQ-OCSP-002: without nextUpdate a response expires after four days;
    /// the limit is inclusive and does not gain the nextUpdate skew allowance.
    #[test]
    fn responses_without_next_update_have_a_bounded_age() {
        let f = fixture();
        let ca = Certificate::parse(&f.ca).unwrap();
        let leaf = Certificate::parse(&f.leaf).unwrap();
        let mut rng = ic_drbg::Rng::from_os().unwrap();
        // Independent of the verifier's constant: changing its policy must
        // fail this test rather than change the expected expiry with it.
        let four_days = 4 * 86_400;
        for age in [0, four_days - 1, four_days, four_days + 1] {
            let this_update = f.now - age;
            let response = build_signed_with_cert_id(
                OID_SHA256,
                &digest(OID_SHA256, ca.subject).unwrap(),
                &digest(OID_SHA256, spki_key_bits(ca.spki).unwrap()).unwrap(),
                leaf.serial,
                ca.subject,
                &f.ca_key,
                None,
                CertStatus::Good,
                this_update,
                None,
                &mut rng,
            )
            .unwrap();
            let result = check(&f, &response, f.now);
            if age <= four_days {
                let verified = result.unwrap();
                assert_eq!(verified.this_update, this_update);
                assert_eq!(verified.next_update, None);
                assert_eq!(verified.status, CertStatus::Good);
                assert!(verified.cert_id_hashes_checked);
            } else {
                let e = result.unwrap_err();
                assert_eq!(e.kind(), ErrorKind::BadCertificateStatus);
                assert_eq!(e.context(), "OCSP response without nextUpdate is too old");
            }
        }
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

    /// REQ-OCSP-004: the CertID must name the leaf's issuer by name as well
    /// as key. A response the real issuer signed, whose issuer name hash is
    /// wrong, does not cover the certificate.
    #[test]
    fn a_cert_id_with_another_issuer_name_does_not_count() {
        let f = fixture();
        let ca = Certificate::parse(&f.ca).unwrap();
        let leaf = Certificate::parse(&f.leaf).unwrap();
        let mut name_hash = digest(OID_SHA256, ca.subject).unwrap();
        let key_hash = digest(OID_SHA256, spki_key_bits(ca.spki).unwrap()).unwrap();
        let mut rng = ic_drbg::Rng::from_os().unwrap();
        let build = |name_hash: &[u8], rng: &mut ic_drbg::Rng| {
            build_signed_with_cert_id(
                OID_SHA256,
                name_hash,
                &key_hash,
                leaf.serial,
                ca.subject,
                &f.ca_key,
                None,
                CertStatus::Good,
                f.now - 60,
                Some(f.now + 3600),
                rng,
            )
            .unwrap()
        };
        assert!(check(&f, &build(&name_hash, &mut rng), f.now).is_ok());
        name_hash[0] ^= 1;
        assert_eq!(
            check(&f, &build(&name_hash, &mut rng), f.now)
                .unwrap_err()
                .kind(),
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
        responder_with_key_kind(f, eku, KeyKind::EcdsaP256)
    }

    fn responder_with_key_kind(
        f: &Fixture,
        eku: Option<&[u8]>,
        kind: KeyKind,
    ) -> (Vec<u8>, SigningKey) {
        let mut rng = ic_drbg::Rng::from_os().unwrap();
        let key = SigningKey::generate(kind, &mut rng).unwrap();
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

    /// REQ-OCSP-032: authentic responder certificates with unsupported algorithms
    /// or unusable key encodings cannot hide a later usable signer.
    #[test]
    fn delegated_signer_selection_skips_unusable_public_keys() {
        let f = fixture();
        let ca = Certificate::parse(&f.ca).unwrap();
        let issuer_key = ca.subject_public_key().unwrap();
        let leaf = Certificate::parse(&f.leaf).unwrap();
        let (cert, key) = responder(&f, Some(OID_KP_OCSP_SIGNING));
        let parsed = Certificate::parse(&cert).unwrap();
        let mut rng = ic_drbg::Rng::from_os().unwrap();
        let name_hash = digest(OID_SHA256, ca.subject).unwrap();
        let key_hash = digest(OID_SHA256, spki_key_bits(ca.spki).unwrap()).unwrap();
        let mut spki_fields = Der::new(parsed.spki).nested(T_SEQUENCE).unwrap();
        let supported_algorithm = spki_fields.expect_raw(T_SEQUENCE).unwrap();
        let mut unknown_algorithm = Vec::new();
        push_tlv(&mut unknown_algorithm, T_OID, &[0x2a, 3, 4]);
        let mut unknown_algorithm_der = Vec::new();
        push_tlv(&mut unknown_algorithm_der, T_SEQUENCE, &unknown_algorithm);
        for algorithm in [unknown_algorithm_der.as_slice(), supported_algorithm] {
            let mut spki_body = algorithm.to_vec();
            // Well-framed BIT STRING, but not a usable P-256 public key.
            push_tlv(&mut spki_body, T_BIT_STRING, &[0, 4, 1]);
            let mut spki = Vec::new();
            push_tlv(&mut spki, T_SEQUENCE, &spki_body);
            let mut fields = Der::new(parsed.tbs).nested(T_SEQUENCE).unwrap();
            let mut body = Vec::new();
            // Preserve version, serial, signature algorithm, issuer, validity, subject.
            for _ in 0..6 {
                let (_, _, whole) = fields.tlv().unwrap();
                body.extend_from_slice(whole);
            }
            fields.expect(T_SEQUENCE).unwrap();
            body.extend_from_slice(&spki);
            while !fields.is_empty() {
                let (_, _, whole) = fields.tlv().unwrap();
                body.extend_from_slice(whole);
            }
            let mut tbs = Vec::new();
            push_tlv(&mut tbs, T_SEQUENCE, &body);
            let scheme = parsed.signature_scheme().unwrap();
            let signature = f.ca_key.sign(scheme, &tbs, &mut rng).unwrap();
            let mut certificate_fields = Der::new(&cert).nested(T_SEQUENCE).unwrap();
            certificate_fields.expect(T_SEQUENCE).unwrap();
            let signature_algorithm = certificate_fields.expect_raw(T_SEQUENCE).unwrap();
            let mut body = tbs;
            body.extend_from_slice(signature_algorithm);
            let mut bits = alloc::vec![0];
            bits.extend_from_slice(&signature);
            push_tlv(&mut body, T_BIT_STRING, &bits);
            let mut unusable = Vec::new();
            push_tlv(&mut unusable, T_SEQUENCE, &body);
            let candidate = Certificate::parse(&unusable).unwrap();
            assert!(candidate.subject_public_key().is_err());
            sign::verify(scheme, &issuer_key, candidate.tbs, candidate.signature).unwrap();
            responder_authorized(&candidate, ca.subject, &issuer_key, f.now, ALL).unwrap();
            for status in [CertStatus::Good, CertStatus::Unknown] {
                for (candidates, accepted) in [
                    ([unusable.clone(), cert.clone()].concat(), true),
                    ([cert.clone(), unusable.clone()].concat(), true),
                    (unusable.clone(), false),
                    ([unusable.clone(), unusable.clone()].concat(), false),
                ] {
                    let response = build_signed_with_cert_id(
                        OID_SHA256,
                        &name_hash,
                        &key_hash,
                        leaf.serial,
                        parsed.subject,
                        &key,
                        Some(&candidates),
                        status,
                        f.now,
                        Some(f.now + 60),
                        &mut rng,
                    )
                    .unwrap();
                    let mut response_fields = Der::new(&response).nested(T_SEQUENCE).unwrap();
                    response_fields.expect(T_ENUMERATED).unwrap();
                    let mut wrapper = response_fields.nested(T_CTX0).unwrap();
                    let mut bytes = wrapper.nested(T_SEQUENCE).unwrap();
                    bytes.expect(T_OID).unwrap();
                    let mut basic = Der::new(bytes.expect(T_OCTET_STRING).unwrap())
                        .nested(T_SEQUENCE)
                        .unwrap();
                    let response_tbs = basic.expect_raw(T_SEQUENCE).unwrap();
                    let response_scheme =
                        scheme_from_alg(basic.expect(T_SEQUENCE).unwrap()).unwrap();
                    let response_signature =
                        whole_bits(basic.expect(T_BIT_STRING).unwrap()).unwrap();
                    sign::verify(
                        response_scheme,
                        &PublicKey::from_spki(key.spki()).unwrap(),
                        response_tbs,
                        response_signature,
                    )
                    .unwrap();
                    let result = check(&f, &response, f.now);
                    if accepted {
                        let verified = result.unwrap();
                        assert!(verified.delegated);
                        assert_eq!(verified.status, status);
                    } else {
                        let error = result.unwrap_err();
                        assert_eq!(error.kind(), ErrorKind::BadCertificateStatus);
                        assert_eq!(
                            error.context(),
                            "OCSP response is not signed by the issuer or an authorized responder"
                        );
                    }
                }
                let response = build_signed_with_cert_id(
                    OID_SHA256,
                    &name_hash,
                    &key_hash,
                    leaf.serial,
                    ca.subject,
                    &f.ca_key,
                    Some(&unusable),
                    status,
                    f.now,
                    Some(f.now + 60),
                    &mut rng,
                )
                .unwrap();
                let verified = check(&f, &response, f.now).unwrap();
                assert!(!verified.delegated);
                assert_eq!(verified.status, status);
            }
        }
    }

    /// REQ-OCSP-031: authentic delegates with unknown critical extensions are
    /// rejected; noncritical extensions and later authorized candidates still work.
    #[test]
    fn delegated_responders_refuse_unknown_critical_extensions() {
        let f = fixture();
        let ca = Certificate::parse(&f.ca).unwrap();
        let leaf = Certificate::parse(&f.leaf).unwrap();
        let issuer_key = ca.subject_public_key().unwrap();
        let mut rng = ic_drbg::Rng::from_os().unwrap();
        let key = SigningKey::generate(KeyKind::EcdsaP256, &mut rng).unwrap();
        let name_hash = digest(OID_SHA256, ca.subject).unwrap();
        let key_hash = digest(OID_SHA256, spki_key_bits(ca.spki).unwrap()).unwrap();
        let mut eku_oid = Vec::new();
        push_tlv(&mut eku_oid, T_OID, OID_KP_OCSP_SIGNING);
        let mut eku_value = Vec::new();
        push_tlv(&mut eku_value, T_SEQUENCE, &eku_oid);
        let mut eku = Vec::new();
        x509::push_ext(&mut eku, x509::OID_EXT_EKU, false, &eku_value);
        let mut valid = None;
        for critical in [false, true] {
            for unknown_first in [false, true] {
                let mut unknown = Vec::new();
                x509::push_ext(&mut unknown, &[0x2a, 3, 4], critical, &[0x05, 0]);
                let extra = if unknown_first {
                    [unknown, eku.clone()]
                } else {
                    [eku.clone(), unknown]
                };
                let cert = x509::build(
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
                    &x509::key_identifier(ca.spki).unwrap(),
                    &f.ca_key,
                    &mut rng,
                    &extra,
                )
                .unwrap();
                let parsed = Certificate::parse(&cert).unwrap();
                assert_eq!(parsed.ext.unknown_critical, critical);
                sign::verify(
                    parsed.signature_scheme().unwrap(),
                    &issuer_key,
                    parsed.tbs,
                    parsed.signature,
                )
                .unwrap();
                let authorized = responder_authorized(&parsed, ca.subject, &issuer_key, f.now, ALL);
                if critical {
                    let error = authorized.unwrap_err();
                    assert_eq!(error.kind(), ErrorKind::BadCertificateStatus);
                    assert_eq!(
                        error.context(),
                        "responder has an unknown critical extension"
                    );
                } else {
                    authorized.unwrap();
                    valid = Some(cert.clone());
                }
                for status in [CertStatus::Good, CertStatus::Unknown] {
                    let response = build_signed_with_cert_id(
                        OID_SHA256,
                        &name_hash,
                        &key_hash,
                        leaf.serial,
                        parsed.subject,
                        &key,
                        Some(&cert),
                        status,
                        f.now,
                        Some(f.now + 60),
                        &mut rng,
                    )
                    .unwrap();
                    let result = check(&f, &response, f.now);
                    if critical {
                        assert_eq!(result.unwrap_err().kind(), ErrorKind::BadCertificateStatus);
                        let valid_cert = valid.as_ref().unwrap();
                        for candidates in [
                            [cert.clone(), valid_cert.clone()].concat(),
                            [valid_cert.clone(), cert.clone()].concat(),
                        ] {
                            let response = build_signed_with_cert_id(
                                OID_SHA256,
                                &name_hash,
                                &key_hash,
                                leaf.serial,
                                parsed.subject,
                                &key,
                                Some(&candidates),
                                status,
                                f.now,
                                Some(f.now + 60),
                                &mut rng,
                            )
                            .unwrap();
                            let verified = check(&f, &response, f.now).unwrap();
                            assert!(verified.delegated);
                            assert_eq!(verified.status, status);
                        }
                        // An unneeded candidate cannot block the issuer's own response.
                        let issuer_response = build_signed_with_cert_id(
                            OID_SHA256,
                            &name_hash,
                            &key_hash,
                            leaf.serial,
                            ca.subject,
                            &f.ca_key,
                            Some(&cert),
                            status,
                            f.now,
                            Some(f.now + 60),
                            &mut rng,
                        )
                        .unwrap();
                        let verified = check(&f, &issuer_response, f.now).unwrap();
                        assert!(!verified.delegated);
                        assert_eq!(verified.status, status);
                    } else {
                        let verified = result.unwrap();
                        assert!(verified.delegated);
                        assert_eq!(verified.status, status);
                    }
                }
            }
        }
    }

    /// REQ-OCSP-017: a genuinely issuer-signed responder certificate with
    /// encipherment-only or CRL-signing-only KeyUsage cannot sign OCSP.
    #[test]
    fn delegated_responder_key_usage_must_permit_signing() {
        let f = fixture();
        let (cert, key) = responder(&f, Some(OID_KP_OCSP_SIGNING));
        let parsed = Certificate::parse(&cert).unwrap();
        let mut fields = Der::new(&cert).nested(T_SEQUENCE).unwrap();
        fields.expect(T_SEQUENCE).unwrap();
        let algorithm = fields.expect_raw(T_SEQUENCE).unwrap();
        let mut rng = ic_drbg::Rng::from_os().unwrap();
        for (unused, bits, allowed) in [(7, 0x80, true), (5, 0x20, false), (1, 0x02, false)] {
            let mut tbs = parsed.tbs.to_vec();
            let positions: Vec<_> = tbs
                .windows(4)
                .enumerate()
                .filter_map(|(i, bytes)| (bytes == [T_BIT_STRING, 2, 7, 0x80]).then_some(i))
                .collect();
            assert_eq!(positions.len(), 1);
            let position = positions[0];
            tbs[position + 2] = unused;
            tbs[position + 3] = bits;
            let signature = f
                .ca_key
                .sign(parsed.signature_scheme().unwrap(), &tbs, &mut rng)
                .unwrap();
            let mut body = tbs;
            body.extend_from_slice(algorithm);
            let mut signature_bits = alloc::vec![0];
            signature_bits.extend_from_slice(&signature);
            push_tlv(&mut body, T_BIT_STRING, &signature_bits);
            let mut altered = Vec::new();
            push_tlv(&mut altered, T_SEQUENCE, &body);
            let parsed_altered = Certificate::parse(&altered).unwrap();
            let ca = Certificate::parse(&f.ca).unwrap();
            sign::verify(
                parsed_altered.signature_scheme().unwrap(),
                &ca.subject_public_key().unwrap(),
                parsed_altered.tbs,
                parsed_altered.signature,
            )
            .unwrap();
            let response = build_signed(
                &f.leaf,
                &f.ca,
                &key,
                Some(&altered),
                CertStatus::Good,
                f.now,
                f.now + 60,
                &mut rng,
            )
            .unwrap();
            let result = check(&f, &response, f.now);
            if allowed {
                assert!(result.unwrap().delegated);
            } else {
                assert_eq!(result.unwrap_err().kind(), ErrorKind::BadCertificateStatus);
            }
        }
        // Absence of KeyUsage adds no restriction; OCSP EKU remains required.
        let mut parsed = Certificate::parse(&cert).unwrap();
        parsed.ext.key_usage = None;
        let ca = Certificate::parse(&f.ca).unwrap();
        responder_authorized(
            &parsed,
            ca.subject,
            &ca.subject_public_key().unwrap(),
            f.now,
            &[SignatureScheme::EcdsaSecp256r1Sha256],
        )
        .unwrap();
    }

    /// REQ-OCSP-029: malformed certificate list entries cannot be hidden
    /// before or after a signer, or ignored when the issuer signs directly.
    #[test]
    fn attached_certificate_lists_require_complete_sequence_entries() {
        let f = fixture();
        let ca = Certificate::parse(&f.ca).unwrap();
        let leaf = Certificate::parse(&f.leaf).unwrap();
        let (signer_cert, signer_key) = responder(&f, Some(OID_KP_OCSP_SIGNING));
        let signer_name = Certificate::parse(&signer_cert).unwrap().subject;
        let name_hash = digest(OID_SHA256, ca.subject).unwrap();
        let key_hash = digest(OID_SHA256, spki_key_bits(ca.spki).unwrap()).unwrap();
        let mut rng = ic_drbg::Rng::from_os().unwrap();
        for delegated in [false, true] {
            let (name, key) = if delegated {
                (signer_name, &signer_key)
            } else {
                (ca.subject, &f.ca_key)
            };
            let public = PublicKey::from_spki(key.spki()).unwrap();
            let build = |certs: &[u8], rng: &mut ic_drbg::Rng| {
                build_signed_with_cert_id(
                    OID_SHA256,
                    &name_hash,
                    &key_hash,
                    leaf.serial,
                    name,
                    key,
                    Some(certs),
                    CertStatus::Good,
                    f.now,
                    Some(f.now + 60),
                    rng,
                )
                .unwrap()
            };
            for (candidate, accepted) in [
                (Vec::new(), true),
                (alloc::vec![T_SEQUENCE, 0], true), // Bounded unusable candidates remain skippable.
                (f.ca.clone(), true),
                (alloc::vec![0x05, 0], false),
                (alloc::vec![T_OCTET_STRING, 0], false),
                (alloc::vec![0x31, 0], false),
                (alloc::vec![T_SEQUENCE], false),
                (alloc::vec![T_SEQUENCE, 2, 0], false),
                (alloc::vec![T_SEQUENCE, 0x81, 0], false),
                (alloc::vec![T_SEQUENCE, 0x80, 0, 0], false),
                (alloc::vec![0x3f, 0x1f, 0], false),
                (alloc::vec![0], false),
            ] {
                for certs in [
                    [candidate.clone(), signer_cert.clone()].concat(),
                    [signer_cert.clone(), candidate.clone()].concat(),
                    [signer_cert.clone(), candidate, f.ca.clone()].concat(),
                ] {
                    let response = build(&certs, &mut rng);
                    // Attachments are outside the signed ResponseData; establish
                    // independently that each fixture's response signature is valid.
                    let mut outer = Der::new(&response).nested(T_SEQUENCE).unwrap();
                    outer.expect(T_ENUMERATED).unwrap();
                    let mut bytes = Der::new(outer.expect(T_CTX0).unwrap())
                        .nested(T_SEQUENCE)
                        .unwrap();
                    bytes.expect(T_OID).unwrap();
                    let mut basic = Der::new(bytes.expect(T_OCTET_STRING).unwrap())
                        .nested(T_SEQUENCE)
                        .unwrap();
                    let tbs = basic.expect_raw(T_SEQUENCE).unwrap();
                    let scheme = scheme_from_alg(basic.expect(T_SEQUENCE).unwrap()).unwrap();
                    let signature = whole_bits(basic.expect(T_BIT_STRING).unwrap()).unwrap();
                    sign::verify(scheme, &public, tbs, signature).unwrap();
                    let result = check(&f, &response, f.now);
                    if accepted {
                        let verified = result.unwrap();
                        assert_eq!(verified.delegated, delegated);
                        assert_eq!(verified.status, CertStatus::Good);
                    } else {
                        assert_eq!(result.unwrap_err().kind(), ErrorKind::BadCertificateStatus);
                    }
                }
            }
            if !delegated {
                let verified = check(&f, &build(&[], &mut rng), f.now).unwrap();
                assert!(!verified.delegated);
            }
        }
    }

    /// REQ-OCSP-001: attached certificates are candidates, not trusted
    /// signers. Invalid candidates cannot prevent a later authorized signer
    /// from verifying, and do not authorize the response on their own.
    #[test]
    fn delegated_signer_selection_tries_later_candidates() {
        let f = fixture();
        let ca = Certificate::parse(&f.ca).unwrap();
        let leaf = Certificate::parse(&f.leaf).unwrap();
        let (signer_cert, signer_key) = responder(&f, Some(OID_KP_OCSP_SIGNING));
        let signer_name = Certificate::parse(&signer_cert).unwrap().subject;
        let (wrong_key_cert, _) = responder(&f, Some(OID_KP_OCSP_SIGNING));
        let (unauthorized_cert, _) = responder(&f, None);
        let name_hash = digest(OID_SHA256, ca.subject).unwrap();
        let key_hash = digest(OID_SHA256, spki_key_bits(ca.spki).unwrap()).unwrap();
        let mut rng = ic_drbg::Rng::from_os().unwrap();
        for (candidate, label) in [
            (alloc::vec![T_SEQUENCE, 0], "malformed certificate"),
            (unauthorized_cert, "missing OCSP signing purpose"),
            (wrong_key_cert, "authorized certificate with the wrong key"),
        ] {
            let build = |certs: &[u8], rng: &mut ic_drbg::Rng| {
                build_signed_with_cert_id(
                    OID_SHA256,
                    &name_hash,
                    &key_hash,
                    leaf.serial,
                    signer_name,
                    &signer_key,
                    Some(certs),
                    CertStatus::Good,
                    f.now,
                    Some(f.now + 60),
                    rng,
                )
                .unwrap()
            };
            assert_eq!(
                check(&f, &build(&candidate, &mut rng), f.now)
                    .unwrap_err()
                    .kind(),
                ErrorKind::BadCertificateStatus,
                "{label}",
            );
            let mut candidates = candidate;
            candidates.extend_from_slice(&signer_cert);
            let verified = check(&f, &build(&candidates, &mut rng), f.now)
                .unwrap_or_else(|e| panic!("{label}: {e}"));
            assert!(verified.delegated && verified.cert_id_hashes_checked);
            assert_eq!(verified.status, CertStatus::Good);
        }
    }

    /// REQ-OCSP-001: a valid response signature cannot compensate for an
    /// altered signature on the delegated responder's certificate.
    #[test]
    fn delegated_responder_certificate_signatures_are_verified() {
        let f = fixture();
        let (mut cert, key) = responder(&f, Some(OID_KP_OCSP_SIGNING));
        let ca = Certificate::parse(&f.ca).unwrap();
        let mut rng = ic_drbg::Rng::from_os().unwrap();
        let response = |cert: &[u8], rng: &mut ic_drbg::Rng| {
            build_signed(
                &f.leaf,
                &f.ca,
                &key,
                Some(cert),
                CertStatus::Good,
                f.now,
                f.now + 60,
                rng,
            )
            .unwrap()
        };
        assert!(
            check(&f, &response(&cert, &mut rng), f.now)
                .unwrap()
                .delegated
        );
        // Certificate's final byte belongs to the signature BIT STRING.
        let last = cert.len() - 1;
        cert[last] ^= 1;
        let parsed = Certificate::parse(&cert).unwrap();
        assert_eq!(parsed.issuer, ca.subject);
        let e = responder_authorized(
            &parsed,
            ca.subject,
            &PublicKey::from_spki(ca.spki).unwrap(),
            f.now,
            ALL,
        )
        .unwrap_err();
        assert_eq!(
            e.context(),
            "responder certificate not signed by the issuer"
        );
        let e = check(&f, &response(&cert, &mut rng), f.now).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::BadCertificateStatus);
    }

    /// REQ-OCSP-006: the policy also applies to the signature on a delegate's
    /// certificate, even when the response itself uses an allowed scheme.
    #[test]
    fn delegated_responder_certificate_schemes_must_be_allowed() {
        let f = fixture();
        let (cert, key) = responder_with_key_kind(&f, Some(OID_KP_OCSP_SIGNING), KeyKind::Ed25519);
        let mut rng = ic_drbg::Rng::from_os().unwrap();
        let response = build_signed(
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
        let ca = Certificate::parse(&f.ca).unwrap();
        let verify =
            |allowed| verify_response(&response, &f.leaf, ca.subject, ca.spki, f.now, allowed);
        // Ed25519 signs the response; ECDSA signs the responder certificate.
        assert!(
            verify(&[
                SignatureScheme::Ed25519,
                SignatureScheme::EcdsaSecp256r1Sha256
            ])
            .unwrap()
            .delegated
        );
        let e = verify(&[SignatureScheme::Ed25519]).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::BadCertificateStatus);
        let e = responder_authorized(
            &Certificate::parse(&cert).unwrap(),
            ca.subject,
            &PublicKey::from_spki(ca.spki).unwrap(),
            f.now,
            &[SignatureScheme::Ed25519],
        )
        .unwrap_err();
        assert_eq!(e.context(), "responder certificate scheme not allowed");
    }

    /// REQ-OCSP-001: a fresh, correctly signed response cannot authorize a
    /// delegate before its certificate becomes valid or after it expires.
    #[test]
    fn delegated_responders_must_be_current() {
        let f = fixture();
        let (cert, key) = responder(&f, Some(OID_KP_OCSP_SIGNING));
        let ca = Certificate::parse(&f.ca).unwrap();
        let responder = Certificate::parse(&cert).unwrap();
        let issuer_key = PublicKey::from_spki(ca.spki).unwrap();
        let mut rng = ic_drbg::Rng::from_os().unwrap();
        for (now, error) in [
            (f.now - 61, Some("certificate is not yet valid")),
            (f.now - 60, None),
            (f.now + 3600, None),
            (f.now + 3601, Some("certificate has expired")),
        ] {
            // Refresh the response at each time so its own currency cannot
            // mask a missing responder-certificate validity check.
            let response = build_signed(
                &f.leaf,
                &f.ca,
                &key,
                Some(&cert),
                CertStatus::Good,
                now,
                now + 60,
                &mut rng,
            )
            .unwrap();
            let authorized = responder_authorized(&responder, ca.subject, &issuer_key, now, ALL);
            if let Some(context) = error {
                let e = authorized.unwrap_err();
                assert_eq!(e.context(), context);
                assert_eq!(
                    check(&f, &response, now).unwrap_err().kind(),
                    ErrorKind::BadCertificateStatus,
                );
            } else {
                authorized.unwrap();
                assert!(check(&f, &response, now).unwrap().delegated);
            }
        }
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

    /// The ResponderID, producedAt and responses fields of a response's
    /// ResponseData, each as a complete TLV.
    fn response_data_fields(response: &[u8]) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let mut outer = Der::new(response);
        let mut body = outer.nested(T_SEQUENCE).unwrap();
        body.expect(T_ENUMERATED).unwrap();
        let mut bytes = Der::new(body.expect(T_CTX0).unwrap())
            .nested(T_SEQUENCE)
            .unwrap();
        bytes.expect(T_OID).unwrap();
        let mut basic = Der::new(bytes.expect(T_OCTET_STRING).unwrap())
            .nested(T_SEQUENCE)
            .unwrap();
        let mut fields = Der::new(basic.expect(T_SEQUENCE).unwrap());
        let responder = fields.tlv().unwrap().2.to_vec();
        let produced = fields.expect_raw(T_GENERALIZED_TIME).unwrap().to_vec();
        let responses = fields.expect_raw(T_SEQUENCE).unwrap().to_vec();
        fields.finish().unwrap();
        (responder, produced, responses)
    }

    fn response_data(fields: &[&[u8]]) -> Vec<u8> {
        let mut tbs = Vec::new();
        push_tlv(&mut tbs, T_SEQUENCE, &fields.concat());
        tbs
    }

    /// REQ-OCSP-007: RFC 6960 section 4.2.1 makes producedAt a
    /// GeneralizedTime; an authentic response whose producedAt is the UTCTime
    /// alternative is refused, while the same time as GeneralizedTime is
    /// accepted.
    #[test]
    fn produced_at_requires_generalized_time() {
        let f = fixture();
        let mut rng = ic_drbg::Rng::from_os().unwrap();
        let good = make(&f, CertStatus::Good, f.now, f.now + 60);
        let (responder, produced, responses) = response_data_fields(&good);
        let mut generalized = Der::new(&produced);
        let time = generalized.expect(T_GENERALIZED_TIME).unwrap();
        let mut utc = Vec::new();
        push_tlv(&mut utc, super::super::T_UTC_TIME, &time[2..]);
        assert_eq!(
            parse_time(super::super::T_UTC_TIME, &time[2..]).unwrap(),
            f.now
        );
        let control = sign_response(
            response_data(&[&responder, &produced, &responses]),
            &f.ca_key,
            None,
            &mut rng,
        )
        .unwrap();
        assert_eq!(check(&f, &control, f.now).unwrap().status, CertStatus::Good);
        let signed = sign_response(
            response_data(&[&responder, &utc, &responses]),
            &f.ca_key,
            None,
            &mut rng,
        )
        .unwrap();
        let e = check(&f, &signed, f.now).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::BadCertificateStatus);
        assert_eq!(e.context(), "producedAt is not GeneralizedTime");
    }

    /// REQ-OCSP-007: RFC 6960 section 4.2.1 makes a SingleResponse's
    /// thisUpdate a GeneralizedTime; the UTCTime alternative is refused.
    #[test]
    fn single_response_this_update_requires_generalized_time() {
        let f = fixture();
        let mut encoded = Vec::new();
        generalized_time(&mut encoded, f.now).unwrap();
        let mut time_der = Der::new(&encoded);
        let time = time_der.expect(T_GENERALIZED_TIME).unwrap();
        for tag in [T_GENERALIZED_TIME, super::super::T_UTC_TIME] {
            let mut cert_id = hash_alg_id(OID_SHA256);
            push_tlv(&mut cert_id, T_OCTET_STRING, &[0; 32]);
            push_tlv(&mut cert_id, T_OCTET_STRING, &[0; 32]);
            push_tlv(&mut cert_id, T_INTEGER, &[1]);
            let mut body = Vec::new();
            push_tlv(&mut body, T_SEQUENCE, &cert_id);
            push_tlv(&mut body, T_GOOD, &[]);
            push_tlv(
                &mut body,
                tag,
                if tag == T_GENERALIZED_TIME {
                    time
                } else {
                    &time[2..]
                },
            );
            match parse_single(&body) {
                Ok(single) => {
                    assert_eq!(tag, T_GENERALIZED_TIME);
                    assert_eq!(single.this_update, f.now);
                }
                Err(e) => {
                    assert_eq!(tag, super::super::T_UTC_TIME);
                    assert_eq!(e.kind(), ErrorKind::BadCertificateStatus);
                    assert_eq!(e.context(), "thisUpdate is not GeneralizedTime");
                }
            }
        }
    }

    /// REQ-OCSP-001, REQ-OCSP-015: a delegated responder may identify itself
    /// by key hash rather than by name; its attached certificate is then
    /// considered whatever its subject, and still must be authorized by the
    /// issuer. The hash below is synthetic: this verifier does not match it
    /// against the key (IronCrypto has no SHA-1), only its encoding.
    #[test]
    fn delegated_responders_may_be_identified_by_key() {
        let f = fixture();
        let mut rng = ic_drbg::Rng::from_os().unwrap();
        let mut by_key = Vec::new();
        let mut hash = Vec::new();
        push_tlv(&mut hash, T_OCTET_STRING, &[0x5a; 20]);
        push_tlv(&mut by_key, T_CTX2, &hash);
        for (eku, accepted) in [(Some(OID_KP_OCSP_SIGNING), true), (None, false)] {
            let (cert, key) = responder(&f, eku);
            let by_name = build_signed(
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
            let (_, produced, responses) = response_data_fields(&by_name);
            let signed = sign_response(
                response_data(&[&by_key, &produced, &responses]),
                &key,
                Some(&cert),
                &mut rng,
            )
            .unwrap();
            let result = check(&f, &signed, f.now);
            if accepted {
                let v = result.unwrap();
                assert!(v.delegated);
                assert_eq!(v.status, CertStatus::Good);
            } else {
                let e = result.unwrap_err();
                assert_eq!(e.kind(), ErrorKind::BadCertificateStatus);
                assert_eq!(
                    e.context(),
                    "OCSP response is not signed by the issuer or an authorized responder"
                );
            }
        }
    }

    /// REQ-OCSP-022: issuance refuses an issuer certificate that did not
    /// issue the leaf (the leaf's issuer Name differs), before any signing.
    #[test]
    fn ocsp_issuance_requires_the_leafs_issuer() {
        let f = fixture();
        let (ca, key) = other_ca(&f, "Another CA");
        let mut rng = ic_drbg::Rng::from_os().unwrap();
        let e = build_response(
            &f.leaf,
            &ca,
            &key,
            CertStatus::Good,
            f.now,
            f.now + 60,
            &mut rng,
        )
        .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::InvalidConfig);
        assert_eq!(e.context(), "issuer does not match the certificate");
    }
}
