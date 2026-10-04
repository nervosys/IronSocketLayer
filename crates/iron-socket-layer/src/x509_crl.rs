//! Certificate revocation lists (RFC 5280 §5).
//!
//! IronSocketLayer does not fetch CRLs: the caller loads them into a
//! [`CrlStore`] (from a private CA's distribution point, a file, an agent
//! fleet's control plane) and path validation consults it. [`build`] issues
//! one, so the operator of a private CA can revoke an identity — a
//! compromised agent's, say — and have every IronSocketLayer peer refuse it.
//!
//! # Rules
//!
//! * A CRL counts only if its issuer name is the certificate's issuer and the
//!   issuer's key signed it; if the issuer certificate carries key usage, it
//!   must include `cRLSign`. `REQ-CRL-001`.
//! * A serial listed in any authentic CRL is revoked, stale CRL or not:
//!   revocation is permanent. Every certificate on the path is checked, not
//!   only the leaf. `REQ-CRL-002`.
//! * Only a *current* authentic CRL (`thisUpdate` not in the future,
//!   `nextUpdate` not passed, five minutes of skew; without `nextUpdate`,
//!   seven days) shows a certificate is good. With `require_crl`, a
//!   certificate lacking one fails. `REQ-CRL-003`.
//! * Delta CRLs, CRLs with an issuing-distribution-point scope, indirect
//!   CRLs and unknown critical extensions are not implemented; such a CRL is
//!   never used to show a certificate is good. `REQ-CRL-004`.

use alloc::vec::Vec;

use ic_core::traits::RandomSource;

use super::{
    alg_id, check_algorithm_identifier_encoding, check_authority_issuer_names, check_oid_encoding,
    check_rdn_sequence, check_relative_distinguished_name, encode_time,
    parse_authority_key_identifier, parse_time, push_tlv, scheme_from_alg, whole_bits, Certificate,
    Der, KU_CRL_SIGN, T_BIT_STRING, T_BOOLEAN, T_CTX0, T_INTEGER, T_OCTET_STRING, T_OID,
    T_SEQUENCE,
};
use crate::crypto::sign::{self, PublicKey, SigningKey};
use crate::enums::SignatureScheme;
use crate::error::{Error, ErrorKind, Result};

const OID_CRL_NUMBER: &[u8] = &[0x55, 0x1d, 0x14];
const OID_REASON_CODE: &[u8] = &[0x55, 0x1d, 0x15];
const OID_INVALIDITY_DATE: &[u8] = &[0x55, 0x1d, 0x18];
const OID_AKI: &[u8] = &[0x55, 0x1d, 0x23];
const OID_DELTA_CRL: &[u8] = &[0x55, 0x1d, 0x1b];
const OID_IDP: &[u8] = &[0x55, 0x1d, 0x1c];
const OID_CERT_ISSUER: &[u8] = &[0x55, 0x1d, 0x1d];

/// Clock skew tolerated on `thisUpdate` and `nextUpdate`.
pub const MAX_SKEW: u64 = 300;
/// How long a CRL without `nextUpdate` counts as current.
pub const MAX_AGE_WITHOUT_NEXT_UPDATE: u64 = 7 * 86_400;

fn bad(ctx: &'static str) -> Error {
    Error::new(ErrorKind::BadCertificateStatus, ctx)
}

#[derive(Debug, Clone)]
struct ParsedCrl {
    issuer: Vec<u8>,
    tbs: Vec<u8>,
    sig_alg: Vec<u8>,
    signature: Vec<u8>,
    this_update: u64,
    next_update: Option<u64>,
    revoked: Vec<Vec<u8>>,
    /// Why this CRL cannot show a certificate is good, if it cannot.
    unsupported: Option<&'static str>,
}

/// REQ-CRL-009: revoked serials are nonempty, minimally encoded DER INTEGERs.
fn check_serial(serial: &[u8]) -> Result<()> {
    if serial.is_empty() {
        return Err(bad("empty revoked serial number"));
    }
    if let [first, second, ..] = serial {
        if (*first == 0 && second & 0x80 == 0) || (*first == 0xff && second & 0x80 != 0) {
            return Err(bad("nonminimal revoked serial number"));
        }
    }
    Ok(())
}

/// REQ-CRL-018, REQ-CRL-022: CRLNumber and BaseCRLNumber contain one
/// complete, minimally encoded nonnegative INTEGER, without a machine-size limit.
fn check_crl_number(value: &[u8]) -> Result<()> {
    let mut number_der = Der::new(value);
    let number = number_der.expect(T_INTEGER)?;
    check_serial(number)?;
    if number.first().is_some_and(|first| first & 0x80 != 0) {
        return Err(bad("negative CRL number"));
    }
    number_der.finish()
}

/// REQ-CRL-024: issuingDistributionPoint contains one complete sequence of
/// ordered, unique defined fields, canonical BOOLEANs and at most one true
/// certificate-kind scope flag.
fn check_issuing_distribution_point_fields(value: &[u8]) -> Result<()> {
    let mut wrapper = Der::new(value);
    let mut fields = wrapper.nested(T_SEQUENCE)?;
    wrapper.finish()?;
    let mut last_field = None;
    let mut certificate_scope = false;
    while !fields.is_empty() {
        let (tag, value, _) = fields.tlv()?;
        if !matches!(tag, T_CTX0 | 0x81..=0x85) {
            return Err(bad("invalid issuingDistributionPoint field tag"));
        }
        let field = tag & 0x1f;
        if last_field.is_some_and(|last| field <= last) {
            return Err(bad("duplicate or misplaced issuingDistributionPoint field"));
        }
        last_field = Some(field);
        if tag == T_CTX0 {
            check_distribution_point_name(value)?;
        }
        if tag == 0x83 {
            check_reason_flags(value)?;
        }
        if matches!(tag, 0x81 | 0x82 | 0x84 | 0x85) {
            let enabled = match value {
                [0] => false,
                [0xff] => true,
                _ => return Err(bad("malformed issuingDistributionPoint BOOLEAN")),
            };
            if enabled && tag != 0x84 {
                if certificate_scope {
                    return Err(bad(
                        "conflicting issuingDistributionPoint certificate scopes",
                    ));
                }
                certificate_scope = true;
            }
        }
    }
    Ok(())
}

/// REQ-CRL-025: distributionPoint wraps exactly one defined name choice:
/// fullName uses shared GeneralNames validation and relative names use shared RDN checks.
fn check_distribution_point_name(body: &[u8]) -> Result<()> {
    let mut choice = Der::new(body);
    let (tag, value, _) = choice.tlv()?;
    match tag {
        T_CTX0 => check_authority_issuer_names(value)?,
        0xa1 => check_relative_distinguished_name(value)?,
        _ => return Err(bad("invalid distributionPoint name choice")),
    }
    choice.finish()
}

/// REQ-CRL-026: onlySomeReasons uses a canonical DER named BIT STRING: an
/// unused-bit count in 0..=7, zero padding and no trailing zero named bits.
/// The canonical empty string and unknown bit positions remain structurally valid.
fn check_reason_flags(body: &[u8]) -> Result<()> {
    let (unused, bytes) = body
        .split_first()
        .ok_or(bad("empty ReasonFlags encoding"))?;
    if *unused > 7 {
        return Err(bad("invalid ReasonFlags unused-bit count"));
    }
    match bytes.last() {
        None if *unused != 0 => Err(bad("ReasonFlags padding without bits")),
        Some(last) if last.trailing_zeros() != u32::from(*unused) => Err(bad(
            "noncanonical ReasonFlags padding or trailing zero bits",
        )),
        _ => Ok(()),
    }
}

/// Is an extensions block acceptable, and does it narrow the CRL's scope?
/// REQ-CRL-005: extension critical flags use a complete DER BOOLEAN encoding.
/// REQ-CRL-006: extension wrappers are fully consumed, nonempty, and contain unique OIDs.
/// REQ-CRL-016: extension identifiers use complete, minimal OBJECT IDENTIFIER encodings.
/// REQ-CRL-018: CRL numbers contain one complete nonnegative minimal INTEGER.
/// REQ-CRL-019: entry reason codes contain one canonical defined ENUMERATED value.
/// REQ-CRL-020: entry invalidity dates contain exactly one valid GeneralizedTime.
/// REQ-CRL-021: CRL AKI fields use the shared certificate structural validation.
/// REQ-CRL-022: delta CRL indicators validate BaseCRLNumber before being marked unsupported.
/// REQ-CRL-023: certificateIssuer wraps one nonempty GeneralNames list with shared issuer-name checks.
fn scan_extensions(body: &[u8], entry: bool) -> Result<Option<&'static str>> {
    let mut wrapper = Der::new(body);
    let mut list = wrapper.nested(T_SEQUENCE)?;
    wrapper.finish()?;
    if list.is_empty() {
        return Err(bad("empty CRL extensions"));
    }
    let mut seen = Vec::new();
    let mut unsupported = None;
    while !list.is_empty() {
        let mut e = list.nested(T_SEQUENCE)?;
        let oid = e.expect(T_OID)?;
        check_oid_encoding(oid)?;
        if seen.contains(&oid) {
            return Err(bad("duplicate CRL extension"));
        }
        seen.push(oid);
        let critical = match e.optional(T_BOOLEAN)? {
            None | Some([0]) => false,
            Some([0xff]) => true,
            _ => return Err(bad("malformed CRL extension critical flag")),
        };
        let value = e.expect(T_OCTET_STRING)?;
        e.finish()?;
        match (entry, oid) {
            (false, OID_CRL_NUMBER) => {
                check_crl_number(value)?;
            }
            (true, OID_REASON_CODE) => {
                let mut reason_der = Der::new(value);
                if !matches!(reason_der.expect(0x0a)?, [0..=6] | [8..=10]) {
                    return Err(bad("invalid CRL reason code"));
                }
                reason_der.finish()?;
            }
            (true, OID_INVALIDITY_DATE) => {
                let mut date_der = Der::new(value);
                let (tag, date, _) = date_der.tlv()?;
                if tag != 0x18 {
                    return Err(bad("invalidityDate is not GeneralizedTime"));
                }
                parse_time(tag, date)?;
                date_der.finish()?;
            }
            (false, OID_AKI) => {
                parse_authority_key_identifier(value)?;
            }
            (false, OID_DELTA_CRL) => {
                check_crl_number(value)?;
                unsupported = Some("delta CRLs are not supported");
            }
            (false, OID_IDP) => {
                check_issuing_distribution_point_fields(value)?;
                unsupported = Some("partitioned CRLs (issuingDistributionPoint) are not supported")
            }
            (true, OID_CERT_ISSUER) => {
                let mut issuer_der = Der::new(value);
                check_authority_issuer_names(issuer_der.expect(T_SEQUENCE)?)?;
                issuer_der.finish()?;
                unsupported = Some("indirect CRLs are not supported");
            }
            _ if critical => unsupported = Some("unknown critical CRL extension"),
            _ => {}
        }
    }
    Ok(unsupported)
}

/// REQ-CRL-007: optional TBSCertList fields occur once and in ASN.1 order.
/// REQ-CRL-008: CRL and revoked-entry extensions require explicit version 2.
/// REQ-CRL-012: the issuer Name contains at least one distinguished-name element.
/// REQ-CRL-015: issuer RDNs and attributes use the shared Name and DER-order checks.
/// REQ-CRL-017: matching signature identifiers have a valid OID and at most one parameter.
fn parse(der: &[u8]) -> Result<ParsedCrl> {
    let wrap = |e: Error| {
        if e.kind() == ErrorKind::BadCertificate {
            bad(e.context())
        } else {
            e
        }
    };
    let mut outer = Der::new(der);
    let mut list = outer.nested(T_SEQUENCE).map_err(wrap)?;
    outer.finish().map_err(wrap)?;
    let tbs = list.expect_raw(T_SEQUENCE).map_err(wrap)?;
    let sig_alg = list.expect(T_SEQUENCE).map_err(wrap)?;
    let signature = whole_bits(list.expect(T_BIT_STRING).map_err(wrap)?).map_err(wrap)?;
    list.finish().map_err(wrap)?;

    let mut t = Der::new(tbs).nested(T_SEQUENCE).map_err(wrap)?;
    let version_two = t.peek() == Some(T_INTEGER);
    if version_two {
        let v = t.expect(T_INTEGER).map_err(wrap)?;
        if v != [1] {
            return Err(bad("unknown CRL version"));
        }
    }
    let inner_alg = t.expect(T_SEQUENCE).map_err(wrap)?;
    if inner_alg != sig_alg {
        return Err(bad(
            "signature algorithm differs between TBSCertList and CRL",
        ));
    }
    check_algorithm_identifier_encoding(sig_alg).map_err(wrap)?;
    let issuer = t.expect_raw(T_SEQUENCE).map_err(wrap)?;
    let issuer_body = Der::new(issuer).expect(T_SEQUENCE).map_err(wrap)?;
    if issuer_body.is_empty() {
        return Err(bad("empty CRL issuer name"));
    }
    check_rdn_sequence(issuer_body).map_err(wrap)?;
    let (tag, v, _) = t.tlv().map_err(wrap)?;
    let this_update = parse_time(tag, v).map_err(wrap)?;
    let mut next_update = None;
    let mut revoked = Vec::new();
    let mut unsupported = None;
    let mut last_field = 0;
    while !t.is_empty() {
        let (tag, v, _) = t.tlv().map_err(wrap)?;
        let field = match tag {
            0x17 | 0x18 => 1,
            T_SEQUENCE => 2,
            T_CTX0 => 3,
            _ => return Err(bad("unexpected field in TBSCertList")),
        };
        if field <= last_field {
            return Err(bad("duplicate or misplaced TBSCertList field"));
        }
        last_field = field;
        match tag {
            0x17 | 0x18 if next_update.is_none() && revoked.is_empty() => {
                next_update = Some(parse_time(tag, v).map_err(wrap)?);
            }
            T_SEQUENCE => {
                let mut entries = Der::new(v);
                while !entries.is_empty() {
                    let mut entry = entries.nested(T_SEQUENCE).map_err(wrap)?;
                    let serial = entry.expect(T_INTEGER).map_err(wrap)?;
                    check_serial(serial)?;
                    let (tt, tv, _) = entry.tlv().map_err(wrap)?;
                    parse_time(tt, tv).map_err(wrap)?;
                    if !entry.is_empty() {
                        if !version_two {
                            return Err(bad("CRL entry extensions require version 2"));
                        }
                        let (et, ev, ewhole) = entry.tlv().map_err(wrap)?;
                        if et != T_SEQUENCE {
                            return Err(bad("malformed CRL entry extensions"));
                        }
                        let _ = ev;
                        if let Some(u) = scan_extensions(ewhole, true).map_err(wrap)? {
                            unsupported = Some(u);
                        }
                    }
                    entry.finish().map_err(wrap)?;
                    revoked.push(serial.to_vec());
                }
            }
            T_CTX0 => {
                if !version_two {
                    return Err(bad("CRL extensions require version 2"));
                }
                if let Some(u) = scan_extensions(v, false).map_err(wrap)? {
                    unsupported = Some(u);
                }
            }
            _ => return Err(bad("unexpected field in TBSCertList")),
        }
    }
    Ok(ParsedCrl {
        issuer: issuer.to_vec(),
        tbs: tbs.to_vec(),
        sig_alg: sig_alg.to_vec(),
        signature: signature.to_vec(),
        this_update,
        next_update,
        revoked,
        unsupported,
    })
}

/// CRLs the caller has obtained, consulted during path validation.
#[derive(Debug, Clone, Default)]
pub struct CrlStore {
    crls: Vec<ParsedCrl>,
}

impl CrlStore {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a DER `CertificateList`. Its structure is checked now; its
    /// signature when a certificate is checked against it, since only then is
    /// the issuer known.
    pub fn add_der(&mut self, der: &[u8]) -> Result<()> {
        self.crls.push(parse(der)?);
        Ok(())
    }

    /// Add every `X509 CRL` block in a PEM text; returns how many.
    pub fn add_pem(&mut self, text: &str) -> Result<usize> {
        const BEGIN: &str = "-----BEGIN X509 CRL-----";
        const END: &str = "-----END X509 CRL-----";
        let mut n = 0;
        let mut rest = text;
        while let Some(start) = rest.find(BEGIN) {
            let after = &rest[start..];
            let stop = after.find(END).ok_or(bad("unterminated PEM CRL"))? + END.len();
            let block = &after[..stop];
            let mut der = alloc::vec![0u8; block.len()];
            let len = ic_pkix::pem::decode("X509 CRL", block.as_bytes(), &mut der)
                .map_err(|_| bad("PEM CRL"))?;
            self.add_der(&der[..len])?;
            n += 1;
            rest = &after[stop..];
        }
        if n == 0 {
            return Err(Error::new(ErrorKind::InvalidConfig, "no X509 CRL blocks"));
        }
        Ok(n)
    }

    /// CRLs held.
    pub fn len(&self) -> usize {
        self.crls.len()
    }

    /// Whether empty.
    pub fn is_empty(&self) -> bool {
        self.crls.is_empty()
    }
}

/// Check `cert` against the store. Returns whether a current, authentic,
/// full-scope CRL showed it good. `REQ-CRL-001..004`.
/// REQ-CRL-014: a reversed update interval cannot show a certificate good;
/// an authentic listing still establishes revocation.
pub(super) fn check(
    cert: &Certificate<'_>,
    issuer_subject: &[u8],
    issuer_spki: &[u8],
    issuer_key_usage: Option<u16>,
    store: &CrlStore,
    now: u64,
    allowed: &[SignatureScheme],
) -> Result<bool> {
    // REQ-CRL-001.
    if let Some(ku) = issuer_key_usage {
        if ku & KU_CRL_SIGN == 0 {
            return Ok(false);
        }
    }
    let key = PublicKey::from_spki(issuer_spki)?;
    let mut good = false;
    for crl in store
        .crls
        .iter()
        .filter(|c| c.issuer == issuer_subject && c.issuer == cert.issuer)
    {
        let Ok(scheme) = scheme_from_alg(&crl.sig_alg) else {
            continue;
        };
        if !allowed.contains(&scheme)
            || sign::verify(scheme, &key, &crl.tbs, &crl.signature).is_err()
        {
            continue;
        }
        // REQ-CRL-002: listed in an authentic CRL is revoked, stale or not.
        if crl.revoked.iter().any(|s| s.as_slice() == cert.serial()) {
            return Err(Error::new(
                ErrorKind::CertificateRevoked,
                "certificate is listed in its issuer's CRL",
            ));
        }
        // REQ-CRL-003, REQ-CRL-004.
        let current = crl.this_update <= now.saturating_add(MAX_SKEW)
            && match crl.next_update {
                Some(n) => n >= crl.this_update && now <= n.saturating_add(MAX_SKEW),
                None => now <= crl.this_update.saturating_add(MAX_AGE_WITHOUT_NEXT_UPDATE),
            };
        if current && crl.unsupported.is_none() {
            good = true;
        }
    }
    Ok(good)
}

/// Issue a CRL (v2, with a CRL number) revoking `revoked` serials (DER
/// INTEGER content octets, as [`Certificate::serial`] returns them).
/// REQ-CRL-010: issuance refuses nextUpdate earlier than thisUpdate.
/// REQ-CRL-011: the signing key matches the issuer certificate.
/// REQ-CRL-013: issuance requires a nonempty issuer certificate subject Name.
pub fn build(
    issuer_cert_der: &[u8],
    issuer_key: &SigningKey,
    revoked: &[(&[u8], u64)],
    this_update: u64,
    next_update: u64,
    crl_number: u64,
    rng: &mut dyn RandomSource,
) -> Result<Vec<u8>> {
    if next_update < this_update {
        return Err(Error::new(
            ErrorKind::InvalidConfig,
            "CRL nextUpdate precedes thisUpdate",
        ));
    }
    let issuer = Certificate::parse(issuer_cert_der)?;
    if Der::new(issuer.subject).expect(T_SEQUENCE)?.is_empty() {
        return Err(Error::new(
            ErrorKind::InvalidConfig,
            "CRL issuer certificate subject name is empty",
        ));
    }
    if issuer.spki != issuer_key.spki() {
        return Err(Error::new(
            ErrorKind::InvalidConfig,
            "issuer key does not match the issuer certificate",
        ));
    }
    let scheme = *issuer_key
        .schemes()
        .first()
        .ok_or(Error::new(ErrorKind::InvalidConfig, "key"))?;
    let alg = alg_id(scheme)?;
    let mut tbs = Vec::new();
    push_tlv(&mut tbs, T_INTEGER, &[1]);
    tbs.extend_from_slice(&alg);
    tbs.extend_from_slice(issuer.subject);
    encode_time(&mut tbs, this_update)?;
    encode_time(&mut tbs, next_update)?;
    if !revoked.is_empty() {
        let mut entries = Vec::new();
        for (serial, when) in revoked {
            check_serial(serial)?;
            let mut e = Vec::new();
            push_tlv(&mut e, T_INTEGER, serial);
            encode_time(&mut e, *when)?;
            push_tlv(&mut entries, T_SEQUENCE, &e);
        }
        push_tlv(&mut tbs, T_SEQUENCE, &entries);
    }
    let n = crl_number.to_be_bytes();
    let first = n.iter().position(|b| *b != 0).unwrap_or(7);
    let mut num = Vec::new();
    if n[first] & 0x80 != 0 {
        num.push(0);
    }
    num.extend_from_slice(&n[first..]);
    let mut int = Vec::new();
    push_tlv(&mut int, T_INTEGER, &num);
    let mut ext = Vec::new();
    push_tlv(&mut ext, T_OID, OID_CRL_NUMBER);
    push_tlv(&mut ext, T_OCTET_STRING, &int);
    let mut one = Vec::new();
    push_tlv(&mut one, T_SEQUENCE, &ext);
    let mut exts = Vec::new();
    push_tlv(&mut exts, T_SEQUENCE, &one);
    push_tlv(&mut tbs, T_CTX0, &exts);
    let mut tbs_seq = Vec::new();
    push_tlv(&mut tbs_seq, T_SEQUENCE, &tbs);

    let signature = issuer_key.sign(scheme, &tbs_seq, rng)?;
    let mut body = tbs_seq;
    body.extend_from_slice(&alg);
    let mut bits = alloc::vec![0u8];
    bits.extend_from_slice(&signature);
    push_tlv(&mut body, T_BIT_STRING, &bits);
    let mut out = Vec::new();
    push_tlv(&mut out, T_SEQUENCE, &body);
    Ok(out)
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use crate::crypto::sign::KeyKind;
    use crate::x509::{self, CertificateParams, Usage};

    struct Fx {
        ca: Vec<u8>,
        ca_key: SigningKey,
        leaf: Vec<u8>,
        now: u64,
    }

    fn fx() -> Fx {
        let mut rng = ic_drbg::Rng::from_os().unwrap();
        let now = 1_800_000_000;
        let ca_key = SigningKey::generate(KeyKind::EcdsaP384, &mut rng).unwrap();
        let ca = x509::self_signed(
            &CertificateParams {
                subject_cn: "CRL CA",
                dns_names: &[],
                ip_addresses: &[],
                not_before: now - 86_400,
                not_after: now + 86_400 * 30,
                is_ca: true,
                path_len: Some(0),
                usage: &[],
                serial: [8; 16],
            },
            &ca_key,
            &mut rng,
        )
        .unwrap();
        let key = SigningKey::generate(KeyKind::EcdsaP256, &mut rng).unwrap();
        let leaf = x509::issue(
            &CertificateParams {
                subject_cn: "agent-1",
                dns_names: &["agent-1.test"],
                ip_addresses: &[],
                not_before: now - 60,
                not_after: now + 86_400,
                is_ca: false,
                path_len: None,
                usage: &[Usage::ClientAuth],
                serial: [3; 16],
            },
            key.spki(),
            &ca,
            &ca_key,
            &mut rng,
        )
        .unwrap();
        Fx {
            ca,
            ca_key,
            leaf,
            now,
        }
    }

    fn run(f: &Fx, crl: &[u8], now: u64) -> Result<bool> {
        let mut store = CrlStore::new();
        store.add_der(crl)?;
        let ca = Certificate::parse(&f.ca).unwrap();
        let leaf = Certificate::parse(&f.leaf).unwrap();
        check(
            &leaf,
            ca.subject,
            ca.spki,
            ca.ext.key_usage,
            &store,
            now,
            crate::crypto::sign::VERIFY_SCHEMES,
        )
    }

    fn make(f: &Fx, revoked: &[(&[u8], u64)], this: u64, next: u64) -> Vec<u8> {
        build(
            &f.ca,
            &f.ca_key,
            revoked,
            this,
            next,
            1,
            &mut ic_drbg::Rng::from_os().unwrap(),
        )
        .unwrap()
    }

    /// REQ-CRL-002, REQ-CRL-003.
    #[test]
    fn listed_is_revoked_and_unlisted_is_good_while_current() {
        let f = fx();
        let serial = Certificate::parse(&f.leaf).unwrap().serial().to_vec();
        assert!(run(&f, &make(&f, &[], f.now - 60, f.now + 3600), f.now).unwrap());
        let crl = make(&f, &[(&serial, f.now - 30)], f.now - 60, f.now + 3600);
        assert_eq!(
            run(&f, &crl, f.now).unwrap_err().kind(),
            ErrorKind::CertificateRevoked
        );
        // Stale: no longer shows good, but a listed serial is still revoked.
        let stale = make(&f, &[], f.now - 7200, f.now - 3600);
        assert!(!run(&f, &stale, f.now).unwrap());
        let stale_listing = make(&f, &[(&serial, f.now - 9000)], f.now - 7200, f.now - 3600);
        assert_eq!(
            run(&f, &stale_listing, f.now).unwrap_err().kind(),
            ErrorKind::CertificateRevoked
        );
        let future = make(&f, &[], f.now + 3600, f.now + 7200);
        assert!(!run(&f, &future, f.now).unwrap());
    }

    /// REQ-CRL-003: five-minute skew is inclusive at both update boundaries.
    #[test]
    fn crl_freshness_skew_boundaries_are_inclusive() {
        let f = fx();
        for offset in [299, 300, 301] {
            let future = make(&f, &[], f.now + offset, f.now + 3600);
            assert_eq!(run(&f, &future, f.now).unwrap(), offset <= 300);
            let expired = make(&f, &[], f.now - 3600, f.now - offset);
            assert_eq!(run(&f, &expired, f.now).unwrap(), offset <= 300);
        }
    }

    #[test]
    fn reversed_update_intervals_cannot_establish_good_standing() {
        let f = fx();
        let serial = Certificate::parse(&f.leaf).unwrap().serial().to_vec();
        for next in [f.now - 1, f.now, f.now + 1] {
            for listed in [false, true] {
                let revoked = if listed {
                    alloc::vec![(serial.as_slice(), f.now - 30)]
                } else {
                    Vec::new()
                };
                let original = make(&f, &revoked, f.now, f.now + 60);
                let mut outer = Der::new(&original).nested(T_SEQUENCE).unwrap();
                let raw_tbs = outer.expect_raw(T_SEQUENCE).unwrap();
                let alg = outer.expect_raw(T_SEQUENCE).unwrap();
                let mut fields = Der::new(raw_tbs).nested(T_SEQUENCE).unwrap();
                let mut body = Vec::new();
                for _ in 0..4 {
                    body.extend_from_slice(fields.tlv().unwrap().2);
                }
                // Replace nextUpdate independently of the public issuance guard.
                fields.tlv().unwrap();
                encode_time(&mut body, next).unwrap();
                while !fields.is_empty() {
                    body.extend_from_slice(fields.tlv().unwrap().2);
                }
                let mut tbs = Vec::new();
                push_tlv(&mut tbs, T_SEQUENCE, &body);
                let mut rng = ic_drbg::Rng::from_os().unwrap();
                let scheme = f.ca_key.schemes()[0];
                let signature = f.ca_key.sign(scheme, &tbs, &mut rng).unwrap();
                let mut signed = tbs;
                signed.extend_from_slice(alg);
                let mut bits = alloc::vec![0];
                bits.extend_from_slice(&signature);
                push_tlv(&mut signed, T_BIT_STRING, &bits);
                let mut der = Vec::new();
                push_tlv(&mut der, T_SEQUENCE, &signed);
                let crl = parse(&der).unwrap();
                assert_eq!(crl.this_update, f.now);
                assert_eq!(crl.next_update, Some(next));
                let public_key = PublicKey::from_spki(f.ca_key.spki()).unwrap();
                sign::verify(scheme, &public_key, &crl.tbs, &crl.signature).unwrap();
                if listed {
                    assert_eq!(
                        run(&f, &der, f.now).unwrap_err().kind(),
                        ErrorKind::CertificateRevoked
                    );
                } else {
                    assert_eq!(run(&f, &der, f.now).unwrap(), next >= f.now);
                }
            }
        }
    }

    /// REQ-CRL-002, REQ-CRL-003: absent nextUpdate has a seven-day age limit;
    /// a listed certificate remains revoked after that limit.
    #[test]
    fn crls_without_next_update_have_a_bounded_age() {
        let f = fx();
        let serial = Certificate::parse(&f.leaf).unwrap().serial().to_vec();
        let age_limit = 7 * 86_400;
        for age in [age_limit - 1, age_limit, age_limit + 1] {
            for listed in [false, true] {
                let revoked = if listed {
                    alloc::vec![(serial.as_slice(), f.now - age)]
                } else {
                    Vec::new()
                };
                let original = make(&f, &revoked, f.now - age, f.now + 60);
                let mut outer = Der::new(&original).nested(T_SEQUENCE).unwrap();
                let raw_tbs = outer.expect_raw(T_SEQUENCE).unwrap();
                let alg = outer.expect_raw(T_SEQUENCE).unwrap();
                let mut fields = Der::new(raw_tbs).nested(T_SEQUENCE).unwrap();
                let mut body = Vec::new();
                for _ in 0..4 {
                    body.extend_from_slice(fields.tlv().unwrap().2);
                }
                fields.tlv().unwrap(); // Remove nextUpdate before re-signing.
                while !fields.is_empty() {
                    body.extend_from_slice(fields.tlv().unwrap().2);
                }
                let mut tbs = Vec::new();
                push_tlv(&mut tbs, T_SEQUENCE, &body);
                let scheme = f.ca_key.schemes()[0];
                let mut rng = ic_drbg::Rng::from_os().unwrap();
                let signature = f.ca_key.sign(scheme, &tbs, &mut rng).unwrap();
                let mut signed = tbs;
                signed.extend_from_slice(alg);
                let mut bits = alloc::vec![0];
                bits.extend_from_slice(&signature);
                push_tlv(&mut signed, T_BIT_STRING, &bits);
                let mut der = Vec::new();
                push_tlv(&mut der, T_SEQUENCE, &signed);
                assert!(parse(&der).unwrap().next_update.is_none());
                if listed {
                    assert_eq!(
                        run(&f, &der, f.now).unwrap_err().kind(),
                        ErrorKind::CertificateRevoked
                    );
                } else {
                    assert_eq!(run(&f, &der, f.now).unwrap(), age <= age_limit);
                }
            }
        }
    }

    /// REQ-CRL-001: a present issuer KeyUsage must permit cRLSign.
    #[test]
    fn issuer_key_usage_must_permit_crl_signing() {
        let f = fx();
        let ca = Certificate::parse(&f.ca).unwrap();
        let leaf = Certificate::parse(&f.leaf).unwrap();
        for listed in [false, true] {
            let revoked = if listed {
                alloc::vec![(leaf.serial(), f.now - 30)]
            } else {
                Vec::new()
            };
            let der = make(&f, &revoked, f.now - 60, f.now + 3600);
            let mut store = CrlStore::new();
            store.add_der(&der).unwrap();
            for (usage, authorized) in [
                (None, true),
                (Some(0), false),
                (Some(super::super::KU_DIGITAL_SIGNATURE), false),
                (Some(super::super::KU_KEY_CERT_SIGN), false),
                (Some(KU_CRL_SIGN), true),
                (Some(KU_CRL_SIGN | super::super::KU_DIGITAL_SIGNATURE), true),
            ] {
                let result = check(
                    &leaf,
                    ca.subject,
                    ca.spki,
                    usage,
                    &store,
                    f.now,
                    crate::crypto::sign::VERIFY_SCHEMES,
                );
                if authorized && listed {
                    assert_eq!(result.unwrap_err().kind(), ErrorKind::CertificateRevoked);
                } else {
                    assert_eq!(result.unwrap(), authorized);
                }
            }
        }
    }

    #[test]
    fn crl_issuance_refuses_reversed_update_intervals() {
        let f = fx();
        let mut rng = ic_drbg::Rng::from_os().unwrap();
        for next in [f.now - 1, f.now, f.now + 1] {
            let result = build(&f.ca, &f.ca_key, &[], f.now, next, 1, &mut rng);
            if next < f.now {
                let error = result.unwrap_err();
                assert_eq!(error.kind(), ErrorKind::InvalidConfig);
                assert_eq!(error.context(), "CRL nextUpdate precedes thisUpdate");
            } else {
                let der = result.unwrap();
                let crl = parse(&der).unwrap();
                assert_eq!(crl.this_update, f.now);
                assert_eq!(crl.next_update, Some(next));
                assert!(run(&f, &der, f.now).unwrap());
            }
        }
    }

    #[test]
    fn crl_issuance_requires_a_named_issuer_certificate() {
        let f = fx();
        let mut rng = ic_drbg::Rng::from_os().unwrap();
        let key = SigningKey::generate(KeyKind::EcdsaP384, &mut rng).unwrap();
        for name in ["", "Named CRL issuer"] {
            let issuer_der = x509::issue(
                &CertificateParams {
                    subject_cn: name,
                    dns_names: &["issuer.test"],
                    ip_addresses: &[],
                    not_before: f.now - 60,
                    not_after: f.now + 86_400,
                    is_ca: true,
                    path_len: Some(0),
                    usage: &[],
                    serial: [9; 16],
                },
                key.spki(),
                &f.ca,
                &f.ca_key,
                &mut rng,
            )
            .unwrap();
            let issuer = Certificate::parse(&issuer_der).unwrap();
            assert_eq!(
                Der::new(issuer.subject)
                    .expect(T_SEQUENCE)
                    .unwrap()
                    .is_empty(),
                name.is_empty()
            );
            let result = build(&issuer_der, &key, &[], f.now, f.now + 60, 1, &mut rng);
            if name.is_empty() {
                let error = result.unwrap_err();
                assert_eq!(error.kind(), ErrorKind::InvalidConfig);
                assert_eq!(
                    error.context(),
                    "CRL issuer certificate subject name is empty"
                );
            } else {
                let der = result.unwrap();
                let crl = parse(&der).unwrap();
                assert_eq!(crl.issuer, issuer.subject);
                let scheme = scheme_from_alg(&crl.sig_alg).unwrap();
                let public_key = PublicKey::from_spki(issuer.spki).unwrap();
                sign::verify(scheme, &public_key, &crl.tbs, &crl.signature).unwrap();
            }
        }
    }

    #[test]
    fn crl_issuance_requires_the_issuers_key() {
        let f = fx();
        let other = fx();
        let mut rng = ic_drbg::Rng::from_os().unwrap();
        let good = build(&f.ca, &f.ca_key, &[], f.now, f.now + 60, 1, &mut rng).unwrap();
        assert!(run(&f, &good, f.now).unwrap());
        let error = build(&f.ca, &other.ca_key, &[], f.now, f.now + 60, 1, &mut rng).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidConfig);
        assert_eq!(
            error.context(),
            "issuer key does not match the issuer certificate"
        );
    }

    /// REQ-CRL-001: a CRL signed by anyone else counts for nothing, either way.
    #[test]
    fn only_the_issuer_speaks_for_its_certificates() {
        let f = fx();
        let other = fx();
        let serial = Certificate::parse(&f.leaf).unwrap().serial().to_vec();
        // Same subject name (both CAs are "CRL CA"), different key.
        let forged = make(&other, &[(&serial, f.now - 30)], f.now - 60, f.now + 3600);
        assert!(!run(&f, &forged, f.now).unwrap());
        let mut tampered = make(&f, &[(&serial, f.now - 30)], f.now - 60, f.now + 3600);
        let n = tampered.len();
        tampered[n - 5] ^= 1;
        assert!(!run(&f, &tampered, f.now).unwrap_or(false));
    }

    #[test]
    fn garbage_never_panics_and_pem_loads() {
        let f = fx();
        let crl = make(&f, &[], f.now, f.now + 60);
        for n in 0..crl.len() {
            assert!(CrlStore::new().add_der(&crl[..n]).is_err());
        }
        let mut b64 = alloc::vec![0u8; ic_pkix::pem::encoded_len("X509 CRL", crl.len())];
        let len = ic_pkix::pem::encode("X509 CRL", &crl, &mut b64).unwrap();
        let mut store = CrlStore::new();
        assert_eq!(
            store
                .add_pem(core::str::from_utf8(&b64[..len]).unwrap())
                .unwrap(),
            1
        );
    }

    /// REQ-CRL-004: a CRL with a scope this build does not implement never
    /// shows a certificate good.
    #[test]
    fn narrowed_scopes_are_not_evidence_of_good_standing() {
        let f = fx();
        let crl = make(&f, &[], f.now - 60, f.now + 3600);
        let mut parsed = parse(&crl).unwrap();
        parsed.unsupported = Some("issuingDistributionPoint");
        let store = CrlStore {
            crls: alloc::vec![parsed],
        };
        let ca = Certificate::parse(&f.ca).unwrap();
        let leaf = Certificate::parse(&f.leaf).unwrap();
        assert!(!check(
            &leaf,
            ca.subject,
            ca.spki,
            None,
            &store,
            f.now,
            crate::crypto::sign::VERIFY_SCHEMES
        )
        .unwrap());
        // And the scanner flags each such extension.
        for oid in [OID_DELTA_CRL, OID_IDP] {
            let mut e = Vec::new();
            push_tlv(&mut e, T_OID, oid);
            push_tlv(&mut e, T_BOOLEAN, &[0xff]);
            let value: &[u8] = if oid == OID_DELTA_CRL {
                &[T_INTEGER, 1, 0]
            } else {
                &[T_SEQUENCE, 0]
            };
            push_tlv(&mut e, T_OCTET_STRING, value);
            let mut one = Vec::new();
            push_tlv(&mut one, T_SEQUENCE, &e);
            let mut list = Vec::new();
            push_tlv(&mut list, T_SEQUENCE, &one);
            assert!(scan_extensions(&list, false).unwrap().is_some());
        }
    }

    #[test]
    fn crl_extension_critical_flags_are_validated() {
        let alg = alg_id(SignatureScheme::EcdsaSecp384r1Sha384).unwrap();
        for flag in [
            None,
            Some(&[][..]),
            Some(&[0][..]),
            Some(&[0xff][..]),
            Some(&[1][..]),
            Some(&[0x7f][..]),
            Some(&[0, 0][..]),
            Some(&[0xff, 0][..]),
        ] {
            let mut e = Vec::new();
            push_tlv(&mut e, T_OID, &[0x2a, 3, 4]);
            if let Some(flag) = flag {
                push_tlv(&mut e, T_BOOLEAN, flag);
            }
            push_tlv(&mut e, T_OCTET_STRING, &[5, 0]);
            let mut one = Vec::new();
            push_tlv(&mut one, T_SEQUENCE, &e);
            let extensions = ext_list(&[one]);
            for entry in [false, true] {
                let der = if entry {
                    assemble(&[1], &alg, &alg, Some(&extensions), None)
                } else {
                    assemble(&[1], &alg, &alg, None, Some(&extensions))
                };
                match flag {
                    None | Some([0]) => assert!(parse(&der).unwrap().unsupported.is_none()),
                    Some([0xff]) => assert!(parse(&der).unwrap().unsupported.is_some()),
                    _ => assert_eq!(
                        parse(&der).unwrap_err().kind(),
                        ErrorKind::BadCertificateStatus
                    ),
                }
            }
        }
    }

    #[test]
    fn crl_extension_lists_are_complete_nonempty_and_unique() {
        let unknown = &[0x2a, 3, 4][..];
        let valid = ext_list(&[ext(unknown, false), ext(OID_AKI, false)]);
        let mut trailing = valid.clone();
        trailing.extend_from_slice(&[5, 0]);
        for entry in [false, true] {
            assert!(scan_extensions(&valid, entry).unwrap().is_none());
            for malformed in [
                ext_list(&[]),
                trailing.clone(),
                ext_list(&[ext(unknown, false), ext(unknown, true)]),
                ext_list(&[ext(OID_AKI, false), ext(OID_AKI, false)]),
            ] {
                assert!(scan_extensions(&malformed, entry).is_err());
            }
        }
        let alg = alg_id(SignatureScheme::EcdsaSecp384r1Sha384).unwrap();
        for malformed in [
            ext_list(&[]),
            trailing,
            ext_list(&[ext(unknown, false), ext(unknown, true)]),
        ] {
            assert_eq!(
                parse(&assemble(&[1], &alg, &alg, None, Some(&malformed)))
                    .unwrap_err()
                    .kind(),
                ErrorKind::BadCertificateStatus
            );
        }
    }

    /// REQ-CRL-016: CRL and entry extension identifiers cannot be malformed,
    /// even when unknown and noncritical.
    #[test]
    fn crl_extension_oids_require_complete_minimal_encodings() {
        let alg = alg_id(SignatureScheme::EcdsaSecp384r1Sha384).unwrap();
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
            for entry in [false, true] {
                for critical in [false, true] {
                    let extensions = ext_list(&[ext(oid, critical)]);
                    let der = if entry {
                        assemble(&[1], &alg, &alg, Some(&extensions), None)
                    } else {
                        assemble(&[1], &alg, &alg, None, Some(&extensions))
                    };
                    let result = parse(&der);
                    if valid {
                        assert_eq!(result.unwrap().unsupported.is_some(), critical);
                    } else {
                        assert_eq!(
                            result.err().unwrap().kind(),
                            ErrorKind::BadCertificateStatus
                        );
                    }
                }
            }
        }
    }

    /// One extension, optionally critical, with a valid number or placeholder.
    fn ext(oid: &[u8], critical: bool) -> Vec<u8> {
        ext_with_value(
            oid,
            critical,
            if oid == OID_CRL_NUMBER || oid == OID_DELTA_CRL {
                &[T_INTEGER, 1, 0]
            } else if oid == OID_REASON_CODE {
                &[0x0a, 1, 0]
            } else if oid == OID_INVALIDITY_DATE {
                b"\x18\x0f20270115080000Z"
            } else if oid == OID_AKI {
                &[T_SEQUENCE, 0]
            } else if oid == OID_CERT_ISSUER {
                &[T_SEQUENCE, 4, 0xa4, 2, T_SEQUENCE, 0]
            } else if oid == OID_IDP {
                &[T_SEQUENCE, 0]
            } else {
                &[0x05, 0]
            },
        )
    }

    fn ext_with_value(oid: &[u8], critical: bool, value: &[u8]) -> Vec<u8> {
        let mut e = Vec::new();
        push_tlv(&mut e, T_OID, oid);
        if critical {
            push_tlv(&mut e, T_BOOLEAN, &[0xff]);
        }
        push_tlv(&mut e, T_OCTET_STRING, value);
        let mut one = Vec::new();
        push_tlv(&mut one, T_SEQUENCE, &e);
        one
    }

    fn ext_list(exts: &[Vec<u8>]) -> Vec<u8> {
        let mut list = Vec::new();
        push_tlv(&mut list, T_SEQUENCE, &exts.concat());
        list
    }

    /// A CRL assembled field by field, for the parser's refusals. It is not
    /// validly signed: `parse` reads structure, and signatures are checked
    /// later, so each refusal here is the parser's own.
    fn assemble(
        version: &[u8],
        inner_alg: &[u8],
        outer_alg: &[u8],
        entry_exts: Option<&[u8]>,
        crl_exts: Option<&[u8]>,
    ) -> Vec<u8> {
        let now = 1_800_000_000;
        let mut tbs = Vec::new();
        push_tlv(&mut tbs, T_INTEGER, version);
        tbs.extend_from_slice(inner_alg);
        tbs.extend_from_slice(&x509::encode_name("Parser CRL Issuer"));
        encode_time(&mut tbs, now).unwrap();
        encode_time(&mut tbs, now + 3600).unwrap();
        let mut entry = Vec::new();
        push_tlv(&mut entry, T_INTEGER, &[0x2a]);
        encode_time(&mut entry, now - 60).unwrap();
        if let Some(e) = entry_exts {
            entry.extend_from_slice(e);
        }
        let mut entries = Vec::new();
        push_tlv(&mut entries, T_SEQUENCE, &entry);
        push_tlv(&mut tbs, T_SEQUENCE, &entries);
        if let Some(e) = crl_exts {
            push_tlv(&mut tbs, T_CTX0, e);
        }
        let mut body = Vec::new();
        push_tlv(&mut body, T_SEQUENCE, &tbs);
        body.extend_from_slice(outer_alg);
        push_tlv(&mut body, T_BIT_STRING, &[0, 1, 2, 3]);
        let mut out = Vec::new();
        push_tlv(&mut out, T_SEQUENCE, &body);
        out
    }

    /// REQ-CRL-021: signed CRLs validate complete, ordered AKI fields, paired
    /// issuer/serial references, and issuer names through the shared parser.
    #[test]
    fn crl_authority_key_identifiers_require_complete_fields() {
        let wrap = |tag, body: &[u8]| {
            let mut encoded = Vec::new();
            push_tlv(&mut encoded, tag, body);
            encoded
        };
        let f = fx();
        let scheme = f.ca_key.schemes()[0];
        let algorithm = alg_id(scheme).unwrap();
        let key = wrap(0x80, &[1, 2, 3]);
        let issuer = wrap(0xa1, &wrap(0xa4, &x509::encode_name("Issuer")));
        let serial = wrap(0x82, &[1]);
        let mut cases = Vec::new();
        for (body, accepted) in [
            (Vec::new(), true),
            (key.clone(), true),
            (wrap(0x80, &[]), true),
            ([issuer.clone(), serial.clone()].concat(), true),
            ([key.clone(), issuer.clone(), serial.clone()].concat(), true),
            ([issuer.clone(), wrap(0x82, &[0, 0x80])].concat(), true),
            ([issuer.clone(), wrap(0x82, &[0xff])].concat(), true),
            ([key.clone(), key.clone()].concat(), false),
            (issuer.clone(), false),
            (serial.clone(), false),
            ([serial.clone(), issuer.clone()].concat(), false),
            ([issuer.clone(), serial.clone(), key].concat(), false),
            ([wrap(0xa1, &[]), serial.clone()].concat(), false),
            (
                [wrap(0xa1, &wrap(0x88, &[0x2a, 0x81])), serial.clone()].concat(),
                false,
            ),
            (
                [
                    wrap(0xa1, &wrap(0xa4, &[T_SEQUENCE, 2, 0x31, 0])),
                    serial.clone(),
                ]
                .concat(),
                false,
            ),
            ([issuer.clone(), wrap(0x82, &[])].concat(), false),
            ([issuer.clone(), wrap(0x82, &[0, 1])].concat(), false),
            ([issuer, wrap(0x82, &[0xff, 0xff])].concat(), false),
            (alloc::vec![0x80, 2, 1], false),
        ] {
            cases.push((wrap(T_SEQUENCE, &body), accepted));
        }
        cases.extend([
            (Vec::new(), false),
            (alloc::vec![0x05, 0], false),
            (alloc::vec![T_SEQUENCE, 0, 0x05, 0], false),
        ]);
        let mut rng = ic_drbg::Rng::from_os().unwrap();
        for (value, accepted) in cases {
            for critical in [false, true] {
                let aki = ext_with_value(OID_AKI, critical, &value);
                let control = ext(OID_CRL_NUMBER, false);
                for extensions in [
                    ext_list(core::slice::from_ref(&aki)),
                    ext_list(&[aki.clone(), control.clone()]),
                    ext_list(&[control.clone(), aki.clone()]),
                ] {
                    let fixture = assemble(&[1], &algorithm, &algorithm, None, Some(&extensions));
                    let mut list = Der::new(&fixture).nested(T_SEQUENCE).unwrap();
                    let tbs = list.expect_raw(T_SEQUENCE).unwrap();
                    let signature = f.ca_key.sign(scheme, tbs, &mut rng).unwrap();
                    sign::verify(
                        scheme,
                        &PublicKey::from_spki(f.ca_key.spki()).unwrap(),
                        tbs,
                        &signature,
                    )
                    .unwrap();
                    let bits = [alloc::vec![0], signature].concat();
                    let der = wrap(
                        T_SEQUENCE,
                        &[
                            tbs,
                            algorithm.as_slice(),
                            wrap(T_BIT_STRING, &bits).as_slice(),
                        ]
                        .concat(),
                    );
                    let result = parse(&der);
                    if accepted {
                        assert!(result.unwrap().unsupported.is_none());
                        CrlStore::new().add_der(&der).unwrap();
                    } else {
                        assert_eq!(
                            result.err().unwrap().kind(),
                            ErrorKind::BadCertificateStatus
                        );
                        assert_eq!(
                            CrlStore::new().add_der(&der).unwrap_err().kind(),
                            ErrorKind::BadCertificateStatus
                        );
                    }
                }
            }
        }
    }

    /// REQ-CRL-026: RFC 5280 Appendix B requires trailing zero named bits to
    /// be omitted. Signed scopes validate padding, counts and empty encodings.
    #[test]
    fn crl_reason_flags_require_canonical_named_bit_strings() {
        // For each possible final octet, the final represented bit must be one
        // and every unused low bit must be zero.
        for unused in 0u8..8 {
            for last in 0u8..=255 {
                let accepted = last & ((1u8 << unused) - 1) == 0 && last & (1u8 << unused) != 0;
                assert_eq!(check_reason_flags(&[unused, last]).is_ok(), accepted);
                assert_eq!(check_reason_flags(&[unused, 0x40, last]).is_ok(), accepted);
            }
        }
        let wrap = |tag, body: &[u8]| {
            let mut encoded = Vec::new();
            push_tlv(&mut encoded, tag, body);
            encoded
        };
        let mut cases = alloc::vec![
            (alloc::vec![0], true),
            (Vec::new(), false),
            (alloc::vec![0, 0], false),
            (alloc::vec![0, 0x40, 0], false),
            (alloc::vec![0, 0x40], false),
            (alloc::vec![6, 0x41], false),
            (alloc::vec![0, 0x40, 1], true),
            (alloc::vec![7, 0x40, 0x80], true),
            (alloc::vec![0, 0, 0, 1], true), // Unknown bit positions remain opaque.
        ];
        for unused in 0u8..=255 {
            cases.push((alloc::vec![unused], unused == 0));
            cases.push((alloc::vec![unused, 0x80], unused == 7));
            cases.push((alloc::vec![unused, 0], false));
        }
        for unused in 0u8..8 {
            cases.push((alloc::vec![unused, 1u8 << unused], true));
            if unused != 0 {
                cases.push((alloc::vec![unused, (1u8 << unused) | 1], false));
            }
        }
        let f = fx();
        let scheme = f.ca_key.schemes()[0];
        let algorithm = alg_id(scheme).unwrap();
        let key = PublicKey::from_spki(f.ca_key.spki()).unwrap();
        let mut rng = ic_drbg::Rng::from_os().unwrap();
        for (bits, accepted) in cases {
            for critical in [false, true] {
                let reason = wrap(0x83, &bits);
                for value in [
                    wrap(T_SEQUENCE, &reason),
                    wrap(
                        T_SEQUENCE,
                        &[wrap(0x81, &[0xff]), reason, wrap(0x84, &[0xff])].concat(),
                    ),
                ] {
                    let extension = ext_with_value(OID_IDP, critical, &value);
                    let control = ext(OID_CRL_NUMBER, false);
                    for extensions in [
                        ext_list(core::slice::from_ref(&extension)),
                        ext_list(&[extension.clone(), control.clone()]),
                        ext_list(&[control.clone(), extension.clone()]),
                    ] {
                        let fixture =
                            assemble(&[1], &algorithm, &algorithm, None, Some(&extensions));
                        let mut list = Der::new(&fixture).nested(T_SEQUENCE).unwrap();
                        let tbs = list.expect_raw(T_SEQUENCE).unwrap();
                        let signature = f.ca_key.sign(scheme, tbs, &mut rng).unwrap();
                        sign::verify(scheme, &key, tbs, &signature).unwrap();
                        let bits = [alloc::vec![0], signature].concat();
                        let der = wrap(
                            T_SEQUENCE,
                            &[
                                tbs,
                                algorithm.as_slice(),
                                wrap(T_BIT_STRING, &bits).as_slice(),
                            ]
                            .concat(),
                        );
                        let result = parse(&der);
                        if accepted {
                            assert_eq!(
                                result.unwrap().unsupported,
                                Some(
                                    "partitioned CRLs (issuingDistributionPoint) are not supported"
                                )
                            );
                            CrlStore::new().add_der(&der).unwrap();
                        } else {
                            assert_eq!(
                                result.err().unwrap().kind(),
                                ErrorKind::BadCertificateStatus
                            );
                            assert_eq!(
                                CrlStore::new().add_der(&der).unwrap_err().kind(),
                                ErrorKind::BadCertificateStatus
                            );
                        }
                    }
                }
            }
        }
    }

    /// REQ-CRL-025: signed distributionPoint names require one complete choice,
    /// nonempty valid fullName lists, or nonempty ordered relative-name attributes.
    #[test]
    fn crl_distribution_point_names_require_complete_choices() {
        let wrap = |tag, body: &[u8]| {
            let mut encoded = Vec::new();
            push_tlv(&mut encoded, tag, body);
            encoded
        };
        let uri = wrap(0x86, b"https://issuer.test/crl");
        let directory = wrap(0xa4, &x509::encode_name("CRL point"));
        let attribute = |oid: &[u8], value: &[u8]| {
            wrap(T_SEQUENCE, &[wrap(T_OID, oid), value.to_vec()].concat())
        };
        let first = attribute(&[0x55, 4, 3], &[0x0c, 1, b'A']);
        let second = attribute(&[0x55, 4, 3], &[0x0c, 1, b'B']);
        let mut cases = alloc::vec![
            (wrap(T_CTX0, &uri), true),
            (
                wrap(T_CTX0, &[uri.clone(), directory.clone()].concat()),
                true
            ),
            (wrap(T_CTX0, &wrap(0xa4, &[T_SEQUENCE, 0])), true),
            (wrap(0xa1, &first), true),
            (wrap(0xa1, &[first.clone(), second.clone()].concat()), true),
            (wrap(0xa1, &[first.clone(), first.clone()].concat()), true),
            (wrap(0xa1, &attribute(&[0x2a, 3], &[0x9f, 0x1f, 0])), true),
            (Vec::new(), false),
            (wrap(T_CTX0, &[]), false),
            (wrap(0xa1, &[]), false),
            (wrap(0xa2, &uri), false),
            (wrap(0x80, &uri), false),
            (wrap(0x81, &first), false),
            (wrap(T_SEQUENCE, &uri), false),
            (wrap(T_CTX0, &wrap(T_SEQUENCE, &uri)), false),
            (wrap(0xa1, &wrap(0x31, &first)), false),
            (wrap(0xa1, &[second.clone(), first.clone()].concat()), false),
            (wrap(0xa1, &attribute(&[], &[0x05, 0])), false),
            (wrap(0xa1, &attribute(&[0x2a, 0x80], &[0x05, 0])), false),
            (wrap(0xa1, &attribute(&[0x2a, 0x80, 0], &[0x05, 0])), false),
            (wrap(0xa1, &attribute(&[0x2a, 3], &[])), false),
            (
                wrap(0xa1, &attribute(&[0x2a, 3], &[0x05, 0, 0x05, 0])),
                false
            ),
            (wrap(0xa1, &attribute(&[0x2a, 3], &[0x0c, 2, b'A'])), false),
            (wrap(0xa1, &attribute(&[0x2a, 3], &[0x9f, 0x1e, 0])), false),
            (wrap(0xa1, &[first.clone(), alloc::vec![0]].concat()), false),
            (alloc::vec![T_CTX0, 3, 0x86, 2, b'A'], false),
            ([wrap(T_CTX0, &uri), alloc::vec![0x05, 0]].concat(), false),
            ([wrap(T_CTX0, &uri), wrap(0xa1, &first)].concat(), false),
        ];
        for name in [
            wrap(0x89, b"undefined"),
            wrap(0x88, &[0x2a, 0x80]),
            wrap(0x82, &[0x80]),
            wrap(0x87, &[0; 5]),
            wrap(0xa4, &[T_SEQUENCE, 2, 0x31, 0]),
            wrap(0xa0, &[T_OID, 2, 0x2a, 3]),
            wrap(0xa5, &[]),
        ] {
            for names in [
                name.clone(),
                [name.clone(), uri.clone()].concat(),
                [uri.clone(), name].concat(),
            ] {
                cases.push((wrap(T_CTX0, &names), false));
            }
        }
        let f = fx();
        let scheme = f.ca_key.schemes()[0];
        let algorithm = alg_id(scheme).unwrap();
        let key = PublicKey::from_spki(f.ca_key.spki()).unwrap();
        let mut rng = ic_drbg::Rng::from_os().unwrap();
        for (choice, accepted) in cases {
            for critical in [false, true] {
                let point = wrap(T_CTX0, &choice);
                for value in [
                    wrap(T_SEQUENCE, &point),
                    wrap(T_SEQUENCE, &[point, wrap(0x84, &[0xff])].concat()),
                ] {
                    let extension = ext_with_value(OID_IDP, critical, &value);
                    let control = ext(OID_CRL_NUMBER, false);
                    for extensions in [
                        ext_list(core::slice::from_ref(&extension)),
                        ext_list(&[extension.clone(), control.clone()]),
                        ext_list(&[control.clone(), extension.clone()]),
                    ] {
                        let fixture =
                            assemble(&[1], &algorithm, &algorithm, None, Some(&extensions));
                        let mut list = Der::new(&fixture).nested(T_SEQUENCE).unwrap();
                        let tbs = list.expect_raw(T_SEQUENCE).unwrap();
                        let signature = f.ca_key.sign(scheme, tbs, &mut rng).unwrap();
                        sign::verify(scheme, &key, tbs, &signature).unwrap();
                        let bits = [alloc::vec![0], signature].concat();
                        let der = wrap(
                            T_SEQUENCE,
                            &[
                                tbs,
                                algorithm.as_slice(),
                                wrap(T_BIT_STRING, &bits).as_slice(),
                            ]
                            .concat(),
                        );
                        let result = parse(&der);
                        if accepted {
                            assert_eq!(
                                result.unwrap().unsupported,
                                Some(
                                    "partitioned CRLs (issuingDistributionPoint) are not supported"
                                )
                            );
                            CrlStore::new().add_der(&der).unwrap();
                        } else {
                            assert_eq!(
                                result.err().unwrap().kind(),
                                ErrorKind::BadCertificateStatus
                            );
                            assert_eq!(
                                CrlStore::new().add_der(&der).unwrap_err().kind(),
                                ErrorKind::BadCertificateStatus
                            );
                        }
                    }
                }
            }
        }
    }

    /// REQ-CRL-024: signed scoped CRLs require complete wrappers, defined field
    /// tags, ordering, canonical BOOLEANs and mutually exclusive certificate scopes.
    /// Empty sequences and explicit FALSE retain existing parse compatibility.
    #[test]
    fn crl_distribution_point_fields_require_complete_ordered_encoding() {
        let wrap = |tag, body: &[u8]| {
            let mut encoded = Vec::new();
            push_tlv(&mut encoded, tag, body);
            encoded
        };
        let point = wrap(
            T_CTX0,
            &wrap(T_CTX0, &wrap(0x86, b"https://issuer.test/crl")),
        );
        let fields = [
            point,
            wrap(0x81, &[0]),
            wrap(0x82, &[0]),
            wrap(0x83, &[6, 0x40]),
            wrap(0x84, &[0xff]),
            wrap(0x85, &[0]),
        ];
        let mut cases = alloc::vec![
            (wrap(T_SEQUENCE, &[]), true),
            (wrap(T_SEQUENCE, &fields.concat()), true)
        ];
        for (index, field) in fields.iter().enumerate() {
            cases.push((wrap(T_SEQUENCE, field), true));
            cases.push((
                wrap(T_SEQUENCE, &[field.clone(), field.clone()].concat()),
                false,
            ));
            for later in &fields[index + 1..] {
                cases.push((
                    wrap(T_SEQUENCE, &[later.clone(), field.clone()].concat()),
                    false,
                ));
            }
        }
        for tag in [0x81, 0x82, 0x84, 0x85] {
            for (value, accepted) in [
                (&[0][..], true),
                (&[0xff][..], true),
                (&[][..], false),
                (&[1][..], false),
                (&[0x7f][..], false),
                (&[0x80][..], false),
                (&[0xfe][..], false),
                (&[0, 0][..], false),
                (&[0xff, 0xff][..], false),
            ] {
                cases.push((wrap(T_SEQUENCE, &wrap(tag, value)), accepted));
            }
        }
        for flags in 0u8..16 {
            let mut body = Vec::new();
            for (bit, tag) in [0x81, 0x82, 0x84, 0x85].into_iter().enumerate() {
                body.extend_from_slice(&wrap(
                    tag,
                    &[if flags & (1 << bit) == 0 { 0 } else { 0xff }],
                ));
            }
            cases.push((wrap(T_SEQUENCE, &body), (flags & 0b1011).count_ones() <= 1));
        }
        for tag in [
            0x80, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0x86, 0xa6, T_BOOLEAN, T_SEQUENCE,
        ] {
            let invalid = wrap(tag, &[0]);
            for body in [
                invalid.clone(),
                [fields[0].clone(), invalid.clone()].concat(),
                [invalid, fields[4].clone()].concat(),
            ] {
                cases.push((wrap(T_SEQUENCE, &body), false));
            }
        }
        cases.extend([
            (Vec::new(), false),
            (wrap(T_OCTET_STRING, &fields.concat()), false),
            (alloc::vec![T_SEQUENCE, 3, 0x81, 2, 0], false),
            (alloc::vec![T_SEQUENCE, 1, 0x81], false),
            (
                [wrap(T_SEQUENCE, &fields.concat()), alloc::vec![0x05, 0]].concat(),
                false,
            ),
        ]);
        let f = fx();
        let scheme = f.ca_key.schemes()[0];
        let algorithm = alg_id(scheme).unwrap();
        let key = PublicKey::from_spki(f.ca_key.spki()).unwrap();
        let mut rng = ic_drbg::Rng::from_os().unwrap();
        for (value, accepted) in cases {
            for critical in [false, true] {
                let point = ext_with_value(OID_IDP, critical, &value);
                let control = ext(OID_CRL_NUMBER, false);
                for extensions in [
                    ext_list(core::slice::from_ref(&point)),
                    ext_list(&[point.clone(), control.clone()]),
                    ext_list(&[control.clone(), point.clone()]),
                ] {
                    let fixture = assemble(&[1], &algorithm, &algorithm, None, Some(&extensions));
                    let mut list = Der::new(&fixture).nested(T_SEQUENCE).unwrap();
                    let tbs = list.expect_raw(T_SEQUENCE).unwrap();
                    let signature = f.ca_key.sign(scheme, tbs, &mut rng).unwrap();
                    sign::verify(scheme, &key, tbs, &signature).unwrap();
                    let bits = [alloc::vec![0], signature].concat();
                    let der = wrap(
                        T_SEQUENCE,
                        &[
                            tbs,
                            algorithm.as_slice(),
                            wrap(T_BIT_STRING, &bits).as_slice(),
                        ]
                        .concat(),
                    );
                    let result = parse(&der);
                    if accepted {
                        assert_eq!(
                            result.unwrap().unsupported,
                            Some("partitioned CRLs (issuingDistributionPoint) are not supported")
                        );
                        CrlStore::new().add_der(&der).unwrap();
                    } else {
                        assert_eq!(
                            result.err().unwrap().kind(),
                            ErrorKind::BadCertificateStatus
                        );
                        assert_eq!(
                            CrlStore::new().add_der(&der).unwrap_err().kind(),
                            ErrorKind::BadCertificateStatus
                        );
                    }
                }
            }
        }
    }

    /// REQ-CRL-023: signed certificateIssuer entry extensions validate their
    /// complete GeneralNames wrappers and every name, including later names.
    /// Well-formed values keep indirect CRLs unsupported for either critical flag.
    #[test]
    fn crl_certificate_issuers_require_complete_general_names() {
        let wrap = |tag, body: &[u8]| {
            let mut encoded = Vec::new();
            push_tlv(&mut encoded, tag, body);
            encoded
        };
        let directory = wrap(0xa4, &x509::encode_name("Indirect issuer"));
        let other = wrap(0xa0, &[T_OID, 2, 0x2a, 3, T_CTX0, 2, 0x05, 0]);
        let edi = wrap(0xa5, &[0xa1, 3, 0x0c, 1, b'A']);
        let mut cases = Vec::new();
        for (name, accepted) in [
            (directory.clone(), true),
            (wrap(0xa4, &[T_SEQUENCE, 0]), true),
            (wrap(0x81, b"issuer@example.test"), true),
            (wrap(0x82, b"issuer.test"), true),
            (wrap(0x86, b"https://issuer.test"), true),
            (wrap(0x87, &[127, 0, 0, 1]), true),
            (wrap(0x87, &[0; 16]), true),
            (wrap(0x88, &[0x2a, 3]), true),
            (other.clone(), true),
            (edi, true),
            (wrap(0xa3, &[]), true), // Existing opaque x400Address compatibility.
            (wrap(0x82, &[]), true), // Existing IA5String syntax compatibility.
            (wrap(0x89, b"invalid choice"), false),
            (wrap(0xa2, b"wrong tag form"), false),
            (wrap(0x81, &[0x80]), false),
            (wrap(0x82, &[0xff]), false),
            (wrap(0x86, &[0x80]), false),
            (wrap(0x87, &[0; 3]), false),
            (wrap(0x87, &[0; 17]), false),
            (wrap(0x88, &[]), false),
            (wrap(0x88, &[0x2a, 0x80]), false),
            (wrap(0x88, &[0x2a, 0x80, 0]), false),
            (wrap(0xa4, &[T_SEQUENCE, 2, 0x31, 0]), false),
            (wrap(0xa4, &[T_SEQUENCE, 0, 0x05, 0]), false),
            (wrap(0xa4, &[T_SEQUENCE, 2, 0x31]), false),
            (wrap(0xa0, &[T_OID, 2, 0x2a, 3]), false),
            ([other, alloc::vec![0]].concat(), false),
            (wrap(0xa5, &[]), false),
            (wrap(0xa5, &[0xa1, 3, 0x0c, 1, 0xff]), false),
            (alloc::vec![0x82, 2, b'A'], false),
        ] {
            for names in [
                name.clone(),
                [name.clone(), directory.clone()].concat(),
                [directory.clone(), name].concat(),
            ] {
                cases.push((wrap(T_SEQUENCE, &names), accepted));
            }
        }
        cases.extend([
            (Vec::new(), false),
            (wrap(T_SEQUENCE, &[]), false),
            (wrap(T_OCTET_STRING, &directory), false),
            (alloc::vec![T_SEQUENCE, 2, 0xa4], false),
            (
                [wrap(T_SEQUENCE, &directory), alloc::vec![0x05, 0]].concat(),
                false,
            ),
        ]);
        let f = fx();
        let scheme = f.ca_key.schemes()[0];
        let algorithm = alg_id(scheme).unwrap();
        let key = PublicKey::from_spki(f.ca_key.spki()).unwrap();
        let mut rng = ic_drbg::Rng::from_os().unwrap();
        for (value, accepted) in cases {
            for critical in [false, true] {
                let issuer = ext_with_value(OID_CERT_ISSUER, critical, &value);
                let control = ext(OID_REASON_CODE, false);
                for extensions in [
                    ext_list(core::slice::from_ref(&issuer)),
                    ext_list(&[issuer.clone(), control.clone()]),
                    ext_list(&[control.clone(), issuer.clone()]),
                ] {
                    let fixture = assemble(&[1], &algorithm, &algorithm, Some(&extensions), None);
                    let mut list = Der::new(&fixture).nested(T_SEQUENCE).unwrap();
                    let tbs = list.expect_raw(T_SEQUENCE).unwrap();
                    let signature = f.ca_key.sign(scheme, tbs, &mut rng).unwrap();
                    sign::verify(scheme, &key, tbs, &signature).unwrap();
                    let bits = [alloc::vec![0], signature].concat();
                    let der = wrap(
                        T_SEQUENCE,
                        &[
                            tbs,
                            algorithm.as_slice(),
                            wrap(T_BIT_STRING, &bits).as_slice(),
                        ]
                        .concat(),
                    );
                    let result = parse(&der);
                    if accepted {
                        assert_eq!(
                            result.unwrap().unsupported,
                            Some("indirect CRLs are not supported")
                        );
                        CrlStore::new().add_der(&der).unwrap();
                    } else {
                        assert_eq!(
                            result.err().unwrap().kind(),
                            ErrorKind::BadCertificateStatus
                        );
                        assert_eq!(
                            CrlStore::new().add_der(&der).unwrap_err().kind(),
                            ErrorKind::BadCertificateStatus
                        );
                    }
                }
            }
        }
    }

    /// REQ-CRL-020: RFC 5280 section 5.3.2 requires GeneralizedTime with the
    /// UTC second precision from section 4.1.2.5.2 and a complete wrapper.
    #[test]
    fn crl_invalidity_dates_require_complete_generalized_time() {
        let wrap = |tag, body: &[u8]| {
            let mut encoded = Vec::new();
            push_tlv(&mut encoded, tag, body);
            encoded
        };
        let f = fx();
        let scheme = f.ca_key.schemes()[0];
        let algorithm = alg_id(scheme).unwrap();
        let mut cases = Vec::new();
        for (date, accepted) in [
            (&b"19700101000000Z"[..], true),
            (&b"20000229010203Z"[..], true),
            (&b"19000228000000Z"[..], true),
            (&b"99991231235959Z"[..], true),
            (&b"20270115080000Z"[..], true),
            (&b""[..], false),
            (&b"19000229000000Z"[..], false),
            (&b"20270229000000Z"[..], false),
            (&b"20270001000000Z"[..], false),
            (&b"20271301000000Z"[..], false),
            (&b"20270100000000Z"[..], false),
            (&b"20270431000000Z"[..], false),
            (&b"20270101240000Z"[..], false),
            (&b"20270101006000Z"[..], false),
            (&b"20270101000060Z"[..], false),
            (&b"20270101000000X"[..], false),
            (&b"202A0101000000Z"[..], false),
            (&b"202701010000Z"[..], false),
            (&b"20270101000000.1Z"[..], false),
            (&b"20270101000000+0000"[..], false),
        ] {
            cases.push((wrap(0x18, date), accepted));
        }
        cases.extend([
            (Vec::new(), false),
            (wrap(0x17, b"270115080000Z"), false),
            (wrap(T_OCTET_STRING, b"20270115080000Z"), false),
            (alloc::vec![0x18, 15, b'2'], false),
            (
                [wrap(0x18, b"20270115080000Z"), alloc::vec![0x05, 0]].concat(),
                false,
            ),
            (
                [
                    wrap(0x18, b"20270115080000Z"),
                    wrap(0x18, b"20270115080000Z"),
                ]
                .concat(),
                false,
            ),
        ]);
        let mut rng = ic_drbg::Rng::from_os().unwrap();
        for (value, accepted) in cases {
            for critical in [false, true] {
                let date = ext_with_value(OID_INVALIDITY_DATE, critical, &value);
                let control = ext(OID_REASON_CODE, false);
                for extensions in [
                    ext_list(core::slice::from_ref(&date)),
                    ext_list(&[date.clone(), control.clone()]),
                    ext_list(&[control.clone(), date.clone()]),
                ] {
                    let fixture = assemble(&[1], &algorithm, &algorithm, Some(&extensions), None);
                    let mut list = Der::new(&fixture).nested(T_SEQUENCE).unwrap();
                    let tbs = list.expect_raw(T_SEQUENCE).unwrap();
                    let signature = f.ca_key.sign(scheme, tbs, &mut rng).unwrap();
                    sign::verify(
                        scheme,
                        &PublicKey::from_spki(f.ca_key.spki()).unwrap(),
                        tbs,
                        &signature,
                    )
                    .unwrap();
                    let bits = [alloc::vec![0], signature].concat();
                    let der = wrap(
                        T_SEQUENCE,
                        &[
                            tbs,
                            algorithm.as_slice(),
                            wrap(T_BIT_STRING, &bits).as_slice(),
                        ]
                        .concat(),
                    );
                    let result = parse(&der);
                    if accepted {
                        assert!(result.unwrap().unsupported.is_none());
                        CrlStore::new().add_der(&der).unwrap();
                    } else {
                        assert_eq!(
                            result.err().unwrap().kind(),
                            ErrorKind::BadCertificateStatus
                        );
                        assert_eq!(
                            CrlStore::new().add_der(&der).unwrap_err().kind(),
                            ErrorKind::BadCertificateStatus
                        );
                    }
                }
            }
        }
    }

    /// REQ-CRL-019: RFC 5280 section 5.3.1 defines reason codes 0..6, 8..10.
    /// Signed fixtures reject wrong tags, noncanonical values and trailing data.
    #[test]
    fn crl_reason_codes_require_complete_defined_enumerations() {
        let wrap = |tag, body: &[u8]| {
            let mut encoded = Vec::new();
            push_tlv(&mut encoded, tag, body);
            encoded
        };
        let f = fx();
        let scheme = f.ca_key.schemes()[0];
        let algorithm = alg_id(scheme).unwrap();
        let mut cases = Vec::new();
        for reason in 0..=u8::MAX {
            cases.push((wrap(0x0a, &[reason]), matches!(reason, 0..=6 | 8..=10)));
        }
        cases.extend([
            (Vec::new(), false),
            (wrap(0x0a, &[]), false),
            (wrap(0x0a, &[0, 1]), false),
            (wrap(0x0a, &[0xff, 0xff]), false),
            (wrap(T_INTEGER, &[1]), false),
            (alloc::vec![0x0a, 2, 1], false),
            (alloc::vec![0x0a, 1, 1, 0x05, 0], false),
            (alloc::vec![0x0a, 1, 1, 0x0a, 1, 2], false),
        ]);
        let mut rng = ic_drbg::Rng::from_os().unwrap();
        for (value, accepted) in cases {
            for critical in [false, true] {
                let reason = ext_with_value(OID_REASON_CODE, critical, &value);
                let control = ext(OID_INVALIDITY_DATE, false);
                for extensions in [
                    ext_list(core::slice::from_ref(&reason)),
                    ext_list(&[reason.clone(), control.clone()]),
                    ext_list(&[control.clone(), reason.clone()]),
                ] {
                    let fixture = assemble(&[1], &algorithm, &algorithm, Some(&extensions), None);
                    let mut list = Der::new(&fixture).nested(T_SEQUENCE).unwrap();
                    let tbs = list.expect_raw(T_SEQUENCE).unwrap();
                    let signature = f.ca_key.sign(scheme, tbs, &mut rng).unwrap();
                    sign::verify(
                        scheme,
                        &PublicKey::from_spki(f.ca_key.spki()).unwrap(),
                        tbs,
                        &signature,
                    )
                    .unwrap();
                    let bits = [alloc::vec![0], signature].concat();
                    let der = wrap(
                        T_SEQUENCE,
                        &[
                            tbs,
                            algorithm.as_slice(),
                            wrap(T_BIT_STRING, &bits).as_slice(),
                        ]
                        .concat(),
                    );
                    let result = parse(&der);
                    if accepted {
                        assert!(result.unwrap().unsupported.is_none());
                        CrlStore::new().add_der(&der).unwrap();
                    } else {
                        assert_eq!(
                            result.err().unwrap().kind(),
                            ErrorKind::BadCertificateStatus
                        );
                        assert_eq!(
                            CrlStore::new().add_der(&der).unwrap_err().kind(),
                            ErrorKind::BadCertificateStatus
                        );
                    }
                }
            }
        }
    }

    /// REQ-CRL-018: CRLNumber is INTEGER (0..MAX), RFC 5280 section 5.2.3;
    /// signed fixtures cover wrapper completeness and values beyond u64.
    #[test]
    fn crl_numbers_require_complete_nonnegative_integers() {
        assert_crl_number_encoding(OID_CRL_NUMBER, None);
    }

    /// REQ-CRL-022: RFC 5280 section 5.2.4 defines BaseCRLNumber as CRLNumber.
    /// Signed malformed indicators fail parsing and insertion; valid indicators
    /// remain unsupported for both critical flags and every extension position.
    #[test]
    fn delta_crl_indicators_require_complete_nonnegative_integers() {
        assert_crl_number_encoding(OID_DELTA_CRL, Some("delta CRLs are not supported"));
    }

    fn assert_crl_number_encoding(oid: &[u8], unsupported: Option<&'static str>) {
        let wrap = |tag, body: &[u8]| {
            let mut encoded = Vec::new();
            push_tlv(&mut encoded, tag, body);
            encoded
        };
        let f = fx();
        let scheme = f.ca_key.schemes()[0];
        let algorithm = alg_id(scheme).unwrap();
        let mut cases = Vec::new();
        for (number, accepted) in [
            (alloc::vec![0], true),
            (alloc::vec![1], true),
            (alloc::vec![0x7f], true),
            (alloc::vec![0, 0x80], true),
            (alloc::vec![1; 20], true),
            (alloc::vec![1; 33], true),
            (Vec::new(), false),
            (alloc::vec![0x80], false),
            (alloc::vec![0xff], false),
            (alloc::vec![0, 0], false),
            (alloc::vec![0, 1], false),
            (alloc::vec![0xff, 0xff], false),
        ] {
            cases.push((wrap(T_INTEGER, &number), accepted));
        }
        cases.extend([
            (Vec::new(), false),
            (alloc::vec![0x05, 0], false),
            (alloc::vec![T_INTEGER, 2, 1], false),
            (alloc::vec![T_INTEGER, 1, 1, 0x05, 0], false),
            (alloc::vec![T_INTEGER, 1, 1, T_INTEGER, 1, 2], false),
        ]);
        for (value, accepted) in cases {
            for critical in [false, true] {
                let number = ext_with_value(oid, critical, &value);
                let control = ext(OID_AKI, false);
                for extensions in [
                    ext_list(core::slice::from_ref(&number)),
                    ext_list(&[number.clone(), control.clone()]),
                    ext_list(&[control.clone(), number.clone()]),
                ] {
                    let fixture = assemble(&[1], &algorithm, &algorithm, None, Some(&extensions));
                    let mut list = Der::new(&fixture).nested(T_SEQUENCE).unwrap();
                    let tbs = list.expect_raw(T_SEQUENCE).unwrap();
                    let signature = f
                        .ca_key
                        .sign(scheme, tbs, &mut ic_drbg::Rng::from_os().unwrap())
                        .unwrap();
                    sign::verify(
                        scheme,
                        &PublicKey::from_spki(f.ca_key.spki()).unwrap(),
                        tbs,
                        &signature,
                    )
                    .unwrap();
                    let bits = [alloc::vec![0], signature].concat();
                    let der = wrap(
                        T_SEQUENCE,
                        &[
                            tbs,
                            algorithm.as_slice(),
                            wrap(T_BIT_STRING, &bits).as_slice(),
                        ]
                        .concat(),
                    );
                    let result = parse(&der);
                    if accepted {
                        assert_eq!(result.unwrap().unsupported, unsupported);
                        CrlStore::new().add_der(&der).unwrap();
                    } else {
                        assert_eq!(
                            result.err().unwrap().kind(),
                            ErrorKind::BadCertificateStatus
                        );
                        assert_eq!(
                            CrlStore::new().add_der(&der).unwrap_err().kind(),
                            ErrorKind::BadCertificateStatus
                        );
                    }
                }
            }
        }
    }

    /// REQ-CRL-017: signed CRLs reject matching malformed algorithm fields
    /// during parsing; structurally valid unknown algorithms remain parseable.
    #[test]
    fn crl_signature_identifiers_require_complete_fields() {
        let wrap = |tag, body: &[u8]| {
            let mut encoded = Vec::new();
            push_tlv(&mut encoded, tag, body);
            encoded
        };
        let f = fx();
        let scheme = f.ca_key.schemes()[0];
        let known = alg_id(scheme).unwrap();
        let unknown = wrap(T_OID, &[0x2a, 3]);
        let mut cases = alloc::vec![(known, true, true)];
        for (body, accepted) in [
            (unknown.clone(), true),
            ([unknown.clone(), alloc::vec![0x05, 0]].concat(), true),
            ([unknown.clone(), alloc::vec![0x9f, 31, 0]].concat(), true),
            (Vec::new(), false),
            (wrap(T_OID, &[]), false),
            (wrap(T_OID, &[0x2a, 0x80, 1]), false),
            (wrap(T_OID, &[0x2a, 0x81]), false),
            (alloc::vec![0x05, 0], false),
            (
                [unknown.clone(), alloc::vec![0x05, 0, 0x05, 0]].concat(),
                false,
            ),
            (
                [unknown.clone(), alloc::vec![T_OCTET_STRING, 2, 1]].concat(),
                false,
            ),
            ([unknown, alloc::vec![0x9f, 30, 0]].concat(), false),
        ] {
            cases.push((wrap(T_SEQUENCE, &body), accepted, false));
        }
        for (algorithm, accepted, supported) in cases {
            let fixture = assemble(&[1], &algorithm, &algorithm, None, None);
            let mut outer = Der::new(&fixture);
            let mut list = outer.nested(T_SEQUENCE).unwrap();
            let tbs = list.expect_raw(T_SEQUENCE).unwrap();
            let signature = f
                .ca_key
                .sign(scheme, tbs, &mut ic_drbg::Rng::from_os().unwrap())
                .unwrap();
            sign::verify(
                scheme,
                &PublicKey::from_spki(f.ca_key.spki()).unwrap(),
                tbs,
                &signature,
            )
            .unwrap();
            let bits = [alloc::vec![0], signature].concat();
            let der = wrap(
                T_SEQUENCE,
                &[
                    tbs,
                    algorithm.as_slice(),
                    wrap(T_BIT_STRING, &bits).as_slice(),
                ]
                .concat(),
            );
            let result = parse(&der);
            let mut store = CrlStore::new();
            if accepted {
                let crl = result.unwrap();
                store.add_der(&der).unwrap();
                if supported {
                    assert_eq!(scheme_from_alg(&crl.sig_alg).unwrap(), scheme);
                } else {
                    assert_eq!(
                        scheme_from_alg(&crl.sig_alg).unwrap_err().kind(),
                        ErrorKind::UnsupportedCertificate
                    );
                }
            } else {
                assert_eq!(
                    result.err().unwrap().kind(),
                    ErrorKind::BadCertificateStatus
                );
                assert_eq!(
                    store.add_der(&der).unwrap_err().kind(),
                    ErrorKind::BadCertificateStatus
                );
            }
        }
    }

    /// REQ-CRL-004: every scope-narrowing extension, and any unknown
    /// critical one, is flagged where it appears (on the CRL or on an entry),
    /// through the parser. Known and non-critical unknown extensions are not.
    #[test]
    fn every_narrowing_or_unknown_critical_extension_is_flagged() {
        let alg = alg_id(SignatureScheme::EcdsaSecp384r1Sha384).unwrap();
        let unknown: &[u8] = &[0x2a, 0x03, 0x04];
        let on_crl = |exts: &[Vec<u8>]| {
            parse(&assemble(&[1], &alg, &alg, None, Some(&ext_list(exts))))
                .unwrap()
                .unsupported
        };
        let on_entry = |exts: &[Vec<u8>]| {
            parse(&assemble(&[1], &alg, &alg, Some(&ext_list(exts)), None))
                .unwrap()
                .unsupported
        };
        assert_eq!(
            on_crl(&[ext(OID_DELTA_CRL, true)]),
            Some("delta CRLs are not supported")
        );
        assert!(on_crl(&[ext(OID_IDP, true)])
            .unwrap()
            .contains("partitioned"));
        assert_eq!(
            on_crl(&[ext(unknown, true)]),
            Some("unknown critical CRL extension")
        );
        assert_eq!(on_crl(&[ext(unknown, false)]), None);
        assert_eq!(
            on_crl(&[ext(OID_CRL_NUMBER, false), ext(OID_AKI, false)]),
            None
        );
        assert_eq!(
            on_entry(&[ext(OID_CERT_ISSUER, true)]),
            Some("indirect CRLs are not supported")
        );
        assert_eq!(
            on_entry(&[ext(unknown, true)]),
            Some("unknown critical CRL extension")
        );
        assert_eq!(
            on_entry(&[ext(OID_REASON_CODE, false), ext(OID_INVALIDITY_DATE, false)]),
            None
        );
        // An entry-level-only extension on the CRL itself is unknown there.
        assert_eq!(
            on_crl(&[ext(OID_CERT_ISSUER, true)]),
            Some("unknown critical CRL extension")
        );
    }

    #[test]
    fn crl_optional_fields_are_unique_and_ordered() {
        let alg = alg_id(SignatureScheme::EcdsaSecp384r1Sha384).unwrap();
        let extensions = ext_list(&[ext(OID_AKI, false)]);
        let fixture = assemble(&[1], &alg, &alg, None, Some(&extensions));
        let mut outer = Der::new(&fixture).nested(T_SEQUENCE).unwrap();
        let raw_tbs = outer.expect_raw(T_SEQUENCE).unwrap();
        let mut tbs = Der::new(raw_tbs).nested(T_SEQUENCE).unwrap();
        let mut prefix = Vec::new();
        for _ in 0..4 {
            prefix.extend_from_slice(tbs.tlv().unwrap().2);
        }
        let fields: Vec<&[u8]> = (0..3).map(|_| tbs.tlv().unwrap().2).collect();
        let build = |order: &[usize], empty_entries: bool| {
            let mut body = prefix.clone();
            for i in order {
                if *i == 1 && empty_entries {
                    body.extend_from_slice(&[0x30, 0]);
                } else {
                    body.extend_from_slice(fields[*i]);
                }
            }
            let mut signed = Vec::new();
            push_tlv(&mut signed, T_SEQUENCE, &body);
            signed.extend_from_slice(&alg);
            push_tlv(&mut signed, T_BIT_STRING, &[0, 1, 2, 3]);
            let mut der = Vec::new();
            push_tlv(&mut der, T_SEQUENCE, &signed);
            der
        };
        for empty_entries in [false, true] {
            for order in [
                &[][..],
                &[0],
                &[1],
                &[2],
                &[0, 1],
                &[0, 2],
                &[1, 2],
                &[0, 1, 2],
            ] {
                assert!(parse(&build(order, empty_entries)).is_ok());
            }
            for order in [
                &[0, 0][..],
                &[1, 1],
                &[2, 2],
                &[1, 0],
                &[2, 0],
                &[2, 1],
                &[0, 2, 1],
            ] {
                assert_eq!(
                    parse(&build(order, empty_entries)).unwrap_err().kind(),
                    ErrorKind::BadCertificateStatus
                );
            }
        }
    }

    #[test]
    fn crl_extensions_require_version_two() {
        let alg = alg_id(SignatureScheme::EcdsaSecp384r1Sha384).unwrap();
        let extensions = ext_list(&[ext(OID_AKI, false)]);
        for entry_exts in [None, Some(extensions.as_slice())] {
            for crl_exts in [None, Some(extensions.as_slice())] {
                let v2 = assemble(&[1], &alg, &alg, entry_exts, crl_exts);
                assert!(parse(&v2).is_ok());
                let mut outer = Der::new(&v2).nested(T_SEQUENCE).unwrap();
                let raw_tbs = outer.expect_raw(T_SEQUENCE).unwrap();
                let mut tbs = Der::new(raw_tbs).nested(T_SEQUENCE).unwrap();
                tbs.expect(T_INTEGER).unwrap();
                let mut body = Vec::new();
                while !tbs.is_empty() {
                    body.extend_from_slice(tbs.tlv().unwrap().2);
                }
                let mut signed = Vec::new();
                push_tlv(&mut signed, T_SEQUENCE, &body);
                signed.extend_from_slice(&alg);
                push_tlv(&mut signed, T_BIT_STRING, &[0, 1, 2, 3]);
                let mut v1 = Vec::new();
                push_tlv(&mut v1, T_SEQUENCE, &signed);
                if entry_exts.is_none() && crl_exts.is_none() {
                    assert!(parse(&v1).is_ok());
                } else {
                    assert_eq!(
                        parse(&v1).unwrap_err().kind(),
                        ErrorKind::BadCertificateStatus
                    );
                }
            }
        }
    }

    #[test]
    fn revoked_serials_require_minimal_integer_encoding() {
        let f = fx();
        let mut rng = ic_drbg::Rng::from_os().unwrap();
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
            let valid = matches!(
                serial,
                [0] | [0x7f] | [0x80] | [0xff] | [0, 0x80] | [0xff, 0x7f]
            );
            let issued = build(
                &f.ca,
                &f.ca_key,
                &[(serial, f.now - 1)],
                f.now,
                f.now + 3600,
                1,
                &mut rng,
            );
            if valid {
                assert_eq!(parse(&issued.unwrap()).unwrap().revoked, [serial.to_vec()]);
            } else {
                assert_eq!(issued.unwrap_err().kind(), ErrorKind::BadCertificateStatus);
            }
            // Independently assemble an entry so the parser is tested even when
            // the issuer refuses to encode the malformed serial.
            let alg = alg_id(SignatureScheme::EcdsaSecp384r1Sha384).unwrap();
            let mut tbs = Vec::new();
            push_tlv(&mut tbs, T_INTEGER, &[1]);
            tbs.extend_from_slice(&alg);
            tbs.extend_from_slice(&x509::encode_name("Parser CRL Issuer"));
            encode_time(&mut tbs, f.now).unwrap();
            let mut entry = Vec::new();
            push_tlv(&mut entry, T_INTEGER, serial);
            encode_time(&mut entry, f.now - 1).unwrap();
            let mut entries = Vec::new();
            push_tlv(&mut entries, T_SEQUENCE, &entry);
            push_tlv(&mut tbs, T_SEQUENCE, &entries);
            let mut body = Vec::new();
            push_tlv(&mut body, T_SEQUENCE, &tbs);
            body.extend_from_slice(&alg);
            push_tlv(&mut body, T_BIT_STRING, &[0, 1]);
            let mut der = Vec::new();
            push_tlv(&mut der, T_SEQUENCE, &body);
            if valid {
                assert_eq!(parse(&der).unwrap().revoked, [serial.to_vec()]);
            } else {
                assert_eq!(
                    parse(&der).unwrap_err().kind(),
                    ErrorKind::BadCertificateStatus
                );
            }
        }
    }

    #[test]
    fn crl_issuer_names_require_complete_ordered_rdn_attributes() {
        let f = fx();
        let original = make(&f, &[], f.now, f.now + 60);
        let mut outer = Der::new(&original).nested(T_SEQUENCE).unwrap();
        let raw_tbs = outer.expect_raw(T_SEQUENCE).unwrap();
        let algorithm = outer.expect_raw(T_SEQUENCE).unwrap();
        let mut fields = Der::new(raw_tbs).nested(T_SEQUENCE).unwrap();
        let mut prefix = Vec::new();
        for _ in 0..2 {
            prefix.extend_from_slice(fields.tlv().unwrap().2);
        }
        fields.expect(T_SEQUENCE).unwrap();
        let mut tail = Vec::new();
        while !fields.is_empty() {
            tail.extend_from_slice(fields.tlv().unwrap().2);
        }
        let attribute = |oid: &[u8], value: &[u8]| {
            let mut body = Vec::new();
            push_tlv(&mut body, T_OID, oid);
            body.extend_from_slice(value);
            let mut out = Vec::new();
            push_tlv(&mut out, T_SEQUENCE, &body);
            out
        };
        let name = |attributes: &[u8]| {
            let mut rdn = Vec::new();
            push_tlv(&mut rdn, x509::T_SET, attributes);
            let mut out = Vec::new();
            push_tlv(&mut out, T_SEQUENCE, &rdn);
            out
        };
        let a = attribute(&[0x2a, 3], &[x509::T_NULL, 0]);
        let b = attribute(&[0x2a, 4], &[x509::T_NULL, 0]);
        let mut cases = alloc::vec![
            (x509::encode_name("CRL issuer fixture"), true),
            (x509::encode_name("É CRL issuer"), true),
            (name(&a), true),
            (name(&attribute(&[0x2a, 3], &[0x9f, 31, 0])), true),
            (name(&[a.clone(), b.clone()].concat()), true),
            (name(&[b, a].concat()), false),
            (alloc::vec![T_SEQUENCE, 0], false),
            (name(&[]), false),
            (alloc::vec![T_SEQUENCE, 2, T_SEQUENCE, 0], false),
            (name(&[T_SEQUENCE, 0]), false),
            (name(&[T_SEQUENCE, 2, x509::T_NULL, 0]), false),
        ];
        for oid in [&[][..], &[0x81][..], &[0x2a, 0x80, 0][..]] {
            cases.push((name(&attribute(oid, &[x509::T_NULL, 0])), false));
        }
        for value in [
            &[][..],
            &[x509::T_NULL][..],
            &[x509::T_NULL, 0, x509::T_NULL, 0][..],
            &[0, 0][..],
        ] {
            cases.push((name(&attribute(&[0x2a, 3], value)), false));
        }
        let scheme = f.ca_key.schemes()[0];
        let public_key = PublicKey::from_spki(f.ca_key.spki()).unwrap();
        let mut rng = ic_drbg::Rng::from_os().unwrap();
        for (issuer, accepted) in cases {
            let mut body = prefix.clone();
            body.extend_from_slice(&issuer);
            body.extend_from_slice(&tail);
            let mut tbs = Vec::new();
            push_tlv(&mut tbs, T_SEQUENCE, &body);
            let signature = f.ca_key.sign(scheme, &tbs, &mut rng).unwrap();
            sign::verify(scheme, &public_key, &tbs, &signature).unwrap();
            let mut content = tbs;
            content.extend_from_slice(algorithm);
            let mut bits = alloc::vec![0];
            bits.extend_from_slice(&signature);
            push_tlv(&mut content, T_BIT_STRING, &bits);
            let mut encoded = Vec::new();
            push_tlv(&mut encoded, T_SEQUENCE, &content);
            let mut store = CrlStore::new();
            if accepted {
                assert_eq!(parse(&encoded).unwrap().issuer, issuer);
                store.add_der(&encoded).unwrap();
            } else {
                assert_eq!(
                    parse(&encoded).err().unwrap().kind(),
                    ErrorKind::BadCertificateStatus
                );
                assert_eq!(
                    store.add_der(&encoded).unwrap_err().kind(),
                    ErrorKind::BadCertificateStatus
                );
            }
        }
    }

    #[test]
    fn crl_issuer_names_must_be_nonempty() {
        let alg = alg_id(SignatureScheme::EcdsaSecp384r1Sha384).unwrap();
        let valid = assemble(&[1], &alg, &alg, None, None);
        assert!(parse(&valid).is_ok());
        let mut outer = Der::new(&valid).nested(T_SEQUENCE).unwrap();
        let raw_tbs = outer.expect_raw(T_SEQUENCE).unwrap();
        let mut fields = Der::new(raw_tbs).nested(T_SEQUENCE).unwrap();
        let mut body = Vec::new();
        for _ in 0..2 {
            body.extend_from_slice(fields.tlv().unwrap().2);
        }
        fields.expect(T_SEQUENCE).unwrap();
        push_tlv(&mut body, T_SEQUENCE, &[]);
        while !fields.is_empty() {
            body.extend_from_slice(fields.tlv().unwrap().2);
        }
        let mut signed = Vec::new();
        push_tlv(&mut signed, T_SEQUENCE, &body);
        signed.extend_from_slice(&alg);
        push_tlv(&mut signed, T_BIT_STRING, &[0, 1]);
        let mut der = Vec::new();
        push_tlv(&mut der, T_SEQUENCE, &signed);
        let error = parse(&der).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::BadCertificateStatus);
        assert_eq!(error.context(), "empty CRL issuer name");
    }

    /// The parser refuses a CRL whose version is not v2, whose inner and
    /// outer signature algorithms differ, or whose entry extensions are not a
    /// SEQUENCE.
    #[test]
    fn malformed_crls_are_refused_by_the_parser() {
        let p384 = alg_id(SignatureScheme::EcdsaSecp384r1Sha384).unwrap();
        let p256 = alg_id(SignatureScheme::EcdsaSecp256r1Sha256).unwrap();
        let msg = |der: Vec<u8>| parse(&der).err().map(|e| e.to_string()).unwrap_or_default();
        assert!(parse(&assemble(&[1], &p384, &p384, None, None)).is_ok());
        assert!(msg(assemble(&[2], &p384, &p384, None, None)).contains("unknown CRL version"));
        assert!(
            msg(assemble(&[1], &p256, &p384, None, None)).contains("signature algorithm differs")
        );
        let not_a_sequence = [0x04, 0x01, 0x00];
        assert!(
            msg(assemble(&[1], &p384, &p384, Some(&not_a_sequence), None))
                .contains("malformed CRL entry extensions")
        );
    }
}
