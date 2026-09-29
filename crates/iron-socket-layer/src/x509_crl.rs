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
    alg_id, encode_time, parse_time, push_tlv, scheme_from_alg, whole_bits, Certificate, Der,
    KU_CRL_SIGN, T_BIT_STRING, T_BOOLEAN, T_CTX0, T_INTEGER, T_OCTET_STRING, T_OID, T_SEQUENCE,
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

/// Is an extensions block acceptable, and does it narrow the CRL's scope?
fn scan_extensions(body: &[u8], entry: bool) -> Result<Option<&'static str>> {
    let mut list = Der::new(body).nested(T_SEQUENCE)?;
    let mut unsupported = None;
    while !list.is_empty() {
        let mut e = list.nested(T_SEQUENCE)?;
        let oid = e.expect(T_OID)?;
        let critical = matches!(e.optional(T_BOOLEAN)?, Some([0xff]));
        let _ = e.expect(T_OCTET_STRING)?;
        e.finish()?;
        match (entry, oid) {
            (false, OID_CRL_NUMBER | OID_AKI) | (true, OID_REASON_CODE | OID_INVALIDITY_DATE) => {}
            (false, OID_DELTA_CRL) => unsupported = Some("delta CRLs are not supported"),
            (false, OID_IDP) => {
                unsupported = Some("partitioned CRLs (issuingDistributionPoint) are not supported")
            }
            (true, OID_CERT_ISSUER) => unsupported = Some("indirect CRLs are not supported"),
            _ if critical => unsupported = Some("unknown critical CRL extension"),
            _ => {}
        }
    }
    Ok(unsupported)
}

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
    if t.peek() == Some(T_INTEGER) {
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
    let issuer = t.expect_raw(T_SEQUENCE).map_err(wrap)?;
    let (tag, v, _) = t.tlv().map_err(wrap)?;
    let this_update = parse_time(tag, v).map_err(wrap)?;
    let mut next_update = None;
    let mut revoked = Vec::new();
    let mut unsupported = None;
    while !t.is_empty() {
        let (tag, v, _) = t.tlv().map_err(wrap)?;
        match tag {
            0x17 | 0x18 if next_update.is_none() && revoked.is_empty() => {
                next_update = Some(parse_time(tag, v).map_err(wrap)?);
            }
            T_SEQUENCE => {
                let mut entries = Der::new(v);
                while !entries.is_empty() {
                    let mut entry = entries.nested(T_SEQUENCE).map_err(wrap)?;
                    let serial = entry.expect(T_INTEGER).map_err(wrap)?;
                    let (tt, tv, _) = entry.tlv().map_err(wrap)?;
                    parse_time(tt, tv).map_err(wrap)?;
                    if !entry.is_empty() {
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
                Some(n) => now <= n.saturating_add(MAX_SKEW),
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
pub fn build(
    issuer_cert_der: &[u8],
    issuer_key: &SigningKey,
    revoked: &[(&[u8], u64)],
    this_update: u64,
    next_update: u64,
    crl_number: u64,
    rng: &mut dyn RandomSource,
) -> Result<Vec<u8>> {
    let issuer = Certificate::parse(issuer_cert_der)?;
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
            push_tlv(&mut e, T_OCTET_STRING, &[0x30, 0x00]);
            let mut one = Vec::new();
            push_tlv(&mut one, T_SEQUENCE, &e);
            let mut list = Vec::new();
            push_tlv(&mut list, T_SEQUENCE, &one);
            assert!(scan_extensions(&list, false).unwrap().is_some());
        }
    }

    /// One extension, optionally critical, with a placeholder value.
    fn ext(oid: &[u8], critical: bool) -> Vec<u8> {
        let mut e = Vec::new();
        push_tlv(&mut e, T_OID, oid);
        if critical {
            push_tlv(&mut e, T_BOOLEAN, &[0xff]);
        }
        push_tlv(&mut e, T_OCTET_STRING, &[0x05, 0x00]);
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
        tbs.extend_from_slice(&[0x30, 0x00]); // issuer: an empty Name
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
