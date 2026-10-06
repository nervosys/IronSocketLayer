//! X.509 certificates: parsing, path validation, name matching, and issuance.
//!
//! # What is checked
//!
//! [`verify_chain`] builds a path from the end-entity certificate to a trust
//! anchor in a [`RootStore`] by exact issuer/subject DER comparison, trying
//! every candidate issuer under a fixed work budget, and never revisiting a
//! certificate already on the path, so cross-signed cycles terminate. Along the
//! path it checks, per RFC 5280 §6 as profiled for TLS:
//!
//! - every link's signature, under a scheme the caller allows;
//! - the validity period of every presented certificate (the anchor itself is
//!   configuration, not a presented certificate, and its dates are not checked);
//! - `basicConstraints` `cA` and `pathLenConstraint` on every issuer;
//! - `keyUsage` (`keyCertSign` on issuers, `digitalSignature` on the leaf) when
//!   present;
//! - `extendedKeyUsage` on the leaf and on intermediates, when present;
//! - that no certificate on the path carries a critical extension this module
//!   does not understand;
//! - `nameConstraints` for `dNSName` and `iPAddress` subtrees, from
//!   intermediates and from anchors. Any other name form in a constraint
//!   (directory names, e-mail, URIs) fails the path closed, because a constraint
//!   that is not evaluated would be a constraint silently ignored;
//! - RSA moduli against a minimum size.
//!
//! # What is not
//!
//! Revocation (CRL, OCSP, CRLite) is out of scope. Certificate policies are not
//! processed: `certificatePolicies` is recognised so a critical instance does
//! not fail the path, which is correct because no explicit policy is ever
//! required; `policyConstraints` and `inhibitAnyPolicy` are unknown, so a
//! critical instance fails closed. Subject common names are never used for name
//! matching; [`Certificate::common_name`] exists for reports only.
//!
//! Requirement trace: `REQ-X509-001` (no panic on any input), `REQ-X509-002`
//! (path search terminates), `REQ-X509-003` (no CN fallback), `REQ-X509-004`
//! (unknown critical extensions fail closed), `REQ-X509-005` (only allowed
//! signature schemes are accepted).

use alloc::string::String;
use alloc::vec::Vec;

use ic_core::traits::RandomSource;

use crate::crypto::sign::{
    self, push_tlv, PublicKey, SigningKey, OID_ML_DSA_44, OID_ML_DSA_65, OID_ML_DSA_87,
};
use crate::crypto::HashAlg;
use crate::enums::SignatureScheme;
use crate::error::{Error, ErrorKind, Result};

// ---------------------------------------------------------------------------
// Object identifiers (content bytes)
// ---------------------------------------------------------------------------

#[path = "x509_crl.rs"]
pub mod crl;
#[path = "x509_ocsp.rs"]
pub mod ocsp;

const OID_ECDSA_SHA1: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x01];
const OID_ECDSA_SHA256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
const OID_ECDSA_SHA384: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03];
const OID_ECDSA_SHA512: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x04];
const OID_RSA_SHA1: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05];
const OID_RSA_PSS: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a];
const OID_RSA_SHA256: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b];
const OID_RSA_SHA384: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c];
const OID_RSA_SHA512: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0d];
const OID_MGF1: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x08];
const OID_SHA256: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
const OID_SHA384: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02];
const OID_SHA512: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03];
const OID_ED25519: &[u8] = &[0x2b, 0x65, 0x70];

const OID_CN: &[u8] = &[0x55, 0x04, 0x03];

const OID_EXT_SKI: &[u8] = &[0x55, 0x1d, 0x0e];
const OID_EXT_KU: &[u8] = &[0x55, 0x1d, 0x0f];
const OID_EXT_SAN: &[u8] = &[0x55, 0x1d, 0x11];
const OID_EXT_BC: &[u8] = &[0x55, 0x1d, 0x13];
const OID_EXT_NC: &[u8] = &[0x55, 0x1d, 0x1e];
const OID_EXT_CP: &[u8] = &[0x55, 0x1d, 0x20];
const OID_EXT_AKI: &[u8] = &[0x55, 0x1d, 0x23];
const OID_EXT_EKU: &[u8] = &[0x55, 0x1d, 0x25];

const OID_KP_SERVER_AUTH: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01];
const OID_KP_CLIENT_AUTH: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02];
const OID_ANY_EKU: &[u8] = &[0x55, 0x1d, 0x25, 0x00];

// DER tags.
const T_BOOLEAN: u8 = 0x01;
const T_INTEGER: u8 = 0x02;
const T_BIT_STRING: u8 = 0x03;
const T_OCTET_STRING: u8 = 0x04;
const T_NULL: u8 = 0x05;
const T_OID: u8 = 0x06;
const T_UTF8: u8 = 0x0c;
const T_PRINTABLE: u8 = 0x13;
const T_T61: u8 = 0x14;
const T_IA5: u8 = 0x16;
const T_UTC_TIME: u8 = 0x17;
const T_GENERALIZED_TIME: u8 = 0x18;
const T_SEQUENCE: u8 = 0x30;
const T_SET: u8 = 0x31;
const T_CTX0: u8 = 0xa0;
const T_CTX1: u8 = 0xa1;
const T_CTX2: u8 = 0xa2;
const T_CTX3: u8 = 0xa3;
const T_ISSUER_UID: u8 = 0x81;
const T_SUBJECT_UID: u8 = 0x82;
const T_GN_DNS: u8 = 0x82;
const T_GN_IP: u8 = 0x87;

// keyUsage bit positions (RFC 5280 §4.2.1.3).
const KU_DIGITAL_SIGNATURE: u16 = 1 << 0;
const KU_KEY_CERT_SIGN: u16 = 1 << 5;
const KU_CRL_SIGN: u16 = 1 << 6;

/// Work bound on path search: signature verifications and candidate visits.
// Every unit of the budget is spent on one signature verification, the
// dominant cost: 24 is three times the deepest path allowed (max_depth 8),
// and bounds what a peer's crafted chain can cost. At 100, a 5 KB chain of
// same-key P-521 intermediates cost a server about 73 ms. `REQ-X509-076`.
const SEARCH_BUDGET: usize = 24;

fn bad(context: &'static str) -> Error {
    Error::new(ErrorKind::BadCertificate, context)
}

// ---------------------------------------------------------------------------
// A strict DER reader that can also return whole TLVs
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct Der<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Der<'a> {
    fn rest(&self) -> &'a [u8] {
        &self.buf[self.pos..]
    }
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn is_empty(&self) -> bool {
        self.pos >= self.buf.len()
    }

    fn peek(&self) -> Option<u8> {
        self.buf.get(self.pos).copied()
    }

    fn byte(&mut self) -> Result<u8> {
        let b = *self.buf.get(self.pos).ok_or(bad("truncated DER"))?;
        self.pos += 1;
        Ok(b)
    }

    /// Next element: `(tag, content, whole TLV)`.
    fn tlv(&mut self) -> Result<(u8, &'a [u8], &'a [u8])> {
        self.tlv_inner(false)
    }

    /// REQ-X509-033: opaque otherName values retain valid high-numbered identifiers.
    fn any(&mut self) -> Result<()> {
        let (tag, _, _) = self.tlv_inner(true)?;
        if tag & 0xdf == 0 {
            return Err(bad("end-of-contents is not a DER value"));
        }
        Ok(())
    }

    fn tlv_inner(&mut self, allow_high_tags: bool) -> Result<(u8, &'a [u8], &'a [u8])> {
        let start = self.pos;
        let tag = self.byte()?;
        if tag & 0x1f == 0x1f {
            if !allow_high_tags {
                return Err(bad("high-tag-number DER form"));
            }
            let first = self.byte()?;
            if first & 0x7f == 0 || first < 31 {
                return Err(bad("nonminimal DER tag number"));
            }
            let mut octet = first;
            while octet & 0x80 != 0 {
                octet = self.byte()?;
            }
        }
        let first = self.byte()?;
        let len = if first < 0x80 {
            first as usize
        } else {
            let n = (first & 0x7f) as usize;
            if n == 0 || n > 4 {
                return Err(bad("unsupported DER length form"));
            }
            let mut len = 0usize;
            for i in 0..n {
                let b = self.byte()?;
                if i == 0 && b == 0 {
                    return Err(bad("non-minimal DER length"));
                }
                len = (len << 8) | b as usize;
            }
            if len < 0x80 {
                return Err(bad("non-minimal DER length"));
            }
            len
        };
        let end = self
            .pos
            .checked_add(len)
            .ok_or(bad("DER length overflow"))?;
        let content = self
            .buf
            .get(self.pos..end)
            .ok_or(bad("DER value runs past its parent"))?;
        let whole = self
            .buf
            .get(start..end)
            .ok_or(bad("DER value runs past its parent"))?;
        self.pos = end;
        Ok((tag, content, whole))
    }

    fn expect(&mut self, tag: u8) -> Result<&'a [u8]> {
        let (t, content, _) = self.tlv()?;
        if t != tag {
            return Err(bad("unexpected DER tag"));
        }
        Ok(content)
    }

    fn expect_raw(&mut self, tag: u8) -> Result<&'a [u8]> {
        let (t, _, whole) = self.tlv()?;
        if t != tag {
            return Err(bad("unexpected DER tag"));
        }
        Ok(whole)
    }

    fn nested(&mut self, tag: u8) -> Result<Der<'a>> {
        Ok(Der::new(self.expect(tag)?))
    }

    fn optional(&mut self, tag: u8) -> Result<Option<&'a [u8]>> {
        if self.peek() == Some(tag) {
            Ok(Some(self.expect(tag)?))
        } else {
            Ok(None)
        }
    }

    fn optional_null(&mut self) -> Result<()> {
        if let Some(c) = self.optional(T_NULL)? {
            if !c.is_empty() {
                return Err(bad("NULL with content"));
            }
        }
        Ok(())
    }

    fn finish(&self) -> Result<()> {
        if self.is_empty() {
            Ok(())
        } else {
            Err(bad("trailing DER data"))
        }
    }
}

/// Content of a `BIT STRING` that must hold whole bytes.
fn whole_bits(content: &[u8]) -> Result<&[u8]> {
    match content.split_first() {
        Some((0, rest)) => Ok(rest),
        _ => Err(bad("BIT STRING with unused bits")),
    }
}

/// REQ-X509-031: registeredID SAN OIDs have nonempty, complete, minimal subidentifiers.
fn check_oid_encoding(content: &[u8]) -> Result<()> {
    if content.is_empty() {
        return Err(bad("empty OBJECT IDENTIFIER"));
    }
    let mut arc_start = true;
    for &byte in content {
        if arc_start && byte == 0x80 {
            return Err(bad("nonminimal OBJECT IDENTIFIER subidentifier"));
        }
        arc_start = byte & 0x80 == 0;
    }
    if !arc_start {
        return Err(bad("truncated OBJECT IDENTIFIER subidentifier"));
    }
    Ok(())
}

/// REQ-X509-033: otherName has a valid type OID and one explicitly wrapped value.
fn check_other_name(content: &[u8]) -> Result<()> {
    let mut name = Der::new(content);
    check_oid_encoding(name.expect(T_OID)?)?;
    let mut value = name.nested(T_CTX0)?;
    name.finish()?;
    value.any()?;
    value.finish()?;
    Ok(())
}

/// REQ-X509-034: EDI party fields contain one nonempty DirectoryString choice.
/// REQ-X509-035: UTF8String EDI fields contain well-formed UTF-8.
/// REQ-X509-036: PrintableString EDI fields use only the ASN.1 character repertoire.
/// REQ-X509-037: BMPString and UniversalString EDI fields contain complete code units.
/// REQ-X509-069: BMPString EDI fields exclude surrogate code units and FFFE/FFFF.
/// REQ-X509-070: UniversalString EDI code units exclude surrogates and values above U+10FFFF.
fn check_directory_string(content: &[u8]) -> Result<()> {
    let mut string = Der::new(content);
    let (tag, value, _) = string.tlv()?;
    if !matches!(tag, T_T61 | T_PRINTABLE | 0x1c | T_UTF8 | 0x1e) {
        return Err(bad("invalid DirectoryString choice"));
    }
    if value.is_empty() {
        return Err(bad("empty DirectoryString"));
    }
    if tag == T_UTF8 && core::str::from_utf8(value).is_err() {
        return Err(bad("invalid DirectoryString UTF-8"));
    }
    if tag == T_PRINTABLE
        && value
            .iter()
            .any(|byte| !byte.is_ascii_alphanumeric() && !b" '()+,-./:=?".contains(byte))
    {
        return Err(bad("invalid DirectoryString PrintableString character"));
    }
    if (tag == 0x1e && value.len() % 2 != 0) || (tag == 0x1c && value.len() % 4 != 0) {
        return Err(bad("incomplete DirectoryString code unit"));
    }
    if tag == 0x1e
        && value.as_chunks::<2>().0.iter().any(|unit| {
            let code = u16::from_be_bytes(*unit);
            matches!(code, 0xd800..=0xdfff | 0xfffe..=0xffff)
        })
    {
        return Err(bad("invalid DirectoryString BMPString character"));
    }
    if tag == 0x1c
        && value.as_chunks::<4>().0.iter().any(|unit| {
            let code = u32::from_be_bytes(*unit);
            matches!(code, 0xd800..=0xdfff) || code > 0x10ffff
        })
    {
        return Err(bad("invalid DirectoryString UniversalString code point"));
    }
    string.finish()?;
    Ok(())
}

/// REQ-X509-034: ediPartyName has an optional assigner followed by a required party.
fn check_edi_party_name(content: &[u8]) -> Result<()> {
    let mut name = Der::new(content);
    if let Some(assigner) = name.optional(T_CTX0)? {
        check_directory_string(assigner)?;
    }
    check_directory_string(name.expect(T_CTX1)?)?;
    name.finish()?;
    Ok(())
}

/// REQ-X509-038: directoryName SANs have nonempty RDN sets and complete attributes.
fn check_directory_name(content: &[u8]) -> Result<()> {
    let mut wrapper = Der::new(content);
    let body = wrapper.expect(T_SEQUENCE)?;
    wrapper.finish()?;
    if body.is_empty() {
        return Err(bad("empty directoryName SAN"));
    }
    check_rdn_sequence(body)
}

/// REQ-X509-038: RDN sets are nonempty and attribute fields are fully consumed.
/// REQ-X509-039: RDN attributes follow DER SET OF encoding order.
/// REQ-X509-040: certificate issuer and subject Names use the same RDN validation.
fn check_rdn_sequence(body: &[u8]) -> Result<()> {
    let mut name = Der::new(body);
    while !name.is_empty() {
        check_relative_distinguished_name(name.expect(T_SET)?)?;
    }
    Ok(())
}

/// REQ-X509-038, REQ-X509-039: validate one RDN's nonempty, ordered attributes
/// independently of whether it appears in a Name or as an implicit RDN choice.
fn check_relative_distinguished_name(body: &[u8]) -> Result<()> {
    let mut rdn = Der::new(body);
    if rdn.is_empty() {
        return Err(bad("empty Name RDN"));
    }
    let mut previous: Option<&[u8]> = None;
    while !rdn.is_empty() {
        let encoded = rdn.expect_raw(T_SEQUENCE)?;
        // Complete, minimally encoded TLVs cannot be prefixes of each other,
        // so slice ordering agrees with X.690's zero-padded octet comparison.
        if previous.is_some_and(|prev| prev > encoded) {
            return Err(bad("Name RDN attributes are not in DER order"));
        }
        previous = Some(encoded);
        let mut attribute_der = Der::new(encoded);
        let mut attribute = attribute_der.nested(T_SEQUENCE)?;
        check_oid_encoding(attribute.expect(T_OID)?)?;
        attribute.any()?;
        attribute.finish()?;
    }
    Ok(())
}

/// REQ-X509-028: nonnegative DER integers use minimal sign encoding.
fn small_uint(content: &[u8]) -> Result<u64> {
    if content.is_empty() || content[0] & 0x80 != 0 {
        return Err(bad("expected a non-negative INTEGER"));
    }
    if let [0, second, ..] = content {
        if second & 0x80 == 0 {
            return Err(bad("nonminimal non-negative INTEGER"));
        }
    }
    let digits = if content[0] == 0 && content.len() > 1 {
        &content[1..]
    } else {
        content
    };
    if digits.len() > 8 {
        return Err(bad("INTEGER too large"));
    }
    Ok(digits.iter().fold(0u64, |acc, b| (acc << 8) | *b as u64))
}

// ---------------------------------------------------------------------------
// Time
// ---------------------------------------------------------------------------

/// Days since 1970-01-01 of a proleptic Gregorian date (Hinnant's algorithm).
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m as i64 + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m, d)
}

fn is_leap(y: i64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

fn digits(s: &[u8]) -> Result<u32> {
    let mut v = 0u32;
    for &c in s {
        if !c.is_ascii_digit() {
            return Err(bad("non-digit in time"));
        }
        v = v * 10 + (c - b'0') as u32;
    }
    Ok(v)
}

/// Parse `UTCTime` or `GeneralizedTime` to Unix seconds (clamped at 0).
fn parse_time(tag: u8, s: &[u8]) -> Result<u64> {
    let (year, rest) = match (tag, s.len()) {
        (T_UTC_TIME, 13) => {
            let yy = digits(&s[..2])? as i64;
            (if yy >= 50 { 1900 + yy } else { 2000 + yy }, &s[2..])
        }
        (T_GENERALIZED_TIME, 15) => (digits(&s[..4])? as i64, &s[4..]),
        _ => return Err(bad("time must be YYMMDDHHMMSSZ or YYYYMMDDHHMMSSZ")),
    };
    if rest[10] != b'Z' {
        return Err(bad("time must be in UTC"));
    }
    let month = digits(&rest[0..2])?;
    let day = digits(&rest[2..4])?;
    let hour = digits(&rest[4..6])?;
    let min = digits(&rest[6..8])?;
    let sec = digits(&rest[8..10])?;
    let dim = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap(year) => 29,
        2 => 28,
        _ => return Err(bad("month out of range")),
    };
    if day == 0 || day > dim || hour > 23 || min > 59 || sec > 59 {
        return Err(bad("time field out of range"));
    }
    let secs = days_from_civil(year, month, day) * 86_400
        + hour as i64 * 3600
        + min as i64 * 60
        + sec as i64;
    Ok(secs.max(0) as u64)
}

fn encode_time(out: &mut Vec<u8>, t: u64) -> Result<()> {
    let days = (t / 86_400) as i64;
    let rem = t % 86_400;
    let (y, m, d) = civil_from_days(days);
    if y > 9999 {
        return Err(Error::new(
            ErrorKind::InvalidConfig,
            "certificate time beyond year 9999",
        ));
    }
    let (h, mi, s) = (rem / 3600, (rem / 60) % 60, rem % 60);
    let body = if (1950..2050).contains(&y) {
        alloc::format!("{:02}{:02}{:02}{:02}{:02}{:02}Z", y % 100, m, d, h, mi, s)
    } else {
        alloc::format!("{:04}{:02}{:02}{:02}{:02}{:02}Z", y, m, d, h, mi, s)
    };
    let tag = if body.len() == 13 {
        T_UTC_TIME
    } else {
        T_GENERALIZED_TIME
    };
    push_tlv(out, tag, body.as_bytes());
    Ok(())
}

// ---------------------------------------------------------------------------
// Names and addresses
// ---------------------------------------------------------------------------

/// An IP address, as it appears in an `iPAddress` subject alternative name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IpAddr {
    /// IPv4.
    V4([u8; 4]),
    /// IPv6.
    V6([u8; 16]),
}

impl IpAddr {
    /// The address octets.
    pub fn octets(&self) -> &[u8] {
        match self {
            Self::V4(a) => a,
            Self::V6(a) => a,
        }
    }

    /// Parse dotted-quad IPv4 or RFC 4291 IPv6 text (optionally in brackets).
    pub fn parse(s: &str) -> Option<Self> {
        if let Some(v4) = parse_ipv4(s) {
            return Some(Self::V4(v4));
        }
        let s = s
            .strip_prefix('[')
            .and_then(|x| x.strip_suffix(']'))
            .unwrap_or(s);
        parse_ipv6(s).map(Self::V6)
    }
}

/// Dotted-quad IPv4, or IPv6 in RFC 5952 form (lowercase, the longest run
/// of two or more zero groups, the first if tied, as `::`).
impl core::fmt::Display for IpAddr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::V4(a) => write!(f, "{}.{}.{}.{}", a[0], a[1], a[2], a[3]),
            Self::V6(a) => {
                let g: [u16; 8] =
                    core::array::from_fn(|i| u16::from_be_bytes([a[2 * i], a[2 * i + 1]]));
                let (mut best, mut best_len, mut i) = (0, 0, 0);
                while i < 8 {
                    let start = i;
                    while i < 8 && g[i] == 0 {
                        i += 1;
                    }
                    if i - start > best_len {
                        (best, best_len) = (start, i - start);
                    }
                    i += 1;
                }
                let mut i = 0;
                while i < 8 {
                    if best_len >= 2 && i == best {
                        f.write_str(if i == 0 { "::" } else { ":" })?;
                        i += best_len;
                        continue;
                    }
                    write!(f, "{:x}", g[i])?;
                    if i < 7 {
                        f.write_str(":")?;
                    }
                    i += 1;
                }
                Ok(())
            }
        }
    }
}

fn parse_ipv4(s: &str) -> Option<[u8; 4]> {
    let mut out = [0u8; 4];
    let mut parts = s.split('.');
    for slot in out.iter_mut() {
        let p = parts.next()?;
        if p.is_empty() || p.len() > 3 || !p.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        if p.len() > 1 && p.starts_with('0') {
            return None; // octal ambiguity
        }
        let v: u32 = p.parse().ok()?;
        *slot = u8::try_from(v).ok()?;
    }
    if parts.next().is_some() {
        return None;
    }
    Some(out)
}

fn parse_ipv6(s: &str) -> Option<[u8; 16]> {
    if s.is_empty() || !s.contains(':') {
        return None;
    }
    let (head, tail) = match s.find("::") {
        Some(i) => (&s[..i], Some(&s[i + 2..])),
        None => (s, None),
    };
    if let Some(t) = tail {
        if t.contains("::") {
            return None;
        }
    }
    fn groups(part: &str, allow_v4_tail: bool) -> Option<Vec<u16>> {
        let mut v = Vec::new();
        if part.is_empty() {
            return Some(v);
        }
        let pieces: Vec<&str> = part.split(':').collect();
        for (i, p) in pieces.iter().enumerate() {
            if allow_v4_tail && i == pieces.len() - 1 && p.contains('.') {
                let a = parse_ipv4(p)?;
                v.push(u16::from_be_bytes([a[0], a[1]]));
                v.push(u16::from_be_bytes([a[2], a[3]]));
            } else {
                if p.is_empty() || p.len() > 4 {
                    return None;
                }
                // RFC 4291 section 2.2: hexadecimal digits only;
                // from_str_radix alone would also take a leading '+'.
                if !p.bytes().all(|b| b.is_ascii_hexdigit()) {
                    return None;
                }
                v.push(u16::from_str_radix(p, 16).ok()?);
            }
        }
        Some(v)
    }
    let words: Vec<u16> = match tail {
        None => {
            let g = groups(head, true)?;
            if g.len() != 8 {
                return None;
            }
            g
        }
        Some(t) => {
            let h = groups(head, false)?;
            let tl = groups(t, true)?;
            if h.len() + tl.len() > 7 {
                return None;
            }
            let mut w = h;
            w.resize(8 - tl.len(), 0);
            w.extend_from_slice(&tl);
            w
        }
    };
    let mut out = [0u8; 16];
    for (i, w) in words.iter().enumerate() {
        out[2 * i..2 * i + 2].copy_from_slice(&w.to_be_bytes());
    }
    Some(out)
}

/// The name a connection is for: what the certificate must cover.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerName<'a> {
    /// A DNS host name, without a trailing dot.
    Dns(&'a str),
    /// An IP address.
    Ip(IpAddr),
}

impl<'a> ServerName<'a> {
    /// Parse a reference identifier: an IP address if it is one, otherwise a
    /// syntactically valid DNS name. A single trailing dot is removed.
    pub fn parse(s: &'a str) -> Result<Self> {
        if let Some(ip) = IpAddr::parse(s) {
            return Ok(Self::Ip(ip));
        }
        let name = s.strip_suffix('.').unwrap_or(s);
        if !is_valid_dns_name(name, false) {
            return Err(Error::new(
                ErrorKind::InvalidConfig,
                "not a valid DNS name or IP address",
            ));
        }
        Ok(Self::Dns(name))
    }
}

fn is_valid_dns_name(name: &str, allow_wildcard: bool) -> bool {
    if name.is_empty() || name.len() > 253 {
        return false;
    }
    name.split('.').enumerate().all(|(i, label)| {
        if allow_wildcard && i == 0 && label == "*" {
            return true;
        }
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    })
}

/// The purpose a certificate is being verified for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Usage {
    /// A TLS server (id-kp-serverAuth).
    ServerAuth,
    /// A TLS client (id-kp-clientAuth).
    ClientAuth,
}

impl Usage {
    const fn oid(self) -> &'static [u8] {
        match self {
            Self::ServerAuth => OID_KP_SERVER_AUTH,
            Self::ClientAuth => OID_KP_CLIENT_AUTH,
        }
    }
}

fn name_common_name(name_der: &[u8]) -> Option<&str> {
    let mut outer = Der::new(name_der);
    let mut rdns = outer.nested(T_SEQUENCE).ok()?;
    let mut found = None;
    while !rdns.is_empty() {
        let mut set = rdns.nested(T_SET).ok()?;
        while !set.is_empty() {
            let mut atv = set.nested(T_SEQUENCE).ok()?;
            let oid = atv.expect(T_OID).ok()?;
            let (tag, value, _) = atv.tlv().ok()?;
            if oid == OID_CN && matches!(tag, T_UTF8 | T_PRINTABLE | T_IA5 | T_T61) {
                found = core::str::from_utf8(value).ok();
            }
        }
    }
    found
}

// ---------------------------------------------------------------------------
// Certificates
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, Default)]
struct Extensions<'a> {
    count: usize,
    basic: Option<(bool, Option<u64>)>,
    key_usage: Option<u16>,
    eku: Option<&'a [u8]>,
    san: Option<&'a [u8]>,
    san_critical: bool,
    name_constraints: Option<&'a [u8]>,
    ski: Option<&'a [u8]>,
    aki: Option<&'a [u8]>,
    unknown_critical: bool,
}

/// A parsed certificate, borrowing from its DER.
#[derive(Debug, Clone)]
pub struct Certificate<'a> {
    der: &'a [u8],
    tbs: &'a [u8],
    sig_alg: &'a [u8],
    signature: &'a [u8],
    serial: &'a [u8],
    issuer: &'a [u8],
    subject: &'a [u8],
    spki: &'a [u8],
    not_before: u64,
    not_after: u64,
    ext: Extensions<'a>,
}

/// REQ-X509-012: implicit unique-ID BIT STRINGs have an unused-bit count
/// in 0..=7, no unused bits without content, and zero padding bits.
fn check_unique_id(content: &[u8]) -> Result<()> {
    let (unused, bytes) = content
        .split_first()
        .ok_or(bad("empty unique identifier"))?;
    if *unused > 7 {
        return Err(bad("invalid unique identifier unused-bit count"));
    }
    match bytes.last() {
        None if *unused != 0 => Err(bad("unique identifier padding without bits")),
        Some(last) if last & ((1u8 << unused) - 1) != 0 => {
            Err(bad("nonzero unique identifier padding bits"))
        }
        _ => Ok(()),
    }
}

impl<'a> Certificate<'a> {
    /// REQ-X509-011: unique identifiers appear only in v2 or v3 certificates.
    /// REQ-X509-013: serial INTEGERs have no redundant sign-extension octets.
    /// REQ-X509-019: the issuer Name is nonempty.
    /// REQ-X509-040: issuer and subject RDNs and attribute fields are validated.
    /// REQ-X509-053: an empty subject requires a present critical SAN.
    /// REQ-X509-065: received validity intervals cannot end before they begin.
    /// Parse a DER certificate. `REQ-X509-001`: any malformed input is
    /// [`ErrorKind::BadCertificate`], never a panic.
    pub fn parse(der: &'a [u8]) -> Result<Self> {
        let mut outer = Der::new(der);
        let mut cert = outer.nested(T_SEQUENCE)?;
        outer.finish()?;
        let tbs = cert.expect_raw(T_SEQUENCE)?;
        let sig_alg = cert.expect(T_SEQUENCE)?;
        let signature = whole_bits(cert.expect(T_BIT_STRING)?)?;
        cert.finish()?;

        let mut t = Der::new(tbs).nested(T_SEQUENCE)?;
        let version = match t.optional(T_CTX0)? {
            Some(v) => {
                let mut v = Der::new(v);
                let n = small_uint(v.expect(T_INTEGER)?)?;
                v.finish()?;
                if n > 2 {
                    return Err(bad("unknown certificate version"));
                }
                // REQ-X509-077: v1 is the DEFAULT, which DER omits (X.690
                // §11.5); an explicit v1 is not a DER encoding.
                if n == 0 {
                    return Err(bad("explicitly encoded default version"));
                }
                n
            }
            None => 0,
        };
        let serial = t.expect(T_INTEGER)?;
        if serial.is_empty() || serial.len() > 21 {
            return Err(bad("serial number length"));
        }
        if let [first, second, ..] = serial {
            if (*first == 0 && second & 0x80 == 0) || (*first == 0xff && second & 0x80 != 0) {
                return Err(bad("nonminimal serial number"));
            }
        }
        let inner_alg = t.expect(T_SEQUENCE)?;
        if inner_alg != sig_alg {
            return Err(bad(
                "signature algorithm differs between TBS and certificate",
            ));
        }
        check_algorithm_identifier_encoding(sig_alg)?;
        let issuer = t.expect_raw(T_SEQUENCE)?;
        let issuer_body = Der::new(issuer).expect(T_SEQUENCE)?;
        if issuer_body.is_empty() {
            return Err(bad("empty certificate issuer name"));
        }
        check_rdn_sequence(issuer_body)?;
        let mut validity = t.nested(T_SEQUENCE)?;
        let (tag, nb, _) = validity.tlv()?;
        let not_before = parse_time(tag, nb)?;
        let (tag, na, _) = validity.tlv()?;
        let not_after = parse_time(tag, na)?;
        validity.finish()?;
        if not_after < not_before {
            return Err(bad("certificate validity ends before it begins"));
        }
        let subject = t.expect_raw(T_SEQUENCE)?;
        check_rdn_sequence(Der::new(subject).expect(T_SEQUENCE)?)?;
        let spki = t.expect_raw(T_SEQUENCE)?;
        check_subject_public_key_info(spki)?;
        let issuer_uid = t.optional(T_ISSUER_UID)?;
        let subject_uid = t.optional(T_SUBJECT_UID)?;
        if version == 0 && (issuer_uid.is_some() || subject_uid.is_some()) {
            return Err(bad("unique identifiers in a v1 certificate"));
        }
        for uid in [issuer_uid, subject_uid].into_iter().flatten() {
            check_unique_id(uid)?;
        }
        let mut ext = Extensions::default();
        if let Some(e) = t.optional(T_CTX3)? {
            if version != 2 {
                return Err(bad("extensions in a certificate that is not v3"));
            }
            ext = parse_extensions(e)?;
        }
        t.finish()?;

        if Der::new(subject).expect(T_SEQUENCE)?.is_empty()
            && (ext.san.is_none() || !ext.san_critical)
        {
            return Err(bad(
                "empty certificate subject requires a critical subjectAltName",
            ));
        }

        Ok(Self {
            der,
            tbs,
            sig_alg,
            signature,
            serial,
            issuer,
            subject,
            spki,
            not_before,
            not_after,
            ext,
        })
    }

    /// The serial number's INTEGER content octets, as encoded.
    pub fn serial(&self) -> &'a [u8] {
        self.serial
    }

    /// The certificate's DER.
    pub fn der(&self) -> &'a [u8] {
        self.der
    }

    /// The subject public key.
    pub fn subject_public_key(&self) -> Result<PublicKey<'a>> {
        PublicKey::from_spki(self.spki)
    }

    /// DER `SubjectPublicKeyInfo`.
    pub fn spki_der(&self) -> &'a [u8] {
        self.spki
    }

    /// DER subject `Name`, including its SEQUENCE header.
    /// Number of encoded certificate extensions, including unknown entries.
    pub fn extension_count(&self) -> usize {
        self.ext.count
    }

    /// The certificate subject Name, DER encoded.
    pub fn subject_der(&self) -> &'a [u8] {
        self.subject
    }

    /// DER issuer `Name`, including its SEQUENCE header.
    pub fn issuer_der(&self) -> &'a [u8] {
        self.issuer
    }

    /// Start of validity, Unix seconds.
    pub fn not_before(&self) -> u64 {
        self.not_before
    }

    /// End of validity, Unix seconds.
    pub fn not_after(&self) -> u64 {
        self.not_after
    }

    /// Whether `basicConstraints` marks this a CA.
    pub fn is_ca(&self) -> bool {
        matches!(self.ext.basic, Some((true, _)))
    }

    /// `dNSName` subject alternative names.
    pub fn dns_names(&self) -> Vec<&'a str> {
        let mut out = Vec::new();
        let _ = for_each_san(self.ext.san, |tag, v| {
            if tag == T_GN_DNS {
                if let Ok(s) = core::str::from_utf8(v) {
                    out.push(s);
                }
            }
        });
        out
    }

    /// `iPAddress` subject alternative names.
    pub fn ip_addresses(&self) -> Vec<IpAddr> {
        let mut out = Vec::new();
        let _ = for_each_san(self.ext.san, |tag, v| {
            if tag == T_GN_IP {
                if let Ok(a) = <[u8; 4]>::try_from(v) {
                    out.push(IpAddr::V4(a));
                } else if let Ok(a) = <[u8; 16]>::try_from(v) {
                    out.push(IpAddr::V6(a));
                }
            }
        });
        out
    }

    /// The signature scheme of the outer signature.
    pub fn signature_scheme(&self) -> Result<SignatureScheme> {
        scheme_from_alg(self.sig_alg)
    }

    /// The subject common name. For reports only; never used to match names.
    pub fn common_name(&self) -> Option<&'a str> {
        name_common_name(self.subject)
    }

    /// REQ-X509-022: both endpoints of the certificate validity interval are inclusive.
    fn check_validity(&self, now: u64) -> Result<()> {
        if now < self.not_before {
            return Err(Error::new(
                ErrorKind::CertificateExpired,
                "certificate is not yet valid",
            ));
        }
        if now > self.not_after {
            return Err(Error::new(
                ErrorKind::CertificateExpired,
                "certificate has expired",
            ));
        }
        Ok(())
    }

    fn check_eku(&self, usage: Usage) -> Result<()> {
        let Some(eku) = self.ext.eku else {
            return Ok(());
        };
        let mut r = Der::new(eku);
        while !r.is_empty() {
            let oid = r.expect(T_OID)?;
            if oid == usage.oid() || oid == OID_ANY_EKU {
                return Ok(());
            }
        }
        Err(Error::new(
            ErrorKind::CertificateUsage,
            "extended key usage does not permit this use",
        ))
    }
}

/// REQ-X509-017: AKI fields are ordered, complete, and pair issuer with serial.
/// REQ-X509-045: serial references contain nonempty minimal DER INTEGER contents.
fn parse_authority_key_identifier(value: &[u8]) -> Result<Option<&[u8]>> {
    let mut v = Der::new(value);
    let mut s = v.nested(T_SEQUENCE)?;
    v.finish()?;
    // Issuer/serial references are checked structurally, not used as path hints.
    let key_identifier = s.optional(0x80)?;
    let issuer = s.optional(T_CTX1)?;
    let serial = s.optional(0x82)?;
    if issuer.is_some() != serial.is_some() {
        return Err(bad("authority key identifier issuer/serial are not paired"));
    }
    if let Some(issuer) = issuer {
        check_authority_issuer_names(issuer)?;
    }
    if let Some(serial) = serial {
        if serial.is_empty() {
            return Err(bad("empty authority certificate serial number"));
        }
        if let [first, second, ..] = serial {
            if (*first == 0 && second & 0x80 == 0) || (*first == 0xff && second & 0x80 != 0) {
                return Err(bad("nonminimal authority certificate serial number"));
            }
        }
    }
    s.finish()?;
    Ok(key_identifier)
}

/// The GeneralName choices and their specified primitive or constructed tags.
fn defined_general_name_tag(tag: u8) -> bool {
    matches!(
        tag,
        0xa0 | 0x81 | 0x82 | 0xa3 | 0xa4 | 0xa5 | 0x86 | 0x87 | 0x88
    )
}

/// REQ-X509-046: AKI issuer GeneralNames contain a nonempty list of complete
/// TLVs with defined GeneralName choice tags and their specified tag forms.
/// REQ-X509-047: registeredID issuer names contain complete, minimal OID encodings.
/// REQ-X509-048: directoryName issuer names wrap one complete Name with valid RDNs.
/// REQ-X509-049: otherName issuer names have a valid OID and one wrapped ANY value.
/// REQ-X509-050: EDI issuer names have ordered fields with valid DirectoryStrings.
/// REQ-X509-051: email, DNS, and URI issuer names contain only IA5String ASCII bytes.
/// REQ-X509-052: IP issuer names encode exactly one IPv4 or IPv6 address.
fn check_authority_issuer_names(body: &[u8]) -> Result<()> {
    if body.is_empty() {
        return Err(bad("empty authority certificate issuer names"));
    }
    let mut names = Der::new(body);
    while !names.is_empty() {
        let (tag, value, _) = names.tlv()?;
        if !defined_general_name_tag(tag) {
            return Err(bad("invalid authority certificate issuer name tag"));
        }
        if matches!(tag, 0x81 | T_GN_DNS | 0x86) && !value.is_ascii() {
            return Err(bad("authority certificate issuer IA5String is non-ASCII"));
        }
        if tag == T_GN_IP && value.len() != 4 && value.len() != 16 {
            return Err(bad("authority certificate issuer iPAddress length"));
        }
        if tag == 0x88 {
            check_oid_encoding(value)?;
        }
        if tag == T_CTX0 {
            check_other_name(value)?;
        }
        if tag == 0xa5 {
            check_edi_party_name(value)?;
        }
        if tag == 0xa4 {
            let mut directory = Der::new(value);
            check_rdn_sequence(directory.expect(T_SEQUENCE)?)?;
            directory.finish()?;
        }
    }
    Ok(())
}

/// Walk a `GeneralNames` body, calling `f(tag, value)` for each entry.
fn for_each_san<'a>(san: Option<&'a [u8]>, mut f: impl FnMut(u8, &'a [u8])) -> Result<()> {
    let Some(san) = san else { return Ok(()) };
    let mut r = Der::new(san);
    while !r.is_empty() {
        let (tag, value, _) = r.tlv()?;
        f(tag, value);
    }
    Ok(())
}

/// REQ-X509-009: KeyUsage has zero padding bits and at least one asserted bit.
/// REQ-X509-010: a present ExtendedKeyUsage sequence contains at least one purpose.
/// REQ-X509-014: the explicit Extensions wrapper contains exactly one sequence.
/// REQ-X509-015: pathLenConstraint requires cA and, when present, keyCertSign.
/// REQ-X509-016: a present SubjectAltName contains at least one name.
/// REQ-X509-017: AKI fields are fully consumed; issuer and serial references are paired.
/// REQ-X509-029: SAN entries use a defined GeneralName choice and its proper tag form.
/// REQ-X509-030: DNS, email, and URI SAN IA5Strings are nonempty ASCII values.
/// REQ-X509-032: directoryName SAN wrappers contain exactly one Name SEQUENCE.
/// REQ-X509-041: extension identifiers use complete, minimal OBJECT IDENTIFIER encodings.
/// REQ-X509-042: every EKU purpose has a complete, minimal OBJECT IDENTIFIER encoding.
/// REQ-X509-045: AKI serial references contain nonempty, minimal DER INTEGER contents.
/// REQ-X509-054: keyCertSign requires basicConstraints with cA asserted.
/// REQ-X509-055: nameConstraints appears only with CA basicConstraints.
/// REQ-X509-068: KeyUsage omits trailing zero named bits in its DER encoding.
fn parse_extensions(body: &[u8]) -> Result<Extensions<'_>> {
    let mut ext = Extensions::default();
    let mut extensions_der = Der::new(body);
    let mut list = extensions_der.nested(T_SEQUENCE)?;
    extensions_der.finish()?;
    let encoded_list = list.rest();
    if list.is_empty() {
        return Err(bad("empty extensions list"));
    }
    while !list.is_empty() {
        let consumed = encoded_list.len() - list.rest().len();
        // Each entry consumes bytes from a finite slice, bounding this count.
        ext.count += 1;
        // Bounded before the duplicate scan below, which compares each
        // extension with every earlier one: unbounded, a 128 KiB certificate
        // of empty extensions cost about 350 ms per parse.
        if ext.count > MAX_EXTENSIONS {
            return Err(bad("too many extensions"));
        }
        let mut e = list.nested(T_SEQUENCE)?;
        let oid = e.expect(T_OID)?;
        check_oid_encoding(oid)?;
        let critical = match e.optional(T_BOOLEAN)? {
            Some([0xff]) => true,
            Some([0x00]) => false,
            Some(_) => return Err(bad("malformed BOOLEAN")),
            None => false,
        };
        let value = e.expect(T_OCTET_STRING)?;
        e.finish()?;
        // Borrow previous entries rather than allocating an OID set.
        let mut previous = Der::new(&encoded_list[..consumed]);
        while !previous.is_empty() {
            let mut entry = previous.nested(T_SEQUENCE)?;
            if entry.expect(T_OID)? == oid {
                return Err(bad("duplicate extension"));
            }
        }
        match oid {
            OID_EXT_BC => {
                let mut v = Der::new(value);
                let mut s = v.nested(T_SEQUENCE)?;
                v.finish()?;
                let ca = match s.optional(T_BOOLEAN)? {
                    Some([0xff]) => true,
                    Some([0x00]) => false,
                    Some(_) => return Err(bad("malformed BOOLEAN")),
                    None => false,
                };
                let path_len = match s.optional(T_INTEGER)? {
                    Some(n) => Some(small_uint(n)?),
                    None => None,
                };
                s.finish()?;
                ext.basic = Some((ca, path_len));
            }
            OID_EXT_KU => {
                let mut v = Der::new(value);
                let bits = v.expect(T_BIT_STRING)?;
                v.finish()?;
                let (unused, bytes) = bits.split_first().ok_or(bad("empty keyUsage"))?;
                if *unused > 7 || bytes.is_empty() {
                    return Err(bad("malformed keyUsage"));
                }
                let last = bytes.last().ok_or(bad("empty keyUsage"))?;
                if last & ((1u8 << unused) - 1) != 0 {
                    return Err(bad("nonzero keyUsage padding bits"));
                }
                if bytes.iter().all(|byte| *byte == 0) {
                    return Err(bad("keyUsage has no asserted bits"));
                }
                if last.trailing_zeros() != u32::from(*unused) {
                    return Err(bad("keyUsage has trailing zero named bits"));
                }
                let mut ku = 0u16;
                for i in 0..9usize {
                    if let Some(b) = bytes.get(i / 8) {
                        if b & (0x80 >> (i % 8)) != 0 {
                            ku |= 1 << i;
                        }
                    }
                }
                ext.key_usage = Some(ku);
            }
            OID_EXT_EKU => {
                let mut v = Der::new(value);
                let body = v.expect(T_SEQUENCE)?;
                v.finish()?;
                if body.is_empty() {
                    return Err(bad("empty extendedKeyUsage"));
                }
                let mut check = Der::new(body);
                while !check.is_empty() {
                    check_oid_encoding(check.expect(T_OID)?)?;
                }
                ext.eku = Some(body);
            }
            OID_EXT_SAN => {
                let mut v = Der::new(value);
                let body = v.expect(T_SEQUENCE)?;
                v.finish()?;
                if body.is_empty() {
                    return Err(bad("empty subjectAltName"));
                }
                let mut check = Der::new(body);
                while !check.is_empty() {
                    let (tag, val, _) = check.tlv()?;
                    if !defined_general_name_tag(tag) {
                        return Err(bad("invalid subjectAltName choice tag"));
                    }
                    if tag == T_GN_DNS && (val.is_empty() || !val.is_ascii()) {
                        return Err(bad("dNSName is not ASCII"));
                    }
                    if matches!(tag, 0x81 | 0x86) && (val.is_empty() || !val.is_ascii()) {
                        return Err(bad("SAN IA5String is empty or non-ASCII"));
                    }
                    if tag == 0x88 {
                        check_oid_encoding(val)?;
                    }
                    if tag == T_CTX0 {
                        check_other_name(val)?;
                    }
                    if tag == 0xa5 {
                        check_edi_party_name(val)?;
                    }
                    if tag == 0xa4 {
                        check_directory_name(val)?;
                    }
                    if tag == T_GN_IP && val.len() != 4 && val.len() != 16 {
                        return Err(bad("iPAddress length"));
                    }
                }
                ext.san = Some(body);
                ext.san_critical = critical;
            }
            OID_EXT_NC => {
                let mut v = Der::new(value);
                let body = v.expect(T_SEQUENCE)?;
                v.finish()?;
                name_constraint_lists(body)?;
                ext.name_constraints = Some(body);
            }
            OID_EXT_SKI => {
                let mut v = Der::new(value);
                ext.ski = Some(v.expect(T_OCTET_STRING)?);
                v.finish()?;
            }
            OID_EXT_AKI => {
                ext.aki = parse_authority_key_identifier(value)?;
            }
            OID_EXT_CP => {}
            _ => {
                if critical {
                    ext.unknown_critical = true;
                }
            }
        }
    }
    if let Some((ca, Some(_))) = ext.basic {
        if !ca || ext.key_usage.is_some_and(|ku| ku & KU_KEY_CERT_SIGN == 0) {
            return Err(bad(
                "pathLenConstraint requires certificate-signing CA usage",
            ));
        }
    }
    if ext.key_usage.is_some_and(|ku| ku & KU_KEY_CERT_SIGN != 0)
        && !matches!(ext.basic, Some((true, _)))
    {
        return Err(bad("keyCertSign requires CA basicConstraints"));
    }
    if ext.name_constraints.is_some() && !matches!(ext.basic, Some((true, _))) {
        return Err(bad("nameConstraints requires CA basicConstraints"));
    }
    Ok(ext)
}

// ---------------------------------------------------------------------------
// Signature algorithms
// ---------------------------------------------------------------------------

fn pss_hash(oid: &[u8]) -> Option<(SignatureScheme, u64)> {
    Some(match oid {
        OID_SHA256 => (SignatureScheme::RsaPssRsaeSha256, 32),
        OID_SHA384 => (SignatureScheme::RsaPssRsaeSha384, 48),
        OID_SHA512 => (SignatureScheme::RsaPssRsaeSha512, 64),
        _ => return None,
    })
}

/// REQ-X509-066: a received signature AlgorithmIdentifier contains one valid
/// OID and at most one complete parameter value, independently of support.
fn check_algorithm_identifier_encoding(alg: &[u8]) -> Result<()> {
    let mut fields = Der::new(alg);
    check_oid_encoding(fields.expect(T_OID)?)?;
    if !fields.is_empty() {
        fields.any()?;
    }
    fields.finish()
}

/// REQ-X509-067: received SubjectPublicKeyInfo contains a complete algorithm
/// identifier and one BIT STRING with valid unused-bit count and padding.
fn check_subject_public_key_info(spki: &[u8]) -> Result<()> {
    let mut wrapper = Der::new(spki);
    let mut fields = wrapper.nested(T_SEQUENCE)?;
    wrapper.finish()?;
    check_algorithm_identifier_encoding(fields.expect(T_SEQUENCE)?)?;
    let bits = fields.expect(T_BIT_STRING)?;
    let (unused, bytes) = bits
        .split_first()
        .ok_or(bad("empty public key BIT STRING"))?;
    if *unused > 7 {
        return Err(bad("invalid public key unused-bit count"));
    }
    match bytes.last() {
        None if *unused != 0 => return Err(bad("public key padding without bits")),
        Some(last) if last & ((1u8 << unused) - 1) != 0 => {
            return Err(bad("nonzero public key padding bits"));
        }
        _ => {}
    }
    fields.finish()
}

/// Map an `AlgorithmIdentifier` body to a scheme.
/// REQ-X509-043: signature and RSA-PSS parameter OIDs are complete and minimal
/// before algorithm matching; malformed identifiers are structural errors.
fn scheme_from_alg(alg: &[u8]) -> Result<SignatureScheme> {
    let unsupported = || {
        Error::new(
            ErrorKind::UnsupportedCertificate,
            "unsupported signature algorithm",
        )
    };
    let mut r = Der::new(alg);
    let oid = r.expect(T_OID)?;
    check_oid_encoding(oid)?;
    let scheme = match oid {
        OID_ECDSA_SHA256 => SignatureScheme::EcdsaSecp256r1Sha256,
        OID_ECDSA_SHA384 => SignatureScheme::EcdsaSecp384r1Sha384,
        OID_ECDSA_SHA512 => SignatureScheme::EcdsaSecp521r1Sha512,
        OID_ECDSA_SHA1 => SignatureScheme::EcdsaSha1,
        OID_ED25519 => SignatureScheme::Ed25519,
        o if o == OID_ML_DSA_44 => SignatureScheme::MlDsa44,
        o if o == OID_ML_DSA_65 => SignatureScheme::MlDsa65,
        o if o == OID_ML_DSA_87 => SignatureScheme::MlDsa87,
        OID_RSA_SHA256 | OID_RSA_SHA384 | OID_RSA_SHA512 | OID_RSA_SHA1 => {
            r.optional_null()?;
            match oid {
                OID_RSA_SHA256 => SignatureScheme::RsaPkcs1Sha256,
                OID_RSA_SHA384 => SignatureScheme::RsaPkcs1Sha384,
                OID_RSA_SHA512 => SignatureScheme::RsaPkcs1Sha512,
                _ => SignatureScheme::RsaPkcs1Sha1,
            }
        }
        OID_RSA_PSS => {
            let mut p = r.nested(T_SEQUENCE)?;
            let mut h = p.nested(T_CTX0).map_err(|_| unsupported())?;
            let mut halg = h.nested(T_SEQUENCE)?;
            h.finish()?;
            let hoid = halg.expect(T_OID)?;
            check_oid_encoding(hoid)?;
            halg.optional_null()?;
            halg.finish()?;
            let (scheme, salt_len) = pss_hash(hoid).ok_or_else(unsupported)?;
            let mut m = p.nested(T_CTX1)?;
            let mut malg = m.nested(T_SEQUENCE)?;
            m.finish()?;
            let mgf_oid = malg.expect(T_OID)?;
            check_oid_encoding(mgf_oid)?;
            if mgf_oid != OID_MGF1 {
                return Err(unsupported());
            }
            let mut mh = malg.nested(T_SEQUENCE)?;
            malg.finish()?;
            let mgf_hash_oid = mh.expect(T_OID)?;
            check_oid_encoding(mgf_hash_oid)?;
            if mgf_hash_oid != hoid {
                return Err(unsupported());
            }
            mh.optional_null()?;
            mh.finish()?;
            let mut s = p.nested(T_CTX2)?;
            let salt = small_uint(s.expect(T_INTEGER)?)?;
            s.finish()?;
            if salt != salt_len {
                return Err(unsupported());
            }
            if let Some(tr) = p.optional(T_CTX3)? {
                let mut tr = Der::new(tr);
                if small_uint(tr.expect(T_INTEGER)?)? != 1 {
                    return Err(bad("PSS trailer field"));
                }
                tr.finish()?;
            }
            p.finish()?;
            scheme
        }
        _ => return Err(unsupported()),
    };
    r.finish()?;
    Ok(scheme)
}

fn hash_alg_id(oid: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    push_tlv(&mut body, T_OID, oid);
    push_tlv(&mut body, T_NULL, &[]);
    let mut out = Vec::new();
    push_tlv(&mut out, T_SEQUENCE, &body);
    out
}

/// The full `AlgorithmIdentifier` TLV for signing with `scheme`.
fn alg_id(scheme: SignatureScheme) -> Result<Vec<u8>> {
    let mut body = Vec::new();
    match scheme {
        SignatureScheme::EcdsaSecp256r1Sha256 => push_tlv(&mut body, T_OID, OID_ECDSA_SHA256),
        SignatureScheme::EcdsaSecp384r1Sha384 => push_tlv(&mut body, T_OID, OID_ECDSA_SHA384),
        SignatureScheme::EcdsaSecp521r1Sha512 => push_tlv(&mut body, T_OID, OID_ECDSA_SHA512),
        SignatureScheme::Ed25519 => push_tlv(&mut body, T_OID, OID_ED25519),
        SignatureScheme::MlDsa44 => push_tlv(&mut body, T_OID, OID_ML_DSA_44),
        SignatureScheme::MlDsa65 => push_tlv(&mut body, T_OID, OID_ML_DSA_65),
        SignatureScheme::MlDsa87 => push_tlv(&mut body, T_OID, OID_ML_DSA_87),
        SignatureScheme::RsaPssRsaeSha256
        | SignatureScheme::RsaPssRsaeSha384
        | SignatureScheme::RsaPssRsaeSha512 => {
            let (hoid, salt) = match scheme {
                SignatureScheme::RsaPssRsaeSha256 => (OID_SHA256, 32u8),
                SignatureScheme::RsaPssRsaeSha384 => (OID_SHA384, 48),
                _ => (OID_SHA512, 64),
            };
            let h = hash_alg_id(hoid);
            let mut mgf_body = Vec::new();
            push_tlv(&mut mgf_body, T_OID, OID_MGF1);
            mgf_body.extend_from_slice(&h);
            let mut mgf = Vec::new();
            push_tlv(&mut mgf, T_SEQUENCE, &mgf_body);
            let mut salt_int = Vec::new();
            push_tlv(&mut salt_int, T_INTEGER, &[salt]);
            let mut params = Vec::new();
            push_tlv(&mut params, T_CTX0, &h);
            push_tlv(&mut params, T_CTX1, &mgf);
            push_tlv(&mut params, T_CTX2, &salt_int);
            push_tlv(&mut body, T_OID, OID_RSA_PSS);
            push_tlv(&mut body, T_SEQUENCE, &params);
        }
        _ => {
            return Err(Error::new(
                ErrorKind::InvalidConfig,
                "no certificate encoding for this scheme",
            ))
        }
    }
    let mut out = Vec::new();
    push_tlv(&mut out, T_SEQUENCE, &body);
    Ok(out)
}

// ---------------------------------------------------------------------------
// Trust anchors
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct Anchor {
    subject: Vec<u8>,
    spki: Vec<u8>,
    /// `REQ-X509-074`: whether this anchor may issue other certificates. A certificate whose
    /// basicConstraints says it is not a CA, or whose keyUsage lacks
    /// keyCertSign, may be trusted directly as itself but issues nothing.
    can_issue: bool,
    ski: Option<Vec<u8>>,
    name_constraints: Option<Vec<u8>>,
}

/// A set of trust anchors.
#[derive(Debug, Clone, Default)]
pub struct RootStore {
    anchors: Vec<Anchor>,
}

impl RootStore {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a DER certificate as a trust anchor. Its subject, key and name
    /// constraints are kept; its dates and other extensions are not consulted.
    /// Adding an anchor already present is a no-op.
    pub fn add_der(&mut self, der: &[u8]) -> Result<()> {
        let cert = Certificate::parse(der)?;
        cert.subject_public_key()?;
        if self
            .anchors
            .iter()
            .any(|a| a.subject == cert.subject && a.spki == cert.spki)
        {
            return Ok(());
        }
        let can_issue = !matches!(cert.ext.basic, Some((false, _)))
            && cert
                .ext
                .key_usage
                .is_none_or(|ku| ku & KU_KEY_CERT_SIGN != 0);
        self.anchors.push(Anchor {
            subject: cert.subject.to_vec(),
            spki: cert.spki.to_vec(),
            can_issue,
            ski: cert.ext.ski.map(<[u8]>::to_vec),
            name_constraints: cert.ext.name_constraints.map(<[u8]>::to_vec),
        });
        Ok(())
    }

    /// Add every `CERTIFICATE` block of a PEM bundle, returning how many were
    /// added. Blocks with other labels, and certificates this module cannot
    /// parse or whose key it cannot use, are skipped; the call fails only if
    /// nothing was added.
    pub fn add_pem_bundle(&mut self, text: &str) -> Result<usize> {
        const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
        const END: &str = "-----END CERTIFICATE-----";
        let mut added = 0;
        let mut rest = text;
        while let Some(start) = rest.find(BEGIN) {
            let after = &rest[start + BEGIN.len()..];
            let Some(end) = after.find(END) else { break };
            let b64: Vec<u8> = after[..end]
                .bytes()
                .filter(|b| !b.is_ascii_whitespace())
                .collect();
            rest = &after[end + END.len()..];
            let mut der = alloc::vec![0u8; b64.len() / 4 * 3];
            let Ok(n) = ic_core::codec::base64_decode(&b64, &mut der) else {
                continue;
            };
            der.truncate(n);
            let before = self.anchors.len();
            if self.add_der(&der).is_ok() && self.anchors.len() > before {
                added += 1;
            }
        }
        if added == 0 && self.anchors.is_empty() {
            return Err(Error::new(
                ErrorKind::InvalidConfig,
                "no usable certificates in PEM bundle",
            ));
        }
        Ok(added)
    }

    /// Number of anchors.
    pub fn len(&self) -> usize {
        self.anchors.len()
    }

    /// True when there are no anchors.
    pub fn is_empty(&self) -> bool {
        self.anchors.is_empty()
    }

    /// Load the platform's PEM bundle: `SSL_CERT_FILE`, then the usual Linux,
    /// BSD and macOS locations, then the bundle Git for Windows ships.
    #[cfg(feature = "std")]
    pub fn from_system() -> Result<Self> {
        let mut paths: Vec<String> = Vec::new();
        if let Ok(p) = std::env::var("SSL_CERT_FILE") {
            paths.push(p);
        }
        for p in [
            "/etc/ssl/certs/ca-certificates.crt",
            "/etc/pki/tls/certs/ca-bundle.crt",
            "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
            "/etc/ssl/ca-bundle.pem",
            "/etc/ssl/cert.pem",
            "/usr/local/etc/openssl/cert.pem",
            "/usr/local/share/certs/ca-root-nss.crt",
            r"C:\Program Files\Git\mingw64\etc\ssl\certs\ca-bundle.crt",
            r"C:\Program Files\Git\mingw64\ssl\certs\ca-bundle.crt",
            r"C:\Program Files\Git\usr\ssl\certs\ca-bundle.crt",
            "/mingw64/etc/ssl/certs/ca-bundle.crt",
        ] {
            paths.push(String::from(p));
        }
        for p in paths {
            if let Ok(text) = std::fs::read_to_string(&p) {
                let mut store = Self::new();
                if store.add_pem_bundle(&text).is_ok() {
                    return Ok(store);
                }
            }
        }
        Err(Error::new(
            ErrorKind::InvalidConfig,
            "no system trust store found; set SSL_CERT_FILE",
        ))
    }
}

// ---------------------------------------------------------------------------
// Path validation
// ---------------------------------------------------------------------------

/// Parameters of [`verify_chain`].
#[derive(Debug, Clone, Copy)]
pub struct VerifyOptions<'s> {
    /// The current time, Unix seconds.
    pub now: u64,
    /// What the leaf is being accepted for.
    pub usage: Usage,
    /// Signature schemes permitted on certificate links. `REQ-X509-005`.
    pub allowed_schemes: &'s [SignatureScheme],
    /// Most certificates on a path, leaf included, anchor excluded.
    pub max_depth: usize,
    /// Smallest RSA modulus accepted anywhere on the path, in bits.
    pub min_rsa_bits: usize,
    /// CRLs to check every non-anchor certificate on the path against.
    pub crls: Option<&'s crl::CrlStore>,
    /// Fail unless every non-anchor certificate is shown good by a current
    /// CRL from its issuer. `REQ-CRL-003`.
    pub require_crl: bool,
}

impl<'s> VerifyOptions<'s> {
    /// Options with the defaults: depth 8, RSA at least 2048 bits.
    pub fn new(now: u64, usage: Usage, allowed_schemes: &'s [SignatureScheme]) -> Self {
        Self {
            now,
            usage,
            allowed_schemes,
            max_depth: 8,
            min_rsa_bits: 2048,
            crls: None,
            require_crl: false,
        }
    }
}

/// What a successful verification established.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainReport {
    /// Signature links verified: intermediates plus one. Zero when the leaf is
    /// itself a trust anchor (pinned).
    pub depth: usize,
    /// The leaf key type, as `PublicKey::kind_id`.
    pub leaf_key: &'static str,
    /// Scheme of each verified link, leaf first.
    pub schemes: Vec<SignatureScheme>,
    /// End of the leaf's validity, Unix seconds.
    pub leaf_not_after: u64,
    /// Common name of the anchor, for display.
    pub anchor_subject_cn: Option<String>,
    /// Weakest classical strength of any key on the path, in bits.
    pub min_classical_bits: u16,
    /// Subject name (DER) of the certificate that issued the leaf.
    pub issuer_subject: Vec<u8>,
    /// `SubjectPublicKeyInfo` (DER) of the certificate that issued the leaf:
    /// what an OCSP response for the leaf must be signed by, or certified by.
    pub issuer_spki: Vec<u8>,
    /// Whether every non-anchor certificate was shown good by a current CRL.
    pub crl_checked: bool,
}

fn rsa_bits(key: &PublicKey<'_>) -> Option<usize> {
    match key {
        PublicKey::Rsa { modulus, .. } => {
            let first = modulus.iter().position(|b| *b != 0)?;
            let lead = modulus[first].leading_zeros() as usize;
            Some((modulus.len() - first) * 8 - lead)
        }
        _ => None,
    }
}

fn check_key_policy(key: &PublicKey<'_>, opts: &VerifyOptions<'_>) -> Result<()> {
    if let Some(bits) = rsa_bits(key) {
        if bits < opts.min_rsa_bits {
            return Err(Error::new(
                ErrorKind::PolicyViolation,
                "RSA key smaller than the policy minimum",
            ));
        }
    }
    Ok(())
}

/// Verify `cert`'s signature with `issuer_spki`, returning the scheme.
fn check_signature(
    cert: &Certificate<'_>,
    issuer_spki: &[u8],
    opts: &VerifyOptions<'_>,
) -> Result<SignatureScheme> {
    let scheme = cert.signature_scheme()?;
    if !opts.allowed_schemes.contains(&scheme) {
        return Err(Error::new(
            ErrorKind::PolicyViolation,
            "certificate signature scheme not allowed by policy",
        ));
    }
    let key = PublicKey::from_spki(issuer_spki)?;
    check_key_policy(&key, opts)?;
    sign::verify(scheme, &key, cert.tbs, cert.signature).map_err(|e| match e.kind() {
        ErrorKind::DecryptError | ErrorKind::IllegalParameter => {
            bad("certificate signature did not verify")
        }
        _ => e,
    })?;
    Ok(scheme)
}

/// Checks an issuing (intermediate) certificate with `below` intermediates
/// between it and the leaf.
fn check_issuer(cert: &Certificate<'_>, below: usize, opts: &VerifyOptions<'_>) -> Result<()> {
    if cert.ext.unknown_critical {
        return Err(Error::new(
            ErrorKind::UnsupportedCertificate,
            "unknown critical extension",
        ));
    }
    cert.check_validity(opts.now)?;
    match cert.ext.basic {
        Some((true, path_len)) => {
            if let Some(n) = path_len {
                if below as u64 > n {
                    return Err(Error::new(
                        ErrorKind::CertificateUsage,
                        "path length constraint exceeded",
                    ));
                }
            }
        }
        _ => {
            return Err(Error::new(
                ErrorKind::CertificateUsage,
                "issuer is not a CA",
            ))
        }
    }
    // REQ-X509-006: an issuer's key usage must allow certificate signing.
    if let Some(ku) = cert.ext.key_usage {
        if ku & KU_KEY_CERT_SIGN == 0 {
            return Err(Error::new(
                ErrorKind::CertificateUsage,
                "issuer key usage lacks keyCertSign",
            ));
        }
    }
    cert.check_eku(opts.usage)?;
    let key = cert.subject_public_key()?;
    check_key_policy(&key, opts)
}

/// The most extensions accepted in one certificate, CRL, CRL entry or OCSP
/// response. Real certificates carry a dozen or so; the bound keeps the
/// quadratic duplicate check cheap on peer input. `REQ-X509-073`.
pub(crate) const MAX_EXTENSIONS: usize = 64;

/// A DNS name without one trailing dot: `example.com.` and `example.com` are
/// the same name, for name constraints as for matching (`dns_matches`).
/// `REQ-X509-071`.
fn dns_canonical(name: &str) -> &str {
    name.strip_suffix('.').unwrap_or(name)
}

/// The IPv4 address an IPv4-mapped IPv6 address (`::ffff:a.b.c.d`) carries.
fn ipv4_mapped(ip: &[u8]) -> Option<&[u8]> {
    match ip {
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, v4 @ ..] => Some(v4),
        _ => None,
    }
}

fn dns_eq(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}

/// Whether `name` lies within DNS subtree `constraint` (RFC 5280 §4.2.1.10).
fn dns_within(name: &str, constraint: &str) -> bool {
    if constraint.is_empty() {
        return true;
    }
    if constraint.starts_with('.') {
        return name.len() > constraint.len()
            && dns_eq(&name[name.len() - constraint.len()..], constraint);
    }
    if dns_eq(name, constraint) {
        return true;
    }
    name.len() > constraint.len() + 1
        && name.as_bytes()[name.len() - constraint.len() - 1] == b'.'
        && dns_eq(&name[name.len() - constraint.len()..], constraint)
}

fn ip_within(ip: &[u8], constraint: &[u8]) -> bool {
    let n = ip.len();
    if constraint.len() != 2 * n {
        return false;
    }
    let (addr, mask) = constraint.split_at(n);
    ip.iter()
        .zip(addr)
        .zip(mask)
        .all(|((i, a), m)| i & m == a & m)
}

/// REQ-X509-044: CIDR masks contain leading one bits followed only by zero bits.
fn contiguous_ip_mask(mask: &[u8]) -> bool {
    let mut zeros = false;
    for &byte in mask {
        if zeros && byte != 0 {
            return false;
        }
        match byte {
            0xff => {}
            0xfe | 0xfc | 0xf8 | 0xf0 | 0xe0 | 0xc0 | 0x80 | 0 => zeros = true,
            _ => return false,
        }
    }
    true
}

struct NameConstraintLists<'a> {
    permitted: Option<&'a [u8]>,
    excluded: Option<&'a [u8]>,
}

/// REQ-X509-058: BaseDistance is a nonempty, nonnegative, minimally encoded
/// INTEGER; validation does not impose a machine-integer size limit.
fn check_base_distance(content: &[u8]) -> Result<()> {
    let (first, _) = content
        .split_first()
        .ok_or(bad("empty BaseDistance INTEGER"))?;
    if first & 0x80 != 0 {
        return Err(bad("negative BaseDistance INTEGER"));
    }
    if let [0, second, ..] = content {
        if second & 0x80 == 0 {
            return Err(bad("nonminimal BaseDistance INTEGER"));
        }
    }
    Ok(())
}

/// REQ-X509-057: each subtree is a complete SEQUENCE with one defined base
/// followed only by ordered optional implicit minimum and maximum fields.
/// REQ-X509-059: registeredID constraint bases contain complete minimal OIDs.
/// REQ-X509-060: directoryName constraint bases wrap a complete, ordered Name.
/// REQ-X509-061: otherName constraint bases contain a valid OID and one explicit value.
/// REQ-X509-062: EDI constraint bases have ordered fields and valid DirectoryStrings.
/// REQ-X509-063: email, DNS, and URI constraint bases contain only IA5String bytes.
/// REQ-X509-064: IP constraint bases encode an address and contiguous mask at parse time.
fn check_general_subtrees(body: &[u8]) -> Result<()> {
    let mut subtrees = Der::new(body);
    while !subtrees.is_empty() {
        let mut subtree = subtrees.nested(T_SEQUENCE)?;
        let (tag, base, _) = subtree.tlv()?;
        if !defined_general_name_tag(tag) {
            return Err(bad("invalid name constraint base tag"));
        }
        if matches!(tag, 0x81 | T_GN_DNS | 0x86) && !base.is_ascii() {
            return Err(bad("name constraint IA5String is non-ASCII"));
        }
        if tag == T_GN_IP {
            if base.len() != 8 && base.len() != 32 {
                return Err(bad("IP name constraint length"));
            }
            if !contiguous_ip_mask(&base[base.len() / 2..]) {
                return Err(bad("noncontiguous IP name constraint mask"));
            }
        }
        if tag == 0x88 {
            check_oid_encoding(base)?;
        }
        if tag == 0xa0 {
            check_other_name(base)?;
        }
        if tag == 0xa5 {
            check_edi_party_name(base)?;
        }
        if tag == 0xa4 {
            let mut directory_base = Der::new(base);
            check_rdn_sequence(directory_base.expect(T_SEQUENCE)?)?;
            directory_base.finish()?;
        }
        if let Some(minimum) = subtree.optional(0x80)? {
            check_base_distance(minimum)?;
            // REQ-X509-077: minimum DEFAULT 0 is omitted in DER.
            if minimum == [0] {
                return Err(bad("explicitly encoded default BaseDistance"));
            }
        }
        if let Some(maximum) = subtree.optional(0x81)? {
            check_base_distance(maximum)?;
        }
        subtree.finish()?;
    }
    Ok(())
}

/// REQ-X509-018: constraints contain a field and each present subtree list is nonempty.
/// REQ-X509-056: parse and evaluation both require complete, ordered constraint lists.
fn name_constraint_lists(nc: &[u8]) -> Result<NameConstraintLists<'_>> {
    let mut r = Der::new(nc);
    let permitted = r.optional(T_CTX0)?;
    let excluded = r.optional(T_CTX1)?;
    r.finish()?;
    if permitted.is_none() && excluded.is_none() {
        return Err(bad("empty name constraints"));
    }
    if permitted.is_some_and(<[u8]>::is_empty) || excluded.is_some_and(<[u8]>::is_empty) {
        return Err(bad("empty general subtrees"));
    }
    for body in [permitted, excluded].into_iter().flatten() {
        check_general_subtrees(body)?;
    }
    Ok(NameConstraintLists {
        permitted,
        excluded,
    })
}

/// Apply one `NameConstraints` body to the names of `subjects`. `REQ-X509-008`.
/// REQ-X509-044: IP constraint masks use CIDR encoding, even for absent name families.
fn apply_name_constraints(nc: &[u8], subjects: &[&Certificate<'_>]) -> Result<()> {
    let violation = || Error::new(ErrorKind::CertificateUsage, "name constraints violated");
    let unsupported = || {
        Error::new(
            ErrorKind::UnsupportedCertificate,
            "name constraint form not supported",
        )
    };
    let NameConstraintLists {
        permitted,
        excluded,
    } = name_constraint_lists(nc)?;

    // Re-scan borrowed subtree encodings; neither SANs nor constraints are copied.
    for body in [permitted, excluded].into_iter().flatten() {
        let mut subtrees = Der::new(body);
        while !subtrees.is_empty() {
            let mut st = subtrees.nested(T_SEQUENCE)?;
            let (tag, _, _) = st.tlv()?;
            if !st.is_empty() || !matches!(tag, T_GN_DNS | T_GN_IP) {
                return Err(unsupported());
            }
        }
    }
    for cert in subjects {
        let mut names = Der::new(cert.ext.san.unwrap_or(&[]));
        while !names.is_empty() {
            let (tag, value, _) = names.tlv()?;
            if !matches!(tag, T_GN_DNS | T_GN_IP) {
                continue;
            }
            let mut applicable = false;
            let mut covered = false;
            for (is_excluded, body) in [(false, permitted), (true, excluded)] {
                let mut subtrees = Der::new(body.unwrap_or(&[]));
                while !subtrees.is_empty() {
                    let mut st = subtrees.nested(T_SEQUENCE)?;
                    let (ctag, base, _) = st.tlv()?;
                    // REQ-X509-072: iPAddress is one name type (RFC 5280 §4.2.1.10): a
                    // subtree of the other address family still applies, and
                    // an address outside its family is not within it.
                    if ctag != tag {
                        continue;
                    }
                    let mut within = if tag == T_GN_DNS {
                        let name = core::str::from_utf8(value).map_err(|_| unsupported())?;
                        let constraint = core::str::from_utf8(base).map_err(|_| unsupported())?;
                        dns_within(dns_canonical(name), dns_canonical(constraint))
                    } else {
                        ip_within(value, base)
                            || (is_excluded
                                && ipv4_mapped(value).is_some_and(|v4| ip_within(v4, base)))
                    };
                    if is_excluded {
                        if tag == T_GN_DNS {
                            let name = core::str::from_utf8(value).map_err(|_| unsupported())?;
                            let name = dns_canonical(name);
                            let constraint = dns_canonical(
                                core::str::from_utf8(base).map_err(|_| unsupported())?,
                            );
                            if let Some(suffix) = name.strip_prefix("*.") {
                                within |= dns_within(constraint.trim_start_matches('.'), suffix);
                            }
                        }
                        if within {
                            return Err(violation());
                        }
                    } else {
                        applicable = true;
                        covered |= within;
                    }
                }
            }
            if applicable && !covered {
                return Err(violation());
            }
        }
    }
    Ok(())
}

struct Search<'c, 'r, 'o> {
    ints: Vec<Certificate<'c>>,
    roots: &'r RootStore,
    opts: &'r VerifyOptions<'o>,
}

/// Whether key identifiers rule `issuer_ski` out as the issuer of `cert`.
///
/// Only a disagreement between two identifiers that are both present excludes
/// a candidate. That keeps a same-named but unrelated CA from being reported as
/// a bad signature, while a tampered certificate under its real issuer still
/// is.
fn key_ids_disagree(cert: &Certificate<'_>, issuer_ski: Option<&[u8]>) -> bool {
    matches!((cert.ext.aki, issuer_ski), (Some(a), Some(s)) if a != s)
}

fn note(best: &mut Option<Error>, e: Error) {
    if best.is_none_or(|b| b.kind() == ErrorKind::UnknownCa) {
        *best = Some(e);
    }
}

impl<'c> Search<'c, '_, '_> {
    fn chain_certs<'s>(
        &'s self,
        leaf: &'s Certificate<'c>,
        path: &[usize],
    ) -> Vec<&'s Certificate<'c>> {
        let mut v = Vec::with_capacity(path.len() + 1);
        v.push(leaf);
        for &i in path {
            v.push(&self.ints[i]);
        }
        v
    }

    fn check_constraints(
        &self,
        leaf: &Certificate<'c>,
        path: &[usize],
        anchor: &Anchor,
    ) -> Result<()> {
        let chain = self.chain_certs(leaf, path);
        for (k, ca) in chain.iter().enumerate().skip(1) {
            if let Some(nc) = ca.ext.name_constraints {
                apply_name_constraints(nc, &chain[..k])?;
            }
        }
        if let Some(nc) = &anchor.name_constraints {
            apply_name_constraints(nc, &chain)?;
        }
        Ok(())
    }

    /// Extend `path` (indices into `ints`, leaf-side first) to an anchor.
    /// `REQ-X509-002`: bounded by `budget` and by never revisiting a cert.
    fn extend(
        &self,
        leaf: &Certificate<'c>,
        path: &mut Vec<usize>,
        schemes: &mut Vec<SignatureScheme>,
        budget: &mut usize,
    ) -> Result<usize> {
        let current = match path.last() {
            Some(&i) => &self.ints[i],
            None => leaf,
        };
        let mut best: Option<Error> = None;

        for (ai, a) in self.roots.anchors.iter().enumerate() {
            if !a.can_issue
                || a.subject != current.issuer
                || key_ids_disagree(current, a.ski.as_deref())
            {
                continue;
            }
            if *budget == 0 {
                return Err(Error::new(
                    ErrorKind::UnknownCa,
                    "path search budget exhausted",
                ));
            }
            *budget -= 1;
            match check_signature(current, &a.spki, self.opts) {
                Ok(s) => {
                    schemes.push(s);
                    match self.check_constraints(leaf, path, a) {
                        Ok(()) => return Ok(ai),
                        Err(e) => {
                            schemes.pop();
                            note(&mut best, e);
                        }
                    }
                }
                Err(e) => note(&mut best, e),
            }
        }

        if path.len() + 1 >= self.opts.max_depth {
            return Err(best.unwrap_or(Error::new(
                ErrorKind::UnknownCa,
                "no trust anchor within the depth limit",
            )));
        }

        for i in 0..self.ints.len() {
            let cand = &self.ints[i];
            if cand.subject != current.issuer
                || path.contains(&i)
                || cand.der == leaf.der
                || key_ids_disagree(current, cand.ext.ski)
            {
                continue;
            }
            if *budget == 0 {
                return Err(Error::new(
                    ErrorKind::UnknownCa,
                    "path search budget exhausted",
                ));
            }
            *budget -= 1;
            if let Err(e) = check_issuer(cand, path.len(), self.opts) {
                note(&mut best, e);
                continue;
            }
            match check_signature(current, cand.spki, self.opts) {
                Err(e) => note(&mut best, e),
                Ok(s) => {
                    path.push(i);
                    schemes.push(s);
                    match self.extend(leaf, path, schemes, budget) {
                        Ok(a) => return Ok(a),
                        Err(e) => {
                            path.pop();
                            schemes.pop();
                            note(&mut best, e);
                        }
                    }
                }
            }
        }
        Err(best.unwrap_or(Error::new(
            ErrorKind::UnknownCa,
            "no path to a trust anchor",
        )))
    }
}

/// Verify that `end_entity` chains to an anchor in `roots` for `opts.usage`.
///
/// `intermediates` may be in any order and may contain unrelated or
/// unparseable certificates; those are ignored. Name matching is separate:
/// call [`verify_name`] as well.
pub fn verify_chain(
    end_entity: &[u8],
    intermediates: &[&[u8]],
    roots: &RootStore,
    opts: &VerifyOptions<'_>,
) -> Result<ChainReport> {
    let leaf = Certificate::parse(end_entity)?;
    if leaf.ext.unknown_critical {
        return Err(Error::new(
            ErrorKind::UnsupportedCertificate,
            "unknown critical extension",
        ));
    }
    // REQ-X509-006: the end entity is not a CA, and may sign.
    if leaf.is_ca() {
        return Err(Error::new(
            ErrorKind::CertificateUsage,
            "a CA certificate cannot be an end entity",
        ));
    }
    leaf.check_validity(opts.now)?;
    if let Some(ku) = leaf.ext.key_usage {
        if ku & KU_DIGITAL_SIGNATURE == 0 {
            return Err(Error::new(
                ErrorKind::CertificateUsage,
                "leaf key usage lacks digitalSignature",
            ));
        }
    }
    leaf.check_eku(opts.usage)?;
    let leaf_key = leaf.subject_public_key()?;
    check_key_policy(&leaf_key, opts)?;

    let mut report = ChainReport {
        depth: 0,
        leaf_key: leaf_key.kind_id(),
        schemes: Vec::new(),
        leaf_not_after: leaf.not_after,
        anchor_subject_cn: None,
        min_classical_bits: leaf_key.classical_bits(),
        issuer_subject: leaf.issuer.to_vec(),
        issuer_spki: leaf.spki.to_vec(),
        crl_checked: false,
    };

    // A leaf that is itself an anchor is pinned: accepted by exact key.
    if let Some(a) = roots
        .anchors
        .iter()
        .find(|a| a.subject == leaf.subject && a.spki == leaf.spki)
    {
        report.anchor_subject_cn = name_common_name(&a.subject).map(String::from);
        return Ok(report);
    }

    let search = Search {
        ints: intermediates
            .iter()
            .filter_map(|d| Certificate::parse(d).ok())
            .collect(),
        roots,
        opts,
    };
    let mut path = Vec::new();
    let mut budget = SEARCH_BUDGET;
    let anchor = search.extend(&leaf, &mut path, &mut report.schemes, &mut budget)?;
    let a = roots
        .anchors
        .get(anchor)
        .ok_or(Error::new(ErrorKind::Internal, "anchor index"))?;

    for &i in &path {
        let k = search.ints[i].subject_public_key()?;
        report.min_classical_bits = report.min_classical_bits.min(k.classical_bits());
    }
    let ak = PublicKey::from_spki(&a.spki)?;
    report.min_classical_bits = report.min_classical_bits.min(ak.classical_bits());
    report.depth = path.len() + 1;
    report.anchor_subject_cn = name_common_name(&a.subject).map(String::from);
    match path.first() {
        Some(&i) => {
            report.issuer_subject = search.ints[i].subject.to_vec();
            report.issuer_spki = search.ints[i].spki.to_vec();
        }
        None => {
            report.issuer_subject = a.subject.clone();
            report.issuer_spki = a.spki.clone();
        }
    }

    // Revocation by CRL, for every certificate below the anchor.
    // REQ-CRL-002, REQ-CRL-003.
    if opts.crls.is_some() || opts.require_crl {
        let empty = crl::CrlStore::new();
        let store = opts.crls.unwrap_or(&empty);
        let chain = search.chain_certs(&leaf, &path);
        let mut all_good = true;
        for (k, cert) in chain.iter().enumerate() {
            let (subject, spki, ku): (&[u8], &[u8], Option<u16>) = match chain.get(k + 1) {
                Some(issuer) => (issuer.subject, issuer.spki, issuer.ext.key_usage),
                None => (&a.subject, &a.spki, None),
            };
            let good = crl::check(
                cert,
                subject,
                spki,
                ku,
                store,
                opts.now,
                opts.allowed_schemes,
            )?;
            all_good &= good;
            if opts.require_crl && !good {
                return Err(Error::new(
                    ErrorKind::BadCertificateStatus,
                    "no current CRL from the issuer covers a certificate on the path",
                ));
            }
        }
        report.crl_checked = all_good;
    }
    Ok(report)
}

/// Certificate-path facts that borrow the initialized trust store and peer DER.
/// `REQ-FIX-003`: at most eight links and 100 candidate checks, without allocation.
pub struct FixedChainReport<'a> {
    /// Whether every non-anchor certificate was shown good by a current CRL.
    pub crl_checked: bool,
    /// Signature links, leaf first, followed by empty slots.
    pub schemes: [Option<SignatureScheme>; 8],
    /// Number of verified signature links.
    pub depth: usize,
    /// Weakest key strength on the accepted path.
    pub min_classical_bits: u16,
    /// Subject of the leaf issuer.
    pub issuer_subject: &'a [u8],
    /// Public key of the leaf issuer.
    pub issuer_spki: &'a [u8],
}

/// Check the leaf's validity, usages, critical extensions and key policy.
/// This also applies to pinned peers; no certificate verification is disabled.
pub fn check_leaf_fixed(der: &[u8], opts: &VerifyOptions<'_>) -> Result<()> {
    let leaf = Certificate::parse(der)?;
    if leaf.ext.unknown_critical {
        return Err(Error::new(
            ErrorKind::UnsupportedCertificate,
            "unknown critical extension",
        ));
    }
    let cannot_sign = || Error::new(ErrorKind::CertificateUsage, "leaf cannot sign handshakes");
    if leaf.is_ca() {
        return Err(cannot_sign());
    }
    // Validity before key usage, in the order `verify_chain` checks them, so
    // both validators refuse a leaf failing both for the same reason.
    leaf.check_validity(opts.now)?;
    if leaf
        .ext
        .key_usage
        .is_some_and(|ku| ku & KU_DIGITAL_SIGNATURE == 0)
    {
        return Err(cannot_sign());
    }
    leaf.check_eku(opts.usage)?;
    check_key_policy(&leaf.subject_public_key()?, opts)
}

/// Verify a certificate path using fixed slots. `REQ-FIX-003`.
pub fn verify_chain_fixed<'a>(
    end_entity: &'a [u8],
    intermediates: &[&'a [u8]],
    roots: &'a RootStore,
    opts: &VerifyOptions<'_>,
) -> Result<FixedChainReport<'a>> {
    if intermediates.len() > 7 || opts.max_depth > 8 {
        return Err(Error::new(
            ErrorKind::CapacityExceeded,
            "certificate path slots",
        ));
    }
    check_leaf_fixed(end_entity, opts)?;
    let leaf = Certificate::parse(end_entity)?;
    let mut ints: [Option<Certificate<'a>>; 7] = core::array::from_fn(|_| None);
    // Like `verify_chain`, ignore certificates that do not parse; an empty
    // slot is never a candidate.
    for (slot, der) in ints.iter_mut().zip(intermediates) {
        *slot = Certificate::parse(der).ok();
    }
    let mut report = FixedChainReport {
        crl_checked: false,
        schemes: [None; 8],
        depth: 0,
        min_classical_bits: leaf.subject_public_key()?.classical_bits(),
        issuer_subject: leaf.issuer,
        issuer_spki: leaf.spki,
    };
    if roots
        .anchors
        .iter()
        .any(|a| a.subject == leaf.subject && a.spki == leaf.spki)
    {
        return Ok(report);
    }
    struct SearchFixed<'a, 'o> {
        ints: [Option<Certificate<'a>>; 7],
        roots: &'a RootStore,
        opts: &'o VerifyOptions<'o>,
    }
    impl<'a> SearchFixed<'a, '_> {
        fn extend(
            &self,
            leaf: &Certificate<'a>,
            path: &mut [usize; 8],
            depth: usize,
            schemes: &mut [Option<SignatureScheme>; 8],
            budget: &mut usize,
        ) -> Result<usize> {
            let current = if depth == 0 {
                leaf
            } else {
                self.ints
                    .get(path[depth - 1])
                    .and_then(Option::as_ref)
                    .ok_or(bad("path slot"))?
            };
            let mut best = None;
            for (ai, anchor) in self.roots.anchors.iter().enumerate() {
                if !anchor.can_issue
                    || anchor.subject != current.issuer
                    || key_ids_disagree(current, anchor.ski.as_deref())
                {
                    continue;
                }
                if *budget == 0 {
                    return Err(Error::new(
                        ErrorKind::UnknownCa,
                        "path search budget exhausted",
                    ));
                }
                *budget -= 1;
                let result = (|| {
                    schemes[depth] = Some(check_signature(current, &anchor.spki, self.opts)?);
                    for k in 0..depth {
                        let issuer = self.ints[path[k]].as_ref().ok_or(bad("path slot"))?;
                        if let Some(nc) = issuer.ext.name_constraints {
                            apply_name_constraints(nc, &[leaf])?;
                            for &i in &path[..k] {
                                apply_name_constraints(
                                    nc,
                                    &[self.ints[i].as_ref().ok_or(bad("path slot"))?],
                                )?;
                            }
                        }
                    }
                    if let Some(nc) = &anchor.name_constraints {
                        apply_name_constraints(nc, &[leaf])?;
                        for &i in &path[..depth] {
                            apply_name_constraints(
                                nc,
                                &[self.ints[i].as_ref().ok_or(bad("path slot"))?],
                            )?;
                        }
                    }
                    Ok(ai)
                })();
                match result {
                    Ok(ai) => return Ok(ai),
                    Err(e) => note(&mut best, e),
                }
            }
            if depth + 1 >= self.opts.max_depth.min(8) {
                return Err(
                    best.unwrap_or(Error::new(ErrorKind::UnknownCa, "path depth exhausted"))
                );
            }
            for (i, cand) in self
                .ints
                .iter()
                .enumerate()
                .filter_map(|(i, c)| c.as_ref().map(|c| (i, c)))
            {
                if cand.subject != current.issuer
                    || path[..depth].contains(&i)
                    || cand.der == leaf.der
                    || key_ids_disagree(current, cand.ext.ski)
                {
                    continue;
                }
                if *budget == 0 {
                    return Err(Error::new(
                        ErrorKind::UnknownCa,
                        "path search budget exhausted",
                    ));
                }
                *budget -= 1;
                let result = (|| {
                    check_issuer(cand, depth, self.opts)?;
                    schemes[depth] = Some(check_signature(current, cand.spki, self.opts)?);
                    path[depth] = i;
                    self.extend(leaf, path, depth + 1, schemes, budget)
                })();
                match result {
                    Ok(ai) => return Ok(ai),
                    Err(e) => note(&mut best, e),
                }
                schemes[depth..].fill(None);
            }
            Err(best.unwrap_or(Error::new(
                ErrorKind::UnknownCa,
                "no path to a trust anchor",
            )))
        }
    }
    let search = SearchFixed { ints, roots, opts };
    let mut path = [0usize; 8];
    let mut budget = SEARCH_BUDGET;
    let ai = search.extend(&leaf, &mut path, 0, &mut report.schemes, &mut budget)?;
    let anchor = &roots.anchors[ai];
    report.depth = report.schemes.iter().take_while(|s| s.is_some()).count();
    report.min_classical_bits = report
        .min_classical_bits
        .min(PublicKey::from_spki(&anchor.spki)?.classical_bits());
    for &i in &path[..report.depth.saturating_sub(1)] {
        report.min_classical_bits = report.min_classical_bits.min(
            search.ints[i]
                .as_ref()
                .ok_or(bad("path slot"))?
                .subject_public_key()?
                .classical_bits(),
        );
    }
    if report.depth > 1 {
        let issuer = search.ints[path[0]].as_ref().ok_or(bad("path slot"))?;
        report.issuer_subject = issuer.subject;
        report.issuer_spki = issuer.spki;
    } else {
        report.issuer_subject = &anchor.subject;
        report.issuer_spki = &anchor.spki;
    }
    if opts.crls.is_some() || opts.require_crl {
        let empty = crl::CrlStore::new();
        let store = opts.crls.unwrap_or(&empty);
        let mut all_good = true;
        for k in 0..report.depth {
            let cert = if k == 0 {
                &leaf
            } else {
                search.ints[path[k - 1]].as_ref().ok_or(bad("path slot"))?
            };
            let (subject, spki, ku) = if k + 1 < report.depth {
                let issuer = search.ints[path[k]].as_ref().ok_or(bad("path slot"))?;
                (issuer.subject, issuer.spki, issuer.ext.key_usage)
            } else {
                (&anchor.subject[..], &anchor.spki[..], None)
            };
            let good = crl::check(
                cert,
                subject,
                spki,
                ku,
                store,
                opts.now,
                opts.allowed_schemes,
            )?;
            if opts.require_crl && !good {
                return Err(Error::new(
                    ErrorKind::BadCertificateStatus,
                    "no current CRL covers a certificate on the path",
                ));
            }
            all_good &= good;
        }
        report.crl_checked = all_good;
    }
    Ok(report)
}

/// Second-level labels that country-code registries commonly delegate
/// under, so that `co.uk` or `com.au` is a public suffix, not a domain.
const REGISTRY_SECOND_LEVEL: &[&str] = &[
    "ac", "co", "com", "edu", "gob", "gov", "govt", "ltd", "mil", "ne", "net", "nhs", "nic", "or",
    "org", "plc", "sch",
];

/// Whether `suffix` is `<registry label>.<two-letter country code>`.
/// REQ-X509-078: a heuristic, not a public-suffix list (none ships in a
/// zero-dependency library). It refuses `*.co.uk` and the like; a wildcard
/// over a private suffix (a hosting provider's domain) is not caught.
fn is_registry_suffix(suffix: &str) -> bool {
    let suffix = suffix.strip_suffix('.').unwrap_or(suffix);
    match suffix.split_once('.') {
        Some((second, tld)) => {
            tld.len() == 2
                && tld.bytes().all(|b| b.is_ascii_alphabetic())
                && REGISTRY_SECOND_LEVEL
                    .iter()
                    .any(|l| l.eq_ignore_ascii_case(second))
        }
        None => false,
    }
}

/// Whether presented `dNSName` `pattern` covers reference name `name`.
/// `REQ-X509-003`: wildcards only as the whole leftmost label, matching exactly
/// one label, and only above at least two further labels.
fn dns_matches(pattern: &str, name: &str) -> bool {
    let pattern = pattern.strip_suffix('.').unwrap_or(pattern);
    if !is_valid_dns_name(pattern, true) {
        return false;
    }
    match pattern.strip_prefix("*.") {
        Some(suffix) => {
            if suffix.split('.').count() < 2 || is_registry_suffix(suffix) {
                return false;
            }
            match name.split_once('.') {
                Some((first, rest)) => !first.is_empty() && dns_eq(rest, suffix),
                None => false,
            }
        }
        None => !pattern.contains('*') && dns_eq(pattern, name),
    }
}

/// Verify that `end_entity` covers `name` through its subject alternative
/// names. The subject common name is never consulted.
pub fn verify_name(end_entity: &[u8], name: &ServerName<'_>) -> Result<()> {
    let cert = Certificate::parse(end_entity)?;
    let mut names = Der::new(cert.ext.san.unwrap_or(&[]));
    let mut ok = false;
    while !names.is_empty() {
        let (tag, value, _) = names.tlv()?;
        ok |= match name {
            ServerName::Dns(n) if tag == T_GN_DNS => {
                core::str::from_utf8(value).is_ok_and(|p| dns_matches(p, n))
            }
            ServerName::Ip(ip) if tag == T_GN_IP => value == ip.octets(),
            _ => false,
        };
    }
    if ok {
        Ok(())
    } else {
        Err(Error::new(
            ErrorKind::CertificateNameMismatch,
            "certificate does not cover the server name",
        ))
    }
}

// ---------------------------------------------------------------------------
// Issuance
// ---------------------------------------------------------------------------

/// What to put in a certificate.
#[derive(Debug, Clone, Copy)]
pub struct CertificateParams<'a> {
    /// Subject common name; may be empty when there are alternative names.
    pub subject_cn: &'a str,
    /// DNS subject alternative names.
    pub dns_names: &'a [&'a str],
    /// IP subject alternative names.
    pub ip_addresses: &'a [IpAddr],
    /// Start of validity, Unix seconds.
    pub not_before: u64,
    /// End of validity, Unix seconds.
    pub not_after: u64,
    /// Whether this is a CA certificate.
    pub is_ca: bool,
    /// Path length constraint; setting this requires `is_ca` to be true.
    pub path_len: Option<u8>,
    /// Extended key usages; empty for none.
    pub usage: &'a [Usage],
    /// Serial number; made positive and minimal on encoding.
    pub serial: [u8; 16],
}

fn encode_name(cn: &str) -> Vec<u8> {
    let mut out = Vec::new();
    if cn.is_empty() {
        push_tlv(&mut out, T_SEQUENCE, &[]);
        return out;
    }
    let mut atv = Vec::new();
    push_tlv(&mut atv, T_OID, OID_CN);
    push_tlv(&mut atv, T_UTF8, cn.as_bytes());
    let mut seq = Vec::new();
    push_tlv(&mut seq, T_SEQUENCE, &atv);
    let mut set = Vec::new();
    push_tlv(&mut set, T_SET, &seq);
    push_tlv(&mut out, T_SEQUENCE, &set);
    out
}

fn push_ext(out: &mut Vec<u8>, oid: &[u8], critical: bool, value: &[u8]) {
    let mut body = Vec::new();
    push_tlv(&mut body, T_OID, oid);
    if critical {
        push_tlv(&mut body, T_BOOLEAN, &[0xff]);
    }
    push_tlv(&mut body, T_OCTET_STRING, value);
    push_tlv(out, T_SEQUENCE, &body);
}

/// REQ-X509-026: RFC 7093 method 1 hashes only the public-key octets,
/// excluding the BIT STRING's unused-bit-count octet.
fn key_identifier(spki: &[u8]) -> Result<Vec<u8>> {
    // RFC 7093 §2 method 1: leftmost 160 bits of SHA-256 of the key bits.
    let mut outer = Der::new(spki);
    let mut s = outer.nested(T_SEQUENCE)?;
    let _ = s.expect(T_SEQUENCE)?;
    let key = whole_bits(s.expect(T_BIT_STRING)?)?;
    let d = HashAlg::Sha256.digest(key);
    Ok(d.as_bytes()[..20].to_vec())
}

fn key_usage_bits(bits: u16) -> Vec<u8> {
    // Named bit list: trailing zero bits are dropped (X.690 §11.2.2).
    let mut bytes = [0u8; 2];
    for i in 0..9 {
        if bits & (1 << i) != 0 {
            bytes[i / 8] |= 0x80 >> (i % 8);
        }
    }
    let len = if bytes[1] != 0 { 2 } else { 1 };
    let last = bytes[len - 1];
    let unused = if last == 0 {
        0
    } else {
        last.trailing_zeros() as u8
    };
    let mut out = alloc::vec![unused];
    out.extend_from_slice(&bytes[..len]);
    out
}

/// Build and sign a certificate. `extra` is appended to the extensions
/// verbatim; it exists for tests of extension handling.
/// REQ-X509-022: issuance rejects reversed validity intervals; equal endpoints are allowed.
/// REQ-X509-023: a configured path length requires a CA certificate and is preserved.
/// REQ-X509-024: an issued certificate needs a subject name or alternative name.
/// REQ-X509-025: every configured DNS alternative name passes syntax and length checks.
/// REQ-X509-027: issuance requires a subject SPKI accepted by the crypto adapter.
#[allow(clippy::too_many_arguments)]
fn build(
    params: &CertificateParams<'_>,
    subject_spki: &[u8],
    issuer_name: &[u8],
    issuer_ki: &[u8],
    issuer_key: &SigningKey,
    rng: &mut dyn RandomSource,
    extra: &[Vec<u8>],
) -> Result<Vec<u8>> {
    let cfg = |c| Error::new(ErrorKind::InvalidConfig, c);
    if params.not_after < params.not_before {
        return Err(cfg("certificate validity ends before it begins"));
    }
    if params.path_len.is_some() && !params.is_ca {
        return Err(cfg("certificate path length requires a CA"));
    }
    if params.subject_cn.is_empty() && params.dns_names.is_empty() && params.ip_addresses.is_empty()
    {
        return Err(cfg(
            "a certificate needs a subject name or an alternative name",
        ));
    }
    for n in params.dns_names {
        if !is_valid_dns_name(n, true) {
            return Err(cfg("invalid DNS name in certificate parameters"));
        }
    }
    PublicKey::from_spki(subject_spki).map_err(|_| cfg("subject public key is not usable"))?;
    let scheme = *issuer_key
        .schemes()
        .first()
        .ok_or(cfg("issuer key has no scheme"))?;
    let alg = alg_id(scheme)?;

    let mut tbs = Vec::new();
    push_tlv(&mut tbs, T_CTX0, &[T_INTEGER, 1, 2]);
    let mut serial: Vec<u8> = params
        .serial
        .iter()
        .copied()
        .skip_while(|b| *b == 0)
        .collect();
    if serial.is_empty() {
        serial.push(1);
    }
    if serial[0] & 0x80 != 0 {
        serial.insert(0, 0);
    }
    push_tlv(&mut tbs, T_INTEGER, &serial);
    tbs.extend_from_slice(&alg);
    tbs.extend_from_slice(issuer_name);
    let mut validity = Vec::new();
    encode_time(&mut validity, params.not_before)?;
    encode_time(&mut validity, params.not_after)?;
    push_tlv(&mut tbs, T_SEQUENCE, &validity);
    tbs.extend_from_slice(&encode_name(params.subject_cn));
    tbs.extend_from_slice(subject_spki);

    let mut exts = Vec::new();
    let mut bc = Vec::new();
    if params.is_ca {
        push_tlv(&mut bc, T_BOOLEAN, &[0xff]);
        if let Some(n) = params.path_len {
            let v: &[u8] = if n & 0x80 != 0 { &[0, n] } else { &[n] };
            push_tlv(&mut bc, T_INTEGER, v);
        }
    }
    let mut bcv = Vec::new();
    push_tlv(&mut bcv, T_SEQUENCE, &bc);
    push_ext(&mut exts, OID_EXT_BC, true, &bcv);

    let ku = if params.is_ca {
        KU_DIGITAL_SIGNATURE | KU_KEY_CERT_SIGN | KU_CRL_SIGN
    } else {
        KU_DIGITAL_SIGNATURE
    };
    let mut kuv = Vec::new();
    push_tlv(&mut kuv, T_BIT_STRING, &key_usage_bits(ku));
    push_ext(&mut exts, OID_EXT_KU, true, &kuv);

    if !params.usage.is_empty() {
        let mut body = Vec::new();
        for u in params.usage {
            push_tlv(&mut body, T_OID, u.oid());
        }
        let mut v = Vec::new();
        push_tlv(&mut v, T_SEQUENCE, &body);
        push_ext(&mut exts, OID_EXT_EKU, false, &v);
    }

    if !params.dns_names.is_empty() || !params.ip_addresses.is_empty() {
        let mut body = Vec::new();
        for n in params.dns_names {
            push_tlv(&mut body, T_GN_DNS, n.as_bytes());
        }
        for ip in params.ip_addresses {
            push_tlv(&mut body, T_GN_IP, ip.octets());
        }
        let mut v = Vec::new();
        push_tlv(&mut v, T_SEQUENCE, &body);
        // An empty subject makes the SAN critical (RFC 5280 §4.2.1.6).
        push_ext(&mut exts, OID_EXT_SAN, params.subject_cn.is_empty(), &v);
    }

    let mut ski = Vec::new();
    push_tlv(&mut ski, T_OCTET_STRING, &key_identifier(subject_spki)?);
    push_ext(&mut exts, OID_EXT_SKI, false, &ski);
    let mut aki_body = Vec::new();
    push_tlv(&mut aki_body, 0x80, issuer_ki);
    let mut aki = Vec::new();
    push_tlv(&mut aki, T_SEQUENCE, &aki_body);
    push_ext(&mut exts, OID_EXT_AKI, false, &aki);

    for e in extra {
        exts.extend_from_slice(e);
    }
    let mut ext_seq = Vec::new();
    push_tlv(&mut ext_seq, T_SEQUENCE, &exts);
    push_tlv(&mut tbs, T_CTX3, &ext_seq);

    let mut tbs_der = Vec::new();
    push_tlv(&mut tbs_der, T_SEQUENCE, &tbs);
    let sig = issuer_key.sign(scheme, &tbs_der, rng)?;
    let mut bits = Vec::with_capacity(sig.len() + 1);
    bits.push(0);
    bits.extend_from_slice(&sig);

    let mut cert = tbs_der;
    cert.extend_from_slice(&alg);
    push_tlv(&mut cert, T_BIT_STRING, &bits);
    let mut out = Vec::new();
    push_tlv(&mut out, T_SEQUENCE, &cert);
    Ok(out)
}

/// Issue a self-signed certificate for `key`.
/// REQ-X509-020: self-signed issuance requires a nonempty issuer common name.
pub fn self_signed(
    params: &CertificateParams<'_>,
    key: &SigningKey,
    rng: &mut dyn RandomSource,
) -> Result<Vec<u8>> {
    if params.subject_cn.is_empty() {
        return Err(Error::new(
            ErrorKind::InvalidConfig,
            "self-signed issuer name is empty",
        ));
    }
    let name = encode_name(params.subject_cn);
    let ki = key_identifier(key.spki())?;
    build(params, key.spki(), &name, &ki, key, rng, &[])
}

/// Issue a certificate for `subject_spki`, signed by the holder of
/// `issuer_key`, whose certificate is `issuer_cert_der`.
/// REQ-X509-021: issuance requires a nonempty subject Name on the issuer certificate.
pub fn issue(
    params: &CertificateParams<'_>,
    subject_spki: &[u8],
    issuer_cert_der: &[u8],
    issuer_key: &SigningKey,
    rng: &mut dyn RandomSource,
) -> Result<Vec<u8>> {
    let issuer = Certificate::parse(issuer_cert_der)?;
    if Der::new(issuer.subject).expect(T_SEQUENCE)?.is_empty() {
        return Err(Error::new(
            ErrorKind::InvalidConfig,
            "issuer certificate subject name is empty",
        ));
    }
    if issuer.spki != issuer_key.spki() {
        return Err(Error::new(
            ErrorKind::InvalidConfig,
            "issuer key does not match the issuer certificate",
        ));
    }
    let ki = match issuer.ext.ski {
        Some(k) => k.to_vec(),
        None => key_identifier(issuer.spki)?,
    };
    build(
        params,
        subject_spki,
        issuer.subject,
        &ki,
        issuer_key,
        rng,
        &[],
    )
}

/// Run both path validators and require them to agree, so the fixed-slot
/// search (`REQ-FIX-003`) cannot drift from the owned one: acceptance with the
/// same path facts, or refusal with the same error kind. The fixed search's
/// own slot limits are the one sanctioned difference.
#[cfg(test)]
fn verify_both(
    leaf: &[u8],
    ints: &[&[u8]],
    roots: &RootStore,
    opts: &VerifyOptions<'_>,
) -> Result<ChainReport> {
    let owned = verify_chain(leaf, ints, roots, opts);
    let fixed = verify_chain_fixed(leaf, ints, roots, opts);
    if ints.len() > 7 || opts.max_depth > 8 {
        assert_eq!(
            fixed.err().map(|e| e.kind()),
            Some(ErrorKind::CapacityExceeded),
            "the fixed search must refuse inputs beyond its slots"
        );
        return owned;
    }
    match (&owned, &fixed) {
        (Ok(o), Ok(f)) => {
            assert_eq!(o.depth, f.depth, "path depth");
            let fs: Vec<SignatureScheme> = f.schemes.iter().flatten().copied().collect();
            assert_eq!(o.schemes, fs, "path schemes");
            assert_eq!(o.min_classical_bits, f.min_classical_bits, "path strength");
            assert_eq!(o.crl_checked, f.crl_checked, "CRL coverage");
        }
        (Err(a), Err(b)) => {
            assert_eq!(a.kind(), b.kind(), "owned refused with {a}, fixed with {b}")
        }
        (Ok(_), Err(b)) => panic!("owned validator accepted; fixed refused with {b}"),
        (Err(a), Ok(_)) => panic!("fixed validator accepted; owned refused with {a}"),
    }
    owned
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Synthetic encodings exercise the minimum-octet rule in X.690 section 8.3.2.
    #[test]
    fn unsigned_integers_require_minimal_der_encoding() {
        for (bytes, expected) in [
            (&[][..], None),
            (&[0][..], Some(0)),
            (&[1][..], Some(1)),
            (&[0x7f][..], Some(127)),
            (&[0, 0x80][..], Some(128)),
            (&[0, 0xff][..], Some(255)),
            (&[1, 0][..], Some(256)),
            (&[0, 0][..], None),
            (&[0, 1][..], None),
            (&[0, 0x7f][..], None),
            (&[0, 0, 0x80][..], None),
            (&[0x80][..], None),
            (&[0xff][..], None),
            (
                &[0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff][..],
                Some(u64::MAX),
            ),
            (&[1, 0, 0, 0, 0, 0, 0, 0, 0][..], None),
        ] {
            let integer = small_uint(bytes);
            let mut basic = Vec::new();
            push_tlv(&mut basic, T_BOOLEAN, &[0xff]);
            push_tlv(&mut basic, T_INTEGER, bytes);
            let mut value = Vec::new();
            push_tlv(&mut value, T_SEQUENCE, &basic);
            let mut extension = Vec::new();
            push_ext(&mut extension, OID_EXT_BC, true, &value);
            let mut extensions = Vec::new();
            push_tlv(&mut extensions, T_SEQUENCE, &extension);
            let parsed = parse_extensions(&extensions);
            if let Some(expected) = expected {
                assert_eq!(integer.unwrap(), expected);
                assert_eq!(parsed.unwrap().basic, Some((true, Some(expected))));
            } else {
                assert_eq!(integer.unwrap_err().kind(), ErrorKind::BadCertificate);
                assert_eq!(parsed.unwrap_err().kind(), ErrorKind::BadCertificate);
            }
        }
    }

    #[test]
    fn times_convert_both_ways() {
        assert_eq!(parse_time(T_UTC_TIME, b"700101000000Z").unwrap(), 0);
        assert_eq!(
            parse_time(T_GENERALIZED_TIME, b"20380119031408Z").unwrap(),
            1 << 31
        );
        assert_eq!(
            parse_time(T_UTC_TIME, b"000229000000Z").unwrap(),
            951_782_400
        );
        assert!(
            parse_time(T_UTC_TIME, b"010229000000Z").is_err(),
            "2001 is not a leap year"
        );
        assert!(
            parse_time(T_UTC_TIME, b"7001010000Z").is_err(),
            "seconds are required"
        );
        assert!(parse_time(T_UTC_TIME, b"700101000000+0100").is_err());
        assert_eq!(
            parse_time(T_UTC_TIME, b"500101000000Z").unwrap(),
            0,
            "1950 clamps to 0"
        );
        for t in [0u64, 951_782_400, 1 << 31, 2_524_607_999, 4_102_444_800] {
            let mut v = Vec::new();
            encode_time(&mut v, t).unwrap();
            let mut r = Der::new(&v);
            let (tag, c, _) = r.tlv().unwrap();
            assert_eq!(parse_time(tag, c).unwrap(), t);
        }
    }

    #[test]
    fn ip_and_name_parsing() {
        assert_eq!(IpAddr::parse("192.0.2.1"), Some(IpAddr::V4([192, 0, 2, 1])));
        assert_eq!(IpAddr::parse("01.2.3.4"), None);
        assert_eq!(IpAddr::parse("1.2.3"), None);
        assert_eq!(IpAddr::parse("256.0.0.1"), None);
        let mut one = [0u8; 16];
        one[15] = 1;
        assert_eq!(IpAddr::parse("::1"), Some(IpAddr::V6(one)));
        assert_eq!(IpAddr::parse("[::1]"), Some(IpAddr::V6(one)));
        let mut v = [0u8; 16];
        v[..4].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8]);
        v[15] = 1;
        assert_eq!(IpAddr::parse("2001:db8::1"), Some(IpAddr::V6(v)));
        assert_eq!(IpAddr::parse("1::2::3"), None);
        assert_eq!(IpAddr::parse("1:2:3:4:5:6:7:8:9"), None);
        let mut m = [0u8; 16];
        m[10] = 0xff;
        m[11] = 0xff;
        m[12..].copy_from_slice(&[192, 0, 2, 1]);
        assert_eq!(IpAddr::parse("::ffff:192.0.2.1"), Some(IpAddr::V6(m)));
        assert_eq!(
            ServerName::parse("example.com.").unwrap(),
            ServerName::Dns("example.com")
        );
        assert!(ServerName::parse("").is_err());
        assert!(ServerName::parse("bad..name").is_err());
        assert!(ServerName::parse("-bad.example").is_err());
        assert!(ServerName::parse("*.example.com").is_err());
    }

    #[test]
    fn wildcard_rules() {
        assert!(dns_matches("*.example.com", "a.example.com"));
        assert!(dns_matches("*.example.com", "A.EXAMPLE.com"));
        assert!(!dns_matches("*.example.com", "example.com"));
        assert!(!dns_matches("*.example.com", "a.b.example.com"));
        assert!(!dns_matches("*.com", "example.com"));
        assert!(!dns_matches("f*.example.com", "foo.example.com"));
        assert!(!dns_matches("a.*.example.com", "a.b.example.com"));
        assert!(!dns_matches("*", "localhost"));
        assert!(dns_matches("Example.COM", "example.com"));
        assert!(!dns_matches("example.com", "example.com.evil"));
    }

    /// REQ-RPT-003: addresses are reported in RFC 5952 text.
    #[test]
    fn ip_addresses_display_in_rfc_5952_form() {
        for text in [
            "192.0.2.1",
            "0.0.0.0",
            "::",
            "::1",
            "1::",
            "2001:db8::1",
            "2001:db8:0:1:1:1:1:1",
            "2001:0:0:1::1",
            "2001:db8::1:0:0:1",
            "fe80::abcd:0:0:1",
            "1:2:3:4:5:6:7:8",
        ] {
            assert_eq!(alloc::format!("{}", IpAddr::parse(text).unwrap()), text);
        }
        assert_eq!(
            alloc::format!("{}", IpAddr::parse("2001:DB8:0000:0:0:0:0:0001").unwrap()),
            "2001:db8::1"
        );
    }

    /// REQ-X509-078: a wildcard directly over a registry suffix such as
    /// `co.uk` covers nothing; one a level below still works.
    #[test]
    fn wildcards_over_registry_suffixes_cover_nothing() {
        for pattern in [
            "*.co.uk",
            "*.CO.UK",
            "*.com.au",
            "*.ac.jp",
            "*.gov.uk",
            "*.org.nz.",
        ] {
            let host = alloc::format!(
                "victim.{}",
                pattern.trim_start_matches("*.").trim_end_matches('.')
            );
            assert!(!dns_matches(pattern, &host), "{pattern}");
        }
        assert!(dns_matches("*.example.co.uk", "www.example.co.uk"));
        assert!(dns_matches("*.co.example", "a.co.example"));
        assert!(dns_matches("*.github.io", "a.github.io"));
        // An exact name under a registry suffix is still matched.
        assert!(dns_matches("co.uk", "co.uk"));
    }

    #[test]
    fn dns_subtrees() {
        assert!(dns_within("example.com", "example.com"));
        assert!(dns_within("a.example.com", "example.com"));
        assert!(!dns_within("badexample.com", "example.com"));
        assert!(dns_within("a.example.com", ".example.com"));
        assert!(!dns_within("example.com", ".example.com"));
        assert!(dns_within("anything", ""));
        assert!(ip_within(&[10, 1, 2, 3], &[10, 0, 0, 0, 255, 0, 0, 0]));
        assert!(!ip_within(&[11, 1, 2, 3], &[10, 0, 0, 0, 255, 0, 0, 0]));
    }

    /// REQ-X509-017: AKI accepts key IDs and paired issuer/serial references;
    /// unpaired, repeated, out-of-order and trailing fields are refused.
    #[test]
    fn authority_key_identifier_fields_are_paired_and_consumed() {
        let mut issuer_names = Vec::new();
        push_tlv(&mut issuer_names, T_GN_DNS, b"issuer.example");
        let fields = |key: bool, issuer: bool, serial: bool| {
            let mut body = Vec::new();
            if key {
                push_tlv(&mut body, 0x80, &[1, 2]);
            }
            if issuer {
                push_tlv(&mut body, T_CTX1, &issuer_names);
            }
            if serial {
                push_tlv(&mut body, 0x82, &[1]);
            }
            body
        };
        let mut cases = Vec::new();
        for key in [false, true] {
            for (issuer, serial) in [(false, false), (true, true), (true, false), (false, true)] {
                cases.push((fields(key, issuer, serial), issuer == serial, key));
            }
        }
        let mut trailing = fields(true, true, true);
        trailing.extend_from_slice(&[0x05, 0]);
        cases.push((trailing, false, true));
        let mut repeated = fields(true, false, false);
        push_tlv(&mut repeated, 0x80, &[3]);
        cases.push((repeated, false, true));
        let mut reversed = fields(false, false, true);
        push_tlv(&mut reversed, T_CTX1, &issuer_names);
        cases.push((reversed, false, false));
        let mut repeated_issuer = fields(false, true, true);
        push_tlv(&mut repeated_issuer, T_CTX1, &issuer_names);
        cases.push((repeated_issuer, false, false));
        for (body, accepted, key) in cases {
            let mut value = Vec::new();
            push_tlv(&mut value, T_SEQUENCE, &body);
            let mut entry = Vec::new();
            push_ext(&mut entry, OID_EXT_AKI, false, &value);
            let mut encoded = Vec::new();
            push_tlv(&mut encoded, T_SEQUENCE, &entry);
            let result = parse_extensions(&encoded);
            if accepted {
                assert_eq!(
                    result.unwrap().aki,
                    if key { Some(&[1, 2][..]) } else { None }
                );
            } else {
                assert_eq!(result.err().unwrap().kind(), ErrorKind::BadCertificate);
            }
        }
    }

    /// REQ-X509-046: unused issuer references still contain a complete, nonempty
    /// GeneralNames list; invalid first or last entries cannot be ignored.
    #[test]
    fn authority_key_identifier_issuer_names_require_complete_defined_choices() {
        let name = |tag, value: &[u8]| {
            let mut encoded = Vec::new();
            push_tlv(&mut encoded, tag, value);
            encoded
        };
        let dns = name(T_GN_DNS, b"issuer.example");
        let directory = name(0xa4, &encode_name("Authority issuer"));
        let email = name(0x81, b"issuer@example.test");
        let uri = name(0x86, b"https://issuer.example");
        let ip = name(T_GN_IP, &[192, 0, 2, 1]);
        let registered = name(0x88, &[0x2a, 3]);
        let other = name(T_CTX0, &[T_OID, 2, 0x2a, 3, T_CTX0, 2, T_NULL, 0]);
        let edi = name(0xa5, &[T_CTX1, 3, T_UTF8, 1, b'A']);
        let x400 = name(0xa3, &[T_SEQUENCE, 0]);
        let valid = [
            dns.clone(),
            directory,
            email,
            uri,
            ip,
            registered,
            other,
            edi,
            x400,
        ];
        let mut cases = Vec::new();
        for encoded in &valid {
            cases.push((encoded.clone(), true));
        }
        cases.push((valid.concat(), true));
        cases.push((Vec::new(), false));
        for tag in 0..=u8::MAX {
            // The ASN.1 choice has these nine tags, including constructed forms.
            if matches!(
                tag,
                0xa0 | 0x81 | 0x82 | 0xa3 | 0xa4 | 0xa5 | 0x86 | 0x87 | 0x88
            ) {
                continue;
            }
            for first in [false, true] {
                let invalid = name(tag, &[0x05, 0]);
                let encoded = if first {
                    [invalid, dns.clone()].concat()
                } else {
                    [dns.clone(), invalid].concat()
                };
                cases.push((encoded, false));
            }
        }
        for tail in [
            &[T_GN_DNS][..],
            &[T_GN_DNS, 2, b'a'][..],
            &[T_GN_DNS, 0x80][..],
        ] {
            cases.push(([dns.as_slice(), tail].concat(), false));
        }
        for (issuer_names, accepted) in cases {
            for key in [false, true] {
                for critical in [false, true] {
                    let mut body = Vec::new();
                    if key {
                        push_tlv(&mut body, 0x80, &[1, 2]);
                    }
                    push_tlv(&mut body, T_CTX1, &issuer_names);
                    push_tlv(&mut body, 0x82, &[1]);
                    let mut value = Vec::new();
                    push_tlv(&mut value, T_SEQUENCE, &body);
                    let mut extension = Vec::new();
                    push_ext(&mut extension, OID_EXT_AKI, critical, &value);
                    let mut extensions = Vec::new();
                    push_tlv(&mut extensions, T_SEQUENCE, &extension);
                    let result = parse_extensions(&extensions);
                    if accepted {
                        assert_eq!(
                            result.unwrap().aki,
                            if key { Some(&[1, 2][..]) } else { None }
                        );
                    } else {
                        assert_eq!(
                            result.err().unwrap().kind(),
                            ErrorKind::BadCertificate,
                            "issuer={issuer_names:?}, key={key}, critical={critical}"
                        );
                    }
                }
            }
        }
    }

    /// REQ-X509-047: registeredID payloads cannot hide malformed OIDs in
    /// otherwise well-framed issuer references, before or after valid names.
    #[test]
    fn authority_key_identifier_registered_ids_require_minimal_oids() {
        let mut dns = Vec::new();
        push_tlv(&mut dns, T_GN_DNS, b"issuer.example");
        for (oid, expected_error) in [
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
            let mut registered = Vec::new();
            push_tlv(&mut registered, 0x88, oid);
            for names in [
                registered.clone(),
                [registered.as_slice(), dns.as_slice()].concat(),
                [dns.as_slice(), registered.as_slice()].concat(),
            ] {
                for key in [false, true] {
                    for critical in [false, true] {
                        let mut body = Vec::new();
                        if key {
                            push_tlv(&mut body, 0x80, &[1, 2]);
                        }
                        push_tlv(&mut body, T_CTX1, &names);
                        push_tlv(&mut body, 0x82, &[1]);
                        let mut value = Vec::new();
                        push_tlv(&mut value, T_SEQUENCE, &body);
                        let mut extension = Vec::new();
                        push_ext(&mut extension, OID_EXT_AKI, critical, &value);
                        let mut extensions = Vec::new();
                        push_tlv(&mut extensions, T_SEQUENCE, &extension);
                        let result = parse_extensions(&extensions);
                        if let Some(context) = expected_error {
                            let error = result.err().unwrap();
                            assert_eq!(error.kind(), ErrorKind::BadCertificate);
                            assert_eq!(error.context(), context);
                        } else {
                            assert_eq!(
                                result.unwrap().aki,
                                if key { Some(&[1, 2][..]) } else { None }
                            );
                        }
                    }
                }
            }
        }
    }

    /// REQ-X509-052: AKI IP addresses have four or sixteen octets, including
    /// entries before or after another name and address/mask-shaped payloads.
    #[test]
    fn authority_key_identifier_ip_names_require_address_lengths() {
        let mut control = Vec::new();
        push_tlv(&mut control, T_GN_DNS, b"issuer.example");
        for len in (0..=33).chain([127, 128, 255, 256]) {
            for byte in [0, 0xff] {
                let address = alloc::vec![byte; len];
                let mut encoded = Vec::new();
                push_tlv(&mut encoded, T_GN_IP, &address);
                for names in [
                    encoded.clone(),
                    [encoded.as_slice(), control.as_slice()].concat(),
                    [control.as_slice(), encoded.as_slice()].concat(),
                ] {
                    for key in [false, true] {
                        for critical in [false, true] {
                            let mut body = Vec::new();
                            if key {
                                push_tlv(&mut body, 0x80, &[1, 2]);
                            }
                            push_tlv(&mut body, T_CTX1, &names);
                            push_tlv(&mut body, 0x82, &[1]);
                            let mut aki = Vec::new();
                            push_tlv(&mut aki, T_SEQUENCE, &body);
                            let mut extension = Vec::new();
                            push_ext(&mut extension, OID_EXT_AKI, critical, &aki);
                            let mut extensions = Vec::new();
                            push_tlv(&mut extensions, T_SEQUENCE, &extension);
                            let result = parse_extensions(&extensions);
                            if len == 4 || len == 16 {
                                assert_eq!(
                                    result.unwrap().aki,
                                    if key { Some(&[1, 2][..]) } else { None }
                                );
                            } else {
                                let error = result.err().unwrap();
                                assert_eq!(error.kind(), ErrorKind::BadCertificate);
                                assert_eq!(
                                    error.context(),
                                    "authority certificate issuer iPAddress length"
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    /// REQ-X509-051: every IA5 issuer-name byte is ASCII, including later entries;
    /// unconstrained empty IA5Strings retain their ASN.1 representation.
    #[test]
    fn authority_key_identifier_ia5strings_require_ascii() {
        let mut control = Vec::new();
        push_tlv(&mut control, 0x88, &[0x2a, 3]);
        let ascii = (0..=0x7f).collect::<Vec<u8>>();
        let mut values = alloc::vec![Vec::new(), ascii];
        for byte in 0x80..=u8::MAX {
            values.extend([
                alloc::vec![byte],
                alloc::vec![byte, b'A'],
                alloc::vec![b'A', byte, b'B'],
                alloc::vec![b'A', byte],
            ]);
        }
        for tag in [0x81, T_GN_DNS, 0x86] {
            for value in &values {
                let mut encoded = Vec::new();
                push_tlv(&mut encoded, tag, value);
                for names in [
                    encoded.clone(),
                    [encoded.as_slice(), control.as_slice()].concat(),
                    [control.as_slice(), encoded.as_slice()].concat(),
                ] {
                    for key in [false, true] {
                        for critical in [false, true] {
                            let mut body = Vec::new();
                            if key {
                                push_tlv(&mut body, 0x80, &[1, 2]);
                            }
                            push_tlv(&mut body, T_CTX1, &names);
                            push_tlv(&mut body, 0x82, &[1]);
                            let mut aki = Vec::new();
                            push_tlv(&mut aki, T_SEQUENCE, &body);
                            let mut extension = Vec::new();
                            push_ext(&mut extension, OID_EXT_AKI, critical, &aki);
                            let mut extensions = Vec::new();
                            push_tlv(&mut extensions, T_SEQUENCE, &extension);
                            let result = parse_extensions(&extensions);
                            if value.is_ascii() {
                                assert_eq!(
                                    result.unwrap().aki,
                                    if key { Some(&[1, 2][..]) } else { None }
                                );
                            } else {
                                let error = result.err().unwrap();
                                assert_eq!(error.kind(), ErrorKind::BadCertificate);
                                assert_eq!(
                                    error.context(),
                                    "authority certificate issuer IA5String is non-ASCII"
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    /// REQ-X509-050: EDI issuer references validate every ordered string field,
    /// regardless of list position, key identifier presence, or criticality.
    #[test]
    fn authority_key_identifier_edi_names_require_ordered_valid_strings() {
        let field = |tag, string: &[u8]| {
            let mut out = Vec::new();
            push_tlv(&mut out, tag, string);
            out
        };
        let party = field(T_CTX1, &[T_UTF8, 1, b'A']);
        let assigner = field(T_CTX0, &[T_UTF8, 1, b'B']);
        let mut cases = alloc::vec![
            (party.clone(), true),
            ([assigner.clone(), party.clone()].concat(), true),
            (Vec::new(), false),
            (assigner.clone(), false),
            ([party.clone(), assigner.clone()].concat(), false),
            ([assigner.clone(), assigner, party.clone()].concat(), false),
            ([party.clone(), party.clone()].concat(), false),
            ([party.clone(), alloc::vec![T_NULL, 0]].concat(), false),
            (field(0x81, &[T_UTF8, 1, b'A']), false),
        ];
        for string in [
            &[T_UTF8, 2, 0xc3, 0xa9][..],
            &[T_PRINTABLE, 1, b'?'][..],
            &[T_T61, 1, 0xff][..],
            &[0x1e, 2, 0, b'A'][..],
            &[0x1c, 4, 0, 0, 0, b'A'][..],
        ] {
            cases.push((field(T_CTX1, string), true));
            cases.push(([field(T_CTX0, string), party.clone()].concat(), true));
        }
        for string in [
            &[][..],
            &[T_UTF8, 0][..],
            &[T_UTF8, 2, b'A'][..],
            &[T_UTF8, 1, 0xff][..],
            &[T_UTF8, 2, 0xc0, 0x80][..],
            &[T_PRINTABLE, 1, b'@'][..],
            &[0x1e, 1, b'A'][..],
            &[0x1c, 3, 0, 0, b'A'][..],
            &[T_NULL, 0][..],
            &[T_UTF8, 1, b'A', T_NULL, 0][..],
        ] {
            cases.push((field(T_CTX1, string), false));
            cases.push(([field(T_CTX0, string), party.clone()].concat(), false));
        }
        let mut dns = Vec::new();
        push_tlv(&mut dns, T_GN_DNS, b"issuer.example");
        for (payload, accepted) in cases {
            let mut encoded = Vec::new();
            push_tlv(&mut encoded, 0xa5, &payload);
            for names in [
                encoded.clone(),
                [encoded.as_slice(), dns.as_slice()].concat(),
                [dns.as_slice(), encoded.as_slice()].concat(),
            ] {
                for key in [false, true] {
                    for critical in [false, true] {
                        let mut body = Vec::new();
                        if key {
                            push_tlv(&mut body, 0x80, &[1, 2]);
                        }
                        push_tlv(&mut body, T_CTX1, &names);
                        push_tlv(&mut body, 0x82, &[1]);
                        let mut value = Vec::new();
                        push_tlv(&mut value, T_SEQUENCE, &body);
                        let mut extension = Vec::new();
                        push_ext(&mut extension, OID_EXT_AKI, critical, &value);
                        let mut extensions = Vec::new();
                        push_tlv(&mut extensions, T_SEQUENCE, &extension);
                        let result = parse_extensions(&extensions);
                        if accepted {
                            assert_eq!(
                                result.unwrap().aki,
                                if key { Some(&[1, 2][..]) } else { None }
                            );
                        } else {
                            assert_eq!(
                                result.err().unwrap().kind(),
                                ErrorKind::BadCertificate,
                                "payload={payload:?}, key={key}, critical={critical}"
                            );
                        }
                    }
                }
            }
        }
    }

    /// REQ-X509-049: AKI otherName fields use the shared ASN.1 structure,
    /// including entries after another issuer name and opaque unknown values.
    #[test]
    fn authority_key_identifier_other_names_require_complete_fields() {
        let other = |oid: &[u8], value: &[u8]| {
            let mut body = Vec::new();
            push_tlv(&mut body, T_OID, oid);
            push_tlv(&mut body, T_CTX0, value);
            body
        };
        let valid = other(&[0x2a, 3], &[T_NULL, 0]);
        let mut trailing = valid.clone();
        trailing.extend_from_slice(&[T_NULL, 0]);
        let mut unwrapped = Vec::new();
        push_tlv(&mut unwrapped, T_OID, &[0x2a, 3]);
        unwrapped.extend_from_slice(&[T_NULL, 0]);
        let mut missing = Vec::new();
        push_tlv(&mut missing, T_OID, &[0x2a, 3]);
        let mut dns = Vec::new();
        push_tlv(&mut dns, T_GN_DNS, b"issuer.example");
        for (payload, accepted) in [
            (valid, true),
            (other(&[0], &[T_UTF8, 1, b'A']), true),
            (other(&[0x2a, 0x81, 0], &[0x9f, 31, 0]), true),
            (other(&[0x2a, 3], &[T_SEQUENCE, 0]), true),
            (Vec::new(), false),
            (other(&[], &[T_NULL, 0]), false),
            (other(&[0x80, 0], &[T_NULL, 0]), false),
            (other(&[0x2a, 0x81], &[T_NULL, 0]), false),
            (missing, false),
            (unwrapped, false),
            (other(&[0x2a, 3], &[]), false),
            (other(&[0x2a, 3], &[T_NULL, 0, T_NULL, 0]), false),
            (other(&[0x2a, 3], &[T_UTF8, 2, b'A']), false),
            (other(&[0x2a, 3], &[0x9f, 0x80, 31, 0]), false),
            (trailing, false),
        ] {
            let mut encoded = Vec::new();
            push_tlv(&mut encoded, T_CTX0, &payload);
            for names in [
                encoded.clone(),
                [encoded.as_slice(), dns.as_slice()].concat(),
                [dns.as_slice(), encoded.as_slice()].concat(),
            ] {
                for key in [false, true] {
                    for critical in [false, true] {
                        let mut body = Vec::new();
                        if key {
                            push_tlv(&mut body, 0x80, &[1, 2]);
                        }
                        push_tlv(&mut body, T_CTX1, &names);
                        push_tlv(&mut body, 0x82, &[1]);
                        let mut value = Vec::new();
                        push_tlv(&mut value, T_SEQUENCE, &body);
                        let mut extension = Vec::new();
                        push_ext(&mut extension, OID_EXT_AKI, critical, &value);
                        let mut extensions = Vec::new();
                        push_tlv(&mut extensions, T_SEQUENCE, &extension);
                        let result = parse_extensions(&extensions);
                        if accepted {
                            assert_eq!(
                                result.unwrap().aki,
                                if key { Some(&[1, 2][..]) } else { None }
                            );
                        } else {
                            assert_eq!(
                                result.err().unwrap().kind(),
                                ErrorKind::BadCertificate,
                                "payload={payload:?}, key={key}, critical={critical}"
                            );
                        }
                    }
                }
            }
        }
    }

    /// REQ-X509-048: AKI directoryName wrappers and RDN attributes are complete
    /// and ordered, even in entries following another valid issuer name.
    #[test]
    fn authority_key_identifier_directory_names_require_complete_ordered_names() {
        let attribute = |oid: &[u8], value: &[u8]| {
            let mut body = Vec::new();
            push_tlv(&mut body, T_OID, oid);
            body.extend_from_slice(value);
            let mut encoded = Vec::new();
            push_tlv(&mut encoded, T_SEQUENCE, &body);
            encoded
        };
        let name = |attributes: &[u8]| {
            let mut rdn = Vec::new();
            push_tlv(&mut rdn, T_SET, attributes);
            let mut encoded = Vec::new();
            push_tlv(&mut encoded, T_SEQUENCE, &rdn);
            encoded
        };
        let a = attribute(&[0x2a, 3], &[T_UTF8, 1, b'A']);
        let b = attribute(&[0x2a, 4], &[T_UTF8, 1, b'B']);
        let mut trailing = encode_name("Issuer");
        trailing.extend_from_slice(&[T_NULL, 0]);
        let mut cases = alloc::vec![
            (encode_name("Issuer"), true),
            (encode_name("É issuer"), true),
            (alloc::vec![T_SEQUENCE, 0], true), // Empty RDNSequence is a Name.
            (name(&a), true),
            (name(&[a.clone(), b.clone()].concat()), true),
            (name(&[b, a].concat()), false),
            (name(&attribute(&[0x2a, 3], &[0x9f, 31, 0])), true),
            (Vec::new(), false),
            (alloc::vec![T_SET, 0], false),
            (alloc::vec![T_SEQUENCE, 1, T_SET], false),
            (trailing, false),
            (name(&[]), false),
            (name(&[T_SEQUENCE, 0]), false),
            (name(&attribute(&[], &[T_NULL, 0])), false),
            (name(&attribute(&[0x2a, 0x81], &[T_NULL, 0])), false),
            (name(&attribute(&[0x80, 0], &[T_NULL, 0])), false),
            (name(&attribute(&[0x2a, 3], &[])), false),
            (name(&attribute(&[0x2a, 3], &[T_NULL, 0, T_NULL, 0])), false),
        ];
        let mut two_names = encode_name("Issuer");
        two_names.extend_from_slice(&encode_name("Other"));
        cases.push((two_names, false));
        let mut dns = Vec::new();
        push_tlv(&mut dns, T_GN_DNS, b"issuer.example");
        for (directory, accepted) in cases {
            let mut encoded = Vec::new();
            push_tlv(&mut encoded, 0xa4, &directory);
            for names in [
                encoded.clone(),
                [encoded.as_slice(), dns.as_slice()].concat(),
                [dns.as_slice(), encoded.as_slice()].concat(),
            ] {
                for key in [false, true] {
                    for critical in [false, true] {
                        let mut body = Vec::new();
                        if key {
                            push_tlv(&mut body, 0x80, &[1, 2]);
                        }
                        push_tlv(&mut body, T_CTX1, &names);
                        push_tlv(&mut body, 0x82, &[1]);
                        let mut value = Vec::new();
                        push_tlv(&mut value, T_SEQUENCE, &body);
                        let mut extension = Vec::new();
                        push_ext(&mut extension, OID_EXT_AKI, critical, &value);
                        let mut extensions = Vec::new();
                        push_tlv(&mut extensions, T_SEQUENCE, &extension);
                        let result = parse_extensions(&extensions);
                        if accepted {
                            assert_eq!(
                                result.unwrap().aki,
                                if key { Some(&[1, 2][..]) } else { None }
                            );
                        } else {
                            assert_eq!(
                                result.err().unwrap().kind(),
                                ErrorKind::BadCertificate,
                                "directory={directory:?}, key={key}, critical={critical}"
                            );
                        }
                    }
                }
            }
        }
    }

    /// Synthetic fixed-width string fixtures test X.690's two/four-octet forms.
    #[test]
    fn edi_party_name_fixed_width_strings_require_complete_code_units() {
        let field = |wrapper, string_tag, value: &[u8]| {
            let mut string = Vec::new();
            push_tlv(&mut string, string_tag, value);
            let mut out = Vec::new();
            push_tlv(&mut out, wrapper, &string);
            out
        };
        let mut control = Vec::new();
        push_tlv(&mut control, T_GN_DNS, b"control.example");
        for (tag, unit) in [(0x1e, &[0, b'P'][..]), (0x1c, &[0, 0, 0, b'P'][..])] {
            let complete = unit.repeat(4);
            for len in 0..=complete.len() {
                let value = &complete[..len];
                let accepted = len > 0 && len % unit.len() == 0;
                for wrapper in [T_CTX0, T_CTX1] {
                    let mut fields = if wrapper == T_CTX0 {
                        field(T_CTX0, tag, value)
                    } else {
                        field(T_CTX0, T_UTF8, b"assigner")
                    };
                    fields.extend_from_slice(&if wrapper == T_CTX1 {
                        field(T_CTX1, tag, value)
                    } else {
                        field(T_CTX1, T_UTF8, b"party")
                    });
                    let mut name = Vec::new();
                    push_tlv(&mut name, 0xa5, &fields);
                    for critical in [false, true] {
                        for first in [false, true] {
                            let mut names = if first { name.clone() } else { control.clone() };
                            names.extend_from_slice(if first { &control } else { &name });
                            let mut encoded_names = Vec::new();
                            push_tlv(&mut encoded_names, T_SEQUENCE, &names);
                            let mut extension = Vec::new();
                            push_ext(&mut extension, OID_EXT_SAN, critical, &encoded_names);
                            let mut extensions = Vec::new();
                            push_tlv(&mut extensions, T_SEQUENCE, &extension);
                            let result = parse_extensions(&extensions);
                            if accepted {
                                assert_eq!(result.unwrap().san, Some(names.as_slice()));
                            } else {
                                assert_eq!(result.unwrap_err().kind(), ErrorKind::BadCertificate);
                            }
                        }
                    }
                }
            }
        }
        // Other string encodings do not inherit the fixed-width checks.
        for tag in [T_T61, T_PRINTABLE, T_UTF8] {
            let mut string = Vec::new();
            push_tlv(&mut string, tag, b"abc");
            assert!(check_directory_string(&string).is_ok());
        }
    }

    /// X.680's PrintableString table supplies the independent accepted alphabet.
    #[test]
    fn edi_party_name_printablestrings_require_the_asn1_repertoire() {
        let alphabet =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 '()+,-./:=?";
        let field = |wrapper, value: &[u8]| {
            let mut string = Vec::new();
            push_tlv(&mut string, T_PRINTABLE, value);
            let mut out = Vec::new();
            push_tlv(&mut out, wrapper, &string);
            out
        };
        let mut control = Vec::new();
        push_tlv(&mut control, T_GN_DNS, b"control.example");
        for byte in 0..=u8::MAX {
            let accepted = alphabet.contains(&byte);
            for value in [
                alloc::vec![byte],
                alloc::vec![byte, b'A'],
                alloc::vec![b'A', byte],
            ] {
                for wrapper in [T_CTX0, T_CTX1] {
                    let mut fields = if wrapper == T_CTX0 {
                        field(T_CTX0, &value)
                    } else {
                        field(T_CTX0, b"assigner")
                    };
                    fields.extend_from_slice(&field(
                        T_CTX1,
                        if wrapper == T_CTX1 { &value } else { b"party" },
                    ));
                    let mut name = Vec::new();
                    push_tlv(&mut name, 0xa5, &fields);
                    for critical in [false, true] {
                        for first in [false, true] {
                            let mut names = if first { name.clone() } else { control.clone() };
                            names.extend_from_slice(if first { &control } else { &name });
                            let mut encoded_names = Vec::new();
                            push_tlv(&mut encoded_names, T_SEQUENCE, &names);
                            let mut extension = Vec::new();
                            push_ext(&mut extension, OID_EXT_SAN, critical, &encoded_names);
                            let mut extensions = Vec::new();
                            push_tlv(&mut extensions, T_SEQUENCE, &extension);
                            let result = parse_extensions(&extensions);
                            if accepted {
                                assert_eq!(result.unwrap().san, Some(names.as_slice()));
                            } else {
                                assert_eq!(result.unwrap_err().kind(), ErrorKind::BadCertificate);
                            }
                        }
                    }
                }
            }
        }
        // These ASCII characters are valid UTF8String, outside PrintableString's set.
        let mut string = Vec::new();
        push_tlv(&mut string, T_UTF8, b"agent@example_test");
        assert!(check_directory_string(&string).is_ok());
    }

    /// Synthetic UTF-8 fixtures cover invalid sequences independently of DER framing.
    #[test]
    fn edi_party_name_utf8strings_require_well_formed_utf8() {
        let cases: &[(&[u8], bool)] = &[
            (b"party", true),
            (&[0], true),
            (&[0x7f], true),
            (&[0xc2, 0x80], true),
            (&[0xdf, 0xbf], true),
            (&[0xe0, 0xa0, 0x80], true),
            (&[0xed, 0x9f, 0xbf], true),
            (&[0xee, 0x80, 0x80], true),
            (&[0xef, 0xbf, 0xbf], true),
            (&[0xf0, 0x90, 0x80, 0x80], true),
            (&[0xf4, 0x8f, 0xbf, 0xbf], true),
            (&[0x80], false),
            (&[0xbf], false),
            (&[0xc0, 0x80], false),
            (&[0xc1, 0xbf], false),
            (&[0xc2], false),
            (&[0xc2, b'A'], false),
            (&[0xe0, 0x9f, 0xbf], false),
            (&[0xe1, 0x80], false),
            (&[0xed, 0xa0, 0x80], false),
            (&[0xed, 0xbf, 0xbf], false),
            (&[0xf0, 0x8f, 0xbf, 0xbf], false),
            (&[0xf1, 0x80, 0x80], false),
            (&[0xf4, 0x90, 0x80, 0x80], false),
            (&[0xf5, 0x80, 0x80, 0x80], false),
            (&[0xf8, 0x88, 0x80, 0x80, 0x80], false),
            (&[0xff], false),
            (&[b'p', 0x80], false),
        ];
        let field = |wrapper, value: &[u8]| {
            let mut string = Vec::new();
            push_tlv(&mut string, T_UTF8, value);
            let mut out = Vec::new();
            push_tlv(&mut out, wrapper, &string);
            out
        };
        let mut control = Vec::new();
        push_tlv(&mut control, T_GN_DNS, b"control.example");
        for &(value, accepted) in cases {
            for wrapper in [T_CTX0, T_CTX1] {
                let mut fields = if wrapper == T_CTX0 {
                    field(T_CTX0, value)
                } else {
                    field(T_CTX0, b"assigner")
                };
                fields.extend_from_slice(&field(
                    T_CTX1,
                    if wrapper == T_CTX1 { value } else { b"party" },
                ));
                let mut name = Vec::new();
                push_tlv(&mut name, 0xa5, &fields);
                for critical in [false, true] {
                    for first in [false, true] {
                        let mut names = if first { name.clone() } else { control.clone() };
                        names.extend_from_slice(if first { &control } else { &name });
                        let mut encoded_names = Vec::new();
                        push_tlv(&mut encoded_names, T_SEQUENCE, &names);
                        let mut extension = Vec::new();
                        push_ext(&mut extension, OID_EXT_SAN, critical, &encoded_names);
                        let mut extensions = Vec::new();
                        push_tlv(&mut extensions, T_SEQUENCE, &extension);
                        let result = parse_extensions(&extensions);
                        if accepted {
                            assert_eq!(result.unwrap().san, Some(names.as_slice()));
                        } else {
                            assert_eq!(result.unwrap_err().kind(), ErrorKind::BadCertificate);
                        }
                    }
                }
            }
        }
        // TeletexString uses a different encoding and is not subject to UTF-8 checks.
        let mut string = Vec::new();
        push_tlv(&mut string, T_T61, &[0xe9]);
        assert!(check_directory_string(&string).is_ok());
    }

    /// Synthetic fixtures cover EDI party fields and DirectoryString choices.
    #[test]
    fn edi_party_name_sans_require_ordered_complete_string_fields() {
        let field = |tag: u8, string_tag: u8, value: &[u8]| {
            let mut string = Vec::new();
            push_tlv(&mut string, string_tag, value);
            let mut out = Vec::new();
            push_tlv(&mut out, tag, &string);
            out
        };
        let party = field(T_CTX1, T_UTF8, b"party");
        let assigner = field(T_CTX0, T_UTF8, b"assigner");
        let mut cases = Vec::new();
        for (tag, value) in [
            (T_T61, &b"party"[..]),
            (T_PRINTABLE, &b"Party 1"[..]),
            (0x1c, &[0, 0, 0, b'P'][..]),
            (T_UTF8, &[0xc3, 0xa9][..]),
            (0x1e, &[0, b'P'][..]),
        ] {
            let valid_party = field(T_CTX1, tag, value);
            cases.push((valid_party.clone(), true));
            let mut assigned = field(T_CTX0, tag, value);
            assigned.extend_from_slice(&valid_party);
            cases.push((assigned, true));
            for wrapper in [T_CTX0, T_CTX1] {
                let empty = field(wrapper, tag, &[]);
                let mut invalid = if wrapper == T_CTX0 {
                    empty.clone()
                } else {
                    assigner.clone()
                };
                invalid.extend_from_slice(if wrapper == T_CTX0 { &party } else { &empty });
                cases.push((invalid, false));
            }
        }
        // Invalid string choices and malformed explicit wrappers at either field.
        for value in [
            &[][..],
            &[T_IA5, 1, b'p'][..],
            &[T_OCTET_STRING, 1, b'p'][..],
            &[T_NULL, 0][..],
            &[T_UTF8][..],
            &[T_UTF8, 2, b'p'][..],
            &[T_UTF8, 0x80, b'p', 0, 0][..],
            &[T_UTF8, 1, b'p', T_UTF8, 1, b'q'][..],
            &[T_UTF8, 1, b'p', 0xff][..],
            &[T_UTF8 | 0x20, 1, b'p'][..],
        ] {
            for wrapper in [T_CTX0, T_CTX1] {
                let mut invalid_field = Vec::new();
                push_tlv(&mut invalid_field, wrapper, value);
                let mut invalid = if wrapper == T_CTX0 {
                    invalid_field.clone()
                } else {
                    assigner.clone()
                };
                invalid.extend_from_slice(if wrapper == T_CTX0 {
                    &party
                } else {
                    &invalid_field
                });
                cases.push((invalid, false));
            }
        }
        for fields in [
            Vec::new(),
            assigner.clone(),
            [party.clone(), assigner.clone()].concat(),
            [assigner.clone(), assigner.clone(), party.clone()].concat(),
            [party.clone(), party.clone()].concat(),
            [assigner.clone(), party.clone(), party.clone()].concat(),
            [party.clone(), alloc::vec![T_NULL, 0]].concat(),
            alloc::vec![0x81, 1, b'p'],
        ] {
            cases.push((fields, false));
        }
        let mut control = Vec::new();
        push_tlv(&mut control, T_GN_DNS, b"control.example");
        for (value, accepted) in cases {
            for critical in [false, true] {
                for first in [false, true] {
                    let mut name = Vec::new();
                    push_tlv(&mut name, 0xa5, &value);
                    let mut names = if first { name.clone() } else { control.clone() };
                    names.extend_from_slice(if first { &control } else { &name });
                    let mut encoded_names = Vec::new();
                    push_tlv(&mut encoded_names, T_SEQUENCE, &names);
                    let mut extension = Vec::new();
                    push_ext(&mut extension, OID_EXT_SAN, critical, &encoded_names);
                    let mut extensions = Vec::new();
                    push_tlv(&mut extensions, T_SEQUENCE, &extension);
                    let result = parse_extensions(&extensions);
                    if accepted {
                        assert_eq!(result.unwrap().san, Some(names.as_slice()));
                    } else {
                        assert_eq!(result.unwrap_err().kind(), ErrorKind::BadCertificate);
                    }
                }
            }
        }
    }

    /// Synthetic fixtures cover AnotherName framing from RFC 5280's ASN.1 module.
    #[test]
    fn other_name_sans_require_an_oid_and_one_explicit_value() {
        let encode = |oid: &[u8], value: &[u8]| {
            let mut out = Vec::new();
            push_tlv(&mut out, T_OID, oid);
            push_tlv(&mut out, T_CTX0, value);
            out
        };
        let valid = encode(&[0x2a, 3], &[T_NULL, 0]);
        let mut cases = alloc::vec![(valid.clone(), true)];
        let mut large_tag = alloc::vec![0xdf];
        large_tag.extend_from_slice(&[0x81; 32]);
        large_tag.extend_from_slice(&[0, 0]);
        let mut long_value = Vec::new();
        push_tlv(&mut long_value, T_OCTET_STRING, &[0x55; 128]);
        for value in [
            &[T_UTF8, 2, 0xc3, 0xa9][..],
            &[T_SEQUENCE, 0][..],
            &[0x9f, 31, 0][..],
            &[0xbf, 0x81, 0, 0][..],
            large_tag.as_slice(),
            long_value.as_slice(),
        ] {
            cases.push((encode(&[0x2a, 3], value), true));
        }
        for value in [
            &[][..],
            &[T_NULL][..],
            &[T_OCTET_STRING, 1][..],
            &[T_NULL, 0, T_NULL, 0][..],
            &[T_NULL, 0, 0xff][..],
            &[0, 0][..],
            &[0x20, 0][..],
            &[0x9f][..],
            &[0x9f, 0x81][..],
            &[0x9f, 0x80, 31, 0][..],
            &[0x9f, 30, 0][..],
            &[T_SEQUENCE, 0x80, 0, 0][..],
            &[T_NULL, 0x81, 0][..],
        ] {
            cases.push((encode(&[0x2a, 3], value), false));
        }
        for oid in [&[][..], &[0x81][..], &[0x2a, 0x80, 0][..]] {
            cases.push((encode(oid, &[T_NULL, 0]), false));
        }
        let mut trailing = valid.clone();
        trailing.extend_from_slice(&[T_NULL, 0]);
        let mut duplicate = valid.clone();
        duplicate.extend_from_slice(&valid);
        cases.extend([
            (Vec::new(), false),
            (alloc::vec![T_OID, 2, 0x2a, 3], false),
            (alloc::vec![T_CTX0, 2, T_NULL, 0], false),
            (alloc::vec![T_OID, 2, 0x2a, 3, 0x80, 2, T_NULL, 0], false),
            (trailing, false),
            (duplicate, false),
        ]);
        let mut control = Vec::new();
        push_tlv(&mut control, T_GN_DNS, b"control.example");
        for (value, accepted) in cases {
            for critical in [false, true] {
                for first in [false, true] {
                    let mut name = Vec::new();
                    push_tlv(&mut name, T_CTX0, &value);
                    let mut names = if first { name.clone() } else { control.clone() };
                    names.extend_from_slice(if first { &control } else { &name });
                    let mut encoded_names = Vec::new();
                    push_tlv(&mut encoded_names, T_SEQUENCE, &names);
                    let mut extension = Vec::new();
                    push_ext(&mut extension, OID_EXT_SAN, critical, &encoded_names);
                    let mut extensions = Vec::new();
                    push_tlv(&mut extensions, T_SEQUENCE, &extension);
                    let result = parse_extensions(&extensions);
                    if accepted {
                        assert_eq!(result.unwrap().san, Some(names.as_slice()));
                    } else {
                        assert_eq!(result.unwrap_err().kind(), ErrorKind::BadCertificate);
                    }
                }
            }
        }
    }

    /// Synthetic RDN fixtures distinguish full-TLV ordering from OID/value ordering.
    #[test]
    fn directory_name_rdn_attributes_require_der_order() {
        let attribute = |oid: &[u8], text: &[u8]| {
            let mut body = Vec::new();
            push_tlv(&mut body, T_OID, oid);
            push_tlv(&mut body, T_UTF8, text);
            let mut out = Vec::new();
            push_tlv(&mut out, T_SEQUENCE, &body);
            out
        };
        let short = attribute(&[0x2a, 9], b"A");
        let medium = attribute(&[0x2a, 1], b"BB");
        let long = attribute(&[0x2a, 2], b"CCC");
        let mut sets = Vec::new();
        for (order, accepted) in [
            ([0, 1, 2], true),
            ([0, 2, 1], false),
            ([1, 0, 2], false),
            ([1, 2, 0], false),
            ([2, 0, 1], false),
            ([2, 1, 0], false),
        ] {
            let attributes = [&short, &medium, &long];
            let body = order
                .into_iter()
                .flat_map(|i| attributes[i].iter().copied())
                .collect::<Vec<_>>();
            sets.push((alloc::vec![body], accepted));
        }
        let a = attribute(&[0x2a, 1], b"A");
        let b = attribute(&[0x2a, 1], b"B");
        let other_oid = attribute(&[0x2a, 2], b"A");
        let long_form = attribute(&[0x2a, 1], &[b'A'; 128]);
        sets.extend([
            (alloc::vec![[a.clone(), b.clone()].concat()], true),
            (alloc::vec![[b.clone(), a.clone()].concat()], false),
            (alloc::vec![[a.clone(), other_oid.clone()].concat()], true),
            (alloc::vec![[other_oid, a.clone()].concat()], false),
            (alloc::vec![[a.clone(), a.clone()].concat()], true),
            (alloc::vec![[a.clone(), long_form.clone()].concat()], true),
            (alloc::vec![[long_form, a.clone()].concat()], false),
            // RDNSequence preserves its own order; sorting restarts for each set.
            (alloc::vec![long.clone(), short.clone()], true),
            (
                alloc::vec![[a.clone(), b.clone()].concat(), [medium, short].concat()],
                false,
            ),
        ]);
        let mut control = Vec::new();
        push_tlv(&mut control, T_GN_DNS, b"control.example");
        for (sets, accepted) in sets {
            let mut rdns = Vec::new();
            for set in sets {
                push_tlv(&mut rdns, T_SET, &set);
            }
            let mut value = Vec::new();
            push_tlv(&mut value, T_SEQUENCE, &rdns);
            let mut directory = Vec::new();
            push_tlv(&mut directory, 0xa4, &value);
            for critical in [false, true] {
                for first in [false, true] {
                    let mut names = if first {
                        directory.clone()
                    } else {
                        control.clone()
                    };
                    names.extend_from_slice(if first { &control } else { &directory });
                    let mut encoded_names = Vec::new();
                    push_tlv(&mut encoded_names, T_SEQUENCE, &names);
                    let mut extension = Vec::new();
                    push_ext(&mut extension, OID_EXT_SAN, critical, &encoded_names);
                    let mut extensions = Vec::new();
                    push_tlv(&mut extensions, T_SEQUENCE, &extension);
                    let result = parse_extensions(&extensions);
                    if accepted {
                        assert_eq!(result.unwrap().san, Some(names.as_slice()));
                    } else {
                        assert_eq!(result.unwrap_err().kind(), ErrorKind::BadCertificate);
                    }
                }
            }
        }
    }

    /// Synthetic Name fixtures cover RDN and AttributeTypeAndValue framing.
    #[test]
    fn directory_name_sans_require_complete_rdn_and_attribute_fields() {
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
            push_tlv(&mut rdn, T_SET, attributes);
            let mut out = Vec::new();
            push_tlv(&mut out, T_SEQUENCE, &rdn);
            out
        };
        let first = attribute(&[0x2a, 3], &[T_NULL, 0]);
        let second = attribute(&[0x2a, 4], &[0x9f, 31, 1, 0x55]);
        let mut sorted = [first.clone(), second.clone()];
        sorted.sort();
        let mut rdns = Vec::new();
        for attr in &sorted {
            push_tlv(&mut rdns, T_SET, attr);
        }
        let mut multiple_rdns = Vec::new();
        push_tlv(&mut multiple_rdns, T_SEQUENCE, &rdns);
        let mut cases = alloc::vec![
            (encode_name("Directory SAN"), true),
            (encode_name("É directory"), true),
            (name(&first), true),
            (name(&second), true),
            (name(&sorted.concat()), true),
            (multiple_rdns, true),
            (alloc::vec![T_SEQUENCE, 0], false),
            (name(&[]), false),
            (name(&[T_SEQUENCE, 0]), false),
            (name(&[T_OCTET_STRING, 0]), false),
            (name(&[T_SEQUENCE, 2, T_NULL, 0]), false),
            (name(&[T_SEQUENCE, 4, T_OID, 2, 0x2a, 3]), false),
            (alloc::vec![T_SEQUENCE, 2, T_SEQUENCE, 0], false),
        ];
        for oid in [&[][..], &[0x81][..], &[0x2a, 0x80, 0][..]] {
            cases.push((name(&attribute(oid, &[T_NULL, 0])), false));
        }
        for value in [
            &[][..],
            &[T_NULL][..],
            &[T_OCTET_STRING, 1][..],
            &[T_NULL, 0, T_NULL, 0][..],
            &[T_NULL, 0, 0xff][..],
            &[0, 0][..],
            &[0x9f, 0x81][..],
        ] {
            cases.push((name(&attribute(&[0x2a, 3], value)), false));
        }
        let mut truncated = first.clone();
        truncated.pop();
        cases.push((name(&truncated), false));
        let mut late_bad_attribute = first.clone();
        late_bad_attribute.extend_from_slice(&attribute(&[0x2a, 4], &[T_NULL]));
        cases.push((name(&late_bad_attribute), false));
        let mut late_bad_rdn = rdns;
        push_tlv(&mut late_bad_rdn, T_SET, &[]);
        let mut late_bad_name = Vec::new();
        push_tlv(&mut late_bad_name, T_SEQUENCE, &late_bad_rdn);
        cases.push((late_bad_name, false));
        let mut control = Vec::new();
        push_tlv(&mut control, T_GN_DNS, b"control.example");
        for (value, accepted) in cases {
            for critical in [false, true] {
                for first in [false, true] {
                    let mut directory = Vec::new();
                    push_tlv(&mut directory, 0xa4, &value);
                    let mut names = if first {
                        directory.clone()
                    } else {
                        control.clone()
                    };
                    names.extend_from_slice(if first { &control } else { &directory });
                    let mut encoded_names = Vec::new();
                    push_tlv(&mut encoded_names, T_SEQUENCE, &names);
                    let mut extension = Vec::new();
                    push_ext(&mut extension, OID_EXT_SAN, critical, &encoded_names);
                    let mut extensions = Vec::new();
                    push_tlv(&mut extensions, T_SEQUENCE, &extension);
                    let result = parse_extensions(&extensions);
                    if accepted {
                        assert_eq!(result.unwrap().san, Some(names.as_slice()));
                    } else {
                        assert_eq!(result.unwrap_err().kind(), ErrorKind::BadCertificate);
                    }
                }
            }
        }
    }

    /// Synthetic directoryName fixtures test its explicit Name wrapper framing.
    #[test]
    fn directory_name_sans_require_one_complete_name_sequence() {
        let named = encode_name("Directory SAN");
        let unicode = encode_name("É directory");
        let mut trailing = named.clone();
        trailing.extend_from_slice(&[T_NULL, 0]);
        let mut duplicate = named.clone();
        duplicate.extend_from_slice(&named);
        let mut truncated = named.clone();
        truncated.pop();
        let cases: &[(&[u8], bool)] = &[
            (&named, true),
            (&unicode, true),
            (&[T_SEQUENCE, 0], false),
            (&[], false),
            (&[T_SET, 0], false),
            (&[T_OCTET_STRING, 0], false),
            (&[T_SEQUENCE], false),
            (&[T_SEQUENCE, 1], false),
            (&[T_SEQUENCE, 0x80, 0, 0], false),
            (&truncated, false),
            (&trailing, false),
            (&duplicate, false),
        ];
        let mut control = Vec::new();
        push_tlv(&mut control, T_GN_DNS, b"control.example");
        for &(value, accepted) in cases {
            for critical in [false, true] {
                for first in [false, true] {
                    let mut name = Vec::new();
                    push_tlv(&mut name, 0xa4, value);
                    let mut names = if first { name.clone() } else { control.clone() };
                    names.extend_from_slice(if first { &control } else { &name });
                    let mut encoded_names = Vec::new();
                    push_tlv(&mut encoded_names, T_SEQUENCE, &names);
                    let mut extension = Vec::new();
                    push_ext(&mut extension, OID_EXT_SAN, critical, &encoded_names);
                    let mut extensions = Vec::new();
                    push_tlv(&mut extensions, T_SEQUENCE, &extension);
                    let result = parse_extensions(&extensions);
                    if accepted {
                        assert_eq!(result.unwrap().san, Some(names.as_slice()));
                    } else {
                        assert_eq!(result.unwrap_err().kind(), ErrorKind::BadCertificate);
                    }
                }
            }
        }
    }

    /// Synthetic OID fixtures exercise X.690 section 8.19's base-128 encoding rules.
    #[test]
    fn registered_id_sans_require_complete_minimal_oids() {
        let mut large_arc = alloc::vec![0x81; 32];
        large_arc.push(0);
        let cases: &[(&[u8], bool)] = &[
            (&[0], true),
            (&[0x2a, 3], true),
            (&[0x81, 0], true),
            (&[0x2a, 0x81, 0], true),
            (&[0x2a, 0x86, 0x47], true),
            (&large_arc, true),
            (&[], false),
            (&[0x81], false),
            (&[0x2a, 0x81], false),
            (&[0x80, 0], false),
            (&[0x2a, 0x80, 0], false),
            (&[0x2a, 0x81, 0, 0x80, 1], false),
        ];
        let mut control = Vec::new();
        push_tlv(&mut control, T_GN_DNS, b"control.example");
        for &(value, accepted) in cases {
            for critical in [false, true] {
                for first in [false, true] {
                    let mut name = Vec::new();
                    push_tlv(&mut name, 0x88, value);
                    let mut names = if first { name.clone() } else { control.clone() };
                    names.extend_from_slice(if first { &control } else { &name });
                    let mut encoded_names = Vec::new();
                    push_tlv(&mut encoded_names, T_SEQUENCE, &names);
                    let mut extension = Vec::new();
                    push_ext(&mut extension, OID_EXT_SAN, critical, &encoded_names);
                    let mut extensions = Vec::new();
                    push_tlv(&mut extensions, T_SEQUENCE, &extension);
                    let result = parse_extensions(&extensions);
                    if accepted {
                        assert_eq!(result.unwrap().san, Some(names.as_slice()));
                    } else {
                        assert_eq!(result.unwrap_err().kind(), ErrorKind::BadCertificate);
                    }
                }
            }
        }
    }

    /// Synthetic IA5String fixtures cover value checks independently of tag validation.
    #[test]
    fn subject_alt_name_ia5strings_require_nonempty_ascii() {
        let extension = |names: &[u8], critical: bool| {
            let mut value = Vec::new();
            push_tlv(&mut value, T_SEQUENCE, names);
            let mut entry = Vec::new();
            push_ext(&mut entry, OID_EXT_SAN, critical, &value);
            let mut out = Vec::new();
            push_tlv(&mut out, T_SEQUENCE, &entry);
            out
        };
        let mut control = Vec::new();
        push_tlv(&mut control, T_GN_DNS, b"control.example");
        for (tag, valid) in [
            (0x81, &b"agent@example.test"[..]),
            (T_GN_DNS, &b"example.test"[..]),
            (0x86, &b"https://example.test/path"[..]),
        ] {
            let mut high_byte_after_ascii = valid.to_vec();
            high_byte_after_ascii.push(0x80);
            for (value, accepted) in [
                (valid, true),
                (&[][..], false),
                (&[0x80][..], false),
                (&[0xff][..], false),
                (&[0xc3, 0xa9][..], false),
                (high_byte_after_ascii.as_slice(), false),
            ] {
                for critical in [false, true] {
                    for first in [false, true] {
                        let mut name = Vec::new();
                        push_tlv(&mut name, tag, value);
                        let mut names = if first { name.clone() } else { control.clone() };
                        names.extend_from_slice(if first { &control } else { &name });
                        let encoded = extension(&names, critical);
                        let result = parse_extensions(&encoded);
                        if accepted {
                            assert_eq!(result.unwrap().san, Some(names.as_slice()));
                        } else {
                            assert_eq!(result.unwrap_err().kind(), ErrorKind::BadCertificate);
                        }
                    }
                }
            }
        }
        // directoryName carries a Name, including UTF8String values, rather than IA5String.
        let mut directory = Vec::new();
        push_tlv(&mut directory, 0xa4, &encode_name("É directory"));
        for critical in [false, true] {
            let encoded = extension(&directory, critical);
            assert_eq!(
                parse_extensions(&encoded).unwrap().san,
                Some(directory.as_slice())
            );
        }
    }

    /// Tag-focused fixtures cover GeneralName's choices from RFC 5280 section 4.2.1.6.
    #[test]
    fn subject_alt_names_require_defined_choice_tags() {
        let choices = [
            (0xa0, alloc::vec![6, 2, 0x2a, 3, 0xa0, 2, 5, 0]),
            (0x81, b"agent@example.test".to_vec()),
            (0x82, b"example.test".to_vec()),
            (0xa3, alloc::vec![T_SEQUENCE, 0]),
            (0xa4, encode_name("Directory SAN")),
            (
                0xa5,
                alloc::vec![0xa1, 7, T_UTF8, 5, b'p', b'a', b'r', b't', b'y'],
            ),
            (0x86, b"https://example.test/".to_vec()),
            (0x87, alloc::vec![192, 0, 2, 1]),
            (0x88, alloc::vec![0x2a, 3]),
        ];
        let mut dns = Vec::new();
        push_tlv(&mut dns, T_GN_DNS, b"control.example");
        for tag in 0..=u8::MAX {
            let choice = choices.iter().find(|(valid_tag, _)| *valid_tag == tag);
            let value = choice.map_or(&b"unused"[..], |(_, value)| value.as_slice());
            for critical in [false, true] {
                for first in [false, true] {
                    let mut name = Vec::new();
                    push_tlv(&mut name, tag, value);
                    let mut names = if first { name.clone() } else { dns.clone() };
                    names.extend_from_slice(if first { &dns } else { &name });
                    let mut encoded_names = Vec::new();
                    push_tlv(&mut encoded_names, T_SEQUENCE, &names);
                    let mut extension = Vec::new();
                    push_ext(&mut extension, OID_EXT_SAN, critical, &encoded_names);
                    let mut extensions = Vec::new();
                    push_tlv(&mut extensions, T_SEQUENCE, &extension);
                    let result = parse_extensions(&extensions);
                    if choice.is_some() {
                        assert_eq!(result.unwrap().san, Some(names.as_slice()));
                    } else {
                        assert_eq!(
                            result.unwrap_err().kind(),
                            ErrorKind::BadCertificate,
                            "tag={tag:#x}"
                        );
                    }
                }
            }
        }
    }

    /// REQ-X509-016: empty SAN lists fail for either criticality; absent SAN
    /// and nonempty DNS/IP/mixed lists remain valid.
    #[test]
    fn subject_alt_name_requires_a_nonempty_name_list() {
        let mut dns = Vec::new();
        push_tlv(&mut dns, T_GN_DNS, b"server.example");
        let mut ip = Vec::new();
        push_tlv(&mut ip, T_GN_IP, &[192, 0, 2, 1]);
        let mut mixed = dns.clone();
        mixed.extend_from_slice(&ip);
        for critical in [false, true] {
            for names in [&[][..], dns.as_slice(), ip.as_slice(), mixed.as_slice()] {
                let mut value = Vec::new();
                push_tlv(&mut value, T_SEQUENCE, names);
                let mut entry = Vec::new();
                push_ext(&mut entry, OID_EXT_SAN, critical, &value);
                let mut encoded = Vec::new();
                push_tlv(&mut encoded, T_SEQUENCE, &entry);
                let result = parse_extensions(&encoded);
                if names.is_empty() {
                    assert_eq!(result.err().unwrap().kind(), ErrorKind::BadCertificate);
                } else {
                    assert_eq!(result.unwrap().san, Some(names));
                }
            }
        }
        let mut value = Vec::new();
        push_tlv(&mut value, T_BIT_STRING, &[7, 0x80]);
        let mut entry = Vec::new();
        push_ext(&mut entry, OID_EXT_KU, true, &value);
        let mut encoded = Vec::new();
        push_tlv(&mut encoded, T_SEQUENCE, &entry);
        assert!(parse_extensions(&encoded).unwrap().san.is_none());
    }

    /// REQ-X509-064: IP lengths and every prefix or mask hole are validated
    /// during parsing in both lists, including later bases and either criticality.
    #[test]
    fn name_constraint_ip_bases_require_address_mask_encoding() {
        let wrap = |tag, body: &[u8]| {
            let mut encoded = Vec::new();
            push_tlv(&mut encoded, tag, body);
            encoded
        };
        let control = wrap(T_SEQUENCE, &wrap(T_GN_DNS, b"example.test"));
        let mut basic = Vec::new();
        push_ext(
            &mut basic,
            OID_EXT_BC,
            true,
            &[T_SEQUENCE, 3, T_BOOLEAN, 1, 0xff],
        );
        let mut cases = Vec::new();
        for length in 0..=65 {
            if length != 8 && length != 32 {
                cases.push((alloc::vec![0; length], false));
            }
        }
        for width in [4usize, 16] {
            for prefix in 0..=width * 8 {
                let mut base = alloc::vec![0xa5; width];
                for byte in 0..width {
                    let bits = prefix.saturating_sub(byte * 8).min(8);
                    base.push(if bits == 0 { 0 } else { 0xff << (8 - bits) });
                }
                cases.push((base, true));
            }
            for hole in 0..width * 8 - 1 {
                let mut base = alloc::vec![0; width];
                let mut mask = alloc::vec![0xff; width];
                mask[hole / 8] &= !(0x80 >> (hole % 8));
                base.extend_from_slice(&mask);
                cases.push((base, false));
            }
        }
        for (base, accepted) in cases {
            let subtree = wrap(T_SEQUENCE, &wrap(T_GN_IP, &base));
            for list in [
                subtree.clone(),
                [subtree.as_slice(), control.as_slice()].concat(),
                [control.as_slice(), subtree.as_slice()].concat(),
            ] {
                for field in [T_CTX0, T_CTX1] {
                    let body = wrap(field, &list);
                    let value = wrap(T_SEQUENCE, &body);
                    for critical in [false, true] {
                        let mut extensions = basic.clone();
                        push_ext(&mut extensions, OID_EXT_NC, critical, &value);
                        let encoded = wrap(T_SEQUENCE, &extensions);
                        let result = parse_extensions(&encoded);
                        if accepted {
                            assert_eq!(result.unwrap().name_constraints, Some(body.as_slice()));
                            apply_name_constraints(&body, &[]).unwrap();
                        } else {
                            assert_eq!(result.err().unwrap().kind(), ErrorKind::BadCertificate);
                        }
                    }
                }
            }
        }
    }

    /// REQ-X509-063: every high byte fails in IA5 constraint bases regardless of
    /// list position or criticality; ASCII and empty strings retain their policy.
    #[test]
    fn name_constraint_ia5strings_require_ascii() {
        let wrap = |tag, body: &[u8]| {
            let mut encoded = Vec::new();
            push_tlv(&mut encoded, tag, body);
            encoded
        };
        let control = wrap(T_SEQUENCE, &wrap(T_GN_DNS, b"example.test"));
        let mut basic = Vec::new();
        push_ext(
            &mut basic,
            OID_EXT_BC,
            true,
            &[T_SEQUENCE, 3, T_BOOLEAN, 1, 0xff],
        );
        let mut values = alloc::vec![Vec::new(), (0..=0x7f).collect::<Vec<u8>>()];
        for byte in 0x80..=0xff {
            values.push(alloc::vec![byte]);
            values.push(alloc::vec![b'a', byte]);
        }
        for tag in [0x81, T_GN_DNS, 0x86] {
            for value in &values {
                let subtree = wrap(T_SEQUENCE, &wrap(tag, value));
                for list in [
                    subtree.clone(),
                    [subtree.as_slice(), control.as_slice()].concat(),
                    [control.as_slice(), subtree.as_slice()].concat(),
                ] {
                    for field in [T_CTX0, T_CTX1] {
                        let body = wrap(field, &list);
                        let extension_value = wrap(T_SEQUENCE, &body);
                        for critical in [false, true] {
                            let mut extensions = basic.clone();
                            push_ext(&mut extensions, OID_EXT_NC, critical, &extension_value);
                            let encoded = wrap(T_SEQUENCE, &extensions);
                            let result = parse_extensions(&encoded);
                            if value.is_ascii() {
                                assert_eq!(result.unwrap().name_constraints, Some(body.as_slice()));
                                let evaluated = apply_name_constraints(&body, &[]);
                                if tag == T_GN_DNS {
                                    assert!(evaluated.is_ok());
                                } else {
                                    assert_eq!(
                                        evaluated.unwrap_err().kind(),
                                        ErrorKind::UnsupportedCertificate
                                    );
                                }
                            } else {
                                assert_eq!(result.err().unwrap().kind(), ErrorKind::BadCertificate);
                            }
                        }
                    }
                }
            }
        }
    }

    /// REQ-X509-062: EDI constraint fields and strings are checked in both lists,
    /// including later bases; valid unsupported forms retain evaluation policy.
    #[test]
    fn name_constraint_edi_names_require_ordered_valid_strings() {
        let wrap = |tag, body: &[u8]| {
            let mut encoded = Vec::new();
            push_tlv(&mut encoded, tag, body);
            encoded
        };
        let assigner = wrap(T_CTX0, &[T_UTF8, 1, b'A']);
        let party = wrap(T_CTX1, &[T_UTF8, 1, b'P']);
        let control = wrap(T_SEQUENCE, &wrap(T_GN_DNS, b"example.test"));
        let mut basic = Vec::new();
        push_ext(
            &mut basic,
            OID_EXT_BC,
            true,
            &[T_SEQUENCE, 3, T_BOOLEAN, 1, 0xff],
        );
        let mut cases = alloc::vec![
            (party.clone(), true),
            ([assigner.clone(), party.clone()].concat(), true),
            (Vec::new(), false),
            (assigner.clone(), false),
            ([party.clone(), assigner.clone()].concat(), false),
            ([assigner.clone(), assigner, party.clone()].concat(), false),
            ([party.clone(), party.clone()].concat(), false),
            ([party.clone(), alloc::vec![T_NULL, 0]].concat(), false),
            (alloc::vec![T_UTF8, 1, b'P'], false),
            (wrap(T_CTX1, &[T_UTF8, 2, b'P']), false),
            (wrap(T_CTX1, &[T_UTF8, 1, b'P', T_NULL, 0]), false),
        ];
        for (string, accepted) in [
            (alloc::vec![T_UTF8, 2, 0xc3, 0x89], true),
            (alloc::vec![T_PRINTABLE, 3, b'A', b'+', b'1'], true),
            (alloc::vec![T_T61, 1, 0xff], true),
            (alloc::vec![0x1e, 2, 0, b'P'], true),
            (alloc::vec![0x1c, 4, 0, 0, 0, b'P'], true),
            (alloc::vec![T_UTF8, 0], false),
            (alloc::vec![T_UTF8, 1, 0xff], false),
            (alloc::vec![T_PRINTABLE, 1, b'@'], false),
            (alloc::vec![T_PRINTABLE, 1, 0xff], false),
            (alloc::vec![0x1e, 1, 0], false),
            (alloc::vec![0x1c, 3, 0, 0, 0], false),
            (alloc::vec![T_NULL, 0], false),
        ] {
            cases.push((wrap(T_CTX1, &string), accepted));
            cases.push(([wrap(T_CTX0, &string), party.clone()].concat(), accepted));
        }
        for (base, accepted) in cases {
            let subtree = wrap(T_SEQUENCE, &wrap(0xa5, &base));
            for list in [
                subtree.clone(),
                [subtree.as_slice(), control.as_slice()].concat(),
                [control.as_slice(), subtree.as_slice()].concat(),
            ] {
                for field in [T_CTX0, T_CTX1] {
                    let body = wrap(field, &list);
                    let value = wrap(T_SEQUENCE, &body);
                    for critical in [false, true] {
                        let mut extensions = basic.clone();
                        push_ext(&mut extensions, OID_EXT_NC, critical, &value);
                        let encoded = wrap(T_SEQUENCE, &extensions);
                        let result = parse_extensions(&encoded);
                        if accepted {
                            assert_eq!(result.unwrap().name_constraints, Some(body.as_slice()));
                            assert_eq!(
                                apply_name_constraints(&body, &[]).unwrap_err().kind(),
                                ErrorKind::UnsupportedCertificate
                            );
                        } else {
                            assert_eq!(result.err().unwrap().kind(), ErrorKind::BadCertificate);
                        }
                    }
                }
            }
        }
    }

    /// REQ-X509-061: every otherName constraint base is checked during parse,
    /// including later entries and both permitted and excluded subtree lists.
    #[test]
    fn name_constraint_other_names_require_complete_fields() {
        let wrap = |tag, body: &[u8]| {
            let mut encoded = Vec::new();
            push_tlv(&mut encoded, tag, body);
            encoded
        };
        let other = |oid: &[u8], value: &[u8]| [wrap(T_OID, oid), wrap(T_CTX0, value)].concat();
        let control = wrap(T_SEQUENCE, &wrap(T_GN_DNS, b"example.test"));
        let valid = other(&[0x2a, 3], &[T_NULL, 0]);
        let mut basic = Vec::new();
        push_ext(
            &mut basic,
            OID_EXT_BC,
            true,
            &[T_SEQUENCE, 3, T_BOOLEAN, 1, 0xff],
        );
        for (base, accepted) in [
            (valid.clone(), true),
            (other(&[0x2a, 0x81, 0], &[T_UTF8, 1, b'A']), true),
            (other(&[0x2a, 3], &[0x9f, 31, 0]), true),
            (Vec::new(), false),
            (other(&[], &[T_NULL, 0]), false),
            (other(&[0x2a, 0x80, 1], &[T_NULL, 0]), false),
            (other(&[0x2a, 0x81], &[T_NULL, 0]), false),
            (wrap(T_OID, &[0x2a, 3]), false),
            (other(&[0x2a, 3], &[]), false),
            (other(&[0x2a, 3], &[T_NULL, 0, T_NULL, 0]), false),
            (other(&[0x2a, 3], &[T_UTF8, 2, b'A']), false),
            (other(&[0x2a, 3], &[0x9f, 30, 0]), false),
            (
                [wrap(T_OID, &[0x2a, 3]), wrap(T_CTX1, &[T_NULL, 0])].concat(),
                false,
            ),
            ([valid, alloc::vec![T_NULL, 0]].concat(), false),
            (
                [wrap(T_CTX0, &[T_NULL, 0]), wrap(T_OID, &[0x2a, 3])].concat(),
                false,
            ),
        ] {
            let subtree = wrap(T_SEQUENCE, &wrap(T_CTX0, &base));
            for list in [
                subtree.clone(),
                [subtree.as_slice(), control.as_slice()].concat(),
                [control.as_slice(), subtree.as_slice()].concat(),
            ] {
                for field in [T_CTX0, T_CTX1] {
                    let body = wrap(field, &list);
                    let value = wrap(T_SEQUENCE, &body);
                    for critical in [false, true] {
                        let mut extensions = basic.clone();
                        push_ext(&mut extensions, OID_EXT_NC, critical, &value);
                        let encoded = wrap(T_SEQUENCE, &extensions);
                        let result = parse_extensions(&encoded);
                        if accepted {
                            assert_eq!(result.unwrap().name_constraints, Some(body.as_slice()));
                            assert_eq!(
                                apply_name_constraints(&body, &[]).unwrap_err().kind(),
                                ErrorKind::UnsupportedCertificate
                            );
                        } else {
                            assert_eq!(result.err().unwrap().kind(), ErrorKind::BadCertificate);
                        }
                    }
                }
            }
        }
    }

    /// REQ-X509-060: malformed directoryName constraint bases fail during parse
    /// in either list, including after valid bases and malformed RDN attributes.
    #[test]
    fn name_constraint_directory_names_require_complete_ordered_names() {
        let wrap = |tag, body: &[u8]| {
            let mut encoded = Vec::new();
            push_tlv(&mut encoded, tag, body);
            encoded
        };
        let attribute = |oid: &[u8], value: &[u8]| {
            wrap(T_SEQUENCE, &[wrap(T_OID, oid).as_slice(), value].concat())
        };
        let name = |attributes: &[u8]| wrap(T_SEQUENCE, &wrap(T_SET, attributes));
        let a = attribute(&[0x2a, 3], &[T_UTF8, 1, b'A']);
        let b = attribute(&[0x2a, 4], &[T_UTF8, 1, b'B']);
        let control = wrap(T_SEQUENCE, &wrap(T_GN_DNS, b"example.test"));
        let mut trailing = encode_name("Issuer");
        trailing.extend_from_slice(&[T_NULL, 0]);
        let mut basic = Vec::new();
        push_ext(
            &mut basic,
            OID_EXT_BC,
            true,
            &[T_SEQUENCE, 3, T_BOOLEAN, 1, 0xff],
        );
        for (directory, accepted) in [
            (encode_name("Issuer"), true),
            (encode_name("É issuer"), true),
            (alloc::vec![T_SEQUENCE, 0], true),
            (name(&[a.clone(), b.clone()].concat()), true),
            (name(&attribute(&[0x2a, 3], &[0x9f, 31, 0])), true),
            (name(&[b, a].concat()), false),
            (Vec::new(), false),
            (alloc::vec![T_SET, 0], false),
            (alloc::vec![T_SEQUENCE, 1, T_SET], false),
            (trailing, false),
            (name(&[]), false),
            (name(&[T_SEQUENCE, 0]), false),
            (name(&attribute(&[], &[T_NULL, 0])), false),
            (name(&attribute(&[0x2a, 0x81], &[T_NULL, 0])), false),
            (name(&attribute(&[0x2a, 3], &[])), false),
            (name(&attribute(&[0x2a, 3], &[T_NULL, 0, T_NULL, 0])), false),
        ] {
            let subtree = wrap(T_SEQUENCE, &wrap(0xa4, &directory));
            for list in [
                subtree.clone(),
                [subtree.as_slice(), control.as_slice()].concat(),
                [control.as_slice(), subtree.as_slice()].concat(),
            ] {
                for field in [T_CTX0, T_CTX1] {
                    let body = wrap(field, &list);
                    let value = wrap(T_SEQUENCE, &body);
                    for critical in [false, true] {
                        let mut extensions = basic.clone();
                        push_ext(&mut extensions, OID_EXT_NC, critical, &value);
                        let encoded = wrap(T_SEQUENCE, &extensions);
                        let result = parse_extensions(&encoded);
                        if accepted {
                            assert_eq!(result.unwrap().name_constraints, Some(body.as_slice()));
                            assert_eq!(
                                apply_name_constraints(&body, &[]).unwrap_err().kind(),
                                ErrorKind::UnsupportedCertificate
                            );
                        } else {
                            assert_eq!(
                                result.err().unwrap().kind(),
                                ErrorKind::BadCertificate,
                                "directory={directory:?}, field={field}, critical={critical}"
                            );
                        }
                    }
                }
            }
        }
    }

    /// REQ-X509-059: malformed registeredID OIDs fail before unsupported-form
    /// evaluation, including bases following another subtree in either list.
    #[test]
    fn name_constraint_registered_ids_require_minimal_oids() {
        let mut dns = Vec::new();
        push_tlv(&mut dns, T_GN_DNS, b"example.test");
        let mut control = Vec::new();
        push_tlv(&mut control, T_SEQUENCE, &dns);
        let mut basic = Vec::new();
        push_ext(
            &mut basic,
            OID_EXT_BC,
            true,
            &[T_SEQUENCE, 3, T_BOOLEAN, 1, 0xff],
        );
        for (oid, expected_error) in [
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
            let mut base = Vec::new();
            push_tlv(&mut base, 0x88, oid);
            let mut subtree = Vec::new();
            push_tlv(&mut subtree, T_SEQUENCE, &base);
            for list in [
                subtree.clone(),
                [subtree.as_slice(), control.as_slice()].concat(),
                [control.as_slice(), subtree.as_slice()].concat(),
            ] {
                for field in [T_CTX0, T_CTX1] {
                    let mut body = Vec::new();
                    push_tlv(&mut body, field, &list);
                    let mut value = Vec::new();
                    push_tlv(&mut value, T_SEQUENCE, &body);
                    for critical in [false, true] {
                        let mut extensions = basic.clone();
                        push_ext(&mut extensions, OID_EXT_NC, critical, &value);
                        let mut encoded = Vec::new();
                        push_tlv(&mut encoded, T_SEQUENCE, &extensions);
                        let result = parse_extensions(&encoded);
                        if let Some(context) = expected_error {
                            let error = result.err().unwrap();
                            assert_eq!(error.kind(), ErrorKind::BadCertificate);
                            assert_eq!(error.context(), context);
                        } else {
                            assert_eq!(result.unwrap().name_constraints, Some(body.as_slice()));
                            assert_eq!(
                                apply_name_constraints(&body, &[]).unwrap_err().kind(),
                                ErrorKind::UnsupportedCertificate
                            );
                        }
                    }
                }
            }
        }
    }

    /// REQ-X509-058: malformed distance INTEGERs fail during parsing in either
    /// field and list, while arbitrarily wide canonical positive values survive.
    #[test]
    fn name_constraint_distances_require_nonnegative_minimal_integers() {
        let mut base = Vec::new();
        push_tlv(&mut base, T_GN_DNS, b"example.test");
        let mut control = Vec::new();
        push_tlv(&mut control, T_SEQUENCE, &base);
        let mut basic = Vec::new();
        push_ext(
            &mut basic,
            OID_EXT_BC,
            true,
            &[T_SEQUENCE, 3, T_BOOLEAN, 1, 0xff],
        );
        let mut wide = alloc::vec![0x80; 128];
        wide.insert(0, 0);
        for (distance, accepted) in [
            (alloc::vec![0], true),
            (alloc::vec![1], true),
            (alloc::vec![0x7f], true),
            (alloc::vec![0, 0x80], true),
            (alloc::vec![1, 0], true),
            (alloc::vec![1; 9], true),
            (wide, true),
            (Vec::new(), false),
            (alloc::vec![0xff], false),
            (alloc::vec![0x80], false),
            (alloc::vec![0xff, 0x7f], false),
            (alloc::vec![0, 0], false),
            (alloc::vec![0, 1], false),
            (alloc::vec![0, 0x7f], false),
            (alloc::vec![0, 0, 0x80], false),
        ] {
            for tag in [0x80, 0x81] {
                // A minimum of 0 is the DEFAULT, omitted in DER (REQ-X509-077).
                let accepted = accepted && !(tag == 0x80 && distance == [0]);
                let mut body = base.clone();
                push_tlv(&mut body, tag, &distance);
                let mut subtree = Vec::new();
                push_tlv(&mut subtree, T_SEQUENCE, &body);
                for list in [
                    subtree.clone(),
                    [subtree.as_slice(), control.as_slice()].concat(),
                    [control.as_slice(), subtree.as_slice()].concat(),
                ] {
                    for field in [T_CTX0, T_CTX1] {
                        let mut body = Vec::new();
                        push_tlv(&mut body, field, &list);
                        let mut value = Vec::new();
                        push_tlv(&mut value, T_SEQUENCE, &body);
                        for critical in [false, true] {
                            let mut extensions = basic.clone();
                            push_ext(&mut extensions, OID_EXT_NC, critical, &value);
                            let mut encoded = Vec::new();
                            push_tlv(&mut encoded, T_SEQUENCE, &extensions);
                            let result = parse_extensions(&encoded);
                            if accepted {
                                assert_eq!(result.unwrap().name_constraints, Some(body.as_slice()));
                                // Existing evaluation policy still refuses distance fields.
                                assert_eq!(
                                    apply_name_constraints(&body, &[]).unwrap_err().kind(),
                                    ErrorKind::UnsupportedCertificate
                                );
                            } else {
                                assert_eq!(
                                    result.err().unwrap().kind(),
                                    ErrorKind::BadCertificate,
                                    "distance={distance:?}, tag={tag}, field={field}"
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    /// REQ-X509-057: every subtree is framed completely, including entries
    /// following a valid subtree in either list and optional distance fields.
    #[test]
    fn name_constraint_subtrees_require_complete_ordered_fields() {
        let wrap = |body: &[u8]| {
            let mut encoded = Vec::new();
            push_tlv(&mut encoded, T_SEQUENCE, body);
            encoded
        };
        let mut dns = Vec::new();
        push_tlv(&mut dns, T_GN_DNS, b"example.test");
        let valid = wrap(&dns);
        // A non-default minimum parses (and later fails closed in
        // evaluation); the DEFAULT 0 written out is not DER (REQ-X509-077).
        let min = [0x80, 1, 1];
        let max = [0x81, 1, 1];
        let mut basic = Vec::new();
        push_ext(
            &mut basic,
            OID_EXT_BC,
            true,
            &[T_SEQUENCE, 3, T_BOOLEAN, 1, 0xff],
        );
        let cases = [
            (valid.clone(), true),
            (wrap(&[dns.as_slice(), &min].concat()), true),
            (wrap(&[dns.as_slice(), &max].concat()), true),
            (wrap(&[dns.as_slice(), &min, &max].concat()), true),
            (wrap(&[0x88, 2, 0x2a, 3]), true), // Defined but unsupported constraint form.
            (wrap(&[]), false),
            (alloc::vec![T_SET, 0], false),
            (alloc::vec![T_SEQUENCE], false),
            (wrap(&[T_GN_DNS, 2, b'A']), false),
            (wrap(&[T_NULL, 0]), false),
            (wrap(&[0xa2, 0]), false),
            (wrap(&[dns.as_slice(), dns.as_slice()].concat()), false),
            (wrap(&[dns.as_slice(), &max, &min].concat()), false),
            (wrap(&[dns.as_slice(), &min, &min].concat()), false),
            (wrap(&[dns.as_slice(), &max, &max].concat()), false),
            (wrap(&[dns.as_slice(), &[T_CTX0, 0]].concat()), false),
            (wrap(&[dns.as_slice(), &[T_CTX1, 0]].concat()), false),
            (wrap(&[dns.as_slice(), &[T_NULL, 0]].concat()), false),
            (wrap(&[dns.as_slice(), &[0x80, 2, 0]].concat()), false),
            (wrap(&[dns.as_slice(), &[0x80, 1, 0]].concat()), false),
        ];
        for (encoded_subtree, accepted) in cases {
            for list in [
                encoded_subtree.clone(),
                [encoded_subtree.as_slice(), valid.as_slice()].concat(),
                [valid.as_slice(), encoded_subtree.as_slice()].concat(),
            ] {
                for field in [T_CTX0, T_CTX1] {
                    let mut body = Vec::new();
                    push_tlv(&mut body, field, &list);
                    let mut value = Vec::new();
                    push_tlv(&mut value, T_SEQUENCE, &body);
                    for critical in [false, true] {
                        let mut extensions = basic.clone();
                        push_ext(&mut extensions, OID_EXT_NC, critical, &value);
                        let mut encoded = Vec::new();
                        push_tlv(&mut encoded, T_SEQUENCE, &extensions);
                        let result = parse_extensions(&encoded);
                        if accepted {
                            assert_eq!(result.unwrap().name_constraints, Some(body.as_slice()));
                        } else {
                            assert_eq!(
                                result.err().unwrap().kind(),
                                ErrorKind::BadCertificate,
                                "subtree={encoded_subtree:?}, field={field}, critical={critical}"
                            );
                        }
                    }
                }
            }
        }
    }

    /// REQ-X509-056: malformed name-constraint list wrappers fail during
    /// extension parsing, before any chain evaluation can be skipped.
    #[test]
    fn name_constraint_list_wrappers_are_validated_during_parse() {
        let mut base = Vec::new();
        push_tlv(&mut base, T_GN_DNS, b"example.test");
        let mut subtree = Vec::new();
        push_tlv(&mut subtree, T_SEQUENCE, &base);
        let mut permitted = Vec::new();
        push_tlv(&mut permitted, T_CTX0, &subtree);
        let mut excluded = Vec::new();
        push_tlv(&mut excluded, T_CTX1, &subtree);
        let mut basic = Vec::new();
        push_ext(
            &mut basic,
            OID_EXT_BC,
            true,
            &[T_SEQUENCE, 3, T_BOOLEAN, 1, 0xff],
        );
        for (body, accepted) in [
            (permitted.clone(), true),
            (excluded.clone(), true),
            ([permitted.clone(), excluded.clone()].concat(), true),
            (Vec::new(), false),
            (alloc::vec![T_CTX0, 0], false),
            (alloc::vec![T_CTX1, 0], false),
            ([permitted.clone(), alloc::vec![T_CTX1, 0]].concat(), false),
            ([alloc::vec![T_CTX0, 0], excluded.clone()].concat(), false),
            ([excluded.clone(), permitted.clone()].concat(), false),
            ([permitted.clone(), permitted.clone()].concat(), false),
            ([excluded.clone(), excluded.clone()].concat(), false),
            ([permitted.clone(), alloc::vec![T_NULL, 0]].concat(), false),
            (alloc::vec![T_CTX0], false),
            (alloc::vec![T_CTX0, 2, T_SEQUENCE], false),
        ] {
            for critical in [false, true] {
                let mut value = Vec::new();
                push_tlv(&mut value, T_SEQUENCE, &body);
                let mut constraint = Vec::new();
                push_ext(&mut constraint, OID_EXT_NC, critical, &value);
                for first in [false, true] {
                    let entries = if first {
                        [basic.as_slice(), constraint.as_slice()].concat()
                    } else {
                        [constraint.as_slice(), basic.as_slice()].concat()
                    };
                    let mut encoded = Vec::new();
                    push_tlv(&mut encoded, T_SEQUENCE, &entries);
                    let result = parse_extensions(&encoded);
                    if accepted {
                        assert_eq!(result.unwrap().name_constraints, Some(body.as_slice()));
                    } else {
                        assert_eq!(
                            result.err().unwrap().kind(),
                            ErrorKind::BadCertificate,
                            "body={body:?}, critical={critical}, first={first}"
                        );
                    }
                }
            }
        }
    }

    /// REQ-X509-055: nameConstraints requires cA regardless of criticality,
    /// permitted/excluded choice, or the order of its basicConstraints sibling.
    #[test]
    fn name_constraints_require_ca_basic_constraints() {
        let mut base = Vec::new();
        push_tlv(&mut base, T_GN_DNS, b"example.test");
        let mut subtree = Vec::new();
        push_tlv(&mut subtree, T_SEQUENCE, &base);
        for field in [T_CTX0, T_CTX1] {
            let mut body = Vec::new();
            push_tlv(&mut body, field, &subtree);
            let mut value = Vec::new();
            push_tlv(&mut value, T_SEQUENCE, &body);
            for critical in [false, true] {
                let mut constraint = Vec::new();
                push_ext(&mut constraint, OID_EXT_NC, critical, &value);
                for ca in [None, Some(None), Some(Some(false)), Some(Some(true))] {
                    for basic_critical in [false, true] {
                        let mut basic = Vec::new();
                        if let Some(ca) = ca {
                            let mut body = Vec::new();
                            if let Some(ca) = ca {
                                push_tlv(&mut body, T_BOOLEAN, &[if ca { 0xff } else { 0 }]);
                            }
                            let mut encoded = Vec::new();
                            push_tlv(&mut encoded, T_SEQUENCE, &body);
                            push_ext(&mut basic, OID_EXT_BC, basic_critical, &encoded);
                        }
                        for first in [false, true] {
                            let entries = if first {
                                [basic.as_slice(), constraint.as_slice()].concat()
                            } else {
                                [constraint.as_slice(), basic.as_slice()].concat()
                            };
                            let mut encoded = Vec::new();
                            push_tlv(&mut encoded, T_SEQUENCE, &entries);
                            let result = parse_extensions(&encoded);
                            if ca == Some(Some(true)) {
                                assert_eq!(result.unwrap().name_constraints, Some(body.as_slice()));
                            } else {
                                let error = result.err().unwrap();
                                assert_eq!(error.kind(), ErrorKind::BadCertificate);
                                assert_eq!(
                                    error.context(),
                                    "nameConstraints requires CA basicConstraints"
                                );
                            }
                        }
                    }
                }
            }
        }
        // An ordinary non-CA extension set without nameConstraints remains valid.
        let mut entry = Vec::new();
        push_ext(&mut entry, OID_EXT_KU, true, &[T_BIT_STRING, 2, 7, 0x80]);
        let mut encoded = Vec::new();
        push_tlv(&mut encoded, T_SEQUENCE, &entry);
        assert!(parse_extensions(&encoded)
            .unwrap()
            .name_constraints
            .is_none());
    }

    /// REQ-X509-054: certificate-signing usage requires cA even without a path
    /// limit, with absent/default/false constraints and either extension order.
    #[test]
    fn certificate_signing_usage_requires_ca_basic_constraints() {
        for basic_ca in [None, Some(None), Some(Some(false)), Some(Some(true))] {
            for usage in [
                None,
                Some(KU_DIGITAL_SIGNATURE),
                Some(KU_CRL_SIGN),
                Some(KU_KEY_CERT_SIGN),
                Some(KU_KEY_CERT_SIGN | KU_DIGITAL_SIGNATURE | KU_CRL_SIGN),
            ] {
                for basic_critical in [false, true] {
                    for usage_critical in [false, true] {
                        for basic_first in [false, true] {
                            let mut basic = Vec::new();
                            if let Some(ca) = basic_ca {
                                let mut body = Vec::new();
                                if let Some(ca) = ca {
                                    push_tlv(&mut body, T_BOOLEAN, &[if ca { 0xff } else { 0 }]);
                                }
                                let mut value = Vec::new();
                                push_tlv(&mut value, T_SEQUENCE, &body);
                                push_ext(&mut basic, OID_EXT_BC, basic_critical, &value);
                            }
                            let mut key_usage = Vec::new();
                            if let Some(usage) = usage {
                                let mut value = Vec::new();
                                push_tlv(&mut value, T_BIT_STRING, &key_usage_bits(usage));
                                push_ext(&mut key_usage, OID_EXT_KU, usage_critical, &value);
                            }
                            // Keep the Extensions sequence nonempty for absent controls.
                            let mut entries = Vec::new();
                            push_ext(&mut entries, &[0x2a, 3], false, &[T_NULL, 0]);
                            if basic_first {
                                entries.extend_from_slice(&basic);
                            }
                            entries.extend_from_slice(&key_usage);
                            if !basic_first {
                                entries.extend_from_slice(&basic);
                            }
                            let mut encoded = Vec::new();
                            push_tlv(&mut encoded, T_SEQUENCE, &entries);
                            let result = parse_extensions(&encoded);
                            let signing = usage.is_some_and(|ku| ku & KU_KEY_CERT_SIGN != 0);
                            if !signing || basic_ca == Some(Some(true)) {
                                let parsed = result.unwrap();
                                assert_eq!(parsed.key_usage, usage);
                                assert_eq!(
                                    parsed.basic,
                                    basic_ca.map(|ca| (ca.unwrap_or(false), None))
                                );
                            } else {
                                let error = result.err().unwrap();
                                assert_eq!(error.kind(), ErrorKind::BadCertificate);
                                assert_eq!(
                                    error.context(),
                                    "keyCertSign requires CA basicConstraints"
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    /// REQ-X509-015: path-length restrictions require cA and cannot
    /// conflict with present KeyUsage, regardless of extension ordering.
    #[test]
    fn path_length_requires_ca_and_signing_usage() {
        for ca in [None, Some(false), Some(true)] {
            for path in [None, Some(0), Some(1)] {
                for usage in [None, Some(KU_DIGITAL_SIGNATURE), Some(KU_KEY_CERT_SIGN)] {
                    for basic_first in [false, true] {
                        let mut body = Vec::new();
                        if let Some(ca) = ca {
                            push_tlv(&mut body, T_BOOLEAN, &[if ca { 0xff } else { 0 }]);
                        }
                        if let Some(path) = path {
                            push_tlv(&mut body, T_INTEGER, &[path]);
                        }
                        let mut value = Vec::new();
                        push_tlv(&mut value, T_SEQUENCE, &body);
                        let mut basic = Vec::new();
                        push_ext(&mut basic, OID_EXT_BC, true, &value);
                        let mut key_usage = Vec::new();
                        if let Some(usage) = usage {
                            let mut value = Vec::new();
                            push_tlv(&mut value, T_BIT_STRING, &key_usage_bits(usage));
                            push_ext(&mut key_usage, OID_EXT_KU, true, &value);
                        }
                        let mut entries = Vec::new();
                        if basic_first {
                            entries.extend_from_slice(&basic);
                        }
                        entries.extend_from_slice(&key_usage);
                        if !basic_first {
                            entries.extend_from_slice(&basic);
                        }
                        let mut encoded = Vec::new();
                        push_tlv(&mut encoded, T_SEQUENCE, &entries);
                        let result = parse_extensions(&encoded);
                        let allowed = (path.is_none()
                            || (ca == Some(true)
                                && usage.is_none_or(|usage| usage & KU_KEY_CERT_SIGN != 0)))
                            && (usage.is_none_or(|usage| usage & KU_KEY_CERT_SIGN == 0)
                                || ca == Some(true));
                        assert_eq!(
                            result.is_ok(),
                            allowed,
                            "ca={ca:?}, path={path:?}, usage={usage:?}, basic_first={basic_first}"
                        );
                    }
                }
            }
        }
    }

    /// REQ-X509-014: trailing fields cannot be hidden outside the parsed
    /// Extensions sequence, even when its individual entries are valid.
    #[test]
    fn extensions_wrapper_refuses_trailing_bytes() {
        let mut value = Vec::new();
        push_tlv(&mut value, T_BIT_STRING, &[7, 0x80]);
        let mut entry = Vec::new();
        push_ext(&mut entry, OID_EXT_KU, true, &value);
        let mut encoded = Vec::new();
        push_tlv(&mut encoded, T_SEQUENCE, &entry);
        assert_eq!(
            parse_extensions(&encoded).unwrap().key_usage,
            Some(KU_DIGITAL_SIGNATURE)
        );
        for suffix in [
            &[0x05, 0][..],
            &[T_SEQUENCE, 0][..],
            &[T_SEQUENCE][..],
            &[0][..],
            encoded.as_slice(),
        ] {
            let mut trailing = encoded.clone();
            trailing.extend_from_slice(suffix);
            assert_eq!(
                parse_extensions(&trailing).err().unwrap().kind(),
                ErrorKind::BadCertificate
            );
        }
    }

    /// REQ-X509-010: present EKU requires at least one purpose; absence and
    /// well-formed single or multiple purposes remain permitted.
    #[test]
    fn extended_key_usage_requires_a_nonempty_purpose_list() {
        for critical in [false, true] {
            for purposes in [
                &[][..],
                &[OID_KP_SERVER_AUTH][..],
                &[OID_KP_SERVER_AUTH, OID_KP_CLIENT_AUTH][..],
                &[OID_ANY_EKU][..],
            ] {
                let mut body = Vec::new();
                for oid in purposes {
                    push_tlv(&mut body, T_OID, oid);
                }
                let mut value = Vec::new();
                push_tlv(&mut value, T_SEQUENCE, &body);
                let mut entry = Vec::new();
                push_ext(&mut entry, OID_EXT_EKU, critical, &value);
                let mut extensions = Vec::new();
                push_tlv(&mut extensions, T_SEQUENCE, &entry);
                let result = parse_extensions(&extensions);
                if purposes.is_empty() {
                    assert!(result.is_err(), "accepted empty EKU, critical={critical}");
                } else {
                    assert_eq!(result.unwrap().eku, Some(body.as_slice()));
                }
            }
        }
        let mut value = Vec::new();
        push_tlv(&mut value, T_BIT_STRING, &[7, 0x80]);
        let mut entry = Vec::new();
        push_ext(&mut entry, OID_EXT_KU, true, &value);
        let mut extensions = Vec::new();
        push_tlv(&mut extensions, T_SEQUENCE, &entry);
        assert!(parse_extensions(&extensions).unwrap().eku.is_none());
    }

    /// REQ-X509-009: padding cannot assert a usage and zero-use extensions
    /// are refused. Unknown named bits remain ignorable for compatibility.
    #[test]
    fn key_usage_padding_and_empty_values_are_refused() {
        for (bits, expected) in [
            (alloc::vec![7, 0x80], Some(KU_DIGITAL_SIGNATURE)),
            (alloc::vec![5, 0x20], Some(1 << 2)),
            (alloc::vec![6, 0, 0x40], Some(0)), // unknown bit 9
            (alloc::vec![7, 0x81], None),
            (alloc::vec![7, 1], None),
            (alloc::vec![5, 0x21], None),
            (alloc::vec![7, 0x80, 1], None),
            (alloc::vec![0, 0], None),
            (alloc::vec![7, 0], None),
            (alloc::vec![0, 0, 0], None),
            (alloc::vec![8, 0x80], None),
            (alloc::vec![0], None),
            (Vec::new(), None),
        ] {
            let mut value = Vec::new();
            push_tlv(&mut value, T_BIT_STRING, &bits);
            let mut entry = Vec::new();
            push_ext(&mut entry, OID_EXT_KU, true, &value);
            let mut extensions = Vec::new();
            push_tlv(&mut extensions, T_SEQUENCE, &entry);
            let result = parse_extensions(&extensions);
            match expected {
                Some(usage) => assert_eq!(result.unwrap().key_usage, Some(usage)),
                None => assert!(result.is_err(), "accepted {bits:?}"),
            }
        }
    }

    #[test]
    fn key_usage_encoding_drops_trailing_zero_bits() {
        assert_eq!(key_usage_bits(KU_DIGITAL_SIGNATURE), [7, 0x80]);
        assert_eq!(
            key_usage_bits(KU_DIGITAL_SIGNATURE | KU_KEY_CERT_SIGN | KU_CRL_SIGN),
            [1, 0x86]
        );
    }

    #[test]
    fn garbage_never_panics() {
        for len in 0..64 {
            let junk: Vec<u8> = (0..len).map(|i| (i * 37 + 11) as u8).collect();
            assert!(Certificate::parse(&junk).is_err());
        }
        assert!(Certificate::parse(&[0x30, 0x84, 0xff, 0xff, 0xff, 0xff]).is_err());
        assert!(Certificate::parse(&[0x30, 0x80, 0x00, 0x00]).is_err());
    }

    /// REQ-X509-066: an RSA PKCS#1 v1.5 signature AlgorithmIdentifier carries
    /// an absent or empty NULL parameter (RFC 4055 section 5); a NULL with
    /// content is malformed, not a parameter to ignore.
    #[test]
    fn rsa_signature_null_parameters_must_be_empty() {
        let alg = |params: &[u8]| {
            let mut alg = Vec::new();
            push_tlv(&mut alg, T_OID, OID_RSA_SHA256);
            alg.extend_from_slice(params);
            alg
        };
        for params in [&[][..], &[T_NULL, 0][..]] {
            assert_eq!(
                scheme_from_alg(&alg(params)).unwrap(),
                SignatureScheme::RsaPkcs1Sha256
            );
        }
        for params in [&[T_NULL, 1, 0][..], &[T_NULL, 2, 0, 0][..]] {
            let e = scheme_from_alg(&alg(params)).unwrap_err();
            assert_eq!(e.kind(), ErrorKind::BadCertificate);
            assert_eq!(e.context(), "NULL with content");
        }
    }

    /// REQ-X509-001: GeneralizedTime admits the years 0000 to 9999, and a
    /// date in January or February of year 0 precedes the March 1 from
    /// which the civil-day algorithm counts eras, so its year term is
    /// negative there. It converts by the proleptic Gregorian calendar (year
    /// 0 is a leap year; 0000-01-01 is 719 528 days before 1970-01-01, as
    /// Python's `datetime` also computes) and clamps to 0 as a validity
    /// time, without a panic.
    #[test]
    fn year_zero_times_convert_by_the_proleptic_calendar() {
        assert_eq!(days_from_civil(0, 1, 1), -719_528);
        assert_eq!(days_from_civil(0, 2, 29), -719_469);
        assert_eq!(days_from_civil(0, 3, 1), -719_468);
        assert_eq!(days_from_civil(1, 1, 1), -719_162);
        for t in [&b"00000101000000Z"[..], b"00000229235959Z"] {
            assert_eq!(parse_time(T_GENERALIZED_TIME, t).unwrap(), 0);
        }
        assert!(parse_time(T_GENERALIZED_TIME, b"00000230000000Z").is_err());
    }

    /// REQ-X509-003: reference IP addresses use the RFC 4291 section 2.2
    /// text forms: eight groups of one to four hexadecimal digits, or fewer
    /// around a single "::" that stands for at least one zero group, and
    /// dotted quads have exactly four decimal parts. Anything else is not an
    /// address.
    #[test]
    fn ip_address_text_requires_exact_groups_and_digits() {
        assert_eq!(IpAddr::parse("192.0.2.1.5"), None);
        let full = IpAddr::parse("2001:db8:0:0:0:0:0:1").unwrap();
        assert_eq!(IpAddr::parse("2001:db8::1"), Some(full));
        assert_eq!(
            IpAddr::parse("1:2:3:4:5:6:7:8"),
            Some(IpAddr::V6([0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6, 0, 7, 0, 8]))
        );
        for text in [
            "1:2:3:4::5:6:7:8",
            "::1:2:3:4:5:6:7:8",
            "1:2:3:4:5:6:7:",
            ":1:2:3:4:5:6:7",
            "1::2:",
            "12345::1",
            "1:2:3:4:5:6:7:12345",
            "1:2:3:4:5:6:7:00008",
            "00001::",
            "1:2:3:4:5:6:7",
            "::+1",
            "+1::",
            "1:2:3:4:5:6:7:+8",
            "::ffff:+1.2.3.4",
        ] {
            assert_eq!(IpAddr::parse(text), None, "{text}");
        }
    }

    /// REQ-X509-040: the display common name is read from a complete Name:
    /// attributes of other types are passed over wherever they sit, and a
    /// Name without a CN has none.
    #[test]
    fn common_name_passes_over_other_attributes() {
        let attribute = |oid: &[u8], tag: u8, value: &[u8]| {
            let mut atv = Vec::new();
            push_tlv(&mut atv, T_OID, oid);
            push_tlv(&mut atv, tag, value);
            let mut seq = Vec::new();
            push_tlv(&mut seq, T_SEQUENCE, &atv);
            let mut set = Vec::new();
            push_tlv(&mut set, T_SET, &seq);
            set
        };
        let name = |rdns: &[Vec<u8>]| {
            let mut out = Vec::new();
            push_tlv(&mut out, T_SEQUENCE, &rdns.concat());
            out
        };
        // id-at-organizationName, 2.5.4.10.
        let org = attribute(&[0x55, 0x04, 0x0a], T_UTF8, b"Example Org");
        let cn = attribute(OID_CN, T_PRINTABLE, b"Example Root");
        assert_eq!(
            name_common_name(&name(&[org.clone(), cn.clone()])),
            Some("Example Root")
        );
        assert_eq!(
            name_common_name(&name(&[cn, org.clone()])),
            Some("Example Root")
        );
        assert_eq!(name_common_name(&name(&[org])), None);
    }

    /// REQ-X509-003: a wildcard stands for exactly one nonempty label, so it
    /// does not match a reference name whose first label is empty.
    #[test]
    fn a_wildcard_never_matches_an_empty_label() {
        assert!(dns_matches("*.example.com", "a.example.com"));
        assert!(!dns_matches("*.example.com", ".example.com"));
    }

    /// REQ-X509-068: decipherOnly (bit 8) is the one KeyUsage bit in the
    /// second octet; the encoder keeps that octet, with seven unused bits
    /// after it and a zero first octet when no other bit is set (X.690
    /// section 11.2.2).
    #[test]
    fn key_usage_encoding_reaches_the_second_octet() {
        assert_eq!(key_usage_bits(1 << 8), [7, 0x00, 0x80]);
        assert_eq!(
            key_usage_bits(KU_DIGITAL_SIGNATURE | 1 << 8),
            [7, 0x80, 0x80]
        );
    }
}

#[cfg(all(test, feature = "std"))]
mod chain_tests {
    use super::*;
    use crate::crypto::sign::KeyKind;

    const NOW: u64 = 1_800_000_000;
    const DAY: u64 = 86_400;

    /// REQ-X509-067: signed certificates refuse malformed SPKI fields during
    /// parsing without restricting structurally valid unknown key algorithms.
    #[test]
    fn received_public_key_info_requires_complete_fields() {
        let wrap = |tag, body: &[u8]| {
            let mut encoded = Vec::new();
            push_tlv(&mut encoded, tag, body);
            encoded
        };
        let mut r = rng();
        let key = SigningKey::generate(KeyKind::Ed25519, &mut r).unwrap();
        let original = self_signed(&params("SPKI fixture", &[], false), &key, &mut r).unwrap();
        let parsed = Certificate::parse(&original).unwrap();
        let mut fields = Der::new(parsed.tbs).nested(T_SEQUENCE).unwrap();
        let mut prefix = Vec::new();
        for _ in 0..6 {
            prefix.extend_from_slice(fields.tlv().unwrap().2);
        }
        fields.expect(T_SEQUENCE).unwrap();
        let mut tail = Vec::new();
        while !fields.is_empty() {
            tail.extend_from_slice(fields.tlv().unwrap().2);
        }
        let unknown = wrap(T_SEQUENCE, &wrap(T_OID, &[0x2a, 3]));
        let mut cases = alloc::vec![(key.spki().to_vec(), true)];
        for (bits, accepted) in [
            (alloc::vec![0], true),
            (alloc::vec![0, 0xff], true),
            (alloc::vec![7, 0x80], true),
            (Vec::new(), false),
            (alloc::vec![1], false),
            (alloc::vec![8, 0], false),
            (alloc::vec![1, 1], false),
            (alloc::vec![7, 0x81], false),
        ] {
            cases.push((
                wrap(
                    T_SEQUENCE,
                    &[unknown.clone(), wrap(T_BIT_STRING, &bits)].concat(),
                ),
                accepted,
            ));
        }
        let bits = wrap(T_BIT_STRING, &[0, 1]);
        for algorithm in [
            wrap(T_SEQUENCE, &[]),
            wrap(T_SEQUENCE, &wrap(T_OID, &[])),
            wrap(T_SEQUENCE, &wrap(T_OID, &[0x2a, 0x81])),
            wrap(
                T_SEQUENCE,
                &[wrap(T_OID, &[0x2a, 3]), alloc::vec![T_NULL, 0, T_NULL, 0]].concat(),
            ),
            wrap(T_NULL, &[]),
        ] {
            cases.push((wrap(T_SEQUENCE, &[algorithm, bits.clone()].concat()), false));
        }
        for body in [
            Vec::new(),
            unknown.clone(),
            [unknown.clone(), wrap(T_OCTET_STRING, &[1])].concat(),
            [unknown.clone(), bits.clone(), bits.clone()].concat(),
            [unknown, bits, alloc::vec![T_NULL, 0]].concat(),
        ] {
            cases.push((wrap(T_SEQUENCE, &body), false));
        }
        for (spki, accepted) in cases {
            let tbs = wrap(
                T_SEQUENCE,
                &[prefix.as_slice(), spki.as_slice(), tail.as_slice()].concat(),
            );
            let signature = key.sign(SignatureScheme::Ed25519, &tbs, &mut r).unwrap();
            sign::verify(
                SignatureScheme::Ed25519,
                &PublicKey::from_spki(key.spki()).unwrap(),
                &tbs,
                &signature,
            )
            .unwrap();
            let der = wrap(
                T_SEQUENCE,
                &[
                    tbs,
                    alg_id(SignatureScheme::Ed25519).unwrap(),
                    wrap(T_BIT_STRING, &[alloc::vec![0], signature].concat()),
                ]
                .concat(),
            );
            let result = Certificate::parse(&der);
            if accepted {
                let cert = result.unwrap();
                assert_eq!(cert.spki_der(), spki.as_slice());
                check_signature(&cert, key.spki(), &opts()).unwrap();
            } else {
                assert_eq!(result.err().unwrap().kind(), ErrorKind::BadCertificate);
            }
        }
    }

    #[test]
    fn certificate_issuance_refuses_unusable_subject_public_keys() {
        let mut r = rng();
        let root_key = SigningKey::generate(KeyKind::EcdsaP256, &mut r).unwrap();
        let root = self_signed(&params("Root", &[], true), &root_key, &mut r).unwrap();
        let pp = params("Subject", &["subject.example"], false);
        let assemble = |alg: &[u8], bits: &[u8]| {
            let mut body = alg.to_vec();
            push_tlv(&mut body, T_BIT_STRING, bits);
            let mut out = Vec::new();
            push_tlv(&mut out, T_SEQUENCE, &body);
            out
        };
        for &kind in KeyKind::ALL {
            let key = SigningKey::generate(kind, &mut r).unwrap();
            let valid = issue(&pp, key.spki(), &root, &root_key, &mut r).unwrap();
            let cert = Certificate::parse(&valid).unwrap();
            assert_eq!(cert.spki, key.spki());
            cert.subject_public_key().unwrap();
            check_signature(&cert, root_key.spki(), &opts()).unwrap();

            let mut spki = Der::new(key.spki()).nested(T_SEQUENCE).unwrap();
            let alg = spki.expect_raw(T_SEQUENCE).unwrap();
            let bits = spki.expect(T_BIT_STRING).unwrap();
            spki.finish().unwrap();
            let mut longer = bits.to_vec();
            longer.push(0);
            let mut unused = bits.to_vec();
            unused[0] = 1;
            let mut trailing = key.spki().to_vec();
            trailing.push(0);
            let mut unknown_alg_body = Vec::new();
            push_tlv(&mut unknown_alg_body, T_OID, &[0x2a, 3, 4]);
            let mut unknown_alg = Vec::new();
            push_tlv(&mut unknown_alg, T_SEQUENCE, &unknown_alg_body);
            for malformed in [
                assemble(alg, &bits[..bits.len() - 1]),
                assemble(alg, &longer),
                assemble(alg, &unused),
                trailing,
                assemble(&unknown_alg, bits),
                Vec::new(),
            ] {
                let error = issue(&pp, &malformed, &root, &root_key, &mut r).unwrap_err();
                assert_eq!(error.kind(), ErrorKind::InvalidConfig, "{kind:?}: {error}");
                assert_eq!(error.context(), "subject public key is not usable");
            }
        }
    }

    /// Published SPKI and method-1 identifier from RFC 7093 section 3:
    /// https://www.rfc-editor.org/rfc/rfc7093.html#section-3
    #[test]
    fn key_identifier_matches_rfc7093_method_one() {
        let mut spki = [0u8; 91];
        ic_core::codec::hex_decode(
            concat!(
                "3059301306072A8648CE3D020106082A8648CE3D030107034200",
                "047F7F35A79794C950060B8029FC8F363A",
                "28F11159692D9D34E6AC948190434735",
                "F833B1A66652DC514337AFF7F5C9C75D",
                "670C019D95A5D639B72744C64A9128BB"
            )
            .as_bytes(),
            &mut spki,
        )
        .unwrap();
        let mut expected = [0u8; 20];
        ic_core::codec::hex_decode(b"BF37B3E5808FD46D54B28E846311BCCE1CAD2E1A", &mut expected)
            .unwrap();
        assert_eq!(key_identifier(&spki).unwrap(), expected);

        let mut r = rng();
        let root_key = SigningKey::generate(KeyKind::EcdsaP256, &mut r).unwrap();
        let root = self_signed(&params("Root", &[], true), &root_key, &mut r).unwrap();
        let leaf = issue(
            &params("Subject", &["subject.example"], false),
            &spki,
            &root,
            &root_key,
            &mut r,
        )
        .unwrap();
        let cert = Certificate::parse(&leaf).unwrap();
        assert_eq!(cert.spki, spki);
        assert_eq!(cert.ext.ski, Some(expected.as_slice()));
        let issuer = Certificate::parse(&root).unwrap();
        assert_eq!(cert.ext.aki, issuer.ext.ski);
        check_signature(&cert, root_key.spki(), &opts()).unwrap();
    }

    #[test]
    fn certificate_issuance_validates_every_dns_alternative_name() {
        let mut r = rng();
        let root_key = SigningKey::generate(KeyKind::EcdsaP256, &mut r).unwrap();
        let root = self_signed(&params("Root", &[], true), &root_key, &mut r).unwrap();
        let subject_key = SigningKey::generate(KeyKind::EcdsaP256, &mut r).unwrap();
        let mut cases: Vec<(String, bool)> = [
            ("subject.example", true),
            ("*.example.com", true),
            ("", false),
            ("bad..example", false),
            ("-bad.example", false),
            ("bad-.example", false),
            ("bad.example.", false),
            ("bad name.example", false),
            ("bad\0.example", false),
            ("é.example", false),
            ("sub.*.example", false),
            ("partial*.example", false),
        ]
        .into_iter()
        .map(|(name, valid)| (String::from(name), valid))
        .collect();
        cases.push((alloc::format!("{}.example", "a".repeat(63)), true));
        cases.push((alloc::format!("{}.example", "a".repeat(64)), false));
        for (last, valid) in [(61, true), (62, false)] {
            cases.push((
                alloc::format!(
                    "{}.{}.{}.{}",
                    "a".repeat(63),
                    "b".repeat(63),
                    "c".repeat(63),
                    "d".repeat(last)
                ),
                valid,
            ));
        }
        for (name, valid) in cases {
            for names in [
                alloc::vec![name.as_str()],
                alloc::vec!["control.example", name.as_str()],
                alloc::vec![name.as_str(), "control.example"],
            ] {
                for issued in [false, true] {
                    let pp = params("Named subject", &names, false);
                    let result = if issued {
                        issue(&pp, subject_key.spki(), &root, &root_key, &mut r)
                    } else {
                        self_signed(&pp, &subject_key, &mut r)
                    };
                    if valid {
                        let der = result.unwrap();
                        let cert = Certificate::parse(&der).unwrap();
                        assert_eq!(cert.dns_names(), names);
                        let signer = if issued { &root_key } else { &subject_key };
                        check_signature(&cert, signer.spki(), &opts()).unwrap();
                    } else {
                        let error = result.unwrap_err();
                        assert_eq!(error.kind(), ErrorKind::InvalidConfig);
                        assert_eq!(
                            error.context(),
                            "invalid DNS name in certificate parameters"
                        );
                    }
                }
            }
        }
    }

    /// REQ-X509-069: X.680's BMPString repertoire excludes surrogate cells and
    /// FFFE/FFFF. Signed SAN fixtures exercise both EDI fields and list orders.
    #[test]
    fn edi_party_name_bmpstrings_require_the_asn1_repertoire() {
        // X.680 (2015) section 41.15 defines the BMP subset; Rust's Unicode
        // scalar conversion independently classifies surrogate cells.
        for code in 0..=u16::MAX {
            let mut string = Vec::new();
            push_tlv(&mut string, 0x1e, &code.to_be_bytes());
            let expected = char::from_u32(u32::from(code)).is_some() && code < 0xfffe;
            assert_eq!(
                check_directory_string(&string).is_ok(),
                expected,
                "{code:04x}"
            );
        }
        let cases: Vec<_> = [
            (0x0000u16, true),
            (0x0041, true),
            (0xd7ff, true),
            (0xe000, true),
            (0xfffd, true),
            (0xd800, false),
            (0xdbff, false),
            (0xdc00, false),
            (0xdfff, false),
            (0xfffe, false),
            (0xffff, false),
        ]
        .into_iter()
        .map(|(code, accepted)| (code.to_be_bytes().to_vec(), accepted))
        .collect();
        assert_signed_edi_strings(0x1e, &cases, "invalid DirectoryString BMPString character");
        // A UTF-16 surrogate pair is also outside BMPString's repertoire.
        let mut pair = Vec::new();
        push_tlv(&mut pair, 0x1e, &[0xd8, 0, 0xdc, 0]);
        assert!(check_directory_string(&pair).is_err());
    }

    /// REQ-X509-070: Unicode section 3.9.1/D90 excludes surrogate code points
    /// and units greater than U+10FFFF; supplementary scalar values remain usable.
    #[test]
    fn edi_party_name_universalstrings_require_unicode_scalars() {
        for code in 0u32..=0x110000 {
            let bytes = code.to_be_bytes();
            let string = [0x1c, 4, bytes[0], bytes[1], bytes[2], bytes[3]];
            assert_eq!(
                check_directory_string(&string).is_ok(),
                char::from_u32(code).is_some(),
                "{code:08x}"
            );
        }
        let mut cases: Vec<_> = [
            (0x0000u32, true),
            (0x004d, true),
            (0x0430, true),
            (0x4e8c, true),
            (0xd7ff, true),
            (0xe000, true),
            (0xfffe, true),
            (0xffff, true),
            (0x10000, true),
            (0x10302, true),
            (0x10fffd, true),
            (0x10ffff, true),
            (0xd800, false),
            (0xdbff, false),
            (0xdc00, false),
            (0xdfff, false),
            (0x110000, false),
            (0x110001, false),
            (0x7fffffff, false),
            (0x80000000, false),
            (u32::MAX, false),
        ]
        .into_iter()
        .map(|(code, accepted)| (code.to_be_bytes().to_vec(), accepted))
        .collect();
        // Unicode Table 3-4 gives this sequence in UTF-32.
        cases.push((
            [0x004du32, 0x0430, 0x4e8c, 0x10302]
                .into_iter()
                .flat_map(u32::to_be_bytes)
                .collect(),
            true,
        ));
        assert_signed_edi_strings(
            0x1c,
            &cases,
            "invalid DirectoryString UniversalString code point",
        );
    }

    fn assert_signed_edi_strings(tag: u8, cases: &[(Vec<u8>, bool)], context: &str) {
        let mut r = rng();
        let key = SigningKey::generate(KeyKind::EcdsaP256, &mut r).unwrap();
        let issuer = self_signed(&params("EDI issuer", &[], true), &key, &mut r).unwrap();
        let ca = Certificate::parse(&issuer).unwrap();
        let public = ca.subject_public_key().unwrap();
        let identifier = key_identifier(ca.spki).unwrap();
        let field = |wrapper, string_tag, value: &[u8]| {
            let mut string = Vec::new();
            push_tlv(&mut string, string_tag, value);
            let mut encoded = Vec::new();
            push_tlv(&mut encoded, wrapper, &string);
            encoded
        };
        let mut control = Vec::new();
        push_tlv(&mut control, T_GN_DNS, b"control.example");
        let padding: &[u8] = if tag == 0x1e {
            &[0, 0x41]
        } else {
            &[0, 0, 0, 0x41]
        };
        for (bytes, accepted) in cases {
            for value in [
                bytes.to_vec(),
                [bytes.as_slice(), padding].concat(),
                [padding, bytes.as_slice()].concat(),
            ] {
                for wrapper in [T_CTX0, T_CTX1] {
                    let mut edi = if wrapper == T_CTX0 {
                        field(T_CTX0, tag, &value)
                    } else {
                        field(T_CTX0, T_UTF8, b"assigner")
                    };
                    edi.extend_from_slice(&field(
                        T_CTX1,
                        if wrapper == T_CTX1 { tag } else { T_UTF8 },
                        if wrapper == T_CTX1 { &value } else { b"party" },
                    ));
                    let mut name = Vec::new();
                    push_tlv(&mut name, 0xa5, &edi);
                    for critical in [false, true] {
                        for names in [
                            [name.clone(), control.clone()].concat(),
                            [control.clone(), name.clone()].concat(),
                        ] {
                            let mut san = Vec::new();
                            push_tlv(&mut san, T_SEQUENCE, &names);
                            let mut extension = Vec::new();
                            push_ext(&mut extension, OID_EXT_SAN, critical, &san);
                            let encoded = build(
                                &params("EDI leaf", &[], false),
                                key.spki(),
                                ca.subject,
                                &identifier,
                                &key,
                                &mut r,
                                &[extension],
                            )
                            .unwrap();
                            let mut certificate = Der::new(&encoded).nested(T_SEQUENCE).unwrap();
                            let tbs = certificate.expect_raw(T_SEQUENCE).unwrap();
                            let scheme =
                                scheme_from_alg(certificate.expect(T_SEQUENCE).unwrap()).unwrap();
                            let signature =
                                whole_bits(certificate.expect(T_BIT_STRING).unwrap()).unwrap();
                            sign::verify(scheme, &public, tbs, signature).unwrap();
                            let result = Certificate::parse(&encoded);
                            if *accepted {
                                let certificate = result.unwrap();
                                assert_eq!(certificate.ext.san, Some(names.as_slice()));
                                check_signature(&certificate, ca.spki, &opts()).unwrap();
                            } else {
                                let error = result.err().unwrap();
                                assert_eq!(error.kind(), ErrorKind::BadCertificate);
                                assert_eq!(error.context(), context);
                            }
                        }
                    }
                }
            }
        }
    }

    /// REQ-X509-068: received KeyUsage omits trailing zero named bits per
    /// RFC 5280 Appendix B; unknown bit positions remain parseable.
    #[test]
    fn received_key_usage_requires_minimal_named_bit_encoding() {
        let mut r = rng();
        let key = SigningKey::generate(KeyKind::EcdsaP256, &mut r).unwrap();
        let original = self_signed(&params("KeyUsage CA", &[], true), &key, &mut r).unwrap();
        let parsed = Certificate::parse(&original).unwrap();
        let scheme = parsed.signature_scheme().unwrap();
        let public = PublicKey::from_spki(key.spki()).unwrap();
        let mut outer = Der::new(&original).nested(T_SEQUENCE).unwrap();
        outer.expect(T_SEQUENCE).unwrap();
        let algorithm = outer.expect_raw(T_SEQUENCE).unwrap();
        let mut fields = Der::new(parsed.tbs).nested(T_SEQUENCE).unwrap();
        let mut required = Vec::new();
        while fields.peek() != Some(T_CTX3) {
            required.extend_from_slice(fields.tlv().unwrap().2);
        }
        let mut extensions = Der::new(fields.expect(T_CTX3).unwrap())
            .nested(T_SEQUENCE)
            .unwrap();
        let mut retained = Vec::new();
        while !extensions.is_empty() {
            let encoded = extensions.expect_raw(T_SEQUENCE).unwrap();
            let mut entry = Der::new(encoded).nested(T_SEQUENCE).unwrap();
            if entry.expect(T_OID).unwrap() != OID_EXT_KU {
                retained.extend_from_slice(encoded);
            }
        }
        let mut cases = alloc::vec![
            (
                key_usage_bits(KU_DIGITAL_SIGNATURE | KU_KEY_CERT_SIGN | KU_CRL_SIGN),
                true
            ),
            (alloc::vec![6, 0, 0x40], true),
            (alloc::vec![0, 0, 1], true),
            (alloc::vec![7, 0, 0, 0x80], true),
            (alloc::vec![0, 0x80], false),
            (alloc::vec![6, 0x80], false),
            (alloc::vec![0, 0, 0x40], false),
            (alloc::vec![7, 0x80, 0], false),
            (alloc::vec![0, 0x80, 1, 0], false),
            (alloc::vec![0, 0x80, 0, 0, 0], false),
        ];
        for unused in 0u8..8 {
            cases.push((alloc::vec![unused, 1u8 << unused], true));
            if unused != 7 {
                cases.push((alloc::vec![unused, 1u8 << (unused + 1)], false));
            }
        }
        for (usage, accepted) in cases {
            for critical in [false, true] {
                let mut value = Vec::new();
                push_tlv(&mut value, T_BIT_STRING, &usage);
                let mut extension = Vec::new();
                push_ext(&mut extension, OID_EXT_KU, critical, &value);
                for entries in [
                    [extension.clone(), retained.clone()].concat(),
                    [retained.clone(), extension.clone()].concat(),
                ] {
                    let mut list = Vec::new();
                    push_tlv(&mut list, T_SEQUENCE, &entries);
                    let mut body = required.clone();
                    push_tlv(&mut body, T_CTX3, &list);
                    let mut tbs = Vec::new();
                    push_tlv(&mut tbs, T_SEQUENCE, &body);
                    let signature = key.sign(scheme, &tbs, &mut r).unwrap();
                    sign::verify(scheme, &public, &tbs, &signature).unwrap();
                    let mut content = tbs;
                    content.extend_from_slice(algorithm);
                    let mut bits = alloc::vec![0];
                    bits.extend_from_slice(&signature);
                    push_tlv(&mut content, T_BIT_STRING, &bits);
                    let mut encoded = Vec::new();
                    push_tlv(&mut encoded, T_SEQUENCE, &content);
                    let result = Certificate::parse(&encoded);
                    if accepted {
                        let cert = result.unwrap();
                        assert!(cert.ext.key_usage.is_some());
                        check_signature(&cert, key.spki(), &opts()).unwrap();
                    } else {
                        let error = result.err().unwrap();
                        assert_eq!(error.kind(), ErrorKind::BadCertificate);
                        assert_eq!(error.context(), "keyUsage has trailing zero named bits");
                    }
                }
            }
        }
    }

    /// REQ-X509-053: empty subjects require a critical SAN on received certificates,
    /// while named subjects can omit SANs or use either criticality.
    #[test]
    fn empty_certificate_subjects_require_a_critical_san() {
        let mut r = rng();
        let key = SigningKey::generate(KeyKind::EcdsaP256, &mut r).unwrap();
        let original = self_signed(&params("Named", &[], false), &key, &mut r).unwrap();
        let parsed = Certificate::parse(&original).unwrap();
        let scheme = parsed.signature_scheme().unwrap();
        let public = PublicKey::from_spki(key.spki()).unwrap();
        let mut outer = Der::new(&original).nested(T_SEQUENCE).unwrap();
        outer.expect(T_SEQUENCE).unwrap();
        let algorithm = outer.expect_raw(T_SEQUENCE).unwrap();
        let mut fields = Der::new(parsed.tbs).nested(T_SEQUENCE).unwrap();
        let mut required = Vec::new();
        while fields.peek() != Some(T_CTX3) {
            required.push(fields.tlv().unwrap().2);
        }
        let retained = Der::new(fields.expect(T_CTX3).unwrap())
            .expect(T_SEQUENCE)
            .unwrap();
        let mut dns = Vec::new();
        push_tlv(&mut dns, T_GN_DNS, b"subject.example");
        let mut ip = Vec::new();
        push_tlv(&mut ip, T_GN_IP, &[192, 0, 2, 1]);
        let mut other = Vec::new();
        push_tlv(
            &mut other,
            T_CTX0,
            &[T_OID, 2, 0x2a, 3, T_CTX0, 2, T_NULL, 0],
        );
        for empty_subject in [false, true] {
            for names in [&dns, &ip, &other] {
                // Absent SAN, omitted critical flag, explicit FALSE, and TRUE.
                for critical in [None, Some(None), Some(Some(false)), Some(Some(true))] {
                    let mut extensions = retained.to_vec();
                    if let Some(flag) = critical {
                        let mut value = Vec::new();
                        push_tlv(&mut value, T_SEQUENCE, names);
                        let mut body = Vec::new();
                        push_tlv(&mut body, T_OID, OID_EXT_SAN);
                        if let Some(flag) = flag {
                            push_tlv(&mut body, T_BOOLEAN, &[if flag { 0xff } else { 0 }]);
                        }
                        push_tlv(&mut body, T_OCTET_STRING, &value);
                        push_tlv(&mut extensions, T_SEQUENCE, &body);
                    }
                    let mut body = Vec::new();
                    for (i, field) in required.iter().enumerate() {
                        body.extend_from_slice(if empty_subject && i == 5 {
                            &[T_SEQUENCE, 0]
                        } else {
                            field
                        });
                    }
                    let mut sequence = Vec::new();
                    push_tlv(&mut sequence, T_SEQUENCE, &extensions);
                    push_tlv(&mut body, T_CTX3, &sequence);
                    let mut tbs = Vec::new();
                    push_tlv(&mut tbs, T_SEQUENCE, &body);
                    let signature = key.sign(scheme, &tbs, &mut r).unwrap();
                    sign::verify(scheme, &public, &tbs, &signature).unwrap();
                    let mut content = tbs;
                    content.extend_from_slice(algorithm);
                    let mut bits = alloc::vec![0];
                    bits.extend_from_slice(&signature);
                    push_tlv(&mut content, T_BIT_STRING, &bits);
                    let mut encoded = Vec::new();
                    push_tlv(&mut encoded, T_SEQUENCE, &content);
                    let result = Certificate::parse(&encoded);
                    if !empty_subject || critical == Some(Some(true)) {
                        let cert = result.unwrap();
                        assert_eq!(cert.ext.san.is_some(), critical.is_some());
                        assert_eq!(cert.ext.san_critical, critical == Some(Some(true)));
                    } else {
                        let error = result.err().unwrap();
                        assert_eq!(error.kind(), ErrorKind::BadCertificate);
                        assert_eq!(
                            error.context(),
                            "empty certificate subject requires a critical subjectAltName"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn certificate_issuance_requires_a_subject_or_alternative_name() {
        let mut r = rng();
        let root_key = SigningKey::generate(KeyKind::EcdsaP256, &mut r).unwrap();
        let root = self_signed(&params("Root", &[], true), &root_key, &mut r).unwrap();
        let subject_key = SigningKey::generate(KeyKind::EcdsaP256, &mut r).unwrap();
        let v4 = [IpAddr::V4([192, 0, 2, 1])];
        let mut v6_octets = [0; 16];
        v6_octets[15] = 1;
        let v6 = [IpAddr::V6(v6_octets)];
        for name in ["", "Named subject"] {
            for dns in [&[][..], &["subject.example"][..]] {
                for ips in [&[][..], &v4[..], &v6[..]] {
                    let mut pp = params(name, dns, false);
                    pp.ip_addresses = ips;
                    let result = issue(&pp, subject_key.spki(), &root, &root_key, &mut r);
                    if name.is_empty() && dns.is_empty() && ips.is_empty() {
                        let error = result.unwrap_err();
                        assert_eq!(error.kind(), ErrorKind::InvalidConfig);
                        assert_eq!(
                            error.context(),
                            "a certificate needs a subject name or an alternative name"
                        );
                    } else {
                        let der = result.unwrap();
                        let cert = Certificate::parse(&der).unwrap();
                        assert_eq!(
                            Der::new(cert.subject)
                                .expect(T_SEQUENCE)
                                .unwrap()
                                .is_empty(),
                            name.is_empty()
                        );
                        check_signature(&cert, root_key.spki(), &opts()).unwrap();
                        assert_eq!(cert.ext.san.is_some(), !dns.is_empty() || !ips.is_empty());
                        if !dns.is_empty() {
                            verify_name(&der, &ServerName::parse("subject.example").unwrap())
                                .unwrap();
                        }
                        for ip in ips {
                            verify_name(&der, &ServerName::Ip(*ip)).unwrap();
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn certificate_issuance_requires_ca_for_path_length() {
        let mut r = rng();
        let root_key = SigningKey::generate(KeyKind::EcdsaP256, &mut r).unwrap();
        let root = self_signed(&params("Root", &[], true), &root_key, &mut r).unwrap();
        let subject_key = SigningKey::generate(KeyKind::EcdsaP256, &mut r).unwrap();
        for ca in [false, true] {
            for issued in [false, true] {
                for path_len in [None, Some(0), Some(127), Some(128), Some(255)] {
                    let mut pp = params("Subject", &["subject.example"], ca);
                    pp.path_len = path_len;
                    let result = if issued {
                        issue(&pp, subject_key.spki(), &root, &root_key, &mut r)
                    } else {
                        self_signed(&pp, &subject_key, &mut r)
                    };
                    if !ca && path_len.is_some() {
                        let error = result.unwrap_err();
                        assert_eq!(error.kind(), ErrorKind::InvalidConfig);
                        assert_eq!(error.context(), "certificate path length requires a CA");
                    } else {
                        let der = result.unwrap();
                        let cert = Certificate::parse(&der).unwrap();
                        assert_eq!(cert.ext.basic, Some((ca, path_len.map(u64::from))));
                        let signer = if issued { &root_key } else { &subject_key };
                        check_signature(&cert, signer.spki(), &opts()).unwrap();
                    }
                }
            }
        }
    }

    /// REQ-X509-065: signed reversed intervals fail during parsing while equal
    /// endpoints and increasing intervals retain inclusive validity semantics.
    #[test]
    fn received_certificates_refuse_reversed_validity_intervals() {
        let mut r = rng();
        for kind in [KeyKind::Ed25519, KeyKind::EcdsaP256, KeyKind::MlDsa65] {
            let key = SigningKey::generate(kind, &mut r).unwrap();
            for ca in [false, true] {
                let mut pp = params("Subject", &["subject.example"], ca);
                pp.not_before = NOW;
                pp.not_after = NOW + 10;
                let original = self_signed(&pp, &key, &mut r).unwrap();
                let mut from = Vec::new();
                encode_time(&mut from, NOW + 10).unwrap();
                for end in [NOW - 1, NOW, NOW + 1] {
                    let mut to = Vec::new();
                    encode_time(&mut to, end).unwrap();
                    let der = resign(&original, &key, &from, &to);
                    // Establish that rejection is independent of signature validity.
                    let mut outer = Der::new(&der);
                    let mut cert = outer.nested(T_SEQUENCE).unwrap();
                    let tbs = cert.expect_raw(T_SEQUENCE).unwrap();
                    let scheme = scheme_from_alg(cert.expect(T_SEQUENCE).unwrap()).unwrap();
                    let signature = whole_bits(cert.expect(T_BIT_STRING).unwrap()).unwrap();
                    sign::verify(
                        scheme,
                        &PublicKey::from_spki(key.spki()).unwrap(),
                        tbs,
                        signature,
                    )
                    .unwrap();
                    let result = Certificate::parse(&der);
                    if end < NOW {
                        let error = result.err().unwrap();
                        assert_eq!(error.kind(), ErrorKind::BadCertificate);
                        assert_eq!(
                            error.context(),
                            "certificate validity ends before it begins"
                        );
                    } else {
                        let parsed = result.unwrap();
                        assert_eq!(parsed.not_before(), NOW);
                        assert_eq!(parsed.not_after(), end);
                        parsed.check_validity(NOW).unwrap();
                        parsed.check_validity(end).unwrap();
                        assert_eq!(
                            parsed.check_validity(NOW - 1).unwrap_err().kind(),
                            ErrorKind::CertificateExpired
                        );
                        assert_eq!(
                            parsed.check_validity(end + 1).unwrap_err().kind(),
                            ErrorKind::CertificateExpired
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn certificate_issuance_refuses_reversed_validity_intervals() {
        let mut r = rng();
        let root_key = SigningKey::generate(KeyKind::EcdsaP256, &mut r).unwrap();
        let root = self_signed(&params("Root", &[], true), &root_key, &mut r).unwrap();
        let subject_key = SigningKey::generate(KeyKind::EcdsaP256, &mut r).unwrap();
        for ca in [false, true] {
            for issued in [false, true] {
                for end in [NOW - 1, NOW, NOW + 1] {
                    let mut pp = params("Subject", &["subject.example"], ca);
                    pp.not_before = NOW;
                    pp.not_after = end;
                    let result = if issued {
                        issue(&pp, subject_key.spki(), &root, &root_key, &mut r)
                    } else {
                        self_signed(&pp, &subject_key, &mut r)
                    };
                    if end < NOW {
                        let error = result.unwrap_err();
                        assert_eq!(error.kind(), ErrorKind::InvalidConfig);
                        assert_eq!(
                            error.context(),
                            "certificate validity ends before it begins"
                        );
                    } else {
                        let der = result.unwrap();
                        let cert = Certificate::parse(&der).unwrap();
                        assert_eq!(cert.not_before(), NOW);
                        assert_eq!(cert.not_after(), end);
                        let signer = if issued { &root_key } else { &subject_key };
                        check_signature(&cert, signer.spki(), &opts()).unwrap();
                        cert.check_validity(NOW).unwrap();
                        cert.check_validity(end).unwrap();
                        assert_eq!(
                            cert.check_validity(NOW - 1).unwrap_err().kind(),
                            ErrorKind::CertificateExpired
                        );
                        assert_eq!(
                            cert.check_validity(end + 1).unwrap_err().kind(),
                            ErrorKind::CertificateExpired
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn issuance_requires_a_named_issuer_certificate() {
        let mut r = rng();
        let root_key = SigningKey::generate(KeyKind::EcdsaP256, &mut r).unwrap();
        let root = self_signed(&params("Root", &[], true), &root_key, &mut r).unwrap();
        let issuer_key = SigningKey::generate(KeyKind::EcdsaP256, &mut r).unwrap();
        let leaf_key = SigningKey::generate(KeyKind::EcdsaP256, &mut r).unwrap();
        for cn in ["", "Named issuer"] {
            let issuer = issue(
                &params(cn, &["issuer.example"], true),
                issuer_key.spki(),
                &root,
                &root_key,
                &mut r,
            )
            .unwrap();
            let parsed = Certificate::parse(&issuer).unwrap();
            assert_eq!(
                Der::new(parsed.subject)
                    .expect(T_SEQUENCE)
                    .unwrap()
                    .is_empty(),
                cn.is_empty()
            );
            let result = issue(
                &params("", &["leaf.example"], false),
                leaf_key.spki(),
                &issuer,
                &issuer_key,
                &mut r,
            );
            if cn.is_empty() {
                let error = result.unwrap_err();
                assert_eq!(error.kind(), ErrorKind::InvalidConfig);
                assert_eq!(error.context(), "issuer certificate subject name is empty");
            } else {
                let der = result.unwrap();
                let leaf = Certificate::parse(&der).unwrap();
                assert_eq!(leaf.issuer, parsed.subject);
                assert!(Der::new(leaf.subject)
                    .expect(T_SEQUENCE)
                    .unwrap()
                    .is_empty());
                assert_eq!(leaf.dns_names(), ["leaf.example"]);
            }
        }
    }

    #[test]
    fn self_signed_issuance_requires_a_named_issuer() {
        let mut r = rng();
        let key = SigningKey::generate(KeyKind::EcdsaP256, &mut r).unwrap();
        for ca in [false, true] {
            for dns in [&[][..], &["server.example"][..]] {
                let error = self_signed(&params("", dns, ca), &key, &mut r).unwrap_err();
                assert_eq!(error.kind(), ErrorKind::InvalidConfig);
                assert_eq!(error.context(), "self-signed issuer name is empty");
                let good = self_signed(&params("Named issuer", dns, ca), &key, &mut r).unwrap();
                let cert = Certificate::parse(&good).unwrap();
                assert_eq!(cert.issuer, cert.subject);
                assert!(!Der::new(cert.issuer).expect(T_SEQUENCE).unwrap().is_empty());
            }
        }
        let ca = self_signed(&params("CA", &[], true), &key, &mut r).unwrap();
        let leaf_key = SigningKey::generate(KeyKind::EcdsaP256, &mut r).unwrap();
        let leaf = issue(
            &params("", &["server.example"], false),
            leaf_key.spki(),
            &ca,
            &key,
            &mut r,
        )
        .unwrap();
        let leaf = Certificate::parse(&leaf).unwrap();
        assert!(Der::new(leaf.subject)
            .expect(T_SEQUENCE)
            .unwrap()
            .is_empty());
        assert_eq!(leaf.dns_names(), ["server.example"]);
    }

    #[test]
    fn certificate_names_require_complete_ordered_rdn_attributes() {
        let mut r = rng();
        let key = SigningKey::generate(KeyKind::EcdsaP256, &mut r).unwrap();
        let root = self_signed(&params("Root", &[], true), &key, &mut r).unwrap();
        let original = issue(
            &params("", &["subject.example"], false),
            key.spki(),
            &root,
            &key,
            &mut r,
        )
        .unwrap();
        let parsed = Certificate::parse(&original).unwrap();
        let mut outer = Der::new(&original).nested(T_SEQUENCE).unwrap();
        outer.expect(T_SEQUENCE).unwrap();
        let algorithm = outer.expect_raw(T_SEQUENCE).unwrap();
        let mut tbs_fields = Der::new(parsed.tbs).nested(T_SEQUENCE).unwrap();
        let mut fields = Vec::new();
        while !tbs_fields.is_empty() {
            fields.push(tbs_fields.tlv().unwrap().2);
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
            push_tlv(&mut rdn, T_SET, attributes);
            let mut out = Vec::new();
            push_tlv(&mut out, T_SEQUENCE, &rdn);
            out
        };
        let a = attribute(&[0x2a, 3], &[T_NULL, 0]);
        let b = attribute(&[0x2a, 4], &[T_NULL, 0]);
        let mut cases = alloc::vec![
            (encode_name("Named fixture"), true),
            (encode_name("É fixture"), true),
            (alloc::vec![T_SEQUENCE, 0], true),
            (name(&a), true),
            (name(&attribute(&[0x2a, 3], &[0x9f, 31, 0])), true),
            (name(&[a.clone(), b.clone()].concat()), true),
            (name(&[b, a.clone()].concat()), false),
            (name(&[]), false),
            (alloc::vec![T_SEQUENCE, 2, T_SEQUENCE, 0], false),
            (name(&[T_SEQUENCE, 0]), false),
            (name(&[T_SEQUENCE, 2, T_NULL, 0]), false),
        ];
        for oid in [&[][..], &[0x81][..], &[0x2a, 0x80, 0][..]] {
            cases.push((name(&attribute(oid, &[T_NULL, 0])), false));
        }
        for value in [
            &[][..],
            &[T_NULL][..],
            &[T_NULL, 0, T_NULL, 0][..],
            &[0, 0][..],
        ] {
            cases.push((name(&attribute(&[0x2a, 3], value)), false));
        }
        let mut late_bad_attribute = a;
        late_bad_attribute.extend_from_slice(&attribute(&[0x2a, 4], &[T_NULL]));
        cases.push((name(&late_bad_attribute), false));
        for (replacement, valid) in cases {
            for issuer in [false, true] {
                let index = if issuer { 3 } else { 5 };
                let mut body = Vec::new();
                for (i, field) in fields.iter().enumerate() {
                    body.extend_from_slice(if i == index { &replacement } else { field });
                }
                let mut tbs = Vec::new();
                push_tlv(&mut tbs, T_SEQUENCE, &body);
                let signature = key
                    .sign(parsed.signature_scheme().unwrap(), &tbs, &mut r)
                    .unwrap();
                let mut content = tbs;
                content.extend_from_slice(algorithm);
                let mut bits = alloc::vec![0];
                bits.extend_from_slice(&signature);
                push_tlv(&mut content, T_BIT_STRING, &bits);
                let mut encoded = Vec::new();
                push_tlv(&mut encoded, T_SEQUENCE, &content);
                let result = Certificate::parse(&encoded);
                if valid && !(issuer && replacement == [T_SEQUENCE, 0]) {
                    let cert = result.unwrap();
                    assert_eq!(if issuer { cert.issuer } else { cert.subject }, replacement);
                    check_signature(&cert, key.spki(), &opts()).unwrap();
                } else {
                    assert_eq!(result.unwrap_err().kind(), ErrorKind::BadCertificate);
                }
            }
        }
    }

    #[test]
    fn certificate_issuer_names_must_be_nonempty() {
        let mut r = rng();
        let key = SigningKey::generate(KeyKind::EcdsaP256, &mut r).unwrap();
        let original = self_signed(&params("Issuer fixture", &[], false), &key, &mut r).unwrap();
        let parsed = Certificate::parse(&original).unwrap();
        let mut outer = Der::new(&original).nested(T_SEQUENCE).unwrap();
        outer.expect(T_SEQUENCE).unwrap();
        let algorithm = outer.expect_raw(T_SEQUENCE).unwrap();
        let mut fields = Der::new(parsed.tbs).nested(T_SEQUENCE).unwrap();
        let mut prefix = Vec::new();
        for _ in 0..3 {
            prefix.extend_from_slice(fields.tlv().unwrap().2);
        }
        let original_issuer = fields.expect_raw(T_SEQUENCE).unwrap();
        let mut tail = Vec::new();
        while !fields.is_empty() {
            tail.extend_from_slice(fields.tlv().unwrap().2);
        }
        for issuer in [original_issuer, &[T_SEQUENCE, 0][..]] {
            let mut body = prefix.clone();
            body.extend_from_slice(issuer);
            body.extend_from_slice(&tail);
            let mut tbs = Vec::new();
            push_tlv(&mut tbs, T_SEQUENCE, &body);
            let signature = key
                .sign(parsed.signature_scheme().unwrap(), &tbs, &mut r)
                .unwrap();
            let mut content = tbs;
            content.extend_from_slice(algorithm);
            let mut bits = alloc::vec![0];
            bits.extend_from_slice(&signature);
            push_tlv(&mut content, T_BIT_STRING, &bits);
            let mut der = Vec::new();
            push_tlv(&mut der, T_SEQUENCE, &content);
            if issuer == original_issuer {
                assert_eq!(Certificate::parse(&der).unwrap().issuer, issuer);
            } else {
                let error = Certificate::parse(&der).unwrap_err();
                assert_eq!(error.kind(), ErrorKind::BadCertificate);
                assert_eq!(error.context(), "empty certificate issuer name");
            }
        }
    }

    /// REQ-X509-013: issuer-signed certificates reject redundant positive
    /// and negative sign octets, retaining necessary sign octets and bounds.
    #[test]
    fn serial_numbers_require_minimal_integer_encoding() {
        let mut r = rng();
        let key = SigningKey::generate(KeyKind::EcdsaP256, &mut r).unwrap();
        let original = self_signed(&params("Serial fixture", &[], false), &key, &mut r).unwrap();
        let parsed = Certificate::parse(&original).unwrap();
        let mut cert = Der::new(&original).nested(T_SEQUENCE).unwrap();
        cert.expect(T_SEQUENCE).unwrap();
        let algorithm = cert.expect_raw(T_SEQUENCE).unwrap();
        let mut fields = Der::new(parsed.tbs).nested(T_SEQUENCE).unwrap();
        let version = fields.expect_raw(T_CTX0).unwrap();
        fields.expect(T_INTEGER).unwrap();
        let mut tail = Vec::new();
        while !fields.is_empty() {
            tail.extend_from_slice(fields.tlv().unwrap().2);
        }
        for (serial, accepted) in [
            (alloc::vec![1], true),
            (alloc::vec![0x7f], true),
            (alloc::vec![0, 0x80], true),
            (alloc::vec![0xff, 0x7f], true),
            // Existing compatibility for canonical zero and negative values.
            (alloc::vec![0], true),
            (alloc::vec![0xff], true),
            (alloc::vec![0, 1], false),
            (alloc::vec![0, 0], false),
            (alloc::vec![0, 0x7f], false),
            (alloc::vec![0xff, 0xff], false),
            (alloc::vec![0xff, 0x80], false),
            (alloc::vec![0, 0, 0x80], false),
            (Vec::new(), false),
            (alloc::vec![1; 22], false),
        ] {
            let mut body = version.to_vec();
            push_tlv(&mut body, T_INTEGER, &serial);
            body.extend_from_slice(&tail);
            let mut tbs = Vec::new();
            push_tlv(&mut tbs, T_SEQUENCE, &body);
            let signature = key
                .sign(parsed.signature_scheme().unwrap(), &tbs, &mut r)
                .unwrap();
            let mut content = tbs;
            content.extend_from_slice(algorithm);
            let mut bits = alloc::vec![0];
            bits.extend_from_slice(&signature);
            push_tlv(&mut content, T_BIT_STRING, &bits);
            let mut encoded = Vec::new();
            push_tlv(&mut encoded, T_SEQUENCE, &content);
            let result = Certificate::parse(&encoded);
            if accepted {
                assert_eq!(result.unwrap().serial(), serial.as_slice());
            } else {
                assert_eq!(result.unwrap_err().kind(), ErrorKind::BadCertificate);
            }
        }
    }

    #[test]
    fn certificate_versions_require_minimal_integer_encoding() {
        let mut r = rng();
        let key = SigningKey::generate(KeyKind::EcdsaP256, &mut r).unwrap();
        let original = self_signed(&params("Version fixture", &[], false), &key, &mut r).unwrap();
        let parsed = Certificate::parse(&original).unwrap();
        let mut outer = Der::new(&original).nested(T_SEQUENCE).unwrap();
        outer.expect(T_SEQUENCE).unwrap();
        let algorithm = outer.expect_raw(T_SEQUENCE).unwrap();
        let mut fields = Der::new(parsed.tbs).nested(T_SEQUENCE).unwrap();
        fields.expect(T_CTX0).unwrap();
        let mut required = Vec::new();
        for _ in 0..6 {
            required.extend_from_slice(fields.tlv().unwrap().2);
        }
        for version in [0, 1, 2] {
            for redundant in [false, true] {
                let bytes = if redundant {
                    alloc::vec![0, version]
                } else {
                    alloc::vec![version]
                };
                let mut integer = Vec::new();
                push_tlv(&mut integer, T_INTEGER, &bytes);
                let mut body = Vec::new();
                push_tlv(&mut body, T_CTX0, &integer);
                body.extend_from_slice(&required);
                let mut tbs = Vec::new();
                push_tlv(&mut tbs, T_SEQUENCE, &body);
                let signature = key
                    .sign(parsed.signature_scheme().unwrap(), &tbs, &mut r)
                    .unwrap();
                let mut content = tbs;
                content.extend_from_slice(algorithm);
                let mut bits = alloc::vec![0];
                bits.extend_from_slice(&signature);
                push_tlv(&mut content, T_BIT_STRING, &bits);
                let mut der = Vec::new();
                push_tlv(&mut der, T_SEQUENCE, &content);
                let result = Certificate::parse(&der);
                if redundant {
                    let error = result.unwrap_err();
                    assert_eq!(error.kind(), ErrorKind::BadCertificate);
                    assert_eq!(error.context(), "nonminimal non-negative INTEGER");
                } else if version == 0 {
                    // REQ-X509-077: the DEFAULT written out is not DER.
                    assert_eq!(
                        result.unwrap_err().context(),
                        "explicitly encoded default version"
                    );
                } else {
                    check_signature(&result.unwrap(), key.spki(), &opts()).unwrap();
                }
            }
        }
    }

    /// REQ-X509-011: implicit and explicit v1 reject either unique ID;
    /// v2/v3 accept them, and v1 without either remains parseable.
    /// REQ-X509-012: both unique-ID fields reject malformed BIT STRING contents.
    #[test]
    fn unique_identifiers_require_v2_or_v3() {
        let mut r = rng();
        let key = SigningKey::generate(KeyKind::EcdsaP256, &mut r).unwrap();
        let original = self_signed(&params("Version fixture", &[], false), &key, &mut r).unwrap();
        let parsed = Certificate::parse(&original).unwrap();
        let mut cert = Der::new(&original).nested(T_SEQUENCE).unwrap();
        cert.expect(T_SEQUENCE).unwrap();
        let algorithm = cert.expect_raw(T_SEQUENCE).unwrap();
        let mut fields = Der::new(parsed.tbs).nested(T_SEQUENCE).unwrap();
        fields.expect(T_CTX0).unwrap();
        let mut required = Vec::new();
        for _ in 0..6 {
            required.extend_from_slice(fields.tlv().unwrap().2);
        }
        fields.expect(T_CTX3).unwrap();
        fields.finish().unwrap();
        for (uid, valid) in [
            (&[7, 0x80][..], true),
            (&[0, 0xff][..], true),
            (&[0][..], true),
            (&[][..], false),
            (&[8, 0][..], false),
            (&[1][..], false),
            (&[7, 0x81][..], false),
            (&[1, 0xff][..], false),
        ] {
            for version in [None, Some(0), Some(1), Some(2)] {
                for (issuer, subject) in
                    [(false, false), (true, false), (false, true), (true, true)]
                {
                    let mut body = Vec::new();
                    if let Some(version) = version {
                        let mut encoded = Vec::new();
                        push_tlv(&mut encoded, T_INTEGER, &[version]);
                        push_tlv(&mut body, T_CTX0, &encoded);
                    }
                    body.extend_from_slice(&required);
                    if issuer {
                        push_tlv(&mut body, T_ISSUER_UID, uid);
                    }
                    if subject {
                        push_tlv(&mut body, T_SUBJECT_UID, uid);
                    }
                    let mut tbs = Vec::new();
                    push_tlv(&mut tbs, T_SEQUENCE, &body);
                    let signature = key
                        .sign(parsed.signature_scheme().unwrap(), &tbs, &mut r)
                        .unwrap();
                    let mut content = tbs;
                    content.extend_from_slice(algorithm);
                    let mut bits = alloc::vec![0];
                    bits.extend_from_slice(&signature);
                    push_tlv(&mut content, T_BIT_STRING, &bits);
                    let mut encoded = Vec::new();
                    push_tlv(&mut encoded, T_SEQUENCE, &content);
                    let result = Certificate::parse(&encoded);
                    // An explicit v1 is not DER at all (REQ-X509-077).
                    let allowed = version != Some(0)
                        && (!(issuer || subject) || (valid && matches!(version, Some(1 | 2))));
                    assert_eq!(
                        result.is_ok(),
                        allowed,
                        "version={version:?}, issuer={issuer}, subject={subject}, uid={uid:?}"
                    );
                }
            }
        }
    }

    fn rng() -> ic_drbg::Rng {
        ic_drbg::Rng::from_os().unwrap()
    }

    fn params<'a>(cn: &'a str, dns: &'a [&'a str], ca: bool) -> CertificateParams<'a> {
        CertificateParams {
            subject_cn: cn,
            dns_names: dns,
            ip_addresses: &[],
            not_before: NOW - DAY,
            not_after: NOW + 365 * DAY,
            is_ca: ca,
            path_len: None,
            usage: if ca { &[] } else { &[Usage::ServerAuth] },
            serial: [0x42; 16],
        }
    }

    const ALL: &[SignatureScheme] = sign::VERIFY_SCHEMES;

    fn opts() -> VerifyOptions<'static> {
        VerifyOptions::new(NOW, Usage::ServerAuth, ALL)
    }

    struct Pki {
        root: Vec<u8>,
        root_key: SigningKey,
        int: Vec<u8>,
        int_key: SigningKey,
        leaf: Vec<u8>,
        roots: RootStore,
    }

    fn pki(kinds: [KeyKind; 3]) -> Pki {
        let mut r = rng();
        let root_key = SigningKey::generate(kinds[0], &mut r).unwrap();
        let root = self_signed(&params("Root", &[], true), &root_key, &mut r).unwrap();
        let int_key = SigningKey::generate(kinds[1], &mut r).unwrap();
        let int = issue(
            &params("Int", &[], true),
            int_key.spki(),
            &root,
            &root_key,
            &mut r,
        )
        .unwrap();
        let leaf_key = SigningKey::generate(kinds[2], &mut r).unwrap();
        let leaf = issue(
            &params("leaf", &["leaf.example.com"], false),
            leaf_key.spki(),
            &int,
            &int_key,
            &mut r,
        )
        .unwrap();
        let mut roots = RootStore::new();
        roots.add_der(&root).unwrap();
        Pki {
            root,
            root_key,
            int,
            int_key,
            leaf,
            roots,
        }
    }

    fn err(r: Result<ChainReport>) -> ErrorKind {
        r.unwrap_err().kind()
    }

    #[test]
    fn chains_verify_for_every_key_kind() {
        for &k in KeyKind::ALL {
            let p = pki([k, k, k]);
            let report = verify_both(&p.leaf, &[&p.int], &p.roots, &opts()).unwrap();
            assert_eq!(report.depth, 2, "{k:?}");
            assert_eq!(report.leaf_key, k.id());
            assert_eq!(report.anchor_subject_cn.as_deref(), Some("Root"));
            assert_eq!(report.schemes.len(), 2);
            verify_name(&p.leaf, &ServerName::parse("leaf.example.com").unwrap()).unwrap();
            let c = Certificate::parse(&p.leaf).unwrap();
            assert_eq!(c.common_name(), Some("leaf"));
            assert_eq!(c.dns_names(), ["leaf.example.com"]);
            assert!(!c.is_ca());
            assert!(Certificate::parse(&p.root).unwrap().is_ca());
        }
        let p = pki([KeyKind::MlDsa65, KeyKind::EcdsaP384, KeyKind::Ed25519]);
        let report = verify_both(&p.leaf, &[&p.int], &p.roots, &opts()).unwrap();
        assert_eq!(
            report.schemes,
            [
                SignatureScheme::EcdsaSecp384r1Sha384,
                SignatureScheme::MlDsa65
            ]
        );
        assert_eq!(report.min_classical_bits, 128);
    }

    #[test]
    fn rsa_issuers_sign_with_pss() {
        let mut r = rng();
        let rsa = ic_rsa::generate(2048, &mut r).unwrap();
        let root_key = SigningKey::rsa(rsa).unwrap();
        let root = self_signed(&params("RSA Root", &[], true), &root_key, &mut r).unwrap();
        assert_eq!(
            Certificate::parse(&root)
                .unwrap()
                .signature_scheme()
                .unwrap(),
            SignatureScheme::RsaPssRsaeSha256
        );
        let leaf_key = SigningKey::generate(KeyKind::EcdsaP256, &mut r).unwrap();
        let leaf = issue(
            &params("leaf", &["leaf.example.com"], false),
            leaf_key.spki(),
            &root,
            &root_key,
            &mut r,
        )
        .unwrap();
        let mut roots = RootStore::new();
        roots.add_der(&root).unwrap();
        let report = verify_both(&leaf, &[], &roots, &opts()).unwrap();
        assert_eq!(report.min_classical_bits, 112);
        let mut strict = opts();
        strict.min_rsa_bits = 3072;
        assert_eq!(
            err(verify_both(&leaf, &[], &roots, &strict)),
            ErrorKind::PolicyViolation
        );
    }

    #[test]
    fn validity_is_checked_at_every_level() {
        let p = pki([KeyKind::EcdsaP256; 3]);
        let mut o = opts();
        o.now = NOW + 400 * DAY;
        assert_eq!(
            err(verify_both(&p.leaf, &[&p.int], &p.roots, &o)),
            ErrorKind::CertificateExpired
        );
        o.now = NOW - 2 * DAY;
        assert_eq!(
            err(verify_both(&p.leaf, &[&p.int], &p.roots, &o)),
            ErrorKind::CertificateExpired
        );

        // An expired intermediate over a current leaf.
        let mut r = rng();
        let root_key = SigningKey::generate(KeyKind::EcdsaP256, &mut r).unwrap();
        let root = self_signed(&params("Root", &[], true), &root_key, &mut r).unwrap();
        let int_key = SigningKey::generate(KeyKind::EcdsaP256, &mut r).unwrap();
        let mut ip = params("Int", &[], true);
        ip.not_after = NOW - 1;
        let int = issue(&ip, int_key.spki(), &root, &root_key, &mut r).unwrap();
        let leaf_key = SigningKey::generate(KeyKind::EcdsaP256, &mut r).unwrap();
        let leaf = issue(
            &params("l", &["l.example.com"], false),
            leaf_key.spki(),
            &int,
            &int_key,
            &mut r,
        )
        .unwrap();
        let mut roots = RootStore::new();
        roots.add_der(&root).unwrap();
        assert_eq!(
            err(verify_both(&leaf, &[&int], &roots, &opts())),
            ErrorKind::CertificateExpired
        );
    }

    #[test]
    fn names_come_from_sans_only() {
        let mut r = rng();
        let key = SigningKey::generate(KeyKind::EcdsaP256, &mut r).unwrap();
        let mut pp = params("leaf.example.com", &[], false);
        pp.ip_addresses = &[IpAddr::V4([192, 0, 2, 1])];
        let cert = self_signed(&pp, &key, &mut r).unwrap();
        // The CN matches, but CN is never consulted.
        assert_eq!(
            verify_name(&cert, &ServerName::parse("leaf.example.com").unwrap())
                .unwrap_err()
                .kind(),
            ErrorKind::CertificateNameMismatch
        );
        verify_name(&cert, &ServerName::parse("192.0.2.1").unwrap()).unwrap();
        assert!(verify_name(&cert, &ServerName::parse("192.0.2.2").unwrap()).is_err());

        let wild = self_signed(&params("w", &["*.example.com"], false), &key, &mut r).unwrap();
        verify_name(&wild, &ServerName::parse("api.example.com").unwrap()).unwrap();
        for bad_name in ["example.com", "a.b.example.com", "example.org"] {
            assert_eq!(
                verify_name(&wild, &ServerName::parse(bad_name).unwrap())
                    .unwrap_err()
                    .kind(),
                ErrorKind::CertificateNameMismatch,
                "{bad_name}"
            );
        }
    }

    #[test]
    fn a_leaf_cannot_issue() {
        let mut r = rng();
        let p = pki([KeyKind::EcdsaP256; 3]);
        // A non-CA leaf key used to issue another certificate.
        let leaf_key = SigningKey::generate(KeyKind::EcdsaP256, &mut r).unwrap();
        let fake_ca = issue(
            &params("notca", &["n.example.com"], false),
            leaf_key.spki(),
            &p.int,
            &p.int_key,
            &mut r,
        )
        .unwrap();
        let victim_key = SigningKey::generate(KeyKind::EcdsaP256, &mut r).unwrap();
        let victim = issue(
            &params("v", &["v.example.com"], false),
            victim_key.spki(),
            &fake_ca,
            &leaf_key,
            &mut r,
        )
        .unwrap();
        assert_eq!(
            err(verify_both(&victim, &[&fake_ca, &p.int], &p.roots, &opts())),
            ErrorKind::CertificateUsage
        );
        // And a CA certificate cannot serve as an end entity.
        assert_eq!(
            err(verify_both(&p.int, &[], &p.roots, &opts())),
            ErrorKind::CertificateUsage
        );
    }

    #[test]
    fn path_length_is_enforced() {
        let mut r = rng();
        let root_key = SigningKey::generate(KeyKind::Ed25519, &mut r).unwrap();
        let root = self_signed(&params("Root", &[], true), &root_key, &mut r).unwrap();
        let k1 = SigningKey::generate(KeyKind::Ed25519, &mut r).unwrap();
        let mut p1 = params("Int1", &[], true);
        p1.path_len = Some(0);
        let int1 = issue(&p1, k1.spki(), &root, &root_key, &mut r).unwrap();
        let k2 = SigningKey::generate(KeyKind::Ed25519, &mut r).unwrap();
        let int2 = issue(&params("Int2", &[], true), k2.spki(), &int1, &k1, &mut r).unwrap();
        let lk = SigningKey::generate(KeyKind::Ed25519, &mut r).unwrap();
        let leaf = issue(
            &params("l", &["l.example.com"], false),
            lk.spki(),
            &int2,
            &k2,
            &mut r,
        )
        .unwrap();
        let mut roots = RootStore::new();
        roots.add_der(&root).unwrap();
        assert_eq!(
            err(verify_both(&leaf, &[&int2, &int1], &roots, &opts())),
            ErrorKind::CertificateUsage
        );
        // Directly under Int1 is within pathLen 0.
        let leaf2 = issue(
            &params("l2", &["l2.example.com"], false),
            lk.spki(),
            &int1,
            &k1,
            &mut r,
        )
        .unwrap();
        assert_eq!(
            verify_both(&leaf2, &[&int1], &roots, &opts())
                .unwrap()
                .depth,
            2
        );
        // The depth limit binds too.
        let mut shallow = opts();
        shallow.max_depth = 2;
        assert_eq!(
            err(verify_both(&leaf, &[&int2, &int1], &roots, &shallow)),
            ErrorKind::UnknownCa
        );
    }

    #[test]
    fn a_flipped_signature_byte_is_caught() {
        let p = pki([KeyKind::EcdsaP256; 3]);
        let mut leaf = p.leaf.clone();
        let n = leaf.len();
        leaf[n - 1] ^= 0x01;
        assert_eq!(
            err(verify_both(&leaf, &[&p.int], &p.roots, &opts())),
            ErrorKind::BadCertificate
        );
        let mut int = p.int.clone();
        let n = int.len();
        int[n - 2] ^= 0x10;
        assert_eq!(
            err(verify_both(&p.leaf, &[&int], &p.roots, &opts())),
            ErrorKind::BadCertificate
        );
    }

    fn with_extra(
        extra: Vec<u8>,
        issuer_der: &[u8],
        issuer_key: &SigningKey,
        ca: bool,
    ) -> (Vec<u8>, SigningKey) {
        let mut r = rng();
        let key = SigningKey::generate(KeyKind::EcdsaP256, &mut r).unwrap();
        let issuer = Certificate::parse(issuer_der).unwrap();
        let ki = key_identifier(issuer.spki_der()).unwrap();
        let p = if ca {
            params("X", &[], true)
        } else {
            params("x", &["x.example.com"], false)
        };
        let cert = build(
            &p,
            key.spki(),
            issuer.subject_der(),
            &ki,
            issuer_key,
            &mut r,
            &[extra],
        )
        .unwrap();
        (cert, key)
    }

    /// REQ-X509-045: opaque AKI serial references still obey DER INTEGER
    /// encoding, with and without key IDs, in signed certificates.
    #[test]
    fn authority_key_identifier_serials_require_minimal_integer_encoding() {
        let p = pki([KeyKind::EcdsaP256; 3]);
        let issuer = Certificate::parse(&p.int).unwrap();
        let key_id = key_identifier(issuer.spki).unwrap();
        let template = Certificate::parse(&p.leaf).unwrap();
        let scheme = template.signature_scheme().unwrap();
        let issuer_key = issuer.subject_public_key().unwrap();
        let mut fields = Der::new(template.tbs).nested(T_SEQUENCE).unwrap();
        let mut required = Vec::new();
        while fields.peek() != Some(T_CTX3) {
            required.extend_from_slice(fields.tlv().unwrap().2);
        }
        let mut extensions = Der::new(fields.expect(T_CTX3).unwrap())
            .nested(T_SEQUENCE)
            .unwrap();
        let mut retained = Vec::new();
        while !extensions.is_empty() {
            let encoded = extensions.expect_raw(T_SEQUENCE).unwrap();
            let mut extension = Der::new(encoded).nested(T_SEQUENCE).unwrap();
            if extension.expect(T_OID).unwrap() != OID_EXT_AKI {
                retained.extend_from_slice(encoded);
            }
        }
        let mut r = rng();
        let mut issuer_names = Vec::new();
        push_tlv(&mut issuer_names, T_GN_DNS, b"issuer.example");
        for (serial, expected_error) in [
            (&[][..], Some("empty authority certificate serial number")),
            (
                &[0, 0][..],
                Some("nonminimal authority certificate serial number"),
            ),
            (
                &[0, 0x7f][..],
                Some("nonminimal authority certificate serial number"),
            ),
            (
                &[0xff, 0x80][..],
                Some("nonminimal authority certificate serial number"),
            ),
            (
                &[0xff, 0xff][..],
                Some("nonminimal authority certificate serial number"),
            ),
            (&[0][..], None),
            (&[1][..], None),
            (&[0x7f][..], None),
            (&[0x80][..], None),
            (&[0xff][..], None),
            (&[0, 0x80][..], None),
            (&[0xff, 0x7f][..], None),
            (&[1, 0][..], None),
        ] {
            for key in [false, true] {
                for critical in [false, true] {
                    let mut body = Vec::new();
                    if key {
                        push_tlv(&mut body, 0x80, &key_id);
                    }
                    push_tlv(&mut body, T_CTX1, &issuer_names);
                    push_tlv(&mut body, 0x82, serial);
                    let mut value = Vec::new();
                    push_tlv(&mut value, T_SEQUENCE, &body);
                    let mut extension = Vec::new();
                    push_ext(&mut extension, OID_EXT_AKI, critical, &value);
                    let mut entries = retained.clone();
                    entries.extend_from_slice(&extension);
                    let mut extensions = Vec::new();
                    push_tlv(&mut extensions, T_SEQUENCE, &entries);
                    let mut body = required.clone();
                    push_tlv(&mut body, T_CTX3, &extensions);
                    let mut tbs = Vec::new();
                    push_tlv(&mut tbs, T_SEQUENCE, &body);
                    let signature = p.int_key.sign(scheme, &tbs, &mut r).unwrap();
                    sign::verify(scheme, &issuer_key, &tbs, &signature).unwrap();
                    let mut content = tbs;
                    push_tlv(&mut content, T_SEQUENCE, template.sig_alg);
                    let mut bits = alloc::vec![0];
                    bits.extend_from_slice(&signature);
                    push_tlv(&mut content, T_BIT_STRING, &bits);
                    let mut leaf = Vec::new();
                    push_tlv(&mut leaf, T_SEQUENCE, &content);
                    let parsed = Certificate::parse(&leaf);
                    if let Some(context) = expected_error {
                        let error = parsed.err().unwrap();
                        assert_eq!(error.kind(), ErrorKind::BadCertificate);
                        assert_eq!(error.context(), context);
                        assert_eq!(
                            err(verify_both(&leaf, &[&p.int], &p.roots, &opts())),
                            ErrorKind::BadCertificate,
                        );
                    } else {
                        assert_eq!(
                            parsed.unwrap().ext.aki,
                            if key { Some(key_id.as_slice()) } else { None }
                        );
                        verify_both(&leaf, &[&p.int], &p.roots, &opts()).unwrap();
                    }
                }
            }
        }
    }

    /// REQ-X509-042: malformed purposes are refused before usage checking,
    /// including those following a recognized purpose in a signed certificate.
    #[test]
    fn extended_key_usage_oids_require_complete_minimal_encodings() {
        let p = pki([KeyKind::EcdsaP256; 3]);
        let issuer = Certificate::parse(&p.int).unwrap();
        let ki = key_identifier(issuer.spki_der()).unwrap();
        let mut r = rng();
        let key = SigningKey::generate(KeyKind::EcdsaP256, &mut r).unwrap();
        let mut parameters = params("eku", &["eku.example.com"], false);
        parameters.usage = &[];
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
            for critical in [false, true] {
                for position in 0..=2 {
                    let mut purposes = alloc::vec![OID_KP_SERVER_AUTH, OID_KP_CLIENT_AUTH];
                    purposes.insert(position, oid);
                    let mut body = Vec::new();
                    for purpose in purposes {
                        push_tlv(&mut body, T_OID, purpose);
                    }
                    let mut value = Vec::new();
                    push_tlv(&mut value, T_SEQUENCE, &body);
                    let mut extension = Vec::new();
                    push_ext(&mut extension, OID_EXT_EKU, critical, &value);
                    let leaf = build(
                        &parameters,
                        key.spki(),
                        issuer.subject_der(),
                        &ki,
                        &p.int_key,
                        &mut r,
                        &[extension],
                    )
                    .unwrap();
                    let parsed = Certificate::parse(&leaf);
                    if valid {
                        assert_eq!(parsed.unwrap().ext.eku, Some(body.as_slice()));
                        for usage in [Usage::ServerAuth, Usage::ClientAuth] {
                            let options = VerifyOptions::new(NOW, usage, ALL);
                            verify_both(&leaf, &[&p.int], &p.roots, &options).unwrap();
                        }
                    } else {
                        assert_eq!(parsed.err().unwrap().kind(), ErrorKind::BadCertificate);
                        assert_eq!(
                            err(verify_both(&leaf, &[&p.int], &p.roots, &opts())),
                            ErrorKind::BadCertificate,
                            "oid={oid:?}, critical={critical}, position={position}",
                        );
                    }
                }
            }
        }
    }

    /// REQ-X509-041: even unknown noncritical extension OIDs must be valid DER.
    #[test]
    fn certificate_extension_oids_require_complete_minimal_encodings() {
        let p = pki([KeyKind::EcdsaP256; 3]);
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
            for critical in [false, true] {
                let mut extra = Vec::new();
                push_ext(&mut extra, oid, critical, &[0x05, 0]);
                let (leaf, _) = with_extra(extra, &p.int, &p.int_key, false);
                let result = Certificate::parse(&leaf);
                if valid {
                    assert_eq!(result.unwrap().ext.unknown_critical, critical);
                    if !critical {
                        verify_both(&leaf, &[&p.int], &p.roots, &opts()).unwrap();
                    }
                } else {
                    assert_eq!(result.err().unwrap().kind(), ErrorKind::BadCertificate);
                }
            }
        }
    }

    #[test]
    fn unknown_critical_extensions_fail_closed() {
        let p = pki([KeyKind::EcdsaP256; 3]);
        let unknown_oid = [0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x99, 0x01];
        let mut crit = Vec::new();
        push_ext(&mut crit, &unknown_oid, true, &[0x05, 0x00]);
        let (leaf, _) = with_extra(crit.clone(), &p.int, &p.int_key, false);
        assert_eq!(
            err(verify_both(&leaf, &[&p.int], &p.roots, &opts())),
            ErrorKind::UnsupportedCertificate
        );
        let mut non = Vec::new();
        push_ext(&mut non, &unknown_oid, false, &[0x05, 0x00]);
        let (leaf, _) = with_extra(non, &p.int, &p.int_key, false);
        verify_both(&leaf, &[&p.int], &p.roots, &opts()).unwrap();
        // On an intermediate as well.
        let (int2, k2) = with_extra(crit, &p.int, &p.int_key, true);
        let mut r = rng();
        let lk = SigningKey::generate(KeyKind::EcdsaP256, &mut r).unwrap();
        let leaf = issue(
            &params("l", &["l.example.com"], false),
            lk.spki(),
            &int2,
            &k2,
            &mut r,
        )
        .unwrap();
        assert_eq!(
            err(verify_both(&leaf, &[&int2, &p.int], &p.roots, &opts())),
            ErrorKind::UnsupportedCertificate
        );
    }

    #[test]
    fn name_constraints_are_enforced() {
        let p = pki([KeyKind::EcdsaP256; 3]);
        // permittedSubtrees: dNSName example.com
        let mut base = Vec::new();
        push_tlv(&mut base, T_GN_DNS, b"example.com");
        let mut subtree = Vec::new();
        push_tlv(&mut subtree, T_SEQUENCE, &base);
        let mut nc_body = Vec::new();
        push_tlv(&mut nc_body, T_CTX0, &subtree);
        let mut nc = Vec::new();
        push_tlv(&mut nc, T_SEQUENCE, &nc_body);
        let mut ext = Vec::new();
        push_ext(&mut ext, OID_EXT_NC, true, &nc);
        let (int2, k2) = with_extra(ext, &p.int, &p.int_key, true);
        let mut r = rng();
        let lk = SigningKey::generate(KeyKind::EcdsaP256, &mut r).unwrap();
        let good = issue(
            &params("g", &["a.example.com"], false),
            lk.spki(),
            &int2,
            &k2,
            &mut r,
        )
        .unwrap();
        verify_both(&good, &[&int2, &p.int], &p.roots, &opts()).unwrap();
        let evil = issue(
            &params("e", &["evil.org"], false),
            lk.spki(),
            &int2,
            &k2,
            &mut r,
        )
        .unwrap();
        assert_eq!(
            err(verify_both(&evil, &[&int2, &p.int], &p.roots, &opts())),
            ErrorKind::CertificateUsage
        );

        // A directoryName constraint is not evaluated, so it fails closed.
        let mut dn = Vec::new();
        push_tlv(&mut dn, 0xa4, &encode_name("Corp"));
        let mut st = Vec::new();
        push_tlv(&mut st, T_SEQUENCE, &dn);
        let mut body = Vec::new();
        push_tlv(&mut body, T_CTX0, &st);
        let mut nc = Vec::new();
        push_tlv(&mut nc, T_SEQUENCE, &body);
        let mut ext = Vec::new();
        push_ext(&mut ext, OID_EXT_NC, true, &nc);
        let (int3, k3) = with_extra(ext, &p.int, &p.int_key, true);
        let leaf = issue(
            &params("g", &["a.example.com"], false),
            lk.spki(),
            &int3,
            &k3,
            &mut r,
        )
        .unwrap();
        assert_eq!(
            err(verify_both(&leaf, &[&int3, &p.int], &p.roots, &opts())),
            ErrorKind::UnsupportedCertificate
        );
    }

    #[test]
    fn name_constraints_require_nonempty_subtree_lists() {
        let mut general_name = Vec::new();
        push_tlv(&mut general_name, T_GN_DNS, b"example.com");
        let mut subtree = Vec::new();
        push_tlv(&mut subtree, T_SEQUENCE, &general_name);
        for permitted in [None, Some(&[][..]), Some(subtree.as_slice())] {
            for excluded in [None, Some(&[][..]), Some(subtree.as_slice())] {
                let mut body = Vec::new();
                if let Some(p) = permitted {
                    push_tlv(&mut body, T_CTX0, p);
                }
                if let Some(e) = excluded {
                    push_tlv(&mut body, T_CTX1, e);
                }
                let valid = (permitted.is_some() || excluded.is_some())
                    && !permitted.is_some_and(|p| p.is_empty())
                    && !excluded.is_some_and(|e| e.is_empty());
                let result = apply_name_constraints(&body, &[]);
                if valid {
                    result.unwrap();
                } else {
                    assert_eq!(result.unwrap_err().kind(), ErrorKind::BadCertificate);
                }
            }
        }
    }

    /// NameConstraints with `permitted` and `excluded` general subtrees
    /// (tag, base) on a fresh intermediate under the fixture's.
    fn constrained(
        p: &Pki,
        permitted: &[(u8, &[u8])],
        excluded: &[(u8, &[u8])],
    ) -> (Vec<u8>, SigningKey) {
        let subtrees = |list: &[(u8, &[u8])]| {
            let mut out = Vec::new();
            for (tag, base) in list {
                let mut gn = Vec::new();
                push_tlv(&mut gn, *tag, base);
                push_tlv(&mut out, T_SEQUENCE, &gn);
            }
            out
        };
        let mut body = Vec::new();
        if !permitted.is_empty() {
            push_tlv(&mut body, T_CTX0, &subtrees(permitted));
        }
        if !excluded.is_empty() {
            push_tlv(&mut body, T_CTX1, &subtrees(excluded));
        }
        let mut nc = Vec::new();
        push_tlv(&mut nc, T_SEQUENCE, &body);
        let mut ext = Vec::new();
        push_ext(&mut ext, OID_EXT_NC, true, &nc);
        with_extra(ext, &p.int, &p.int_key, true)
    }

    /// Verify a leaf with these names under `(int, key)` and the fixture's
    /// intermediate; `Err(kind)` if refused.
    fn under(
        p: &Pki,
        ca: &(Vec<u8>, SigningKey),
        dns: &[&str],
        ips: &[&str],
    ) -> core::result::Result<(), ErrorKind> {
        let mut r = rng();
        let lk = SigningKey::generate(KeyKind::EcdsaP256, &mut r).unwrap();
        let ips: Vec<IpAddr> = ips.iter().map(|s| IpAddr::parse(s).unwrap()).collect();
        let params = CertificateParams {
            ip_addresses: &ips,
            ..params("leaf", dns, false)
        };
        let leaf = issue(&params, lk.spki(), &ca.0, &ca.1, &mut r).unwrap();
        verify_both(&leaf, &[&ca.0, &p.int], &p.roots, &opts())
            .map(|_| ())
            .map_err(|e| e.kind())
    }

    /// RFC 5280 §4.2.1.10: excluded DNS subtrees refuse the names inside them,
    /// and a wildcard whose scope contains an excluded subtree, conservatively.
    #[test]
    fn excluded_dns_subtrees_are_enforced() {
        let p = pki([KeyKind::EcdsaP256; 3]);
        let ca = constrained(&p, &[], &[(T_GN_DNS, b"evil.example.com")]);
        let v = Err(ErrorKind::CertificateUsage);
        assert_eq!(under(&p, &ca, &["a.example.com"], &[]), Ok(()));
        assert_eq!(under(&p, &ca, &["evil.example.com"], &[]), v);
        assert_eq!(under(&p, &ca, &["x.evil.example.com"], &[]), v);
        assert_eq!(
            under(&p, &ca, &["EVIL.Example.com"], &[]),
            v,
            "case-insensitive"
        );
        assert_eq!(
            under(&p, &ca, &["*.example.com"], &[]),
            v,
            "a wildcard over an excluded subtree"
        );
        // A name that merely ends with the same characters is not inside it.
        assert_eq!(under(&p, &ca, &["notevil.example.com"], &[]), Ok(()));
        // One excluded name among several SANs is enough.
        assert_eq!(
            under(&p, &ca, &["a.example.com", "evil.example.com"], &[]),
            v
        );
    }

    /// REQ-X509-044: every IPv4/IPv6 prefix is valid; a hole in the mask is
    /// refused in permitted and excluded lists, even without subjects.
    #[test]
    fn ip_name_constraint_masks_require_contiguous_prefix_bits() {
        let constraint = |base: &[u8], excluded: bool| {
            let mut name = Vec::new();
            push_tlv(&mut name, T_GN_IP, base);
            let mut subtree = Vec::new();
            push_tlv(&mut subtree, T_SEQUENCE, &name);
            let mut body = Vec::new();
            push_tlv(&mut body, if excluded { T_CTX1 } else { T_CTX0 }, &subtree);
            body
        };
        for width in [4usize, 16] {
            for prefix in 0..=width * 8 {
                let mut base = alloc::vec![0xa5; width];
                for byte in 0..width {
                    let bits = prefix.saturating_sub(byte * 8).min(8);
                    base.push(if bits == 0 { 0 } else { 0xff << (8 - bits) });
                }
                for excluded in [false, true] {
                    apply_name_constraints(&constraint(&base, excluded), &[]).unwrap();
                }
            }
            for hole in 0..width * 8 - 1 {
                let mut base = alloc::vec![0; width];
                let mut mask = alloc::vec![0xff; width];
                mask[hole / 8] &= !(0x80 >> (hole % 8));
                base.extend_from_slice(&mask);
                for excluded in [false, true] {
                    let error =
                        apply_name_constraints(&constraint(&base, excluded), &[]).unwrap_err();
                    assert_eq!(error.kind(), ErrorKind::BadCertificate);
                    assert_eq!(error.context(), "noncontiguous IP name constraint mask");
                }
            }
        }
        let p = pki([KeyKind::EcdsaP256; 3]);
        for width in [4usize, 16] {
            for hole in [0, 7, width * 8 - 2] {
                let mut base = alloc::vec![0; width];
                let mut mask = alloc::vec![0xff; width];
                mask[hole / 8] &= !(0x80 >> (hole % 8));
                base.extend_from_slice(&mask);
                for excluded in [false, true] {
                    for malformed_first in [false, true] {
                        let mut entries = alloc::vec![(T_GN_DNS, &b"example.com"[..])];
                        entries.insert(if malformed_first { 0 } else { 1 }, (T_GN_IP, &base));
                        let ca = if excluded {
                            constrained(&p, &[], &entries)
                        } else {
                            constrained(&p, &entries, &[])
                        };
                        // The malformed CA is refused before issuing a leaf.
                        assert_eq!(
                            Certificate::parse(&ca.0).err().unwrap().kind(),
                            ErrorKind::BadCertificate
                        );
                    }
                }
            }
        }
    }

    /// IP subtrees are address and mask; they apply to addresses of their own
    /// family only.
    #[test]
    fn ip_name_constraints_are_enforced() {
        let p = pki([KeyKind::EcdsaP256; 3]);
        let v = Err(ErrorKind::CertificateUsage);
        // Permitted 10.0.0.0/8, excluded 10.9.0.0/16.
        let ca = constrained(
            &p,
            &[(T_GN_IP, &[10, 0, 0, 0, 255, 0, 0, 0])],
            &[(T_GN_IP, &[10, 9, 0, 0, 255, 255, 0, 0])],
        );
        assert_eq!(under(&p, &ca, &["a.example.com"], &["10.1.2.3"]), Ok(()));
        assert_eq!(under(&p, &ca, &["a.example.com"], &["192.0.2.1"]), v);
        assert_eq!(under(&p, &ca, &["a.example.com"], &["10.9.1.1"]), v);
        // REQ-X509-072: iPAddress is one name type. A permitted list of IPv4
        // subtrees leaves an IPv6 address outside it, not unconstrained.
        assert_eq!(under(&p, &ca, &["a.example.com"], &["2001:db8::1"]), v);
        // And an IPv4-mapped IPv6 address is the IPv4 address it carries, for
        // an excluded IPv4 subtree.
        let ex = constrained(&p, &[], &[(T_GN_IP, &[10, 0, 0, 0, 255, 0, 0, 0])]);
        assert_eq!(under(&p, &ex, &["a.example.com"], &["::ffff:10.0.0.1"]), v);
        assert_eq!(
            under(&p, &ex, &["a.example.com"], &["::ffff:192.0.2.1"]),
            Ok(())
        );
        assert_eq!(under(&p, &ex, &["a.example.com"], &["2001:db8::1"]), Ok(()));
        // An IPv6 permitted subtree: 2001:db8::/32.
        let mut v6 = [0u8; 32];
        v6[..4].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8]);
        v6[16..20].copy_from_slice(&[0xff; 4]);
        let ca6 = constrained(&p, &[(T_GN_IP, &v6)], &[]);
        assert_eq!(
            under(&p, &ca6, &["a.example.com"], &["2001:db8:1::5"]),
            Ok(())
        );
        assert_eq!(under(&p, &ca6, &["a.example.com"], &["2001:db9::5"]), v);
        // An IPv4 address under an IPv6-only permitted list is outside it.
        assert_eq!(under(&p, &ca6, &["a.example.com"], &["10.1.2.3"]), v);
        // A malformed IP subtree (neither 8 nor 32 bytes) fails closed.
        let bad = constrained(&p, &[(T_GN_IP, &[10, 0, 0, 0])], &[]);
        assert_eq!(
            Certificate::parse(&bad.0).err().unwrap().kind(),
            ErrorKind::BadCertificate
        );
    }

    /// An RSASSA-PSS AlgorithmIdentifier body with the given parameters.
    fn pss_alg(hash: &[u8], mgf: &[u8], mgf_hash: &[u8], salt: u8, trailer: Option<u8>) -> Vec<u8> {
        pss_alg_integers(
            hash,
            mgf,
            mgf_hash,
            &[salt],
            trailer.as_ref().map(core::slice::from_ref),
        )
    }

    fn pss_alg_integers(
        hash: &[u8],
        mgf: &[u8],
        mgf_hash: &[u8],
        salt: &[u8],
        trailer: Option<&[u8]>,
    ) -> Vec<u8> {
        let mut halg = Vec::new();
        push_tlv(&mut halg, T_OID, hash);
        push_tlv(&mut halg, T_NULL, &[]);
        let mut hseq = Vec::new();
        push_tlv(&mut hseq, T_SEQUENCE, &halg);
        let mut params = Vec::new();
        push_tlv(&mut params, T_CTX0, &hseq);
        let mut mhalg = Vec::new();
        push_tlv(&mut mhalg, T_OID, mgf_hash);
        push_tlv(&mut mhalg, T_NULL, &[]);
        let mut mgfb = Vec::new();
        push_tlv(&mut mgfb, T_OID, mgf);
        push_tlv(&mut mgfb, T_SEQUENCE, &mhalg);
        let mut mseq = Vec::new();
        push_tlv(&mut mseq, T_SEQUENCE, &mgfb);
        push_tlv(&mut params, T_CTX1, &mseq);
        let mut sint = Vec::new();
        push_tlv(&mut sint, T_INTEGER, salt);
        push_tlv(&mut params, T_CTX2, &sint);
        if let Some(t) = trailer {
            let mut ti = Vec::new();
            push_tlv(&mut ti, T_INTEGER, t);
            push_tlv(&mut params, T_CTX3, &ti);
        }
        let mut body = Vec::new();
        push_tlv(&mut body, T_OID, OID_RSA_PSS);
        push_tlv(&mut body, T_SEQUENCE, &params);
        body
    }

    /// REQ-X509-066: matching malformed signature identifiers fail at parse
    /// time; supported identifiers and well-formed unknown parameters survive.
    #[test]
    fn certificate_signature_identifiers_require_complete_fields() {
        let wrap = |tag, body: &[u8]| {
            let mut encoded = Vec::new();
            push_tlv(&mut encoded, tag, body);
            encoded
        };
        let mut r = rng();
        let key = SigningKey::generate(KeyKind::Ed25519, &mut r).unwrap();
        let original = self_signed(&params("Algorithm fixture", &[], false), &key, &mut r).unwrap();
        let parsed = Certificate::parse(&original).unwrap();
        let mut fields = Der::new(parsed.tbs).nested(T_SEQUENCE).unwrap();
        let version = fields.expect_raw(T_CTX0).unwrap();
        let serial = fields.expect_raw(T_INTEGER).unwrap();
        fields.expect(T_SEQUENCE).unwrap();
        let mut tail = Vec::new();
        while !fields.is_empty() {
            tail.extend_from_slice(fields.tlv().unwrap().2);
        }
        let unknown = wrap(T_OID, &[0x2a, 3]);
        let known = wrap(T_OID, OID_ED25519);
        for (algorithm, accepted, supported) in [
            (known, true, true),
            (unknown.clone(), true, false),
            (
                [unknown.clone(), alloc::vec![T_NULL, 0]].concat(),
                true,
                false,
            ),
            (
                [unknown.clone(), alloc::vec![0x9f, 31, 0]].concat(),
                true,
                false,
            ),
            (Vec::new(), false, false),
            (wrap(T_OID, &[]), false, false),
            (wrap(T_OID, &[0x2a, 0x80, 1]), false, false),
            (wrap(T_OID, &[0x2a, 0x81]), false, false),
            (alloc::vec![T_NULL, 0], false, false),
            (
                [unknown.clone(), alloc::vec![T_NULL, 0, T_NULL, 0]].concat(),
                false,
                false,
            ),
            (
                [unknown.clone(), alloc::vec![T_OCTET_STRING, 2, 1]].concat(),
                false,
                false,
            ),
            ([unknown, alloc::vec![0x9f, 30, 0]].concat(), false, false),
        ] {
            let encoded_algorithm = wrap(T_SEQUENCE, &algorithm);
            let body = [
                version,
                serial,
                encoded_algorithm.as_slice(),
                tail.as_slice(),
            ]
            .concat();
            let tbs = wrap(T_SEQUENCE, &body);
            let signature = key.sign(SignatureScheme::Ed25519, &tbs, &mut r).unwrap();
            sign::verify(
                SignatureScheme::Ed25519,
                &PublicKey::from_spki(key.spki()).unwrap(),
                &tbs,
                &signature,
            )
            .unwrap();
            let bits = [alloc::vec![0], signature].concat();
            let der = wrap(
                T_SEQUENCE,
                &[tbs, encoded_algorithm, wrap(T_BIT_STRING, &bits)].concat(),
            );
            let result = Certificate::parse(&der);
            if accepted {
                let cert = result.unwrap();
                if supported {
                    assert_eq!(cert.signature_scheme().unwrap(), SignatureScheme::Ed25519);
                } else {
                    assert_eq!(
                        cert.signature_scheme().unwrap_err().kind(),
                        ErrorKind::UnsupportedCertificate
                    );
                }
            } else {
                assert_eq!(result.err().unwrap().kind(), ErrorKind::BadCertificate);
            }
        }
    }

    /// REQ-X509-043: malformed identifiers have precise structural errors at
    /// every signature OID location; well-formed unknown algorithms stay unsupported.
    #[test]
    fn signature_algorithm_oids_require_complete_minimal_encodings() {
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
            for (hash, salt) in [(OID_SHA256, 32), (OID_SHA384, 48), (OID_SHA512, 64)] {
                let mut top = Vec::new();
                push_tlv(&mut top, T_OID, oid);
                for (location, algorithm) in [
                    ("signature", top),
                    ("message hash", pss_alg(oid, OID_MGF1, hash, salt, None)),
                    ("mask generator", pss_alg(hash, oid, hash, salt, None)),
                    ("mask hash", pss_alg(hash, OID_MGF1, oid, salt, None)),
                ] {
                    let error = scheme_from_alg(&algorithm).unwrap_err();
                    if let Some(context) = structural_error {
                        assert_eq!(
                            error.kind(),
                            ErrorKind::BadCertificate,
                            "location={location}, oid={oid:?}"
                        );
                        assert_eq!(error.context(), context);
                    } else {
                        assert_eq!(error.kind(), ErrorKind::UnsupportedCertificate);
                    }
                }
            }
        }
        for scheme in [
            SignatureScheme::EcdsaSecp256r1Sha256,
            SignatureScheme::EcdsaSecp384r1Sha384,
            SignatureScheme::EcdsaSecp521r1Sha512,
            SignatureScheme::Ed25519,
            SignatureScheme::MlDsa65,
            SignatureScheme::MlDsa87,
            SignatureScheme::RsaPssRsaeSha256,
            SignatureScheme::RsaPssRsaeSha384,
            SignatureScheme::RsaPssRsaeSha512,
        ] {
            let encoded = alg_id(scheme).unwrap();
            let body = Der::new(&encoded).expect(T_SEQUENCE).unwrap();
            assert_eq!(scheme_from_alg(body).unwrap(), scheme);
        }
    }

    #[test]
    fn rsa_pss_parameters_require_minimal_integer_encoding() {
        for (hash, salt, scheme) in [
            (OID_SHA256, 32, SignatureScheme::RsaPssRsaeSha256),
            (OID_SHA384, 48, SignatureScheme::RsaPssRsaeSha384),
            (OID_SHA512, 64, SignatureScheme::RsaPssRsaeSha512),
        ] {
            for redundant_salt in [false, true] {
                for trailer in [None, Some(&[1][..]), Some(&[0, 1][..])] {
                    let salt = if redundant_salt {
                        alloc::vec![0, salt]
                    } else {
                        alloc::vec![salt]
                    };
                    let alg = pss_alg_integers(hash, OID_MGF1, hash, &salt, trailer);
                    let result = scheme_from_alg(&alg);
                    if redundant_salt || trailer == Some(&[0, 1][..]) {
                        let error = result.unwrap_err();
                        assert_eq!(error.kind(), ErrorKind::BadCertificate);
                        assert_eq!(error.context(), "nonminimal non-negative INTEGER");
                    } else {
                        assert_eq!(result.unwrap(), scheme);
                    }
                }
            }
        }
    }

    /// REQ-X509-005: RSA-PSS certificate signatures are accepted only with the
    /// RFC 8446 parameters: MGF1 over the message hash, a salt as long as that
    /// hash, and trailer field 1. Anything else is refused rather than
    /// verified under altered parameters.
    #[test]
    fn rsa_pss_parameters_must_be_the_standard_ones() {
        let sha1: &[u8] = &[0x2b, 0x0e, 0x03, 0x02, 0x1a];
        assert_eq!(
            scheme_from_alg(&pss_alg(OID_SHA256, OID_MGF1, OID_SHA256, 32, None)).unwrap(),
            SignatureScheme::RsaPssRsaeSha256
        );
        assert_eq!(
            scheme_from_alg(&pss_alg(OID_SHA384, OID_MGF1, OID_SHA384, 48, Some(1))).unwrap(),
            SignatureScheme::RsaPssRsaeSha384
        );
        let refused = |alg: Vec<u8>| scheme_from_alg(&alg).unwrap_err().kind();
        let u = ErrorKind::UnsupportedCertificate;
        assert_eq!(
            refused(pss_alg(OID_SHA256, OID_SHA256, OID_SHA256, 32, None)),
            u,
            "not MGF1"
        );
        assert_eq!(
            refused(pss_alg(OID_SHA256, OID_MGF1, OID_SHA384, 32, None)),
            u,
            "MGF1 hash differs"
        );
        assert_eq!(
            refused(pss_alg(OID_SHA256, OID_MGF1, OID_SHA256, 20, None)),
            u,
            "salt length"
        );
        assert_eq!(refused(pss_alg(sha1, OID_MGF1, sha1, 20, None)), u, "SHA-1");
        let e =
            scheme_from_alg(&pss_alg(OID_SHA256, OID_MGF1, OID_SHA256, 32, Some(2))).unwrap_err();
        assert!(e.to_string().contains("PSS trailer field"), "{e}");
        // Our own encoder writes exactly the accepted form.
        let ours = alg_id(SignatureScheme::RsaPssRsaeSha512).unwrap();
        let body = Der::new(&ours).expect(T_SEQUENCE).unwrap();
        assert_eq!(
            scheme_from_alg(body).unwrap(),
            SignatureScheme::RsaPssRsaeSha512
        );
    }

    /// REQ-X509-002: a graph built to be expensive exhausts the search
    /// budget and fails, rather than running on. Twelve CAs share a name and
    /// a key, so key identifiers cannot prune them: each validly issues the
    /// leaf and every other, and none reaches an anchor.
    #[test]
    fn an_adversarial_graph_exhausts_the_search_budget() {
        let p = pki([KeyKind::EcdsaP256; 3]);
        let mut r = rng();
        let hub_key = SigningKey::generate(KeyKind::EcdsaP256, &mut r).unwrap();
        let hub = self_signed(&params("Hub", &[], true), &hub_key, &mut r).unwrap();
        let hubs: Vec<Vec<u8>> = (1..=12u8)
            .map(|i| {
                let params = CertificateParams {
                    serial: [i; 16],
                    ..params("Hub", &[], true)
                };
                issue(&params, hub_key.spki(), &hub, &hub_key, &mut r).unwrap()
            })
            .collect();
        let lk = SigningKey::generate(KeyKind::EcdsaP256, &mut r).unwrap();
        let leaf = issue(
            &params("l", &["l.example.com"], false),
            lk.spki(),
            &hub,
            &hub_key,
            &mut r,
        )
        .unwrap();
        let ints: Vec<&[u8]> = hubs.iter().map(|h| &h[..]).collect();
        let e = verify_both(&leaf, &ints, &p.roots, &opts()).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::UnknownCa, "{e}");
        assert!(
            e.to_string().contains("path search budget exhausted"),
            "{e}"
        );
    }

    /// REQ-X509-008: name constraints on a trust anchor bind the whole path.
    #[test]
    fn a_trust_anchor_can_constrain_names() {
        let mut r = rng();
        let root_key = SigningKey::generate(KeyKind::EcdsaP256, &mut r).unwrap();
        let mut base = Vec::new();
        push_tlv(&mut base, T_GN_DNS, b"example.com");
        let mut subtree = Vec::new();
        push_tlv(&mut subtree, T_SEQUENCE, &base);
        let mut body = Vec::new();
        push_tlv(&mut body, T_CTX0, &subtree);
        let mut nc = Vec::new();
        push_tlv(&mut nc, T_SEQUENCE, &body);
        let mut ext = Vec::new();
        push_ext(&mut ext, OID_EXT_NC, true, &nc);
        let root = build(
            &params("Constrained Root", &[], true),
            root_key.spki(),
            &encode_name("Constrained Root"),
            &key_identifier(root_key.spki()).unwrap(),
            &root_key,
            &mut r,
            &[ext],
        )
        .unwrap();
        let mut roots = RootStore::new();
        roots.add_der(&root).unwrap();
        let ik = SigningKey::generate(KeyKind::EcdsaP256, &mut r).unwrap();
        let int = issue(
            &params("Int", &[], true),
            ik.spki(),
            &root,
            &root_key,
            &mut r,
        )
        .unwrap();
        let leaf = |name: &str, r: &mut ic_drbg::Rng| {
            let lk = SigningKey::generate(KeyKind::EcdsaP256, r).unwrap();
            issue(&params("l", &[name], false), lk.spki(), &int, &ik, r).unwrap()
        };
        verify_both(&leaf("a.example.com", &mut r), &[&int], &roots, &opts()).unwrap();
        assert_eq!(
            err(verify_both(
                &leaf("evil.org", &mut r),
                &[&int],
                &roots,
                &opts()
            )),
            ErrorKind::CertificateUsage
        );
    }

    #[test]
    fn schemes_outside_the_policy_are_refused() {
        let p = pki([KeyKind::EcdsaP256; 3]);
        let o = VerifyOptions::new(NOW, Usage::ServerAuth, &[SignatureScheme::Ed25519]);
        assert_eq!(
            err(verify_both(&p.leaf, &[&p.int], &p.roots, &o)),
            ErrorKind::PolicyViolation
        );
    }

    #[test]
    fn extended_key_usage_must_permit_the_use() {
        let p = pki([KeyKind::EcdsaP256; 3]);
        let o = VerifyOptions::new(NOW, Usage::ClientAuth, ALL);
        assert_eq!(
            err(verify_both(&p.leaf, &[&p.int], &p.roots, &o)),
            ErrorKind::CertificateUsage
        );
    }

    #[test]
    fn an_unknown_ca_is_reported_as_such() {
        let p = pki([KeyKind::EcdsaP256; 3]);
        let other = pki([KeyKind::EcdsaP256; 3]);
        assert_eq!(
            err(verify_both(&p.leaf, &[&p.int], &other.roots, &opts())),
            ErrorKind::UnknownCa
        );
        assert_eq!(
            err(verify_both(&p.leaf, &[], &p.roots, &opts())),
            ErrorKind::UnknownCa
        );
        assert_eq!(
            err(verify_both(&p.leaf, &[&p.int], &RootStore::new(), &opts())),
            ErrorKind::UnknownCa
        );
    }

    #[test]
    fn cross_signed_cycles_terminate() {
        let mut r = rng();
        let ka = SigningKey::generate(KeyKind::EcdsaP256, &mut r).unwrap();
        let kb = SigningKey::generate(KeyKind::EcdsaP256, &mut r).unwrap();
        let a_self = self_signed(&params("A", &[], true), &ka, &mut r).unwrap();
        let b_self = self_signed(&params("B", &[], true), &kb, &mut r).unwrap();
        let a_by_b = issue(&params("A", &[], true), ka.spki(), &b_self, &kb, &mut r).unwrap();
        let b_by_a = issue(&params("B", &[], true), kb.spki(), &a_self, &ka, &mut r).unwrap();
        let lk = SigningKey::generate(KeyKind::EcdsaP256, &mut r).unwrap();
        let leaf = issue(
            &params("l", &["l.example.com"], false),
            lk.spki(),
            &a_by_b,
            &ka,
            &mut r,
        )
        .unwrap();
        let ints: [&[u8]; 4] = [&a_by_b, &b_by_a, &a_self, &b_self];
        assert_eq!(
            err(verify_both(&leaf, &ints, &RootStore::new(), &opts())),
            ErrorKind::UnknownCa
        );
        // With B trusted, the same pool yields a path.
        let mut roots = RootStore::new();
        roots.add_der(&b_self).unwrap();
        verify_both(&leaf, &ints, &roots, &opts()).unwrap();
    }

    #[test]
    fn a_pinned_self_signed_leaf_is_accepted() {
        let mut r = rng();
        let key = SigningKey::generate(KeyKind::Ed25519, &mut r).unwrap();
        let cert =
            self_signed(&params("agent-7", &["agent-7.local"], false), &key, &mut r).unwrap();
        let mut roots = RootStore::new();
        roots.add_der(&cert).unwrap();
        let report = verify_both(&cert, &[], &roots, &opts()).unwrap();
        assert_eq!(report.depth, 0);
        assert_eq!(
            err(verify_both(&cert, &[], &RootStore::new(), &opts())),
            ErrorKind::UnknownCa
        );
    }

    #[test]
    fn issuing_with_a_mismatched_key_is_refused() {
        let mut r = rng();
        let p = pki([KeyKind::EcdsaP256; 3]);
        let wrong = SigningKey::generate(KeyKind::EcdsaP256, &mut r).unwrap();
        let e = issue(
            &params("l", &["l.example.com"], false),
            wrong.spki(),
            &p.root,
            &wrong,
            &mut r,
        )
        .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::InvalidConfig);
    }

    #[test]
    fn every_truncation_of_a_real_certificate_is_rejected() {
        let p = pki([KeyKind::EcdsaP384; 3]);
        for n in 0..p.leaf.len() {
            assert!(
                Certificate::parse(&p.leaf[..n]).is_err(),
                "prefix {n} parsed"
            );
        }
        let mut extended = p.leaf.clone();
        extended.push(0);
        assert!(Certificate::parse(&extended).is_err());
    }

    #[test]
    fn pem_bundles_load() {
        let p = pki([KeyKind::EcdsaP256; 3]);
        let b64 = |d: &[u8]| {
            let mut out = alloc::vec![0u8; d.len().div_ceil(3) * 4];
            ic_core::codec::base64_encode(d, &mut out).unwrap();
            let s = String::from_utf8(out).unwrap();
            let lines: Vec<&str> = s
                .as_bytes()
                .chunks(64)
                .map(|c| core::str::from_utf8(c).unwrap())
                .collect();
            alloc::format!(
                "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
                lines.join("\n")
            )
        };
        let text = alloc::format!(
            "junk\n{}-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n{}{}",
            b64(&p.root),
            b64(&p.int),
            b64(&p.root)
        );
        let mut store = RootStore::new();
        assert_eq!(store.add_pem_bundle(&text).unwrap(), 2);
        assert_eq!(store.len(), 2);
        assert!(RootStore::new().add_pem_bundle("nothing here").is_err());
    }

    #[test]
    fn the_system_bundle_loads_when_present() {
        match RootStore::from_system() {
            Ok(store) => {
                eprintln!("system trust store: {} anchors", store.len());
                assert!(store.len() > 50, "only {} anchors parsed", store.len());
            }
            Err(e) => assert_eq!(e.kind(), ErrorKind::InvalidConfig),
        }
    }

    fn msg(r: Result<ChainReport>) -> String {
        r.unwrap_err().to_string()
    }

    /// Replace `from` with `to` (same length) inside a certificate's TBS and
    /// sign it again with `issuer_key`, as a CA that issued it would have.
    fn resign(cert: &[u8], issuer_key: &SigningKey, from: &[u8], to: &[u8]) -> Vec<u8> {
        assert_eq!(from.len(), to.len());
        let mut outer = Der::new(cert);
        let mut s = outer.nested(T_SEQUENCE).unwrap();
        let mut tbs = s.expect_raw(T_SEQUENCE).unwrap().to_vec();
        let alg = s.expect_raw(T_SEQUENCE).unwrap().to_vec();
        let at = tbs
            .windows(from.len())
            .position(|w| w == from)
            .expect("pattern in TBS");
        tbs[at..at + from.len()].copy_from_slice(to);
        let scheme = issuer_key.schemes()[0];
        let sig = issuer_key.sign(scheme, &tbs, &mut rng()).unwrap();
        let mut body = tbs;
        body.extend_from_slice(&alg);
        let mut bits = alloc::vec![0u8];
        bits.extend_from_slice(&sig);
        push_tlv(&mut body, T_BIT_STRING, &bits);
        let mut out = Vec::new();
        push_tlv(&mut out, T_SEQUENCE, &body);
        out
    }

    /// REQ-X509-*: key usage must permit each certificate's role. A leaf
    /// without digitalSignature cannot sign a handshake; an issuer without
    /// keyCertSign cannot issue, even when validly signed.
    #[test]
    fn key_usage_must_permit_the_role() {
        let mut r = rng();
        let root_key = SigningKey::generate(KeyKind::EcdsaP256, &mut r).unwrap();
        let root = self_signed(&params("Root", &[], true), &root_key, &mut r).unwrap();
        let int_key = SigningKey::generate(KeyKind::EcdsaP256, &mut r).unwrap();
        let int = issue(
            &params("Int", &[], true),
            int_key.spki(),
            &root,
            &root_key,
            &mut r,
        )
        .unwrap();
        let leaf_key = SigningKey::generate(KeyKind::EcdsaP256, &mut r).unwrap();
        let leaf = issue(
            &params("leaf", &["leaf.example.com"], false),
            leaf_key.spki(),
            &int,
            &int_key,
            &mut r,
        )
        .unwrap();
        let mut roots = RootStore::new();
        roots.add_der(&root).unwrap();
        verify_both(&leaf, &[&int], &roots, &opts()).unwrap();

        // The leaf allows keyEncipherment only.
        let leaf2 = resign(
            &leaf,
            &int_key,
            &[0x03, 0x02, 0x07, 0x80],
            &[0x03, 0x02, 0x05, 0x20],
        );
        assert!(msg(verify_both(&leaf2, &[&int], &roots, &opts()))
            .contains("leaf key usage lacks digitalSignature"));
        // The intermediate allows digitalSignature and cRLSign, not keyCertSign.
        let int2 = resign(
            &int,
            &root_key,
            &[0x03, 0x02, 0x01, 0x86],
            &[0x03, 0x02, 0x01, 0x82],
        );
        assert!(msg(verify_both(&leaf, &[&int2], &roots, &opts()))
            .contains("issuer key usage lacks keyCertSign"));
    }

    /// Policy limits: the path depth, the smallest RSA modulus, and a CA
    /// certificate presented as the end entity.
    #[test]
    fn path_policy_limits_are_enforced() {
        let p = pki([KeyKind::EcdsaP256; 3]);
        let mut shallow = opts();
        shallow.max_depth = 1;
        assert!(msg(verify_both(&p.leaf, &[&p.int], &p.roots, &shallow))
            .contains("no trust anchor within the depth limit"));
        assert!(msg(verify_both(&p.int, &[], &p.roots, &opts()))
            .contains("a CA certificate cannot be an end entity"));

        let mut r = rng();
        let rsa = SigningKey::rsa(ic_rsa::generate(2048, &mut r).unwrap()).unwrap();
        let root = self_signed(&params("RSA Root", &[], true), &rsa, &mut r).unwrap();
        let lk = SigningKey::generate(KeyKind::EcdsaP256, &mut r).unwrap();
        let leaf = issue(
            &params("l", &["l.example.com"], false),
            lk.spki(),
            &root,
            &rsa,
            &mut r,
        )
        .unwrap();
        let mut roots = RootStore::new();
        roots.add_der(&root).unwrap();
        verify_both(&leaf, &[], &roots, &opts()).unwrap();
        let mut strict = opts();
        strict.min_rsa_bits = 3072;
        assert!(msg(verify_both(&leaf, &[], &roots, &strict))
            .contains("RSA key smaller than the policy minimum"));
    }

    /// A certificate whose outer signature algorithm differs from the one in
    /// its TBSCertificate is refused at parse time: algorithm substitution.
    #[test]
    fn the_two_signature_algorithms_must_agree() {
        let p = pki([KeyKind::EcdsaP256; 3]);
        // ecdsa-with-SHA256; its last occurrence is the outer AlgorithmIdentifier.
        let oid = [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
        let at = p.leaf.windows(oid.len()).rposition(|w| w == oid).unwrap();
        let mut leaf = p.leaf.clone();
        leaf[at + oid.len() - 1] = 0x03; // ecdsa-with-SHA384
        let e = Certificate::parse(&leaf).unwrap_err();
        assert!(e.to_string().contains("signature algorithm differs"), "{e}");
    }

    /// Re-sign `original` with `key` after `edit` rewrites its TBS fields:
    /// the explicit version INTEGER content (None when omitted), the other
    /// fields before the extensions as complete TLVs, and the extension
    /// entries (None when the [3] field is omitted).
    fn rebuild_tbs(
        original: &[u8],
        key: &SigningKey,
        edit: impl FnOnce(&mut Option<Vec<u8>>, &mut Vec<Vec<u8>>, &mut Option<Vec<Vec<u8>>>),
    ) -> Vec<u8> {
        let parsed = Certificate::parse(original).unwrap();
        let mut outer = Der::new(original).nested(T_SEQUENCE).unwrap();
        outer.expect(T_SEQUENCE).unwrap();
        let algorithm = outer.expect_raw(T_SEQUENCE).unwrap();
        let mut fields = Der::new(parsed.tbs).nested(T_SEQUENCE).unwrap();
        let mut version = fields
            .optional(T_CTX0)
            .unwrap()
            .map(|v| Der::new(v).expect(T_INTEGER).unwrap().to_vec());
        let mut others = Vec::new();
        let mut extensions = None;
        while !fields.is_empty() {
            if fields.peek() == Some(T_CTX3) {
                let mut list = Der::new(fields.expect(T_CTX3).unwrap())
                    .nested(T_SEQUENCE)
                    .unwrap();
                let mut entries = Vec::new();
                while !list.is_empty() {
                    entries.push(list.expect_raw(T_SEQUENCE).unwrap().to_vec());
                }
                extensions = Some(entries);
            } else {
                others.push(fields.tlv().unwrap().2.to_vec());
            }
        }
        edit(&mut version, &mut others, &mut extensions);
        let mut body = Vec::new();
        if let Some(v) = version {
            let mut integer = Vec::new();
            push_tlv(&mut integer, T_INTEGER, &v);
            push_tlv(&mut body, T_CTX0, &integer);
        }
        for field in others {
            body.extend_from_slice(&field);
        }
        if let Some(entries) = extensions {
            let mut list = Vec::new();
            push_tlv(&mut list, T_SEQUENCE, &entries.concat());
            push_tlv(&mut body, T_CTX3, &list);
        }
        let mut tbs = Vec::new();
        push_tlv(&mut tbs, T_SEQUENCE, &body);
        let signature = key
            .sign(parsed.signature_scheme().unwrap(), &tbs, &mut rng())
            .unwrap();
        let mut content = tbs;
        content.extend_from_slice(algorithm);
        let mut bits = alloc::vec![0];
        bits.extend_from_slice(&signature);
        push_tlv(&mut content, T_BIT_STRING, &bits);
        let mut der = Vec::new();
        push_tlv(&mut der, T_SEQUENCE, &content);
        der
    }

    fn extension_oid(entry: &[u8]) -> &[u8] {
        Der::new(entry)
            .nested(T_SEQUENCE)
            .unwrap()
            .expect(T_OID)
            .unwrap()
    }

    /// REQ-X509-011: RFC 5280 section 4.1.2.1 defines versions v1(0) to
    /// v3(2), and section 4.1.2.9 allows extensions only in v3. A higher
    /// version, or extensions under an implicit or explicit v1 or v2, are
    /// refused at parse time.
    #[test]
    fn unknown_versions_and_pre_v3_extensions_are_refused() {
        let mut r = rng();
        let key = SigningKey::generate(KeyKind::EcdsaP256, &mut r).unwrap();
        let original = self_signed(&params("Version fixture", &[], true), &key, &mut r).unwrap();
        Certificate::parse(&rebuild_tbs(&original, &key, |_, _, _| {})).unwrap();
        for version in [3u8, 4, 0x7f] {
            let e = Certificate::parse(&rebuild_tbs(&original, &key, |v, _, _| {
                *v = Some(alloc::vec![version])
            }))
            .unwrap_err();
            assert_eq!(e.kind(), ErrorKind::BadCertificate);
            assert_eq!(e.context(), "unknown certificate version");
        }
        for version in [None, Some(1u8)] {
            let e = Certificate::parse(&rebuild_tbs(&original, &key, |v, _, _| {
                *v = version.map(|n| alloc::vec![n])
            }))
            .unwrap_err();
            assert_eq!(e.kind(), ErrorKind::BadCertificate);
            assert_eq!(e.context(), "extensions in a certificate that is not v3");
        }
        // REQ-X509-077: an explicit v1, with or without extensions, is not
        // DER (the DEFAULT is omitted).
        for extensions in [true, false] {
            let e = Certificate::parse(&rebuild_tbs(&original, &key, |v, _, x| {
                *v = Some(alloc::vec![0]);
                if !extensions {
                    *x = None;
                }
            }))
            .unwrap_err();
            assert_eq!(e.context(), "explicitly encoded default version");
        }
        // Omitted, v1 without extensions still parses.
        Certificate::parse(&rebuild_tbs(&original, &key, |v, _, x| {
            *v = None;
            *x = None;
        }))
        .unwrap();
    }

    /// REQ-X509-014: an explicit Extensions field holds SEQUENCE SIZE
    /// (1..MAX) OF Extension (RFC 5280 section 4.1); an empty list is
    /// malformed, where omitting the field is not.
    #[test]
    fn an_empty_extensions_list_is_refused() {
        let mut r = rng();
        let key = SigningKey::generate(KeyKind::EcdsaP256, &mut r).unwrap();
        let original = self_signed(&params("Ext fixture", &[], true), &key, &mut r).unwrap();
        let e = Certificate::parse(&rebuild_tbs(&original, &key, |_, _, x| {
            *x = Some(Vec::new())
        }))
        .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::BadCertificate);
        assert_eq!(e.context(), "empty extensions list");
        let v3_without = rebuild_tbs(&original, &key, |_, _, x| *x = None);
        assert_eq!(
            Certificate::parse(&v3_without).unwrap().extension_count(),
            0
        );
    }

    /// REQ-X509-041: RFC 5280 section 4.2 forbids more than one instance of
    /// an extension; a repeated identifier is refused wherever the repeat
    /// sits, while the same entries once each are accepted in any order.
    #[test]
    fn a_repeated_extension_is_refused() {
        let mut r = rng();
        let key = SigningKey::generate(KeyKind::EcdsaP256, &mut r).unwrap();
        let original =
            self_signed(&params("dup", &["dup.example.com"], false), &key, &mut r).unwrap();
        let count = Certificate::parse(&original).unwrap().extension_count();
        for index in 0..count {
            for position in [0, index, count] {
                let duplicated = rebuild_tbs(&original, &key, |_, _, x| {
                    let entries = x.as_mut().unwrap();
                    let copy = entries[index].clone();
                    entries.insert(position, copy);
                });
                let e = Certificate::parse(&duplicated).unwrap_err();
                assert_eq!(e.kind(), ErrorKind::BadCertificate, "{index} at {position}");
                assert_eq!(e.context(), "duplicate extension");
            }
        }
        let reversed = rebuild_tbs(&original, &key, |_, _, x| x.as_mut().unwrap().reverse());
        assert_eq!(
            Certificate::parse(&reversed).unwrap().extension_count(),
            count
        );
    }

    /// REQ-X509-029: an iPAddress SAN is an OCTET STRING of four (IPv4) or
    /// sixteen (IPv6) octets (RFC 5280 section 4.2.1.6); any other length,
    /// including the eight- and thirty-two-octet constraint forms, is refused.
    #[test]
    fn ip_address_alternative_names_require_address_lengths() {
        let mut r = rng();
        let key = SigningKey::generate(KeyKind::EcdsaP256, &mut r).unwrap();
        let original =
            self_signed(&params("ip", &["ip.example.com"], false), &key, &mut r).unwrap();
        for len in [0usize, 1, 3, 4, 5, 8, 15, 16, 17, 32] {
            let cert = rebuild_tbs(&original, &key, |_, _, x| {
                for entry in x.as_mut().unwrap().iter_mut() {
                    if extension_oid(entry) == OID_EXT_SAN {
                        let mut names = Vec::new();
                        push_tlv(&mut names, T_GN_DNS, b"ip.example.com");
                        push_tlv(&mut names, T_GN_IP, &alloc::vec![7u8; len]);
                        let mut value = Vec::new();
                        push_tlv(&mut value, T_SEQUENCE, &names);
                        let mut replaced = Vec::new();
                        push_ext(&mut replaced, OID_EXT_SAN, false, &value);
                        *entry = replaced;
                    }
                }
            });
            match Certificate::parse(&cert) {
                Ok(c) => {
                    assert!(len == 4 || len == 16, "{len}");
                    assert_eq!(c.ip_addresses()[0].octets(), alloc::vec![7u8; len]);
                }
                Err(e) => {
                    assert!(len != 4 && len != 16, "{len}");
                    assert_eq!(e.kind(), ErrorKind::BadCertificate);
                    assert_eq!(e.context(), "iPAddress length");
                }
            }
        }
    }

    /// REQ-X509-003: the SAN accessors report each name in its own family:
    /// dNSName entries as text, iPAddress entries as IPv4 or IPv6 by length,
    /// and a certificate without a SAN has neither.
    #[test]
    fn alternative_name_accessors_separate_the_families() {
        let mut r = rng();
        let key = SigningKey::generate(KeyKind::EcdsaP256, &mut r).unwrap();
        // 65.66.67.68 is also the UTF-8 text "ABCD", and the DNS name is
        // sixteen octets long, so neither family can pass for the other.
        let ips = [
            IpAddr::V4([65, 66, 67, 68]),
            IpAddr::parse("2001:db8::1").unwrap(),
        ];
        let both = CertificateParams {
            ip_addresses: &ips,
            ..params("names", &["a.example.com", "abcd.example.org"], false)
        };
        let c = self_signed(&both, &key, &mut r).unwrap();
        let c = Certificate::parse(&c).unwrap();
        assert_eq!(c.dns_names(), ["a.example.com", "abcd.example.org"]);
        assert_eq!(c.ip_addresses(), ips);
        let only_v6 = CertificateParams {
            ip_addresses: &ips[1..],
            ..params("v6", &[], false)
        };
        let c = self_signed(&only_v6, &key, &mut r).unwrap();
        let c = Certificate::parse(&c).unwrap();
        assert!(c.dns_names().is_empty());
        assert_eq!(c.ip_addresses(), &ips[1..]);
        let ca = self_signed(&params("CA", &[], true), &key, &mut r).unwrap();
        let ca = Certificate::parse(&ca).unwrap();
        assert!(ca.ext.san.is_none());
        assert!(ca.dns_names().is_empty());
        assert!(ca.ip_addresses().is_empty());
    }

    /// REQ-X509-006: anyExtendedKeyUsage places no purpose restriction (RFC
    /// 5280 section 4.2.1.12), so a leaf asserting only it is accepted for
    /// either TLS role, by both validators.
    #[test]
    fn any_extended_key_usage_permits_either_role() {
        let p = pki([KeyKind::EcdsaP256; 3]);
        let mut r = rng();
        let lk = SigningKey::generate(KeyKind::EcdsaP256, &mut r).unwrap();
        let mut purposes = Vec::new();
        push_tlv(&mut purposes, T_OID, OID_ANY_EKU);
        let mut value = Vec::new();
        push_tlv(&mut value, T_SEQUENCE, &purposes);
        let mut ext = Vec::new();
        push_ext(&mut ext, OID_EXT_EKU, false, &value);
        let issuer = Certificate::parse(&p.int).unwrap();
        let leaf = build(
            &CertificateParams {
                usage: &[],
                ..params("any", &["any.example.com"], false)
            },
            lk.spki(),
            issuer.subject_der(),
            &key_identifier(issuer.spki_der()).unwrap(),
            &p.int_key,
            &mut r,
            &[ext],
        )
        .unwrap();
        for usage in [Usage::ServerAuth, Usage::ClientAuth] {
            let o = VerifyOptions::new(NOW, usage, ALL);
            verify_both(&leaf, &[&p.int], &p.roots, &o).unwrap();
        }
    }

    /// REQ-X509-006: keyCertSign and digitalSignature are demanded only when
    /// a KeyUsage extension is present (RFC 5280 section 4.2.1.3); an issuer
    /// and a leaf without one are accepted by both validators.
    #[test]
    fn absent_key_usage_does_not_restrict_either_role() {
        let p = pki([KeyKind::EcdsaP256; 3]);
        let drop_ku =
            |_: &mut Option<Vec<u8>>, _: &mut Vec<Vec<u8>>, x: &mut Option<Vec<Vec<u8>>>| {
                x.as_mut()
                    .unwrap()
                    .retain(|e| extension_oid(e) != OID_EXT_KU)
            };
        let int = rebuild_tbs(&p.int, &p.root_key, drop_ku);
        assert_eq!(Certificate::parse(&int).unwrap().ext.key_usage, None);
        let leaf = rebuild_tbs(&p.leaf, &p.int_key, drop_ku);
        assert_eq!(Certificate::parse(&leaf).unwrap().ext.key_usage, None);
        verify_both(&leaf, &[&int], &p.roots, &opts()).unwrap();
        verify_both(&leaf, &[&p.int], &p.roots, &opts()).unwrap();
        verify_both(&p.leaf, &[&int], &p.roots, &opts()).unwrap();
    }

    /// REQ-X509-013: RFC 5280 section 4.1.2.2 requires a positive serial, so
    /// an all-zero configured serial is issued as the minimal INTEGER 1, and
    /// a high first octet gains its sign padding.
    #[test]
    fn issued_serials_are_positive_minimal_integers() {
        let mut r = rng();
        let key = SigningKey::generate(KeyKind::EcdsaP256, &mut r).unwrap();
        let mut high = [0u8; 16];
        high[15] = 0x80;
        for (serial, expected) in [([0u8; 16], &[1u8][..]), (high, &[0, 0x80][..])] {
            let p = CertificateParams {
                serial,
                ..params("serial", &[], true)
            };
            let c = self_signed(&p, &key, &mut r).unwrap();
            assert_eq!(Certificate::parse(&c).unwrap().serial(), expected);
        }
    }

    /// REQ-X509-022: validity times are encoded with four-digit years, so the
    /// last representable second, 9999-12-31T23:59:59Z (RFC 5280 section
    /// 4.1.2.5), is issued and round-trips, and one second later is refused
    /// as invalid configuration.
    #[test]
    fn issued_validity_ends_at_year_9999() {
        let mut r = rng();
        let key = SigningKey::generate(KeyKind::EcdsaP256, &mut r).unwrap();
        let last = parse_time(T_GENERALIZED_TIME, b"99991231235959Z").unwrap();
        assert_eq!(last, 253_402_300_799);
        let p = |not_after| CertificateParams {
            not_after,
            ..params("far", &[], true)
        };
        let c = self_signed(&p(last), &key, &mut r).unwrap();
        assert_eq!(Certificate::parse(&c).unwrap().not_after(), last);
        for not_after in [last + 1, u64::MAX] {
            let e = self_signed(&p(not_after), &key, &mut r).unwrap_err();
            assert_eq!(e.kind(), ErrorKind::InvalidConfig);
            assert_eq!(e.context(), "certificate time beyond year 9999");
        }
    }

    /// REQ-X509-002, REQ-FIX-003: when every candidate issuer fails, the
    /// first specific reason is reported by both validators; a later
    /// candidate's different failure does not overwrite it.
    #[test]
    fn the_first_specific_path_failure_is_reported() {
        let p = pki([KeyKind::EcdsaP256; 3]);
        let mut r = rng();
        let expired = issue(
            &CertificateParams {
                not_before: NOW - 2 * DAY,
                not_after: NOW - DAY,
                ..params("Int", &[], true)
            },
            p.int_key.spki(),
            &p.root,
            &p.root_key,
            &mut r,
        )
        .unwrap();
        let not_ca = issue(
            &params("Int", &[], false),
            p.int_key.spki(),
            &p.root,
            &p.root_key,
            &mut r,
        )
        .unwrap();
        assert_eq!(
            err(verify_both(
                &p.leaf,
                &[&expired, &not_ca],
                &p.roots,
                &opts()
            )),
            ErrorKind::CertificateExpired
        );
        assert_eq!(
            err(verify_both(
                &p.leaf,
                &[&not_ca, &expired],
                &p.roots,
                &opts()
            )),
            ErrorKind::CertificateUsage
        );
    }

    /// `n` CA certificates named "Hub" under one key, each validly issuing the
    /// others, and a leaf that any of them could have issued.
    fn hub_graph(n: u8) -> (SigningKey, Vec<Vec<u8>>, Vec<u8>) {
        let mut r = rng();
        let hub_key = SigningKey::generate(KeyKind::EcdsaP256, &mut r).unwrap();
        let hub = self_signed(&params("Hub", &[], true), &hub_key, &mut r).unwrap();
        let hubs = (1..=n)
            .map(|i| {
                let params = CertificateParams {
                    serial: [i; 16],
                    ..params("Hub", &[], true)
                };
                issue(&params, hub_key.spki(), &hub, &hub_key, &mut r).unwrap()
            })
            .collect();
        let lk = SigningKey::generate(KeyKind::EcdsaP256, &mut r).unwrap();
        let leaf = issue(
            &params("l", &["l.example.com"], false),
            lk.spki(),
            &hub,
            &hub_key,
            &mut r,
        )
        .unwrap();
        (hub_key, hubs, leaf)
    }

    /// REQ-X509-002, REQ-FIX-003: seven hubs fit the fixed slots, and both
    /// validators exhaust the same budget among intermediate candidates.
    #[test]
    fn a_seven_slot_adversarial_graph_exhausts_both_budgets() {
        let p = pki([KeyKind::EcdsaP256; 3]);
        let (_, hubs, leaf) = hub_graph(7);
        let ints: Vec<&[u8]> = hubs.iter().map(|h| &h[..]).collect();
        let e = verify_both(&leaf, &ints, &p.roots, &opts()).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::UnknownCa, "{e}");
        assert_eq!(e.context(), "path search budget exhausted");
        let fixed = verify_chain_fixed(&leaf, &ints, &p.roots, &opts())
            .err()
            .unwrap();
        assert_eq!(fixed.context(), "path search budget exhausted");
    }

    /// REQ-X509-002, REQ-FIX-003: attempts at trust anchors draw on the same
    /// budget. An anchor with the hubs' name and key is tried at every step
    /// and always refused by its name constraints, so attempts alternate
    /// between anchor and intermediate and the budget runs out on an anchor
    /// attempt, in both validators.
    #[test]
    fn anchor_attempts_draw_on_the_search_budget() {
        let mut r = rng();
        let (hub_key, hubs, leaf) = hub_graph(7);
        let mut base = Vec::new();
        push_tlv(&mut base, T_GN_DNS, b"example.org");
        let mut subtree = Vec::new();
        push_tlv(&mut subtree, T_SEQUENCE, &base);
        let mut body = Vec::new();
        push_tlv(&mut body, T_CTX0, &subtree);
        let mut nc = Vec::new();
        push_tlv(&mut nc, T_SEQUENCE, &body);
        let mut ext = Vec::new();
        push_ext(&mut ext, OID_EXT_NC, true, &nc);
        let anchor = build(
            &params("Hub", &[], true),
            hub_key.spki(),
            &encode_name("Hub"),
            &key_identifier(hub_key.spki()).unwrap(),
            &hub_key,
            &mut r,
            &[ext],
        )
        .unwrap();
        let mut roots = RootStore::new();
        roots.add_der(&anchor).unwrap();
        assert_eq!(
            err(verify_both(&leaf, &[], &roots, &opts())),
            ErrorKind::CertificateUsage
        );
        let ints: Vec<&[u8]> = hubs.iter().map(|h| &h[..]).collect();
        let e = verify_both(&leaf, &ints, &roots, &opts()).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::UnknownCa, "{e}");
        assert_eq!(e.context(), "path search budget exhausted");
    }

    /// REQ-X509-002, REQ-FIX-003: candidates that cannot be the issuer are
    /// passed over without a signature check: the leaf itself when it names
    /// itself as issuer, and a same-named CA whose subject key identifier
    /// disagrees with the authority key identifier. Neither is reported as a
    /// bad issuer; the path is simply unknown.
    #[test]
    fn impossible_issuers_are_not_tried() {
        let p = pki([KeyKind::EcdsaP256; 3]);
        let mut r = rng();
        let key = SigningKey::generate(KeyKind::EcdsaP256, &mut r).unwrap();
        let own = self_signed(&params("self", &["self.example.com"], false), &key, &mut r).unwrap();
        assert_eq!(
            err(verify_both(&own, &[&own], &RootStore::new(), &opts())),
            ErrorKind::UnknownCa
        );
        let other = self_signed(&params("Int", &[], true), &key, &mut r).unwrap();
        assert_eq!(
            err(verify_both(&p.leaf, &[&other], &p.roots, &opts())),
            ErrorKind::UnknownCa
        );
        verify_both(&p.leaf, &[&other, &p.int], &p.roots, &opts()).unwrap();
    }

    /// REQ-FIX-003: a depth limit beyond the fixed search's eight slots is
    /// CapacityExceeded there, while the owned validator honours it.
    #[test]
    fn depth_limits_beyond_the_fixed_slots_are_refused() {
        let p = pki([KeyKind::EcdsaP256; 3]);
        let mut o = opts();
        o.max_depth = 9;
        assert_eq!(
            verify_chain_fixed(&p.leaf, &[&p.int], &p.roots, &o)
                .err()
                .map(|e| e.kind()),
            Some(ErrorKind::CapacityExceeded)
        );
        assert_eq!(
            verify_both(&p.leaf, &[&p.int], &p.roots, &o).unwrap().depth,
            2
        );
        o.max_depth = 8;
        verify_chain_fixed(&p.leaf, &[&p.int], &p.roots, &o).unwrap();
    }

    /// REQ-CRL-003, REQ-FIX-003: both validators check every certificate
    /// below the anchor against a CRL from its own issuer. A path is reported
    /// CRL-checked only when every link is covered; with require_crl, a
    /// missing CRL for any link, or no CRL store at all, is
    /// BadCertificateStatus.
    #[test]
    fn crls_cover_every_link_in_both_validators() {
        let p = pki([KeyKind::EcdsaP256; 3]);
        let mut r = rng();
        let leaf_crl =
            crl::build(&p.int, &p.int_key, &[], NOW - 60, NOW + 3600, 1, &mut r).unwrap();
        let int_crl =
            crl::build(&p.root, &p.root_key, &[], NOW - 60, NOW + 3600, 1, &mut r).unwrap();
        let mut both = crl::CrlStore::new();
        both.add_der(&leaf_crl).unwrap();
        both.add_der(&int_crl).unwrap();
        let mut leaf_only = crl::CrlStore::new();
        leaf_only.add_der(&leaf_crl).unwrap();
        let mut int_only = crl::CrlStore::new();
        int_only.add_der(&int_crl).unwrap();

        let mut o = opts();
        o.crls = Some(&both);
        assert!(
            verify_both(&p.leaf, &[&p.int], &p.roots, &o)
                .unwrap()
                .crl_checked
        );
        for partial in [&leaf_only, &int_only] {
            o.crls = Some(partial);
            o.require_crl = false;
            let report = verify_both(&p.leaf, &[&p.int], &p.roots, &o).unwrap();
            assert!(!report.crl_checked);
            o.require_crl = true;
            assert_eq!(
                err(verify_both(&p.leaf, &[&p.int], &p.roots, &o)),
                ErrorKind::BadCertificateStatus
            );
        }
        o.crls = None;
        assert_eq!(
            err(verify_both(&p.leaf, &[&p.int], &p.roots, &o)),
            ErrorKind::BadCertificateStatus
        );
        o.crls = Some(&both);
        assert!(
            verify_both(&p.leaf, &[&p.int], &p.roots, &o)
                .unwrap()
                .crl_checked
        );
    }

    /// REQ-X509-001: a bundle loads what it can. A block whose base64 or DER
    /// is broken is skipped, an unterminated block ends the scan, and a
    /// bundle that adds nothing to a store already holding anchors reports
    /// zero instead of failing.
    #[test]
    fn pem_bundles_skip_unusable_blocks() {
        let p = pki([KeyKind::EcdsaP256; 3]);
        let other = pki([KeyKind::EcdsaP256; 3]);
        let pem = |d: &[u8]| {
            let mut out = alloc::vec![0u8; d.len().div_ceil(3) * 4];
            ic_core::codec::base64_encode(d, &mut out).unwrap();
            alloc::format!(
                "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
                String::from_utf8(out).unwrap()
            )
        };
        let bad_base64 = "-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n";
        let bad_der = pem(&[0x30, 0x03, 0x02, 0x01, 0x00]);
        let unterminated = pem(&other.root).replace("-----END CERTIFICATE-----\n", "");
        let text = alloc::format!(
            "{}{bad_base64}{bad_der}{}{unterminated}",
            pem(&p.root),
            pem(&p.int)
        );
        let mut store = RootStore::new();
        assert_eq!(store.add_pem_bundle(&text).unwrap(), 2);
        assert_eq!(store.len(), 2);
        assert_eq!(store.add_pem_bundle(&pem(&p.root)).unwrap(), 0);
        assert_eq!(store.add_pem_bundle(bad_base64).unwrap(), 0);
        assert_eq!(store.len(), 2);
        for nothing in [bad_base64, bad_der.as_str(), unterminated.as_str()] {
            assert_eq!(
                RootStore::new().add_pem_bundle(nothing).unwrap_err().kind(),
                ErrorKind::InvalidConfig
            );
        }
    }

    /// REQ-FIX-003: certificates in the peer's list that do not parse are
    /// ignored by both validators, as `verify_chain` documents, wherever they
    /// sit; the fixed search reaches the same path instead of refusing.
    #[test]
    fn unparseable_extra_certificates_are_ignored_by_both_validators() {
        let p = pki([KeyKind::EcdsaP256; 3]);
        let truncated = &p.int[..p.int.len() - 1];
        for junk in [
            &[0x30, 0x00][..],
            &[0x30, 0x03, 0x02, 0x01, 0x00],
            truncated,
        ] {
            for ints in [[junk, &p.int[..]], [&p.int[..], junk]] {
                let report = verify_both(&p.leaf, &ints, &p.roots, &opts()).unwrap();
                assert_eq!(report.depth, 2);
                verify_chain_fixed(&p.leaf, &ints, &p.roots, &opts()).unwrap();
            }
        }
    }

    /// REQ-FIX-003, REQ-X509-006: both validators check a leaf's validity
    /// before its key usage, so a leaf that is expired and also lacks
    /// digitalSignature is refused for the same reason by each; a current one
    /// lacking it is a usage failure in both.
    #[test]
    fn leaf_checks_run_in_the_same_order_in_both_validators() {
        let p = pki([KeyKind::EcdsaP256; 3]);
        let mut r = rng();
        let lk = SigningKey::generate(KeyKind::EcdsaP256, &mut r).unwrap();
        let expired = issue(
            &CertificateParams {
                not_before: NOW - 2 * DAY,
                not_after: NOW - DAY,
                ..params("leaf", &["leaf.example.com"], false)
            },
            lk.spki(),
            &p.int,
            &p.int_key,
            &mut r,
        )
        .unwrap();
        // keyEncipherment (bit 2) only.
        let mut ku = Vec::new();
        push_tlv(&mut ku, T_BIT_STRING, &key_usage_bits(1 << 2));
        let mut entry = Vec::new();
        push_ext(&mut entry, OID_EXT_KU, true, &ku);
        let no_signing = |x: &mut Option<Vec<Vec<u8>>>| {
            for e in x.as_mut().unwrap().iter_mut() {
                if extension_oid(e) == OID_EXT_KU {
                    *e = entry.clone();
                }
            }
        };
        let expired = rebuild_tbs(&expired, &p.int_key, |_, _, x| no_signing(x));
        let current = rebuild_tbs(&p.leaf, &p.int_key, |_, _, x| no_signing(x));
        assert_eq!(
            err(verify_both(&expired, &[&p.int], &p.roots, &opts())),
            ErrorKind::CertificateExpired
        );
        assert_eq!(
            err(verify_both(&current, &[&p.int], &p.roots, &opts())),
            ErrorKind::CertificateUsage
        );
    }

    /// REQ-X509-008: name constraints apply to names of their own form (RFC
    /// 5280 section 4.2.1.10). Under DNS-only constraints, URI and rfc822Name
    /// SAN entries are outside their scope and passed over, while the
    /// dNSName beside them is still bound by them.
    #[test]
    fn other_name_forms_are_outside_dns_constraints() {
        let p = pki([KeyKind::EcdsaP256; 3]);
        let ca = constrained(&p, &[(T_GN_DNS, b"example.com")], &[]);
        let issuer = Certificate::parse(&ca.0).unwrap();
        let mut r = rng();
        let mut leaf_with = |dns: &str| {
            let lk = SigningKey::generate(KeyKind::EcdsaP256, &mut r).unwrap();
            let mut names = Vec::new();
            push_tlv(&mut names, 0x86, b"https://evil.org/");
            push_tlv(&mut names, 0x81, b"admin@evil.org");
            push_tlv(&mut names, T_GN_DNS, dns.as_bytes());
            let mut value = Vec::new();
            push_tlv(&mut value, T_SEQUENCE, &names);
            let mut ext = Vec::new();
            push_ext(&mut ext, OID_EXT_SAN, false, &value);
            build(
                &params("leaf", &[], false),
                lk.spki(),
                issuer.subject_der(),
                &key_identifier(issuer.spki_der()).unwrap(),
                &ca.1,
                &mut r,
                &[ext],
            )
            .unwrap()
        };
        let inside = leaf_with("a.example.com");
        let outside = leaf_with("a.evil.org");
        verify_both(&inside, &[&ca.0, &p.int], &p.roots, &opts()).unwrap();
        assert_eq!(
            err(verify_both(&outside, &[&ca.0, &p.int], &p.roots, &opts())),
            ErrorKind::CertificateUsage
        );
    }
}
