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

use crate::crypto::sign::{self, push_tlv, PublicKey, SigningKey, OID_ML_DSA_65, OID_ML_DSA_87};
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
const SEARCH_BUDGET: usize = 100;

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
        let start = self.pos;
        let tag = self.byte()?;
        if tag & 0x1f == 0x1f {
            return Err(bad("high-tag-number DER form"));
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

fn small_uint(content: &[u8]) -> Result<u64> {
    if content.is_empty() || content[0] & 0x80 != 0 {
        return Err(bad("expected a non-negative INTEGER"));
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
    basic: Option<(bool, Option<u64>)>,
    key_usage: Option<u16>,
    eku: Option<&'a [u8]>,
    san: Option<&'a [u8]>,
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

impl<'a> Certificate<'a> {
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
                n
            }
            None => 0,
        };
        let serial = t.expect(T_INTEGER)?;
        if serial.is_empty() || serial.len() > 21 {
            return Err(bad("serial number length"));
        }
        let inner_alg = t.expect(T_SEQUENCE)?;
        if inner_alg != sig_alg {
            return Err(bad(
                "signature algorithm differs between TBS and certificate",
            ));
        }
        let issuer = t.expect_raw(T_SEQUENCE)?;
        let mut validity = t.nested(T_SEQUENCE)?;
        let (tag, nb, _) = validity.tlv()?;
        let not_before = parse_time(tag, nb)?;
        let (tag, na, _) = validity.tlv()?;
        let not_after = parse_time(tag, na)?;
        validity.finish()?;
        let subject = t.expect_raw(T_SEQUENCE)?;
        let spki = t.expect_raw(T_SEQUENCE)?;
        let _ = t.optional(T_ISSUER_UID)?;
        let _ = t.optional(T_SUBJECT_UID)?;
        let mut ext = Extensions::default();
        if let Some(e) = t.optional(T_CTX3)? {
            if version != 2 {
                return Err(bad("extensions in a certificate that is not v3"));
            }
            ext = parse_extensions(e)?;
        }
        t.finish()?;

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

fn parse_extensions(body: &[u8]) -> Result<Extensions<'_>> {
    let mut ext = Extensions::default();
    let mut list = Der::new(body).nested(T_SEQUENCE)?;
    let mut seen: Vec<&[u8]> = Vec::new();
    if list.is_empty() {
        return Err(bad("empty extensions list"));
    }
    while !list.is_empty() {
        let mut e = list.nested(T_SEQUENCE)?;
        let oid = e.expect(T_OID)?;
        let critical = match e.optional(T_BOOLEAN)? {
            Some([0xff]) => true,
            Some([0x00]) => false,
            Some(_) => return Err(bad("malformed BOOLEAN")),
            None => false,
        };
        let value = e.expect(T_OCTET_STRING)?;
        e.finish()?;
        if seen.contains(&oid) {
            return Err(bad("duplicate extension"));
        }
        seen.push(oid);
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
                let mut check = Der::new(body);
                while !check.is_empty() {
                    check.expect(T_OID)?;
                }
                ext.eku = Some(body);
            }
            OID_EXT_SAN => {
                let mut v = Der::new(value);
                let body = v.expect(T_SEQUENCE)?;
                v.finish()?;
                let mut check = Der::new(body);
                while !check.is_empty() {
                    let (tag, val, _) = check.tlv()?;
                    if tag == T_GN_DNS && (val.is_empty() || !val.is_ascii()) {
                        return Err(bad("dNSName is not ASCII"));
                    }
                    if tag == T_GN_IP && val.len() != 4 && val.len() != 16 {
                        return Err(bad("iPAddress length"));
                    }
                }
                ext.san = Some(body);
            }
            OID_EXT_NC => {
                let mut v = Der::new(value);
                let body = v.expect(T_SEQUENCE)?;
                v.finish()?;
                ext.name_constraints = Some(body);
            }
            OID_EXT_SKI => {
                let mut v = Der::new(value);
                ext.ski = Some(v.expect(T_OCTET_STRING)?);
                v.finish()?;
            }
            OID_EXT_AKI => {
                let mut v = Der::new(value);
                let mut s = v.nested(T_SEQUENCE)?;
                v.finish()?;
                // keyIdentifier [0] IMPLICIT OCTET STRING; issuer and serial
                // forms are accepted and ignored.
                ext.aki = s.optional(0x80)?;
            }
            OID_EXT_CP => {}
            _ => {
                if critical {
                    ext.unknown_critical = true;
                }
            }
        }
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

/// Map an `AlgorithmIdentifier` body to a scheme.
fn scheme_from_alg(alg: &[u8]) -> Result<SignatureScheme> {
    let unsupported = || {
        Error::new(
            ErrorKind::UnsupportedCertificate,
            "unsupported signature algorithm",
        )
    };
    let mut r = Der::new(alg);
    let oid = r.expect(T_OID)?;
    let scheme = match oid {
        OID_ECDSA_SHA256 => SignatureScheme::EcdsaSecp256r1Sha256,
        OID_ECDSA_SHA384 => SignatureScheme::EcdsaSecp384r1Sha384,
        OID_ECDSA_SHA512 => SignatureScheme::EcdsaSecp521r1Sha512,
        OID_ECDSA_SHA1 => SignatureScheme::EcdsaSha1,
        OID_ED25519 => SignatureScheme::Ed25519,
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
            halg.optional_null()?;
            halg.finish()?;
            let (scheme, salt_len) = pss_hash(hoid).ok_or_else(unsupported)?;
            let mut m = p.nested(T_CTX1)?;
            let mut malg = m.nested(T_SEQUENCE)?;
            m.finish()?;
            if malg.expect(T_OID)? != OID_MGF1 {
                return Err(unsupported());
            }
            let mut mh = malg.nested(T_SEQUENCE)?;
            malg.finish()?;
            if mh.expect(T_OID)? != hoid {
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
        self.anchors.push(Anchor {
            subject: cert.subject.to_vec(),
            spki: cert.spki.to_vec(),
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

/// Apply one `NameConstraints` body to the names of `subjects`.
fn apply_name_constraints(nc: &[u8], subjects: &[&Certificate<'_>]) -> Result<()> {
    let violation = || Error::new(ErrorKind::CertificateUsage, "name constraints violated");
    let unsupported = || {
        Error::new(
            ErrorKind::UnsupportedCertificate,
            "name constraint form not supported",
        )
    };
    let mut r = Der::new(nc);
    let mut permitted: Option<&[u8]> = None;
    let mut excluded: Option<&[u8]> = None;
    if let Some(p) = r.optional(T_CTX0)? {
        permitted = Some(p);
    }
    if let Some(e) = r.optional(T_CTX1)? {
        excluded = Some(e);
    }
    r.finish()?;

    // Collect (tag, base) pairs, failing closed on forms not evaluated here.
    let collect = |body: Option<&[u8]>| -> Result<Vec<(u8, Vec<u8>)>> {
        let mut out = Vec::new();
        let Some(body) = body else { return Ok(out) };
        let mut subtrees = Der::new(body);
        while !subtrees.is_empty() {
            let mut st = subtrees.nested(T_SEQUENCE)?;
            let (tag, base, _) = st.tlv()?;
            if !st.is_empty() {
                // minimum/maximum MUST be absent in this profile.
                return Err(unsupported());
            }
            match tag {
                T_GN_DNS if base.is_ascii() => out.push((tag, base.to_vec())),
                T_GN_IP if base.len() == 8 || base.len() == 32 => out.push((tag, base.to_vec())),
                _ => return Err(unsupported()),
            }
        }
        Ok(out)
    };
    let permitted = collect(permitted)?;
    let excluded = collect(excluded)?;

    for cert in subjects {
        let dns = cert.dns_names();
        let ips = cert.ip_addresses();
        let perm_dns: Vec<&str> = permitted
            .iter()
            .filter(|(t, _)| *t == T_GN_DNS)
            .filter_map(|(_, b)| core::str::from_utf8(b).ok())
            .collect();
        let perm_ip: Vec<&[u8]> = permitted
            .iter()
            .filter(|(t, _)| *t == T_GN_IP)
            .map(|(_, b)| &b[..])
            .collect();
        for name in &dns {
            if !perm_dns.is_empty() && !perm_dns.iter().any(|c| dns_within(name, c)) {
                return Err(violation());
            }
            for (t, b) in &excluded {
                if *t != T_GN_DNS {
                    continue;
                }
                let c = core::str::from_utf8(b).map_err(|_| unsupported())?;
                if dns_within(name, c) {
                    return Err(violation());
                }
                // A wildcard covers names below its suffix; an excluded subtree
                // inside that scope is a violation, conservatively.
                if let Some(suffix) = name.strip_prefix("*.") {
                    if dns_within(c.trim_start_matches('.'), suffix) {
                        return Err(violation());
                    }
                }
            }
        }
        for ip in &ips {
            let o = ip.octets();
            let applicable: Vec<&&[u8]> =
                perm_ip.iter().filter(|c| c.len() == 2 * o.len()).collect();
            if !applicable.is_empty() && !applicable.iter().any(|c| ip_within(o, c)) {
                return Err(violation());
            }
            for (t, b) in &excluded {
                if *t == T_GN_IP && ip_within(o, b) {
                    return Err(violation());
                }
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
    if best.map_or(true, |b| b.kind() == ErrorKind::UnknownCa) {
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
            if a.subject != current.issuer || key_ids_disagree(current, a.ski.as_deref()) {
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
            if suffix.split('.').count() < 2 {
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
    let ok = match name {
        ServerName::Dns(n) => cert.dns_names().iter().any(|p| dns_matches(p, n)),
        ServerName::Ip(ip) => cert.ip_addresses().iter().any(|a| a == ip),
    };
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
    /// Path length constraint, for CAs.
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

fn key_identifier(spki: &[u8]) -> Result<Vec<u8>> {
    // RFC 7093 §2 method 1: leftmost 160 bits of SHA-256 of the key bits.
    let mut outer = Der::new(spki);
    let mut s = outer.nested(T_SEQUENCE)?;
    let _ = s.expect(T_SEQUENCE)?;
    let key = s.expect(T_BIT_STRING)?;
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
pub fn self_signed(
    params: &CertificateParams<'_>,
    key: &SigningKey,
    rng: &mut dyn RandomSource,
) -> Result<Vec<u8>> {
    let name = encode_name(params.subject_cn);
    let ki = key_identifier(key.spki())?;
    build(params, key.spki(), &name, &ki, key, rng, &[])
}

/// Issue a certificate for `subject_spki`, signed by the holder of
/// `issuer_key`, whose certificate is `issuer_cert_der`.
pub fn issue(
    params: &CertificateParams<'_>,
    subject_spki: &[u8],
    issuer_cert_der: &[u8],
    issuer_key: &SigningKey,
    rng: &mut dyn RandomSource,
) -> Result<Vec<u8>> {
    let issuer = Certificate::parse(issuer_cert_der)?;
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

#[cfg(test)]
mod tests {
    use super::*;

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
}

#[cfg(all(test, feature = "std"))]
mod chain_tests {
    use super::*;
    use crate::crypto::sign::KeyKind;

    const NOW: u64 = 1_800_000_000;
    const DAY: u64 = 86_400;

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
            let report = verify_chain(&p.leaf, &[&p.int], &p.roots, &opts()).unwrap();
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
        let report = verify_chain(&p.leaf, &[&p.int], &p.roots, &opts()).unwrap();
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
        let report = verify_chain(&leaf, &[], &roots, &opts()).unwrap();
        assert_eq!(report.min_classical_bits, 112);
        let mut strict = opts();
        strict.min_rsa_bits = 3072;
        assert_eq!(
            err(verify_chain(&leaf, &[], &roots, &strict)),
            ErrorKind::PolicyViolation
        );
    }

    #[test]
    fn validity_is_checked_at_every_level() {
        let p = pki([KeyKind::EcdsaP256; 3]);
        let mut o = opts();
        o.now = NOW + 400 * DAY;
        assert_eq!(
            err(verify_chain(&p.leaf, &[&p.int], &p.roots, &o)),
            ErrorKind::CertificateExpired
        );
        o.now = NOW - 2 * DAY;
        assert_eq!(
            err(verify_chain(&p.leaf, &[&p.int], &p.roots, &o)),
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
            err(verify_chain(&leaf, &[&int], &roots, &opts())),
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
            err(verify_chain(
                &victim,
                &[&fake_ca, &p.int],
                &p.roots,
                &opts()
            )),
            ErrorKind::CertificateUsage
        );
        // And a CA certificate cannot serve as an end entity.
        assert_eq!(
            err(verify_chain(&p.int, &[], &p.roots, &opts())),
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
            err(verify_chain(&leaf, &[&int2, &int1], &roots, &opts())),
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
            verify_chain(&leaf2, &[&int1], &roots, &opts())
                .unwrap()
                .depth,
            2
        );
        // The depth limit binds too.
        let mut shallow = opts();
        shallow.max_depth = 2;
        assert_eq!(
            err(verify_chain(&leaf, &[&int2, &int1], &roots, &shallow)),
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
            err(verify_chain(&leaf, &[&p.int], &p.roots, &opts())),
            ErrorKind::BadCertificate
        );
        let mut int = p.int.clone();
        let n = int.len();
        int[n - 2] ^= 0x10;
        assert_eq!(
            err(verify_chain(&p.leaf, &[&int], &p.roots, &opts())),
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

    #[test]
    fn unknown_critical_extensions_fail_closed() {
        let p = pki([KeyKind::EcdsaP256; 3]);
        let unknown_oid = [0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x99, 0x01];
        let mut crit = Vec::new();
        push_ext(&mut crit, &unknown_oid, true, &[0x05, 0x00]);
        let (leaf, _) = with_extra(crit.clone(), &p.int, &p.int_key, false);
        assert_eq!(
            err(verify_chain(&leaf, &[&p.int], &p.roots, &opts())),
            ErrorKind::UnsupportedCertificate
        );
        let mut non = Vec::new();
        push_ext(&mut non, &unknown_oid, false, &[0x05, 0x00]);
        let (leaf, _) = with_extra(non, &p.int, &p.int_key, false);
        verify_chain(&leaf, &[&p.int], &p.roots, &opts()).unwrap();
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
            err(verify_chain(&leaf, &[&int2, &p.int], &p.roots, &opts())),
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
        verify_chain(&good, &[&int2, &p.int], &p.roots, &opts()).unwrap();
        let evil = issue(
            &params("e", &["evil.org"], false),
            lk.spki(),
            &int2,
            &k2,
            &mut r,
        )
        .unwrap();
        assert_eq!(
            err(verify_chain(&evil, &[&int2, &p.int], &p.roots, &opts())),
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
            err(verify_chain(&leaf, &[&int3, &p.int], &p.roots, &opts())),
            ErrorKind::UnsupportedCertificate
        );
    }

    #[test]
    fn schemes_outside_the_policy_are_refused() {
        let p = pki([KeyKind::EcdsaP256; 3]);
        let o = VerifyOptions::new(NOW, Usage::ServerAuth, &[SignatureScheme::Ed25519]);
        assert_eq!(
            err(verify_chain(&p.leaf, &[&p.int], &p.roots, &o)),
            ErrorKind::PolicyViolation
        );
    }

    #[test]
    fn extended_key_usage_must_permit_the_use() {
        let p = pki([KeyKind::EcdsaP256; 3]);
        let o = VerifyOptions::new(NOW, Usage::ClientAuth, ALL);
        assert_eq!(
            err(verify_chain(&p.leaf, &[&p.int], &p.roots, &o)),
            ErrorKind::CertificateUsage
        );
    }

    #[test]
    fn an_unknown_ca_is_reported_as_such() {
        let p = pki([KeyKind::EcdsaP256; 3]);
        let other = pki([KeyKind::EcdsaP256; 3]);
        assert_eq!(
            err(verify_chain(&p.leaf, &[&p.int], &other.roots, &opts())),
            ErrorKind::UnknownCa
        );
        assert_eq!(
            err(verify_chain(&p.leaf, &[], &p.roots, &opts())),
            ErrorKind::UnknownCa
        );
        assert_eq!(
            err(verify_chain(&p.leaf, &[&p.int], &RootStore::new(), &opts())),
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
            err(verify_chain(&leaf, &ints, &RootStore::new(), &opts())),
            ErrorKind::UnknownCa
        );
        // With B trusted, the same pool yields a path.
        let mut roots = RootStore::new();
        roots.add_der(&b_self).unwrap();
        verify_chain(&leaf, &ints, &roots, &opts()).unwrap();
    }

    #[test]
    fn a_pinned_self_signed_leaf_is_accepted() {
        let mut r = rng();
        let key = SigningKey::generate(KeyKind::Ed25519, &mut r).unwrap();
        let cert =
            self_signed(&params("agent-7", &["agent-7.local"], false), &key, &mut r).unwrap();
        let mut roots = RootStore::new();
        roots.add_der(&cert).unwrap();
        let report = verify_chain(&cert, &[], &roots, &opts()).unwrap();
        assert_eq!(report.depth, 0);
        assert_eq!(
            err(verify_chain(&cert, &[], &RootStore::new(), &opts())),
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
}
