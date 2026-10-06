//! The FIPS 140-3 gate, and the security properties a session achieved.
//!
//! IronSocketLayer does not implement cryptography, so it has no cryptographic
//! module boundary of its own: the module is IronCrypto's (`ic_fips`). What
//! this crate owes FIPS 140-3 is discipline at the call sites — never use an
//! algorithm the module has not approved while a FIPS profile is in force, and
//! report the service indicator for what was used. [`fips_gate`] enforces the
//! first at configuration time; every connection re-checks the negotiated
//! algorithms (the module can latch into its error state at any time) and
//! records the indicators in its report.
//!
//! **IronCrypto is not CMVP-validated**, and neither is anything built on it.
//! [`VALIDATION_STATEMENT`] says so, and every report carries `validated: false`.

use alloc::vec::Vec;

use crate::config::Common;
use crate::crypto::{kx, sign};
use crate::enums::{CipherSuite, NamedGroup, SignatureScheme};
use crate::error::{Error, ErrorKind, Result};
use crate::record::suite_params;

/// Statement of certification status, for humans and agents that ask.
pub const VALIDATION_STATEMENT: &str =
    "IronSocketLayer enforces the FIPS 140-3 operational discipline of \
IronCrypto's module (approved-mode gate, self-tests, service indicators) on every algorithm a TLS \
or QUIC session uses. Neither IronCrypto nor IronSocketLayer has been validated by the CMVP, and \
neither holds a DO-178C certification; the DAL-A profile and life-cycle data are designed to \
support a certification effort by an applicant, not to substitute for one.";

/// Bring IronCrypto's module up in approved mode: run the pre-operational
/// self-tests, then select approved mode. Idempotent.
pub fn enable_fips() -> Result<ic_fips::SelfTestReport> {
    let report = ic_fips::initialize()
        .map_err(|_| Error::new(ErrorKind::FipsModule, "IronCrypto self-tests failed"))?;
    ic_fips::set_mode(ic_fips::Mode::Approved)
        .map_err(|_| Error::new(ErrorKind::FipsModule, "could not enter approved mode"))?;
    Ok(report)
}

/// IronCrypto identifiers a suite uses.
pub fn suite_ic_ids(suite: CipherSuite) -> Vec<&'static str> {
    match suite_params(suite) {
        Some((aead, hash)) => alloc::vec![
            aead.ic_id(),
            hash.ic_hash_id(),
            hash.ic_hmac_id(),
            hash.ic_hkdf_id()
        ],
        None => Vec::new(),
    }
}

fn check(id: &str) -> Result<ic_fips::ServiceIndicator> {
    ic_fips::check(id).map_err(|e| match e.kind() {
        ic_core::ErrorKind::NotApprovedInFipsMode => Error::new(
            ErrorKind::PolicyViolation,
            "algorithm not approved by the FIPS module",
        ),
        _ => Error::new(
            ErrorKind::FipsModule,
            "FIPS module not operational; call ironsocketlayer::policy::enable_fips()",
        ),
    })
}

/// The configuration-time gate. `REQ-CFG-003`.
pub fn fips_gate(c: &Common) -> Result<()> {
    if ic_fips::mode() != Some(ic_fips::Mode::Approved) {
        return Err(Error::new(
            ErrorKind::FipsModule,
            "FIPS profile requires IronCrypto's module in approved mode; call ironsocketlayer::policy::enable_fips()",
        ));
    }
    for s in &c.suites {
        for id in suite_ic_ids(*s) {
            check(id)?;
        }
    }
    for g in &c.groups {
        for id in kx::ic_ids(*g) {
            check(id)?;
        }
    }
    for s in &c.schemes {
        let id = sign::ic_id(*s).ok_or(Error::new(ErrorKind::InvalidConfig, "unknown scheme"))?;
        check(id)?;
    }
    Ok(())
}

/// Service indicators for the algorithms a session negotiated.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Indicators {
    /// `(ic algorithm id, indicator id)` pairs.
    pub entries: Vec<(&'static str, &'static str)>,
}

impl Indicators {
    /// Whether every entry is `approved` or `approved-as-component`.
    pub fn all_approved(&self) -> bool {
        !self.entries.is_empty() && self.entries.iter().all(|(_, i)| *i != "not-approved")
    }
}

/// Re-check the negotiated algorithms at use, returning their indicators.
///
/// With `enforce`, a non-approved algorithm is an error. Without it, the
/// indicators are still gathered when the module is operational so an agent
/// can see what it would have got.
pub fn session_indicators(
    suite: CipherSuite,
    group: NamedGroup,
    schemes: &[SignatureScheme],
    enforce: bool,
) -> Result<Indicators> {
    let mut ids: Vec<&'static str> = suite_ic_ids(suite);
    ids.extend_from_slice(kx::ic_ids(group));
    let mut unknown: Vec<&'static str> = Vec::new();
    for s in schemes {
        match sign::ic_id(*s) {
            Some(id) => ids.push(id),
            None => unknown.push(s.id()),
        }
    }
    // A scheme the module has no identifier for cannot be approved: refuse
    // it under enforcement, and report it rather than drop it otherwise.
    if enforce && !unknown.is_empty() {
        return Err(Error::new(
            ErrorKind::PolicyViolation,
            "signature scheme unknown to the FIPS module",
        ));
    }
    let mut out = Indicators::default();
    if !enforce && ic_fips::mode().is_none() {
        return Ok(out);
    }
    for id in unknown {
        out.entries.push((id, "not-approved"));
    }
    for id in ids {
        match ic_fips::check(id) {
            Ok(ind) => out.entries.push((id, ind.id())),
            Err(_) if !enforce => out.entries.push((id, "not-approved")),
            Err(_) => {
                check(id)?;
            }
        }
    }
    Ok(out)
}
