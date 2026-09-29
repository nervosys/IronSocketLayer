//! Intents and the selector: from what an agent is trying to do to a profile.
//!
//! The property that matters most is the one IronCrypto's selector has: never
//! substitute something the caller did not ask for. When no available profile
//! meets every stated requirement the answer is [`NoRecommendation`], with the
//! reason, and never the closest thing that is available.

use crate::profiles::{self, Profile, ProfileStatus};
use crate::types::{Constraint, Severity};

/// A deployment situation an agent can name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Intent {
    /// Stable identifier, `intent:` prefixed.
    pub id: &'static str,
    /// One sentence.
    pub summary: &'static str,
    /// The profile chosen when no policy flag says otherwise.
    pub profile: &'static str,
    /// Whether the intent inherently needs mutual authentication.
    pub mutual_auth: bool,
    /// Whether the intent inherently needs FIPS.
    pub fips: bool,
    /// Whether the intent inherently needs post-quantum key exchange.
    pub post_quantum: bool,
    /// Whether the transport is QUIC rather than TCP.
    pub quic: bool,
    /// ALPN protocols to configure, most preferred first.
    pub alpn: &'static [&'static str],
    /// Settings an agent must configure beyond the profile.
    pub settings: &'static [&'static str],
    /// Rules for this situation.
    pub constraints: &'static [Constraint],
}

const fn rule(
    id: &'static str,
    requirement: &'static str,
    consequence: &'static str,
    severity: Severity,
) -> Constraint {
    Constraint {
        id,
        requirement,
        consequence,
        severity,
    }
}

const VERIFY_NAME: Constraint = rule(
    "verify-server-name",
    "Always pass the server's DNS name and let IronSocketLayer verify the certificate against it; never install a verifier that accepts everything.",
    "Without name verification any holder of any certificate from a trusted CA can impersonate the server.",
    Severity::Critical,
);
const PIN_ROOTS: Constraint = rule(
    "private-trust-anchor",
    "Trust only the private CA that issues agent identities, not the public web roots.",
    "Public roots let any web CA mint an identity your agents accept.",
    Severity::Critical,
);
const AUTHZ: Constraint = rule(
    "authorize-after-authenticate",
    "Map the authenticated peer certificate to an identity and authorise each request against it.",
    "mTLS proves who the peer is, not what it may do.",
    Severity::Serious,
);
const CLOSE: Constraint = rule(
    "send-close-notify",
    "Close with close_notify and treat an unannounced end of stream as truncation.",
    "A response cut short can look complete to the application.",
    Severity::Serious,
);
const NO_FALLBACK: Constraint = rule(
    "no-downgrade-on-failure",
    "On handshake failure report the error; do not retry with a weaker profile.",
    "Automatic fallback is the downgrade attack.",
    Severity::Critical,
);

/// Every intent.
pub static INTENTS: &[Intent] = &[
    Intent { id: "intent:https-client", summary: "Call HTTPS APIs on the public Internet.", profile: "profile:default", mutual_auth: false, fips: false, post_quantum: false, quic: false, alpn: &["h2", "http/1.1"], settings: &["Load the platform or a curated root store.", "Set the server name."], constraints: &[VERIFY_NAME, CLOSE, NO_FALLBACK] },
    Intent { id: "intent:api-server", summary: "Serve an HTTPS API to arbitrary clients.", profile: "profile:default", mutual_auth: false, fips: false, post_quantum: false, quic: false, alpn: &["h2", "http/1.1"], settings: &["Configure a certificate chain and its private key.", "Rotate certificates before expiry."], constraints: &[CLOSE] },
    Intent { id: "intent:agent-to-agent-mtls", summary: "Authenticated channel between autonomous agents, both sides holding identities from a private CA.", profile: "profile:post-quantum", mutual_auth: true, fips: false, post_quantum: true, quic: false, alpn: &["a2a/1"], settings: &["Issue each agent a short-lived certificate from a private CA.", "Configure client and server certificate verification against that CA only."], constraints: &[PIN_ROOTS, AUTHZ, NO_FALLBACK] },
    Intent { id: "intent:mcp-transport", summary: "Carry Model Context Protocol traffic (streamable HTTP) between an agent host and tool servers.", profile: "profile:post-quantum", mutual_auth: true, fips: false, post_quantum: true, quic: false, alpn: &["h2", "http/1.1"], settings: &["Authenticate tool servers by certificate; authenticate hosts by client certificate or by a token bound to the TLS session."], constraints: &[VERIFY_NAME, AUTHZ, CLOSE] },
    Intent { id: "intent:quic-client", summary: "HTTP/3 or other QUIC client.", profile: "profile:default", mutual_auth: false, fips: false, post_quantum: false, quic: true, alpn: &["h3"], settings: &["Supply QUIC transport parameters.", "Install per-level keys as the handshake yields them."], constraints: &[VERIFY_NAME, rule("amplification-budget", "Keep ClientHello within one Initial packet where possible; large hybrid key shares can need two.", "Servers may drop or delay a ClientHello split across packets.", Severity::Advisory)] },
    Intent { id: "intent:quic-server", summary: "HTTP/3 or other QUIC server.", profile: "profile:default", mutual_auth: false, fips: false, post_quantum: false, quic: true, alpn: &["h3"], settings: &["Supply QUIC transport parameters.", "Respect the 3x anti-amplification limit before address validation."], constraints: &[rule("cert-size", "Keep the certificate chain small (ECDSA over RSA or ML-DSA) so the server flight fits the amplification budget.", "Over-budget flights stall until the client's address is validated.", Severity::Advisory)] },
    Intent { id: "intent:fips-regulated", summary: "Deployment that must use FIPS 140-3 approved algorithms (FedRAMP, CMMC, healthcare, finance).", profile: "profile:fips-140-3", mutual_auth: false, fips: true, post_quantum: false, quic: false, alpn: &[], settings: &["Call ic_fips::initialize() and ic_fips::set_mode(Approved) at startup.", "Record that IronCrypto is not CMVP-validated in your compliance documentation."], constraints: &[NO_FALLBACK, rule("no-validation-claim", "Do not describe the deployment as using a FIPS-validated module.", "IronCrypto has no CMVP certificate; the claim would be false.", Severity::Critical)] },
    Intent { id: "intent:harvest-now-decrypt-later", summary: "Traffic that must stay confidential after large quantum computers exist.", profile: "profile:post-quantum", mutual_auth: false, fips: false, post_quantum: true, quic: false, alpn: &[], settings: &["Refuse classical-only sessions; do not accept a fallback to x25519."], constraints: &[NO_FALLBACK] },
    Intent { id: "intent:avionics-dal-a", summary: "Safety-critical airborne software where DO-178C DAL-A objectives apply.", profile: "profile:dal-a", mutual_auth: true, fips: true, post_quantum: false, quic: false, alpn: &[], settings: &["Use the no_std build with a caller-supplied DRBG and clock.", "Provision device certificates at manufacture.", "Produce system-level DO-178C evidence; IronSocketLayer supplies requirement IDs and tests, not a certification."], constraints: &[NO_FALLBACK, rule("no-certification-claim", "Do not describe IronSocketLayer as DO-178C certified.", "Certification is granted to a system by an authority; no such certification exists.", Severity::Critical)] },
    Intent { id: "intent:embedded-constrained", summary: "Microcontroller or other memory-constrained device.", profile: "profile:cnsa-1", mutual_auth: true, fips: false, post_quantum: false, quic: false, alpn: &[], settings: &["Use the no_std build.", "Pre-provision a single device certificate and trust anchor."], constraints: &[rule("single-parameter-set", "Offer exactly one suite and one group.", "Every extra option costs code size and handshake bytes.", Severity::Advisory)] },
];

/// Look up an intent by id. The `intent:` prefix is optional.
pub fn intent(id: &str) -> Option<&'static Intent> {
    INTENTS
        .iter()
        .find(|i| i.id == id || i.id.strip_prefix("intent:") == Some(id))
}

/// Requirements the caller states on top of the intent.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Policy {
    /// Approved algorithms only, through the FIPS gate.
    pub require_fips: bool,
    /// Post-quantum key exchange only.
    pub require_post_quantum: bool,
    /// Both sides authenticate.
    pub require_mutual_auth: bool,
}

/// A profile that was considered and not chosen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rejected {
    /// The profile.
    pub id: &'static str,
    /// Why not.
    pub reason: &'static str,
}

/// A choice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Recommendation {
    /// The intent it answers.
    pub intent: &'static Intent,
    /// The profile to use.
    pub profile: &'static Profile,
    /// Whether mutual authentication must be configured.
    pub mutual_auth: bool,
    /// Why this profile.
    pub rationale: &'static str,
    /// What else was considered.
    pub rejected: alloc::vec::Vec<Rejected>,
    /// Rules to honour: the intent's.
    pub constraints: &'static [Constraint],
}

/// Why there is no answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoRecommendation {
    /// The intent id is not known.
    UnknownIntent,
    /// The right profile exists but is not implemented in this build. Do not
    /// substitute.
    Unavailable {
        /// The profile that would be correct.
        profile: &'static str,
        /// Why it cannot be used.
        reason: &'static str,
    },
    /// No profile satisfies every requirement at once.
    Impossible {
        /// Which requirements conflict.
        reason: &'static str,
    },
}

impl NoRecommendation {
    /// Stable identifier.
    pub const fn id(&self) -> &'static str {
        match self {
            Self::UnknownIntent => "unknown-intent",
            Self::Unavailable { .. } => "unavailable",
            Self::Impossible { .. } => "impossible",
        }
    }
}

fn meets(p: &Profile, fips: bool, pq: bool) -> bool {
    (!fips || p.fips_gate) && (!pq || p.post_quantum_required || pq_first(p))
}

/// A profile whose first-choice group is post-quantum satisfies a PQ
/// requirement only if every group is PQ; `profile:fips-140-3` is not, so
/// this is strict.
fn pq_first(p: &Profile) -> bool {
    p.groups.iter().all(|g| {
        matches!(
            *g,
            "group:x25519mlkem768"
                | "group:secp256r1mlkem768"
                | "group:mlkem768"
                | "group:mlkem1024"
                | "group:secp384r1mlkem1024"
        )
    })
}

/// Recommend a profile for `intent_id` under `policy`.
///
/// Never returns a profile that fails a stated requirement, and never returns
/// an unavailable one.
pub fn recommend(intent_id: &str, policy: &Policy) -> Result<Recommendation, NoRecommendation> {
    let it = intent(intent_id).ok_or(NoRecommendation::UnknownIntent)?;
    let fips = policy.require_fips || it.fips;
    let pq = policy.require_post_quantum || it.post_quantum;
    let mutual = policy.require_mutual_auth || it.mutual_auth;

    let base = profiles::get(it.profile).ok_or(NoRecommendation::UnknownIntent)?;
    let chosen: &'static Profile;
    let rationale: &'static str;

    if meets(base, fips, pq) {
        chosen = base;
        rationale = base.rationale;
    } else if fips && pq {
        // Every approved-and-post-quantum profile needs ML-KEM-1024 (CNSA 2.0)
        // or accepts classical groups; neither meets both requirements.
        let cnsa2 = profiles::get("profile:cnsa-2").ok_or(NoRecommendation::UnknownIntent)?;
        return Err(NoRecommendation::Unavailable { profile: cnsa2.id, reason: "FIPS and post-quantum-only together need an approved profile whose every group is post-quantum. profile:fips-140-3 also accepts classical groups, and profile:cnsa-2 (ML-KEM-1024, ML-DSA-87) is not implemented. Do not substitute: either accept profile:fips-140-3 with SecP256r1MLKEM768 preferred but not required, or use a validated module that implements CNSA 2.0." });
    } else if fips {
        chosen = profiles::get("profile:fips-140-3").ok_or(NoRecommendation::UnknownIntent)?;
        rationale = "A FIPS requirement was stated, so the intent's usual profile is replaced by profile:fips-140-3, which offers approved algorithms only.";
    } else {
        chosen = profiles::get("profile:post-quantum").ok_or(NoRecommendation::UnknownIntent)?;
        rationale = "A post-quantum requirement was stated, so only hybrid or pure ML-KEM groups are offered.";
    }
    if chosen.status == ProfileStatus::Unavailable {
        return Err(NoRecommendation::Unavailable {
            profile: chosen.id,
            reason: chosen.status_reason,
        });
    }
    if chosen.id == "profile:dal-a" && !mutual {
        return Err(NoRecommendation::Impossible {
            reason: "profile:dal-a requires mutual authentication.",
        });
    }

    let mut rejected = alloc::vec::Vec::new();
    for p in profiles::PROFILES {
        if p.id == chosen.id {
            continue;
        }
        let reason = if p.status == ProfileStatus::Unavailable {
            p.status_reason
        } else if fips && !p.fips_gate {
            "Admits algorithms that are not FIPS-approved."
        } else if pq && !pq_first(p) {
            "Accepts classical-only key exchange."
        } else if p.id == "profile:dal-a" {
            "Narrower than needed: a single parameter set chosen to reduce certification scope, which costs interoperability."
        } else if p.id == "profile:cnsa-1" {
            "Classical only and a single parameter set; chosen only where CNSA 1.0 is mandated."
        } else {
            "Meets the requirements but is less suited to this intent than the chosen profile."
        };
        rejected.push(Rejected { id: p.id, reason });
    }

    Ok(Recommendation {
        intent: it,
        profile: chosen,
        mutual_auth: mutual || chosen.mutual_auth_required,
        rationale,
        rejected,
        constraints: it.constraints,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_intent_names_a_profile() {
        for i in INTENTS {
            assert!(profiles::get(i.profile).is_some(), "{}", i.id);
            assert!(i.id.starts_with("intent:"));
        }
    }

    #[test]
    fn a_requirement_is_never_dropped() {
        for i in INTENTS {
            for fips in [false, true] {
                for pq in [false, true] {
                    let pol = Policy {
                        require_fips: fips,
                        require_post_quantum: pq,
                        require_mutual_auth: false,
                    };
                    if let Ok(r) = recommend(i.id, &pol) {
                        assert_eq!(r.profile.status, ProfileStatus::Available);
                        if fips || i.fips {
                            assert!(r.profile.fips_gate, "{} fips", i.id);
                        }
                        if pq || i.post_quantum {
                            assert!(pq_first(r.profile), "{} pq", i.id);
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn fips_and_post_quantum_together_is_unavailable_not_substituted() {
        let pol = Policy {
            require_fips: true,
            require_post_quantum: true,
            require_mutual_auth: false,
        };
        match recommend("intent:https-client", &pol) {
            Err(NoRecommendation::Unavailable { profile, .. }) => {
                assert_eq!(profile, "profile:cnsa-2")
            }
            other => panic!("expected unavailable, got {other:?}"),
        }
    }

    #[test]
    fn unknown_intent() {
        assert_eq!(
            recommend("intent:nope", &Policy::default()).unwrap_err(),
            NoRecommendation::UnknownIntent
        );
        assert!(recommend("https-client", &Policy::default()).is_ok());
    }
}
