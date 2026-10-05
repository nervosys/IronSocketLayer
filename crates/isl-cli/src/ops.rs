//! Operations shared by the command line and the MCP server.
//!
//! Every command is implemented once, here, returning JSON. The CLI's `--json`
//! output and the MCP tool results are the same values, so an agent that
//! learned one interface has learned the other.

use ic_json::{parse, Json};
use isl_ontology::{export, ImplStatus, Kind, Policy};

/// Parse JSON produced by the ontology exporters.
///
/// The exporters are ours, so a parse failure is a bug; it is still reported
/// as an error rather than a panic.
pub fn json_of(s: &str) -> Result<Json, String> {
    parse(s).map_err(|e| format!("internal: exporter produced invalid JSON: {e}"))
}

fn strs(items: &[&str]) -> Json {
    Json::Array(items.iter().map(|s| Json::str(*s)).collect())
}

/// Resolve a possibly unprefixed id, trying every known prefix.
pub fn resolve_id(id: &str) -> Option<String> {
    if export::describe(id).is_some() {
        return Some(id.to_string());
    }
    for p in export::ID_PREFIXES {
        let full = format!("{p}:{id}");
        if export::describe(&full).is_some() {
            return Some(full);
        }
    }
    None
}

/// `ontology list`.
pub fn ontology_list(kind: Option<&str>) -> Result<Json, String> {
    let kind = match kind {
        None => None,
        Some(k) => Some(Kind::from_id(k).ok_or_else(|| {
            let known: Vec<&str> = Kind::ALL.iter().map(|k| k.id()).collect();
            format!("unknown kind '{k}'; expected one of: {}", known.join(", "))
        })?),
    };
    let items = isl_ontology::all()
        .filter(|e| kind.is_none_or(|k| e.kind == k))
        .map(|e| {
            Json::object([
                ("id", Json::str(e.id)),
                ("name", Json::str(e.name)),
                ("kind", Json::str(e.kind.id())),
                ("code", Json::num(e.code)),
                ("status", Json::str(e.status.id())),
                ("fipsStatus", Json::str(e.fips.id())),
                ("postQuantum", Json::Bool(e.post_quantum)),
                ("summary", Json::str(e.summary)),
            ])
        })
        .collect();
    Ok(Json::Array(items))
}

/// `ontology show`.
pub fn ontology_show(id: &str) -> Result<Json, String> {
    let full =
        resolve_id(id).ok_or_else(|| format!("no ontology entry '{id}'; try `ontology list`"))?;
    json_of(&export::describe(&full).unwrap_or_default())
}

/// `ontology related`.
pub fn ontology_related(id: &str) -> Result<Json, String> {
    let full = if id.starts_with(isl_ontology::IC_PREFIX) {
        id.to_string()
    } else {
        resolve_id(id).ok_or_else(|| format!("no ontology entry '{id}'"))?
    };
    let items = isl_ontology::related(&full)
        .into_iter()
        .map(|r| {
            Json::object([
                ("relation", Json::str(r.relation.id())),
                ("direction", Json::str(r.direction.id())),
                ("target", Json::str(r.other)),
            ])
        })
        .collect();
    Ok(Json::object([
        ("id", Json::str(full)),
        ("relations", Json::Array(items)),
    ]))
}

/// `recommend`.
///
/// "unavailable" and "impossible" are answers, not failures: they come back
/// as successful results whose `status` says so, because the agent must act on
/// them (tell the user) rather than retry.
pub fn recommend(
    intent: &str,
    fips: bool,
    post_quantum: bool,
    mutual: bool,
) -> Result<Json, String> {
    let policy = Policy {
        require_fips: fips,
        require_post_quantum: post_quantum,
        require_mutual_auth: mutual,
    };
    let r = isl_ontology::recommend(intent, &policy);
    json_of(&export::recommendation_to_json(&r))
}

/// `explain`.
pub fn explain_error(id: &str) -> Result<Json, String> {
    let full = if id.starts_with("error:") {
        id.to_string()
    } else {
        format!("error:{id}")
    };
    let doc = isl_ontology::errors::get(&full).ok_or_else(|| {
        format!(
            "no error '{id}'; known errors: {}",
            isl_ontology::errors::CATALOG
                .iter()
                .map(|e| e.id)
                .collect::<Vec<_>>()
                .join(", ")
        )
    })?;
    json_of(&export::error_to_json(doc))
}

/// `profiles`.
pub fn profiles() -> Result<Json, String> {
    let items: Result<Vec<Json>, String> = isl_ontology::PROFILES
        .iter()
        .map(|p| json_of(&export::profile_to_json(p)))
        .collect();
    Ok(Json::Array(items?))
}

fn implemented(kind: Kind) -> Json {
    Json::Array(
        isl_ontology::by_kind(kind)
            .filter(|e| e.status == ImplStatus::Implemented)
            .map(|e| Json::str(e.id))
            .collect(),
    )
}

/// What DO-178C status to report. Deliberately blunt, like IronCrypto's FIPS
/// statement: an agent reading this must not be able to conclude that
/// anything is certified.
pub const DO178C_STATEMENT: &str = "IronSocketLayer is not DO-178C certified at any design assurance level. \
It provides a restricted profile (profile:dal-a), requirement identifiers traced to code and tests, \
no unsafe code, and no panics on peer input, to support a certification effort. DO-178C approval is \
granted to a specific airborne system by a certification authority on the evidence produced for that system.";

/// `capabilities`.
pub fn capabilities() -> Result<Json, String> {
    let planned: Vec<Json> = isl_ontology::all()
        .filter(|e| e.status == ImplStatus::Planned)
        .map(|e| {
            Json::object([
                ("id", Json::str(e.id)),
                ("reason", Json::str(e.status_reason)),
            ])
        })
        .collect();
    Ok(Json::object([
        ("library", Json::str("iron-socket-layer")),
        ("version", Json::str(isl_ontology::VERSION)),
        ("ontologyVersion", Json::str(isl_ontology::ONTOLOGY_VERSION)),
        ("protocolVersions", implemented(Kind::ProtocolVersion)),
        ("quic", Json::object([
            ("tls", Json::Bool(true)),
            ("versions", strs(&["quic-v1 (RFC 9000/9001)", "quic-v2 (RFC 9369)"])),
            ("note", Json::str("IronSocketLayer supplies QUIC-TLS: handshake, per-level keys, packet and header protection. The QUIC transport (streams, loss recovery, congestion control) is out of scope.")),
        ])),
        ("cipherSuites", implemented(Kind::CipherSuite)),
        ("namedGroups", implemented(Kind::NamedGroup)),
        ("signatureSchemes", implemented(Kind::SignatureScheme)),
        ("extensions", implemented(Kind::Extension)),
        ("planned", Json::Array(planned)),
        ("cryptography", Json::str("IronCrypto (every primitive; nothing is implemented in IronSocketLayer)")),
        ("fipsValidated", Json::Bool(false)),
        ("fipsModuleState", Json::str(ic_fips::state().id())),
        ("fipsValidationStatement", Json::str(ic_fips::VALIDATION_STATEMENT)),
        ("do178cCertified", Json::Bool(false)),
        ("do178cStatement", Json::str(DO178C_STATEMENT)),
    ]))
}

/// `selftest`: run IronCrypto's pre-operational self-tests.
pub fn selftest() -> Result<Json, String> {
    match ic_fips::initialize() {
        Ok(report) => Ok(Json::object([
            ("passed", Json::num(report.passed as f64)),
            ("failed", Json::num(report.failed as f64)),
            ("allPassed", Json::Bool(report.all_passed())),
            ("state", Json::str(ic_fips::state().id())),
            (
                "outcomes",
                Json::Array(
                    report
                        .outcomes
                        .iter()
                        .map(|o| {
                            Json::object([
                                ("algorithm", Json::str(o.algorithm)),
                                ("passed", Json::Bool(o.passed)),
                            ])
                        })
                        .collect(),
                ),
            ),
        ])),
        Err(e) => Err(format!(
            "self-test failed: {e}; the module is latched in its error state"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_resolve_with_or_without_prefix() {
        assert_eq!(
            resolve_id("x25519mlkem768").as_deref(),
            Some("group:x25519mlkem768")
        );
        assert_eq!(
            resolve_id("profile:dal-a").as_deref(),
            Some("profile:dal-a")
        );
        assert!(resolve_id("nonsense").is_none());
    }

    #[test]
    fn capabilities_deny_validation_and_certification() {
        let c = capabilities().unwrap();
        assert_eq!(
            c.get("fipsValidated").and_then(|v| v.as_bool()),
            Some(false)
        );
        assert_eq!(
            c.get("do178cCertified").and_then(|v| v.as_bool()),
            Some(false)
        );
        assert!(c
            .get("fipsValidationStatement")
            .and_then(|v| v.as_str())
            .unwrap()
            .contains("NOT"));
    }

    #[test]
    fn recommend_answers_fips_and_post_quantum_with_cnsa2() {
        let r = recommend("intent:https-client", true, true, false).unwrap();
        assert_eq!(
            r.get("status").and_then(|v| v.as_str()),
            Some("recommended")
        );
        assert!(r.to_string().contains("profile:cnsa-2"), "{r}");
        // A refusal is an answer, not an error, with the instruction not to
        // substitute. No profile is unavailable in this build, so the
        // rendering is checked on a constructed refusal.
        let refusal: Result<isl_ontology::select::Recommendation, _> =
            Err(isl_ontology::select::NoRecommendation::Unavailable {
                profile: "profile:example",
                reason: "needs an algorithm this build lacks",
            });
        let r = json_of(&export::recommendation_to_json(&refusal)).unwrap();
        assert_eq!(
            r.get("status").and_then(|v| v.as_str()),
            Some("unavailable")
        );
        assert!(r.to_string().contains("Do not substitute"));
        let r = recommend("intent:agent-to-agent-mtls", false, false, false).unwrap();
        assert_eq!(
            r.get("status").and_then(|v| v.as_str()),
            Some("recommended")
        );
    }
}
