//! Exporters: JSON, JSON-LD, Turtle (RDF/OWL), JSON Schema and Markdown.
//!
//! JSON keys are camelCase throughout, matching the MCP server. Identifiers
//! with an `ic:` prefix resolve into IronCrypto's vocabulary, so a graph that
//! loads both ontologies joins them on `builtOn` edges without a mapping step.

use std::fmt::Write as _;
use std::string::String;

use crate::errors::{self, ErrorDoc};
use crate::profiles::{Profile, PROFILES};
use crate::select::{Intent, NoRecommendation, Recommendation, INTENTS};
use crate::types::{Constraint, Entry, FipsStatus, ImplStatus, Kind, Relation, Severity};
use crate::{related, REGISTRY};

/// The IRI every IronSocketLayer term lives under.
pub const VOCAB: &str = "https://nervosys.github.io/IronSocketLayer/ontology#";
/// IronCrypto's vocabulary IRI, which `ic:` identifiers expand into. It is the
/// `@vocab` and `@base` of IronCrypto's own JSON-LD export, so `ic:aes-128-gcm`
/// names the same node there and here.
pub const IC_VOCAB: &str = "https://nervosys.github.io/IronCrypto/ontology#";

/// Identifier prefixes, each mapped to its own IRI namespace.
pub const ID_PREFIXES: &[&str] = &[
    "version",
    "content",
    "message",
    "suite",
    "group",
    "sigscheme",
    "ext",
    "alert",
    "key-update",
    "error",
    "profile",
    "intent",
];

/// JSON-escape `s`, with quotes.
pub fn quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn str_array(items: &[&str]) -> String {
    let parts: Vec<String> = items.iter().map(|s| quote(s)).collect();
    format!("[{}]", parts.join(","))
}

fn constraint_json(c: &Constraint) -> String {
    format!(
        "{{\"id\":{},\"requirement\":{},\"consequence\":{},\"severity\":{}}}",
        quote(c.id),
        quote(c.requirement),
        quote(c.consequence),
        quote(c.severity.id())
    )
}

fn constraints_json(cs: &[Constraint]) -> String {
    let parts: Vec<String> = cs.iter().map(constraint_json).collect();
    format!("[{}]", parts.join(","))
}

/// camelCase form of a hyphenated term.
pub fn camel(term: &str) -> String {
    let mut out = String::new();
    let mut upper = false;
    for c in term.chars() {
        if c == '-' {
            upper = true;
        } else if upper {
            out.extend(c.to_uppercase());
            upper = false;
        } else {
            out.push(c);
        }
    }
    out
}

/// One entry as JSON, with relations in both directions.
pub fn entry_to_json(e: &Entry) -> String {
    let rel: Vec<String> = related(e.id)
        .iter()
        .map(|r| {
            format!(
                "{{\"relation\":{},\"direction\":{},\"target\":{}}}",
                quote(r.relation.id()),
                quote(r.direction.id()),
                quote(r.other)
            )
        })
        .collect();
    format!(
        "{{\"id\":{},\"name\":{},\"kind\":{},\"code\":{},\"codeHex\":{},\"summary\":{},\"status\":{},\"statusReason\":{},\"fipsStatus\":{},\"postQuantum\":{},\"strength\":{{\"classicalBits\":{},\"quantumBits\":{}}},\"standards\":{},\"constraints\":{},\"relations\":[{}],\"notes\":{}}}",
        quote(e.id),
        quote(e.name),
        quote(e.kind.id()),
        e.code,
        quote(&format!("0x{:04x}", e.code)),
        quote(e.summary),
        quote(e.status.id()),
        quote(e.status_reason),
        quote(e.fips.id()),
        e.post_quantum,
        e.strength.classical,
        e.strength.quantum,
        str_array(e.standards),
        constraints_json(e.constraints),
        rel.join(","),
        quote(e.notes)
    )
}

/// One error as JSON.
pub fn error_to_json(e: &ErrorDoc) -> String {
    format!(
        "{{\"id\":{},\"meaning\":{},\"recovery\":{},\"retryable\":{},\"callerCorrectable\":{},\"peerFault\":{},\"alert\":{}}}",
        quote(e.id),
        quote(e.meaning),
        str_array(e.recovery),
        e.retryable,
        e.caller_correctable,
        e.peer_fault,
        e.alert.map(quote).unwrap_or_else(|| "null".into())
    )
}

/// One profile as JSON.
pub fn profile_to_json(p: &Profile) -> String {
    format!(
        "{{\"id\":{},\"name\":{},\"summary\":{},\"status\":{},\"statusReason\":{},\"suites\":{},\"groups\":{},\"sigschemes\":{},\"mutualAuthRequired\":{},\"fipsGate\":{},\"postQuantumRequired\":{},\"minRsaBits\":{},\"rationale\":{},\"notes\":{}}}",
        quote(p.id),
        quote(p.name),
        quote(p.summary),
        quote(p.status.id()),
        quote(p.status_reason),
        str_array(p.suites),
        str_array(p.groups),
        str_array(p.sigschemes),
        p.mutual_auth_required,
        p.fips_gate,
        p.post_quantum_required,
        p.min_rsa_bits,
        quote(p.rationale),
        quote(p.notes)
    )
}

/// One intent as JSON.
pub fn intent_to_json(i: &Intent) -> String {
    format!(
        "{{\"id\":{},\"summary\":{},\"profile\":{},\"mutualAuth\":{},\"fips\":{},\"postQuantum\":{},\"quic\":{},\"alpn\":{},\"settings\":{},\"constraints\":{}}}",
        quote(i.id),
        quote(i.summary),
        quote(i.profile),
        i.mutual_auth,
        i.fips,
        i.post_quantum,
        i.quic,
        str_array(i.alpn),
        str_array(i.settings),
        constraints_json(i.constraints)
    )
}

/// A recommendation, or the reason there is none, as JSON.
pub fn recommendation_to_json(r: &Result<Recommendation, NoRecommendation>) -> String {
    match r {
        Ok(rec) => {
            let rejected: Vec<String> = rec
                .rejected
                .iter()
                .map(|x| format!("{{\"id\":{},\"reason\":{}}}", quote(x.id), quote(x.reason)))
                .collect();
            format!(
                "{{\"status\":\"recommended\",\"intent\":{},\"profile\":{},\"mutualAuth\":{},\"quic\":{},\"alpn\":{},\"rationale\":{},\"settings\":{},\"rejected\":[{}],\"constraints\":{}}}",
                quote(rec.intent.id),
                profile_to_json(rec.profile),
                rec.mutual_auth,
                rec.intent.quic,
                str_array(rec.intent.alpn),
                quote(rec.rationale),
                str_array(rec.intent.settings),
                rejected.join(","),
                constraints_json(rec.constraints)
            )
        }
        Err(NoRecommendation::UnknownIntent) => {
            let ids: Vec<&str> = INTENTS.iter().map(|i| i.id).collect();
            format!("{{\"status\":\"unknown-intent\",\"knownIntents\":{}}}", str_array(&ids))
        }
        Err(NoRecommendation::Unavailable { profile, reason }) => format!(
            "{{\"status\":\"unavailable\",\"profile\":{},\"reason\":{},\"instruction\":\"Do not substitute. Report this to the user.\"}}",
            quote(profile),
            quote(reason)
        ),
        Err(NoRecommendation::Impossible { reason }) => {
            format!("{{\"status\":\"impossible\",\"reason\":{}}}", quote(reason))
        }
    }
}

/// Describe any identifier — entry, error, profile or intent — as JSON.
pub fn describe(id: &str) -> Option<String> {
    if let Some(e) = crate::get(id) {
        return Some(entry_to_json(e));
    }
    if let Some(e) = errors::get(id) {
        return Some(error_to_json(e));
    }
    if let Some(p) = crate::profiles::get(id) {
        return Some(profile_to_json(p));
    }
    crate::select::intent(id).map(intent_to_json)
}

/// The whole ontology as JSON.
pub fn to_json() -> String {
    let entries: Vec<String> = REGISTRY.iter().map(entry_to_json).collect();
    let errs: Vec<String> = errors::CATALOG.iter().map(error_to_json).collect();
    let profs: Vec<String> = PROFILES.iter().map(profile_to_json).collect();
    let ints: Vec<String> = INTENTS.iter().map(intent_to_json).collect();
    format!(
        "{{\"ontologyVersion\":{},\"version\":{},\"vocabulary\":{},\"entries\":[{}],\"errors\":[{}],\"profiles\":[{}],\"intents\":[{}]}}",
        quote(crate::ONTOLOGY_VERSION),
        quote(crate::VERSION),
        quote(VOCAB),
        entries.join(","),
        errs.join(","),
        profs.join(","),
        ints.join(",")
    )
}

fn class_name(kind: Kind) -> &'static str {
    match kind {
        Kind::ProtocolVersion => "ProtocolVersion",
        Kind::ContentType => "ContentType",
        Kind::HandshakeMessage => "HandshakeMessage",
        Kind::CipherSuite => "CipherSuite",
        Kind::NamedGroup => "NamedGroup",
        Kind::SignatureScheme => "SignatureScheme",
        Kind::Extension => "Extension",
        Kind::Alert => "Alert",
        Kind::KeyUpdateRequest => "KeyUpdateRequest",
    }
}

/// The ontology as JSON-LD.
///
/// Each id prefix (`suite`, `group`, ...) is a JSON-LD prefix expanding under
/// [`VOCAB`], and `ic` expands under [`IC_VOCAB`]. Relations are node-valued,
/// so `builtOn` is a traversable edge.
pub fn to_json_ld() -> String {
    let mut out = String::from("{\"@context\":{");
    let _ = write!(out, "\"@vocab\":{},", quote(VOCAB));
    for p in ID_PREFIXES {
        let _ = write!(out, "{}:{},", quote(p), quote(&format!("{VOCAB}{p}:")));
    }
    let _ = write!(out, "\"ic\":{},", quote(IC_VOCAB));
    out.push_str("\"id\":\"@id\",\"entries\":{\"@id\":\"member\",\"@container\":\"@set\"},");
    for r in Relation::ALL {
        let _ = write!(
            out,
            "{}:{{\"@type\":\"@id\",\"@container\":\"@set\"}},",
            quote(&camel(r.id()))
        );
    }
    out.push_str("\"kind\":{\"@type\":\"@vocab\"},\"status\":{\"@type\":\"@vocab\"},\"fipsStatus\":{\"@type\":\"@vocab\"}");
    out.push_str("},\"@type\":\"ProtocolRegistry\",\"entries\":[");
    for (i, e) in REGISTRY.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        let _ = write!(
            out,
            "{{\"@type\":{},\"id\":{},\"name\":{},\"code\":{},\"summary\":{},\"kind\":{},\"status\":{},\"fipsStatus\":{},\"postQuantum\":{},\"classicalBits\":{},\"quantumBits\":{}",
            quote(class_name(e.kind)),
            quote(e.id),
            quote(e.name),
            e.code,
            quote(e.summary),
            quote(e.kind.id()),
            quote(e.status.id()),
            quote(e.fips.id()),
            e.post_quantum,
            e.strength.classical,
            e.strength.quantum
        );
        for r in Relation::ALL {
            let targets: Vec<&str> = e
                .edges
                .iter()
                .filter(|x| x.relation == *r)
                .map(|x| x.target)
                .collect();
            if !targets.is_empty() {
                let _ = write!(out, ",{}:{}", quote(&camel(r.id())), str_array(&targets));
            }
        }
        out.push('}');
    }
    out.push_str("]}");
    out
}

fn ttl_string(s: &str) -> String {
    // Turtle string escaping is JSON-compatible for the characters we emit.
    quote(s)
}

/// The ontology as RDF 1.1 Turtle with OWL class and property declarations.
pub fn to_turtle() -> String {
    let mut out = String::new();
    let _ = writeln!(out, "@prefix isl: <{VOCAB}> .");
    let _ = writeln!(out, "@prefix ic: <{IC_VOCAB}> .");
    for p in ID_PREFIXES {
        let _ = writeln!(out, "@prefix {p}: <{VOCAB}{p}:> .");
    }
    out.push_str("@prefix owl: <http://www.w3.org/2002/07/owl#> .\n");
    out.push_str("@prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> .\n");
    out.push_str("@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .\n\n");
    let _ = writeln!(
        out,
        "<{VOCAB}> a owl:Ontology ; owl:versionInfo {} ;",
        ttl_string(crate::ONTOLOGY_VERSION)
    );
    let _ = writeln!(out, "    rdfs:comment \"TLS 1.3 and QUIC-TLS protocol elements, profiles and errors for IronSocketLayer.\" .\n");
    out.push_str("isl:ProtocolElement a owl:Class .\n");
    for k in Kind::ALL {
        let _ = writeln!(
            out,
            "isl:{} a owl:Class ; rdfs:subClassOf isl:ProtocolElement .",
            class_name(*k)
        );
    }
    out.push_str(
        "isl:Profile a owl:Class .\nisl:Intent a owl:Class .\nisl:ErrorKind a owl:Class .\n",
    );
    for r in Relation::ALL {
        let _ = writeln!(out, "isl:{} a owl:ObjectProperty .", camel(r.id()));
    }
    for p in [
        "usesProfile",
        "offersSuite",
        "offersGroup",
        "offersSigscheme",
        "sendsAlert",
    ] {
        let _ = writeln!(out, "isl:{p} a owl:ObjectProperty .");
    }
    for p in [
        "code",
        "status",
        "fipsStatus",
        "postQuantum",
        "classicalBits",
        "quantumBits",
        "summary",
    ] {
        let _ = writeln!(out, "isl:{p} a owl:DatatypeProperty .");
    }
    out.push('\n');
    for e in REGISTRY {
        let _ = write!(
            out,
            "{} a isl:{} ;\n    rdfs:label {} ;\n    isl:summary {} ;\n    isl:code {} ;\n    isl:status {} ;\n    isl:fipsStatus {} ;\n    isl:postQuantum {} ;\n    isl:classicalBits {} ;\n    isl:quantumBits {}",
            e.id,
            class_name(e.kind),
            ttl_string(e.name),
            ttl_string(e.summary),
            e.code,
            ttl_string(e.status.id()),
            ttl_string(e.fips.id()),
            e.post_quantum,
            e.strength.classical,
            e.strength.quantum
        );
        for edge in e.edges {
            let _ = write!(
                out,
                " ;\n    isl:{} {}",
                camel(edge.relation.id()),
                edge.target
            );
        }
        out.push_str(" .\n");
    }
    for p in PROFILES {
        let _ = write!(
            out,
            "{} a isl:Profile ; rdfs:label {} ; isl:status {}",
            p.id,
            ttl_string(p.name),
            ttl_string(p.status.id())
        );
        for s in p.suites {
            let _ = write!(out, " ;\n    isl:offersSuite {s}");
        }
        for g in p.groups {
            let _ = write!(out, " ;\n    isl:offersGroup {g}");
        }
        for s in p.sigschemes {
            let _ = write!(out, " ;\n    isl:offersSigscheme {s}");
        }
        out.push_str(" .\n");
    }
    for i in INTENTS {
        let _ = writeln!(
            out,
            "{} a isl:Intent ; rdfs:comment {} ; isl:usesProfile {} .",
            i.id,
            ttl_string(i.summary),
            i.profile
        );
    }
    for e in errors::CATALOG {
        let _ = write!(
            out,
            "{} a isl:ErrorKind ; rdfs:comment {}",
            e.id,
            ttl_string(e.meaning)
        );
        if let Some(a) = e.alert {
            let _ = write!(out, " ;\n    isl:sendsAlert {a}");
        }
        out.push_str(" .\n");
    }
    out
}

fn enum_json(values: &[&str]) -> String {
    format!("{{\"type\":\"string\",\"enum\":{}}}", str_array(values))
}

/// A JSON Schema (2020-12) for the JSON export's entry objects.
pub fn to_json_schema() -> String {
    let kinds: Vec<&str> = Kind::ALL.iter().map(|k| k.id()).collect();
    let statuses: Vec<&str> = ImplStatus::ALL.iter().map(|s| s.id()).collect();
    let fips: Vec<&str> = FipsStatus::ALL.iter().map(|s| s.id()).collect();
    let sev: Vec<&str> = Severity::ALL.iter().map(|s| s.id()).collect();
    let rels: Vec<&str> = Relation::ALL.iter().map(|r| r.id()).collect();
    format!(
        concat!(
            "{{\"$schema\":\"https://json-schema.org/draft/2020-12/schema\",",
            "\"$id\":\"{vocab}schema\",\"title\":\"IronSocketLayer ontology entry\",\"type\":\"object\",",
            "\"required\":[\"id\",\"name\",\"kind\",\"code\",\"status\",\"fipsStatus\"],",
            "\"properties\":{{",
            "\"id\":{{\"type\":\"string\",\"pattern\":\"^[a-z-]+:[a-z0-9.-]+$\"}},",
            "\"name\":{{\"type\":\"string\"}},\"kind\":{kinds},\"code\":{{\"type\":\"integer\",\"minimum\":0,\"maximum\":65535}},",
            "\"codeHex\":{{\"type\":\"string\"}},\"summary\":{{\"type\":\"string\"}},\"status\":{statuses},\"statusReason\":{{\"type\":\"string\"}},",
            "\"fipsStatus\":{fips},\"postQuantum\":{{\"type\":\"boolean\"}},",
            "\"strength\":{{\"type\":\"object\",\"properties\":{{\"classicalBits\":{{\"type\":\"integer\"}},\"quantumBits\":{{\"type\":\"integer\"}}}}}},",
            "\"standards\":{{\"type\":\"array\",\"items\":{{\"type\":\"string\"}}}},",
            "\"constraints\":{{\"type\":\"array\",\"items\":{{\"type\":\"object\",\"required\":[\"id\",\"requirement\",\"consequence\",\"severity\"],\"properties\":{{\"id\":{{\"type\":\"string\"}},\"requirement\":{{\"type\":\"string\"}},\"consequence\":{{\"type\":\"string\"}},\"severity\":{sev}}}}}}},",
            "\"relations\":{{\"type\":\"array\",\"items\":{{\"type\":\"object\",\"properties\":{{\"relation\":{rels},\"direction\":{dirs},\"target\":{{\"type\":\"string\"}}}}}}}},",
            "\"notes\":{{\"type\":\"string\"}}}}}}"
        ),
        vocab = VOCAB,
        kinds = enum_json(&kinds),
        statuses = enum_json(&statuses),
        fips = enum_json(&fips),
        sev = enum_json(&sev),
        rels = enum_json(&rels),
        dirs = enum_json(&["outgoing", "incoming"]),
    )
}

/// Human-readable Markdown.
pub fn to_markdown() -> String {
    let mut out = String::from("# IronSocketLayer ontology\n\n");
    let _ = writeln!(
        out,
        "Ontology version {}. Generated from `isl-ontology`; do not edit by hand.\n",
        crate::ONTOLOGY_VERSION
    );
    for k in Kind::ALL {
        let _ = writeln!(
            out,
            "## {}\n\n| id | code | status | FIPS | PQ | summary |\n|---|---|---|---|---|---|",
            class_name(*k)
        );
        for e in REGISTRY.iter().filter(|e| e.kind == *k) {
            let _ = writeln!(
                out,
                "| `{}` | 0x{:04x} | {} | {} | {} | {} |",
                e.id,
                e.code,
                e.status.id(),
                e.fips.id(),
                if e.post_quantum { "yes" } else { "" },
                e.summary.replace('|', "\\|")
            );
        }
        out.push('\n');
    }
    out.push_str("## Profiles\n\n");
    for p in PROFILES {
        let _ = writeln!(
            out,
            "### `{}` — {} ({})\n\n{}\n",
            p.id,
            p.name,
            p.status.id(),
            p.summary
        );
        let _ = writeln!(out, "- suites: {}\n- groups: {}\n- signature schemes: {}\n- mutual auth required: {}\n- FIPS gate: {}\n\n{}\n", p.suites.join(", "), p.groups.join(", "), p.sigschemes.join(", "), p.mutual_auth_required, p.fips_gate, p.rationale);
        if !p.notes.is_empty() {
            let _ = writeln!(out, "> {}\n", p.notes);
        }
    }
    out.push_str("## Intents\n\n| id | profile | summary |\n|---|---|---|\n");
    for i in INTENTS {
        let _ = writeln!(out, "| `{}` | `{}` | {} |", i.id, i.profile, i.summary);
    }
    out.push_str("\n## Errors\n\n| id | alert | retryable | meaning |\n|---|---|---|---|\n");
    for e in errors::CATALOG {
        let _ = writeln!(
            out,
            "| `{}` | {} | {} | {} |",
            e.id,
            e.alert.unwrap_or("—"),
            e.retryable,
            e.meaning
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exports_are_well_formed_enough() {
        for s in [to_json(), to_json_ld(), to_json_schema()] {
            assert!(s.starts_with('{') && s.ends_with('}'));
            let opens = s.matches('{').count();
            let closes = s.matches('}').count();
            // Braces in string content are rare; the registry has none.
            assert_eq!(opens, closes);
        }
        let ttl = to_turtle();
        assert!(ttl.contains("suite:tls-aes-128-gcm-sha256 a isl:CipherSuite"));
        assert!(ttl.contains("isl:builtOn ic:aes-128-gcm"));
        assert!(to_markdown().contains("profile:dal-a"));
    }

    #[test]
    fn describe_covers_every_kind_of_id() {
        for id in crate::all_ids() {
            assert!(describe(id).is_some(), "{id}");
        }
        assert!(describe("nope").is_none());
    }

    #[test]
    fn camel_case() {
        assert_eq!(camel("built-on"), "builtOn");
        assert_eq!(camel("superseded-by"), "supersededBy");
    }
}
