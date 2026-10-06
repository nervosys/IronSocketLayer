//! `isl`: the IronSocketLayer command line and MCP server.
//!
//! Every command prints text for people and, with `--json`, the same JSON the
//! MCP server returns for the matching tool.

#![forbid(unsafe_code)]
#![warn(clippy::all)]

mod mcp;
mod net;
mod offline;
mod ops;

use ic_json::Json;
use std::process::ExitCode;

const USAGE: &str = "\
isl — IronSocketLayer: agentic-first TLS 1.3 and QUIC-TLS over IronCrypto

USAGE:
    isl ontology list [--kind <kind>] [--json]
    isl ontology show <id> [--json]
    isl ontology related <id> [--json]
    isl ontology export --format json|jsonld|turtle|schema|markdown
    isl recommend <intent> [--fips] [--post-quantum] [--mutual] [--json]
    isl explain <error-id> [--json]
    isl profiles [--json]
    isl capabilities [--json]
    isl selftest [--json]
    isl probe <host[:port]> [--profile <p>] [--alpn h2,http/1.1] [--ech] [--json]
    isl serve --cert <chain.pem> --key <pkcs8.pem> [--bind 127.0.0.1] [--port 8443] [--profile <p>] [--alpn ..] [--once]
    isl inspect <cert.pem> [--json]
    isl verify <chain.pem> --roots <roots.pem> [--name <host>] [--client] [--json]
    isl check-config <config.json|-> [--json]
    isl mcp

Kinds: protocol-version, content-type, handshake-message, cipher-suite,
       named-group, signature-scheme, extension, alert, key-update-request
Intents: run `isl recommend help`.
";

struct Args {
    positional: Vec<String>,
    flags: Vec<String>,
    options: Vec<(String, String)>,
}

impl Args {
    fn parse(raw: Vec<String>) -> Args {
        let mut a = Args {
            positional: Vec::new(),
            flags: Vec::new(),
            options: Vec::new(),
        };
        let mut it = raw.into_iter();
        while let Some(s) = it.next() {
            if let Some(name) = s.strip_prefix("--") {
                if matches!(
                    name,
                    "kind"
                        | "format"
                        | "profile"
                        | "alpn"
                        | "cert"
                        | "key"
                        | "port"
                        | "bind"
                        | "roots"
                        | "name"
                ) {
                    let v = it.next().unwrap_or_default();
                    a.options.push((name.to_string(), v));
                } else {
                    a.flags.push(name.to_string());
                }
            } else {
                a.positional.push(s);
            }
        }
        a
    }

    fn flag(&self, name: &str) -> bool {
        self.flags.iter().any(|f| f == name)
    }

    fn option(&self, name: &str) -> Option<&str> {
        self.options
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    fn pos(&self, i: usize) -> Option<&str> {
        self.positional.get(i).map(|s| s.as_str())
    }
}

fn s<'a>(j: &'a Json, k: &str) -> &'a str {
    j.get(k).and_then(|v| v.as_str()).unwrap_or("")
}

/// A scalar field for display: strings as they are, numbers and booleans
/// written out, anything else empty.
fn show(j: &Json, k: &str) -> String {
    match j.get(k) {
        Some(Json::String(v)) => v.clone(),
        Some(Json::Number(n)) => format!("{n}"),
        Some(Json::Bool(v)) => v.to_string(),
        _ => String::new(),
    }
}

fn b(j: &Json, k: &str) -> bool {
    j.get(k).and_then(|v| v.as_bool()).unwrap_or(false)
}

fn arr<'a>(j: &'a Json, k: &str) -> &'a [Json] {
    j.get(k).and_then(|v| v.as_array()).unwrap_or(&[])
}

fn str_list(j: &Json, k: &str) -> String {
    arr(j, k)
        .iter()
        .filter_map(|v| v.as_str())
        .collect::<Vec<_>>()
        .join(", ")
}

fn print_constraints(j: &Json) {
    let cs = arr(j, "constraints");
    if cs.is_empty() {
        return;
    }
    println!("\nconstraints:");
    for c in cs {
        println!(
            "  [{}] {}\n      {}",
            s(c, "severity"),
            s(c, "requirement"),
            s(c, "consequence")
        );
    }
}

fn render_entry(j: &Json) {
    if j.get("meaning").is_some() {
        // An error.
        println!("{}\n{}\n", s(j, "id"), s(j, "meaning"));
        println!("  action:             {}", s(j, "action"));
        println!("  retryable:          {}", b(j, "retryable"));
        println!("  caller correctable: {}", b(j, "callerCorrectable"));
        println!("  peer fault:         {}", b(j, "peerFault"));
        println!(
            "  alert sent:         {}",
            j.get("alert").and_then(|v| v.as_str()).unwrap_or("none")
        );
        println!("\nrecovery:");
        for (i, step) in arr(j, "recovery").iter().enumerate() {
            println!("  {}. {}", i + 1, step.as_str().unwrap_or(""));
        }
    } else if j.get("fipsGate").is_some() {
        render_profile(j);
    } else if j.get("settings").is_some() {
        println!("{}\n{}\n", s(j, "id"), s(j, "summary"));
        println!("  profile:      {}", s(j, "profile"));
        println!(
            "  mutual auth:  {}\n  fips:         {}\n  post-quantum: {}\n  quic:         {}",
            b(j, "mutualAuth"),
            b(j, "fips"),
            b(j, "postQuantum"),
            b(j, "quic")
        );
        println!("  alpn:         {}", str_list(j, "alpn"));
        println!("\nsettings:");
        for st in arr(j, "settings") {
            println!("  - {}", st.as_str().unwrap_or(""));
        }
        print_constraints(j);
    } else {
        println!("{} ({})\n{}\n", s(j, "name"), s(j, "id"), s(j, "summary"));
        println!("  kind:       {}", s(j, "kind"));
        println!("  code:       {}", s(j, "codeHex"));
        let st = s(j, "status");
        let reason = s(j, "statusReason");
        println!(
            "  status:     {st}{}",
            if reason.is_empty() {
                String::new()
            } else {
                format!(" — {reason}")
            }
        );
        println!("  fips:       {}", s(j, "fipsStatus"));
        println!("  pq:         {}", b(j, "postQuantum"));
        if let Some(st) = j.get("strength") {
            let c = st
                .get("classicalBits")
                .and_then(|v| v.as_i64())
                .unwrap_or(0);
            let q = st.get("quantumBits").and_then(|v| v.as_i64()).unwrap_or(0);
            if c > 0 {
                println!("  strength:   {c} bits classical, {q} bits quantum");
            }
        }
        println!("  standards:  {}", str_list(j, "standards"));
        print_constraints(j);
        let rel = arr(j, "relations");
        if !rel.is_empty() {
            println!("\nrelations:");
            for r in rel {
                let arrow = if s(r, "direction") == "outgoing" {
                    "->"
                } else {
                    "<-"
                };
                println!("  {} {arrow} {}", s(r, "relation"), s(r, "target"));
            }
        }
        let notes = s(j, "notes");
        if !notes.is_empty() {
            println!("\nnotes: {notes}");
        }
    }
}

fn render_profile(p: &Json) {
    println!("{} — {} [{}]", s(p, "id"), s(p, "name"), s(p, "status"));
    println!("  {}", s(p, "summary"));
    if !s(p, "statusReason").is_empty() {
        println!("  unavailable: {}", s(p, "statusReason"));
    }
    println!("  suites:      {}", str_list(p, "suites"));
    println!("  groups:      {}", str_list(p, "groups"));
    println!("  sigschemes:  {}", str_list(p, "sigschemes"));
    println!(
        "  mutual auth required: {}   fips gate: {}   post-quantum required: {}",
        b(p, "mutualAuthRequired"),
        b(p, "fipsGate"),
        b(p, "postQuantumRequired")
    );
    println!("  rationale:   {}", s(p, "rationale"));
    if !s(p, "notes").is_empty() {
        println!("  note:        {}", s(p, "notes"));
    }
}

fn render_recommendation(r: &Json) {
    match s(r, "status") {
        "recommended" => {
            let p = r.get("profile").cloned().unwrap_or(Json::Null);
            println!("use: {}", s(&p, "id"));
            println!("  {}", s(r, "rationale"));
            println!(
                "  suites:     {}\n  groups:     {}\n  sigschemes: {}",
                str_list(&p, "suites"),
                str_list(&p, "groups"),
                str_list(&p, "sigschemes")
            );
            println!(
                "  mutual auth: {}   quic: {}   alpn: {}",
                b(r, "mutualAuth"),
                b(r, "quic"),
                str_list(r, "alpn")
            );
            if !arr(r, "settings").is_empty() {
                println!("\nconfigure:");
                for st in arr(r, "settings") {
                    println!("  - {}", st.as_str().unwrap_or(""));
                }
            }
            print_constraints(r);
            println!("\nconsidered and rejected:");
            for x in arr(r, "rejected") {
                println!("  {}: {}", s(x, "id"), s(x, "reason"));
            }
        }
        "unavailable" => {
            println!(
                "unavailable: {}\n  {}\n  Do not substitute. Report this to the user.",
                s(r, "profile"),
                s(r, "reason")
            );
        }
        "impossible" => println!("impossible: {}", s(r, "reason")),
        _ => println!(
            "unknown intent; known intents: {}",
            str_list(r, "knownIntents")
        ),
    }
}

fn emit(result: Result<Json, String>, json: bool, render: impl FnOnce(&Json)) -> ExitCode {
    match result {
        Ok(v) => {
            if json {
                println!("{v}");
            } else {
                render(&v);
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            if json {
                println!("{}", Json::object([("error", Json::str(e))]));
            } else {
                eprintln!("error: {e}");
            }
            ExitCode::from(2)
        }
    }
}

fn run(args: Args) -> ExitCode {
    let json = args.flag("json");
    match (args.pos(0), args.pos(1)) {
        (Some("ontology"), Some("list")) => {
            emit(ops::ontology_list(args.option("kind")), json, |v| {
                for e in v.as_array().unwrap_or(&[]) {
                    println!(
                        "{:<44} {:<12} {:<13} {}",
                        s(e, "id"),
                        s(e, "status"),
                        s(e, "fipsStatus"),
                        if b(e, "postQuantum") { "pq" } else { "" }
                    );
                }
            })
        }
        (Some("ontology"), Some("show")) => match args.pos(2) {
            Some(id) => emit(ops::ontology_show(id), json, render_entry),
            None => usage_error("ontology show needs an id"),
        },
        (Some("ontology"), Some("related")) => match args.pos(2) {
            Some(id) => emit(ops::ontology_related(id), json, |v| {
                for r in arr(v, "relations") {
                    let arrow = if s(r, "direction") == "outgoing" {
                        "->"
                    } else {
                        "<-"
                    };
                    println!(
                        "{} {} {arrow} {}",
                        s(v, "id"),
                        s(r, "relation"),
                        s(r, "target")
                    );
                }
            }),
            None => usage_error("ontology related needs an id"),
        },
        (Some("ontology"), Some("export")) => {
            let out = match args.option("format").unwrap_or("json") {
                "json" => isl_ontology::export::to_json(),
                "jsonld" | "json-ld" => isl_ontology::export::to_json_ld(),
                "turtle" | "ttl" | "owl" => isl_ontology::export::to_turtle(),
                "schema" | "json-schema" => isl_ontology::export::to_json_schema(),
                "markdown" | "md" => isl_ontology::export::to_markdown(),
                other => return usage_error(&format!("unknown format '{other}'")),
            };
            println!("{out}");
            ExitCode::SUCCESS
        }
        (Some("recommend"), intent) => {
            let intent = match intent {
                Some(i) if i != "help" => i,
                _ => {
                    for i in isl_ontology::INTENTS {
                        println!("{:<36} {}", i.id, i.summary);
                    }
                    return ExitCode::SUCCESS;
                }
            };
            emit(
                ops::recommend(
                    intent,
                    args.flag("fips"),
                    args.flag("post-quantum"),
                    args.flag("mutual"),
                ),
                json,
                render_recommendation,
            )
        }
        (Some("explain"), Some(id)) => emit(ops::explain_error(id), json, render_entry),
        (Some("profiles"), _) => emit(ops::profiles(), json, |v| {
            for p in v.as_array().unwrap_or(&[]) {
                render_profile(p);
                println!();
            }
        }),
        (Some("capabilities"), _) => emit(ops::capabilities(), json, |v| {
            println!(
                "ironsocketlayer {} (ontology {})",
                s(v, "version"),
                s(v, "ontologyVersion")
            );
            println!("  versions:   {}", str_list(v, "protocolVersions"));
            println!("  suites:     {}", str_list(v, "cipherSuites"));
            println!("  groups:     {}", str_list(v, "namedGroups"));
            println!("  sigschemes: {}", str_list(v, "signatureSchemes"));
            println!("  extensions: {}", str_list(v, "extensions"));
            println!(
                "  planned:    {}",
                arr(v, "planned")
                    .iter()
                    .map(|p| s(p, "id"))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            println!("\nFIPS validated: no. {}", s(v, "fipsValidationStatement"));
            println!("\nDO-178C certified: no. {}", s(v, "do178cStatement"));
        }),
        (Some("selftest"), _) => emit(ops::selftest(), json, |v| {
            for o in arr(v, "outcomes") {
                println!(
                    "  {:<28} {}",
                    s(o, "algorithm"),
                    if b(o, "passed") { "pass" } else { "FAIL" }
                );
            }
            println!("module state: {}", s(v, "state"));
        }),
        (Some("mcp"), _) => match mcp::serve() {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("error: {e}");
                ExitCode::FAILURE
            }
        },
        (Some("probe"), Some(target)) => {
            // The command line is the operator's own: any target is allowed.
            let r = net::tls_probe(
                target,
                args.option("profile"),
                args.option("alpn"),
                args.flag("ech"),
                true,
            );
            let failed = matches!(&r, Ok(v) if v.get("error").map(|e| !matches!(e, Json::Null)).unwrap_or(false));
            let code = emit(r, json, |v| {
                println!("{} {}", s(v, "target"), s(v, "state"));
                for k in [
                    "ech",
                    "revocation",
                    "version",
                    "cipherSuite",
                    "keyExchangeGroup",
                    "peerSignatureScheme",
                    "peerKey",
                    "peerSubjectCommonName",
                    "alpn",
                    "alertSent",
                    "alertReceived",
                    "alertReceivedMeaning",
                ] {
                    if let Some(Json::String(x)) = v.get(k) {
                        // Peer-supplied text (a certificate's common name)
                        // must not reach the terminal as control sequences.
                        let x: String = x
                            .chars()
                            .map(|c| if c.is_control() { '?' } else { c })
                            .collect();
                        println!("  {k:<22} {x}");
                    }
                }
                let names: String = str_list(v, "peerNames")
                    .chars()
                    .map(|c| if c.is_control() { '?' } else { c })
                    .collect();
                if !names.is_empty() {
                    println!("  peerNames              {names}");
                }
                println!("  properties             {}", str_list(v, "properties"));
                if let Some(Json::String(e)) = v.get("error") {
                    println!(
                        "
failed: {e} ({})",
                        s(v, "errorContext")
                    );
                    println!("meaning: {}", s(v, "meaning"));
                    println!("action:  {}", s(v, "action"));
                    if let Some(Json::String(h)) = v.get("hint") {
                        println!("note:    {h}");
                    }
                    println!("recovery:");
                    for step in arr(v, "recovery") {
                        println!("  - {}", step.as_str().unwrap_or(""));
                    }
                }
            });
            if failed {
                ExitCode::FAILURE
            } else {
                code
            }
        }
        (Some("inspect"), Some(path)) => emit(
            read_capped(path).and_then(|t| offline::inspect_certificate(&t)),
            json,
            |v| {
                for c in v.as_array().unwrap_or(&[]) {
                    for k in [
                        "subjectCommonName",
                        "issuerCommonName",
                        "serial",
                        "key",
                        "signatureScheme",
                        "spkiSha256",
                    ] {
                        println!("  {k:<18} {}", clean(&show(c, k)));
                    }
                    println!("  {:<18} {}", "dnsNames", clean(&str_list(c, "dnsNames")));
                    println!("  {:<18} {}", "ipAddresses", str_list(c, "ipAddresses"));
                    println!("  {:<18} {}", "isCa", b(c, "isCa"));
                    println!("  {:<18} {}", "expired", b(c, "expired"));
                    println!("  {:<18} {}", "secondsLeft", show(c, "secondsLeft"));
                    println!();
                }
            },
        ),
        (Some("verify"), Some(path)) => {
            let Some(roots) = args.option("roots") else {
                return usage_error("verify needs --roots");
            };
            let r = read_capped(path).and_then(|chain| {
                let roots = read_capped(roots)?;
                offline::verify_chain(&chain, &roots, args.option("name"), args.flag("client"))
            });
            let valid =
                matches!(&r, Ok(v) if v.get("valid").and_then(|x| x.as_bool()) == Some(true));
            let code = emit(r, json, |v| {
                println!("  {:<8} {}", "valid", b(v, "valid"));
                for k in ["error", "context", "action", "depth", "leafKey", "anchor"] {
                    if let Some(x) = v.get(k) {
                        if !matches!(x, Json::Null) {
                            println!("  {k:<8} {}", clean(&show(v, k)));
                        }
                    }
                }
            });
            if valid {
                code
            } else {
                ExitCode::FAILURE
            }
        }
        (Some("check-config"), Some(path)) => {
            let r = read_capped(path).and_then(|t| {
                let cfg = ic_json::parse(&t).map_err(|e| format!("not JSON: {e}"))?;
                offline::check_config(&cfg)
            });
            let valid =
                matches!(&r, Ok(v) if v.get("valid").and_then(|x| x.as_bool()) == Some(true));
            let code = emit(r, json, |v| {
                println!("  {:<12} {}", "valid", b(v, "valid"));
                for k in ["error", "context", "action", "profile"] {
                    if let Some(x) = v.get(k) {
                        if !matches!(x, Json::Null) {
                            println!("  {k:<12} {}", s(v, k));
                        }
                    }
                }
                println!("  {:<12} {}", "required", str_list(v, "required"));
                println!("  {:<12} {}", "relaxations", str_list(v, "relaxations"));
            });
            if valid {
                code
            } else {
                ExitCode::FAILURE
            }
        }
        (Some("serve"), _) => {
            let (Some(cert), Some(key)) = (args.option("cert"), args.option("key")) else {
                return usage_error("serve needs --cert and --key");
            };
            let port = match args.option("port").map(|p| p.parse::<u16>()) {
                None => 8443,
                Some(Ok(p)) => p,
                Some(Err(_)) => return usage_error("bad --port"),
            };
            match net::serve(
                cert,
                key,
                args.option("bind").unwrap_or("127.0.0.1"),
                port,
                args.option("profile"),
                args.option("alpn"),
                args.flag("once"),
            ) {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("error: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        (Some("help") | Some("--help") | None, _) => {
            print!("{USAGE}");
            ExitCode::SUCCESS
        }
        (Some(other), _) => usage_error(&format!("unknown command '{other}'")),
    }
}

/// A file (or `-` for standard input) of at most `offline::MAX_INPUT` bytes.
fn read_capped(path: &str) -> Result<String, String> {
    use std::io::Read as _;
    let limit = offline::MAX_INPUT as u64 + 1;
    let mut text = String::new();
    let read = if path == "-" {
        std::io::stdin().take(limit).read_to_string(&mut text)
    } else {
        std::fs::File::open(path).and_then(|f| f.take(limit).read_to_string(&mut text))
    };
    read.map_err(|e| format!("{path}: {e}"))?;
    if text.len() as u64 >= limit {
        return Err(format!("{path}: larger than {} bytes", offline::MAX_INPUT));
    }
    Ok(text)
}

/// Peer-supplied text (a certificate's names) without control characters.
fn clean(text: &str) -> String {
    text.chars()
        .map(|c| if c.is_control() { '?' } else { c })
        .collect()
}

fn usage_error(msg: &str) -> ExitCode {
    eprintln!("error: {msg}\n\n{USAGE}");
    ExitCode::from(2)
}

fn main() -> ExitCode {
    let raw: Vec<String> = std::env::args().skip(1).collect();
    if raw.iter().any(|a| a == "-h") {
        print!("{USAGE}");
        return ExitCode::SUCCESS;
    }
    run(Args::parse(raw))
}

#[cfg(test)]
mod tests {
    use super::Args;

    /// Every option that takes a value consumes it: `--bind` once did not,
    /// so `isl serve --bind 0.0.0.0` silently kept 127.0.0.1.
    #[test]
    fn options_with_values_are_parsed() {
        let raw = |v: &[&str]| v.iter().map(|s| s.to_string()).collect();
        let a = Args::parse(raw(&[
            "serve", "--bind", "0.0.0.0", "--roots", "r.pem", "--name", "h", "--once",
        ]));
        assert_eq!(a.option("bind"), Some("0.0.0.0"));
        assert_eq!(a.option("roots"), Some("r.pem"));
        assert_eq!(a.option("name"), Some("h"));
        assert!(a.flag("once"));
        assert_eq!(a.positional, ["serve"]);
    }
}
