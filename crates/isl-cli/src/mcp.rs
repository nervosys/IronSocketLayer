//! A Model Context Protocol server over stdio.
//!
//! Newline-delimited JSON-RPC 2.0 on stdin/stdout, exposing the ontology, the
//! profile selector, the error catalog and IronCrypto's self-tests as MCP
//! tools. Run it with `isl mcp`, or wire it into a client:
//!
//! ```jsonc
//! { "mcpServers": { "iron-socket-layer": { "command": "isl", "args": ["mcp"] } } }
//! ```
//!
//! Every tool is a thin wrapper over [`crate::ops`], the same code the CLI's
//! `--json` output comes from.

use crate::ops;
use ic_json::{parse, Json};
use std::io::{BufRead, Read, Write};

/// The MCP protocol revision this server implements.
pub const PROTOCOL_VERSION: &str = "2024-11-05";

/// The largest JSON-RPC message held in memory. Far above any real request;
/// the bound exists so a peer that never sends a newline cannot exhaust memory.
pub const MAX_MESSAGE: usize = 4 * 1024 * 1024;

/// One exposed tool.
pub struct Tool {
    /// Tool name.
    pub name: &'static str,
    /// Prose description for the agent.
    pub description: &'static str,
    /// JSON Schema of the arguments.
    pub schema: fn() -> Json,
    /// The implementation.
    pub call: fn(&Json) -> Result<Json, String>,
}

fn string_prop(desc: &str) -> Json {
    Json::object([
        ("type", Json::str("string")),
        ("description", Json::str(desc)),
    ])
}

fn bool_prop(desc: &str) -> Json {
    Json::object([
        ("type", Json::str("boolean")),
        ("description", Json::str(desc)),
    ])
}

fn enum_prop(desc: &str, values: Vec<&str>) -> Json {
    Json::object([
        ("type", Json::str("string")),
        ("description", Json::str(desc)),
        (
            "enum",
            Json::Array(values.into_iter().map(Json::str).collect()),
        ),
    ])
}

fn schema(props: Vec<(&str, Json)>, required: &[&str]) -> Json {
    let mut map = std::collections::BTreeMap::new();
    for (k, v) in props {
        map.insert(k.to_string(), v);
    }
    Json::object([
        ("type", Json::str("object")),
        ("properties", Json::Object(map)),
        (
            "required",
            Json::Array(required.iter().map(|r| Json::str(*r)).collect()),
        ),
    ])
}

fn arg<'a>(args: &'a Json, name: &str) -> Option<&'a str> {
    args.get(name).and_then(|v| v.as_str())
}

fn flag(args: &Json, name: &str) -> bool {
    args.get(name).and_then(|v| v.as_bool()).unwrap_or(false)
}

fn required<'a>(args: &'a Json, name: &str) -> Result<&'a str, String> {
    arg(args, name).ok_or_else(|| format!("missing required string argument '{name}'"))
}

/// The tools this server exposes.
pub fn tools() -> Vec<Tool> {
    let mut t = vec![
        Tool {
            name: "ontology_list",
            description: "List TLS 1.3 / QUIC protocol elements (cipher suites, groups, signature schemes, extensions, alerts, messages) with their implementation status, FIPS status and post-quantum flag.",
            schema: || schema(vec![("kind", enum_prop("Restrict to one kind.", isl_ontology::Kind::ALL.iter().map(|k| k.id()).collect()))], &[]),
            call: |a| ops::ontology_list(arg(a, "kind")),
        },
        Tool {
            name: "ontology_show",
            description: "Show one ontology entry, error, profile or intent in full: constraints with severities, standards, strength, and relations including built-on edges into IronCrypto. Read the constraints before configuring anything.",
            schema: || schema(vec![("id", string_prop("An id such as group:x25519mlkem768, suite:tls-aes-256-gcm-sha384, profile:fips-140-3 or error:unknown-ca. The prefix may be omitted."))], &["id"]),
            call: |a| ops::ontology_show(required(a, "id")?),
        },
        Tool {
            name: "ontology_related",
            description: "Every edge touching an entry, in both directions. Accepts ic: ids to find which TLS elements are built on an IronCrypto algorithm.",
            schema: || schema(vec![("id", string_prop("An ontology id, or an IronCrypto id with the ic: prefix."))], &["id"]),
            call: |a| ops::ontology_related(required(a, "id")?),
        },
        Tool {
            name: "recommend",
            description: "Choose a TLS profile for an intent. Call this before configuring a connection. A status of 'unavailable' or 'impossible' means no profile in this build meets the requirements: report that to the user and do not substitute a weaker profile.",
            schema: || {
                schema(
                    vec![
                        ("intent", enum_prop("What the connection is for.", isl_ontology::INTENTS.iter().map(|i| i.id).collect())),
                        ("fips", bool_prop("Require FIPS 140-3 approved algorithms.")),
                        ("postQuantum", bool_prop("Require post-quantum key exchange.")),
                        ("mutual", bool_prop("Require mutual authentication.")),
                    ],
                    &["intent"],
                )
            },
            call: |a| ops::recommend(required(a, "intent")?, flag(a, "fips"), flag(a, "postQuantum"), flag(a, "mutual")),
        },
        Tool {
            name: "explain_error",
            description: "Explain an IronSocketLayer error id (as carried by every error the library returns) and give the recovery steps, whether it is retryable, and whether the caller or the peer is at fault.",
            schema: || schema(vec![("id", string_prop("An error id such as error:unknown-ca; the error: prefix may be omitted."))], &["id"]),
            call: |a| ops::explain_error(required(a, "id")?),
        },
        Tool {
            name: "profiles",
            description: "List every profile with its suites, groups, signature schemes, requirements, status and rationale.",
            schema: || schema(vec![], &[]),
            call: |_| ops::profiles(),
        },
        Tool {
            name: "capabilities",
            description: "What this build implements and plans, and its certification status: FIPS validation (none) and DO-178C certification (none), stated plainly.",
            schema: || schema(vec![], &[]),
            call: |_| ops::capabilities(),
        },
        Tool {
            name: "selftest",
            description: "Run IronCrypto's pre-operational FIPS self-tests and report each result and the module state.",
            schema: || schema(vec![], &[]),
            call: |_| ops::selftest(),
        },
    ];
    t.extend(extra_tools());
    t
}

/// Tools that drive live connections: `tls_probe` connects to host:port and
/// returns the SessionReport JSON. Keep every such tool total: hostile
/// arguments must produce an `isError` result, never a panic.
pub fn extra_tools() -> Vec<Tool> {
    vec![Tool {
        name: "tls_probe",
        description: "Open a real TLS 1.3 connection to host[:port] with IronSocketLayer, verify the server against the system trust store, and return the session report: version, suite, key-exchange group, signature scheme, peer certificate facts, the security properties that hold (post-quantum key exchange, forward secrecy, ...), FIPS indicators and an event trail. On failure the report carries the error id with its meaning and recovery steps. Makes a network connection.",
        schema: || {
            schema(
                vec![
                    ("target", string_prop("host or host:port; port defaults to 443.")),
                    ("profile", enum_prop("Profile to connect with; defaults to profile:default.", iron_socket_layer::config::Profile::ALL.iter().map(|p| p.id()).collect())),
                    ("alpn", string_prop("Comma-separated ALPN protocols to offer, e.g. h2,http/1.1.")),
                    ("ech", bool_prop("Fetch the host's ECH configuration from DNS and send the server name only encrypted (Encrypted Client Hello); retries once with the server's retry configurations.")),
                ],
                &["target"],
            )
        },
        call: |a| crate::net::tls_probe(required(a, "target")?, arg(a, "profile"), arg(a, "alpn"), flag(a, "ech")),
    }]
}

fn error_response(id: Json, code: i64, message: &str) -> Json {
    Json::object([
        ("jsonrpc", Json::str("2.0")),
        ("id", id),
        (
            "error",
            Json::object([
                ("code", Json::num(code as f64)),
                ("message", Json::str(message)),
            ]),
        ),
    ])
}

fn result_response(id: Json, result: Json) -> Json {
    Json::object([
        ("jsonrpc", Json::str("2.0")),
        ("id", id),
        ("result", result),
    ])
}

fn tool_content(body: Json, is_error: bool) -> Json {
    Json::object([
        (
            "content",
            Json::Array(vec![Json::object([
                ("type", Json::str("text")),
                ("text", Json::str(body.to_string())),
            ])]),
        ),
        ("isError", Json::Bool(is_error)),
    ])
}

/// Handle one request; `None` for a notification.
pub fn handle(request: &Json) -> Option<Json> {
    let method = request.get("method").and_then(|m| m.as_str()).unwrap_or("");
    let id = request.get("id").cloned()?;
    let params = request.get("params").cloned().unwrap_or(Json::Null);

    let response = match method {
        "initialize" => result_response(
            id,
            Json::object([
                ("protocolVersion", Json::str(PROTOCOL_VERSION)),
                ("capabilities", Json::object([("tools", Json::object([]))])),
                ("serverInfo", Json::object([("name", Json::str("iron-socket-layer")), ("version", Json::str(isl_ontology::VERSION))])),
                (
                    "instructions",
                    Json::str(
                        "Call recommend with the intent before configuring TLS. If it answers 'unavailable' or \
                         'impossible', tell the user; never fall back to a weaker profile. Read ontology_show for \
                         constraints before changing any parameter, and explain_error for recovery steps when a \
                         connection fails.",
                    ),
                ),
            ]),
        ),
        "tools/list" => result_response(
            id,
            Json::object([(
                "tools",
                Json::Array(
                    tools()
                        .iter()
                        .map(|t| Json::object([("name", Json::str(t.name)), ("description", Json::str(t.description)), ("inputSchema", (t.schema)())]))
                        .collect(),
                ),
            )]),
        ),
        "tools/call" => {
            let name = params.get("name").and_then(|n| n.as_str()).unwrap_or("");
            let args = match params.get("arguments") {
                Some(a @ Json::Object(_)) => a.clone(),
                _ => Json::Object(Default::default()),
            };
            match tools().iter().find(|t| t.name == name) {
                Some(tool) => match (tool.call)(&args) {
                    Ok(body) => result_response(id, tool_content(body, false)),
                    Err(message) => result_response(id, tool_content(Json::object([("error", Json::str(message))]), true)),
                },
                None => error_response(id, -32601, &format!("unknown tool '{name}'")),
            }
        }
        "ping" => result_response(id, Json::object([])),
        other => error_response(id, -32601, &format!("unknown method '{other}'")),
    };
    Some(response)
}

/// Serve MCP over stdin/stdout until end of input.
pub fn serve() -> std::io::Result<()> {
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    serve_on(stdin.lock(), &mut stdout)
}

/// [`serve`] over any reader and writer.
pub fn serve_on(mut input: impl BufRead, out: &mut impl Write) -> std::io::Result<()> {
    loop {
        let mut line = Vec::new();
        let read = (&mut input)
            .take(MAX_MESSAGE as u64 + 1)
            .read_until(b'\n', &mut line)?;
        if read == 0 {
            break;
        }
        if line.len() > MAX_MESSAGE {
            // Discard the rest of this message without buffering it, stopping
            // at its newline so the next message is still served.
            let mut sink = Vec::new();
            loop {
                sink.clear();
                let n = (&mut input).take(65536).read_until(b'\n', &mut sink)?;
                if n == 0 || sink.ends_with(b"\n") {
                    break;
                }
            }
            writeln!(
                out,
                "{}",
                error_response(
                    Json::Null,
                    -32700,
                    &format!("message larger than {MAX_MESSAGE} bytes")
                )
            )?;
            out.flush()?;
            continue;
        }
        let text = String::from_utf8_lossy(&line);
        if text.trim().is_empty() {
            continue;
        }
        let response = match parse(&text) {
            Ok(request) => handle(&request),
            Err(message) => Some(error_response(
                Json::Null,
                -32700,
                &format!("parse error: {message}"),
            )),
        };
        if let Some(r) = response {
            writeln!(out, "{r}")?;
            out.flush()?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(method: &str, params: Json) -> Json {
        Json::object([
            ("jsonrpc", Json::str("2.0")),
            ("id", Json::num(1)),
            ("method", Json::str(method)),
            ("params", params),
        ])
    }

    fn call(name: &str, args: Json) -> Json {
        handle(&request(
            "tools/call",
            Json::object([("name", Json::str(name)), ("arguments", args)]),
        ))
        .unwrap()
    }

    fn body(r: &Json) -> Json {
        let text = r
            .get("result")
            .unwrap()
            .get("content")
            .unwrap()
            .as_array()
            .unwrap()[0]
            .get("text")
            .unwrap()
            .as_str()
            .unwrap();
        parse(text).unwrap()
    }

    fn is_error(r: &Json) -> bool {
        r.get("result")
            .and_then(|x| x.get("isError"))
            .and_then(|x| x.as_bool())
            .unwrap_or(true)
    }

    fn hostile() -> Vec<Json> {
        let mut v = vec![
            Json::Null,
            Json::Bool(true),
            Json::num(-1),
            Json::num(1e308),
            Json::str(""),
            Json::str("\u{0}"),
            Json::str("../../etc/passwd"),
            Json::str("error:"),
            Json::str("ic:"),
            Json::str(":"),
            Json::str("group:"),
            Json::str("x".repeat(100_000)),
            Json::str("\u{202e}\u{fffd}𝕏"),
            Json::Array(vec![Json::Null]),
            Json::object([]),
        ];
        v.push(Json::str("intent:https-client"));
        v
    }

    #[test]
    fn every_tool_returns_on_hostile_arguments() {
        for tool in tools() {
            for value in hostile() {
                for key in ["id", "kind", "intent", "fips", "postQuantum", "mutual"] {
                    let args = Json::object([(key, value.clone())]);
                    let r = call(tool.name, args);
                    assert!(
                        r.get("result").is_some(),
                        "{} returned a protocol error",
                        tool.name
                    );
                }
            }
            // Non-object arguments.
            for value in hostile() {
                let r = handle(&request(
                    "tools/call",
                    Json::object([("name", Json::str(tool.name)), ("arguments", value)]),
                ))
                .unwrap();
                assert!(r.get("result").is_some());
            }
        }
    }

    #[test]
    fn the_protocol_layer_returns_on_anything() {
        for v in hostile() {
            let _ = handle(&v);
            let _ = handle(&Json::object([("id", Json::num(1)), ("method", v.clone())]));
            let _ = handle(&Json::object([
                ("id", Json::num(1)),
                ("method", Json::str("tools/call")),
                ("params", v),
            ]));
        }
        // A notification gets no answer.
        assert!(handle(&Json::object([("method", Json::str("ping"))])).is_none());
    }

    #[test]
    fn initialize_and_tools_list_are_well_formed() {
        let r = handle(&request("initialize", Json::object([]))).unwrap();
        let res = r.get("result").unwrap();
        assert_eq!(
            res.get("protocolVersion").and_then(|v| v.as_str()),
            Some(PROTOCOL_VERSION)
        );
        let r = handle(&request("tools/list", Json::object([]))).unwrap();
        let list = r
            .get("result")
            .unwrap()
            .get("tools")
            .unwrap()
            .as_array()
            .unwrap();
        assert_eq!(list.len(), tools().len());
        let names: Vec<&str> = list
            .iter()
            .map(|t| t.get("name").unwrap().as_str().unwrap())
            .collect();
        for want in [
            "ontology_list",
            "ontology_show",
            "ontology_related",
            "recommend",
            "explain_error",
            "profiles",
            "capabilities",
            "selftest",
        ] {
            assert!(names.contains(&want), "{want} missing");
        }
        for t in list {
            let s = t.get("inputSchema").unwrap();
            assert_eq!(s.get("type").and_then(|v| v.as_str()), Some("object"));
            let props = s.get("properties").unwrap();
            for r in s.get("required").unwrap().as_array().unwrap() {
                assert!(
                    props.get(r.as_str().unwrap()).is_some(),
                    "required arg without a property"
                );
            }
            let d = t.get("description").unwrap().as_str().unwrap();
            assert!(d.ends_with('.') && d.len() > 40);
        }
    }

    #[test]
    fn tools_produce_correct_answers() {
        let r = call(
            "ontology_show",
            Json::object([("id", Json::str("x25519mlkem768"))]),
        );
        assert!(!is_error(&r));
        assert_eq!(body(&r).get("code").and_then(|v| v.as_i64()), Some(0x11ec));

        let r = call(
            "recommend",
            Json::object([
                ("intent", Json::str("intent:fips-regulated")),
                ("postQuantum", Json::Bool(true)),
            ]),
        );
        assert_eq!(
            body(&r).get("status").and_then(|v| v.as_str()),
            Some("recommended")
        );
        assert!(body(&r).to_string().contains("profile:cnsa-2"));

        let r = call(
            "explain_error",
            Json::object([("id", Json::str("unknown-ca"))]),
        );
        assert_eq!(
            body(&r).get("alert").and_then(|v| v.as_str()),
            Some("alert:unknown-ca")
        );

        let r = call(
            "ontology_related",
            Json::object([("id", Json::str("ic:ml-kem-768"))]),
        );
        assert!(body(&r).get("relations").unwrap().as_array().unwrap().len() >= 3);

        let r = call("ontology_show", Json::object([("id", Json::str("nope"))]));
        assert!(is_error(&r));

        let r = call("selftest", Json::object([]));
        assert_eq!(
            body(&r).get("allPassed").and_then(|v| v.as_bool()),
            Some(true)
        );

        let r = call("capabilities", Json::object([]));
        assert_eq!(
            body(&r).get("fipsValidated").and_then(|v| v.as_bool()),
            Some(false)
        );
    }

    #[test]
    fn response_keys_are_camel_case() {
        fn walk(v: &Json, path: &str, bad: &mut Vec<String>) {
            match v {
                Json::Object(m) => {
                    for (k, x) in m {
                        if k.contains('-') || k.contains('_') {
                            bad.push(format!("{path}.{k}"));
                        }
                        walk(x, &format!("{path}.{k}"), bad);
                    }
                }
                Json::Array(a) => a.iter().for_each(|x| walk(x, path, bad)),
                _ => {}
            }
        }
        let mut bad = Vec::new();
        for (name, args) in [
            ("ontology_list", Json::object([])),
            (
                "ontology_show",
                Json::object([("id", Json::str("suite:tls-aes-128-gcm-sha256"))]),
            ),
            (
                "ontology_show",
                Json::object([("id", Json::str("profile:dal-a"))]),
            ),
            (
                "ontology_show",
                Json::object([("id", Json::str("intent:quic-client"))]),
            ),
            (
                "recommend",
                Json::object([("intent", Json::str("intent:agent-to-agent-mtls"))]),
            ),
            ("explain_error", Json::object([("id", Json::str("decode"))])),
            ("profiles", Json::object([])),
            ("capabilities", Json::object([])),
        ] {
            walk(&body(&call(name, args)), name, &mut bad);
        }
        assert!(bad.is_empty(), "non-camelCase keys: {bad:?}");
    }

    #[test]
    fn an_oversized_message_is_refused_and_the_next_one_still_answered() {
        let mut input = Vec::new();
        input.extend(std::iter::repeat(b'x').take(MAX_MESSAGE + 10));
        input.push(b'\n');
        input.extend_from_slice(br#"{"jsonrpc":"2.0","id":7,"method":"ping"}"#);
        input.push(b'\n');
        let mut out = Vec::new();
        serve_on(std::io::Cursor::new(input), &mut out).unwrap();
        let text = String::from_utf8(out).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("-32700"));
        assert!(lines[1].contains("\"id\":7"));
    }

    #[test]
    fn malformed_json_gets_a_parse_error() {
        let mut out = Vec::new();
        serve_on(std::io::Cursor::new(b"{not json\n\n".to_vec()), &mut out).unwrap();
        assert!(String::from_utf8(out).unwrap().contains("-32700"));
    }
}
