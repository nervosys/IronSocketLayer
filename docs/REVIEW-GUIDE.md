# Guide for an independent security review

Everything in this repository's verification was done by its author, with
AI-assisted review: the audit, the tests, the coverage dispositions, the
traceability. This guide is for someone else, so that their time goes where
it matters. It says what to review, where hostile bytes enter, what has
already been checked and how, and what has not.

Nothing here claims FIPS 140-3 validation, DO-178C certification or CMMC
compliance. None exists.

## Scope

| In scope | Not in scope |
|---|---|
| `crates/ironsocketlayer`: the TLS 1.3 and QUIC-TLS engines, X.509 path validation, OCSP, CRLs, ECH, the session report | The cryptographic primitives: every cipher, hash, MAC, KDF, curve, KEM and signature is IronCrypto's (`../IronCrypto`), reached only through `src/crypto/`. Review IronCrypto separately. |
| `crates/isl-cli`: the `isl` command and its MCP server, which an AI agent may drive | `bench/`, `fuzz/`, `embedded/`: harnesses outside the library's dependency graph |
| `crates/isl-ontology`: data an agent configures from | |

The library is about 36,000 lines of Rust including in-file unit tests,
`#![forbid(unsafe_code)]`, with no third-party dependencies.

## Threat model

- **The network peer is hostile.** It controls every byte read, the timing,
  and when the connection ends. It may hold a certificate from a CA the
  victim trusts, but not that CA's key. Goals: impersonation, reading or
  altering traffic, downgrade, denial of service, memory disclosure.
- **The agent driving the library may be confused or prompt-injected.**
  It chooses configurations and calls the MCP tools. Goals for an attacker
  steering it: weakening a connection, reaching the internal network,
  leaking keys. The design answer is that weakening needs explicit,
  reported settings (`config.relaxations()`), certificate verification
  cannot be turned off, and failures say "ask the user" rather than suggest
  a weaker retry.
- **The operator is trusted**: it supplies certificates, keys, trust
  anchors, CRLs and configuration.

## Where hostile bytes enter

Read these first; each has a fuzz target (`fuzz/`) and robustness tests
(`tests/robustness.rs`).

| Entry | Code | Notes |
|---|---|---|
| Record layer | `record.rs` (`peek_record`, `take_record`, `Protector::open`), `conn.rs` (`read_tls`, `open_in_place`) | Two receive paths: the in-place bulk path and the general one. Both must apply the same bounds; one did not (REQ-REC-012). |
| Handshake framing and messages | `msgs.rs` (`take_message`, every `decode`) | Extension lists are uncapped by count; duplicates are found by sorting (REQ-MSG-020). |
| Client and server state machines | `client.rs`, `server.rs`, `conn.rs` | PSK and ticket selection (`server.rs::try_resume`), 0-RTT skipping and acceptance, HelloRetryRequest, post-handshake authentication, KeyUpdate. |
| Fixed-capacity engine | `fixed.rs` | A second, allocation-free implementation over caller storage. Its own parser and state machine; differences from the owned engine are bugs. |
| Certificates | `x509.rs` (`Certificate::parse`, `verify_chain`, `verify_chain_fixed`, name constraints) | Two path validators. Name constraints and the bounded path search (REQ-X509-076) deserve the most attention. |
| OCSP and CRLs | `x509_ocsp.rs`, `x509_crl.rs` | Responder authorisation, freshness, indirect CRLs. |
| ECH | `ech.rs`, `server.rs::open_ech` | Inner hello reconstruction (`ech_outer_extensions`), HPKE via IronCrypto. |
| QUIC | `quic.rs` | Transport parameters, levels. |
| CLI and MCP | `isl-cli/src/mcp.rs`, `net.rs`, `offline.rs` | JSON from an agent; `tls_probe` must not reach internal addresses unless the operator allows it. |

## Highest-value questions

1. Can a peer make either path validator accept a certificate it should
   not: name-constraint escapes, path-building confusion, anchor misuse,
   pinning paths that skip a check?
2. Do the owned and fixed engines, and the two receive paths, apply the
   same rules? Every past defect of this kind was found by comparing them.
3. Is any secret compared in variable time, logged, kept after use, or
   reachable through the report or an error? (`ic_core::ct`, `Zeroize`
   throughout; the report carries no secret by design.)
4. Can a peer make the library do unbounded work or hold unbounded memory?
   Bounds are listed in [ARCHITECTURE.md](ARCHITECTURE.md) ("Bounded
   resources") and the
   requirements; the audit found and fixed several (A-3, A-4, A-13 to A-17).
5. PSK and 0-RTT: binder checks, Selfie reflection (REQ-EPSK-005), replay,
   and skipping rejected early data (REQ-0RTT-004, -007, -008).
6. Can an agent, through the MCP tools or the configuration API, be led to
   weaken security without that weakening being reported?

## What has been checked, and how

| Check | Where | Limits |
|---|---|---|
| Author's audit against CVE classes, ATT&CK, FIPS and CMMC | [SECURITY-AUDIT-2026-10-06.md](SECURITY-AUDIT-2026-10-06.md) | Not independent. 21 findings and 12 weaknesses, all fixed. |
| 276 low-level requirements, each traced to code and a test that fails when the behaviour is removed | [TRACEABILITY.md](TRACEABILITY.md) (enforced by `tests/traceability.rs`) | The requirements are the author's reading of the RFCs. |
| Interoperability with OpenSSL 3.5 (both directions), Cloudflare, Google, GitHub | `tests/openssl_*.rs`, `tests/interop.rs` | Agreement with other implementations, not proof of correctness. |
| tlsfuzzer's TLS 1.3 conformance scripts | [VERIFICATION-2026-10-06-tlsfuzzer.md](VERIFICATION-2026-10-06-tlsfuzzer.md) | Found eight defects. Server side only: tlsfuzzer cannot test clients. |
| TLS-Anvil's TLS 1.3 client and server tests | [VERIFICATION-2026-10-07-tls-anvil.md](VERIFICATION-2026-10-07-tls-anvil.md) | Found two client defects; the server passed every test that ran. Owned engine, one configuration per side, strength 1; two defects in the test tool patched, server keys pinned. |
| libFuzzer under AddressSanitizer, eleven targets | `fuzz/` | Short campaigns (minutes per target), not days. |
| Branch coverage 97.7%, every gap dispositioned | [VERIFICATION-2026-10-05.md](VERIFICATION-2026-10-05.md), `docs/evidence/` | Branch coverage, not MC/DC; dispositions are the author's. |
| Differential fuzzing of the two engines (servers, and clients up to the encrypted flight) and the two path validators | [VERIFICATION-2026-10-06-differential.md](VERIFICATION-2026-10-06-differential.md) | Found fourteen differences in the fixed-capacity engine, all fixed. Finds no defect both share. |
| Mutation checks: each security fix's test was run against the code with the fix removed | commit messages and the audit report | Manual, per fix; no mutation-testing tool was run over the whole crate. |

## What has not been checked

- An independent review of any of the above.
- BoringSSL's BoGo; TLS-Anvil at higher strengths, against the fixed-capacity engine, or with resumption, 0-RTT, client certificates, ECDSA certificates or ECH.
- Long fuzzing campaigns (days), and differential fuzzing of the two
  clients on the encrypted part of the server's flight.
- Timing side channels beyond the constant-time comparisons and the
  padding scan reviewed in [VERIFICATION-2026-10-05.md](VERIFICATION-2026-10-05.md).
- IronCrypto itself (see its own documentation; it is not CMVP-validated).
- The `isl-cli` MCP server under a hostile agent beyond the hostile-argument
  tests in `mcp.rs`.

## Running everything

```console
$ cargo test --workspace
$ cargo clippy --workspace --all-targets
$ cargo build -p ironsocketlayer --no-default-features --target thumbv7em-none-eabihf
$ cargo test -p ironsocketlayer --test openssl_interop -- --ignored --test-threads=1   # OpenSSL 3.5+
$ cargo test -p ironsocketlayer --test openssl_cnsa2 -- --ignored
$ cargo test -p ironsocketlayer --test openssl_cnsa1 -- --ignored
$ cargo test -p ironsocketlayer --test interop -- --ignored                          # network
$ sh scripts/tlsfuzzer.sh ~/tlsfuzzer-work                                           # Linux
$ sh scripts/tls-anvil.sh ~/tls-anvil-work                                            # Linux, Docker
$ ./scripts/fuzz.ps1 -Seconds 600                                                    # see fuzz/README.md
```

Report findings as [SECURITY.md](../SECURITY.md) describes.
