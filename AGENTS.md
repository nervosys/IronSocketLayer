# Working with IronSocketLayer

Instructions for coding agents, whether you are *using* this library or
*changing* it. Humans may also find them useful.

## Before configuring a connection, ask

Do not assemble suites, groups and schemes from memory. Ask for the intent:

```console
$ isl recommend <intent> [--fips] [--post-quantum] [--mutual] --json
```

Intents: `intent:https-client`, `intent:api-server`,
`intent:agent-to-agent-mtls`, `intent:mcp-transport`, `intent:quic-client`,
`intent:quic-server`, `intent:fips-regulated`,
`intent:harvest-now-decrypt-later`, `intent:avionics-dal-a`,
`intent:embedded-constrained`.

Then build the profile it names: `ClientConfig::new(Profile::PostQuantum, roots)`.

## When the answer is "unavailable", stop

`profile:cnsa-2` is unavailable in this build: it needs ML-KEM-1024 and
ML-DSA-87. If `recommend` returns `unavailable` or `impossible`, report it to
the user. **Do not substitute another profile.** Falling back is the downgrade
attack, performed by the agent itself.

## Never disable verification

There is no API for it, and do not write one. To reach a peer without a PKI,
pin its key: `ClientConfig::pinned(profile, &spki_der)`.

## After connecting, check what you got

```rust
let r = conn.report();
assert!(r.has(Property::PostQuantumKeyExchange));   // if the task required it
```

To gate a privileged operation on the peer agent's identity without
requiring certificates from every client, configure the server with
`ClientAuth::OnDemand(...)`, call `Connection::request_client_auth()` before
the operation, and proceed only once the report has
`Property::MutualAuthentication`.

If the server name itself is sensitive, set `config.ech_configs` from the
host's DNS HTTPS record (`isl probe --ech` shows how) and assert
`Property::EncryptedClientHello`. On `error:ech-rejected`, reconnect with
`Connection::ech_retry_configs()`; never retry without ECH unless the user
agrees to expose the name.

If the task needs revocation checking, set `config.revocation =
Revocation::RequireStaple` and assert `Property::RevocationChecked`; the default
checks a staple only when the server sends one.

Assert on properties, not on the absence of errors. A handshake that succeeded
with classical key exchange is a success for TLS and a failure for a task that
required post-quantum confidentiality.

## When a connection fails, read the error id

Every `iron_socket_layer::Error` has an `id()` such as `error:unknown-ca`.
`isl explain <id> --json` (or the `explain_error` MCP tool) returns its
meaning and recovery steps. Errors with `retryable: false` do not get better by
retrying; `peer_fault: true` means the remote end is broken or hostile.

## Rules for changing this repository

- **No primitive is implemented here.** Every cipher, hash, MAC, KDF, curve,
  KEM and signature comes from IronCrypto through `src/crypto/`. If you need an
  algorithm IronCrypto lacks, add it there, with its ontology entry and
  self-test, not here.
- **Zero third-party dependencies**, as in IronCrypto.
- **`no_std + alloc` first.** Anything needing `std` goes behind the `std`
  feature. Check: `cargo build -p iron-socket-layer --no-default-features --target thumbv7em-none-eabihf`.
- **Nothing panics on peer input.** Return `Error`. No `unwrap`, indexing or
  arithmetic that a peer controls without a bound. `tests/robustness.rs`
  mutates real flights; keep it passing.
- **`#![forbid(unsafe_code)]`** stays.
- **Every protocol element has an ontology entry**, implemented or not, and
  its `id()` matches. `tests/ontology_agreement.rs` fails if the code and the
  ontology disagree, including profile contents and order. Fix the
  disagreement; do not relax the test.
- **Every requirement is traced.** Tag new behaviour with a `REQ-AREA-NNN`
  in its doc comment, add the row to `docs/TRACEABILITY.md`, and name the test
  that verifies it. `tests/traceability.rs` enforces all three.
- **Test vectors come from the published standard.** If you cannot verify a
  value from an authoritative source, do not assert it; test against an
  independent implementation instead (`tests/openssl_interop.rs`).
- **Break the thing and confirm the test fails.** A test that passes on broken
  code verified nothing.

## Before you finish

```console
$ cargo test --workspace
$ cargo clippy --workspace --all-targets
$ cargo build -p iron-socket-layer --no-default-features --target thumbv7em-none-eabihf
$ cargo test -p iron-socket-layer --test openssl_interop -- --ignored --test-threads=1   # if openssl >= 3.5 is present
```

If you changed a parser or the state machine, fuzz it too (see
`fuzz/README.md`). A crash input goes into a regression test in
`tests/robustness.rs` along with the fix.

## Never claim certification

Neither this library nor IronCrypto is FIPS 140-3 validated or DO-178C
certified. Do not say or imply otherwise, anywhere. Reports carry
`"validated": false`, and that must not change until a certificate exists.
