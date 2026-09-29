# IronSocketLayer

**Agentic-first TLS 1.3 and QUIC-TLS in pure Rust, over [IronCrypto](../AgenticCrypto), with a machine-readable ontology.**

Post-quantum by default. Sans-I/O. `no_std`. No C, no `unsafe` in this repository, no third-party
dependencies. Every cryptographic operation is IronCrypto's; IronSocketLayer
implements the protocol and nothing else.

```console
$ isl probe cloudflare.com --alpn h2,http/1.1
cloudflare.com:443 state:connected
  version                version:tls1.3
  cipherSuite            suite:tls-aes-128-gcm-sha256
  keyExchangeGroup       group:x25519mlkem768
  peerSignatureScheme    sigscheme:ecdsa-secp256r1-sha256
  peerKey                key:ecdsa-p256
  peerSubjectCommonName  cloudflare.com
  alpn                   h2
  properties             property:confidentiality, property:forward-secrecy, property:post-quantum-key-exchange, property:server-authenticated
```

---

## Why a TLS library for agents

An autonomous agent that opens a TLS connection has three problems a human
programmer mostly does not:

1. **It cannot read your docs and reliably act on them.** It needs to know which
   configuration is right for *this* purpose, as data.
2. **It cannot tell what it got.** "The handshake succeeded" says nothing about
   whether the session is post-quantum, mutually authenticated, or FIPS-approved.
3. **It cannot interpret a failure.** `SSL_ERROR_SSL` plus an error-queue string
   is not something a planner can branch on.

IronSocketLayer answers each one in the library itself:

| Problem | IronSocketLayer |
|---|---|
| Choosing a configuration | Named **profiles** and **intents**: `isl recommend intent:agent-to-agent-mtls --post-quantum` returns the profile, the rationale, the rejected alternatives with reasons, and the constraints to honour. When nothing meets the requirements it says *unavailable* and never substitutes a weaker profile. |
| Knowing what you got | Every connection yields a **`SessionReport`**: version, suite, group, schemes, peer chain facts, the **security properties that hold** (`property:post-quantum-key-exchange`, `property:mutual-authentication`, `property:fips-approved-algorithms`, ...), FIPS service indicators, and a typed event trail. Stable camelCase JSON. |
| Understanding failure | Every error is a closed **`ErrorKind`** with a stable id (`error:unknown-ca`), the TLS alert it maps to, and `retryable` / `caller_correctable` / `peer_fault` flags. The ontology holds its meaning and recovery steps under the same id. |
| Discovering the library | A **ontology** of 102 protocol entries, 28 errors, 6 profiles and 10 intents, exported as JSON, JSON-LD, OWL/Turtle, JSON Schema and Markdown, linked into IronCrypto's ontology by `builtOn` edges. |
| Tool use | An **MCP server** (`isl mcp`) exposing the ontology, the recommender, the error catalog, self-tests and a live `tls_probe`. |

And it removes one foot-gun entirely: **there is no option to disable
certificate verification.** An agent that needs to talk to a peer without a PKI
pins the peer's public key instead, which is stricter and easier to provision.

## What is implemented

| | |
|---|---|
| Protocol | TLS 1.3 (RFC 8446), client and server: full handshake, HelloRetryRequest with cookie, mutual authentication, KeyUpdate, **post-handshake client authentication** (step-up: `request_client_auth()` before a privileged operation), **0-RTT early data** (opt-in, TLS over TCP and QUIC, replay guard and freshness window on the server; rejected data returned, never silently resent), **external PSKs** (for devices and agent pairs with no PKI; 256-bit minimum, still with a fresh key exchange), **session resumption** (PSK with (EC)DHE only, stateless AES-256-GCM tickets, single-use on the client, so resumption keeps forward secrecy and post-quantum key exchange), exporters (RFC 8446 §7.5, for RFC 9266 channel binding), ALPN, SNI, close_notify, middlebox compatibility mode |
| QUIC | TLS for QUIC (RFC 9001), QUIC v1 and v2 (RFC 9369): CRYPTO-frame levels, transport parameters, Initial / Handshake / 1-RTT packet protection, header protection, 1-RTT key update |
| Cipher suites | TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256 |
| Key exchange | **X25519MLKEM768**, **SecP256r1MLKEM768**, **ML-KEM-768**, X25519, P-256, P-384, P-521; **SecP384r1MLKEM1024** and **ML-KEM-1024** on request (not offered by default: their shares exceed 1.5 KB) |
| Signatures | **ML-DSA-65**, **ML-DSA-87**, ECDSA P-256/P-384/P-521, Ed25519, RSA-PSS (2048–4096), RSA PKCS#1 v1.5 in certificates only |
| PKI | RFC 5280 path building and validation, name constraints (dNSName, iPAddress), EKU, RFC 6125 name matching with no CN fallback, SPKI pinning, a certificate builder for ephemeral agent identities, PKCS#8 and PEM loading (including OpenSSL's ML-DSA key format) |
| Revocation | **CRLs** (RFC 5280 §5), checked along the whole path on both sides from a caller-filled `CrlStore`, with `require_crl` to demand coverage, and `x509::crl::build` so a private CA can revoke an agent. OCSP stapling (RFC 6066, RFC 6960): client policy `Off`, `IfStapled` (default) or `RequireStaple`; staples must be signed by the issuer or its certified delegate and be current; a revoked certificate is always fatal. Servers staple a supplied response, and `x509::ocsp::build_response` mints one for a private CA. |
| Constrained links | `record_size_limit` (RFC 8449) in both directions |
| Privacy | **Encrypted Client Hello** (draft-ietf-tls-esni, HPKE per RFC 9180), client and server, over TCP and QUIC, including HelloRetryRequest and `retry_configs`. Configured ECH is used or the connection fails; the real name is never sent in the clear as a fallback. `isl probe --ech` fetches the host's configuration over DNS-over-HTTPS. |
| Profiles | `default`, `post-quantum`, `fips-140-3`, `cnsa-1`, `cnsa-2` (ML-KEM-1024, ML-DSA-87, AES-256), `dal-a` |
| Targets | `std`; `no_std + alloc` (builds for `thumbv7em-none-eabihf`) |

Named in the ontology but not implemented: ML-DSA-44, ML-KEM-512 and the
other groups and schemes marked so there. TLS 1.2 is excluded by design.
ML-KEM-1024 and ML-DSA-87 need IronCrypto 0.2.3 or later.

## Evidence that it interoperates

Two copies of the same misreading of an RFC interoperate perfectly, so the
in-memory tests are backed by handshakes with independent implementations:

* **Public servers** (`tests/interop.rs`): Cloudflare, Google and GitHub, every
  suite × {X25519, P-256}, a hybrid X25519MLKEM768 handshake with Cloudflare,
  a real HelloRetryRequest from Google, session resumption with Cloudflare
  that keeps the hybrid group, and **Encrypted Client Hello with Cloudflare**
  (its trace endpoint reports `sni=encrypted`), including the rejection path:
  a key Cloudflare does not hold is refused, the retry configurations it
  returns are authenticated, and the retry succeeds. All with full path
  validation to the system trust store.
* **OpenSSL 3.5** (`tests/openssl_interop.rs`), in both directions: the
  IronSocketLayer client against `openssl s_server` for 7 key types × 9 groups
  (keys generated by OpenSSL and loaded through IronSocketLayer's PKCS#8 parser,
  ML-DSA-65 and ML-DSA-87 included, and the groups include MLKEM1024 and
  SecP384r1MLKEM1024); `openssl s_client` verifying IronSocketLayer-minted
  chains for every key type × 9 groups; `openssl verify -x509_strict`
  accepting all-ML-DSA-65 and all-ML-DSA-87 chains IronSocketLayer issues; IronSocketLayer verifying OpenSSL client
  certificates for mutual TLS; and session resumption in both directions
  (OpenSSL reports `Reused, TLSv1.3` against the IronSocketLayer server); and OCSP
  stapling in both directions: IronSocketLayer verifies OpenSSL-generated
  responses (SHA-1 and SHA-256 CertIDs, good and revoked), and OpenSSL's
  `ocsp` verifier and `s_client -status` accept responses IronSocketLayer mints;
  and CRLs both ways: `openssl verify -crl_check` honours CRLs IronSocketLayer
  issues, and IronSocketLayer honours CRLs from `openssl ca -gencrl`; and
  post-handshake authentication: `s_client -enable_pha` answers the
  IronSocketLayer server's mid-session certificate request; and external PSKs
  both ways (`s_server -psk -nocert`, `s_client -psk`); and 0-RTT both ways
  (`s_server -early_data` answers a request IronSocketLayer sent only as early
  data, and `s_client -early_data` reports its early data accepted).
* **CNSA 2.0 with OpenSSL 3.5** (`tests/openssl_cnsa2.rs`), both ways:
  `profile:cnsa-2` with the FIPS gate on, against an OpenSSL restricted to
  MLKEM1024, TLS_AES_256_GCM_SHA384 and mldsa87. The client verifies an
  OpenSSL-generated ML-DSA-87 certificate, and OpenSSL verifies an
  all-ML-DSA-87 chain IronSocketLayer issued.
* **Published vectors**: RFC 9001 Appendix A (Initial secrets, packet key and
  IV, header protection for AES and ChaCha20), RFC 9180 Appendix A.1.1 (HPKE)
  and the RFC 8446 HelloRetryRequest constant.

Robustness is checked separately. Six libFuzzer targets under
AddressSanitizer cover every peer-facing parser and whole client, server and
QUIC connections (`fuzz/`). Branch coverage is measured, with each refusal it
found untested now pinned by a test that fails when the check is removed
(`docs/DO-178C.md`).

Both interop suites are `#[ignore]`d by default because they need the network or
`openssl`:

```console
$ cargo test -p iron-socket-layer --test interop -- --ignored
$ cargo test -p iron-socket-layer --test openssl_interop -- --ignored --test-threads=1
$ cargo test -p iron-socket-layer --test openssl_cnsa2 -- --ignored
```

## Using it

### Rust, blocking

```rust
use std::{io::{Read, Write}, net::TcpStream, sync::Arc};
use iron_socket_layer::{config::{ClientConfig, Profile}, report::Property, stream::TlsStream, x509::RootStore};

let config = Arc::new(ClientConfig::new(Profile::Default, RootStore::from_system()?)?.with_alpn(&[b"http/1.1"]));
let mut tls = TlsStream::connect(TcpStream::connect("example.com:443")?, config, "example.com")?;
assert!(tls.report().has(Property::ServerAuthenticated));
tls.write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")?;
```

### Rust, sans-I/O (any runtime, any transport, `no_std`)

```rust
let mut conn = iron_socket_layer::Connection::client(config, "example.com")?;
socket.send(&conn.take_tls());          // ClientHello
conn.read_tls(&socket.recv())?;          // server flight
socket.send(&conn.take_tls());          // client Finished
println!("{}", conn.report().to_json());
```

### Agent-to-agent mutual TLS with ephemeral identities

```rust
use iron_socket_layer::{config::*, crypto::sign::{KeyKind, SigningKey}, x509};

let key = SigningKey::generate(KeyKind::MlDsa65, &mut rng)?;         // post-quantum identity
let cert = x509::issue(&params, key.spki(), &ca_cert, &ca_key, &mut rng)?;
let client = ClientConfig::new(Profile::PostQuantum, private_roots)?
    .with_identity(Identity::new(vec![cert], key)?);
let server = ServerConfig::new(Profile::PostQuantum, server_identity)?
    .with_client_auth(ClientAuth::Required(PeerVerification::Roots(private_roots)));
```

With ML-DSA at every link of the chain, the report carries
`property:post-quantum-authentication` as well as
`property:post-quantum-key-exchange`. It carries it only then: one ECDSA
signature anywhere in the chain withdraws the claim.

### QUIC

```rust
use iron_socket_layer::{quic::{QuicConnection, Version}, Level};

let mut tls = QuicConnection::client(config, "example.com", &transport_params, Version::V1)?;
while let Some((level, bytes)) = tls.write_handshake() { /* CRYPTO frames at `level` */ }
tls.read_handshake(Level::Initial, &crypto_frame_data)?;
while let Some(k) = tls.next_key_change()? { /* install k.keys at k.level */ }
```

### Command line and MCP

```console
$ isl recommend intent:harvest-now-decrypt-later --json
$ isl ontology show group:x25519mlkem768
$ isl explain error:unknown-ca
$ isl probe example.com:443 --profile post-quantum --json
$ isl probe crypto.cloudflare.com --ech
$ isl serve --cert chain.pem --key key.pem --port 8443
$ isl capabilities
$ isl mcp        # { "mcpServers": { "iron-socket-layer": { "command": "isl", "args": ["mcp"] } } }
```

## FIPS 140-3 and DO-178C

**Neither IronSocketLayer nor IronCrypto is CMVP-validated, and neither holds a
DO-178C certification.** What they provide:

* **FIPS 140-3**: the `fips-140-3`, `cnsa-1` and `dal-a` profiles refuse to
  build a connection unless IronCrypto's module is operational in approved mode
  (`iron_socket_layer::policy::enable_fips()`), check every negotiated algorithm
  through `ic_fips::check`, and record the service indicators in the session
  report. See [docs/FIPS.md](docs/FIPS.md).
* **DO-178C DAL-A**: the `dal-a` profile narrows the protocol to one suite, one
  group, one scheme and mandatory mutual authentication. The code carries 79
  tagged low-level requirements traced to high-level requirements and to their
  verifying tests in [docs/TRACEABILITY.md](docs/TRACEABILITY.md). A test fails
  if that matrix drifts from the code. [docs/DO-178C.md](docs/DO-178C.md) lists
  what this supports and what a certification applicant must still produce.

## Compared with wolfSSL

wolfSSL is mature, small, broadly deployed, holds FIPS 140-3 certificates and
sells DO-178C DAL-A packages. IronSocketLayer holds neither, and says so. What it
does differently for agentic workloads is set out, with its gaps, in
[docs/COMPARISON.md](docs/COMPARISON.md).

## Repository

| Crate | |
|---|---|
| `crates/iron-socket-layer` | The protocol engine: TLS 1.3, QUIC-TLS, X.509, profiles, reports |
| `crates/isl-ontology` | The ontology: static, `no_std`, zero dependencies; exporters behind `std` |
| `crates/isl-cli` | `isl`: command line and MCP server |
| `bench/` | Handshake and throughput comparison with rustls; outside the workspace |
| `fuzz/` | libFuzzer targets for every peer-facing parser; outside the workspace |

```console
$ cargo test --workspace
$ cargo clippy --workspace --all-targets
$ cargo build -p iron-socket-layer --no-default-features --target thumbv7em-none-eabihf
```

IronCrypto is expected at `../AgenticCrypto` (path dependencies with a version
pin, so the workspace also resolves from a registry once published).

## License

AGPL-3.0-or-later, as IronCrypto. Encryption source code is export-controlled
(ECCN 5D002); see IronCrypto's `docs/EXPORT.md` before publishing.
