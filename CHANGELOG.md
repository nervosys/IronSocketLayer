# Changelog

All notable changes to IronSocketLayer. The project is pre-1.0: minor
versions may change the API.

## Unreleased

### Added
- `Common::required_properties`, set with `ClientConfig::require` and
  `ServerConfig::require`: the handshake fails with `error:policy-violation`
  (the missing property's id as context) before any application data is sent
  or accepted, in both engines. `validate()` refuses requirements that
  cannot be enforced in time (with 0-RTT) or met (mutual authentication
  without an identity or required client authentication).
- `ClientConfig::for_intent` and `ServerConfig::for_intent`: the
  configuration an intent calls for, from the ontology's selector (as
  `isl recommend`): its profile, its ALPN, and its needs as required
  properties. An unknown intent or an unavailable profile is an error, never
  a fallback. `config::IntentPolicy` re-exports the selector's policy flags.
- `config::Relaxation`, `ClientConfig::relaxations` and
  `ServerConfig::relaxations`: the safe defaults a configuration gives up
  (revocation off, 0-RTT, no ECH GREASE, SNI fallback, Selfie guard off).
  Every session report lists them as `relaxations`.
- `TlsStream::connect_with` and `accept_with` over TCP, with
  `stream::Timeouts`: a deadline for the whole handshake (a peer sending a
  byte at a time cannot stretch it) and an idle limit for each later read or
  write. Both fail with `io::ErrorKind::TimedOut`; after an idle timeout the
  stream remains usable.
- `Recovery`, `ErrorKind::recovery`, `Error::recovery` and
  `Connection::recovery`: what to do about an error as one of eight actions
  (`recovery:retry`, `reconnect`, `retry-with-ech-configs`, `fix-caller`,
  `ask-user`, `stop`, `fix-environment`, `report-bug`). The connection's
  version turns an ECH rejection without retry configurations into
  `ask-user`. The ontology's error catalog carries the same `action`, and
  `isl explain` and `isl probe` print it.
- Expiry warnings: `event:peer-certificate-expiring` and
  `event:local-certificate-expiring` (detail: seconds left) when a
  certificate in use expires within `Common::expiry_warning` (14 days by
  default; 0 never), at handshake completion and after post-handshake
  authentication. `SessionReport::local_not_after` (`localNotAfter`).
- Offline tools, as MCP tools and `isl` commands: `inspect_certificate`
  (`isl inspect`: names, validity, CA flag, key, signature, `spkiSha256`),
  `verify_chain` (`isl verify`: path, usage and name, with error id and
  action), and `check_config` (`isl check-config`: a configuration built
  from JSON with the library's validation, its requirements and
  relaxations; unknown keys and mistyped values are errors). Inputs are
  capped at 256 KiB. `Certificate::issuer_common_name`.

### Fixed
- `isl serve --bind <addr>` was parsed as a flag and its address ignored,
  so the server always bound 127.0.0.1.

### Changed
- Requires IronCrypto 0.2.15 or later, below 0.3. Its HPKE now also offers
  DHKEM(P-384, HKDF-SHA384); ECH here still uses the X25519 suite, whose
  outputs are unchanged.

## 0.2.1 (2026-10-06)

### Hardened
- The fixed-capacity client also sends ECH GREASE (`ClientConfig::ech_grease`),
  repeats it after HelloRetryRequest, and ignores retry configurations sent
  in answer. Its ClientHello grows by up to 350 bytes; turn `ech_grease` off
  where that matters.

### Verification
- Tests for the branches the 0.2.0 fixes opened; whole-suite branch
  coverage 97.70%, every remaining gap reviewed.
- `scripts/coverage.ps1` no longer merges profiles left by an earlier run.

## 0.2.0 (2026-10-06)

Security fixes from the 2026-10-06 audit
([docs/SECURITY-AUDIT-2026-10-06.md](docs/SECURITY-AUDIT-2026-10-06.md)).
Upgrade from 0.1.0. A minor version because the configuration and report
structs gained public fields and servers now refuse unknown SNI (see
Changed). Requires IronCrypto 0.2.13 or later, below 0.3.

### Fixed (security)
- Name constraints: a dNSName with a trailing dot no longer escapes an
  excluded subtree, and iPAddress constraints apply across address families
  (including IPv4-mapped IPv6).
- Denial of service:
  - extensions in certificates, CRLs and OCSP responses are capped before
    the duplicate check, which was quadratic;
  - certificate path search spends at most 24 signature verifications;
  - ClientHello extensions and key shares are capped;
  - KeyUpdate requests are answered once while silent;
  - ChangeCipherSpec records are bounded;
  - RSA exponents above 2^32 are refused;
  - OCSP responder candidates are limited.
- `TlsStream` reports truncation (no close_notify) as `UnexpectedEof`.
- Fixed engine: messages after a key change in the same record are
  refused, and ALPN with no overlap is refused.
- Owned engine: no records are accepted between the fragments of a
  handshake message.
- ECH retry configurations are returned only after `ech_rejected`.
- A non-CA trust anchor no longer issues certificates.
- A leaf cannot staple OCSP for itself.
- Pinned peers get the full leaf checks.
- Peer-driven counters saturate instead of overflowing.
- `isl` MCP `tls_probe` refuses loopback, private and link-local targets
  unless `ISL_MCP_ALLOW_PRIVATE=1`. Probes have an absolute deadline.
  `isl serve` binds 127.0.0.1 by default (`--bind`). Peer text is
  sanitized in terminal output.
- A server that requires client certificates no longer accepts an external
  PSK in their place.

### Hardened (weaknesses W-1 to W-12 of the audit)
- Selfie: with `std`, a server refuses an external-PSK ClientHello this
  process sent (`ServerConfig::selfie_guard`, on by default).
- A server refuses an SNI none of its certificates covers, with
  `unrecognized_name`, unless `ServerConfig::sni_fallback` is set.
- The client sends ECH GREASE when it has no ECH configuration
  (`ClientConfig::ech_grease`, on by default).
- A wildcard directly over a registry suffix such as `co.uk` matches
  nothing.
- A PSK-only server answers an unknown PSK identity as it answers a wrong
  binder.
- `MemoryReplayGuard::with_capacity`, and `event:replay-guard-full` when a
  full guard refuses early data.
- A client answers at most 16 post-handshake CertificateRequests per
  connection.
- `CrlStore::add_der_for_issuer` verifies a CRL once, at load.
- Indirect-CRL entries are attributed through certificateIssuer.
- Unread application data is bounded (`Common::max_buffered_plaintext`,
  1 MiB by default).
- An explicit v1 certificate version, or an explicit name-constraint
  minimum of 0, is refused (not DER).
- The record IV and `isl serve`'s private-key PEM text are zeroized.

### Added
- `SessionReport::peer_names` (`peerNames` in JSON): the peer certificate's
  subject alternative names. `isl probe` prints them.
- `ErrorKind::UnrecognizedName` (`error:unrecognized-name`).
- `x509::IpAddr` implements `Display` (RFC 5952 text).

### Changed
- An owned server refuses SNI it has no certificate for (see above); set
  `sni_fallback` for the old behaviour. The fixed server's refusal is now
  `error:unrecognized-name` instead of `error:handshake-failure`.
- A client and server in one process that share an external PSK must turn
  off `selfie_guard` on the server.
- `ServerConfig` and `ClientConfig` gained public fields; code building them
  with struct literals must set them.
- `Connection::ech_retry_configs()` returns `None` unless the handshake
  failed with `ech_rejected`.
- `TlsStream::read` returns `UnexpectedEof` where it used to return `Ok(0)`
  without close_notify.

## 0.1.0 (2026-10-05)

The first release. Not FIPS 140-3 validated, not DO-178C certified and not
independently reviewed; see [SECURITY.md](SECURITY.md).

### Protocols
- TLS 1.3 client and server (RFC 8446), sans-I/O, with a blocking
  `std::io` stream wrapper. Includes HelloRetryRequest, PSK resumption from
  tickets, external PSKs, opt-in 0-RTT with server-side anti-replay,
  post-handshake client authentication on demand, KeyUpdate and exporters.
- TLS for QUIC (RFC 9001), QUIC versions 1 and 2 (RFC 9369), including 0-RTT.
- Encrypted ClientHello (RFC 9849), client and server, over TCP and QUIC,
  with HPKE from IronCrypto's `ic-hpke`.
- X.509 path validation and issuance (RFC 5280), including name constraints,
  SPKI pinning, OCSP stapling (RFC 6066, RFC 6960) and CRLs, under a
  caller-chosen revocation policy.
- record_size_limit (RFC 8449), ALPN (RFC 7301).

### Post-quantum
- ML-KEM-512/768/1024 key exchange and the X25519MLKEM768,
  SecP256r1MLKEM768 and SecP384r1MLKEM1024 hybrids.
- ML-DSA-44/65/87 authentication, including certificates (RFC 9881).
- A CNSA 2.0 profile (ML-KEM-1024, ML-DSA-87, AES-256), interoperable with
  OpenSSL 3.5.

### For agents
- A machine-readable ontology (`isl-ontology`) of every protocol element,
  with named profiles and intents; `isl recommend` returns the profile for a
  purpose, or says it is unavailable rather than substituting a weaker one.
- Stable error ids, with `isl explain` giving their meaning and recovery.
- Session reports listing the security properties actually obtained.
- The `isl` command line and an MCP server (`isl mcp`).

### Embedded
- A separate fixed-capacity engine (`ironsocketlayer::fixed`) over
  caller-owned storage. It makes no allocator call after initialization and
  fails closed with `error:capacity-exceeded`. On an emulated Cortex-M4,
  every session needs 26 to 34 KB of stack.
- `no_std + alloc` for the main engine.

### Verification
- 231 low-level requirements, each traced to code and to a test or review.
- Interoperability with OpenSSL 3.5.7 in both directions, and with
  Cloudflare, Google and GitHub.
- Eight libFuzzer targets under AddressSanitizer.
- Whole-suite branch coverage of 97.6%, with a recorded disposition for
  every remaining gap.

### Requirements
- IronCrypto 0.2.11 or later, below 0.3.
- Rust 1.88 or later.
