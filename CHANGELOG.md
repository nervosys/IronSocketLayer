# Changelog

All notable changes to IronSocketLayer. The project is pre-1.0: minor
versions may change the API.

## Unreleased (to be 0.1.1)

Security fixes from the 2026-10-06 audit
([docs/SECURITY-AUDIT-2026-10-06.md](docs/SECURITY-AUDIT-2026-10-06.md)).
Upgrade from 0.1.0.

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

### Changed
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
