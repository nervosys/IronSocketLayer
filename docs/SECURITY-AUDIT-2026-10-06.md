# Security audit, 2026-10-06

An audit of IronSocketLayer 0.1.0 against historical CVE classes for TLS and
X.509 implementations, MITRE ATT&CK, NIST FIPS publications and CMMC 2.0. It
covers the crates `ironsocketlayer`, `isl-ontology` and `isl-cli`. The
fixes are in 0.2.0.

**This is not an independent audit.** The project's author, with
AI-assisted review, examined code the same process wrote. It finds real
defects, as the results below show, but it is no substitute for review by
someone else. Nothing here claims FIPS 140-3 validation, CMMC certification
or DO-178C certification. None of those exists.

## Method

- **Dependencies.** `cargo audit` (RustSec, 1,290 advisories) on every
  lockfile: the library workspace, `fuzz/`, `bench/` and `embedded/qemu-m4`.
- **Code review.** Three parallel reviews, each working from a checklist of
  historical CVE classes:
  - handshake and protocol logic, in both engines;
  - certificate, CRL and OCSP handling;
  - resource exhaustion, memory, secrets and side channels, including the
    `isl` CLI and MCP server.

  Every suspected flaw was turned into a proof-of-concept test before it was
  counted.
- **Fixes.** Each fix has a regression test, and each test was confirmed to
  fail with its fix undone. The tests are in `tests/pki_hardening.rs`,
  `tests/protocol_hardening.rs` and the unit tests named below, and are traced
  in [TRACEABILITY.md](TRACEABILITY.md).
- **Afterwards.** With the findings and the W items fixed, the full suite
  passes (628 tests), along with clippy, the Cortex-M4 `no_std` build, the
  QEMU Cortex-M4 run of the fixed engine, the OpenSSL 3.5.7 interoperability
  and CNSA 2.0 suites, live handshakes with Cloudflare, Google and GitHub,
  and a five-minute AddressSanitizer fuzz campaign of all eight targets
  (about 30 million runs, no crashes or sanitizer reports).

## Findings

Severity is the reviewer's assessment, and the CVSS-style vectors are
indicative only. Every Medium and Low finding below is fixed.

| ID | Finding | Severity | Status |
|---|---|---|---|
| A-1 | A dNSName with a trailing dot (`victim.evil.com.`) escaped an excluded name-constraint subtree, in both path validators | Medium | Fixed, REQ-X509-071 |
| A-2 | iPAddress constraints were applied per address family: an IPv6 SAN escaped an IPv4-only permitted list; an IPv4-mapped IPv6 SAN escaped an excluded IPv4 subtree. An existing test asserted the bypass as correct. | Medium | Fixed, REQ-X509-072 |
| A-3 | Quadratic duplicate-extension scan before any signature check: a 128 KiB certificate cost ~350 ms (release) per parse, parsed several times per handshake | Medium (DoS) | Fixed, REQ-X509-073 |
| A-4 | Certificate path search could spend 100 signature verifications on a crafted same-key chain: 73 ms for a 5 KB P-521 chain, reachable by any client against a server that accepts client certificates | Medium (DoS) | Fixed, REQ-X509-076 |
| A-5 | `TlsStream` reported a transport closed without close_notify as a clean end of stream (truncation) | Medium | Fixed, REQ-CONN-011 |
| A-6 | Fixed engine applied handshake messages after a key change in the same record (RFC 8446 §5.1): stacked KeyUpdates, plaintext after ServerHello | Low | Fixed, REQ-REC-008 |
| A-7 | Owned engine accepted application data or alerts between fragments of a handshake message | Low | Fixed, REQ-CONN-009 |
| A-8 | ECH retry configurations from a handshake that failed for another reason (e.g. unknown CA) were readable; a careless retry would encrypt the real server name to an attacker | Low | Fixed, REQ-ECH-010 |
| A-9 | A non-CA certificate added as a trust anchor (to pin a peer) could issue certificates for any name | Low | Fixed, REQ-X509-074 |
| A-10 | A leaf trusted directly as an anchor could staple an OCSP response signed by its own key, and be reported revocation-checked | Low | Fixed, REQ-OCSP-033 |
| A-11 | Owned-engine SPKI pinning skipped leaf checks the fixed engine applies (EKU, CA flag, key usage, unknown critical extensions, RSA size) | Low | Fixed, REQ-X509-075 |
| A-12 | Peer-driven `u32` counters (KeyUpdates, tickets) could overflow and panic after ~2^32 messages; the early-data skip budget could overflow on 32-bit targets | Low | Fixed (saturating) |
| A-13 | Unbounded ChangeCipherSpec records during the owned handshake | Low (DoS) | Fixed, REQ-CONN-004 |
| A-14 | Each KeyUpdate request was answered with its own update: a 1:1 reflection | Low (DoS) | Fixed, REQ-CONN-010 |
| A-15 | ClientHello extension and key-share duplicate checks grew with the square of their count | Low (DoS) | Fixed, REQ-MSG-020 |
| A-16 | RSA public exponents up to 2^64 accepted: each verification six times the usual cost | Low (DoS) | Fixed, REQ-SIG-006 |
| A-17 | OCSP: every attached certificate cost a signature verification before the cheap purpose check | Low (DoS) | Fixed, REQ-OCSP-034 |
| A-18 | Fixed server continued when ALPN lists did not overlap (RFC 7301 §3.2; ALPACA), unless `require_alpn` | Low | Fixed |
| A-19 | MCP `tls_probe` could reach loopback, private and link-local addresses, including cloud metadata (SSRF-like network mapping by a prompt-injected agent); no absolute probe deadline; unbounded DNS response; `isl serve` bound 0.0.0.0; peer-supplied text printed raw to terminals | Low–Medium | Fixed: internal targets refused unless `ISL_MCP_ALLOW_PRIVATE=1`, 30 s deadline, 64 KiB cap, `--bind` defaulting to 127.0.0.1, control characters stripped |
| A-20 | Ticket plaintext buffer could reallocate while holding the resumption PSK, leaving an unzeroized copy | Low | Fixed (exact capacity) |
| A-21 | A server configured with `ClientAuth::Required` and external PSKs accepted a PSK in place of the required client certificate | Low | Fixed, REQ-EPSK-006 |

### Weaknesses, hardened after the audit

The audit first listed these as accepted. Each has since been changed; what
remains is noted.

| ID | Item | Now |
|---|---|---|
| W-1 | External-PSK "Selfie" reflection (RFC 9257 §4.1): a node using one external PSK as both client and server accepts its own reflected ClientHello | With `std`, a server refuses an external-PSK ClientHello this process sent (`ServerConfig::selfie_guard`, on by default), REQ-EPSK-005. The guard is process-local and absent without `std`; one key per direction remains the real defence, and the `ExternalPsk` documentation says so. |
| W-2 | The owned server presented its default certificate for an SNI that matched no identity | Refused with `unrecognized_name` in both engines unless `ServerConfig::sni_fallback` is set; a hello without SNI still gets the first identity. REQ-NEG-002, new `error:unrecognized-name`. |
| W-3 | No ECH GREASE | The owned client sends a GREASE `encrypted_client_hello` when it has no ECH configuration (`ClientConfig::ech_grease`, on by default) and ignores retry configurations sent in answer, REQ-ECH-011. The fixed-capacity client does not GREASE. |
| W-4 | Wildcards were not checked against a public-suffix list | A wildcard directly over `<registry label>.<two-letter country code>` (`*.co.uk`, `*.com.au`, ...) matches nothing, REQ-X509-078. A heuristic: no public-suffix list ships in a zero-dependency library, so private suffixes are not caught. |
| W-5 | External-PSK identities could be enumerated: a known identity with a wrong binder was fatal, an unknown one was not | A PSK-only server now answers an unknown identity with `decrypt_error` after the same binder computation, REQ-EPSK-007. A server that also has certificates still falls back to the certificate handshake for an identity it does not know, and a ticket holder can still tell whether a ticket is live; both follow RFC 8446 §4.2.11. Use unguessable identities. |
| W-6 | A full in-memory 0-RTT replay guard refused early data for everyone until entries expired | Still fails safe, but `MemoryReplayGuard::with_capacity` sizes it, and the server reports `event:replay-guard-full`, REQ-0RTT-006. |
| W-7 | An authenticated server could request post-handshake client authentication without limit | A client answers at most 16 requests per connection, REQ-PHA-005. |
| W-8 | CRLs were re-verified on every handshake | `CrlStore::add_der_for_issuer` verifies a CRL once, at load, bound to its issuer's key, REQ-CRL-028. CRLs added with `add_der` are still verified per handshake. |
| W-9 | Indirect-CRL entries were attributed to the CRL issuer | Entries are attributed through certificateIssuer (RFC 5280 §5.3.3); one attributed to another issuer no longer revokes, REQ-CRL-027. Indirect CRLs still never show a certificate good. |
| W-10 | The sans-I/O owned engine buffered application data until the application read it | Bounded by `Common::max_buffered_plaintext` (1 MiB by default), including accepted 0-RTT data; beyond it the connection fails closed, REQ-CONN-012. |
| W-11 | Only `peer_subject_cn`, which is informational, named the peer in the report | `SessionReport::peer_names` (`peerNames` in JSON) lists the certificate's subject alternative names, and survives resumption, REQ-RPT-003. |
| W-12 | Explicitly encoded DER DEFAULT values (a v1 version, a name-constraint minimum of 0) were accepted | Refused, REQ-X509-077. |

Also after the audit: a record protector's static IV is zeroized on drop
(REQ-REC-009), and `isl serve` wipes the private-key PEM text once parsed.

## CVE classes: historical vulnerabilities, assessed

| Class (example CVEs) | Result |
|---|---|
| Buffer over-read, use-after-free, memory corruption (Heartbleed, CVE-2014-0160) | Not affected: `#![forbid(unsafe_code)]`, no heartbeat extension; parsers fuzzed under ASan |
| CCS injection (CVE-2014-0224) | Not affected: CCS only as the exact compatibility byte, in a window, and now bounded |
| Protocol downgrade (FREAK, Logjam, POODLE: CVE-2015-0204, -4000, CVE-2014-3566) | Not affected: TLS 1.3 only; `supported_versions` required; no export or CBC suites |
| Bleichenbacher / ROBOT (CVE-2017-13099) | Not affected: no RSA key transport in TLS 1.3 |
| Lucky13, padding oracles (CVE-2013-0169) | Not affected: AEAD only; constant-time padding scan, assembly reviewed on Cortex-M4 |
| Invalid-curve and small-subgroup key shares (CVE-2015-7940) | Not affected: points validated by IronCrypto; all-zero X25519 output refused; ML-KEM keys checked (proof-of-concept test passed) |
| Name-constraint bypass (CVE-2022-3602/3786, CVE-2021-3450 class) | **Affected (A-1, A-2), fixed.** Email, URI and other forms fail closed. |
| GeneralName type confusion (CVE-2023-0286, CVE-2020-1971) | Not affected: every comparison checks the name type first |
| Explicit curve parameters causing an infinite loop (CVE-2022-0778) | Not affected: only named curves accepted, before any arithmetic |
| Certificate policy-tree exponential cost (CVE-2023-0464) | Not affected: no policy tree; critical policy constraints fail closed |
| Path-building denial of service | **Affected (A-4), fixed** |
| basicConstraints ignored on intermediates | Not affected: cA required of every issuer; **anchor variant (A-9) fixed** |
| Hostname verification errors (wildcards, embedded NUL, CN fallback) | Not affected: left-most whole-label wildcards only, no CN fallback, NUL refused; trailing-dot normalisation in constraints fixed (A-1) |
| Signature algorithm confusion, SHA-1 / MD5 | Not affected: TBS and outer algorithms must match byte for byte; SHA-1 and MD5 not accepted for signatures |
| OCSP response forgery, delegated responder misuse | Not affected: issuer-certified responder with id-kp-OCSPSigning required; self-attestation (A-10) fixed |
| Session ticket forgery, PSK binder errors | Not affected: AEAD-sealed tickets, constant-time binder check over the right transcript |
| 0-RTT replay | Mitigated: single-use replay guard, first identity only, freshness window |
| Truncation (cf. CVE-2013-1606 class) | **Affected (A-5), fixed** |
| ALPACA cross-protocol (2021) | Client strict; owned server strict; **fixed-server gap (A-18) fixed**; default-certificate behaviour W-2 |
| KeyUpdate and renegotiation DoS (cf. CVE-2011-1473) | No renegotiation; **reflection (A-14) and stacking (A-6) fixed** |
| Timing side channels in comparisons (cf. CVE-2018-0737 class) | Not affected: Finished, binders, cookies, ECH confirmation, ticket names and pins use constant-time comparison |

**Dependencies.** The library's lockfile contains IronCrypto and first-party
crates only, and no advisory applies. The excluded crates have:
- `bench/`: rustls 0.23.45, already past RUSTSEC-2026-0285;
- `embedded/qemu-m4`: `bare-metal` 0.2.5 (RUSTSEC-2026-0110, unmaintained),
  pulled in by `cortex-m` 0.7. It is a measurement harness, never in the
  library.

## MITRE ATT&CK

How the library resists, or could help, each technique relevant to a TLS
implementation.

| Technique | Relevance | Controls in this library |
|---|---|---|
| T1557 Adversary-in-the-Middle | Interception or impersonation | Mandatory peer authentication with no off switch; path validation with name constraints (A-1, A-2 fixed); pinning with leaf checks (A-11); downgrade refusal; ECH; truncation detection (A-5) |
| T1040 Network Sniffing | Passive capture, including harvest-now-decrypt-later | TLS 1.3 forward secrecy; ML-KEM hybrids by default; ECH hides the server name |
| T1600.001 Weaken Encryption: Reduce Key Space | Forcing weak parameters | Named profiles refuse rather than substitute; minimum RSA sizes; `isl` warns against retrying with a weaker profile |
| T1562 Impair Defenses | Disabling verification | No API to disable certificate verification exists (AGENTS.md) |
| T1190 Exploit Public-Facing Application | Parser and memory bugs | Memory-safe Rust, `forbid(unsafe_code)`, no panics on peer input, fuzzing, 97.6% branch coverage with every gap dispositioned |
| T1499.002/.003/.004 Endpoint Denial of Service | CPU and memory exhaustion | A-3, A-4, A-6, A-12 to A-17 fixed; bounded buffers throughout; fixed-capacity engine |
| T1552.004 Unsecured Credentials: Private Keys | Key theft from memory | Keys and secrets zeroized on drop (A-20 fixed); no key export API; no keylog facility |
| T1195.001/.002 Supply Chain Compromise | Malicious dependency | Zero third-party dependencies in the library; IronCrypto is first-party; `cargo audit` clean |
| T1046 / T1590 Network Service and Victim Network Discovery | Agent-driven probing via MCP | A-19 fixed: internal addresses refused by default |
| T1573 Encrypted Channel (adversary use) | Any TLS library can carry command-and-control traffic | Out of scope for a library; noted for completeness |

## NIST FIPS and related publications

| Publication | Status |
|---|---|
| FIPS 140-3 | **Not validated.** IronCrypto, the module boundary, holds no CMVP certificate. The `fips-140-3`, `cnsa-1`, `cnsa-2` and `dal-a` profiles route every algorithm through IronCrypto's module gate (`ic_fips::check`): non-approved algorithms are refused, and the module must be in approved mode, in both engines (`tests/fips.rs`, `coverage_fixed.rs::leaving_fips_approved_mode_latches_failure`). Service indicators are reported. Reports say `"validated": false`. See [FIPS.md](FIPS.md). |
| FIPS 197, 180-4, 198-1 (AES, SHA-2, HMAC) | Implemented in IronCrypto, tested against NIST vectors there |
| FIPS 186-5 (ECDSA, EdDSA, RSA) | IronCrypto; this library enforces scheme and curve pairing, and RSA ≥ 2048 bits (≥ 3072 for CNSA and DAL-A profiles) with exponent ≤ 2^32 (A-16) |
| FIPS 203, 204 (ML-KEM, ML-DSA) | IronCrypto, tested against NIST ACVP vectors there; interoperable with OpenSSL 3.5 here |
| SP 800-52 Rev. 2 (TLS guidelines) | TLS 1.3 only; AES-GCM suites and NIST curves in the FIPS profile; certificate validation per RFC 5280; OCSP stapling supported |
| SP 800-131A (algorithm transitions) | No SHA-1 or MD5 signatures; RSA below 2048 bits refused |
| SP 800-90A/B (DRBG and entropy) | DRBG from IronCrypto; platform entropy assessment (90B) is open, recorded in FIPS.md |

## CMMC 2.0 (Level 2, NIST SP 800-171 Rev. 2)

CMMC assesses organisations and their systems, not libraries. The table shows
which practices this library supports when used correctly, and one it
cannot meet.

| Practice | Assessment |
|---|---|
| SC.L2-3.13.8 Data in Transit | Supports: TLS 1.3 confidentiality and integrity for CUI in transit |
| **SC.L2-3.13.11 CUI Encryption** | **Not met by this library.** It requires FIPS-validated cryptography, and IronCrypto is not CMVP-validated. The FIPS profile restricts to approved algorithms but does not make the module validated. A deployment that needs this practice must use a validated module. |
| SC.L2-3.13.15 Communications Authenticity | Supports: mandatory server authentication; mutual TLS and on-demand client authentication; exporters for channel binding |
| SC.L2-3.13.10 Key Management | Partly: keys and secrets are zeroized and never exported; key generation, storage and rotation are the system's responsibility |
| IA.L2-3.5.2 Authentication | Supports device authentication with client certificates or pinned keys |
| AU.L2-3.3.1 System Auditing | Supports: each session reports its security properties and an event trail, as JSON |
| CM.L2-3.4.2 Security Configuration Settings | Supports: named profiles and intents give reviewable baselines that refuse rather than downgrade |
| SI.L1-3.14.1 Flaw Remediation | Process in place: [SECURITY.md](../SECURITY.md), this audit, and fixed releases |

## Recommendations

1. Have an independent party review this audit and the code. This audit is
   the author's.
2. Publish the fixed release, then a GitHub security advisory (and RustSec
   entry) for 0.1.0 covering A-1 to A-5.
3. Re-run this checklist when the handshake, X.509 code or CLI change.
4. W-1: the Selfie guard is a backstop. Provision external PSKs per
   direction, and consider RFC 9258 importers.
