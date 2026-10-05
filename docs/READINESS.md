# Remaining engineering and external evidence

Status: 2026-10-05. Neither IronSocketLayer nor IronCrypto is FIPS 140-3
validated or DO-178C certified. `validated: false` remains unchanged.

## Repository work delivered

ML-KEM-512 and ML-DSA-44 now use the corresponding IronCrypto implementations.
They are available by explicit configuration. Named profiles retain their
previous parameter sets and preference order. Tests cover TCP, QUIC v1/v2,
OpenSSL key loading, signatures and certificate chains. Requirements
`REQ-KX-005` and `REQ-SIG-005` are traced in [TRACEABILITY.md](TRACEABILITY.md).

The README's requirement count and ECH reference are updated. CI now checks out
IronCrypto at the path Cargo actually requires. Reproducible tools for branch
coverage, trace-cited test selection, gap inventories, footprint measurements,
timing experiments and longer fuzz campaigns are in [scripts](../scripts/README.md).

A separate fixed-capacity TLS 1.3 engine, `iron_socket_layer::fixed`, runs
over caller-owned storage (requirements `REQ-FIX-001` to `REQ-FIX-005`,
HLR-015). It is described under the scope below.

See [VERIFICATION-2026-10-05.md](VERIFICATION-2026-10-05.md) for measured results
and their limits. Passing host tests and compiling for Cortex-M4 do not establish
hardware behavior or certification.

## Branch-gap review (author)

Every uncovered production branch in a whole-suite coverage run has a
recorded disposition in [coverage-review.csv](evidence/coverage-review.csv),
keyed by file, source line text and column so it survives edits elsewhere.
`scripts/coverage_review.py` checks a fresh gap inventory against it: every
gap must have a disposition, and no gap marked `tested` may still be
uncovered. Of the 352 gap keys reviewed, 290 now have requirements-based
tests, and the rest are `defensive` (46), `unreachable` (14) or
`environment` (2), each with a specific rationale. Every new test was
checked by breaking the condition it guards. A fresh whole-suite run
afterwards left 62 gap keys, every one reviewed and none marked `tested`.

The review found and fixed real defects:
- fixed engine: record_size_limit sent and enforced without negotiation;
- the fixed and owned path validators disagreed on an unparseable extra
  certificate, and reported different errors for the same bad leaf;
- IPv6 reference identifiers accepted a leading `+`;
- the PKCS#8 fallback reader accepted trailing bytes and fields, and ML-DSA
  algorithm parameters;
- server and client kept a post-quantum authentication claim after a
  classical post-handshake authentication;
- the client recomputed an external-PSK binder under the wrong hash after a
  HelloRetryRequest;
- an unrequested extension drew illegal_parameter instead of
  unsupported_extension;
- 0-RTT was held to the server's current policy rather than the ticket's
  limit;
- an empty PSK list drew illegal_parameter instead of decode_error; FIPS
  indicators dropped unknown signature schemes; long DER lengths could be
  truncated.

Known leniencies left in place deliberately: explicitly encoded DER DEFAULT
values (a v1 certificate version, a name-constraint minimum of 0) are
accepted, as many real CAs emit them; a byKey OCSP responder ID is not
compared to the signer's key hash (IronCrypto provides no SHA-1), though the
signature is still verified against an authorized key. P-521 keys are now
read by ic_pkix alone, like P-256 and P-384, so a P-521 scalar missing its
leading zero octet is refused.

## Work that remains open

| Work | Completion evidence | Prerequisite / owner |
|---|---|---|
| ML-DSA stack use | IronCrypto ML-DSA signing and verification with stack use suited to small targets (today, on the host, ML-DSA-87 signing alone needs 248 KiB of thread stack; see the verification report), with its own tests | IronCrypto maintainers; the primitive is not implemented in this repository |
| Independent review of branch-gap dispositions | An independent verifier confirms or overturns each author disposition in [coverage-review.csv](evidence/coverage-review.csv), especially every `defensive`, `unreachable` and `environment` row | Independent verifier; the author review is done (see below), but it is not independent |
| Embedded execution | Run requirements-based tests and capacity failures on a named board with its clock, entropy source, allocator policy, compiler and linker configuration recorded | Target integrator; no physical board is connected to this workspace |
| Firmware footprint | Linked firmware map, measured peak stack and live memory under adversarial maximum inputs, for both engines (host stack figures and Cortex-M4 per-function frames for the fixed engine are in the verification report) | Target integrator; unlinked object sizes exclude cryptography and link-time removal |
| Timing beyond the host experiment | Target assembly review and statistical measurements across representative valid and malformed inputs; include IronCrypto's primitive evidence | Target integrator and independent reviewer |
| Independent review | Findings, dispositions and signed review record by someone other than the author | Independent reviewer; author-written tests do not meet independence |
| DAL-A evidence | Project PSAC, SDP, SVP, SCMP, SQAP and standards; accepted MC/DC/object-code method; tool qualification or accepted alternative; IronCrypto life-cycle data; independent verification | Certification applicant and authority, as detailed in [DO-178C.md](DO-178C.md) |
| FIPS validation | IronCrypto CMVP submission and certificate, algorithm testing, security policy and platform entropy assessment | Module owner, laboratory and validating authority; see [FIPS.md](FIPS.md) |

## Fixed-capacity scope

Use `thumbv7em-none-eabihf` (Cortex-M4) as the reference compile target.
The `no_std + alloc` build of the owned engine is not a fixed-capacity build:
its parsers, flights, key wrappers and reports create owned buffers.

`iron_socket_layer::fixed::Connection` is a separate backend. The caller
declares byte capacities in `fixed::Storage` (record, handshake, outgoing,
application, certificates, private key, public key, scratch) and slot counts
in `fixed::Limits` (certificates, extensions, events, name, ALPN protocols).
Configuration, trust anchors and signing identities are built with the owned
API before the gate closes; the owned API is unchanged. Record protection,
key exchange and signing share `src/crypto/` with the owned engine, and
certificate paths are searched in fixed slots (at most 7 intermediates,
depth 8). Verification stays mandatory and `forbid(unsafe_code)` is intact.

What the tests establish, on the host:

* A full client/server handshake, application data, key update and export
  make zero allocator calls after initialization, under a counting global
  allocator, for every signing-key kind, HelloRetryRequest, revocation and
  each named profile (`tests/fixed_capacity.rs`).
* Every byte capacity on both sides has a found minimum, and one byte below it
  is `error:capacity-exceeded`. Every slot limit fails closed one below what
  the handshake needs.
* A failure latches, erases buffered and queued data, and repeats; mutated
  and truncated flights never panic; empty records and messages do not stall.
* ECH, PSK, tickets, early data, post-handshake and on-demand client
  authentication are refused with `error:invalid-config`, not ignored.
* The fixed path validator agrees with the owned one on every chain unit test
  (same decision or error kind, depth, schemes, strength and CRL coverage).
* The fixed engine interoperates with the owned engine and with OpenSSL
  3.5.7 in both directions: every implemented group, every key type, client
  certificates both ways and repeated KeyUpdate (`tests/openssl_fixed.rs`),
  with every engine call allocation-gated.
* IronCrypto's lazily built curve tables are built while the engine
  initializes; a fresh process whose first curve use is inside a handshake
  makes no allocation (`tests/fixed_cold_start.rs`).
* Any number of KeyUpdates in either direction leaves the connection up.
* `robustness.rs` mutates all three flights for the fixed engine, from
  seeded randomness: no panic, no allocation, every failure latched, any pair
  that still connects agrees on its exporter, and an intact stream delivers
  exactly.
* `peer_closed()` distinguishes an authenticated close from truncation.
* Mutations caught: removed record capacity check, an allocation in
  `receive`, removed early-data refusal, reverted empty-message fix, nonce
  consumed before the capacity check, two removed checks in the fixed path
  search, skipped table preparation, and an ignored Finished check (caught
  by a unit test; flight mutation cannot reach that check).
* Fuzzing the fixed server: see [the fuzz README](../fuzz/README.md).

OpenSSL interoperability found two defects that the in-process tests had
missed. Each peer KeyUpdate used an audit-event slot, so a long-lived session
failed after about 55 updates. The first P-256 signature verification in a
process allocated IronCrypto's table inside the handshake. Both are fixed and
covered by tests.

Capacity remains an application contract: each build declares its storage,
slot limits and maximum concurrent connections. Stack use is measured on the
host only (see the verification report); the target measurement belongs to
the firmware footprint row above. Host tests do not establish target behavior.
