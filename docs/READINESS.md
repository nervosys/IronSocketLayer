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

## Work that remains open

| Work | Completion evidence | Prerequisite / owner |
|---|---|---|
| Fixed-capacity engine: remaining evidence | Measured worst-case stack on target; OpenSSL interoperability and the `robustness.rs` flight mutations run against `fixed::Connection` (today they exercise the owned engine, and the fixed engine is checked against the owned one); a longer `fixed_server` fuzz campaign | Repository engineering for the suites; target integrator for stack measurement. See the scope below. |
| Uncovered production branches | Review each generated gap; add a requirements-based test for reachable required behavior, or document a reviewed justification for defensive/deactivated code | Maintainer and independent verifier; a CSV inventory is a lead, not a justification |
| Embedded execution | Run requirements-based tests and capacity failures on a named board with its clock, entropy source, allocator policy, compiler and linker configuration recorded | Target integrator; no physical board is connected to this workspace |
| Firmware footprint | Linked firmware map, measured peak stack and live memory under adversarial maximum inputs | Target integrator; unlinked object sizes exclude cryptography and link-time removal |
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
* The fixed engine interoperates with the owned engine in both directions.
* Mutations caught: removed record capacity check, an allocation in
  `receive`, removed early-data refusal, reverted empty-message fix, nonce
  consumed before the capacity check, and two removed checks in the fixed
  path search.

Capacity remains an application contract: each build declares its storage,
slot limits and maximum concurrent connections. Measured stack use on the
target, and the suites listed in the table above, are still open. Host tests
do not establish target behavior.
