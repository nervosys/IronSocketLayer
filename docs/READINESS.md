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

See [VERIFICATION-2026-10-05.md](VERIFICATION-2026-10-05.md) for measured results
and their limits. Passing host tests and compiling for Cortex-M4 do not establish
hardware behavior or certification.

## Work that remains open

| Work | Completion evidence | Prerequisite / owner |
|---|---|---|
| Fixed-capacity engine | A separate caller-storage API for all handshake, record, certificate, report and key-wrapper buffers; overflow errors; zero allocator calls after initialization; worst-case memory/stack analysis; existing interoperability and robustness suites passing on the new backend | Repository engineering; this API is not implemented. See the scope below. |
| Uncovered production branches | Review each generated gap; add a requirements-based test for reachable required behavior, or document a reviewed justification for defensive/deactivated code | Maintainer and independent verifier; a CSV inventory is a lead, not a justification |
| Embedded execution | Run requirements-based tests and capacity failures on a named board with its clock, entropy source, allocator policy, compiler and linker configuration recorded | Target integrator; no physical board is connected to this workspace |
| Firmware footprint | Linked firmware map, measured peak stack and live memory under adversarial maximum inputs | Target integrator; unlinked object sizes exclude cryptography and link-time removal |
| Timing beyond the host experiment | Target assembly review and statistical measurements across representative valid and malformed inputs; include IronCrypto's primitive evidence | Target integrator and independent reviewer |
| Independent review | Findings, dispositions and signed review record by someone other than the author | Independent reviewer; author-written tests do not meet independence |
| DAL-A evidence | Project PSAC, SDP, SVP, SCMP, SQAP and standards; accepted MC/DC/object-code method; tool qualification or accepted alternative; IronCrypto life-cycle data; independent verification | Certification applicant and authority, as detailed in [DO-178C.md](DO-178C.md) |
| FIPS validation | IronCrypto CMVP submission and certificate, algorithm testing, security policy and platform entropy assessment | Module owner, laboratory and validating authority; see [FIPS.md](FIPS.md) |

## Fixed-capacity scope

Use `thumbv7em-none-eabihf` (Cortex-M4) as the reference compile target.
The existing `no_std + alloc` build is not a fixed-capacity build. Merely
reserving the connection's input buffer or using a bounded global heap would
not meet a rule prohibiting allocations after initialization: parsers, outgoing
flights, key wrappers and reports still create owned buffers.

A separate backend must accept caller-owned storage, return borrowed message
views, encode into caller-provided slices, and use fixed slots for keys and
certificate-path search. Configuration, trust anchors and signing identities
are initialized before the allocation gate closes. Preserve the existing alloc
API for other users; the storage API needs explicit lifetime and ownership rules.
Keep primitive operations in `src/crypto/`, verification mandatory, and
`forbid(unsafe_code)` intact.

Capacity is an application contract, not a protocol default: each build must
declare record, flight, certificate-chain, name, ALPN, extension, event and key
slot bounds and maximum concurrent connections. An input exceeding a capacity
must produce a traced error and latch failure without panic or partial success.
Certificate-path depth and signature-check budgets remain bounded. Do not
silently drop certificate facts or security properties to fit a buffer.

Acceptance requires boundary/one-over-limit tests for every capacity, an
allocator-gated full client/server handshake and data exchange, mutation tests
that catch allocation and bound regressions, and measured stack use on target.
These are implementation requirements for future work, not claims that the
current engine meets them.
