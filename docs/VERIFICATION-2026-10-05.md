# Verification results, 2026-10-05

These results cover the ML-KEM-512 / ML-DSA-44 bindings and verification tools
introduced alongside this report, on top of `b1eb7c2`. IronCrypto was
`a7f7f460b605dab4c384ad37247214e5e01e5fe6` (0.2.7), with a clean worktree.
The host is Windows 11, Ryzen 9 9900X. Stable rustc is 1.98.1; nightly is
1.100.0-nightly (bba531001, 2026-09-20). The machine was shared with other
workloads; these are host observations, not certified target results.

## Checks and independent implementation

Workspace tests, Clippy with warnings denied, and Cortex-M4 `no_std + alloc`
builds pass. The trace matrix names 220 low-level requirements. Library unit
tests: 251 pass; the statistical timing experiment is ignored in ordinary runs.
TCP and QUIC v1/v2 tests explicitly configure ML-KEM-512 with an all-ML-DSA-44
certificate chain and check negotiated parameters, post-quantum authentication
and data/packet protection. All named profile lists remain unchanged.

Debian WSL OpenSSL 3.5.7 passes all 13 interoperability tests and the separate
CNSA 2.0 test. The expanded matrix includes 10 groups and 8 OpenSSL-generated
key types on the client side; the server side includes all 7 generated key kinds
(RSA is tested separately by existing fixtures). OpenSSL verifies our
ML-DSA-44/65/87 certificate chains. Committed throwaway ML-DSA-44 fixtures
check seed and seed-plus-expanded PKCS#8 forms, OpenSSL-derived public keys,
OpenSSL signatures, and refusal when the seed and expanded key disagree.
Wire identifiers were checked against [IANA TLS Parameters](https://www.iana.org/assignments/tls-parameters)
and certificate identifiers against [RFC 9881](https://www.rfc-editor.org/rfc/rfc9881.html).

## Mutation checks

| Deliberate break | Test that failed |
|---|---|
| Route ML-KEM-512 to ML-KEM-768 | `mlkem512_agrees_with_the_parameter_specific_ironcrypto_api` |
| Give ML-DSA-44 the ML-DSA-65 OID | `keys_written_by_openssl_load_with_the_public_key_openssl_derives` |
| Remove the record plaintext bound | `record_boundaries_are_checked_directly` |
| Remove HKDF label/vector bounds | `crypto_interface_length_bounds` |
| Restore a backward early-exit padding scan | `padding_scan_timing_experiment` |

The initial self-handshake test survived the wrong ML-KEM routing because
both endpoints made the same mistake. The direct parameter-specific API test
was added and caught it. All mutations were restored before final checks.

## Coverage

Nightly branch instrumentation, cargo-llvm-cov 0.8.4, raw LLVM profile merge
and export. [scripts/coverage.ps1](../scripts/coverage.ps1) reproduces the runs;
[scripts/coverage_gaps.py](../scripts/coverage_gaps.py) produces the inventories.

| Selection | Merged production branch outcomes | Uncovered locations |
|---|---:|---:|
| Whole ordinary suite | 1,903 / 2,112 (90.10%) | 201 |
| Tests cited by Test rows in traceability | 1,816 / 2,112 (85.98%) | 266 |

These figures merge repeated source locations and exclude trailing unit-test
modules. Raw LLVM file branch summaries, which include test source and retain
instantiation distinctions, were 90.09% and 86.70% respectively for
`crates/ironsocketlayer/src/`. Do not compare these directly to older reports
without checking their aggregation method. Ignored OpenSSL/network tests were
verified separately and are not included in these coverage percentages.

The inventories are [whole-suite gaps](evidence/coverage-whole-20261005.csv)
and [trace-cited test gaps](evidence/coverage-requirements-20261005.csv).
Coverage led to new direct record-boundary and crypto-interface length tests.
Remaining gaps are not automatically justified as defensive or deactivated
code; their review remains open. This does not establish MC/DC. A fresh probe
confirms this nightly rejects `-Zcoverage-options=mcdc`.

## Fuzzing

Six libFuzzer / AddressSanitizer campaigns ran concurrently, each with a
600-second requested limit and 601 seconds reported. Corpus generation and
seed replay included the new parameter sets. No crashes, sanitizer reports,
timeouts or slow units; every process exited successfully. Total:
169,688,310 executions. Windows ASan does not provide leak detection here.

| Target | Executions | Final coverage edges |
|---|---:|---:|
| messages | 39,269,009 | 1,508 |
| records | 115,134,742 | 58 |
| pki | 5,940,957 | 3,445 |
| tls_server | 1,198,684 | 5,682 |
| tls_client | 355,341 | 4,300 |
| quic_server | 7,789,577 | 2,591 |

An earlier campaign was interrupted by a corpus working-directory mistake;
the corpus was regenerated and all six campaigns restarted. Only completed
replacement campaigns are counted here. The scripted runner was also checked
with a short `records` run. Clean runs establish only that these inputs found
no crash; they do not establish absence of defects.

## Timing and Cortex-M4 assembly

The release padding-scan experiment randomly selects between two 16,384-byte
inputs whose final nonzero byte is at offset 0 or 16,383, measures batches of
64 scans, and uses 20,000 samples. Original run: means 797.33 / 793.62 ns,
Welch t = 1.0501. After mutation and restoration: means 788.36 / 784.76 ns,
t = 1.7678. Both were below the investigation threshold |t| = 4.5.
The broken early-exit scan produced t = 265.4375 and the test failed.
This experiment covers two input classes on one host, not every timing channel.

The Cortex-M4 release assembly of `record::content_end` was inspected.
Its conditional control-flow branches use the public buffer length and block
offset (including the offset overflow check). Byte-derived predicates become
`it ne` / `movne` instructions and masks. The tail-copy call length is public.
There is no early return or branch controlled by the padding position in this
object. Predicated instruction timing and the rest of the firmware still need
target measurements; this is source-author review, not independent approval.
The footprint script emits the function's assembly for repeat review.

## Footprint measurements and limits

`thumbv7em-none-eabihf`, release, LTO off, native object emission: protocol
object text = 311,594 bytes; data = 0; BSS = 0. Object SHA-256:
`e63f35c2dbb40b03180aef5db4d2a4ab4d9dfdfd174e7f5248b867cc4d9f2e79`.
This unlinked object excludes IronCrypto and linker removal of unused code;
it is not final firmware flash size or a RAM bound.

Host inline storage (64-bit): Connection 2,080 bytes; QuicConnection 2,256;
ClientConfig 328; ServerConfig 280; SessionReport 376. Owned Vec/Box/Arc
allocations and stack scratch space are excluded. These figures predate the
fixed-capacity engine, which stores AEAD state inline in each record
protector; the addendum below re-measures them. Peak stack measurements and execution on
physical hardware remain open in [READINESS.md](READINESS.md), which also
summarizes the fixed-capacity engine's host evidence.

## Addendum: fixed-capacity engine

Measured later on 2026-10-05 with the fixed-capacity engine
(`ironsocketlayer::fixed`) in place, same host and IronCrypto commit.

### Footprint

`scripts/footprint.ps1`, same settings as above: protocol object text =
378,368 bytes (was 311,594; the difference is mostly the fixed engine);
data = 0; BSS = 0. Object SHA-256:
`1fb098d856ef34861ddbd7d5d4f58b74acf9cc7c829909c4dbb7a93f45d88561`.

Host inline storage (64-bit): Connection 3,136 bytes (was 2,080: the AEAD
state is now inline rather than boxed); QuicConnection 3,312; ClientConfig
328; ServerConfig 280; SessionReport 376; `fixed::Connection` 5,056;
`fixed::Report` 168. The fixed engine's buffers are whatever the caller
lends it, in addition; the tests use about 250 KiB per endpoint and find the
minimum for each buffer by search.

### Stack

Cortex-M4 per-function frames, from the compiler (`-Z emit-stack-sizes`, now
part of the footprint script, which writes the 40 largest). Largest in the
fixed engine's path: `fixed::Connection::client` 7,936 bytes (it builds the
5 KiB connection value), `crypto::hkdf_extract` 5,432 and
`crypto::hkdf_expand` 5,368 (IronCrypto's HMAC state, inlined; its
`Hmac<Sha384>::new` alone is 3,624), `x509::verify_chain_fixed` 3,872,
`fixed::hello_fingerprint` 1,840, `fixed::Connection::install_handshake`
1,800. These are single frames, not a call-chain worst case: no call-graph
tool was available, and the path search recurses (bounded at depth 8).
IronCrypto's own frames are not in this object. IronCrypto commit 46d082a absorbs the HMAC pads in place and keeps
SHA-384/512 key setup out of line. It reports, for a linked Cortex-M4 binary
with fat LTO at full call depth, HMAC-SHA384 down from 11,072 to 7,888 bytes
and HKDF-SHA384 extract-and-expand from 14,824 to 11,440. Our unlinked
per-function frames for the HKDF wrappers stay about 5.3 KB. That is one
1.7 KiB HMAC-SHA384 state and its working space: moving each hash's state
into its own out-of-line function was tried here and gained nothing, so
it was not kept.

Host peak thread stack, Linux x86_64 under WSL, release build, rustc 1.95.0,
from `cargo run --release --example fixed_stack`. Each figure is the smallest
4 KiB-granular thread stack, found by binary search in fresh processes, on
which a complete mutual-TLS session succeeds. The session covers both
constructors (including the one-time curve-table build), the handshake, data
both ways, KeyUpdate, an exporter and close. Both endpoints' connection values
are on that stack.

| Case | Stack |
|---|---:|
| ECDSA P-256/P-384/P-521 or Ed25519 keys, SecP384r1MLKEM1024 | 64 KiB |
| ECDSA P-256, each other implemented group | 60–64 KiB |
| ML-DSA-44 keys | 128 KiB |
| ML-DSA-65 keys | 184 KiB |
| ML-DSA-87 keys | 264 KiB |
| IronCrypto alone: ML-DSA-44 / 65 / 87 sign | 112 / 164 / 248 KiB |
| IronCrypto alone: ML-DSA-44 / 65 / 87 verify | 84 / 124 / 192 KiB |
| IronCrypto alone: Ed25519 verify | 36 KiB |
| IronCrypto alone: ECDSA sign or verify, any curve | ≤ 16 KiB (platform minimum) |

ML-DSA dominated, and its stack was IronCrypto's: the session figure was
the primitive's plus about 16 KiB. IronCrypto commit b0dbcb4 stops ML-DSA
holding the matrix A: each entry is resampled where it is used. Measured
again the same way on that commit:

| Case | Before | After |
|---|---:|---:|
| Session, ML-DSA-44 / 65 / 87 keys | 128 / 184 / 264 KiB | 64 / 64 / 68 KiB |
| Session, ECDSA or Ed25519 keys, any group | 60–64 KiB | 64 KiB |
| IronCrypto alone: ML-DSA-44 / 65 / 87 sign | 112 / 164 / 248 KiB | 32 / 40 / 48 KiB |
| IronCrypto alone: ML-DSA-44 / 65 / 87 verify | 84 / 124 / 192 KiB | 32 / 36 / 32 KiB |

Every session now needs about the same stack, which is the engine's own.
IronCrypto reports, from its byte-granular stack painting on Windows, the
same reductions: ML-DSA-87 sign 242.6 to 47.7 KiB, verify 174.5 to 17.8 KiB,
keygen 345.0 to 55.0 KiB. Signing takes 1.7 to 1.9 times as long, and
verification is unchanged. Outputs are unchanged: IronCrypto's ACVP cases
pass, and so do this repository's tests and the OpenSSL suites (OpenSSL
verifies our ML-DSA signatures and certificate chains). Host frames differ
from Cortex-M4 frames, so these are not target figures.

### Interoperability, robustness and fuzzing

`tests/openssl_fixed.rs` runs against OpenSSL 3.5.7 with every engine call
allocation-gated. It covers the fixed client against `s_server` for 8 key types
× 10 groups, `s_client` against the fixed server for 7 key kinds × 10 groups,
client certificates in both directions, and 80 KeyUpdates each asking
OpenSSL to update too. All 5 tests pass. The owned-engine interoperability
suite (13) and CNSA 2.0 still pass.

The OpenSSL runs found two defects that the in-process tests had missed.
Each peer KeyUpdate recorded an audit event, so the 64-slot default failed a
session after about 55 updates. And the first ECDSA verification in a
process built IronCrypto's P-256 table inside the allocation gate. Both
were fixed, each with a test that failed before its fix: 
`key_updates_are_unbounded_in_number`, and `tests/fixed_cold_start.rs`, which
needs a separate process because any earlier key generation hides the
allocation.

`tests/robustness.rs` now runs 1,500 seeded mutations across the three
flights of a fixed-engine handshake. An earlier version of this report said
it catches an ignored Finished check. That was wrong: the apparent catch was
an intermittent false failure in the test, since fixed. Flight mutation
cannot reach the Finished check, because a changed ClientHello changes the
keys and a changed encrypted flight fails AEAD first. A unit test
(`fixed::finished_tests::a_wrong_client_finished_is_refused`) now hands the
server's Finished handler a wrong verify_data at the point a real handshake
reaches it, and ignoring the check makes that test fail.

### Branch coverage after the gap review

Same tools and aggregation as the coverage section above, now including the
fixed engine and its test binaries. The coverage script finds test binaries
from `tests/*.rs`, where it previously used a fixed list.

| Selection | Merged production branch outcomes | Uncovered locations |
|---|---:|---:|
| Before the review (fixed engine included) | 2,335 / 2,732 (85.47%) | 365 |
| Whole ordinary suite, after | 2,683 / 2,750 (97.56%) | 67 |
| Tests cited by Test rows in traceability, after | 2,631 / 2,750 (95.67%) | 115 |

Every gap in the 365-location inventory was reviewed, as 352 keys (file,
source text, column). Five reviewers worked by area in separate worktrees,
writing requirements-based tests and checking each one by breaking the
condition it guards. The dispositions are in
[coverage-review.csv](evidence/coverage-review.csv): 290 tested, 46
defensive, 14 unreachable, 2 environment. On the fresh run, all 62 remaining
gap keys have a disposition, and none is marked tested
(`scripts/coverage_review.py`). The inventories are
[whole-suite gaps](evidence/coverage-whole-20261005b.csv) and
[trace-cited test gaps](evidence/coverage-requirements-20261005b.csv).

The review found real defects, all fixed with tests that fail without the
fix; [READINESS.md](READINESS.md) lists them. The traceability matrix now has
231 low-level requirements. The new ones cover the post-quantum
authentication claim rule, suite selection, `wants_write`, QUIC's refusal of
TLS KeyUpdate, error text, and the audit trail bound. The dispositions are
the author's and await independent review. This is branch coverage, not
MC/DC.

### Emulated Cortex-M4

`embedded/qemu-m4`, run by `scripts/qemu-m4.sh`: the fixed engine linked for
`thumbv7em-none-eabihf` with fat LTO and `opt-level = "s"`, on QEMU 10.0.13's
MPS2-AN386 board. Toolchain: Rust 1.99.0. IronCrypto: 0.2.8. Each case runs a
whole mutual-TLS session between a fixed client and a fixed server in one
thread: both constructors, the handshake, data both ways, KeyUpdate, an
exporter and close_notify. Peak stack is found by painting the free stack.
Allocations are counted after both constructors.

Peak stack per session, by IronCrypto version. Every case made zero
allocator calls after initialization.

| Signing keys | Group | 0.2.8 | 0.2.9 | 0.2.10 + split verify |
|---|---|---:|---:|---:|
| ECDSA P-256 | X25519 | 29,440 B | 29,440 B | 26,104 B |
| ECDSA P-256 | X25519MLKEM768 | 55,844 B | 31,004 B | 31,004 B |
| Ed25519 | X25519MLKEM768 | 55,844 B | 31,608 B | 31,004 B |
| ECDSA P-384 | SecP384r1MLKEM1024 | 63,012 B | 31,996 B | 31,996 B |
| ML-DSA-44 | ML-KEM-512 | 50,020 B | 44,836 B | 30,348 B |
| ML-DSA-65 | X25519MLKEM768 | 55,844 B | 51,428 B | 31,924 B |
| ML-DSA-87 | SecP384r1MLKEM1024 | 63,012 B | 60,404 B | 34,308 B |
| ML-DSA-87 | ML-KEM-1024 | 63,012 B | 60,404 B | 34,308 B |

With 0.2.8 the key-exchange group set the peak: ML-KEM needed 20 to 34 KB.
IronCrypto 0.2.9 (commit 2f95d30) stops ML-KEM holding its matrix. A
session with classical or Ed25519 signatures then needs about 31 KB with any
group, and ML-DSA signing set the peak.

IronCrypto commit ddff292, released in 0.2.10 (now this crate's minimum), decodes ML-DSA's secret
vectors per use and holds hints as bitmaps. IronCrypto reports, from its
linked Cortex-M4 call graph, ML-DSA-87 signing falling from 43,788 to
17,596 bytes and verification from 20,268 to 17,508, for 6 to 8% more
signing time on x86-64. The linked image also showed this crate's own
`crypto::sign::verify` holding a 10,848-byte frame: every verifier was
inlined into it, on top of the ML-DSA verifier it then called. Each family
now verifies out of line.

With both changes every session needs 26 to 34 KB, and post-quantum
authentication costs at most about 3 KB over classical. All tests,
the no_std build and the OpenSSL suites pass on ddff292.

A client whose handshake buffer cannot hold the server's flight
fails with `capacity-exceeded`, latched, with nothing queued. Adding one
allocation inside the session makes the run fail, so the counter observes
allocations.

The linked image holds the library, IronCrypto with every algorithm, the
certificate builder and the harness. Its sections: `.text` 268,024 bytes,
`.rodata` 30,924, vector table 1,024, and `.data` 4. `.bss` is dominated by
the harness's 3 MiB heap. The engine's own buffers are caller storage (about
250 KiB per endpoint here, the same as the host tests; the minimum per buffer
is found in `tests/fixed_capacity.rs`).

QEMU models no timing, caches or wait states, and the clock and random
source are fixed. This is emulation, not evidence from a physical board.

### Fuzzing after the review

All eight targets were run under AddressSanitizer on the code after the
branch-gap review and the IronCrypto 0.2.8 upgrade, including the new
`fixed_client` target. Each ran for 601 seconds, all at once. The total was
152,994,855 executions, with no crashes, sanitizer reports or timeouts, and
no unit slower than a second. These are clean runs, which do not establish
the absence of defects.

| Target | Executions | Final coverage edges |
|---|---:|---:|
| messages | 41,006,568 | 1,567 |
| records | 93,666,102 | 58 |
| pki | 5,855,172 | 3,525 |
| tls_server | 1,313,734 | 5,739 |
| tls_client | 359,157 | 4,483 |
| quic_server | 7,995,582 | 2,623 |
| fixed_server | 2,307,521 | 3,516 |
| fixed_client | 491,019 | 3,314 |

### Release 0.1.0

Tag `v0.1.0` (commit 48ffc42) was published to crates.io on 2026-10-06 UTC.
The full test suite passed:

| Platform | Result | Where |
|---|---|---|
| Windows 11 | 597 passed, 0 failed | locally, against IronCrypto 0.2.11 and against 0.2.12 |
| Linux (WSL, x86_64) | 598 passed, 0 failed | locally, earlier the same day; the count is from before one test moved to IronCrypto |
| macOS | 597 passed, 0 failed | GitHub Actions run 37411718066, on the tag; clippy, the no_std Cortex-M build and the benchmark build also passed |

That run's Ubuntu, Windows and fuzz jobs did not start: GitHub reported
an account billing problem.


### Release 0.2.0

The security release after the 2026-10-06 audit
([SECURITY-AUDIT-2026-10-06.md](SECURITY-AUDIT-2026-10-06.md)). The full test
suite passed:

| Platform | Result | Where |
|---|---|---|
| Windows 11 | 628 passed, 0 failed | locally, against IronCrypto 0.2.14 (path) and against the 0.2.13 release commit, the latest published |
| Linux (WSL Debian, x86_64, rustc 1.95.0) | 628 passed, 0 failed | locally, against IronCrypto 0.2.14 |

Also on Windows: `cargo fmt --check`, clippy with no warnings, the Cortex-M4
`no_std` build, the Rust 1.88 build, the OpenSSL 3.5.7 suites
(`openssl_interop` 13, `openssl_fixed` 5, `openssl_cnsa2` 1), live interop
with Cloudflare, Google and GitHub (6), the QEMU Cortex-M4 run of the fixed
engine (largest session stack 34,332 bytes), and five minutes of
AddressSanitizer fuzzing of all eight targets with no findings. GitHub
Actions was not used: its runners are blocked by an account billing problem.
