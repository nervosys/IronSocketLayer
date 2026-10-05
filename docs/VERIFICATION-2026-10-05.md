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
`crates/iron-socket-layer/src/`. Do not compare these directly to older reports
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
allocations and stack scratch space are excluded. The fixed-capacity engine,
peak heap/stack measurements and execution on physical hardware remain open
in [READINESS.md](READINESS.md).
