# isl-fuzz

Coverage-guided fuzzing (libFuzzer via `cargo fuzz`) of everything in
IronSocketLayer that parses bytes from a peer or the network. This crate is
excluded from the workspace, so `libfuzzer-sys` never enters the library's
dependency graph.

| Target | What it reaches |
|---|---|
| `messages` | Every handshake-message decoder (ClientHello, ServerHello, EncryptedExtensions, CertificateRequest, Certificate, CertificateVerify, NewSessionTicket, KeyUpdate), ECH inner hello reconstruction and handshake framing, directly |
| `records` | The record framer |
| `pki` | X.509 parsing, name checks and path validation, CRLs, OCSP responses, ECH configuration lists |
| `tls_server` | A whole server connection with ECH, 0-RTT, an external PSK, optional client certificates, tickets and HelloRetryRequest cookies enabled |
| `tls_client` | A client after its ClientHello, fed the server's side |
| `quic_server` | QUIC-TLS at Initial, Handshake and 1-RTT levels, v1 and v2, including transport parameters |
| `fixed_server` | The fixed-capacity server (`iron_socket_layer::fixed`) over caller storage, with every group and optional client certificates; a failure must latch and leave nothing queued |

The TCP targets also assert that a failed connection stays failed.

## Deterministic by construction

The fixtures (`src/lib.rs`) use a fixed clock and a DRBG from a fixed seed.
A connection's bytes therefore depend only on its input, which has two
consequences:

* A crash input reproduces exactly: `cargo fuzz run <target> <file>`.
* Seeds recorded from real handshakes stay valid. `seed-corpus` records
  complete handshakes, including ECH, an external PSK, and QUIC v1 and v2. It
  then replays the TLS seeds along the targets' code path and fails unless
  they complete again. So `tls_client` starts from a server flight that
  decrypts, rather than from bytes that fail at the first AEAD check.

The `messages` corpus also includes raw encoded inner hellos, including
duplicate compression markers, to reach ECH reconstruction directly without
requiring HPKE authentication.

## Running

```console
$ cd fuzz
$ cargo run --bin seed-corpus                       # writes corpus/<target>/
$ cd ..
$ cargo +nightly fuzz run --fuzz-dir fuzz -O tls_server -- -max_total_time=600
```

On Windows with the MSVC toolchain, AddressSanitizer needs its runtime on
`PATH`: the directory with `clang_rt.asan_dynamic-x86_64.dll`, under
`VC/Tools/MSVC/<version>/bin/Hostx64/x64` in the Visual Studio install.
Without it the target exits with `STATUS_DLL_NOT_FOUND`.

## Results so far

Windows 11, nightly, AddressSanitizer, one process per target, on a heavily
loaded machine. No crashes or sanitizer reports (leak detection is not
available with ASan on Windows), and no slow units:

| Target | Runs | Time | Coverage (edges) |
|---|---:|---:|---:|
| `messages` | 7.1 M | 151 s | 1,159 |
| `records` | 14.0 M | 151 s | 58 |
| `pki` (now with ML-DSA-65/87 certificates) | 586 k | 151 s | 2,790 |
| `tls_server` (now with every group enabled) | 137 k | 151 s | 5,281 |
| `tls_client` | 41 k | 151 s | 4,299 |
| `quic_server` | 1.17 M | 151 s | 1,816 |

That is the 2026-09-29 afternoon run, after in-place record decryption,
ML-KEM-1024 and ML-DSA-87. The fixture server now enables every implemented
group, so ClientHellos reach the ML-KEM-1024 key-share parsers, and the seeds
include ML-KEM-1024 ClientHellos and ML-DSA certificates.

Twice a run was stopped by an outer timeout before libFuzzer's own limit
(`tls_client` in the morning, `tls_server` in the afternoon). Rerun with
`-timeout=10 -print_final_stats=1`, the slowest unit took under a second and
the run ended on time, so these were start-up delays on a loaded machine,
not hangs. These are still short runs. Longer campaigns on a quiet machine
are the next step.

When a target does crash, fix the cause and add the input as a regression test
in `crates/iron-socket-layer/tests/robustness.rs`.

## Longer campaign, 2026-10-05

All six targets completed ten-minute campaigns under AddressSanitizer, with
169,688,310 total executions and no crashes or sanitizer reports. The corpus
includes ML-KEM-512 handshakes and ML-DSA-44 certificates. Per-target counts,
coverage and limitations are in [the verification report](../docs/VERIFICATION-2026-10-05.md).
The repeatable Windows runner is `./scripts/fuzz.ps1 -Seconds 600` from the
repository root; it generates seeds from `fuzz/` and checks completion.

## Fixed-capacity server, 2026-10-05

The first runs of `fixed_server` found two hangs within seconds: a record, or
a handshake message, announcing an empty body was never consumed, so the
engine looped without progress. Both were fixed in `src/fixed.rs`, and the
inputs are regression cases in
`crates/iron-socket-layer/tests/fixed_capacity.rs::an_empty_record_does_not_stall_the_engine`.
Reverting either fix makes that test fail. After the fixes, a 181-second
AddressSanitizer run made 869,977 executions and reached 3,415 edges, with
no crashes, timeouts or sanitizer reports. This is a short run.
