# isl-fuzz

Coverage-guided fuzzing (libFuzzer via `cargo fuzz`) of everything in
IronSocketLayer that parses bytes from a peer or the network. This crate is
excluded from the workspace, so `libfuzzer-sys` never enters the library's
dependency graph.

| Target | What it reaches |
|---|---|
| `messages` | Every handshake-message decoder (ClientHello, ServerHello, EncryptedExtensions, CertificateRequest, Certificate, CertificateVerify, NewSessionTicket, KeyUpdate) and handshake framing, directly |
| `records` | The record framer |
| `pki` | X.509 parsing, name checks and path validation, CRLs, OCSP responses, ECH configuration lists |
| `tls_server` | A whole server connection with ECH, 0-RTT, an external PSK, optional client certificates, tickets and HelloRetryRequest cookies enabled |
| `tls_client` | A client after its ClientHello, fed the server's side |
| `quic_server` | QUIC-TLS at Initial, Handshake and 1-RTT levels, v1 and v2, including transport parameters |

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

2026-09-29, Windows 11, nightly, AddressSanitizer, one process per target, on
a heavily loaded machine. No crashes or sanitizer reports (leak detection is
not available with ASan on Windows):

| Target | Runs | Time | Coverage (edges) |
|---|---:|---:|---:|
| `messages` | 1.9 M | 61 s | 956 |
| `records` | 13.9 M | 181 s | 67 |
| `pki` | 533 k | 181 s | 2,695 |
| `tls_server` | 155 k | 171 s | 4,812 |
| `tls_client` | 38 k | 151 s | 4,262 |
| `quic_server` | 1.46 M | 171 s | 1,805 |

These are short runs. A first `tls_client` run was stopped by an outer
timeout before libFuzzer's own time limit. A rerun with a 5-second per-input
limit found no input that slow, so it looks like start-up time on a loaded
machine, but this has not been proven. Longer campaigns on a quiet machine are
the next step.

When a target does crash, fix the cause and add the input as a regression test
in `crates/iron-socket-layer/tests/robustness.rs`.
