# isl-bench

IronSocketLayer against rustls 0.23 with the *ring* provider, in one process
and in memory: client and server run on the same thread, so every figure is
the CPU cost of both ends of the connection. Rows for the raw primitives
(IronCrypto against *ring*) show where each gap comes from.

This package is excluded from the workspace, so rustls and ring never enter the
library's dependency graph.

```console
$ cd bench
$ cargo run --release
```

## Results

AMD Ryzen 9 9900X, Windows 11, rustc 1.98.1, 2026-09-28. The machine was busy
with other builds, so the spread is wide; read these as indicative, and compare
runs only when they come from the same machine a few minutes apart. Each figure
is the median of 7 runs.

| | IronSocketLayer | rustls (ring) | ratio |
|---|---:|---:|---:|
| Full handshake, X25519, ECDSA P-256 certificate | 2,434 hs/s | 3,406 hs/s | 0.71× |
| Full handshake, X25519MLKEM768 | 1,475 hs/s | not offered by ring | — |
| Resumed handshake, PSK with X25519 | 4,353 hs/s | 5,614 hs/s | 0.78× |
| Bulk AES-128-GCM, 16 KiB records | 788 MiB/s | 2,881 MiB/s | 0.27× |

| Primitive | IronCrypto | ring |
|---|---:|---:|
| AES-128-GCM seal, 16 KiB | 1,652 MiB/s | 10,008 MiB/s |
| ECDSA P-256 sign | 18,519 op/s | 75,534 op/s |
| ECDSA P-256 verify | 7,957 op/s | 23,732 op/s |
| X25519, both ends of an exchange | 7,179 op/s | 6,107 op/s |

## What the numbers say

* **Bulk throughput is bounded by the cipher, not the record layer.** Every
  byte is sealed once and opened once, so the ceiling is half the raw seal
  rate. IronSocketLayer reaches about 95% of IronCrypto's ceiling; rustls
  reaches about 58% of ring's. The gap is IronCrypto's AES-GCM, which is
  about 6× slower than ring's assembly.
* **Handshakes are bounded by P-256.** Of about 410 µs per full handshake,
  about 320 µs is the ECDSA signature, its verification and X25519. IronCrypto's
  P-256 is 3–4× slower than ring's, while its X25519 is slightly faster. The
  remaining protocol cost is similar for the two libraries: about 90 µs here and
  about 75 µs in rustls.
* **Resumption has about 75 µs of overhead** beyond the X25519 exchange,
  against about 15 µs in rustls. Counting calls shows a resumed handshake
  performs about 56 HMAC-based operations across both ends (HKDF-Extract,
  HKDF-Expand-Label, binders, Finished). That is what RFC 8446 requires, with
  nothing repeated. IronCrypto takes about 0.75 µs for a short HMAC-SHA256
  where ring takes about 0.21 µs, which accounts for 30–40 µs of the gap. Plain
  SHA-256 matches ring on 4 KiB, so the cost is per-call HMAC setup. Ticket
  sealing, AEAD key setup (about 2 µs each) and the per-connection DRBG (about
  3.5 µs) are small.
* **Hybrid post-quantum key exchange costs about 40%** of full-handshake rate
  (2,434 → 1,475 hs/s).

The first run of this harness found that `Connection::recv` copied one byte at
a time. It now copies slices, which raised bulk throughput from about 430 to
about 790 MiB/s. The benchmark is here to catch things like that.

## Where the time goes

`cargo run --release -- parts` prints per-operation costs (DRBG setup, HMAC,
SHA-256, AEAD key setup, X25519 key generation) and times each flight of a
full and a resumed handshake. Use it to attribute a regression before
optimising anything.

## What would close the gap

All three causes are in IronCrypto, not in this repository:

| IronCrypto primitive | vs ring | Effect here |
|---|---:|---|
| AES-GCM (AES-NI + CLMUL paths already present) | ~6× slower | Bulk throughput |
| ECDSA P-256 sign and verify | 3–4× slower | Full-handshake rate |
| HMAC-SHA256 on short inputs | ~3.5× slower | Resumption and key-schedule overhead |

Changes there should be made in IronCrypto with its own tests and self-tests;
this harness will show their effect here without any change to the library.

## Not measured

* **wolfSSL.** It is not installed on this machine, and no figure for it is
  claimed anywhere in this repository. Adding it means building wolfSSL with
  its assembly enabled and driving it through its C API from this harness.
* Anything across a real network, memory footprint, or code size.
