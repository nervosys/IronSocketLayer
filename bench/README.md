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

AMD Ryzen 9 9900X, Windows 11, rustc 1.98.1, 2026-09-29. IronSocketLayer
a1194d5 (records opened in place) over IronCrypto abcc2d2 (SHA-NI for
buffered blocks, 8-block GHASH, AES-NI counter mode). IronCrypto's later
releases, 0.2.3 and 0.2.4, add algorithms and change neither AES-GCM nor
P-256. The machine was never quiet: this is the cleanest of five full runs,
each the median of 7. Compare runs only on one machine, minutes apart.

| | IronSocketLayer | rustls (ring) | ratio |
|---|---:|---:|---:|
| Full handshake, X25519, ECDSA P-256 certificate | 3,598 hs/s | 4,944 hs/s | 0.73× |
| Full handshake, X25519MLKEM768 | 2,043 hs/s | not offered by ring | — |
| Resumed handshake, PSK with X25519 | 7,241 hs/s | 7,250 hs/s | 1.00× |
| Bulk AES-128-GCM, 16 KiB records | 2,120 MiB/s | 3,928 MiB/s | 0.54× |

| Primitive | IronCrypto | ring |
|---|---:|---:|
| AES-128-GCM seal, 16 KiB | 5,109 MiB/s | 13,553 MiB/s |
| ECDSA P-256 sign | 25,734 op/s | 83,036–104,221 op/s |
| ECDSA P-256 verify | 9,960 op/s | 33,454 op/s |
| X25519, both ends of an exchange | 11,351 op/s | 9,841 op/s |

Across all five runs, two on this build and three on IronCrypto 0.2.4 at
97% load, the ratios were: full handshakes 0.61–0.75× (and one 1.34×, where
the rustls run was clearly disturbed), resumed 0.86–1.15×, bulk 0.43–0.54×.

Where this started, before any of the changes below: full 0.71×, resumed
0.78×, bulk 0.27×.

## What the numbers say

* **Resumption is level with rustls.** IronCrypto's SHA-256 had routed
  every buffered block (including each HMAC's final padding block) through
  the portable rounds instead of SHA-NI. It was fixed at f295fe3, and short
  HMACs went from 0.75 µs to 0.28 µs (ring: 0.20 µs). A resumed handshake is
  about 56 HMAC-based operations, so that was most of the gap.
* **Bulk throughput is bounded by the cipher.** Every byte is sealed once
  and opened once, so the ceiling is half the raw seal rate. The record layer
  reaches 73–87% of IronCrypto's ceiling, where rustls reaches 56–77% of
  ring's. The record layer's own gains here:
  * `recv` copies slices instead of single bytes;
  * protected records are opened in place, not copied first;
  * a sealed record is allocated once.

  It also pays about 0.8 µs per record for the constant-time padding scan
  (`REQ-REC-007`). What remains is AES-GCM: IronCrypto seals at about
  2.6× below ring. ring very likely uses VAES and VPCLMULQDQ on this Zen 5
  CPU, where IronCrypto does 128 bits at a time.
* **Full handshakes are bounded by P-256.** IronCrypto signs 3–4× and
  verifies about 3.4× slower than ring's assembly (nistz256), while its
  X25519 is faster than ring's. Hybrid post-quantum key exchange costs
  about 45% of the full-handshake rate.

The first run of this harness found `recv` copying one byte at a time. That
is what it is for.

## Where the time goes

`cargo run --release -- parts` prints per-operation costs (DRBG setup, HMAC,
SHA-256, AEAD key setup, X25519 key generation) and times each flight of a
full and a resumed handshake. Use it to attribute a regression before
optimising anything.

## What would close the gap

Both remaining causes are in IronCrypto, not in this repository:

| IronCrypto primitive | vs ring | Effect here | Status |
|---|---:|---|---|
| AES-GCM | ~2.6× slower (was ~6×) | Bulk throughput | Needs a wide-vector (VAES) backend |
| ECDSA P-256 sign and verify | 3–4× slower | Full-handshake rate | Open; IronCrypto's P-256 code had uncommitted changes on 2026-09-29, nothing released |
| HMAC-SHA256 on short inputs | ~1.4× (was ~3.5×) | Resumption | Fixed at f295fe3 |

Changes there are made in IronCrypto with its own tests and self-tests.
This harness shows their effect here without any change to the library.

## Not measured

* **wolfSSL.** It is not installed on this machine, and no figure for it is
  claimed anywhere in this repository. Adding it means building wolfSSL with
  its assembly enabled and driving it through its C API from this harness.
* Anything across a real network, final linked firmware size, or peak heap/stack use. Unlinked Cortex-M4 protocol-object size and host inline storage are measured separately in [the verification report](../docs/VERIFICATION-2026-10-05.md); they are not firmware flash/RAM budgets.
