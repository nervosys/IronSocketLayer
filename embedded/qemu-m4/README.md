# isl-qemu-m4

Runs the fixed-capacity engine (`ironsocketlayer::fixed`) on an emulated
Cortex-M4. The board is QEMU's MPS2-AN386, and the image is linked with fat
LTO for `thumbv7em-none-eabihf`. For each signing-key kind and key-exchange
group listed in `src/main.rs`, it runs a whole mutual-TLS session between a
fixed client and a fixed server: both constructors, the handshake, data both
ways, KeyUpdate, an exporter and close_notify. It reports:

* **Peak stack.** The free stack is painted before the session; afterwards
  the deepest word the session overwrote is found.
* **Allocator calls after initialization**, counted by a wrapper around the
  heap. Any call fails the run. Adding a single allocation inside the session
  was checked to fail it.
* **A capacity failure.** A client whose handshake buffer cannot hold the
  server's flight gets `capacity-exceeded`, the error latches, and nothing is
  queued.

```console
$ ./scripts/qemu-m4.sh        # from the repository root; needs qemu-system-arm
```

The crate is excluded from the library's workspace, like `bench/` and
`fuzz/`. Its board crates (`cortex-m`, `cortex-m-rt`, `cortex-m-semihosting`,
`embedded-alloc`) never enter the library's dependency graph.

## Limits

QEMU executes Cortex-M4 instructions, but it does not model timing, caches,
wait states, or a board's clock and entropy. The clock and random source here
are fixed: this image is a measurement, never a deployment. It is not
evidence of behaviour on a physical board, and it gives no timing evidence.
