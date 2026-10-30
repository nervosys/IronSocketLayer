# A build with only the FIPS-approved algorithms

**This does not make anything FIPS 140-3 validated.** Neither IronCrypto nor
IronSocketLayer has been validated by the CMVP. What this build gives is
narrower and checkable: the program contains only the algorithms FIPS
approved mode permits, so none of the others can be called, by this library
or by anything else linked with it. Describe it as "uses only FIPS-approved
algorithms, in a module built to the FIPS 140-3 discipline", never as "FIPS
validated" or "FIPS compliant". Session reports still carry
`"validated": false`.

## Building it

IronCrypto 0.3.2 introduced the configuration as a compiler cfg, not a Cargo
feature: removing API is not additive, and a feature one dependency enabled
would strip algorithms from every crate in the graph. Set it for the whole
build, in both variables:

```console
$ RUSTFLAGS="--cfg ic_approved_only" RUSTDOCFLAGS="--cfg ic_approved_only" cargo build
```

Use a separate target directory from your default build, since `RUSTFLAGS`
is part of what Cargo fingerprints. The dependency graph must hold one copy
of IronCrypto; `cargo tree -d` shows a second.

## Bring the module up first

In this build IronCrypto refuses every operation, random number generation
and key loading included, until its self-tests have passed. Call
`ironsocketlayer::policy::enable_fips()` before anything else. Before that
call, loading a key or opening a connection fails with `error:fips-module`
(`recovery:fix-environment`), not with an error about the key or the peer.

## What changes

IronCrypto leaves out ChaCha20-Poly1305, X25519, Ed25519 and HPKE, among
others. In IronSocketLayer that means:

| | Default build | `--cfg ic_approved_only` |
|---|---|---|
| `profile:fips-140-3`, `profile:cnsa-1`, `profile:cnsa-2`, `profile:dal-a` | available | available, unchanged |
| `profile:default`, `profile:post-quantum` | available | **unavailable**: refused with `error:invalid-config`, never narrowed to what remains |
| An intent whose profile is unavailable (`intent:https-client` with no FIPS policy, for example) | | `error:invalid-config`; with `IntentPolicy { require_fips: true, .. }` it gets `profile:fips-140-3`, as in every build |
| TLS_CHACHA20_POLY1305_SHA256, X25519, X25519MLKEM768, Ed25519 | implemented | not implemented; a configuration naming one is `error:invalid-config` |
| Ed25519 signing key (seed, PKCS#8, generation) | loads | `error:invalid-config` |
| Ed25519 key in a peer's certificate | verified | `error:unsupported-certificate` |
| Encrypted Client Hello with `ech_configs` | works | refused at validation with `error:invalid-config`, rather than send the server name in the clear; no ECH server key can be made |
| GREASE `encrypted_client_hello` (random bytes, no algorithm) | sent | sent; no `relaxation:no-ech-grease` |
| Ontology entries for the excluded algorithms and ECH | `implemented` | `excluded`, with the reason |
| Wire code points, enum variants, `SignatureScheme::Ed25519` and the like | present | present: what a peer may send is still named |

Requirements `REQ-APPR-001` to `REQ-APPR-003`, and `REQ-ERR-003` for the
key-loading error, are traced in [TRACEABILITY.md](TRACEABILITY.md).

## How it is checked

`scripts/approved-only.sh`, run in CI as its own job, builds the workspace
with the cfg and runs:

* clippy on every target, warnings denied;
* `tests/approved_only.rs`, which exists only in this build: the refused
  profiles and intents, the absent algorithms and keys, ECH refused and
  GREASE still sent, handshakes under every remaining profile, and a FIPS
  configuration narrowed by the caller to AES-256-GCM, SecP256r1MLKEM768 and
  ECDSA P-256 with mutual authentication and CRLs on both sides;
* the tests whose subject this build changes: the ontology's own, its
  agreement with the code, the FIPS and CNSA profiles, the module error
  state and the traceability matrix;
* the `no_std` build for Cortex-M4.

With `ISL_OPENSSL=1` it also runs the OpenSSL CNSA 1.0 and 2.0
interoperability tests. The rest of the test suite is written against the
default build, where every profile exists, and is not run in this one. QUIC
and the fixed-capacity engine compile in this build; their tests are among
those not run in it.
