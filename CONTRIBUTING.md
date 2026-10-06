# Contributing to IronSocketLayer

## Before anything else

- **Licensing.** Contributions are accepted under the
  [Contributor License Agreement](CLA.md), so they can be distributed under
  both the AGPL v3 and the commercial licence
  ([LICENSE-COMMERCIAL.md](LICENSE-COMMERCIAL.md)). Opening a pull request
  indicates agreement; your commit name and email serve as the signature.
- **Security issues** are reported privately: see [SECURITY.md](SECURITY.md).
- **Cryptography belongs in IronCrypto.** A cipher, hash, MAC, KDF, curve,
  KEM, signature or HPKE change goes to
  [nervosys/IronCrypto](https://github.com/nervosys/IronCrypto), not here.

## Rules

[AGENTS.md](AGENTS.md) holds the repository's rules, and they apply to people
as well as agents:
- zero third-party dependencies in the library;
- `no_std + alloc` first;
- nothing panics on peer input;
- `#![forbid(unsafe_code)]`;
- every protocol element has an ontology entry;
- every requirement is traced;
- test vectors come from published standards;
- every new test is shown to fail when the code it guards is broken.

## Before you open a pull request

```console
$ cargo fmt --all -- --check
$ cargo clippy --workspace --all-targets
$ cargo test --workspace
$ cargo build -p ironsocketlayer --no-default-features --target thumbv7em-none-eabihf
```

If you changed a parser or the state machine, fuzz it as well (see
[fuzz/README.md](fuzz/README.md)). A crash input becomes a regression test
alongside the fix.

Never claim FIPS 140-3 validation or DO-178C certification, in code,
documentation or commit messages. Neither exists.
