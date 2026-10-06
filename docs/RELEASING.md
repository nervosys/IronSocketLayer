# Releasing

The order matters: some steps cannot be undone once taken. Everything up to
step 4 can be repeated freely.

## 1. Decide what publication commits to

Decide these in the same change that first makes the code public, because
publication fixes them:

- **Licence.** Today it is AGPL-3.0-or-later only. A commercial option, as
  IronCrypto offers, needs a contributor licence agreement in place before
  outside contributions arrive. It also needs its own export classification
  (see [EXPORT.md](EXPORT.md)).
- **What is claimed.** No FIPS 140-3 validation, no DO-178C certification and
  no independent review. Reports carry `"validated": false`. Check that the
  README, [READINESS.md](READINESS.md) and the crate descriptions say so and
  claim nothing more.
- **Version.** The first release is 0.1.0: pre-1.0, so minor versions may
  break the API.

## 2. Verify the release commit

From the repository root, on the commit to be released:

```console
$ cargo fmt --all -- --check
$ cargo clippy --workspace --all-targets          # no warnings
$ cargo test --workspace                          # on Windows, Linux and macOS
$ cargo build -p ironsocketlayer --no-default-features --target thumbv7em-none-eabihf
$ cargo +1.88 build -p ironsocketlayer -p isl-cli   # the declared rust-version
$ cargo test -p ironsocketlayer --test openssl_interop -- --ignored --test-threads=1
$ cargo test -p ironsocketlayer --test openssl_fixed -- --ignored --test-threads=1
$ cargo test -p ironsocketlayer --test openssl_cnsa2 -- --ignored
$ cargo test -p ironsocketlayer --test interop -- --ignored   # needs the network
$ sh scripts/qemu-m4.sh                           # needs qemu-system-arm
```

CI covers the first four on three operating systems when it runs. If CI is
not running, run the test suite on at least two operating systems by hand and
record which. Check that `Cargo.toml` requires the IronCrypto version the
release was tested against, and that the version is published.

Update [CHANGELOG.md](../CHANGELOG.md): move "Unreleased" under the version
and date.

## 3. Package

```console
$ cargo package -p isl-ontology
```

`ironsocketlayer` and `isl-cli` cannot be packaged until their
dependencies are on crates.io, so they are packaged in step 5, in order.

## 4. Export notification (first public release only; cannot be undone)

Before the first public release only: follow [EXPORT.md](EXPORT.md), send the
notification, then commit the record under `docs/export/`. Nothing in step 5
happens before that record exists.

Later releases skip this step if a record already exists and the URLs it
names are unchanged. A new location, a new mirror, or non-standard
cryptography (see EXPORT.md) needs a new notice first.

## 5. Publish (cannot be undone)

1. Set `publish = true` in the workspace `Cargo.toml` and commit it.
2. Publish in dependency order, each after the previous one is visible on
   crates.io:
   ```console
   $ cargo publish -p isl-ontology
   $ cargo publish -p ironsocketlayer
   $ cargo publish -p isl-cli
   ```
3. Tag the commit `v0.1.0` and push the tag.
4. If the repository is to be public, change its visibility. Review
   `.github/workflows/` first: GitHub advises against self-hosted runners on
   public repositories, because a fork's pull request would run on your
   hardware. The workflows here use GitHub-hosted runners only.

A yanked crate stays in the index and in every mirror, and a repository that
was public has been cloned. Publishing is permanent.
