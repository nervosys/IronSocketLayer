#!/usr/bin/env bash
#
# The build with only the FIPS-approved algorithms: IronCrypto's
# `--cfg ic_approved_only`, in RUSTFLAGS and RUSTDOCFLAGS. See
# docs/APPROVED-ONLY.md.
#
# Nothing else in this repository's checks builds it, so it is checked here:
# clippy on every target, the tests written for it and the tests whose
# subject it changes (the ontology, its agreement with the code, the FIPS and
# CNSA profiles, the module error state, the traceability matrix), and the
# no_std build. The rest of the suite is written against the default build,
# where every profile exists; it is not run here.
#
# No --cfg ic_startup_gate_off: in this build IronCrypto refuses service
# until its self-tests have passed, and every test run here brings the module
# up first, as an application must.
#
# Its own target directory, because RUSTFLAGS is part of what Cargo
# fingerprints and sharing one would rebuild the workspace on every switch.
#
# Optional: the OpenSSL CNSA interoperability tests, when openssl >= 3.5 is
# on PATH (ISL_OPENSSL=1).

set -euo pipefail

cd "$(dirname "$0")/.."

: "${CARGO_TARGET_DIR:=target}"
export CARGO_TARGET_DIR="$CARGO_TARGET_DIR/approved-only"
export RUSTFLAGS="${RUSTFLAGS:-} --cfg ic_approved_only"
export RUSTDOCFLAGS="${RUSTDOCFLAGS:-} --cfg ic_approved_only"

echo "-- clippy"
cargo clippy --workspace --all-targets --locked -- -D warnings

echo "-- tests"
cargo test --locked -p isl-ontology
cargo test --locked -p ironsocketlayer \
    --test approved_only --test ontology_agreement --test traceability \
    --test fips --test cnsa --test error_state

if [ "${ISL_OPENSSL:-0}" = 1 ]; then
    echo "-- OpenSSL CNSA interoperability"
    cargo test --locked -p ironsocketlayer --test openssl_cnsa1 --test openssl_cnsa2 -- --ignored
fi

target=thumbv7em-none-eabihf
if rustup target list --installed 2>/dev/null | grep -qx "$target"; then
    echo "-- $target"
    cargo build --locked -p ironsocketlayer --no-default-features --target "$target"
else
    echo "-- $target not installed; the approved-only no_std build was NOT checked"
fi
