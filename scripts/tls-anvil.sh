#!/bin/sh
# Run TLS-Anvil's TLS 1.3 client tests against the IronSocketLayer client
# (Linux or WSL, with Docker).
#
# TLS-Anvil (https://tls-anvil.com) is an independent conformance suite. In
# client mode it plays a server and, before each handshake, runs a trigger
# that starts the client under test: here crates/ironsocketlayer/examples/
# tls_anvil_client.rs, built for Linux and mounted into the container.
#
# Adjustments, all recorded in docs/VERIFICATION-2026-10-07-tls-anvil.md:
#
# - TLS-Anvil's generated server certificates carry no subject alternative
#   name, so the client pins their public keys (the fixed keys TLS-Anvil
#   uses: RSA-1024, -2048 and -4096 leaves and the scanner's RSA-2048 and
#   P-256 keys) instead of checking a name. Verification stays on: the key,
#   the certificate's validity and the CertificateVerify signature are
#   checked.
# - X509-Attacker 4.3.10, which TLS-Anvil uses to build those certificates,
#   has two defects that make every certificate invalid for a strict client:
#   it encodes an empty extensions block (`[3] { SEQUENCE {} }`), which RFC
#   5280 §4.1 forbids (SIZE (1..MAX)), and a configuration copied through XML
#   loses its validity dates, which come back as "now", giving certificates
#   valid for zero seconds. scripts/x509-attacker-tls-anvil.patch omits an
#   empty extensions block and gives the dates an XML adapter; the script
#   rebuilds X509-Attacker with it and mounts that jar over the shipped one.
#   Nothing else in the tool changes.
#
# Usage:
#   sh scripts/tls-anvil.sh [work-dir] [strength]
# Results go to <work-dir>/results/ (TLS-Anvil's report and client.log).
set -eu

REPO=$(cd "$(dirname "$0")/.." && pwd)
WORK=${1:-$HOME/tls-anvil-work}
STRENGTH=${2:-1}
IMAGE=${IMAGE:-ghcr.io/tls-attacker/tlsanvil:latest}
# The X509-Attacker release commit for v4.3.10 (the version in the image).
X509_COMMIT=${X509_COMMIT:-122688c}
# SHA-256 of the SubjectPublicKeyInfo of each server key TLS-Anvil uses.
PINS="095e98ed493064178becf697be29846bd00cb9a11b69e5c07679146ef5969a8c 2b985badf1bac8293f6b92e8c0acc1139bc5a5ecbbf97a6271dcf0d4f6c68af6 d6ef56ebd67406d32a979538d17976e67b27ef26a8ec57c10fcecfec8e339063 a96400ebd676e4c6d1064e56656094f9fdc6fb42513be291df3ce2d001d45292 f944e55b14b8da769c32abc20ef978db026974dac5bdb6fc088ae864a1b31c4f e7ee0b0bccf57df0002c6e37fd829ba64983b06c277e37ddcbe3c09e6a4e51f7 e31cd7b09259b5fa1e1cd7ec9789b86043c4c26c81453725582f86a8f59efa3a 9bddf2aed23ab5ffd2a24c9f6f6b7f3d7c4ca4f949f787d6d6015c945ab3665c"
PINS=$(echo $PINS)

mkdir -p "$WORK/client" "$WORK/results"
cd "$WORK"

# The client under test.
(cd "$REPO" && cargo build -q --release -p ironsocketlayer --example tls_anvil_client)
TARGET_DIR=${CARGO_TARGET_DIR:-$REPO/target}
cp "$TARGET_DIR/release/examples/tls_anvil_client" client/

# X509-Attacker, patched.
if [ ! -d X509-Attacker ]; then
    git clone -q https://github.com/tls-attacker/X509-Attacker.git
fi
git -C X509-Attacker checkout -q -f "$X509_COMMIT"
git -C X509-Attacker clean -fdq
git -C X509-Attacker apply "$REPO/scripts/x509-attacker-tls-anvil.patch"
docker run --rm -v "$WORK/X509-Attacker:/src" -v isl-m2:/root/.m2 -w /src \
    maven:3.9-eclipse-temurin-21 mvn -q -B -DskipTests \
    -Dspotless.check.skip=true -Dspotless.apply.skip=true \
    -Dmaven.javadoc.skip=true -Dgpg.skip package
cp X509-Attacker/target/X509Attacker.jar client/x509-attacker-4.3.10.jar

docker run --rm \
    -v "$WORK/results:/output" \
    -v "$WORK/client:/client:ro" \
    -v "$WORK/client/x509-attacker-4.3.10.jar:/apps/lib/x509-attacker-4.3.10.jar:ro" \
    "$IMAGE" \
    -parallelHandshakes 3 -parallelTests 3 -strength "$STRENGTH" \
    -disableTcpDump -identifier ironsocketlayer-client \
    client -port 8443 \
    -triggerScript sh -c "(sleep 0.3; /client/tls_anvil_client localhost 8443 $PINS >> /output/client.log 2>&1) &"
