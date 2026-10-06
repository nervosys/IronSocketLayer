#!/bin/sh
# Run tlsfuzzer's TLS 1.3 scripts against `isl serve --http` (Linux or WSL).
#
# tlsfuzzer is an independent conformance suite: each script drives a server
# with hostile or unusual messages and checks the exact response. It is not a
# dependency of this repository; this script fetches it into a work directory
# outside the repository and runs it from there.
#
# Usage:
#   sh scripts/tlsfuzzer.sh [work-dir] [script ...]
# With no scripts named, every scripts/test-tls13-*.py is run. Results go to
# <work-dir>/results/, one .out and one .serve file per script, and a
# summary.txt. See docs/VERIFICATION-2026-10-05.md for how each remaining
# failure was classified.
set -eu

REPO=$(cd "$(dirname "$0")/.." && pwd)
WORK=${1:-$HOME/tlsfuzzer-work}
[ $# -gt 0 ] && shift
# The tlsfuzzer commit last run, for repeatable results.
TLSFUZZER_COMMIT=${TLSFUZZER_COMMIT:-5eebc44}
PORT=${PORT:-4433}

mkdir -p "$WORK"
cd "$WORK"
if [ ! -d tlsfuzzer ]; then
    git clone -q https://github.com/tlsfuzzer/tlsfuzzer.git
fi
git -C tlsfuzzer fetch -q --depth 50 origin || true
git -C tlsfuzzer checkout -q "$TLSFUZZER_COMMIT" 2>/dev/null || echo "note: using tlsfuzzer $(git -C tlsfuzzer rev-parse --short HEAD)"
if [ ! -x venv/bin/python ]; then
    python3 -m venv venv
    # tlsfuzzer's master needs tlslite-ng's master (ML-DSA code points).
    venv/bin/pip -q install ecdsa "git+https://github.com/tlsfuzzer/tlslite-ng.git"
fi
if [ ! -f rsakey.p8 ]; then
    openssl req -x509 -newkey rsa:2048 -nodes -keyout rsakey.pem -out rsacert.pem \
        -days 30 -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost" 2>/dev/null
    openssl pkcs8 -topk8 -nocrypt -in rsakey.pem -out rsakey.p8
fi

(cd "$REPO" && cargo build -q --release -p isl-cli)
ISL=${CARGO_TARGET_DIR:-$REPO/target}/release/isl

if [ $# -eq 0 ]; then
    set -- $(cd tlsfuzzer/scripts && ls test-tls13-*.py)
fi
rm -rf results
mkdir -p results
for s in "$@"; do
    "$ISL" serve --cert rsacert.pem --key rsakey.p8 --port "$PORT" --http \
        > "results/$s.serve" 2>&1 &
    pid=$!
    sleep 1
    (cd tlsfuzzer && PYTHONPATH=. timeout 300 ../venv/bin/python "scripts/$s" \
        -h localhost -p "$PORT" > "../results/$s.out" 2>&1; echo "exit $?" >> "../results/$s.out") || true
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
    pass=$(grep -m1 '^PASS:' "results/$s.out" | awk '{print $2}')
    fail=$(grep -m1 '^FAIL:' "results/$s.out" | awk '{print $2}')
    echo "$s pass=${pass:-?} fail=${fail:-?} $(tail -1 "results/$s.out")"
done | tee results/summary.txt
