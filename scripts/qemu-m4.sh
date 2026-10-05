#!/bin/sh
# Build the Cortex-M4 measurement firmware and run it under QEMU's MPS2-AN386
# board. Needs the thumbv7em-none-eabihf target and qemu-system-arm (on
# Windows, run this from WSL or Git Bash with QEMU reachable through `wsl`).
# Exits non-zero if any check in the firmware fails.
set -eu
here=$(cd "$(dirname "$0")/../embedded/qemu-m4" && pwd)
cd "$here"
CARGO_TARGET_DIR="$here/target" cargo build --release
elf=target/thumbv7em-none-eabihf/release/isl-qemu-m4
run="qemu-system-arm -machine mps2-an386 -cpu cortex-m4 -nographic -monitor none -serial none -semihosting-config enable=on,target=native -kernel $elf"
if command -v qemu-system-arm >/dev/null 2>&1; then
    $run
else
    # Git Bash paths (/c/...) need converting to Windows form before wslpath.
    win=$(cygpath -m "$here" 2>/dev/null || printf '%s' "$here")
    wsl -e sh -c "cd \"\$(wslpath '$win')\" && $run"
fi
