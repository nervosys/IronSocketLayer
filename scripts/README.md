# Verification tools

Run these PowerShell scripts from any directory. They resolve the repository
from their own paths and save generated artifacts under ignored `target/`.
They do not publish, delete corpora, or change source files.

```powershell
./scripts/coverage.ps1
./scripts/coverage.ps1 -RequirementsOnly
python scripts/coverage_gaps.py target/coverage-whole-suite/coverage.json target/coverage-whole-suite/gaps.csv
python scripts/coverage_gaps.py target/coverage-requirements/coverage.json target/coverage-requirements/gaps.csv
python scripts/coverage_review.py target/coverage-whole-suite/gaps.csv docs/evidence/coverage-review.csv
./scripts/footprint.ps1
cargo run --release -p iron-socket-layer --example fixed_stack   # on Linux
./scripts/fuzz.ps1 -Seconds 600
cargo test -p iron-socket-layer --release --lib padding_scan_timing_experiment -- --ignored --nocapture
```

Coverage requires nightly, cargo-llvm-cov and that toolchain's LLVM tools.
The script drives LLVM directly to accommodate Cargo's test executable layout.
`-ReportOnly` regenerates reports from existing execution profiles. Use a clean,
dedicated output directory when changing the toolchain or test binary set.
The gap inventory merges branch locations across instantiations and excludes
the trailing unit-test modules; raw LLVM file summaries still include unit-test
source. This is branch coverage, not MC/DC.

`coverage_review.py` checks a gap inventory against the reviewed
dispositions in `docs/evidence/coverage-review.csv`. It fails if a gap has no
disposition, if a disposition no longer matches a gap (and is not `tested`),
or if a gap marked `tested` is still uncovered. `--template FILE` writes the
unreviewed gaps as rows to fill in. Dispositions are the author's, not an
independent review.

Requirements-only coverage selects test names cited by Test rows in
`docs/TRACEABILITY.md`. Ignored network/OpenSSL tests remain ignored and
Analysis rows are not executable tests. Their separate verification results
must accompany this report; a coverage percentage is not certification credit.

Footprint requires `llvm-size`, `llvm-readobj` and `llvm-cxxfilt` on PATH and
the Cortex-M4 target installed. It measures an unlinked protocol object without
LTO, host inline struct storage, and the 40 largest Cortex-M4 stack frames
(`-Z emit-stack-sizes`, enabled on stable with `RUSTC_BOOTSTRAP`). Frames are
per function, not a call-chain worst case. It does not measure final firmware
flash, live heap or stack use.

`fixed_stack` measures the host thread stack a complete fixed-engine session
needs, per key kind and group, plus IronCrypto's ML-DSA and Ed25519
operations alone. Each probe is a fresh child process. Run it on Linux, where
stacks are 4 KiB-granular; Windows reserves 64 KiB units. Host figures are not
target figures.

Fuzzing requires nightly and cargo-fuzz. On Windows the MSVC AddressSanitizer
runtime directory must be on PATH (see `fuzz/README.md`). Campaigns run
sequentially and fail if a target crashes or exits without reporting completion.

The timing experiment randomly interleaves equal-length short- and long-padding
inputs, measures 64 calls per sample, and reports Welch's t statistic. Its
threshold is an investigation trigger. Repeat on an idle host; failure may be
noise, and success does not prove constant-time execution or cover other inputs.
