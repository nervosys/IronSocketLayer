# Verification tools

Run these PowerShell scripts from any directory. They resolve the repository
from their own paths and save generated artifacts under ignored `target/`.
They do not publish, delete corpora, or change source files.

```powershell
./scripts/coverage.ps1
./scripts/coverage.ps1 -RequirementsOnly
python scripts/coverage_gaps.py target/coverage-whole-suite/coverage.json target/coverage-whole-suite/gaps.csv
python scripts/coverage_gaps.py target/coverage-requirements/coverage.json target/coverage-requirements/gaps.csv
./scripts/footprint.ps1
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

Requirements-only coverage selects test names cited by Test rows in
`docs/TRACEABILITY.md`. Ignored network/OpenSSL tests remain ignored and
Analysis rows are not executable tests. Their separate verification results
must accompany this report; a coverage percentage is not certification credit.

Footprint requires `llvm-size` on PATH and the Cortex-M4 target installed.
It measures an unlinked protocol object without LTO and host inline struct
storage. It does not measure final firmware flash, live heap or stack use.

Fuzzing requires nightly and cargo-fuzz. On Windows the MSVC AddressSanitizer
runtime directory must be on PATH (see `fuzz/README.md`). Campaigns run
sequentially and fail if a target crashes or exits without reporting completion.

The timing experiment randomly interleaves equal-length short- and long-padding
inputs, measures 64 calls per sample, and reports Welch's t statistic. Its
threshold is an investigation trigger. Repeat on an idle host; failure may be
noise, and success does not prove constant-time execution or cover other inputs.
