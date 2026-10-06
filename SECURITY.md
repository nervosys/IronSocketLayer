# Security policy

## Reporting a vulnerability

Report privately, not as a public issue. Open a GitHub security advisory on
`nervosys/IronSocketLayer`, or contact the maintainers directly if you cannot.

Useful reports include the version or commit, what you observed, and the
smallest input that shows it. A failing test is the most useful form. If you
believe the finding is exploitable, say what you think an attacker gains: that
decides how fast it moves, and only you can supply it.

You do not need a working exploit. A convincing argument that a handshake
check is missing, a bound is wrong, a certificate is accepted that should not
be, or a security property is reported that does not hold is worth reporting
on its own.

A flaw in a cryptographic primitive belongs to IronCrypto: report it to
`nervosys/IronCrypto`. IronSocketLayer implements no primitive.

## What this project can and cannot claim

**IronSocketLayer is not FIPS 140-3 validated and not DO-178C certified**, and
neither is IronCrypto. Session reports carry `"validated": false`, and that
does not change until a certificate exists. The library supports a FIPS mode
that uses only algorithms IronCrypto's module approves and reports service
indicators; that is a prerequisite for validation, not validation.
[docs/FIPS.md](docs/FIPS.md) and [docs/DO-178C.md](docs/DO-178C.md) describe
what exists and what does not.

**It has not been independently reviewed.** The evidence in
[docs/VERIFICATION-2026-10-05.md](docs/VERIFICATION-2026-10-05.md) is the
author's:
- requirements-based tests, traced in [docs/TRACEABILITY.md](docs/TRACEABILITY.md);
- interoperability with OpenSSL 3.5 and public servers;
- AddressSanitizer fuzzing of every peer-facing parser;
- branch coverage, with a recorded disposition for every uncovered branch;
- execution on an emulated Cortex-M4.

None of that substitutes for review by someone else.
[docs/READINESS.md](docs/READINESS.md) lists what remains open.

## Supported versions

Before 1.0, only the latest release receives fixes.
