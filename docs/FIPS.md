# FIPS 140-3

## Status, first

**IronSocketLayer is not FIPS 140-3 validated. IronCrypto, which provides every
cryptographic algorithm it uses, is not CMVP-validated either.** Nothing in
this repository changes that, and no report, log line or API returns anything
that could be read as a claim of validation: `SessionReport` carries
`"validated": false` unconditionally, and `isl capabilities` states the
position in words.

What IronSocketLayer does is apply the FIPS 140-3 *operational discipline* that
IronCrypto's module (`ic_fips`) implements, at every point where a TLS or QUIC
session uses cryptography.

## Where the module boundary is

IronSocketLayer implements no cryptographic algorithm. Its TLS key schedule is
HKDF from IronCrypto; its record protection is IronCrypto's AES-GCM; its key
exchange and signatures are IronCrypto's. The cryptographic module, for any
future validation, would therefore be IronCrypto, with IronSocketLayer as a
calling application. That is the same split wolfSSL uses between wolfSSL
(protocol) and wolfCrypt (the validated module).

## What the FIPS profiles enforce

`Profile::Fips140_3`, `Profile::Cnsa1` and `Profile::DalA` set `fips: true`.
For those profiles:

1. **Module state.** `Common::validate` refuses to build a connection unless
   `ic_fips::mode()` is `Approved`. Bring the module up with
   `iron_socket_layer::policy::enable_fips()`, which runs IronCrypto's
   pre-operational self-tests and selects approved mode. If a self-test fails
   the module latches into its error state and every FIPS connection fails
   with `error:fips-module`.
2. **Algorithm gate.** Every suite (AEAD, hash, HMAC, HKDF), every group
   (each component) and every signature scheme in the configuration is passed
   through `ic_fips::check`. One non-approved algorithm fails validation with
   `error:policy-violation`; nothing is silently dropped.
3. **Re-check at use.** When a handshake completes, the negotiated
   algorithms are checked again, since the module can enter its error state at
   any time, and the resulting **service indicators** are recorded in
   `SessionReport::fips_indicators` as `(ic:algorithm, indicator)` pairs.
4. **Property.** `property:fips-approved-algorithms` is added only when the
   profile enforced the gate and every indicator was approved.

`tests/fips.rs` exercises all four: refused before approved mode, refused
with a smuggled X25519 group or Ed25519 scheme, admitted after, indicators
all approved.

## Which algorithms

Approval follows IronCrypto's registry, not this repository's opinion. The
agreement test `fips_status_follows_ironcrypto` fails if an ontology entry
here calls something approved that IronCrypto does not permit.

| Element | In the FIPS profile | Why |
|---|---|---|
| TLS_AES_256_GCM_SHA384, TLS_AES_128_GCM_SHA256 | yes | AES-GCM (SP 800-38D), SHA-2, HMAC, HKDF |
| TLS_CHACHA20_POLY1305_SHA256 | no | not approved |
| SecP256r1MLKEM768 | yes, preferred | both components approved (SP 800-56A ECDH, FIPS 203 ML-KEM) |
| P-256, P-384, P-521 ECDHE | yes | SP 800-56A |
| MLKEM1024, SecP384r1MLKEM1024 | no (approved; `profile:cnsa-2` uses MLKEM1024) | FIPS 203; not offered here because the shares exceed 1.5 KB |
| X25519MLKEM768 | no | X25519 is not approved in IronCrypto's registry (see below) |
| X25519 | no | not approved |
| ECDSA P-256/384/521, RSA-PSS, ML-DSA-65, ML-DSA-87 | yes | FIPS 186-5, FIPS 204 |
| RSA PKCS#1 v1.5 | certificates only | never signs a TLS 1.3 handshake |
| Ed25519 | no | not approved in IronCrypto's registry |

**`profile:cnsa-2`** is also gated: ML-KEM-1024 only, ML-DSA-87 on the
handshake and on every certificate of the path, and TLS_AES_256_GCM_SHA384.
All three are approved in IronCrypto's registry and self-tested at start-up.
It interoperates with OpenSSL 3.5 restricted to the same three parameters,
in both directions (`tests/openssl_cnsa2.rs`). As with every profile here,
that is conformance to an algorithm set, not a validation.

**X25519MLKEM768.** Because its ML-KEM secret comes first in the
concatenation, SP 800-56C rev. 2 can be read to permit it in approved mode with
the X25519 secret as auxiliary input. That is an argument, not an approval, and
the FIPS profile does not rely on it. It uses SecP256r1MLKEM768 for
post-quantum key exchange instead, in which every component is approved.

## What a validation would still need

* IronCrypto's own CMVP submission, with ACVP testing of each algorithm.
  That includes the **TLS 1.3 KDF** (RFC 8446 §7.1, tested under SP 800-135
  / ACVP "TLS-v1.3 KDF"), which is HKDF composed as TLS composes it.
* A security policy naming IronSocketLayer' use of the module.
* Entropy assessment (SP 800-90B) of the platform source behind
  `ic_drbg::Rng::from_os`.
