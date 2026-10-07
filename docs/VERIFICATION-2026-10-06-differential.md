# Differential fuzzing, 2026-10-06

The library has two TLS engines, the owned one (`Connection`) and the
fixed-capacity one (`fixed::Connection`), and two certificate path
validators, `verify_chain` and `verify_chain_fixed`. Each pair is meant to
make the same decisions. Three libFuzzer targets compare them on the same
input and fail when they disagree; a disagreement is a defect in one of
them, or a documented difference.

## Targets

| Target | Compares | Input |
|---|---|---|
| `pki_differential` | `verify_chain` and `verify_chain_fixed`: the same `Ok` or the same error kind | An intermediate and a leaf whose to-be-signed bytes the fuzzer mutates and the harness re-signs, so signatures always verify and both validators reach their deepest checks. The intermediate carries name constraints (permitted dNSName `fuzz.test`, excluded `bad.fuzz.test`, permitted iPAddress `10.0.0.0/8`). |
| `hello_differential` | The owned and the fixed-capacity servers, configured alike: both refuse the client's flight, or neither does | The client's first flight, cut into chunks the fuzzer chooses. |
| `server_hello_differential` | The owned and the fixed-capacity clients, configured alike: both refuse the server's plaintext records, or neither does | The server's ServerHello or HelloRetryRequest, ChangeCipherSpec and alerts, cut into chunks, up to the first encrypted record. |

All three run under AddressSanitizer on Windows (MSVC); see
[fuzz/README.md](../fuzz/README.md).

## Documented differences, not compared

Both handshake targets skip an input when either engine reports
`CapacityExceeded`: the fixed engine's buffers are bounded by design.

`hello_differential` also skips a ClientHello carrying an extension of a
feature the fixed engine does not implement (`encrypted_client_hello`,
`pre_shared_key`, `early_data`, `psk_key_exchange_modes`,
`post_handshake_auth`). The fixed engine ignores these as unknown, where the
owned engine checks their syntax.

`server_hello_differential` compares only the plaintext stage. The two
clients send different ClientHellos (extension order, the signature schemes
they offer, the size of the ECH GREASE), so their handshake keys differ and
an encrypted server flight can be valid for at most one of them. With the
fixed DRBG they share what a ServerHello depends on: the session id, the
suites, the groups and the key-share group.

## What it found

`pki_differential` found no disagreement in 1,784,697 runs (15 minutes).

The handshake targets found twelve differences, and reading the two alert
handlers side by side after one of them found two more. All are in the
fixed-capacity engine, and each is fixed so that it behaves as the owned
engine does, with a test in `tests/protocol_hardening.rs` that fails without
the fix:

| Difference in the fixed-capacity engine | Effect | Found by | Requirement |
|---|---|---|---|
| A malformed `signature_algorithms_cert` was ignored | Lenient | `hello_differential` | REQ-FIX-006 |
| A server_name entry of a type other than host_name was refused, not skipped (RFC 6066 §3) | Strict | `hello_differential` | REQ-FIX-007 |
| A record header announcing more than 2^14 + 256 bytes was refused only when the body would have arrived | Late | `hello_differential` | REQ-REC-010 |
| A ClientHello `legacy_version` other than 0x0303 was refused; values above SSL 3.0 are to be ignored | Strict | `hello_differential` | REQ-FIX-008 |
| A zero-length record other than application data was refused only when the next byte arrived | Late | `hello_differential` | REQ-REC-004 |
| A handshake header announcing more than the engine can hold, or a Finished longer than any hash, was refused only when the next record arrived | Late | `hello_differential` | REQ-FIX-009 |
| A record or handshake message announcing an empty body was processed, and so refused, only when more input arrived | Late | `hello_differential` | REQ-FIX-010 |
| QUIC transport parameters in a ClientHello over TCP were ignored, not refused with `unsupported_extension` (RFC 9001 §8.2) | Lenient | `hello_differential` | REQ-FIX-011 |
| The client accepted a ChangeCipherSpec before the server's ServerHello or HelloRetryRequest (RFC 8446 appendix D.4) | Lenient | `server_hello_differential` | REQ-FIX-012 |
| A cookie in a first ClientHello was refused; the owned server and OpenSSL ignore it | Strict | `hello_differential` | REQ-FIX-013 |
| The fix for the cookie, as first written, ignored a malformed or empty cookie without decoding it | Lenient | `hello_differential` | REQ-FIX-013 |
| An alert between the fragments of a handshake message was accepted (RFC 8446 §5.1) | Lenient | `hello_differential` | REQ-FIX-014 |
| A close_notify before the handshake completed was taken as a clean close | Lenient | review of the alert handlers | REQ-FIX-014 |
| user_canceled was fatal; the owned engine ignores it, a close_notify following (RFC 8446 §6.1) | Strict | review of the alert handlers | REQ-FIX-014 |

*Lenient*: the fixed engine accepted what the owned engine refuses.
*Strict*: it refused what the owned engine accepts. *Late*: it refused bad
input, but only after more input arrived. The lenient cases concern
extensions the fixed engine does not otherwise use, record framing and
alerts; none involves certificate, CertificateVerify or Finished
verification, so none let a peer authenticate falsely, though some let a
malformed handshake complete. For REQ-FIX-009 the error
kinds still differ by design: the fixed engine reports a message over its
configured maximum as `CapacityExceeded` (REQ-FIX-005), the owned engine as
`illegal_parameter`.

## Result

After the fixes, a final round of each handshake target found no
disagreement: `hello_differential` in 1,530,414 runs and
`server_hello_differential` in 261,448 runs (15 minutes each).

## Limits

- Campaigns of minutes to hours, not days.
- The clients are compared only on the server's plaintext records, not on
  the encrypted flight.
- Agreement between the two engines is not correctness: a defect both share
  is not found this way. tlsfuzzer
  ([VERIFICATION-2026-10-06-tlsfuzzer.md](VERIFICATION-2026-10-06-tlsfuzzer.md))
  and the OpenSSL interoperability tests are the independent checks.
