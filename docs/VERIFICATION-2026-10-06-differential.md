# Differential fuzzing, 2026-10-06

The library has two TLS engines, the owned one (`Connection`) and the
fixed-capacity one (`fixed::Connection`), and two certificate path
validators, `verify_chain` and `verify_chain_fixed`. Each pair is meant to
make the same decisions. Two libFuzzer targets compare them on the same
input and fail when they disagree; a disagreement is a defect in one of
them, or a documented difference.

## Targets

| Target | Compares | Input |
|---|---|---|
| `pki_differential` | `verify_chain` and `verify_chain_fixed`: the same `Ok` or the same error kind | An intermediate and a leaf whose to-be-signed bytes the fuzzer mutates and the harness re-signs, so signatures always verify and both validators reach their deepest checks. The intermediate carries name constraints (permitted dNSName `fuzz.test`, excluded `bad.fuzz.test`, permitted iPAddress `10.0.0.0/8`). |
| `hello_differential` | The owned and the fixed-capacity servers, configured alike: both refuse the client's flight, or neither does | The client's first flight, cut into chunks the fuzzer chooses. |

Both run under AddressSanitizer on Windows (MSVC); see
[fuzz/README.md](../fuzz/README.md).

## Documented differences, not compared

`hello_differential` skips an input when:

- either engine reports `CapacityExceeded`: the fixed engine's buffers are
  bounded by design;
- the ClientHello carries an extension of a feature the fixed engine does not
  implement (`encrypted_client_hello`, `pre_shared_key`, `early_data`,
  `psk_key_exchange_modes`, `post_handshake_auth`). The fixed engine ignores
  these as unknown, where the owned engine checks their syntax.

## What it found

`pki_differential` found no disagreement in 1,784,697 runs (15 minutes).

`hello_differential` found seven differences, each in the fixed-capacity
engine, each fixed so that it now behaves as the owned engine does, with a
test in `tests/protocol_hardening.rs` that fails without the fix:

| Difference | Requirement |
|---|---|
| A malformed `signature_algorithms_cert` was ignored, not refused | REQ-FIX-006 |
| A server_name entry of a type other than host_name was refused, not skipped (RFC 6066 §3) | REQ-FIX-007 |
| A record header announcing more than 2^14 + 256 bytes was refused only when the body would have arrived | REQ-REC-010 |
| A ClientHello `legacy_version` other than 0x0303 was refused; values above SSL 3.0 are to be ignored | REQ-FIX-008 |
| A zero-length record other than application data was refused only when the next byte arrived | REQ-REC-004 |
| A handshake header announcing more than the engine can hold, or a Finished longer than any hash, was refused only when the next record arrived | REQ-FIX-009 |
| A record or handshake message announcing an empty body was processed, and so refused, only when more input arrived | REQ-FIX-010 |

Only the first was lenient: the fixed engine accepted a malformed
`signature_algorithms_cert` whose syntax the owned engine checks. The second
and fourth refused valid ClientHellos, and the other four refused bad
input later than the owned engine, but still refused it. For the sixth the
error kinds still differ by design: the fixed engine reports a message over
its configured maximum as `CapacityExceeded` (REQ-FIX-005), the owned engine
as `illegal_parameter`.

## Result

After the fixes, a final `hello_differential` round of 698,239 runs (15 minutes)
found no disagreement.

## Limits

- Campaigns of minutes to hours, not days.
- Only the server side of the handshake is compared; the two clients are
  not.
- Agreement between the two engines is not correctness: a defect both share
  is not found this way. tlsfuzzer
  ([VERIFICATION-2026-10-06-tlsfuzzer.md](VERIFICATION-2026-10-06-tlsfuzzer.md))
  and the OpenSSL interoperability tests are the independent checks.
