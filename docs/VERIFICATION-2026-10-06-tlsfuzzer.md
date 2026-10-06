# tlsfuzzer, 2026-10-06

[tlsfuzzer](https://github.com/tlsfuzzer/tlsfuzzer) (commit 5eebc44, with
tlslite-ng from git) is an independent TLS conformance suite: each script
drives a server with unusual or hostile messages and checks the exact
response. Its 57 TLS 1.3 scripts were run against `isl serve --http` with a
2048-bit RSA certificate, on Linux (WSL), with
[scripts/tlsfuzzer.sh](../scripts/tlsfuzzer.sh).

## What it found

At the first run, 2 scripts passed. The failures included eight defects in
the library, all fixed with tests that fail without the fix:

| Defect | Requirement |
|---|---|
| A record's legacy version was checked; RFC 8446 §5.1 says to ignore it (servers refused 0x0300, tlsfuzzer's default) | REQ-REC-010 |
| `TlsStream` over TCP lost its own alert after a failed handshake (the kernel's reset destroyed it on Linux) | REQ-CONN-016 |
| A TLS 1.3 ClientHello with `supported_groups` but no `key_share` drew a HelloRetryRequest, not `missing_extension` | REQ-MSG-022 |
| A Hello `legacy_version` below SSL 3.0 was answered | REQ-MSG-021 |
| Messages with more than 128 extensions, or ClientHellos with more than 16 key shares, were refused; RFC 8446 sets no such limit | REQ-MSG-020 |
| A record's inner plaintext could exceed 2^14 + 1 bytes when padded | REQ-REC-012 |
| After a HelloRetryRequest, undecryptable records were still skipped as 0-RTT after the second ClientHello | REQ-0RTT-007 |
| An empty application-data record before any keys was skipped, stalling the handshake | REQ-0RTT-008 |

and four answers that now match RFC 8446 and common practice: a Finished
of the wrong length is `decode_error` (REQ-KS-004), an empty alert record
`unexpected_message` (REQ-REC-011), a second compatibility
ChangeCipherSpec `unexpected_message` (REQ-CONN-004), and `isl serve` grew
an HTTP mode (`--http`) and echoes whole messages.

## Result

20 of the 57 scripts pass completely (`ccs`, `conversation`,
`dhe-shared-secret-padding`, `empty-alert`, `finished-plaintext`, `hrr`,
`invalid-ciphers`, `keyshare-omitted`, `keyupdate`,
`large-number-of-extensions`, `legacy-version`, `multiple-ccs-messages`,
`nociphers`, `pkcs-signature`, `record-layer-limits`, `record-padding`,
`rsa-signatures`, `signature-algorithms`, `zero-content-type`,
`zero-length-data`), and `lengths` passes 1,002 of 1,002 in echo mode (it
exceeds the five-minute limit in HTTP mode). `finished` passes 41 of 42:
the 16 MiB Finished now draws the expected `decode_error` on its header,
but the script then reports a second alert where it expects the connection
to close. The library sends exactly one alert and nothing after it
(`tests/protocol_hardening.rs::a_finished_of_the_wrong_length_is_decode_error`
asserts this); the second alert the script sees is not explained, and a
packet capture was not available. Every other remaining failure is one of
these:

| Kind | Scripts |
|---|---|
| By design: TLS 1.2, draft versions and `psk_ke` are not implemented | `version-negotiation`, `non-support`, `session-resumption` (TLS 1.2 and PSK-only cases), `psk_ke`, `0rtt-garbage` (one TLS 1.2 case) |
| By design: groups and schemes not implemented (FFDHE, brainpool, X448, Ed448, CCM suites, certificate compression) | `ffdhe-groups`, `ffdhe-sanity`, `ecdhe-brainpool-curves`, `obsolete-curves`, `crfg-curves`, `ecdhe-curves` (X448 cases), `eddsa` (Ed448), `symetric-ciphers` (CCM), `certificate-compression`, `client-certificate-compression`, `serverhello-random` (FFDHE and X448 cases) |
| Configuration: needs another server key type (ECDSA, Ed25519, RSA-PSS), P-521 in the server's groups, client authentication, an external PSK, or arguments | `ecdsa-support`, `minerva`, `rsapss-signatures`, `eddsa` (Ed25519), `ecdhe-curves` (P-521), `certificate-request`, `post-handshake-auth`, `*-in-certificate-verify`, `psk_dhe_ke`, `mlkem` (needs the kyber-py library) |
| Server choice the RFC permits: the server uses an offered key share rather than asking for another with HelloRetryRequest, and picks its own group | `shuffled-extentions`, `unrecognised-groups`, `no-unknown-groups` |
| Server behaviour the script assumes: issuing a set number of tickets, sending its own KeyUpdate, staying silent after an abort | `count-tickets`, `keyupdate-from-server`, `connection-abort` |
| Codepoint assigned since tlsfuzzer's list: 0xfd00 is `ech_outer_extensions` (RFC 9849), refused in a ClientHello | `large-number-of-extensions`, in a run whose random ranges include 0xfd00 (22 of 22 otherwise) |
| A difference in politeness: a plaintext alert where an encrypted one is due is answered with `unexpected_message` before closing, where the script expects a silent close | `unencrypted-alert` |

The library side of every script that exercises implemented features now
passes; what fails asks for features this library does not implement, for
a different server configuration, or for server behaviour the RFC leaves
open.
