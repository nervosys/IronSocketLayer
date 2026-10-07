# TLS-Anvil, client side, 2026-10-07

[TLS-Anvil](https://tls-anvil.com) is an independent conformance suite from
the TLS-Attacker project. In client mode it plays a server, mostly a hostile
one, and checks that the client under test completes or aborts each
handshake as RFC 8446 requires, across combinations of parameters (groups,
suites, certificates, fragmentation). tlsfuzzer, used for the server side
([VERIFICATION-2026-10-06-tlsfuzzer.md](VERIFICATION-2026-10-06-tlsfuzzer.md)),
cannot test clients: its runner only connects to servers.

The client under test is
[crates/ironsocketlayer/examples/tls_anvil_client.rs](../crates/ironsocketlayer/examples/tls_anvil_client.rs):
the owned engine through `TlsStream`, with the default profile. It connects,
sends a request, reads until the server closes or goes idle, and closes with
close_notify. [scripts/tls-anvil.sh](../scripts/tls-anvil.sh) reproduces the
run (image `ghcr.io/tls-attacker/tlsanvil:latest`: TLS-Anvil with
tls-test-framework 1.5.3, TLS-Attacker 7.7.0, X509-Attacker 4.3.10; strength
1, three parallel handshakes and tests).

## Changes to the test setup

TLS-Anvil could not test this client unchanged. None of the changes below
touches the library or relaxes what the client checks.

- **Pinned keys instead of names.** TLS-Anvil's server certificates carry no
  subject alternative name, so no name check can pass. The client pins the
  public keys TLS-Anvil uses (`PeerVerification::PinnedSpki` with
  `check_names: false`), eight fixed keys found by running the suite once
  against `openssl s_client`. The key, the certificate's validity and the
  CertificateVerify signature are still checked.
- **Two defects in X509-Attacker, patched**
  ([scripts/x509-attacker-tls-anvil.patch](../scripts/x509-attacker-tls-anvil.patch)).
  Unpatched, every certificate TLS-Anvil serves is invalid, and the client
  correctly refuses all of them; TLS-Anvil's feature scanner then finds no
  TLS 1.3 support and disables every test.
  - It encodes an empty extensions block, `[3] { SEQUENCE {} }`. RFC 5280
    §4.1 defines `Extensions ::= SEQUENCE SIZE (1..MAX)`, and the client
    refuses the certificate (`bad_certificate`). The patch omits the block
    when no extension is present.
  - A configuration copied through XML loses its validity dates: JAXB has no
    adapter for Joda `DateTime`, writes it empty and reads it back as the
    current time. Certificates in most tests were valid from one second to
    the same second, and the client refused them as expired. The patch adds
    the adapter.
- **close_notify.** The first version of the test client exited without
  closing when a server went idle, so TLS-Anvil saw the connection drop
  without close_notify (`AlertProtocol.sendsCloseNotify`,
  `KeyUpdate.appDataUnderNewKeysSucceeds`). The client now calls
  `TlsStream::close`, as an application should. `TlsStream` sends
  close_notify only from `close`, not on drop.

## What it found

Two defects in the library, both fixed, each with a test that fails without
the fix:

| Defect | Requirement |
|---|---|
| Both clients refused a TLS 1.3 ServerHello whose legacy_version was not 0x0303. RFC 8446 §4.2.1: "clients MUST ignore the ServerHello.legacy_version value" when supported_versions is present. Values above SSL 3.0 are now ignored; SSL 3.0 and below remain `protocol_version` (`SupportedVersions.invalidLegacyVersion`) | REQ-MSG-014 |
| A client that offered no ALPN answered a server's ALPN response with `illegal_parameter` (the owned client) or `no_application_protocol` (the fixed-capacity client). An unrequested extension is `unsupported_extension` (RFC 8446 §4.2); both clients now send it, and `illegal_parameter` for a protocol outside an offered list (`Extensions.sendAdditionalExtension`) | REQ-MSG-006 |

The fixed-capacity engine was not run under TLS-Anvil. Both fixes were made
in both engines, and its tests cover them.

## Result

After the fixes, of 437 test templates:

| Result | Templates | Cases |
|---|---|---|
| Strictly succeeded | 95 | 814 |
| Conceptually succeeded | 8 | 24 |
| Partially failed | 6 | 57 failed |
| Fully failed | 0 | |
| Disabled | 328 | |

Every case that did not strictly succeed is the same one: a server
certificate with a 1024-bit RSA key, which the client refuses with
`insufficient_security` (the default profile requires 2048 bits; NIST SP
800-131A disallows RSA below 2048 bits for signatures). TLS-Anvil did not
learn this minimum during feature extraction, so it expected those
handshakes to complete. The refusal is deliberate.

The disabled templates are server tests (205), TLS 1.2 and older (71), and
features the test client does not use (PSK resumption and 0-RTT, maximum
fragment length, legacy RSA signature schemes and others: 52).

## Limits

- Strength 1, the suite's standard run; higher strengths test more
  parameter combinations.
- One client configuration: the default profile, no ALPN, no client
  certificate, no session resumption or 0-RTT, no ECH.
- The certificates carry no names, so name checking was not exercised here;
  it is covered by the library's own tests and the OpenSSL interoperability
  tests.
- Only the owned engine ran under TLS-Anvil.
- The runs were made step by step (client built in WSL, Docker on
  Windows), not with `scripts/tls-anvil.sh` end to end, which this machine
  cannot run (no Docker inside WSL). The script's patched X509-Attacker,
  rebuilt from a fresh clone, has byte-identical classes to the one used.
