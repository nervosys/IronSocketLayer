# Architecture

```
                 ┌────────────────────────── isl-cli (isl) ───────────────────────────┐
                 │  CLI commands  ·  MCP server (stdio JSON-RPC)  ·  probe / serve      │
                 └───────────────┬──────────────────────────────────┬──────────────────┘
                                 │                                  │
     ┌───────────── ironsocketlayer ▼──────────────────────┐   ┌───────▼────────────┐
     │ stream (std)   TlsStream<S: Read + Write>         │   │  isl-ontology       │
     │ quic           QuicConnection, packet/header keys │   │  102 entries,      │
     │ conn           Connection: sans-I/O engine        │◄──┤  errors, profiles, │
     │   ├ client     state machine (RFC 8446 A.1)       │   │  intents; JSON-LD, │
     │   └ server     state machine (RFC 8446 A.2)       │   │  OWL, Markdown     │
     │ record         record layer, nonces, limits      │   └───────┬────────────┘
     │ msgs · codec   handshake messages, wire codec    │           │ builtOn
     │ key_schedule   RFC 8446 §7 key schedule, exporter│           ▼
     │ x509           path validation, names, builder   │   ┌────────────────────┐
     │ config·policy  profiles, FIPS gate               │   │  ic-ontology       │
     │ report         SessionReport, properties, events │   │  (IronCrypto)      │
     │ crypto/        the only module naming IronCrypto ├──►│                    │
     └──────────────────────────────────────────────────┘   │ ic-hash ic-mac     │
                                                            │ ic-kdf ic-cipher   │
                                                            │ ic-ec ic-rsa       │
                                                            │ ic-mlkem ic-mldsa  │
                                                            │ ic-pkix ic-fips    │
                                                            └────────────────────┘
```

## Sans-I/O at the core

`Connection` never touches a socket. `read_tls(&[u8])` feeds it bytes from the
peer; `take_tls()` returns bytes to send. Everything else — `TlsStream`,
`QuicConnection`, `isl probe` — is a driver that moves bytes. Consequences:

* **Deterministic.** Given the same inputs and the same random source, the
  engine produces the same outputs. A test harness (or a DO-178C
  requirements-based test procedure) drives it without timing or scheduling.
* **Portable.** The engine is `no_std + alloc`; the caller supplies time
  (`Clock`) and randomness (`RngFactory`). It builds for Cortex-M.
* **Runtime-agnostic.** Tokio, smol, an RTOS, WebAssembly, or a QUIC stack all
  drive the same engine.

## One engine, two transports

TLS over TCP and TLS for QUIC run the same client and server state machines.
The difference is confined to `conn::Transport`:

| | `Transport::Tls` | `Transport::Quic` |
|---|---|---|
| handshake bytes | records, sealed under the current write key | queued per encryption level for CRYPTO frames |
| key installation | re-keys the record layer | emits a `KeyChange` for the QUIC stack |
| ChangeCipherSpec | sent once for middlebox compatibility, tolerated during the handshake | never |
| alerts | records | an alert code for CONNECTION_CLOSE (0x0100 + alert) |
| KeyUpdate message | supported | forbidden (QUIC has its own key update) |

## State machines

Each handshake message is matched against `(state, message type)` before any
of its content is read, so an out-of-order message is `unexpected_message`
regardless of what it contains. States are `report::HandshakeState`, each with
an ontology id (`state:wait-certificate-verify`), so an agent watching a
connection sees the same names this document uses.

The client verifies the server's certificate as soon as the Certificate
message arrives, then the CertificateVerify signature over the transcript,
then the Finished MAC, and only then sends its own second flight. The server
selects by its own preference: suite, then a group the client already sent a
share for (else a HelloRetryRequest), then the identity whose certificate
covers the SNI name.

## Session resumption

Resumption is PSK **with** (EC)DHE only (`psk_dhe_ke`), so every resumed
handshake still runs a fresh key exchange: forward secrecy holds, and with a
hybrid group so does post-quantum confidentiality. What resumption saves is
certificate transmission, path validation and the handshake signatures.

* **Server tickets are stateless.** `resumption::TicketKeys` seals the
  resumption PSK, the issuing suite, the SNI name, the lifetime, and whether and
  how the client authenticated, with AES-256-GCM under a key only the server
  holds. A ticket that does not open, has expired, names another host or
  another hash, or would satisfy a client-authentication requirement its
  session never met, is ignored and the handshake runs in full.
* **Binders are checked before use.** A ticket that opens but whose binder
  does not verify is `decrypt_error`: that client is not holding the PSK.
* **Client tickets are single use.** `resumption::TicketStore::take` removes
  the ticket it returns, so no ticket is presented twice.
* **Reports carry the original authentication.** A resumed session's report
  says `"resumed": true` and repeats the peer facts established when the
  ticket was issued, including post-quantum authentication and mutual
  authentication, each only if it held then.

The DAL-A profile disables resumption on both sides to keep one handshake path.

## Encrypted Client Hello

The client builds its real ClientHello (the *inner*), encodes it without the
session ID, pads it so the name's length does not show, and seals it with
HPKE to the key in the server's `ECHConfigList`. It sends an *outer* hello
naming only the public name, with the same key shares, and keeps both
transcripts ready. The server's 8-byte confirmation, in the ServerHello random
or the HelloRetryRequest, decides which transcript is real; nothing else does.

A server that cannot decrypt completes the handshake as its public name and
returns fresh `retry_configs`. The client authenticates that server under the
public name, verifies its Finished, and only then aborts with `ech_required`,
so the retry configurations it exposes are authenticated. A configured ECH
that cannot be used is an error before anything is sent: there is no path by
which IronSocketLayer sends the real name in the clear after being told to hide
it.

## Revocation

Two sources, used together. **CRLs** come from a caller-filled
`x509::crl::CrlStore` (`Common::crls`): every certificate below the anchor is
checked against its issuer's CRLs, on the client and on a server doing mutual
TLS. A serial listed by any authentic CRL is revoked — stale or not — and only
a current, full-scope CRL shows a certificate good; `require_crl` demands
that for the whole path. **OCSP stapling** covers the leaf. The client asks for a staple unless its
policy is `Revocation::Off`. A staple that arrives must verify whatever the
policy — signed by the leaf's issuer or a delegate the issuer certified with
`id-kp-OCSPSigning`, current within five minutes of skew, and about this
leaf — because a stale or forged staple is not the same as none. A revoked
status always fails the handshake with `certificate_revoked`.
`RequireStaple` also fails when there is no staple or the status is unknown.
IronCrypto has no SHA-1, so SHA-1 CertIDs are matched on the serial number,
with the issuer bound by the signature; SHA-2 CertIDs are checked in full.

## Where the cryptography is

`src/crypto/` is the only code that names an IronCrypto type:

* `crypto/mod.rs`: hashes and the running transcript, HMAC, HKDF and
  HKDF-Expand-Label, AEADs, QUIC header protection.
* `crypto/kx.rs`: every key-exchange group, including the hybrid encodings.
* `crypto/sign.rs`: signing keys (PKCS#8, PEM, generation; ML-DSA private
  keys through `ic_pkix::MlDsaPrivateKey`), SPKI parsing and signature
  verification.
* `crypto/hpke.rs`: an adapter over IronCrypto's `ic-hpke` (RFC 9180 base
  mode), naming the identifiers ECH uses and mapping its errors.

Each function reports the IronCrypto ontology ids it uses, which is what lets
`policy` check them through `ic_fips::check` and lets the agreement tests
prove the ontology's `builtOn` edges are the code's actual dependencies.

## Bounded resources

Everything a peer can make this endpoint hold is bounded:

| Resource | Bound |
|---|---|
| Unparsed TLS input buffered | 4 full records + 16 KiB |
| One handshake message | 128 KiB (configurable) |
| Certificates in a chain | 10 |
| Path-building work | 100 candidate checks, depth 8 |
| Audit events per report | 256 |
| Records per AES-GCM key | 2^24, with a KeyUpdate sent 2^16 before |

## The ontology as a contract

`isl-ontology` is static data with no dependencies. `ironsocketlayer` depends on
it and its tests hold the two in agreement: every code point has an entry with
the right wire value; "implemented" means implemented; every error kind has a
catalog entry with the same flags and alert; every `ic:` edge resolves in
IronCrypto and equals the primitives the code calls; every profile contains
exactly the suites, groups and schemes the configuration builds, in the same
order. Documentation that is also a test cannot drift.
