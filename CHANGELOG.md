# Changelog

All notable changes to IronSocketLayer. The project is pre-1.0: minor
versions may change the API.

## 0.6.0 (2026-10-12)

Moves onto IronPKI 0.3. One breaking change, IronPKI's: `x509::CertificateParams`
can no longer be built field by field. Requires IronPKI 0.3.

### Changed
- `x509::CertificateParams` is `#[non_exhaustive]`. Build it with
  `CertificateParams::new(subject_cn, not_before, not_after, serial)` and set
  the other fields after.

### Added, from IronPKI 0.3
- `x509::Certificate::uri_names` and `x509::CertificateParams::uris`: URI
  alternative names, read and issued.
- `x509::request`: PKCS#10 certificate requests, read, verified and made.

### Not covered
- The session report's `peer_names` still lists DNS names and addresses
  only, not URIs.

## 0.5.1 (2026-10-12)

`isl check-config` reads certificate policies, the project publishes its
control mappings, and IronPKI 0.2.1 or later is required, for its fixes to
certificate policy processing. No API change.

### Added
- `isl check-config` and the `check_config` MCP tool read
  `certificatePolicies` from a description: `acceptable`, a list of policy
  identifiers in dotted decimal, and `requireExplicit`, `inhibitMapping`
  and `inhibitAny`. The configuration is built and validated with them,
  and the answer says what was understood.
- `docs/controls.json` (`ironsecurity-controls/1`): the project's own
  statement of how it stands against SP 800-53 SC-8, SC-8(1), SC-13 and
  SC-23 and CMMC SC.L2-3.13.8, 3.13.11 and 3.13.15, for IronEvidence's
  OSCAL document. Only session authenticity is claimed as met; SC-13 and
  3.13.11 are unmet, IronCrypto not being CMVP validated. It is a claim,
  not an assessment.

### Fixed
- With IronPKI 0.2.1, which 0.5.0 picks up on a dependency update:
  certificate policy processing no longer refuses ordinary paths as too
  involved (five certificates of 30 policies each with 64 policies
  configured was enough), and a crafted chain under a trusted anchor can
  no longer make one policy evaluation take 170 ms or more; it is bounded
  at about 15 ms. A certificate that lists a policy twice, or whose policy
  qualifiers are malformed, no longer parses. 0.5.1 requires it. 0.4.1
  gets the same fixes from IronPKI 0.1.4 on a dependency update. Neither
  defect accepted a path it should not.

## 0.5.0 (2026-10-11)

A configuration can say which certificate policies it accepts on a peer's
path. Two breaking changes, both to types callers build or match by
field. Requires IronPKI 0.2.

### Added
- `common.certificate_policies`, a `CertificatePolicies` (REQ-CFG-010):
  the policy inputs of RFC 5280 section 6.1.1 for a peer's path.
  `acceptable` names up to 64 policies by the contents of their object
  identifiers; `require_explicit` requires a valid policy from the start
  of the path; `inhibit_mapping` and `inhibit_any` inhibit policy mapping
  and anyPolicy from the start. `CertificatePolicies::require(&[..])` is
  for "only these policies": naming policies requires none by itself. The
  default asks nothing, and a handshake then behaves as in 0.4.1.
- A peer whose path these refuse fails the handshake with
  `error:certificate-usage`, at a client, at a server (in the handshake
  and for a certificate requested after it) and in the fixed-capacity
  engine, which passes them without allocating.
- `peer_policy` in the session report and in the fixed engine's:
  whether a policy was required of the peer's path, and which of the
  configured policies are valid for it, one bit each
  (`peerPolicyRequired` and `peerPoliciesValid` in the JSON). Absent
  without a peer path.
- Under a policy mapping, the policy to name is the one the trust
  anchor's side knows, not the one the peer's certificate lists.

### Changed
- `config::Common` has a new public field, so code that builds one field
  by field no longer compiles. Build a configuration with
  `ClientConfig::new` or `ServerConfig::new` and set fields after.
- `x509::VerifyOptions`, `x509::ChainReport` and `x509::FixedChainReport`
  (IronPKI's) are `#[non_exhaustive]`: build options with
  `VerifyOptions::new`, and read reports by field.

### Not covered
- These settings are not applied to a pinned peer, which has no path.
- `isl check-config` and the `check_config` MCP tool do not read
  certificate policies from a JSON description yet.

## 0.4.1 (2026-10-11)

The CNSA profiles are brought into line with the certificate profiles
their TLS profiles defer to: RFC 8603 for `profile:cnsa-1` and
draft-jenkins-cnsa2-pkix-profile-05 for `profile:cnsa-2`. Certificate
policies are processed under every profile. No API change. Requires
IronPKI 0.1.3.

### Changed
- Certificate policies are processed, by IronPKI 0.1.3, as RFC 5280
  section 6.1 has it for a caller that accepts any policy and requires
  none at the start. Both CNSA certificate profiles require it of a
  relying party. Under every profile:
  - a peer whose path has a CA that requires an explicit policy, and no
    policy valid down to the leaf, is refused with
    `error:certificate-usage`. It was accepted before unless the
    requirement was marked critical;
  - a critical `policyConstraints`, `policyMappings` or `inhibitAnyPolicy`
    no longer fails the handshake as an unknown critical extension;
  - a certificate whose `certificatePolicies` is malformed no longer
    parses.
  A configuration cannot yet name the policies it accepts.
- Under `profile:cnsa-1` and `profile:cnsa-2`, every certificate a peer
  presents must carry a key of the suite, whether the path uses it or not
  (REQ-CFG-009; RFC 8603 section 4.1 and the draft's section 4): P-384 or
  RSA for 1.0, ML-DSA-87 or ML-KEM-1024 for 2.0. Any other key fails the
  handshake with `policy-violation`. Before, only RSA keys were held to a
  rule, and only under 1.0. A peer that sends an extra certificate for the
  benefit of other clients, with a key outside the suite, is now refused
  under these two profiles.
- OCSP responses built by `x509::ocsp::build_response` identify the
  certificate with SHA-384 hashes, where they used SHA-256. The CNSA
  certificate profiles allow no shorter hash outside a signature.
  Verification is unchanged. A verifier that looks a certificate up by one
  hash only must be asked for SHA-384 (`openssl ocsp -sha384`).

### Verification
- `tests/cnsa.rs` shows what was already enforced of the two certificate
  profiles: a chain whose CA signed with anything but the suite's
  algorithm (ECDSA P-384 or RSA with SHA-384; ML-DSA-87) is refused with
  `policy-violation` although the leaf's key is one the profile allows,
  and a leaf key outside the suite leaves the server nothing to sign with.
  HashML-DSA and RSA exponents of 2^256 or more are not accepted under any
  profile.

### Not covered
- What the certificate profiles ask of an issuer is not checked on
  receipt: that key identifiers are present, that key usage is critical
  with exactly the listed bits, that a self-signed CA has no path length.
- A caller can still widen `common.suites`, `groups` or `schemes` after
  choosing a CNSA profile; the profile name does not change when they do.

## 0.4.0 (2026-10-10)

The certificate code is now [IronPKI](https://github.com/nervosys/IronPKI),
a separate crate that IronPrivacyGuard shares. `ironsocketlayer::x509` is
IronPKI's `x509` module re-exported, so most code that only names its types
keeps compiling; what changed is listed below. Handshake behaviour is
unchanged. Requires IronPKI 0.1 and IronCrypto 0.2.21 or later, below 0.3.

### Changed (breaking)
- `x509::Usage` is `x509::Purpose`: `ServerAuth` and `ClientAuth` are
  `TlsServer` and `TlsClient`. IronPKI adds `TpmEndorsementKey`, which a TLS
  handshake never uses.
- `x509::VerifyOptions::new` takes a fourth argument, `x509::Limits`, and
  has no `max_depth` field: the bounds are `limits`. A handshake passes
  `Limits::ONLINE`, which is the depth of 8 and the 24 signature checks this
  crate always used. `isl verify` passes `Limits::DEFAULT`, for a chain the
  operator chose to examine.
- The certificate functions return `ironpki::Error`. It converts into this
  crate's `Error` (`?` and `Error::from` both work) under the same kinds as
  before: IronPKI's `bad-signature` and `key-algorithm-mismatch` are
  `decrypt-error` and `illegal-parameter` here.
- Algorithms in the certificate API are IronCrypto's `SignatureAlgorithm`,
  not `SignatureScheme`: `VerifyOptions::allowed_schemes`,
  `ChainReport::schemes`, `Certificate::signature_scheme`, the OCSP and CRL
  functions. `SignatureScheme::algorithm` and `SignatureScheme::from_algorithm`
  convert between them.
- `Certificate::subject_public_key` returns IronCrypto's `ic_sig::PublicKey`,
  whose `kind_id` has no `key:` prefix. This crate's
  `crypto::sign::PublicKey::from_spki(cert.spki_der())` gives the type and
  identifiers it gave before. `ChainReport::leaf_key` likewise has no prefix.
- Issuance (`x509::self_signed`, `x509::issue`, `ocsp::build_response`,
  `crl::build`) takes `&dyn ic_core::sig::Signer`. A `&SigningKey` is one; an
  `Arc<SigningKey>` needs `&*key`.
- A certificate with a SHA-1 signature algorithm now fails
  `Certificate::signature_scheme` with `policy-violation`, where it used to
  return a scheme that path validation then refused with the same error.
- A chain of more than 64 certificates, or a certificate longer than 64 KiB,
  is refused with `capacity-exceeded` before it is parsed.

### Added
- `SigningKey` implements `ic_core::sig::Signer` (REQ-SIG-007), so anything
  that signs through IronCrypto's trait takes it as it is.
- `ChainReport::anchor_subject` and `anchor_spki`, and
  `VerifyOptions::accept_anchor_as_leaf`, from IronPKI.
- `x509::RootStore::add` takes IronPKI's `TrustAnchor`.

### Moved
- 138 requirements and the 221 tests that verify them moved to IronPKI with
  the code, under the identifiers they had here; `docs/TRACEABILITY.md` says
  which stayed. The fuzz targets `pki` and `pki_differential` still run here,
  through this crate, against IronPKI's code.

## 0.3.4 (2026-10-09)

The CNSA profiles compared, clause by clause, with their TLS profiles:
RFC 9151 for `profile:cnsa-1` and draft-becker-cnsa2-tls-profile-05 for
`profile:cnsa-2`. The algorithm lists already agreed; the differences were
in what the profiles let through.

### Fixed
- `profile:cnsa-1` refused RSA chains whose certificates are signed with
  PKCS#1 v1.5 and SHA-384 (`sha384WithRSAEncryption`), which RFC 9151 §5.2
  says MUST be supported in TLS 1.3 and is how most RSA certificates are
  signed. `rsa_pkcs1_sha384` is now in the profile, for certificates only;
  the handshake still signs with RSASSA-PSS. Checked against an RSA-3072
  chain issued by OpenSSL (REQ-CFG-008).

- `SigningKey::sign_into` (the fixed-capacity engine's signing path) checked
  the caller's storage against the DER encoding's bound for the curve, not
  against the signature, so for P-521 it refused 139 bytes, which is as
  long as a P-521 signature gets. It now encodes into scratch storage and
  measures. Found while moving the certificate code to IronPKI; the bound
  is corrected in IronCrypto after 0.2.20, where it grows by one byte, so
  the old check would have refused one byte more.

### Changed
- Under `profile:cnsa-1`, an RSA key on any certificate a peer presents
  must have a modulus of 3072 or 4096 bits and an odd exponent above 2^16
  (RFC 9151 §5.2); otherwise the handshake fails with `policy-violation`.
  It used to accept any size from 3072 to 4096 bits and any odd exponent
  from 3 (REQ-CFG-008). The rule covers the certificates presented, not
  the trust anchors, which are the operator's configuration.
- A configuration under `profile:cnsa-1` or `profile:cnsa-2` no longer
  validates with early data enabled or with an external PSK. Both TLS
  profiles forbid early data, and both require certificate authentication:
  this library's external PSK authenticates in place of certificates, and
  RFC 8773, which combines the two, is not implemented (REQ-CFG-007).

### Not covered
- The certificate profiles the two documents defer to (RFC 8603 and
  draft-jenkins-cnsa2-pkix-profile) were not compared.
- A caller can still widen `common.suites`, `groups` or `schemes` after
  choosing a CNSA profile; the profile name does not change when they do.

## 0.3.3 (2026-10-09)

Received application data is wiped from the connection once read, and a
trust anchor can be given as a name and a key. One behaviour change: a
connection that fails discards application data not yet read. One API
addition, `RootStore::add_anchor`. Requires IronCrypto 0.2.20 or later,
below 0.3, which fixes a Poly1305 defect a peer could reach.

### Security
- The minimum IronCrypto is now 0.2.20. IronCrypto 0.2.5 to 0.2.19 have a
  Poly1305 defect (GHSA-xr22-8pqp-gwfh) that a peer reaches by sending
  ChaCha20-Poly1305 records of large byte values, before either side is
  authenticated: a build with overflow checks on panics (and aborts under
  `panic = "abort"`, as the `isl` binary is built); a build without them
  computes a wrong tag. Releases 0.1.0 to 0.3.2 admit those versions.
  `profile:default` and `profile:post-quantum` offer ChaCha20-Poly1305; the
  FIPS, CNSA and DAL-A profiles do not. No code here changed for this;
  a regression test now opens all-ones records under a thousand keys per
  suite (REQ-REC-013). If you cannot upgrade, pin IronCrypto 0.2.20 in
  your lock file (`cargo update`).
- Received application data no longer outlives its reading (REQ-CONN-017).
  `Connection` kept it in ordinary buffers: bytes already read stayed in
  the allocation, a buffer that grew left its old storage behind unwiped,
  and dropping the connection freed the rest unwiped, so a response
  carrying a token or a derived key left copies in freed memory. A record
  is now wiped from the record buffer once opened, bytes are wiped from
  the receive queue as `recv` hands them over, outgrown storage is wiped
  before it is freed, and a connection that fails or is dropped wipes
  both. The fixed-capacity engine already wiped its application storage.
  What the caller reads into its own buffer is the caller's to wipe.

### Added
- `RootStore::add_anchor(subject_der, spki_der, name_constraints_der)`: a
  trust anchor given as a name and a key, for roots distributed that way
  and not as certificates (REQ-X509-079). Each argument is one complete
  DER element (the `Name`, the `SubjectPublicKeyInfo`, and the
  `NameConstraints` SEQUENCE). The anchor's constraints bind every path
  that ends at it; the same anchor under different constraints is refused.

### Changed
- A connection that fails discards application data received but not yet
  read: `recv` returns nothing after a failure, where it used to return
  what had arrived before it. Read what you need before feeding more
  records, or treat a failure as the loss of the unread data.

### Fixed
- The published packages' own tests now run from the package alone:
  `isl-cli` 0.3.2's tests read a key from the `ironsocketlayer` crate and
  did not compile, and `ironsocketlayer`'s traceability tests read
  `docs/TRACEABILITY.md` from the repository root. `isl-cli` carries its own
  copy of the throwaway key; the traceability tests check the matrix in the
  repository and say they have nothing to check outside it.

## 0.3.2 (2026-10-07)

Client fixes found by running TLS-Anvil, an independent conformance suite,
against the client and the server. No API change. A client now accepts a
ServerHello it used to refuse (one whose legacy_version is not 0x0303), and
sends a different alert for an unrequested ALPN answer. Requires IronCrypto
0.2.15 or later, below 0.3.

### Fixed
- Found with TLS-Anvil: both clients refused a TLS 1.3 ServerHello whose
  legacy_version was not 0x0303. RFC 8446 §4.2.1 says clients MUST ignore
  it when supported_versions is present; values above SSL 3.0 are now
  ignored, and SSL 3.0 and below are still `protocol_version`
  (REQ-MSG-014).
- Found with TLS-Anvil: a client that offered no ALPN answered a server's
  ALPN response with `illegal_parameter` (the owned client) or
  `no_application_protocol` (the fixed-capacity client); an unrequested
  extension is `unsupported_extension` (RFC 8446 §4.2). A protocol outside
  the offered list is now `illegal_parameter` in both clients (REQ-MSG-006).

### Changed
- `isl serve` serves connections concurrently, up to 64 at once, so a peer
  that stalls no longer holds up the next one.

### Verification
- TLS-Anvil's TLS 1.3 tests against the client and the server, with
  `scripts/tls-anvil.sh`; the results, and two defects in the test tool
  patched to make the run possible, are in
  `docs/VERIFICATION-2026-10-07-tls-anvil.md`.

## 0.3.1 (2026-10-06)

Fixes to the fixed-capacity engine found by fuzzing it against the owned
engine: it now accepts and refuses what the owned engine does, at the same
point in the input. No API change, but a non-conforming peer may notice the
fixed engine's new refusals (an alert or ChangeCipherSpec out of place,
QUIC transport parameters over TCP, a malformed `signature_algorithms_cert`
or cookie). Requires IronCrypto 0.2.15 or later, below 0.3.

### Fixed
Found by differential fuzzing of the two engines; in the fixed-capacity
engine:
- a malformed `signature_algorithms_cert` was ignored; its syntax is
  checked, as in the owned engine;
- a server_name entry of a type other than host_name was refused; it is
  skipped (RFC 6066 §3);
- a ClientHello `legacy_version` other than 0x0303 was refused; any value
  above SSL 3.0 is ignored, and SSL 3.0 and below are `protocol_version`
  (RFC 8446 §4.1.2, appendix D.5);
- QUIC transport parameters in a ClientHello were ignored; they are
  `unsupported_extension` over TCP (RFC 9001 §8.2);
- a cookie in a first ClientHello was refused; a well-formed one is
  ignored, as in the owned server and OpenSSL (RFC 8446 §4.2.2 forbids the
  client to send one but gives the server no duty to refuse it), and a
  cookie in a second ClientHello the server did not ask for is still
  refused;
- the client accepted a ChangeCipherSpec before the server's ServerHello or
  HelloRetryRequest; it is `unexpected_message` (RFC 8446 appendix D.4);
- alerts are handled as in the owned engine: one between the fragments of
  a handshake message is `unexpected_message` (RFC 8446 §5.1), a
  close_notify before the handshake completes is a failure rather than a
  clean close, and user_canceled is ignored rather than fatal (§6.1);
- several refusals came only when more input arrived; they now come as soon
  as the header that warrants them is complete: a record header announcing
  more than 2^14 + 256 bytes, a zero-length record other than application
  data, a handshake header announcing more than the engine can hold or a
  Finished longer than any hash, and any record or handshake message with
  an empty body (an empty application-data record before any keys went
  unrefused until more input arrived).

### Verification
- Three differential fuzz targets: `pki_differential` (the two path
  validators on re-signed, mutated chains with name constraints),
  `hello_differential` (the two servers on the same client flight) and
  `server_hello_differential` (the two clients on the server's plaintext
  records). Results in `docs/VERIFICATION-2026-10-06-differential.md`.

## 0.3.0 (2026-10-06)

Features that make the safe path the default for agents, and conformance
fixes found with tlsfuzzer. A minor version: new public fields and
functions, and stricter refusals (a second ChangeCipherSpec, an omitted
`key_share`, an oversized padded record) that a non-conforming peer may
notice. Requires IronCrypto 0.2.15 or later, below 0.3.

### Added
- `Common::required_properties`, set with `ClientConfig::require` and
  `ServerConfig::require`: the handshake fails with `error:policy-violation`
  (the missing property's id as context) before any application data is sent
  or accepted, in both engines. `validate()` refuses requirements that
  cannot be enforced in time (with 0-RTT) or met (mutual authentication
  without an identity or required client authentication).
- `ClientConfig::for_intent` and `ServerConfig::for_intent`: the
  configuration an intent calls for, from the ontology's selector (as
  `isl recommend`): its profile, its ALPN, and its needs as required
  properties. An unknown intent or an unavailable profile is an error, never
  a fallback. `config::IntentPolicy` re-exports the selector's policy flags.
- `config::Relaxation`, `ClientConfig::relaxations` and
  `ServerConfig::relaxations`: the safe defaults a configuration gives up
  (revocation off, 0-RTT, no ECH GREASE, SNI fallback, Selfie guard off).
  Every session report lists them as `relaxations`.
- `TlsStream::connect_with` and `accept_with` over TCP, with
  `stream::Timeouts`: a deadline for the whole handshake (a peer sending a
  byte at a time cannot stretch it) and an idle limit for each later read or
  write. Both fail with `io::ErrorKind::TimedOut`; after an idle timeout the
  stream remains usable.
- `Recovery`, `ErrorKind::recovery`, `Error::recovery` and
  `Connection::recovery`: what to do about an error as one of eight actions
  (`recovery:retry`, `reconnect`, `retry-with-ech-configs`, `fix-caller`,
  `ask-user`, `stop`, `fix-environment`, `report-bug`). The connection's
  version turns an ECH rejection without retry configurations into
  `ask-user`. The ontology's error catalog carries the same `action`, and
  `isl explain` and `isl probe` print it.
- Expiry warnings: `event:peer-certificate-expiring` and
  `event:local-certificate-expiring` (detail: seconds left) when a
  certificate in use expires within `Common::expiry_warning` (14 days by
  default; 0 never), at handshake completion and after post-handshake
  authentication. `SessionReport::local_not_after` (`localNotAfter`).
- Offline tools, as MCP tools and `isl` commands: `inspect_certificate`
  (`isl inspect`: names, validity, CA flag, key, signature, `spkiSha256`),
  `verify_chain` (`isl verify`: path, usage and name, with error id and
  action), and `check_config` (`isl check-config`: a configuration built
  from JSON with the library's validation, its requirements and
  relaxations; unknown keys and mistyped values are errors). Inputs are
  capped at 256 KiB. `Certificate::issuer_common_name`.

- `channel_binding()` on `Connection`, `QuicConnection` and
  `fixed::Connection`: the RFC 9266 `tls-exporter` value, checked against
  OpenSSL's `-keymatexport`. `conn::CHANNEL_BINDING_LABEL`.

### Fixed
- Found with tlsfuzzer:
  - a TLS 1.3 ClientHello with `supported_groups` but no `key_share` drew a
    HelloRetryRequest; it is refused with `missing_extension` (RFC 8446 §9.2);
  - a ClientHello `legacy_version` below SSL 3.0 was answered; it is
    refused with `protocol_version`;
  - an empty alert record is `unexpected_message`, not `decode_error`;
  - handshake messages may carry as many extensions, and ClientHellos as
    many key shares, as fit (tlsfuzzer sends over a thousand). The 0.2.0
    caps of 128 and 16 are gone: duplicates are found by sorting, in
    O(n log n), which keeps the audit's denial-of-service fix (A-15);
  - a record's inner plaintext (content, type and padding) may not exceed
    2^14 + 1 bytes (RFC 8446 §5.4); only the content was limited, so up to
    2^14 + 239 bytes were accepted;
  - a Finished of the wrong length is `decode_error`, not `decrypt_error`;
  - a second compatibility ChangeCipherSpec is `unexpected_message`, in
    both engines: a peer sends at most one (RFC 8446 appendix D.4). 0.2
    tolerated two;
  - after a HelloRetryRequest, a server kept skipping undecryptable records
    as rejected 0-RTT data after the second ClientHello; such a record is
    now `bad_record_mac` (RFC 8446 §4.2.10);
  - an empty application-data record before any keys was silently skipped
    (a zero skip budget covered a zero-length record), so a handshake
    stalled; it is `unexpected_message`;
  - a Finished announced longer than any hash is refused on its header.

- A `TlsStream` over TCP whose handshake failed could lose its own alert:
  closing the socket with the peer's bytes unread made the kernel send a
  reset, which on Linux discarded the alert before the peer read it. The TCP
  constructors now close gracefully. Found with tlsfuzzer.
- `isl serve --http` answers one HTTP request per connection, as
  `openssl s_server -www` does, for conformance suites such as tlsfuzzer.
- `isl serve` echoes whole messages (it echoed one read of at most 4 KiB),
  uses the handshake deadline, and keeps its idle limit with
  `TlsStream::set_timeouts`, which is new.
- The record layer's legacy version is ignored apart from its major byte,
  as RFC 8446 §5.1 requires; servers refused a ClientHello in a 0x0300
  record (tlsfuzzer's default), and the fixed engine also 0x0302. The fixed
  engine now refuses a record that is not TLS on its header, not after
  waiting for the body it announces.
- `isl serve --bind <addr>` was parsed as a flag and its address ignored,
  so the server always bound 127.0.0.1.

### Verification
- tlsfuzzer's 57 TLS 1.3 scripts, run with `scripts/tlsfuzzer.sh`; the
  results and the classification of every remaining failure are in
  `docs/VERIFICATION-2026-10-06-tlsfuzzer.md`.

### Changed
- Requires IronCrypto 0.2.15 or later, below 0.3. Its HPKE now also offers
  DHKEM(P-384, HKDF-SHA384); ECH here still uses the X25519 suite, whose
  outputs are unchanged.

## 0.2.1 (2026-10-06)

### Hardened
- The fixed-capacity client also sends ECH GREASE (`ClientConfig::ech_grease`),
  repeats it after HelloRetryRequest, and ignores retry configurations sent
  in answer. Its ClientHello grows by up to 350 bytes; turn `ech_grease` off
  where that matters.

### Verification
- Tests for the branches the 0.2.0 fixes opened; whole-suite branch
  coverage 97.70%, every remaining gap reviewed.
- `scripts/coverage.ps1` no longer merges profiles left by an earlier run.

## 0.2.0 (2026-10-06)

Security fixes from the 2026-10-06 audit
([docs/SECURITY-AUDIT-2026-10-06.md](docs/SECURITY-AUDIT-2026-10-06.md)).
Upgrade from 0.1.0. A minor version because the configuration and report
structs gained public fields and servers now refuse unknown SNI (see
Changed). Requires IronCrypto 0.2.13 or later, below 0.3.

### Fixed (security)
- Name constraints: a dNSName with a trailing dot no longer escapes an
  excluded subtree, and iPAddress constraints apply across address families
  (including IPv4-mapped IPv6).
- Denial of service:
  - extensions in certificates, CRLs and OCSP responses are capped before
    the duplicate check, which was quadratic;
  - certificate path search spends at most 24 signature verifications;
  - ClientHello extensions and key shares are capped;
  - KeyUpdate requests are answered once while silent;
  - ChangeCipherSpec records are bounded;
  - RSA exponents above 2^32 are refused;
  - OCSP responder candidates are limited.
- `TlsStream` reports truncation (no close_notify) as `UnexpectedEof`.
- Fixed engine: messages after a key change in the same record are
  refused, and ALPN with no overlap is refused.
- Owned engine: no records are accepted between the fragments of a
  handshake message.
- ECH retry configurations are returned only after `ech_rejected`.
- A non-CA trust anchor no longer issues certificates.
- A leaf cannot staple OCSP for itself.
- Pinned peers get the full leaf checks.
- Peer-driven counters saturate instead of overflowing.
- `isl` MCP `tls_probe` refuses loopback, private and link-local targets
  unless `ISL_MCP_ALLOW_PRIVATE=1`. Probes have an absolute deadline.
  `isl serve` binds 127.0.0.1 by default (`--bind`). Peer text is
  sanitized in terminal output.
- A server that requires client certificates no longer accepts an external
  PSK in their place.

### Hardened (weaknesses W-1 to W-12 of the audit)
- Selfie: with `std`, a server refuses an external-PSK ClientHello this
  process sent (`ServerConfig::selfie_guard`, on by default).
- A server refuses an SNI none of its certificates covers, with
  `unrecognized_name`, unless `ServerConfig::sni_fallback` is set.
- The client sends ECH GREASE when it has no ECH configuration
  (`ClientConfig::ech_grease`, on by default).
- A wildcard directly over a registry suffix such as `co.uk` matches
  nothing.
- A PSK-only server answers an unknown PSK identity as it answers a wrong
  binder.
- `MemoryReplayGuard::with_capacity`, and `event:replay-guard-full` when a
  full guard refuses early data.
- A client answers at most 16 post-handshake CertificateRequests per
  connection.
- `CrlStore::add_der_for_issuer` verifies a CRL once, at load.
- Indirect-CRL entries are attributed through certificateIssuer.
- Unread application data is bounded (`Common::max_buffered_plaintext`,
  1 MiB by default).
- An explicit v1 certificate version, or an explicit name-constraint
  minimum of 0, is refused (not DER).
- The record IV and `isl serve`'s private-key PEM text are zeroized.

### Added
- `SessionReport::peer_names` (`peerNames` in JSON): the peer certificate's
  subject alternative names. `isl probe` prints them.
- `ErrorKind::UnrecognizedName` (`error:unrecognized-name`).
- `x509::IpAddr` implements `Display` (RFC 5952 text).

### Changed
- An owned server refuses SNI it has no certificate for (see above); set
  `sni_fallback` for the old behaviour. The fixed server's refusal is now
  `error:unrecognized-name` instead of `error:handshake-failure`.
- A client and server in one process that share an external PSK must turn
  off `selfie_guard` on the server.
- `ServerConfig` and `ClientConfig` gained public fields; code building them
  with struct literals must set them.
- `Connection::ech_retry_configs()` returns `None` unless the handshake
  failed with `ech_rejected`.
- `TlsStream::read` returns `UnexpectedEof` where it used to return `Ok(0)`
  without close_notify.

## 0.1.0 (2026-10-05)

The first release. Not FIPS 140-3 validated, not DO-178C certified and not
independently reviewed; see [SECURITY.md](SECURITY.md).

### Protocols
- TLS 1.3 client and server (RFC 8446), sans-I/O, with a blocking
  `std::io` stream wrapper. Includes HelloRetryRequest, PSK resumption from
  tickets, external PSKs, opt-in 0-RTT with server-side anti-replay,
  post-handshake client authentication on demand, KeyUpdate and exporters.
- TLS for QUIC (RFC 9001), QUIC versions 1 and 2 (RFC 9369), including 0-RTT.
- Encrypted ClientHello (RFC 9849), client and server, over TCP and QUIC,
  with HPKE from IronCrypto's `ic-hpke`.
- X.509 path validation and issuance (RFC 5280), including name constraints,
  SPKI pinning, OCSP stapling (RFC 6066, RFC 6960) and CRLs, under a
  caller-chosen revocation policy.
- record_size_limit (RFC 8449), ALPN (RFC 7301).

### Post-quantum
- ML-KEM-512/768/1024 key exchange and the X25519MLKEM768,
  SecP256r1MLKEM768 and SecP384r1MLKEM1024 hybrids.
- ML-DSA-44/65/87 authentication, including certificates (RFC 9881).
- A CNSA 2.0 profile (ML-KEM-1024, ML-DSA-87, AES-256), interoperable with
  OpenSSL 3.5.

### For agents
- A machine-readable ontology (`isl-ontology`) of every protocol element,
  with named profiles and intents; `isl recommend` returns the profile for a
  purpose, or says it is unavailable rather than substituting a weaker one.
- Stable error ids, with `isl explain` giving their meaning and recovery.
- Session reports listing the security properties actually obtained.
- The `isl` command line and an MCP server (`isl mcp`).

### Embedded
- A separate fixed-capacity engine (`ironsocketlayer::fixed`) over
  caller-owned storage. It makes no allocator call after initialization and
  fails closed with `error:capacity-exceeded`. On an emulated Cortex-M4,
  every session needs 26 to 34 KB of stack.
- `no_std + alloc` for the main engine.

### Verification
- 231 low-level requirements, each traced to code and to a test or review.
- Interoperability with OpenSSL 3.5.7 in both directions, and with
  Cloudflare, Google and GitHub.
- Eight libFuzzer targets under AddressSanitizer.
- Whole-suite branch coverage of 97.6%, with a recorded disposition for
  every remaining gap.

### Requirements
- IronCrypto 0.2.11 or later, below 0.3.
- Rust 1.88 or later.
