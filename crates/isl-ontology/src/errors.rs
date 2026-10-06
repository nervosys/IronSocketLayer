//! The error catalog: what each `ironsocketlayer::ErrorKind` means and how an
//! agent recovers from it.
//!
//! An error carries its id; an agent looks the id up here and follows
//! `recovery`. The flags equal the methods on `ErrorKind`, and
//! `crates/ironsocketlayer/tests/ontology_agreement.rs` checks that they do.

/// One error kind, documented.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ErrorDoc {
    /// Stable identifier, `error:` prefixed.
    pub id: &'static str,
    /// What happened.
    pub meaning: &'static str,
    /// What to do about it, as imperative steps.
    pub recovery: &'static [&'static str],
    /// Whether a fresh attempt could succeed unchanged.
    pub retryable: bool,
    /// Whether the local caller can fix it.
    pub caller_correctable: bool,
    /// Whether the remote peer caused it.
    pub peer_fault: bool,
    /// The alert this endpoint sends, if any.
    pub alert: Option<&'static str>,
}

const fn doc(
    id: &'static str,
    meaning: &'static str,
    recovery: &'static [&'static str],
    flags: (bool, bool, bool),
    alert: Option<&'static str>,
) -> ErrorDoc {
    ErrorDoc {
        id,
        meaning,
        recovery,
        retryable: flags.0,
        caller_correctable: flags.1,
        peer_fault: flags.2,
        alert,
    }
}

// (retryable, caller_correctable, peer_fault)
const PEER: (bool, bool, bool) = (false, false, true);
const LOCAL: (bool, bool, bool) = (false, true, false);
const NEITHER: (bool, bool, bool) = (false, false, false);
const RETRY: (bool, bool, bool) = (true, false, false);

/// Every error kind.
pub static CATALOG: &[ErrorDoc] = &[
    doc("error:capacity-exceeded", "Caller-owned connection storage cannot hold this operation.",
        &["Close this connection. Increase the declared capacity before initializing a new connection."],
        (false, true, false), Some("alert:internal-error")),
    doc("error:decode", "A record or handshake message from the peer could not be parsed.",
        &["Do not retry against the same peer with the same configuration.", "Capture the SessionReport and the peer's software version; report a peer bug or an on-path interference."],
        PEER, Some("alert:decode-error")),
    doc("error:unexpected-message", "The peer sent a message the handshake state does not permit.",
        &["Treat the peer as non-conforming.", "Check that nothing between you and the peer (proxy, TLS-terminating middlebox) is rewriting the stream."],
        PEER, Some("alert:unexpected-message")),
    doc("error:illegal-parameter", "A field was well-formed but forbidden: a key share for an unoffered group, an invalid point, an unoffered suite.",
        &["Do not retry unchanged.", "If the peer is a server you control, compare its configured groups and suites with the client's profile."],
        PEER, Some("alert:illegal-parameter")),
    doc("error:handshake-failure", "The peers share no acceptable cipher suite, group or signature scheme.",
        &["Call `isl recommend` for the intent and compare the recommended profile with what the peer supports.", "Widen the profile only if the user's requirements permit it; never drop a FIPS or post-quantum requirement to make a handshake succeed."],
        LOCAL, Some("alert:handshake-failure")),
    doc("error:protocol-version", "The peer does not speak TLS 1.3.",
        &["Report that the peer needs TLS 1.3; IronSocketLayer does not implement TLS 1.2 and will not fall back."],
        PEER, Some("alert:protocol-version")),
    doc("error:missing-extension", "A mandatory extension was absent (supported_versions, key_share, signature_algorithms, or QUIC transport parameters).",
        &["Treat the peer as non-conforming.", "For QUIC, confirm both endpoints run QUIC-TLS rather than TLS over TCP."],
        PEER, Some("alert:missing-extension")),
    doc("error:unsupported-extension", "The peer sent an extension it was not permitted to send, or one the client never offered.",
        &["Treat the peer as non-conforming; do not retry unchanged."],
        PEER, Some("alert:unsupported-extension")),
    doc("error:bad-record-mac", "A record failed authenticated decryption: corruption or tampering in transit.",
        &["Close the connection; never use data from it.", "Open a new connection; if it recurs, suspect an on-path attacker or a broken middlebox."],
        PEER, Some("alert:bad-record-mac")),
    doc("error:record-overflow", "A record exceeded 2^14 bytes of plaintext or the protocol's ciphertext bound.",
        &["Treat the peer as non-conforming."],
        PEER, Some("alert:record-overflow")),
    doc("error:decrypt-error", "The peer's CertificateVerify signature or Finished MAC did not verify.",
        &["Do not trust the peer's identity.", "If the peer is yours, check that its private key matches its certificate."],
        PEER, Some("alert:decrypt-error")),
    doc("error:bad-certificate", "The peer's certificate could not be parsed or a chain signature did not verify.",
        &["Do not add the certificate to the trust store to make the error go away.", "Inspect the chain with an X.509 tool and have the peer's operator reissue it."],
        PEER, Some("alert:bad-certificate")),
    doc("error:unsupported-certificate", "The certificate uses a key or signature algorithm this build does not support.",
        &["Consult `isl ontology list --kind signature-scheme` for supported schemes.", "Ask the peer's operator for a certificate with a supported key (ECDSA P-256/P-384/P-521, Ed25519, RSA 2048-4096, ML-DSA-65)."],
        NEITHER, Some("alert:unsupported-certificate")),
    doc("error:certificate-expired", "A certificate in the chain is outside its validity period.",
        &["Check the local clock first: a wrong clock is the commonest cause.", "If the clock is right, the peer's operator must renew the certificate. Do not disable time checks."],
        PEER, Some("alert:certificate-expired")),
    doc("error:certificate-revoked", "The certificate's issuer has revoked it: a current, signed OCSP response says so.",
        &["Do not retry and do not work around it: the key may be compromised.", "Tell the user; the peer's operator must deploy a new certificate."],
        PEER, Some("alert:certificate-revoked")),
    doc("error:bad-certificate-status", "An OCSP staple was malformed, stale, unsigned by the issuer, about another certificate, or required and missing.",
        &["If the policy requires a staple, confirm the server is configured to staple and its responder is reachable from the server.", "A stale or invalid staple is the server operator's to fix; do not downgrade the revocation policy to get past it without the user's agreement."],
        PEER, Some("alert:bad-certificate-status-response")),
    doc("error:unknown-ca", "The chain does not lead to any configured trust anchor.",
        &["Confirm which CA the peer is supposed to chain to.", "Add that CA's root to the trust store only if the user confirms it is trusted for this purpose.", "Check the peer sends its intermediates."],
        LOCAL, Some("alert:unknown-ca")),
    doc("error:certificate-name-mismatch", "The certificate is valid but does not cover the server name the connection is for.",
        &["Check that the name you connected to is the name the service is published under.", "Never disable name checking; connect using the right name instead."],
        LOCAL, Some("alert:bad-certificate")),
    doc("error:certificate-usage", "The certificate is not permitted for this use: wrong key usage or extended key usage, or a CA certificate used as a leaf.",
        &["Have the peer's operator issue a certificate with serverAuth (or clientAuth for mutual TLS) extended key usage."],
        NEITHER, Some("alert:bad-certificate")),
    doc("error:certificate-required", "Mutual authentication was required and the peer presented no certificate.",
        &["On a client: configure a client certificate and key.", "On a server: confirm that mutual TLS is really required for this listener."],
        LOCAL, Some("alert:certificate-required")),
    doc("error:no-application-protocol", "Both sides configured ALPN and share no protocol.",
        &["Align the ALPN lists (for example h2, http/1.1, h3); do not remove ALPN to silence the error."],
        LOCAL, Some("alert:no-application-protocol")),
    doc("error:ech-rejected", "The server could not decrypt the Encrypted Client Hello (usually a rotated key) and completed the handshake as its public name instead. No data was sent.",
        &["Reconnect with Connection::ech_retry_configs() as ClientConfig::ech_configs; the handshake authenticated them.", "If there are none, fetch the host's current ECH configuration from DNS again. Never retry without ECH unless the user agrees to expose the server name."],
        LOCAL, Some("alert:ech-required")),
    doc("error:policy-violation", "The peer negotiated parameters that are valid TLS but violate the configured profile (for example classical-only key exchange under profile:post-quantum).",
        &["Report which requirement the peer failed.", "Do not relax the profile unless the user explicitly withdraws the requirement."],
        LOCAL, Some("alert:insufficient-security")),
    doc("error:fips-module", "The IronCrypto FIPS module refused the operation: not initialised, in its error state, or asked for a non-approved algorithm in approved mode.",
        &["Call ic_fips::initialize() before connecting, and ic_fips::set_mode(Approved) for the FIPS profile.", "If the module is in its error state, restart the process; the state latches by design.", "Remember that IronCrypto is not CMVP-validated."],
        LOCAL, Some("alert:internal-error")),
    doc("error:peer-alert", "The peer sent a fatal alert; the alert id is attached to the error.",
        &["Look up the attached alert with `isl ontology show alert:<name>`; it says what the peer objected to."],
        PEER, None),
    doc("error:closed", "The connection was closed and can carry no more data.",
        &["Open a new connection."],
        NEITHER, None),
    doc("error:key-exhausted", "A traffic key reached its usage limit and has not been updated.",
        &["Let the connection perform a KeyUpdate, or reconnect."],
        RETRY, Some("alert:internal-error")),
    doc("error:invalid-state", "The API was called out of order (for example, sending application data before the handshake completed).",
        &["Drive the handshake to completion (is_handshaking() == false) before sending data.", "Check the connection's state with its report."],
        LOCAL, None),
    doc("error:invalid-config", "The configuration cannot produce a working handshake: no suites, a key that does not match its certificate, an unavailable profile.",
        &["Read the error context; it names the offending field.", "Rebuild the configuration from a profile via `isl recommend`."],
        LOCAL, None),
    doc("error:crypto", "A cryptographic primitive failed for a reason other than authentication.",
        &["Run `isl selftest`; if self-tests fail, stop using the process."],
        NEITHER, Some("alert:internal-error")),
    doc("error:entropy", "The random source failed.",
        &["Retry once; if it persists, the operating system's entropy source is unavailable and no handshake is safe."],
        RETRY, Some("alert:internal-error")),
    doc("error:internal", "An internal invariant failed. This is a bug in IronSocketLayer.",
        &["Report it with the SessionReport; do not retry in a loop."],
        NEITHER, Some("alert:internal-error")),
];

/// Look up an error by id.
pub fn get(id: &str) -> Option<&'static ErrorDoc> {
    CATALOG.iter().find(|e| e.id == id)
}
