//! Behaviour of the core modules that needs a process of its own.
//!
//! IronCrypto's FIPS module state is process-global, so the test that brings
//! it up lives in this binary alone and is the only test here.

use iron_socket_layer::enums::{CipherSuite, NamedGroup, SignatureScheme};
use iron_socket_layer::policy::{enable_fips, session_indicators};
use iron_socket_layer::ErrorKind;

/// REQ-CFG-003: once IronCrypto's module is operational, the service
/// indicators of a session's algorithms are gathered even when no FIPS
/// profile enforces them, with every algorithm the module does not approve
/// marked `not-approved`; under enforcement the same algorithms are a policy
/// violation. Before the module is up, an unenforced session gathers nothing.
#[test]
fn indicators_are_reported_unenforced_and_refused_enforced() {
    let suite = CipherSuite::TlsAes128GcmSha256;
    let schemes = [SignatureScheme::Ed25519];
    let before = session_indicators(suite, NamedGroup::X25519, &schemes, false).unwrap();
    assert!(before.entries.is_empty(), "{before:?}");

    assert_eq!(enable_fips().unwrap().failed, 0);

    let ind = session_indicators(suite, NamedGroup::X25519, &schemes, false).unwrap();
    assert!(ind.entries.contains(&("x25519", "not-approved")), "{ind:?}");
    assert!(
        ind.entries.contains(&("ed25519", "not-approved")),
        "{ind:?}"
    );
    assert!(
        ind.entries.iter().any(|(_, i)| *i != "not-approved"),
        "AES-GCM and SHA-256 are approved: {ind:?}"
    );
    assert!(!ind.all_approved());

    assert_eq!(
        session_indicators(suite, NamedGroup::X25519, &schemes, true)
            .unwrap_err()
            .kind(),
        ErrorKind::PolicyViolation
    );
    // A scheme with no IronCrypto identifier is reported, never dropped,
    // and refused under enforcement.
    let ind = session_indicators(
        suite,
        NamedGroup::X25519,
        &[SignatureScheme::EcdsaSha1],
        false,
    )
    .unwrap();
    assert!(
        ind.entries
            .contains(&("sigscheme:ecdsa-sha1", "not-approved")),
        "{ind:?}"
    );
    assert_eq!(
        session_indicators(
            suite,
            NamedGroup::Secp256r1,
            &[SignatureScheme::EcdsaSha1],
            true
        )
        .unwrap_err()
        .kind(),
        ErrorKind::PolicyViolation
    );
    let approved = session_indicators(
        suite,
        NamedGroup::Secp256r1,
        &[SignatureScheme::EcdsaSecp256r1Sha256],
        true,
    )
    .unwrap();
    assert!(approved.all_approved(), "{approved:?}");
}
