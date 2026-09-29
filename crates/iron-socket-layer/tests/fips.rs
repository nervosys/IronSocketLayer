//! The FIPS 140-3 gate and the DAL-A profile.
//!
//! IronCrypto's module state is process-global, so these run in their own
//! test binary, sequenced inside one test: first with the module down, then
//! with it in approved mode.

mod common;

use std::sync::Arc;

use common::*;
use iron_socket_layer::config::{
    ClientAuth, ClientConfig, PeerVerification, Profile, ServerConfig,
};
use iron_socket_layer::crypto::sign::KeyKind;
use iron_socket_layer::enums::{NamedGroup, SignatureScheme};
use iron_socket_layer::report::Property;
use iron_socket_layer::ErrorKind;

#[test]
fn the_fips_gate_refuses_then_admits_and_reports_indicators() {
    let pki = Pki::new(KeyKind::EcdsaP256, "server.test");

    // 1. Module not in approved mode: FIPS profiles do not build a connection.
    for profile in [Profile::Fips140_3, Profile::Cnsa1] {
        let cfg = ClientConfig::new(profile, pki.roots()).unwrap();
        assert_eq!(
            cfg.validate().unwrap_err().kind(),
            ErrorKind::FipsModule,
            "{profile:?}"
        );
    }

    // 2. Bring the module up in approved mode.
    let report = iron_socket_layer::policy::enable_fips().unwrap();
    assert_eq!(report.failed, 0);

    // 3. A non-approved algorithm smuggled into a FIPS profile is refused.
    let mut bad = ClientConfig::new(Profile::Fips140_3, pki.roots()).unwrap();
    bad.common.groups.push(NamedGroup::X25519);
    assert_eq!(
        bad.validate().unwrap_err().kind(),
        ErrorKind::PolicyViolation
    );
    let mut bad = ClientConfig::new(Profile::Fips140_3, pki.roots()).unwrap();
    bad.common.schemes.push(SignatureScheme::Ed25519);
    assert_eq!(
        bad.validate().unwrap_err().kind(),
        ErrorKind::PolicyViolation
    );

    // 4. The FIPS profile connects, and every indicator is approved.
    let (c, s) = connect(
        Arc::new(pki.client_config(Profile::Fips140_3)),
        Arc::new(pki.server_config(Profile::Fips140_3)),
        "server.test",
    )
    .unwrap();
    let r = c.report();
    assert_eq!(r.group, Some(NamedGroup::SecP256r1MlKem768));
    assert!(r.has(Property::FipsApprovedAlgorithms), "{}", r.to_json());
    assert!(r.has(Property::PostQuantumKeyExchange));
    assert!(r.fips_indicators.all_approved());
    assert!(r
        .fips_indicators
        .entries
        .iter()
        .any(|(alg, _)| *alg == "ml-kem-768"));
    assert!(r.to_json().contains(r#""validated":false"#));
    assert!(s.report().has(Property::FipsApprovedAlgorithms));

    // 5. DAL-A: one suite, one group, one scheme, mutual authentication.
    let pki = Pki::with_kinds(KeyKind::EcdsaP384, KeyKind::EcdsaP384, "fcc.test");
    let client_id = pki.client_identity(KeyKind::EcdsaP384, "flight-computer-2");
    let refused = |r: iron_socket_layer::Result<()>, expect: &str| {
        let e = r.expect_err(expect);
        assert_eq!(e.kind(), ErrorKind::InvalidConfig, "{e}");
        assert!(e.to_string().contains(expect), "wanted {expect:?}, got {e}");
    };
    let no_identity = pki.client_config(Profile::DalA);
    refused(no_identity.validate(), "profile requires a client identity");
    let optional = pki
        .server_config(Profile::DalA)
        .with_client_auth(ClientAuth::Optional(PeerVerification::Roots(pki.roots())));
    refused(
        optional.validate(),
        "profile requires mandatory client authentication",
    );
    // DAL-A signs with ECDSA P-384 only: a P-256 server key cannot serve it.
    let p256 = Pki::new(KeyKind::EcdsaP256, "fcc.test");
    let wrong_key = ServerConfig::new(Profile::DalA, p256.server_identity())
        .unwrap()
        .with_client_auth(ClientAuth::Required(PeerVerification::Roots(pki.roots())));
    refused(
        wrong_key.validate(),
        "a server key cannot sign with any scheme the profile allows",
    );
    let cc = pki.client_config(Profile::DalA).with_identity(client_id);
    let sc = pki
        .server_config(Profile::DalA)
        .with_client_auth(ClientAuth::Required(PeerVerification::Roots(pki.roots())));
    let (c, s) = connect(Arc::new(cc), Arc::new(sc), "fcc.test").unwrap();
    for r in [c.report(), s.report()] {
        assert_eq!(r.group, Some(NamedGroup::Secp384r1));
        assert!(r.has(Property::MutualAuthentication));
        assert!(r.has(Property::FipsApprovedAlgorithms));
        assert_eq!(r.profile, "profile:dal-a");
    }
    assert_eq!(
        s.report().peer_subject_cn.as_deref(),
        Some("flight-computer-2")
    );
}
