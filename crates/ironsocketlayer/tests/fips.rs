//! The FIPS 140-3 gate and the DAL-A profile.
//!
//! IronCrypto's module state is process-global, so these run in their own
//! test binary, sequenced inside one test: first with the module down, then
//! with it in approved mode.

mod common;

use std::sync::Arc;

use common::*;
use ironsocketlayer::config::{ClientAuth, ClientConfig, PeerVerification, Profile, ServerConfig};
use ironsocketlayer::crypto::sign::KeyKind;
use ironsocketlayer::enums::{NamedGroup, SignatureScheme};
use ironsocketlayer::report::Property;
use ironsocketlayer::ErrorKind;

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
    let report = ironsocketlayer::policy::enable_fips().unwrap();
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
    let refused = |r: ironsocketlayer::Result<()>, expect: &str| {
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

    // 6. CNSA 2.0: ML-KEM-1024, ML-DSA-87 on every signature, AES-256.
    let pki = Pki::with_kinds(KeyKind::MlDsa87, KeyKind::MlDsa87, "nss.test");
    let (c, s) = connect(
        Arc::new(pki.client_config(Profile::Cnsa2)),
        Arc::new(pki.server_config(Profile::Cnsa2)),
        "nss.test",
    )
    .unwrap();
    for r in [c.report(), s.report()] {
        assert_eq!(r.group, Some(NamedGroup::MlKem1024));
        assert_eq!(
            r.suite,
            Some(ironsocketlayer::enums::CipherSuite::TlsAes256GcmSha384)
        );
        assert!(r.has(Property::PostQuantumKeyExchange));
        assert!(r.has(Property::FipsApprovedAlgorithms), "{}", r.to_json());
        assert_eq!(r.profile, "profile:cnsa-2");
    }
    let r = c.report();
    assert_eq!(r.peer_signature_scheme, Some(SignatureScheme::MlDsa87));
    assert!(
        r.has(Property::PostQuantumAuthentication),
        "{}",
        r.to_json()
    );
    assert_eq!(r.peer_chain_min_bits, Some(256));
    assert!(r
        .fips_indicators
        .entries
        .iter()
        .any(|(alg, _)| *alg == "ml-dsa-87"));

    // A server with an ML-DSA-65 chain is refused, not accepted as a near miss.
    let near = Pki::with_kinds(KeyKind::MlDsa65, KeyKind::MlDsa65, "nss.test");
    let mut roots = near.roots();
    roots.add_der(&pki.ca_cert).unwrap();
    let mut cc = pki.client_config(Profile::Cnsa2);
    cc.verification = PeerVerification::Roots(roots);
    let mut sc = near.server_config(Profile::Fips140_3);
    sc.common.groups = vec![NamedGroup::MlKem1024];
    sc.common.suites = vec![ironsocketlayer::enums::CipherSuite::TlsAes256GcmSha384];
    assert!(connect(Arc::new(cc), Arc::new(sc), "nss.test").is_err());
}
