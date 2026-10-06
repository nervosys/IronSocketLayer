//! CRL checking in handshakes, on both sides and along the whole path.

mod common;

use std::sync::Arc;

use common::*;
use ironsocketlayer::config::{ClientAuth, Identity, PeerVerification, Profile, ServerConfig};
use ironsocketlayer::crypto::sign::{KeyKind, SigningKey};
use ironsocketlayer::enums::AlertDescription;
use ironsocketlayer::report::Property;
use ironsocketlayer::x509::crl::CrlStore;
use ironsocketlayer::x509::{self, Certificate, CertificateParams, Usage};
use ironsocketlayer::ErrorKind;

fn store(crl: &[u8]) -> Arc<CrlStore> {
    let mut s = CrlStore::new();
    s.add_der(crl).unwrap();
    Arc::new(s)
}

/// REQ-CRL-002: a server refuses a client whose certificate its CA revoked —
/// how an agent fleet cuts off a compromised agent.
#[test]
fn a_revoked_agent_is_refused_by_a_mutual_tls_server() {
    let pki = Pki::new(KeyKind::EcdsaP256, "server.test");
    let agent = pki.client_identity(KeyKind::Ed25519, "agent-13");
    let serial = Certificate::parse(&agent.chain[0])
        .unwrap()
        .serial()
        .to_vec();
    let mut sc = pki
        .server_config(Profile::Default)
        .with_client_auth(ClientAuth::Required(PeerVerification::Roots(pki.roots())));
    sc.common.crls = Some(store(&pki.crl(&[&serial])));
    let cc = pki.client_config(Profile::Default).with_identity(agent);
    let err = connect(Arc::new(cc), Arc::new(sc), "server.test").unwrap_err();
    assert_eq!(
        err.server.map(|e| e.kind()),
        Some(ErrorKind::CertificateRevoked)
    );
    assert_eq!(
        err.client.and_then(|e| e.peer_alert()),
        Some(AlertDescription::CertificateRevoked)
    );
}

/// REQ-CRL-003: a current CRL that does not list the certificate shows it good.
#[test]
fn a_clean_path_is_reported_revocation_checked() {
    let pki = Pki::new(KeyKind::EcdsaP256, "server.test");
    let mut cc = pki.client_config(Profile::Default);
    cc.common.crls = Some(store(&pki.crl(&[])));
    cc.common.require_crl = true;
    let (c, _) = connect(
        Arc::new(cc),
        Arc::new(pki.server_config(Profile::Default)),
        "server.test",
    )
    .unwrap();
    assert!(c.report().has(Property::RevocationChecked));
    assert_eq!(c.report().revocation, "revocation:good");
}

/// REQ-CRL-003: require_crl with nothing to show the path good fails.
#[test]
fn require_crl_without_a_crl_fails() {
    let pki = Pki::new(KeyKind::EcdsaP256, "server.test");
    let mut cc = pki.client_config(Profile::Default);
    cc.common.require_crl = true;
    let err = connect(
        Arc::new(cc),
        Arc::new(pki.server_config(Profile::Default)),
        "server.test",
    )
    .unwrap_err();
    assert_eq!(
        err.client.map(|e| e.kind()),
        Some(ErrorKind::BadCertificateStatus)
    );
    // A CRL from an unrelated CA does not count.
    let other = Pki::new(KeyKind::EcdsaP256, "server.test");
    let mut cc = pki.client_config(Profile::Default);
    cc.common.require_crl = true;
    cc.common.crls = Some(store(&other.crl(&[])));
    let err = connect(
        Arc::new(cc),
        Arc::new(pki.server_config(Profile::Default)),
        "server.test",
    )
    .unwrap_err();
    assert_eq!(
        err.client.map(|e| e.kind()),
        Some(ErrorKind::BadCertificateStatus)
    );
}

/// REQ-CRL-002: revocation of an intermediate takes down every certificate
/// beneath it.
#[test]
fn a_revoked_intermediate_revokes_the_path() {
    let pki = Pki::new(KeyKind::EcdsaP256, "server.test");
    let (ca, ca_key) = pki.ca();
    let mut rng = ic_drbg::Rng::from_os().unwrap();
    let t = now();
    let int_key = SigningKey::generate(KeyKind::EcdsaP384, &mut rng).unwrap();
    let int = x509::issue(
        &CertificateParams {
            subject_cn: "Issuing CA",
            dns_names: &[],
            ip_addresses: &[],
            not_before: t - 60,
            not_after: t + 86_400,
            is_ca: true,
            path_len: Some(0),
            usage: &[],
            serial: [0x44; 16],
        },
        int_key.spki(),
        ca,
        ca_key,
        &mut rng,
    )
    .unwrap();
    let leaf_key = SigningKey::generate(KeyKind::EcdsaP256, &mut rng).unwrap();
    let leaf = x509::issue(
        &CertificateParams {
            subject_cn: "server.test",
            dns_names: &["server.test"],
            ip_addresses: &[],
            not_before: t - 60,
            not_after: t + 86_400,
            is_ca: false,
            path_len: None,
            usage: &[Usage::ServerAuth],
            serial: [0x55; 16],
        },
        leaf_key.spki(),
        &int,
        &int_key,
        &mut rng,
    )
    .unwrap();
    let identity = Identity::new(vec![leaf, int.clone()], leaf_key).unwrap();
    let sc = Arc::new(ServerConfig::new(Profile::Default, identity).unwrap());
    let int_serial = Certificate::parse(&int).unwrap().serial().to_vec();

    let mut cc = pki.client_config(Profile::Default);
    cc.common.crls = Some(store(&pki.crl(&[&int_serial])));
    let err = connect(Arc::new(cc), sc.clone(), "server.test").unwrap_err();
    assert_eq!(
        err.client.map(|e| e.kind()),
        Some(ErrorKind::CertificateRevoked)
    );

    // Not revoked: the root's CRL covers the intermediate, but nothing
    // covers the leaf, so the path is not fully checked.
    let mut cc = pki.client_config(Profile::Default);
    cc.common.crls = Some(store(&pki.crl(&[])));
    let (c, _) = connect(Arc::new(cc), sc, "server.test").unwrap();
    assert!(!c.report().has(Property::RevocationChecked));
}
