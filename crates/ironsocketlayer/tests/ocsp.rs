//! OCSP stapling end to end: a server staples, a client applies its policy.

mod common;

use std::sync::Arc;

use common::*;
use ironsocketlayer::config::{Profile, Revocation};
use ironsocketlayer::crypto::sign::KeyKind;
use ironsocketlayer::enums::AlertDescription;
use ironsocketlayer::report::Property;
use ironsocketlayer::x509::ocsp::CertStatus;
use ironsocketlayer::ErrorKind;

fn stapling_server(
    pki: &Pki,
    staple: Option<Vec<u8>>,
) -> Arc<ironsocketlayer::config::ServerConfig> {
    let mut sc = pki.server_config(Profile::Default);
    if let Some(s) = staple {
        sc.identities[0] = sc.identities[0].clone().with_ocsp(s);
    }
    Arc::new(sc)
}

fn client(pki: &Pki, policy: Revocation) -> Arc<ironsocketlayer::config::ClientConfig> {
    let mut cc = pki.client_config(Profile::Default);
    cc.revocation = policy;
    Arc::new(cc)
}

#[test]
fn a_good_staple_is_verified_and_reported() {
    let pki = Pki::new(KeyKind::EcdsaP256, "server.test");
    let t = now();
    let sc = stapling_server(&pki, Some(pki.staple(CertStatus::Good, t - 60, t + 3600)));
    let (c, _) = connect(client(&pki, Revocation::IfStapled), sc, "server.test").unwrap();
    assert!(c.report().has(Property::RevocationChecked));
    assert_eq!(c.report().revocation, "revocation:good");
    assert!(c
        .report()
        .to_json()
        .contains(r#""revocation":"revocation:good""#));
}

/// REQ-OCSP-003: a revoked certificate fails the handshake with
/// certificate_revoked, whatever the policy.
#[test]
fn a_revoked_certificate_fails_the_handshake() {
    let pki = Pki::new(KeyKind::EcdsaP256, "server.test");
    let t = now();
    let sc = stapling_server(
        &pki,
        Some(pki.staple(CertStatus::Revoked { at: t - 100 }, t - 60, t + 3600)),
    );
    let err = connect(client(&pki, Revocation::IfStapled), sc, "server.test").unwrap_err();
    assert_eq!(
        err.client.map(|e| e.kind()),
        Some(ErrorKind::CertificateRevoked)
    );
    assert_eq!(
        err.server.and_then(|e| e.peer_alert()),
        Some(AlertDescription::CertificateRevoked)
    );
}

/// REQ-OCSP-005: RequireStaple fails without a good staple; IfStapled does not.
#[test]
fn require_staple_refuses_a_server_that_staples_nothing_or_unknown() {
    let pki = Pki::new(KeyKind::EcdsaP256, "server.test");
    let t = now();
    let bare = stapling_server(&pki, None);
    let err = connect(
        client(&pki, Revocation::RequireStaple),
        bare.clone(),
        "server.test",
    )
    .unwrap_err();
    assert_eq!(
        err.client.map(|e| e.kind()),
        Some(ErrorKind::BadCertificateStatus)
    );
    assert_eq!(
        err.server.and_then(|e| e.peer_alert()),
        Some(AlertDescription::BadCertificateStatusResponse)
    );
    let (c, _) = connect(client(&pki, Revocation::IfStapled), bare, "server.test").unwrap();
    assert_eq!(c.report().revocation, "revocation:not-checked");
    assert!(!c.report().has(Property::RevocationChecked));

    let unknown = stapling_server(
        &pki,
        Some(pki.staple(CertStatus::Unknown, t - 60, t + 3600)),
    );
    let err = connect(
        client(&pki, Revocation::RequireStaple),
        unknown.clone(),
        "server.test",
    )
    .unwrap_err();
    assert_eq!(
        err.client.map(|e| e.kind()),
        Some(ErrorKind::BadCertificateStatus)
    );
    let (c, _) = connect(client(&pki, Revocation::IfStapled), unknown, "server.test").unwrap();
    assert_eq!(c.report().revocation, "revocation:unknown");
}

/// REQ-OCSP-002: a stale staple is not treated as absent.
#[test]
fn a_stale_staple_fails_even_when_stapling_is_optional() {
    let pki = Pki::new(KeyKind::EcdsaP256, "server.test");
    let t = now();
    let sc = stapling_server(&pki, Some(pki.staple(CertStatus::Good, t - 7200, t - 3600)));
    let err = connect(client(&pki, Revocation::IfStapled), sc, "server.test").unwrap_err();
    assert_eq!(
        err.client.map(|e| e.kind()),
        Some(ErrorKind::BadCertificateStatus)
    );
}

/// REQ-OCSP-001: a staple from another CA does not vouch for this certificate.
#[test]
fn a_staple_from_another_issuer_fails() {
    let pki = Pki::new(KeyKind::EcdsaP256, "server.test");
    let other = Pki::new(KeyKind::EcdsaP256, "server.test");
    let t = now();
    let sc = stapling_server(&pki, Some(other.staple(CertStatus::Good, t - 60, t + 3600)));
    let err = connect(client(&pki, Revocation::IfStapled), sc, "server.test").unwrap_err();
    assert_eq!(
        err.client.map(|e| e.kind()),
        Some(ErrorKind::BadCertificateStatus)
    );
}

#[test]
fn nothing_is_stapled_unless_asked_and_resumption_keeps_the_status() {
    let pki = Pki::new(KeyKind::EcdsaP256, "server.test");
    let t = now();
    let sc = stapling_server(&pki, Some(pki.staple(CertStatus::Good, t - 60, t + 3600)));
    let (_, s) = connect(client(&pki, Revocation::Off), sc.clone(), "server.test").unwrap();
    assert!(!s
        .report()
        .events
        .iter()
        .any(|e| e.id == "event:ocsp-stapled"));
    let cc = client(&pki, Revocation::IfStapled);
    let (mut c, mut s) = connect(cc.clone(), sc.clone(), "server.test").unwrap();
    let tickets = s.take_tls();
    c.read_tls(&tickets).unwrap();
    let (c, _) = connect(cc, sc, "server.test").unwrap();
    assert!(c.report().resumed);
    assert_eq!(c.report().revocation, "revocation:good");
    assert!(c.report().has(Property::RevocationChecked));
}
