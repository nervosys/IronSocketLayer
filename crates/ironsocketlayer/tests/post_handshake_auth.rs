//! Post-handshake client authentication (RFC 8446 §4.6.2): step-up auth.

mod common;

use std::sync::Arc;

use common::*;
use ironsocketlayer::config::{ClientAuth, ClientConfig, PeerVerification, Profile, ServerConfig};
use ironsocketlayer::crypto::sign::KeyKind;
use ironsocketlayer::enums::SignatureScheme;
use ironsocketlayer::report::Property;
use ironsocketlayer::x509::{crl::CrlStore, Certificate};
use ironsocketlayer::{Connection, ErrorKind};

fn pump(c: &mut Connection, s: &mut Connection) -> Result<(), ironsocketlayer::Error> {
    for _ in 0..3 {
        let to_c = s.take_tls();
        if !to_c.is_empty() {
            c.read_tls(&to_c)?;
        }
        let to_s = c.take_tls();
        if !to_s.is_empty() {
            s.read_tls(&to_s)?;
        }
    }
    Ok(())
}

fn configs(pki: &Pki, kind: KeyKind) -> (ClientConfig, ServerConfig) {
    let mut cc = pki
        .client_config(Profile::Default)
        .with_identity(pki.client_identity(kind, "agent-7"));
    cc.post_handshake_auth = true;
    let sc = pki
        .server_config(Profile::Default)
        .with_client_auth(ClientAuth::OnDemand(PeerVerification::Roots(pki.roots())));
    (cc, sc)
}

/// REQ-PHA-001..003: the server asks mid-session; the agent proves its
/// identity; the session carries on.
#[test]
fn step_up_authentication_mid_session() {
    let pki = Pki::new(KeyKind::EcdsaP256, "server.test");
    let (cc, sc) = configs(&pki, KeyKind::EcdsaP384);
    let (mut c, mut s) = connect(Arc::new(cc), Arc::new(sc), "server.test").unwrap();
    assert!(
        !s.report().has(Property::MutualAuthentication),
        "no certificate before it is asked for"
    );
    exchange(&mut c, &mut s);
    s.request_client_auth().unwrap();
    assert_eq!(
        s.request_client_auth().unwrap_err().kind(),
        ErrorKind::InvalidState,
        "two outstanding requests"
    );
    pump(&mut c, &mut s).unwrap();
    assert!(
        s.report().has(Property::MutualAuthentication),
        "{}",
        s.report().to_json()
    );
    assert_eq!(s.report().peer_subject_cn.as_deref(), Some("agent-7"));
    assert_eq!(
        s.report().peer_signature_scheme,
        Some(SignatureScheme::EcdsaSecp384r1Sha384)
    );
    assert!(c.report().has(Property::MutualAuthentication));
    exchange(&mut c, &mut s);
    // It can be asked again.
    s.request_client_auth().unwrap();
    pump(&mut c, &mut s).unwrap();
    assert_eq!(
        s.report()
            .events
            .iter()
            .filter(|e| e.id == "event:post-handshake-auth")
            .count(),
        2
    );
}

/// REQ-PHA-001: only a client that offered it is asked, and only a client
/// that offered it answers.
#[test]
fn a_client_that_did_not_offer_cannot_be_asked() {
    let pki = Pki::new(KeyKind::EcdsaP256, "server.test");
    let (mut cc, sc) = configs(&pki, KeyKind::EcdsaP256);
    cc.post_handshake_auth = false;
    let (_, mut s) = connect(Arc::new(cc), Arc::new(sc), "server.test").unwrap();
    assert_eq!(
        s.request_client_auth().unwrap_err().kind(),
        ErrorKind::InvalidState
    );
    let (cc, _) = configs(&pki, KeyKind::EcdsaP256);
    let (_, mut s) = connect(
        Arc::new(cc),
        Arc::new(pki.server_config(Profile::Default)),
        "server.test",
    )
    .unwrap();
    assert_eq!(
        s.request_client_auth().unwrap_err().kind(),
        ErrorKind::InvalidConfig
    );
}

/// REQ-PHA-004: a client with no acceptable identity declines, and that
/// grants nothing.
#[test]
fn a_declined_request_grants_nothing() {
    let pki = Pki::new(KeyKind::EcdsaP256, "server.test");
    let (cc, mut sc) = configs(&pki, KeyKind::Ed25519);
    sc.common.schemes.retain(|s| *s != SignatureScheme::Ed25519);
    let (mut c, mut s) = connect(Arc::new(cc), Arc::new(sc), "server.test").unwrap();
    s.request_client_auth().unwrap();
    pump(&mut c, &mut s).unwrap();
    assert!(!s.report().has(Property::MutualAuthentication));
    assert!(s
        .report()
        .events
        .iter()
        .any(|e| e.id == "event:post-handshake-auth" && e.detail == "declined"));
    exchange(&mut c, &mut s);
}

/// Step-up authentication applies the full verification, CRLs included.
#[test]
fn a_revoked_agent_fails_step_up() {
    let pki = Pki::new(KeyKind::EcdsaP256, "server.test");
    let (cc, mut sc) = configs(&pki, KeyKind::EcdsaP256);
    let leaf = cc.identity.as_ref().unwrap().chain[0].clone();
    let serial = Certificate::parse(&leaf).unwrap().serial().to_vec();
    let mut crls = CrlStore::new();
    crls.add_der(&pki.crl(&[&serial])).unwrap();
    sc.common.crls = Some(Arc::new(crls));
    let (mut c, mut s) = connect(Arc::new(cc), Arc::new(sc), "server.test").unwrap();
    s.request_client_auth().unwrap();
    let err = pump(&mut c, &mut s).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::CertificateRevoked);
}

#[test]
fn quic_never_offers_post_handshake_auth() {
    let pki = Pki::new(KeyKind::EcdsaP256, "server.test");
    let (cc, _) = configs(&pki, KeyKind::EcdsaP256);
    let cc = Arc::new(cc.with_alpn(&[b"h3"]));
    let mut q = ironsocketlayer::quic::QuicConnection::client(
        cc.clone(),
        "server.test",
        b"p",
        ironsocketlayer::quic::Version::V1,
    )
    .unwrap();
    let (_, hello) = q.write_handshake().unwrap();
    assert!(
        !ironsocketlayer::msgs::ClientHello::decode(&hello[4..])
            .unwrap()
            .post_handshake_auth
    );
    let mut t = Connection::client(cc, "server.test").unwrap();
    let hello = t.take_tls();
    assert!(
        ironsocketlayer::msgs::ClientHello::decode(&hello[9..])
            .unwrap()
            .post_handshake_auth
    );
}
