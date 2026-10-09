//! What the CNSA profiles refuse beyond their algorithm lists: RFC 9151 for
//! `profile:cnsa-1`, draft-becker-cnsa2-tls-profile-05 for `profile:cnsa-2`.
//!
//! Approved mode is process-global, so this is its own test binary, with the
//! module brought up first in its one test.

mod common;

use std::sync::Arc;

use common::*;
use ironsocketlayer::config::{
    ClientAuth, ClientConfig, EarlyDataPolicy, ExternalPsk, Identity, PeerVerification, Profile,
    ServerConfig,
};
use ironsocketlayer::crypto::sign::{KeyKind, SigningKey};
use ironsocketlayer::crypto::HashAlg;
use ironsocketlayer::report::Property;
use ironsocketlayer::x509::{self, CertificateParams};
use ironsocketlayer::ErrorKind;

fn psk() -> ExternalPsk {
    ExternalPsk::new(b"sensor-17", &[0x42; 48], HashAlg::Sha384).unwrap()
}

/// A CA certificate with an RSA key of `bits`, which nothing on a path
/// needs: it only rides along in a Certificate message.
fn stray_rsa_certificate(bits: usize) -> Vec<u8> {
    let mut rng = ic_drbg::Rng::from_os().unwrap();
    let key = SigningKey::rsa(ic_rsa::generate(bits, &mut rng).unwrap()).unwrap();
    x509::self_signed(
        &CertificateParams {
            subject_cn: "Stray RSA CA",
            dns_names: &[],
            ip_addresses: &[],
            not_before: now() - 3600,
            not_after: now() + 3600,
            is_ca: true,
            path_len: None,
            usage: &[],
            serial: [7; 16],
        },
        &key,
        &mut rng,
    )
    .unwrap()
}

#[test]
fn the_cnsa_profiles_refuse_what_their_tls_profiles_forbid() {
    ironsocketlayer::policy::enable_fips().unwrap();
    let pki = Pki::with_kinds(KeyKind::EcdsaP384, KeyKind::EcdsaP384, "server.test");
    let pq = Pki::with_kinds(KeyKind::MlDsa87, KeyKind::MlDsa87, "server.test");

    // REQ-CFG-007: neither profile validates with early data or with an
    // external PSK standing in for certificates (RFC 9151 sections 7.3 and
    // 4.2; the CNSA 2.0 draft, sections 12 and 9). Without either, both do.
    for (profile, p) in [(Profile::Cnsa1, &pki), (Profile::Cnsa2, &pq)] {
        p.client_config(profile).validate().unwrap();
        p.server_config(profile).validate().unwrap();

        let mut c = p.client_config(profile);
        c.early_data = true;
        let e = c.validate().unwrap_err();
        assert_eq!(e.kind(), ErrorKind::InvalidConfig, "{profile:?}");
        assert_eq!(e.context(), "the CNSA profiles forbid early data");

        let mut s = p.server_config(profile);
        s.early_data = Some(EarlyDataPolicy::new(1024));
        let e = s.validate().unwrap_err();
        assert_eq!(e.kind(), ErrorKind::InvalidConfig, "{profile:?}");
        assert_eq!(e.context(), "the CNSA profiles forbid early data");

        let mut c = p.client_config(profile);
        c.external_psk = Some(psk());
        let e = c.validate().unwrap_err();
        assert_eq!(e.kind(), ErrorKind::InvalidConfig, "{profile:?}");
        assert!(e.context().contains("external PSK"), "{}", e.context());

        let mut s = p.server_config(profile);
        s.external_psks = vec![psk()];
        let e = s.validate().unwrap_err();
        assert_eq!(e.kind(), ErrorKind::InvalidConfig, "{profile:?}");
        assert!(e.context().contains("external PSK"), "{}", e.context());

        let e = ClientConfig::external_psk(profile, psk())
            .unwrap()
            .validate()
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::InvalidConfig, "{profile:?}");
        let e = ServerConfig::external_psk_only(profile, vec![psk()])
            .unwrap()
            .validate()
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::InvalidConfig, "{profile:?}");
    }
    // The refusal is the profile's: the same settings validate elsewhere.
    let mut c = pki.client_config(Profile::Fips140_3);
    c.early_data = true;
    c.validate().unwrap();
    let mut s = pki.server_config(Profile::Fips140_3);
    s.early_data = Some(EarlyDataPolicy::new(1024));
    s.external_psks = vec![psk()];
    s.validate().unwrap();

    // REQ-CFG-008: under CNSA 1.0 an RSA key on a peer's chain must be 3072
    // or 4096 bits (RFC 9151 section 5.2). A 2048-bit RSA certificate that
    // path validation never needs is enough to refuse the peer, as a server
    // and as a client; a 3072-bit one is not, and neither is the 2048-bit
    // one under another profile.
    let small = stray_rsa_certificate(2048);
    let large = stray_rsa_certificate(3072);
    let server_with = |extra: &[u8], profile| {
        let mut chain = pki.server_chain.clone();
        chain.push(extra.to_vec());
        let id = Identity {
            chain,
            ..pki.server_identity()
        };
        Arc::new(ServerConfig::new(profile, id).unwrap())
    };
    let f = connect(
        Arc::new(pki.client_config(Profile::Cnsa1)),
        server_with(&small, Profile::Cnsa1),
        "server.test",
    )
    .expect_err("a 2048-bit RSA key on the server's chain");
    let e = f.client.unwrap();
    assert_eq!(e.kind(), ErrorKind::PolicyViolation);
    assert_eq!(
        e.context(),
        "CNSA 1.0 allows RSA moduli of 3072 or 4096 bits only"
    );
    connect(
        Arc::new(pki.client_config(Profile::Cnsa1)),
        server_with(&large, Profile::Cnsa1),
        "server.test",
    )
    .map_err(|f| f.client)
    .unwrap();
    connect(
        Arc::new(pki.client_config(Profile::Fips140_3)),
        server_with(&small, Profile::Fips140_3),
        "server.test",
    )
    .map_err(|f| f.client)
    .unwrap();

    // The same rule for a client's chain, at the server.
    let client_with = |extra: &[u8]| {
        let mut id = pki.client_identity(KeyKind::EcdsaP384, "agent");
        id.chain.push(extra.to_vec());
        Arc::new(pki.client_config(Profile::Cnsa1).with_identity(id))
    };
    let server = Arc::new(
        pki.server_config(Profile::Cnsa1)
            .with_client_auth(ClientAuth::Required(PeerVerification::Roots(pki.roots()))),
    );
    let f = connect(client_with(&small), server.clone(), "server.test")
        .expect_err("a 2048-bit RSA key on the client's chain");
    assert_eq!(f.server.unwrap().kind(), ErrorKind::PolicyViolation);
    connect(client_with(&large), server, "server.test")
        .map_err(|f| f.server)
        .unwrap();

    // And for a chain the server asks for after the handshake.
    for (extra, accepted) in [(&small, false), (&large, true)] {
        let mut id = pki.client_identity(KeyKind::EcdsaP384, "agent");
        id.chain.push(extra.clone());
        let mut cc = pki.client_config(Profile::Cnsa1).with_identity(id);
        cc.post_handshake_auth = true;
        let sc = pki
            .server_config(Profile::Cnsa1)
            .with_client_auth(ClientAuth::OnDemand(PeerVerification::Roots(pki.roots())));
        let (mut c, mut s) = connect(Arc::new(cc), Arc::new(sc), "server.test")
            .map_err(|f| f.client)
            .unwrap();
        s.request_client_auth().unwrap();
        let mut outcome = Ok(());
        for _ in 0..3 {
            let to_client = s.take_tls();
            let _ = c.read_tls(&to_client);
            let to_server = c.take_tls();
            if let Err(e) = s.read_tls(&to_server) {
                outcome = Err(e);
                break;
            }
        }
        if accepted {
            outcome.unwrap();
            assert!(s.report().has(Property::MutualAuthentication));
        } else {
            assert_eq!(outcome.unwrap_err().kind(), ErrorKind::PolicyViolation);
        }
    }
}
