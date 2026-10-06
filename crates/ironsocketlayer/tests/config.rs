//! Every configuration rule refuses its case, with `invalid_config` and a
//! message saying which rule. An agent that assembles a configuration by hand
//! learns what it got wrong from these messages, so each is pinned here.
//! `REQ-CFG-002`.

mod common;

use std::sync::Arc;

use common::*;
use ironsocketlayer::config::{describe_identity, ClientConfig, ExternalPsk, Identity, Profile};
use ironsocketlayer::crypto::sign::{KeyKind, SigningKey};
use ironsocketlayer::crypto::HashAlg;
use ironsocketlayer::enums::{CipherSuite, NamedGroup, SignatureScheme};
use ironsocketlayer::x509::RootStore;
use ironsocketlayer::{Connection, ErrorKind};

fn refused(r: ironsocketlayer::Result<()>, expect: &str) {
    let e = r.expect_err(expect);
    assert_eq!(e.kind(), ErrorKind::InvalidConfig, "{expect}: {e}");
    assert!(e.to_string().contains(expect), "wanted {expect:?}, got {e}");
}

#[test]
fn every_common_rule_refuses_its_case() {
    let pki = Pki::new(KeyKind::EcdsaP256, "server.test");
    let base = || pki.client_config(Profile::Default);
    type Edit = fn(&mut ClientConfig);
    let cases: &[(Edit, &str)] = &[
        (|c| c.common.suites.clear(), "no suites, groups or schemes"),
        (|c| c.common.groups.clear(), "no suites, groups or schemes"),
        (|c| c.common.schemes.clear(), "no suites, groups or schemes"),
        (
            |c| c.common.groups.push(NamedGroup::X448),
            "a configured group is not implemented",
        ),
        (
            |c| c.common.groups.push(NamedGroup::Ffdhe2048),
            "a configured group is not implemented",
        ),
        (
            |c| c.common.schemes = vec![SignatureScheme::RsaPkcs1Sha256],
            "no scheme may sign a TLS 1.3 handshake",
        ),
        (
            |c| c.common.alpn = vec![vec![]],
            "ALPN names must be 1..=255 bytes",
        ),
        (
            |c| c.common.alpn = vec![vec![b'x'; 256]],
            "ALPN names must be 1..=255 bytes",
        ),
        (
            |c| c.common.record_size_limit = Some(63),
            "record_size_limit must be 64..=16385",
        ),
        (
            |c| c.common.record_size_limit = Some(16_386),
            "record_size_limit must be 64..=16385",
        ),
    ];
    for (edit, expect) in cases {
        let mut c = base();
        edit(&mut c);
        refused(c.validate(), expect);
        // Connection construction runs the same check.
        refused(
            Connection::client(Arc::new(c), "server.test").map(drop),
            expect,
        );
    }
    // The edges of the record_size_limit range are accepted.
    for ok in [64, 16_385] {
        let mut c = base();
        c.common.record_size_limit = Some(ok);
        c.validate().unwrap();
    }
}

#[test]
fn every_client_rule_refuses_its_case() {
    let pki = Pki::new(KeyKind::EcdsaP256, "server.test");
    refused(
        ClientConfig::new(Profile::Default, RootStore::new())
            .unwrap()
            .validate(),
        "no trust anchors: add roots or pin the server key",
    );
    let psk = || ExternalPsk::new(b"id", &[7; 32], HashAlg::Sha384).unwrap();
    let mut c = ClientConfig::external_psk(Profile::Default, psk()).unwrap();
    c.ech_configs = Some(vec![0; 8]);
    refused(c.validate(), "ECH and an external PSK cannot be combined");
    let mut c = ClientConfig::external_psk(Profile::Default, psk()).unwrap();
    c.common.suites = vec![CipherSuite::TlsAes128GcmSha256];
    refused(
        c.validate(),
        "no configured suite uses the external PSK's hash",
    );
    let _ = pki;
    // The DAL-A rules are in tests/fips.rs: that profile needs approved mode,
    // which is process-wide and so lives in its own test binary.
}

#[test]
fn every_server_rule_refuses_its_case() {
    let p256 = Pki::new(KeyKind::EcdsaP256, "server.test");
    let mut s = p256.server_config(Profile::Default);
    s.identities.clear();
    refused(
        s.validate(),
        "server has neither a certificate nor an external PSK",
    );
}

#[test]
fn an_identity_must_pair_a_parsable_chain_with_its_own_key() {
    let pki = Pki::new(KeyKind::EcdsaP256, "server.test");
    let key =
        || SigningKey::generate(KeyKind::EcdsaP256, &mut ic_drbg::Rng::from_os().unwrap()).unwrap();
    let e = Identity::new(vec![], key()).unwrap_err();
    assert!(e.to_string().contains("empty certificate chain"), "{e}");
    let e = Identity::new(vec![vec![0x30, 0x00]], key()).unwrap_err();
    assert!(e.to_string().contains("does not parse"), "{e}");
    let e = Identity::new(pki.server_identity().chain.clone(), key()).unwrap_err();
    assert!(e.to_string().contains("private key does not match"), "{e}");

    let id = pki.server_identity();
    assert_eq!(
        describe_identity(&id),
        format!("{} chain of 1", id.key.kind_id())
    );
    assert!(format!("{id:?}").starts_with("Identity(1 certs"));
}

#[test]
fn profiles_round_trip_through_their_ontology_ids() {
    for p in Profile::ALL {
        assert_eq!(Profile::from_id(p.id()), Some(*p));
    }
    assert_eq!(Profile::from_id("profile:no-such-thing"), None);
}
