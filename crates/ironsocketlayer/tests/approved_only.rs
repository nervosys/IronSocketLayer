//! A build with IronCrypto's `--cfg ic_approved_only`, in `RUSTFLAGS` and
//! `RUSTDOCFLAGS`. IronCrypto then leaves out every algorithm FIPS approved
//! mode does not permit; this crate follows it. The profiles that name one
//! are unavailable and refused, never narrowed (`REQ-APPR-001`); the
//! excluded suites, groups and schemes are not implemented, and a
//! configuration that names one is refused (`REQ-APPR-002`); ECH, which needs
//! HPKE, is refused, and GREASE is still sent (`REQ-APPR-003`).
//!
//! In this build IronCrypto refuses service until its self-tests have run,
//! so every test brings the module up first, as an application must.
//!
//! None of this makes anything FIPS 140-3 validated.
//!
//! `scripts/approved-only.sh` runs this file; in the default build it is
//! empty.

#![cfg(ic_approved_only)]

mod common;

use std::sync::Arc;

use common::*;
use ironsocketlayer::config::{
    ClientAuth, ClientConfig, IntentPolicy, PeerVerification, Profile, ServerConfig,
};
use ironsocketlayer::crypto::kx::IMPLEMENTED_GROUPS;
use ironsocketlayer::crypto::sign::{KeyKind, SigningKey, VERIFY_SCHEMES};
use ironsocketlayer::enums::{CipherSuite, NamedGroup, SignatureScheme};
use ironsocketlayer::record::IMPLEMENTED_SUITES;
use ironsocketlayer::report::Property;
use ironsocketlayer::x509::crl::CrlStore;
use ironsocketlayer::ErrorKind;
use isl_ontology::{ImplStatus, ProfileStatus};

fn up() {
    ironsocketlayer::policy::enable_fips().unwrap();
}

fn invalid(r: Result<impl core::fmt::Debug, ironsocketlayer::Error>, what: &str) {
    let e = r.expect_err(what);
    assert_eq!(e.kind(), ErrorKind::InvalidConfig, "{what}: {e}");
}

/// REQ-APPR-001: the default and post-quantum profiles name X25519,
/// Ed25519 and ChaCha20-Poly1305; they are refused whole, offer nothing,
/// and the selector does not recommend another in their place.
#[test]
fn profiles_that_need_an_excluded_algorithm_are_refused_not_narrowed() {
    up();
    let pki = Pki::new(KeyKind::EcdsaP256, "server.test");
    for p in [Profile::Default, Profile::PostQuantum] {
        assert!(!p.available(), "{p:?}");
        assert!(p.suites().is_empty() && p.groups().is_empty() && p.schemes().is_empty());
        invalid(ClientConfig::new(p, pki.roots()), p.id());
        invalid(ServerConfig::new(p, pki.server_identity()), p.id());
        let entry = isl_ontology::profiles::get(p.id()).unwrap();
        assert_eq!(entry.status, ProfileStatus::Unavailable, "{}", p.id());
        assert!(entry.status_reason.contains("ic_approved_only"));
    }
    for p in [
        Profile::Fips140_3,
        Profile::Cnsa1,
        Profile::Cnsa2,
        Profile::DalA,
    ] {
        assert!(p.available(), "{p:?}");
        assert!(!p.suites().is_empty());
    }

    // An intent whose profile is unavailable is an error, not a substitute.
    let none = IntentPolicy::default();
    invalid(
        ClientConfig::for_intent("intent:https-client", &none, pki.roots()),
        "https-client",
    );
    invalid(
        ClientConfig::for_intent("intent:harvest-now-decrypt-later", &none, pki.roots()),
        "harvest-now-decrypt-later",
    );
    assert!(matches!(
        isl_ontology::select::recommend("intent:https-client", &none),
        Err(isl_ontology::select::NoRecommendation::Unavailable { .. })
    ));
    // Asked for FIPS, the same intent gets the FIPS profile, as it does in
    // every build.
    let fips = IntentPolicy {
        require_fips: true,
        ..IntentPolicy::default()
    };
    let c = ClientConfig::for_intent("intent:https-client", &fips, pki.roots()).unwrap();
    assert_eq!(c.common.profile, Profile::Fips140_3);
    c.validate().unwrap();
}

/// REQ-APPR-002: ChaCha20-Poly1305, X25519, X25519MLKEM768 and Ed25519 are
/// not implemented, and naming one in a configuration, or loading or making
/// an Ed25519 key, is `error:invalid-config`.
#[test]
fn excluded_algorithms_are_not_implemented_and_are_refused() {
    up();
    assert!(!IMPLEMENTED_SUITES.contains(&CipherSuite::TlsChaCha20Poly1305Sha256));
    assert!(!IMPLEMENTED_GROUPS.contains(&NamedGroup::X25519));
    assert!(!IMPLEMENTED_GROUPS.contains(&NamedGroup::X25519MlKem768));
    assert!(!VERIFY_SCHEMES.contains(&SignatureScheme::Ed25519));
    for id in [
        "suite:tls-chacha20-poly1305-sha256",
        "group:x25519",
        "group:x25519mlkem768",
        "sigscheme:ed25519",
        "ext:encrypted-client-hello",
    ] {
        let e = isl_ontology::get(id).unwrap();
        assert_eq!(e.status, ImplStatus::Excluded, "{id}");
        assert!(e.status_reason.contains("ic_approved_only"), "{id}");
    }

    let pki = Pki::new(KeyKind::EcdsaP256, "server.test");
    let mut c = pki.client_config(Profile::Fips140_3);
    c.common.suites.push(CipherSuite::TlsChaCha20Poly1305Sha256);
    invalid(c.validate(), "ChaCha20-Poly1305");
    for g in [NamedGroup::X25519, NamedGroup::X25519MlKem768] {
        let mut c = pki.client_config(Profile::Fips140_3);
        c.common.groups.push(g);
        invalid(c.validate(), g.id());
        let mut s = pki.server_config(Profile::Fips140_3);
        s.common.groups.push(g);
        invalid(s.validate(), g.id());
    }
    let mut c = pki.client_config(Profile::Fips140_3);
    c.common.schemes.push(SignatureScheme::Ed25519);
    invalid(c.validate(), "Ed25519 scheme");

    invalid(SigningKey::ed25519(&[7; 32]), "Ed25519 seed");
    invalid(
        SigningKey::generate(KeyKind::Ed25519, &mut ic_drbg::Rng::from_os().unwrap()),
        "Ed25519 generation",
    );
    // RFC 8410 section 10.3: an Ed25519 private key.
    let pkcs8 = [
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
        0x20, 0xd4, 0xee, 0x72, 0xdb, 0xf9, 0x13, 0x58, 0x4a, 0xd5, 0xb6, 0xd8, 0xf1, 0xf7, 0x69,
        0xf8, 0xad, 0x3a, 0xfe, 0x7c, 0x28, 0xcb, 0xf1, 0xd4, 0xfb, 0xe0, 0x97, 0xa8, 0x8f, 0x44,
        0x75, 0x58, 0x42,
    ];
    invalid(SigningKey::from_pkcs8_der(&pkcs8), "Ed25519 PKCS#8");
}

/// The extension types in a ClientHello flight.
fn client_hello_extensions(flight: &[u8]) -> Vec<u16> {
    let u16_at = |i: usize| u16::from_be_bytes([flight[i], flight[i + 1]]);
    // Record header (5), handshake header (4), version (2), random (32).
    let mut i = 5 + 4 + 2 + 32;
    i += 1 + usize::from(flight[i]); // session id
    i += 2 + usize::from(u16_at(i)); // cipher suites
    i += 1 + usize::from(flight[i]); // compression methods
    let end = i + 2 + usize::from(u16_at(i));
    i += 2;
    let mut out = Vec::new();
    while i < end {
        out.push(u16_at(i));
        i += 4 + usize::from(u16_at(i + 2));
    }
    out
}

/// REQ-APPR-003: no HPKE, so no ECH: a client configuration with
/// `ech_configs` is refused before any connection, and no ECH server key
/// can be made. A GREASE extension, random bytes, is still sent, so the
/// client does not stand out.
#[test]
fn ech_is_refused_and_grease_is_still_sent() {
    up();
    let pki = Pki::new(KeyKind::EcdsaP256, "server.test");
    let mut c = pki.client_config(Profile::Fips140_3);
    c.ech_configs = Some(vec![0; 64]);
    invalid(c.validate(), "ech_configs");
    invalid(
        ironsocketlayer::ech::EchServer::generate(
            1,
            "public.test",
            0,
            &mut ic_drbg::Rng::from_os().unwrap(),
        ),
        "ECH server key",
    );

    let c = pki.client_config(Profile::Fips140_3);
    assert!(c.ech_grease && c.relaxations().is_empty());
    let mut conn = ironsocketlayer::Connection::client(Arc::new(c), "server.test").unwrap();
    assert!(client_hello_extensions(&conn.take_tls()).contains(&0xfe0d));
}

/// REQ-APPR-001: the profiles that remain work. Each completes a handshake
/// and carries data, and the report says what was used.
#[test]
fn the_approved_profiles_complete_handshakes() {
    up();
    for (profile, kind) in [
        (Profile::Fips140_3, KeyKind::EcdsaP256),
        (Profile::Cnsa1, KeyKind::EcdsaP384),
        (Profile::Cnsa2, KeyKind::MlDsa87),
    ] {
        let pki = Pki::with_kinds(kind, kind, "server.test");
        let (mut c, mut s) = connect(
            Arc::new(pki.client_config(profile)),
            Arc::new(pki.server_config(profile)),
            "server.test",
        )
        .unwrap_or_else(|f| panic!("{profile:?}: {f:?}"));
        exchange(&mut c, &mut s);
        let r = c.report();
        assert!(r.has(Property::FipsApprovedAlgorithms), "{}", r.to_json());
        assert!(r.has(Property::ServerAuthenticated));
        assert!(r.to_json().contains(r#""validated":false"#));
    }

    // DAL-A: mutual authentication, P-384.
    let pki = Pki::with_kinds(KeyKind::EcdsaP384, KeyKind::EcdsaP384, "server.test");
    let client = pki
        .client_config(Profile::DalA)
        .with_identity(pki.client_identity(KeyKind::EcdsaP384, "client"));
    let server = pki
        .server_config(Profile::DalA)
        .with_client_auth(ClientAuth::Required(PeerVerification::Roots(pki.roots())));
    let (mut c, mut s) = connect(Arc::new(client), Arc::new(server), "server.test").unwrap();
    exchange(&mut c, &mut s);
    assert!(c.report().has(Property::MutualAuthentication));
    assert!(s.report().has(Property::MutualAuthentication));
}

/// REQ-APPR-001: the FIPS 140-3 profile narrowed by the caller, as a
/// deployment that wants one parameter set does: AES-256-GCM,
/// SecP256r1MLKEM768 only, ECDSA P-256, mutual authentication, CRLs on
/// both sides. Narrowing is the caller's choice; the library never narrows
/// on its own.
#[test]
fn a_narrowed_fips_configuration_with_mutual_authentication_and_crls() {
    up();
    let pki = Pki::with_kinds(KeyKind::EcdsaP256, KeyKind::EcdsaP256, "server.test");
    let crls = || {
        let mut store = CrlStore::new();
        store.add_der(&pki.crl(&[])).unwrap();
        Some(Arc::new(store))
    };
    let narrow = |c: &mut ironsocketlayer::config::Common| {
        c.suites = vec![CipherSuite::TlsAes256GcmSha384];
        c.groups = vec![NamedGroup::SecP256r1MlKem768];
        c.schemes = vec![SignatureScheme::EcdsaSecp256r1Sha256];
        c.require_crl = true;
    };
    let mut client = pki
        .client_config(Profile::Fips140_3)
        .with_identity(pki.client_identity(KeyKind::EcdsaP256, "client"))
        .require(&[
            Property::ServerAuthenticated,
            Property::MutualAuthentication,
            Property::PostQuantumKeyExchange,
            Property::FipsApprovedAlgorithms,
        ]);
    narrow(&mut client.common);
    client.common.crls = crls();
    let mut server = pki
        .server_config(Profile::Fips140_3)
        .with_client_auth(ClientAuth::Required(PeerVerification::Roots(pki.roots())));
    narrow(&mut server.common);
    server.common.crls = crls();

    let (mut c, mut s) = connect(Arc::new(client), Arc::new(server), "server.test")
        .unwrap_or_else(|f| panic!("{f:?}"));
    exchange(&mut c, &mut s);
    for r in [c.report(), s.report()] {
        assert_eq!(r.suite, Some(CipherSuite::TlsAes256GcmSha384));
        assert_eq!(r.group, Some(NamedGroup::SecP256r1MlKem768));
        assert!(r.has(Property::MutualAuthentication), "{}", r.to_json());
        assert!(r.has(Property::PostQuantumKeyExchange));
        assert!(r.has(Property::FipsApprovedAlgorithms));
        assert!(r.has(Property::RevocationChecked), "{}", r.to_json());
    }
}
