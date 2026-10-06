//! Cross-layer agreement between the code and the ontology.
//!
//! These tests fail when `ironsocketlayer` and `isl_ontology` disagree about what
//! exists, what it is called, what code it has, whether it is implemented, or
//! what an error means. That failure is the point: fix the disagreement, never
//! relax the test.

use ironsocketlayer::crypto::{kx, sign};
use ironsocketlayer::enums::{
    AlertDescription, CipherSuite, ContentType, ExtensionType, HandshakeType, KeyUpdateRequest,
    NamedGroup, ProtocolVersion, SignatureScheme,
};
use ironsocketlayer::ErrorKind;
use isl_ontology::{Kind, Relation};

/// Cipher suites the record layer implements.
const IMPLEMENTED_SUITES: &[CipherSuite] = &[
    CipherSuite::TlsAes128GcmSha256,
    CipherSuite::TlsAes256GcmSha384,
    CipherSuite::TlsChaCha20Poly1305Sha256,
];

/// Extensions the handshake implements.
const IMPLEMENTED_EXTENSIONS: &[ExtensionType] = &[
    ExtensionType::ServerName,
    ExtensionType::SupportedGroups,
    ExtensionType::SignatureAlgorithms,
    ExtensionType::SignatureAlgorithmsCert,
    ExtensionType::ApplicationLayerProtocolNegotiation,
    ExtensionType::SupportedVersions,
    ExtensionType::KeyShare,
    ExtensionType::Cookie,
    ExtensionType::QuicTransportParameters,
    ExtensionType::PreSharedKey,
    ExtensionType::PskKeyExchangeModes,
    ExtensionType::StatusRequest,
    ExtensionType::RecordSizeLimit,
    ExtensionType::EncryptedClientHello,
    ExtensionType::EchOuterExtensions,
    ExtensionType::PostHandshakeAuth,
    ExtensionType::EarlyData,
];

fn check_kind<T: Copy + core::fmt::Debug>(
    kind: Kind,
    all: &[T],
    id: fn(T) -> &'static str,
    code: fn(T) -> u16,
) {
    for &v in all {
        let e = isl_ontology::get(id(v))
            .unwrap_or_else(|| panic!("{v:?} ({}) has no ontology entry", id(v)));
        assert_eq!(e.kind, kind, "{}", e.id);
        assert_eq!(e.code, code(v), "{}: wire code disagrees", e.id);
    }
    let n = isl_ontology::by_kind(kind).count();
    assert_eq!(
        n,
        all.len(),
        "{kind:?}: the ontology has {n} entries, the code names {}",
        all.len()
    );
}

#[test]
fn every_code_point_has_an_entry_with_its_wire_value() {
    check_kind(
        Kind::ProtocolVersion,
        ProtocolVersion::ALL,
        ProtocolVersion::id,
        ProtocolVersion::to_wire,
    );
    check_kind(Kind::ContentType, ContentType::ALL, ContentType::id, |v| {
        v.to_wire() as u16
    });
    check_kind(
        Kind::HandshakeMessage,
        HandshakeType::ALL,
        HandshakeType::id,
        |v| v.to_wire() as u16,
    );
    check_kind(
        Kind::CipherSuite,
        CipherSuite::ALL,
        CipherSuite::id,
        CipherSuite::to_wire,
    );
    check_kind(
        Kind::NamedGroup,
        NamedGroup::ALL,
        NamedGroup::id,
        NamedGroup::to_wire,
    );
    check_kind(
        Kind::SignatureScheme,
        SignatureScheme::ALL,
        SignatureScheme::id,
        SignatureScheme::to_wire,
    );
    check_kind(
        Kind::Extension,
        ExtensionType::ALL,
        ExtensionType::id,
        ExtensionType::to_wire,
    );
    check_kind(
        Kind::Alert,
        AlertDescription::ALL,
        AlertDescription::id,
        |v| v.to_wire() as u16,
    );
    check_kind(
        Kind::KeyUpdateRequest,
        KeyUpdateRequest::ALL,
        KeyUpdateRequest::id,
        |v| v.to_wire() as u16,
    );
}

fn check_implemented<T: Copy + PartialEq + core::fmt::Debug>(
    all: &[T],
    implemented: &[T],
    id: fn(T) -> &'static str,
) {
    for &v in all {
        let e = isl_ontology::get(id(v)).expect("entry");
        assert_eq!(
            e.implemented(),
            implemented.contains(&v),
            "{}: ontology says {}, code says {}",
            e.id,
            e.status.id(),
            if implemented.contains(&v) {
                "implemented"
            } else {
                "not implemented"
            }
        );
    }
}

#[test]
fn implemented_means_implemented() {
    check_implemented(CipherSuite::ALL, IMPLEMENTED_SUITES, CipherSuite::id);
    check_implemented(NamedGroup::ALL, kx::IMPLEMENTED_GROUPS, NamedGroup::id);
    check_implemented(
        SignatureScheme::ALL,
        sign::VERIFY_SCHEMES,
        SignatureScheme::id,
    );
    check_implemented(
        ExtensionType::ALL,
        IMPLEMENTED_EXTENSIONS,
        ExtensionType::id,
    );
    for &g in kx::IMPLEMENTED_GROUPS {
        let e = isl_ontology::get(g.id()).unwrap();
        assert_eq!(
            e.post_quantum,
            kx::is_post_quantum(g),
            "{}: post-quantum flag",
            e.id
        );
    }
}

#[test]
fn certificate_only_schemes_are_marked_so() {
    for &s in SignatureScheme::ALL {
        let e = isl_ontology::get(s.id()).unwrap();
        let cert_only = e
            .constraints
            .iter()
            .any(|c| c.id == "certificates-only" || c.id == "never-use");
        assert_eq!(cert_only, !s.allowed_in_handshake(), "{}", e.id);
    }
}

#[test]
fn every_error_kind_has_a_matching_catalog_entry() {
    for &k in ErrorKind::ALL {
        let d = isl_ontology::errors::get(k.id())
            .unwrap_or_else(|| panic!("{} missing from the catalog", k.id()));
        assert_eq!(d.retryable, k.retryable(), "{}: retryable", d.id);
        assert_eq!(
            d.caller_correctable,
            k.caller_correctable(),
            "{}: caller_correctable",
            d.id
        );
        assert_eq!(d.peer_fault, k.peer_fault(), "{}: peer_fault", d.id);
        assert_eq!(d.alert, k.alert().map(|a| a.id()), "{}: alert", d.id);
        // REQ-ERR-001.
        assert_eq!(d.action, k.recovery().id(), "{}: action", d.id);
    }
    assert_eq!(isl_ontology::errors::CATALOG.len(), ErrorKind::ALL.len());
}

#[test]
fn every_ironcrypto_edge_resolves_in_ironcrypto() {
    for e in isl_ontology::all() {
        for edge in e.edges {
            if let Some(ic) = edge.target.strip_prefix(isl_ontology::IC_PREFIX) {
                let target = ic_ontology::get(ic)
                    .unwrap_or_else(|| panic!("{} -> ic:{ic}: IronCrypto has no such entry", e.id));
                if e.implemented() && edge.relation == Relation::BuiltOn {
                    assert_eq!(
                        target.status,
                        ic_ontology::ImplStatus::Available,
                        "{} is implemented but built on ic:{ic}, which IronCrypto does not implement",
                        e.id
                    );
                }
            }
        }
    }
}

#[test]
fn the_code_uses_what_the_ontology_says_it_is_built_on() {
    // Groups: the IronCrypto ids kx reports equal the built-on edges.
    for &g in kx::IMPLEMENTED_GROUPS {
        let e = isl_ontology::get(g.id()).unwrap();
        let mut edges: Vec<&str> = e
            .edges
            .iter()
            .filter(|x| x.relation == Relation::BuiltOn)
            .filter_map(|x| x.target.strip_prefix("ic:"))
            .collect();
        let mut code: Vec<&str> = kx::ic_ids(g).to_vec();
        edges.sort_unstable();
        code.sort_unstable();
        assert_eq!(edges, code, "{}", e.id);
    }
    for &s in sign::VERIFY_SCHEMES {
        let e = isl_ontology::get(s.id()).unwrap();
        let ic = sign::ic_id(s).unwrap();
        assert!(
            e.edges.iter().any(
                |x| x.relation == Relation::BuiltOn && x.target.strip_prefix("ic:") == Some(ic)
            ),
            "{} does not declare built-on ic:{ic}",
            e.id
        );
    }
}

#[test]
fn fips_status_follows_ironcrypto() {
    // An entry is approved exactly when every IronCrypto primitive it is built
    // on is approved (or allowed as a component) in IronCrypto's registry.
    for e in isl_ontology::all().filter(|e| e.implemented()) {
        let ic: Vec<&str> = e
            .edges
            .iter()
            .filter(|x| x.relation == Relation::BuiltOn)
            .filter_map(|x| x.target.strip_prefix("ic:"))
            .collect();
        if ic.is_empty() {
            continue;
        }
        let all_approved = ic.iter().all(|id| {
            ic_ontology::get(id)
                .map(|t| t.fips.permitted_in_approved_mode())
                .unwrap_or(false)
        });
        assert_eq!(
            e.fips == isl_ontology::FipsStatus::Approved,
            all_approved,
            "{}: FIPS status disagrees with IronCrypto",
            e.id
        );
    }
}

#[test]
fn profiles_name_only_known_code_points() {
    for p in isl_ontology::PROFILES {
        for id in p.suites {
            assert!(CipherSuite::from_id(id).is_some(), "{} {id}", p.id);
        }
        for id in p.groups {
            assert!(NamedGroup::from_id(id).is_some(), "{} {id}", p.id);
        }
        for id in p.sigschemes {
            assert!(SignatureScheme::from_id(id).is_some(), "{} {id}", p.id);
        }
    }
}

/// REQ-CFG-001: every profile the code builds uses exactly the suites, groups
/// and schemes -- in the same order -- that its ontology entry declares, and
/// agrees on mutual authentication, the FIPS gate and the RSA floor. An agent
/// that reads `profile:fips-140-3` must get precisely what the config builds.
#[test]
fn config_profiles_are_the_ontology_profiles() {
    use ironsocketlayer::config::Profile;
    for &p in Profile::ALL {
        let entry =
            isl_ontology::profiles::get(p.id()).unwrap_or_else(|| panic!("{} missing", p.id()));
        let ids = |v: Vec<&'static str>| v;
        if p.available() {
            assert_eq!(
                ids(p.suites().iter().map(|s| s.id()).collect()),
                entry.suites,
                "{} suites",
                p.id()
            );
            assert_eq!(
                ids(p.groups().iter().map(|s| s.id()).collect()),
                entry.groups,
                "{} groups",
                p.id()
            );
            assert_eq!(
                ids(p.schemes().iter().map(|s| s.id()).collect()),
                entry.sigschemes,
                "{} schemes",
                p.id()
            );
            assert_eq!(
                p.min_rsa_bits(),
                usize::from(entry.min_rsa_bits),
                "{} rsa floor",
                p.id()
            );
        } else {
            assert!(
                p.suites().is_empty() && p.groups().is_empty(),
                "an unavailable profile must offer nothing"
            );
        }
        assert_eq!(
            p.requires_mutual_auth(),
            entry.mutual_auth_required,
            "{} mutual",
            p.id()
        );
        assert_eq!(p.requires_fips(), entry.fips_gate, "{} fips gate", p.id());
        assert_eq!(
            p.available(),
            entry.status == isl_ontology::ProfileStatus::Available,
            "{} status",
            p.id()
        );
    }
    assert_eq!(Profile::ALL.len(), isl_ontology::profiles::PROFILES.len());
}

/// Every handshake state and security property the report can carry is
/// named in the vocabulary an agent reads, with a stable, prefixed id.
#[test]
fn report_vocabulary_is_stable() {
    use ironsocketlayer::report::{HandshakeState, Property};
    for s in HandshakeState::ALL {
        assert!(s.id().starts_with("state:"));
    }
    for p in Property::ALL {
        assert!(p.id().starts_with("property:"));
    }
}
