//! Features that make the safe path the default for agents: requirements
//! the library enforces rather than the caller checking afterwards.

mod common;
mod fixed_support;

use std::sync::Arc;

use common::*;
use fixed_support::Buffers;
use ironsocketlayer::config::{ClientAuth, EarlyDataPolicy, PeerVerification, Profile};
use ironsocketlayer::crypto::sign::KeyKind;
use ironsocketlayer::enums::{AlertDescription, NamedGroup};
use ironsocketlayer::fixed;
use ironsocketlayer::report::{HandshakeState, Property};
use ironsocketlayer::{Connection, ErrorKind};

const NAME: &str = "server.test";

/// REQ-CONN-013: a client that requires post-quantum key exchange fails the
/// handshake, before it sends its Finished or any data, when the server
/// negotiates a classical group; with a hybrid group it connects.
#[test]
fn a_client_requirement_fails_the_handshake_before_any_data() {
    let pki = Pki::new(KeyKind::EcdsaP256, NAME);
    let cc = Arc::new(
        pki.client_config(Profile::Default)
            .require(&[Property::PostQuantumKeyExchange]),
    );
    let mut classical = pki.server_config(Profile::Default);
    classical.common.groups = vec![NamedGroup::X25519];
    let failure = connect(cc.clone(), Arc::new(classical), NAME).unwrap_err();
    let e = failure.client.expect("the client refused");
    assert_eq!(e.kind(), ErrorKind::PolicyViolation, "{e}");
    assert_eq!(e.context(), "property:post-quantum-key-exchange");
    // The server never saw a client Finished.
    let s = failure.server.expect("the server heard the alert");
    assert_eq!(s.peer_alert(), Some(AlertDescription::InsufficientSecurity));

    // Step by step: once the client has failed it has nothing to send and
    // cannot send.
    let mut classical = pki.server_config(Profile::Default);
    classical.common.groups = vec![NamedGroup::X25519];
    let mut c = Connection::client(cc.clone(), NAME).unwrap();
    let mut s = Connection::server(Arc::new(classical)).unwrap();
    s.read_tls(&c.take_tls()).unwrap();
    assert!(c.read_tls(&s.take_tls()).is_err());
    assert_ne!(c.state(), HandshakeState::Connected);
    assert!(c.send(b"secret").is_err());
    assert!(
        c.report()
            .events
            .iter()
            .any(|e| e.id == "event:required-property-missing"),
        "{}",
        c.report().to_json()
    );

    // Control: the default hybrid group meets the requirement.
    let (c, _) = connect(cc, Arc::new(pki.server_config(Profile::Default)), NAME).unwrap();
    assert!(c.report().has(Property::PostQuantumKeyExchange));
}

/// REQ-CONN-013: a server's requirement fails the handshake before it
/// accepts application data: a client's data sent straight after its
/// Finished never reaches the application.
#[test]
fn a_server_requirement_refuses_before_accepting_data() {
    let pki = Pki::new(KeyKind::EcdsaP256, NAME);
    let sc = Arc::new(
        pki.server_config(Profile::Default)
            .require(&[Property::PostQuantumAuthentication]),
    );
    let mut c = Connection::client(Arc::new(pki.client_config(Profile::Default)), NAME).unwrap();
    let mut s = Connection::server(sc).unwrap();
    s.read_tls(&c.take_tls()).unwrap();
    c.read_tls(&s.take_tls()).unwrap();
    // The client is done and sends data with its Finished.
    assert_eq!(c.state(), HandshakeState::Connected);
    c.send(b"privileged request").unwrap();
    let e = s.read_tls(&c.take_tls()).unwrap_err();
    assert_eq!(e.kind(), ErrorKind::PolicyViolation, "{e}");
    assert_eq!(e.context(), "property:post-quantum-authentication");
    let mut buf = [0u8; 64];
    assert_eq!(s.recv(&mut buf), 0, "no data reached the application");
}

/// REQ-CONN-013: the fixed-capacity engine enforces the same requirement.
#[test]
fn the_fixed_engine_enforces_requirements() {
    let pki = Pki::new(KeyKind::EcdsaP256, NAME);
    let mut cc = pki
        .client_config(Profile::Default)
        .require(&[Property::PostQuantumKeyExchange]);
    cc.tickets = None;
    cc.common.groups = vec![NamedGroup::X25519];
    let mut sc = pki.server_config(Profile::Default);
    sc.tickets = None;
    sc.common.groups = vec![NamedGroup::X25519];
    let (mut cb, mut sb) = (Buffers::new(), Buffers::new());
    let (mut cr, mut sr) = (
        ic_drbg::Rng::from_os().unwrap(),
        ic_drbg::Rng::from_os().unwrap(),
    );
    let mut c =
        fixed::Connection::client(&cc, NAME, &mut cr, cb.storage(), fixed::Limits::default())
            .unwrap();
    let mut s =
        fixed::Connection::server(&sc, &mut sr, sb.storage(), fixed::Limits::default()).unwrap();
    let mut failed = None;
    for _ in 0..4 {
        let n = c.outgoing().len();
        if n > 0 {
            let _ = s.receive(c.outgoing());
            c.consume_outgoing(n).unwrap();
        }
        let n = s.outgoing().len();
        if n > 0 {
            if let Err(e) = c.receive(s.outgoing()) {
                failed = Some(e);
                break;
            }
            s.consume_outgoing(n).unwrap();
        }
    }
    let e = failed.expect("the fixed client refused");
    assert_eq!(e.kind(), ErrorKind::PolicyViolation, "{e}");
    assert_eq!(e.context(), "property:post-quantum-key-exchange");
    assert_ne!(c.report().state, HandshakeState::Connected);
}

/// REQ-CONN-013: requirements that could not be checked in time, or could
/// never be met, are configuration errors.
#[test]
fn unenforceable_requirements_are_refused_at_configuration() {
    let pki = Pki::new(KeyKind::EcdsaP256, NAME);
    let refused = |r: ironsocketlayer::Result<()>| {
        assert_eq!(r.unwrap_err().kind(), ErrorKind::InvalidConfig);
    };
    // 0-RTT data goes out, or is delivered, before anything is proven.
    let mut cc = pki
        .client_config(Profile::Default)
        .require(&[Property::ServerAuthenticated]);
    cc.early_data = true;
    refused(cc.validate());
    let mut sc = pki
        .server_config(Profile::Default)
        .require(&[Property::ForwardSecrecy]);
    sc.early_data = Some(EarlyDataPolicy::new(1024));
    refused(sc.validate());
    // Mutual authentication without the means to get it.
    refused(
        pki.client_config(Profile::Default)
            .require(&[Property::MutualAuthentication])
            .validate(),
    );
    for auth in [
        ClientAuth::None,
        ClientAuth::Optional(PeerVerification::Roots(pki.roots())),
        ClientAuth::OnDemand(PeerVerification::Roots(pki.roots())),
    ] {
        refused(
            pki.server_config(Profile::Default)
                .with_client_auth(auth)
                .require(&[Property::MutualAuthentication])
                .validate(),
        );
    }
    // The meetable versions validate.
    pki.client_config(Profile::Default)
        .with_identity(pki.client_identity(KeyKind::EcdsaP256, "agent"))
        .require(&[Property::MutualAuthentication])
        .validate()
        .unwrap();
    pki.server_config(Profile::Default)
        .with_client_auth(ClientAuth::Required(PeerVerification::Roots(pki.roots())))
        .require(&[Property::MutualAuthentication])
        .validate()
        .unwrap();
}

/// REQ-CFG-005: every intent yields the configuration the ontology's
/// selector names: its profile, its ALPN, and its needs as requirements.
#[test]
fn every_intent_builds_the_recommended_configuration() {
    use ironsocketlayer::config::{ClientConfig, IntentPolicy, ServerConfig};
    use isl_ontology::select::{recommend, INTENTS};
    let pki = Pki::new(KeyKind::EcdsaP256, NAME);
    let policy = IntentPolicy::default();
    for intent in INTENTS {
        let rec = recommend(intent.id, &policy).unwrap();
        let cc = ClientConfig::for_intent(intent.id, &policy, pki.roots()).unwrap();
        assert_eq!(cc.common.profile.id(), rec.profile.id, "{}", intent.id);
        let alpn: Vec<&[u8]> = cc.common.alpn.iter().map(Vec::as_slice).collect();
        let want: Vec<&[u8]> = intent.alpn.iter().map(|p| p.as_bytes()).collect();
        assert_eq!(alpn, want, "{}", intent.id);
        let req = &cc.common.required_properties;
        assert!(
            req.contains(&Property::ServerAuthenticated),
            "{}",
            intent.id
        );
        assert_eq!(
            req.contains(&Property::PostQuantumKeyExchange),
            intent.post_quantum,
            "{}",
            intent.id
        );
        assert_eq!(
            req.contains(&Property::FipsApprovedAlgorithms),
            intent.fips,
            "{}",
            intent.id
        );
        assert_eq!(
            req.contains(&Property::MutualAuthentication),
            rec.mutual_auth,
            "{}",
            intent.id
        );
        let sc = ServerConfig::for_intent(intent.id, &policy, pki.server_identity()).unwrap();
        assert_eq!(sc.common.profile.id(), rec.profile.id, "{}", intent.id);
        assert!(!sc
            .common
            .required_properties
            .contains(&Property::ServerAuthenticated));
    }
}

/// REQ-CFG-005: policy flags move the choice as `isl recommend` does, and an
/// unknown intent is an error rather than a default.
#[test]
fn intent_policy_and_unknown_intents() {
    use ironsocketlayer::config::{ClientConfig, IntentPolicy};
    let pki = Pki::new(KeyKind::EcdsaP256, NAME);
    let both = IntentPolicy {
        require_fips: true,
        require_post_quantum: true,
        require_mutual_auth: false,
    };
    let cc = ClientConfig::for_intent("intent:https-client", &both, pki.roots()).unwrap();
    assert_eq!(cc.common.profile, Profile::Cnsa2);
    assert!(cc
        .common
        .required_properties
        .contains(&Property::PostQuantumKeyExchange));
    assert!(cc
        .common
        .required_properties
        .contains(&Property::FipsApprovedAlgorithms));
    let e = ClientConfig::for_intent(
        "intent:no-such-thing",
        &IntentPolicy::default(),
        pki.roots(),
    )
    .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::InvalidConfig);
    assert_eq!(e.context(), "unknown intent");
}

/// REQ-CFG-005: agent-to-agent mTLS from the intent on both ends connects
/// with mutual authentication and post-quantum key exchange; without the
/// identity and client authentication the intent needs, it does not start.
#[test]
fn an_intent_configuration_connects_and_refuses_what_it_lacks() {
    use ironsocketlayer::config::{ClientConfig, IntentPolicy, ServerConfig};
    let pki = Pki::new(KeyKind::EcdsaP256, NAME);
    let policy = IntentPolicy::default();
    let intent = "intent:agent-to-agent-mtls";
    let bare = ClientConfig::for_intent(intent, &policy, pki.roots()).unwrap();
    assert_eq!(
        Connection::client(Arc::new(bare.clone()), NAME)
            .unwrap_err()
            .kind(),
        ErrorKind::InvalidConfig
    );
    let bare_server = ServerConfig::for_intent(intent, &policy, pki.server_identity()).unwrap();
    assert_eq!(
        Connection::server(Arc::new(bare_server.clone()))
            .unwrap_err()
            .kind(),
        ErrorKind::InvalidConfig
    );
    let cc = bare.with_identity(pki.client_identity(KeyKind::EcdsaP256, "agent-a"));
    let sc =
        bare_server.with_client_auth(ClientAuth::Required(PeerVerification::Roots(pki.roots())));
    let (c, s) = connect(Arc::new(cc), Arc::new(sc), NAME).unwrap();
    for r in [c.report(), s.report()] {
        assert!(r.has(Property::MutualAuthentication), "{}", r.to_json());
        assert!(r.has(Property::PostQuantumKeyExchange));
        assert_eq!(r.alpn.as_deref(), Some(&b"a2a/1"[..]));
    }
}

/// REQ-CFG-006: default configurations give up nothing; each relaxation is
/// listed when made, and only then.
#[test]
fn relaxations_are_listed_exactly() {
    use ironsocketlayer::config::{ClientConfig, ExternalPsk, Relaxation, Revocation};
    use ironsocketlayer::crypto::HashAlg;
    let pki = Pki::new(KeyKind::EcdsaP256, NAME);
    assert!(pki.client_config(Profile::Default).relaxations().is_empty());
    assert!(pki.server_config(Profile::Default).relaxations().is_empty());

    let client = |edit: fn(&mut ClientConfig)| {
        let mut cc = pki.client_config(Profile::Default);
        edit(&mut cc);
        cc.relaxations()
    };
    assert_eq!(
        client(|c| c.revocation = Revocation::Off),
        [Relaxation::RevocationOff]
    );
    assert_eq!(client(|c| c.early_data = true), [Relaxation::EarlyData]);
    assert_eq!(client(|c| c.ech_grease = false), [Relaxation::NoEchGrease]);
    // GREASE is moot when real ECH is configured.
    assert!(client(|c| {
        c.ech_grease = false;
        c.ech_configs = Some(vec![0]);
    })
    .is_empty());
    // A pin is the peer's identity; it gives up nothing.
    let pinned = ClientConfig::pinned(Profile::Default, &pki.server_spki()).unwrap();
    assert!(pinned.relaxations().is_empty());

    let mut sc = pki.server_config(Profile::Default);
    sc.sni_fallback = true;
    assert_eq!(sc.relaxations(), [Relaxation::SniFallback]);
    let mut sc = pki.server_config(Profile::Default);
    sc.early_data = Some(EarlyDataPolicy::new(1024));
    assert_eq!(sc.relaxations(), [Relaxation::EarlyData]);
    // The Selfie guard matters only with external PSKs to guard.
    let mut sc = pki.server_config(Profile::Default);
    sc.selfie_guard = false;
    assert!(sc.relaxations().is_empty());
    sc.external_psks = vec![ExternalPsk::new(b"k", &[1; 32], HashAlg::Sha256).unwrap()];
    assert_eq!(sc.relaxations(), [Relaxation::SelfieGuardOff]);
}

/// REQ-CFG-006: every session reports its configuration's relaxations, in
/// the struct and in the JSON, on both sides.
#[test]
fn sessions_report_their_relaxations() {
    use ironsocketlayer::config::{Relaxation, Revocation};
    let pki = Pki::new(KeyKind::EcdsaP256, NAME);
    let mut cc = pki.client_config(Profile::Default);
    cc.revocation = Revocation::Off;
    let mut sc = pki.server_config(Profile::Default);
    sc.sni_fallback = true;
    let (c, s) = connect(Arc::new(cc), Arc::new(sc), NAME).unwrap();
    assert_eq!(c.report().relaxations, [Relaxation::RevocationOff]);
    assert!(c
        .report()
        .to_json()
        .contains(r#""relaxations":["relaxation:revocation-off"]"#));
    assert_eq!(s.report().relaxations, [Relaxation::SniFallback]);
    assert!(s
        .report()
        .to_json()
        .contains(r#""relaxations":["relaxation:sni-fallback"]"#));
    let (c, _) = connect(
        Arc::new(pki.client_config(Profile::Default)),
        Arc::new(pki.server_config(Profile::Default)),
        NAME,
    )
    .unwrap();
    assert!(c.report().to_json().contains(r#""relaxations":[]"#));
}
