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
