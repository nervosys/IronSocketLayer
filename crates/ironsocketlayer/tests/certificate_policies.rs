//! The certificate policies a configuration accepts on a peer's path
//! (`REQ-CFG-010`). Certificates are assembled from raw DER, since the
//! crate's own builder issues none with policy extensions.

mod common;
mod fixed_support;

use std::sync::Arc;

use fixed_support::Buffers;
use ironsocketlayer::config::{
    CertificatePolicies, ClientAuth, ClientConfig, Identity, PeerVerification, Profile,
    ServerConfig,
};
use ironsocketlayer::crypto::sign::{self, KeyKind, SigningKey};
use ironsocketlayer::enums::SignatureScheme;
use ironsocketlayer::x509::{PolicyOutcome, RootStore, MAX_ACCEPTABLE};
use ironsocketlayer::ErrorKind;

const ECDSA_SHA256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
const POLICY_1: &[u8] = &[0x2a, 0x03, 0x01];
const POLICY_2: &[u8] = &[0x2a, 0x03, 0x02];
const NAME: &str = "srv.example";

fn rng() -> ic_drbg::Rng {
    ic_drbg::Rng::from_os().unwrap()
}

fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    sign::push_tlv(&mut out, tag, body);
    out
}

fn name(cn: &str) -> Vec<u8> {
    let atv = [tlv(0x06, &[0x55, 0x04, 0x03]), tlv(0x0c, cn.as_bytes())].concat();
    tlv(0x30, &tlv(0x31, &tlv(0x30, &atv)))
}

fn ext(oid: &[u8], critical: bool, value: &[u8]) -> Vec<u8> {
    let mut b = tlv(0x06, oid);
    if critical {
        b.extend(tlv(0x01, &[0xff]));
    }
    b.extend(tlv(0x04, value));
    tlv(0x30, &b)
}

fn basic_constraints(ca: bool) -> Vec<u8> {
    let body: &[u8] = if ca { &[0x01, 0x01, 0xff] } else { &[] };
    ext(&[0x55, 0x1d, 0x13], true, &tlv(0x30, body))
}

fn key_usage(ca: bool) -> Vec<u8> {
    let bits: &[u8] = if ca { &[0x01, 0x06] } else { &[0x07, 0x80] };
    ext(&[0x55, 0x1d, 0x0f], true, &tlv(0x03, bits))
}

fn certificate_policies(policies: &[&[u8]]) -> Vec<u8> {
    let list: Vec<u8> = policies
        .iter()
        .flat_map(|p| tlv(0x30, &tlv(0x06, p)))
        .collect();
    ext(&[0x55, 0x1d, 0x20], false, &tlv(0x30, &list))
}

fn cert(
    serial: u8,
    issuer: &[u8],
    subject: &[u8],
    spki: &[u8],
    exts: &[Vec<u8>],
    signer: &SigningKey,
) -> Vec<u8> {
    let alg = tlv(0x30, &tlv(0x06, ECDSA_SHA256));
    let validity = [tlv(0x17, b"200101000000Z"), tlv(0x17, b"491231235959Z")].concat();
    let tbs = tlv(
        0x30,
        &[
            tlv(0xa0, &tlv(0x02, &[2])),
            tlv(0x02, &[serial]),
            alg.clone(),
            issuer.to_vec(),
            tlv(0x30, &validity),
            subject.to_vec(),
            spki.to_vec(),
            tlv(0xa3, &tlv(0x30, &exts.concat())),
        ]
        .concat(),
    );
    let signature = signer
        .sign(SignatureScheme::EcdsaSecp256r1Sha256, &tbs, &mut rng())
        .unwrap();
    let mut bits = vec![0u8];
    bits.extend(signature);
    tlv(0x30, &[tbs, alg, tlv(0x03, &bits)].concat())
}

fn key() -> SigningKey {
    SigningKey::generate(KeyKind::EcdsaP256, &mut rng()).unwrap()
}

/// A root, a server certificate under it asserting policy 1 and a client
/// certificate under it asserting policy 2.
struct Fixture {
    root: Vec<u8>,
    server: Vec<u8>,
    server_spki: Vec<u8>,
    client: Vec<u8>,
}

impl Fixture {
    fn new() -> (Self, SigningKey, SigningKey) {
        let (root_key, server_key, client_key) = (key(), key(), key());
        let root = cert(
            1,
            &name("Root"),
            &name("Root"),
            root_key.spki(),
            &[basic_constraints(true), key_usage(true)],
            &root_key,
        );
        let san = ext(
            &[0x55, 0x1d, 0x11],
            false,
            &tlv(0x30, &tlv(0x82, NAME.as_bytes())),
        );
        let server = cert(
            2,
            &name("Root"),
            &name("srv"),
            server_key.spki(),
            &[
                basic_constraints(false),
                key_usage(false),
                san,
                certificate_policies(&[POLICY_1]),
            ],
            &root_key,
        );
        let client = cert(
            3,
            &name("Root"),
            &name("agent"),
            client_key.spki(),
            &[
                basic_constraints(false),
                key_usage(false),
                certificate_policies(&[POLICY_2]),
            ],
            &root_key,
        );
        (
            Self {
                root,
                server,
                server_spki: server_key.spki().to_vec(),
                client,
            },
            server_key,
            client_key,
        )
    }

    fn roots(&self) -> RootStore {
        let mut roots = RootStore::new();
        roots.add_der(&self.root).unwrap();
        roots
    }
}

fn outcome(required: bool, valid: u64) -> Option<PolicyOutcome> {
    let mut o = PolicyOutcome::default();
    o.required = required;
    o.valid = valid;
    Some(o)
}

/// REQ-CFG-010: a configuration's `certificate_policies` are asked of the
/// path a peer presents, at a client and at a server, in the handshake and
/// for a certificate requested after it; the report says what held. The
/// default asks nothing. A pinned peer has no path, and is asked nothing.
#[test]
fn certificate_policies_are_asked_of_a_peers_path() {
    let (f, server_key, client_key) = Fixture::new();
    let server_id = Identity::new(vec![f.server.clone()], server_key).unwrap();
    let client_id = Identity::new(vec![f.client.clone()], client_key).unwrap();
    let server_config = || ServerConfig::new(Profile::Default, server_id.clone()).unwrap();
    let client_with = |policies: CertificatePolicies| {
        let mut cc = ClientConfig::new(Profile::Default, f.roots()).unwrap();
        cc.common.certificate_policies = policies;
        common::connect(Arc::new(cc), Arc::new(server_config()), NAME)
    };

    // The default: nothing asked, and the report says so.
    let (c, s) = client_with(CertificatePolicies::default()).unwrap();
    assert_eq!(c.report().peer_policy, outcome(false, 0));
    assert!(
        c.report()
            .to_json()
            .contains(r#""peerPolicyRequired":false,"peerPoliciesValid":0"#),
        "{}",
        c.report().to_json()
    );
    // The server saw no client certificate: no path, nothing to report.
    assert_eq!(s.report().peer_policy, None);
    assert!(!s.report().to_json().contains("peerPolicyRequired"));

    // The server's policy, required.
    let (c, _) = client_with(CertificatePolicies::require(&[POLICY_1])).unwrap();
    assert_eq!(c.report().peer_policy, outcome(true, 0b1));
    assert!(c
        .report()
        .to_json()
        .contains(r#""peerPolicyRequired":true,"peerPoliciesValid":1"#));
    let (c, _) = client_with(CertificatePolicies::require(&[POLICY_2, POLICY_1])).unwrap();
    assert_eq!(c.report().peer_policy, outcome(true, 0b10));
    // Another policy, required: refused.
    let failure = client_with(CertificatePolicies::require(&[POLICY_2])).unwrap_err();
    assert_eq!(failure.client.unwrap().kind(), ErrorKind::CertificateUsage);
    // Another policy, named and not required: accepted, and reported absent.
    let named = CertificatePolicies {
        acceptable: vec![POLICY_2.to_vec()],
        ..CertificatePolicies::default()
    };
    let (c, _) = client_with(named).unwrap();
    assert_eq!(c.report().peer_policy, outcome(false, 0));
    // Any policy acceptable, one required: the server has one.
    let required = CertificatePolicies {
        require_explicit: true,
        ..CertificatePolicies::default()
    };
    let (c, _) = client_with(required).unwrap();
    assert_eq!(c.report().peer_policy, outcome(true, 0));

    // A pinned peer has no path.
    let mut pinned = ClientConfig::pinned(Profile::Default, &f.server_spki).unwrap();
    pinned.common.certificate_policies = CertificatePolicies::require(&[POLICY_2]);
    let (c, _) = common::connect(Arc::new(pinned), Arc::new(server_config()), NAME).unwrap();
    assert_eq!(c.report().peer_policy, None);

    // At the server, of a client's path.
    let client_config = || {
        ClientConfig::new(Profile::Default, f.roots())
            .unwrap()
            .with_identity(client_id.clone())
    };
    let server_with = |policies: CertificatePolicies| {
        let mut sc = server_config()
            .with_client_auth(ClientAuth::Required(PeerVerification::Roots(f.roots())));
        sc.common.certificate_policies = policies;
        common::connect(Arc::new(client_config()), Arc::new(sc), NAME)
    };
    let (_, s) = server_with(CertificatePolicies::require(&[POLICY_2])).unwrap();
    assert_eq!(s.report().peer_policy, outcome(true, 0b1));
    let failure = server_with(CertificatePolicies::require(&[POLICY_1])).unwrap_err();
    assert_eq!(failure.server.unwrap().kind(), ErrorKind::CertificateUsage);

    // And of a certificate the server asks for after the handshake.
    for (policy, accepted) in [(POLICY_2, true), (POLICY_1, false)] {
        let mut cc = client_config();
        cc.post_handshake_auth = true;
        let mut sc = server_config()
            .with_client_auth(ClientAuth::OnDemand(PeerVerification::Roots(f.roots())));
        sc.common.certificate_policies = CertificatePolicies::require(&[policy]);
        let (mut c, mut s) = common::connect(Arc::new(cc), Arc::new(sc), NAME)
            .map_err(|f| f.client)
            .unwrap();
        assert_eq!(s.report().peer_policy, None);
        s.request_client_auth().unwrap();
        let mut result = Ok(());
        for _ in 0..3 {
            let to_client = s.take_tls();
            let _ = c.read_tls(&to_client);
            let to_server = c.take_tls();
            if let Err(e) = s.read_tls(&to_server) {
                result = Err(e);
                break;
            }
        }
        if accepted {
            result.unwrap();
            assert_eq!(s.report().peer_policy, outcome(true, 0b1));
        } else {
            assert_eq!(result.unwrap_err().kind(), ErrorKind::CertificateUsage);
        }
    }
}

/// REQ-CFG-010: the fixed-capacity engine asks the same of a peer's path,
/// and reports the same, and asks nothing of a pinned peer.
#[test]
fn the_fixed_engine_asks_the_same_of_a_peers_path() {
    use ironsocketlayer::fixed::{Connection, Limits};
    let (f, server_key, _) = Fixture::new();
    let server_id = Identity::new(vec![f.server.clone()], server_key).unwrap();
    for (pinned, policies, expected) in [
        (false, CertificatePolicies::default(), Ok(outcome(false, 0))),
        (
            false,
            CertificatePolicies::require(&[POLICY_2, POLICY_1]),
            Ok(outcome(true, 0b10)),
        ),
        (
            false,
            CertificatePolicies::require(&[POLICY_2]),
            Err(ErrorKind::CertificateUsage),
        ),
        // A pinned peer has no path: nothing is asked, and nothing reported.
        (true, CertificatePolicies::require(&[POLICY_2]), Ok(None)),
    ] {
        let mut cc = if pinned {
            ClientConfig::pinned(Profile::Default, &f.server_spki).unwrap()
        } else {
            ClientConfig::new(Profile::Default, f.roots()).unwrap()
        };
        cc.tickets = None;
        cc.common.certificate_policies = policies;
        let mut sc = ServerConfig::new(Profile::Default, server_id.clone()).unwrap();
        sc.tickets = None;
        let (mut cb, mut sb) = (Buffers::new(), Buffers::new());
        let (mut cr, mut sr) = (rng(), rng());
        let mut c =
            Connection::client(&cc, NAME, &mut cr, cb.storage(), Limits::default()).unwrap();
        let mut s = Connection::server(&sc, &mut sr, sb.storage(), Limits::default()).unwrap();
        let mut result = Ok(());
        'pump: for _ in 0..12 {
            for client_sends in [true, false] {
                let (from, to) = if client_sends {
                    (&mut c, &mut s)
                } else {
                    (&mut s, &mut c)
                };
                let n = from.outgoing().len();
                let step = to.receive(from.outgoing());
                from.consume_outgoing(n).unwrap();
                if let Err(e) = step {
                    result = Err(e.kind());
                    break 'pump;
                }
            }
            if c.is_connected() && s.is_connected() {
                break;
            }
        }
        assert_eq!(result.map(|()| c.report().peer_policy), expected);
    }
}

/// REQ-CFG-010: the two initial inhibitions reach the validator: a policy
/// that holds only through a CA's mapping, or only through anyPolicy, is
/// accepted until the configuration inhibits that.
#[test]
fn the_initial_inhibitions_are_passed_on() {
    const ANY_POLICY: &[u8] = &[0x55, 0x1d, 0x20, 0x00];
    let (root_key, ca_key) = (key(), key());
    let root = cert(
        1,
        &name("Root"),
        &name("Root"),
        root_key.spki(),
        &[basic_constraints(true), key_usage(true)],
        &root_key,
    );
    let san = || {
        ext(
            &[0x55, 0x1d, 0x11],
            false,
            &tlv(0x30, &tlv(0x82, NAME.as_bytes())),
        )
    };
    // A CA that holds policy 1 and maps it to policy 2, and a server under
    // it that lists policy 2: valid for a caller that names policy 1.
    let mapping = ext(
        &[0x55, 0x1d, 0x21],
        true,
        &tlv(
            0x30,
            &tlv(0x30, &[tlv(0x06, POLICY_1), tlv(0x06, POLICY_2)].concat()),
        ),
    );
    let ca = cert(
        2,
        &name("Root"),
        &name("Bridge"),
        ca_key.spki(),
        &[
            basic_constraints(true),
            key_usage(true),
            certificate_policies(&[POLICY_1]),
            mapping,
        ],
        &root_key,
    );
    let mapped_key = key();
    let mapped = cert(
        3,
        &name("Bridge"),
        &name("srv"),
        mapped_key.spki(),
        &[
            basic_constraints(false),
            key_usage(false),
            san(),
            certificate_policies(&[POLICY_2]),
        ],
        &ca_key,
    );
    // A server directly under the root that asserts anyPolicy only.
    let any_key = key();
    let any = cert(
        4,
        &name("Root"),
        &name("srv"),
        any_key.spki(),
        &[
            basic_constraints(false),
            key_usage(false),
            san(),
            certificate_policies(&[ANY_POLICY]),
        ],
        &root_key,
    );
    let mapped_id = Identity::new(vec![mapped, ca], mapped_key).unwrap();
    let any_id = Identity::new(vec![any], any_key).unwrap();
    let verdict = |id: &Identity, policies: CertificatePolicies| {
        let mut roots = RootStore::new();
        roots.add_der(&root).unwrap();
        let mut cc = ClientConfig::new(Profile::Default, roots).unwrap();
        cc.common.certificate_policies = policies;
        let sc = ServerConfig::new(Profile::Default, id.clone()).unwrap();
        common::connect(Arc::new(cc), Arc::new(sc), NAME)
            .map(|(c, _)| c.report().peer_policy)
            .map_err(|f| f.client.unwrap().kind())
    };
    let only_1 = || CertificatePolicies::require(&[POLICY_1]);
    assert_eq!(verdict(&mapped_id, only_1()), Ok(outcome(true, 0b1)));
    assert_eq!(
        verdict(
            &mapped_id,
            CertificatePolicies {
                inhibit_mapping: true,
                ..only_1()
            }
        ),
        Err(ErrorKind::CertificateUsage)
    );
    assert_eq!(verdict(&any_id, only_1()), Ok(outcome(true, 0b1)));
    assert_eq!(
        verdict(
            &any_id,
            CertificatePolicies {
                inhibit_any: true,
                ..only_1()
            }
        ),
        Err(ErrorKind::CertificateUsage)
    );
}

/// REQ-CFG-010: policy inputs that cannot be evaluated do not validate.
#[test]
fn unusable_certificate_policies_do_not_validate() {
    let (f, _, _) = Fixture::new();
    let config = |policies: CertificatePolicies| {
        let mut cc = ClientConfig::new(Profile::Default, f.roots()).unwrap();
        cc.common.certificate_policies = policies;
        cc.validate().map_err(|e| e.kind())
    };
    assert_eq!(config(CertificatePolicies::default()), Ok(()));
    assert_eq!(
        config(CertificatePolicies::require(&[POLICY_1; MAX_ACCEPTABLE])),
        Ok(())
    );
    assert_eq!(
        config(CertificatePolicies::require(
            &[POLICY_1; MAX_ACCEPTABLE + 1]
        )),
        Err(ErrorKind::InvalidConfig)
    );
    assert_eq!(
        config(CertificatePolicies::require(&[POLICY_1, &[0x80, 0x01]])),
        Err(ErrorKind::InvalidConfig)
    );
    assert_eq!(
        config(CertificatePolicies::require(&[&[]])),
        Err(ErrorKind::InvalidConfig)
    );
}
