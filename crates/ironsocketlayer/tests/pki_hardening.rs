//! Certificate-handling regressions found by the 2026-10-06 security audit.
//! Certificates are assembled from raw DER here so that inputs the crate's
//! own builder refuses (a trailing-dot dNSName, thousands of extensions, a
//! non-CA "anchor" that signs) can still be presented to the validators.

mod common;

use std::sync::Arc;

use ironsocketlayer::config::{ClientConfig, Identity, Profile, ServerConfig};
use ironsocketlayer::crypto::sign::{self, KeyKind, SigningKey};
use ironsocketlayer::enums::SignatureScheme;

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

const ECDSA_SHA256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];

fn basic_constraints(ca: bool) -> Vec<u8> {
    let body: &[u8] = if ca { &[0x01, 0x01, 0xff] } else { &[] };
    ext(&[0x55, 0x1d, 0x13], true, &tlv(0x30, body))
}

fn key_usage(ca: bool) -> Vec<u8> {
    let bits: &[u8] = if ca { &[0x01, 0x06] } else { &[0x07, 0x80] };
    ext(&[0x55, 0x1d, 0x0f], true, &tlv(0x03, bits))
}

fn san(entries: &[(u8, &[u8])]) -> Vec<u8> {
    let body: Vec<u8> = entries.iter().flat_map(|(t, v)| tlv(*t, v)).collect();
    ext(&[0x55, 0x1d, 0x11], false, &tlv(0x30, &body))
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

/// REQ-X509-075: a pinned peer's leaf passes the same leaf checks as one on
/// a validated path, in the owned engine as in the fixed one: here, an
/// extended key usage for client authentication only, and an unknown
/// critical extension.
#[test]
fn a_pinned_server_leaf_still_gets_the_leaf_checks() {
    let client_auth_only = ext(
        &[0x55, 0x1d, 0x25],
        false,
        &tlv(
            0x30,
            &tlv(0x06, &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02]),
        ),
    );
    let unknown_critical = ext(&[0x2a, 0x03, 0x04], true, &[0x05, 0x00]);
    let pinned_server = |extra: Option<Vec<u8>>| {
        let k = key();
        let mut exts = vec![basic_constraints(false), key_usage(false)];
        exts.extend(extra);
        exts.push(san(&[(0x82, b"srv.example")]));
        let leaf = cert(7, &name("srv"), &name("srv"), k.spki(), &exts, &k);
        let client = ClientConfig::pinned(Profile::Default, k.spki()).unwrap();
        let server =
            ServerConfig::new(Profile::Default, Identity::new(vec![leaf], k).unwrap()).unwrap();
        common::connect(Arc::new(client), Arc::new(server), "srv.example")
    };
    for extra in [client_auth_only, unknown_critical] {
        let Err(failure) = pinned_server(Some(extra)) else {
            panic!("the owned client must refuse the leaf");
        };
        assert!(failure.client.is_some(), "{failure:?}");
    }
    // Control: a well-formed pinned leaf still connects.
    assert!(pinned_server(None).is_ok());
}

/// REQ-RPT-003: the report lists the names the peer's certificate was issued
/// for, dNSNames then iPAddresses, in the struct and in its JSON.
#[test]
fn the_report_lists_the_peers_verified_names() {
    let k = key();
    let leaf = cert(
        7,
        &name("srv"),
        &name("srv"),
        k.spki(),
        &[
            basic_constraints(false),
            key_usage(false),
            san(&[
                (0x87, &[192, 0, 2, 1]),
                (0x82, b"srv.example"),
                (
                    0x87,
                    &[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                ),
                (0x82, b"alt.example"),
            ]),
        ],
        &k,
    );
    let client = ClientConfig::pinned(Profile::Default, k.spki()).unwrap();
    let server =
        ServerConfig::new(Profile::Default, Identity::new(vec![leaf], k).unwrap()).unwrap();
    let (c, s) = common::connect(Arc::new(client), Arc::new(server), "srv.example").unwrap();
    let r = c.report();
    assert_eq!(
        r.peer_names,
        ["srv.example", "alt.example", "192.0.2.1", "2001:db8::1"]
    );
    assert!(
        r.to_json()
            .contains(r#""peerNames":["srv.example","alt.example","192.0.2.1","2001:db8::1"]"#),
        "{}",
        r.to_json()
    );
    // The server authenticated no client, so it lists none.
    assert!(s.report().peer_names.is_empty());
    assert!(s.report().to_json().contains(r#""peerNames":[]"#));
}
