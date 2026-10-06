//! Certificate-handling regressions found by the 2026-10-06 security audit.
//! Certificates are assembled from raw DER here so that inputs the crate's
//! own builder refuses (a trailing-dot dNSName, thousands of extensions, a
//! non-CA "anchor" that signs) can still be presented to the validators.

mod common;

use std::sync::Arc;

use ironsocketlayer::config::{ClientConfig, Identity, Profile, ServerConfig};
use ironsocketlayer::crypto::sign::{self, KeyKind, SigningKey};
use ironsocketlayer::enums::SignatureScheme;
use ironsocketlayer::x509::{self, RootStore, Usage, VerifyOptions};
use ironsocketlayer::ErrorKind;

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

fn name_constraints(excluded: &[(u8, &[u8])]) -> Vec<u8> {
    let list: Vec<u8> = excluded
        .iter()
        .flat_map(|(t, v)| tlv(0x30, &tlv(*t, v)))
        .collect();
    ext(&[0x55, 0x1d, 0x1e], true, &tlv(0x30, &tlv(0xa1, &list)))
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

fn opts() -> VerifyOptions<'static> {
    VerifyOptions::new(common::now(), Usage::ServerAuth, sign::VERIFY_SCHEMES)
}

/// Both validators' verdicts on `leaf` issued by `int` under `roots`.
fn verdicts(
    leaf: &[u8],
    ints: &[&[u8]],
    roots: &RootStore,
) -> (Option<ErrorKind>, Option<ErrorKind>) {
    let o = opts();
    (
        x509::verify_chain(leaf, ints, roots, &o)
            .err()
            .map(|e| e.kind()),
        x509::verify_chain_fixed(leaf, ints, roots, &o)
            .err()
            .map(|e| e.kind()),
    )
}

/// REQ-X509-071: a dNSName with a trailing dot names the same host, so it
/// cannot escape an excluded subtree, as a name or as a wildcard, in either
/// validator.
#[test]
fn a_trailing_dot_does_not_escape_an_excluded_subtree() {
    let (root_key, int_key, leaf_key) = (key(), key(), key());
    let root = cert(
        1,
        &name("Root"),
        &name("Root"),
        root_key.spki(),
        &[basic_constraints(true), key_usage(true)],
        &root_key,
    );
    let int = cert(
        2,
        &name("Root"),
        &name("Int"),
        int_key.spki(),
        &[
            basic_constraints(true),
            key_usage(true),
            name_constraints(&[(0x82, b"evil.com")]),
        ],
        &root_key,
    );
    let mut roots = RootStore::new();
    roots.add_der(&root).unwrap();
    let refused = (
        Some(ErrorKind::CertificateUsage),
        Some(ErrorKind::CertificateUsage),
    );
    for dns in [
        &b"victim.evil.com."[..],
        b"evil.com.",
        b"*.evil.com.",
        b"VICTIM.Evil.COM.",
    ] {
        let leaf = cert(
            3,
            &name("Int"),
            &name("leaf"),
            leaf_key.spki(),
            &[
                basic_constraints(false),
                key_usage(false),
                san(&[(0x82, dns)]),
            ],
            &int_key,
        );
        assert_eq!(
            verdicts(&leaf, &[&int], &roots),
            refused,
            "{}",
            String::from_utf8_lossy(dns)
        );
    }
    // Control: a name outside the subtree is still accepted.
    let leaf = cert(
        3,
        &name("Int"),
        &name("leaf"),
        leaf_key.spki(),
        &[
            basic_constraints(false),
            key_usage(false),
            san(&[(0x82, b"good.example.")]),
        ],
        &int_key,
    );
    assert_eq!(verdicts(&leaf, &[&int], &roots), (None, None));
}

/// REQ-X509-074: a certificate trusted as an anchor that is not a CA (its
/// basicConstraints says so) is trusted as itself only; it cannot issue.
#[test]
fn a_non_ca_anchor_issues_nothing() {
    let (pinned_key, other_key) = (key(), key());
    let pinned = cert(
        9,
        &name("peer.example"),
        &name("peer.example"),
        pinned_key.spki(),
        &[
            basic_constraints(false),
            key_usage(false),
            san(&[(0x82, b"peer.example")]),
        ],
        &pinned_key,
    );
    let mut roots = RootStore::new();
    roots.add_der(&pinned).unwrap();
    // The anchored certificate itself is still accepted.
    assert_eq!(verdicts(&pinned, &[], &roots), (None, None));
    // A certificate it signed for another name is not.
    let forged = cert(
        10,
        &name("peer.example"),
        &name("bank"),
        other_key.spki(),
        &[
            basic_constraints(false),
            key_usage(false),
            san(&[(0x82, b"bank.example")]),
        ],
        &pinned_key,
    );
    let (owned, fixed) = verdicts(&forged, &[], &roots);
    assert!(owned.is_some() && owned == fixed, "{owned:?} / {fixed:?}");
}

/// REQ-OCSP-033: a leaf trusted directly as an anchor cannot attest its own
/// revocation status with a staple signed by its own key.
#[test]
fn a_self_anchored_leaf_cannot_staple_for_itself() {
    let k = key();
    let leaf = cert(
        9,
        &name("peer.example"),
        &name("peer.example"),
        k.spki(),
        &[
            basic_constraints(false),
            key_usage(false),
            san(&[(0x82, b"peer.example")]),
        ],
        &k,
    );
    let mut roots = RootStore::new();
    roots.add_der(&leaf).unwrap();
    let report = x509::verify_chain(&leaf, &[], &roots, &opts()).unwrap();
    assert_eq!(report.depth, 0);
    let now = common::now();
    let staple = x509::ocsp::build_response(
        &leaf,
        &leaf,
        &k,
        x509::ocsp::CertStatus::Good,
        now - 60,
        now + 3600,
        &mut rng(),
    )
    .unwrap();
    let e = x509::ocsp::verify_response(
        &staple,
        &leaf,
        &report.issuer_subject,
        &report.issuer_spki,
        now,
        sign::VERIFY_SCHEMES,
    )
    .unwrap_err();
    assert!(e.to_string().contains("cannot attest its own"), "{e}");
}

/// REQ-X509-073: the extension count is bounded before the duplicate check,
/// so a certificate of thousands of empty extensions is refused quickly
/// instead of costing quadratic time on every parse.
#[test]
fn a_certificate_with_thousands_of_extensions_is_refused_quickly() {
    let k = key();
    let mut all = vec![
        basic_constraints(false),
        key_usage(false),
        san(&[(0x82, b"x.example")]),
    ];
    for i in 0..14_000u32 {
        all.push(ext(
            &[0x2a, ((i >> 7) & 0x7f) as u8, (i & 0x7f) as u8],
            false,
            &[],
        ));
    }
    let c = cert(5, &name("i"), &name("l"), k.spki(), &all, &k);
    assert!(c.len() > 100_000);
    let start = std::time::Instant::now();
    let e = x509::Certificate::parse(&c).unwrap_err();
    let took = start.elapsed();
    assert_eq!(e.kind(), ErrorKind::BadCertificate, "{e}");
    assert!(e.to_string().contains("too many extensions"), "{e}");
    assert!(
        took < std::time::Duration::from_millis(100),
        "took {took:?}"
    );
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
