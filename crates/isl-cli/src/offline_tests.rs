//! The offline tools on real certificates and configurations,
//! good and bad.

use super::*;

fn rng() -> Box<dyn ic_core::traits::RandomSource + Send> {
    ClientConfig::new(Profile::Default, RootStore::new())
        .unwrap()
        .common
        .new_rng()
        .unwrap()
}

fn pem(der: &[u8]) -> String {
    let mut out = vec![0u8; der.len() * 2 + 128];
    let n = ic_pkix::pem::encode("CERTIFICATE", der, &mut out).unwrap();
    String::from_utf8(out[..n].to_vec()).unwrap()
}

fn params<'a>(
    cn: &'a str,
    dns: &'a [&'a str],
    ca: bool,
    usage: &'a [Usage],
) -> CertificateParams<'a> {
    let t = now();
    CertificateParams {
        subject_cn: cn,
        dns_names: dns,
        ip_addresses: &[],
        not_before: t - 60,
        not_after: t + 86_400,
        is_ca: ca,
        path_len: if ca { Some(0) } else { None },
        usage,
        serial: [7; 16],
    }
}

/// A CA, and a server leaf it issued for `api.test`: (ca, leaf, leaf SPKI).
fn chain() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let mut r = rng();
    let ca_key = SigningKey::generate(KeyKind::EcdsaP256, &mut *r).unwrap();
    let ca = x509::self_signed(&params("Test CA", &[], true, &[]), &ca_key, &mut *r).unwrap();
    let key = SigningKey::generate(KeyKind::EcdsaP256, &mut *r).unwrap();
    let leaf = x509::issue(
        &params("api", &["api.test"], false, &[Usage::ServerAuth]),
        key.spki(),
        &ca,
        &ca_key,
        &mut *r,
    )
    .unwrap();
    (ca, leaf, key.spki().to_vec())
}

#[test]
fn inspect_reports_names_validity_and_the_pin() {
    let (ca, leaf, spki) = chain();
    let v = inspect_certificate(&(pem(&leaf) + &pem(&ca))).unwrap();
    let certs = v.as_array().unwrap();
    assert_eq!(certs.len(), 2);
    let l = &certs[0];
    assert_eq!(l.get("subjectCommonName").unwrap().as_str(), Some("api"));
    assert_eq!(l.get("issuerCommonName").unwrap().as_str(), Some("Test CA"));
    assert_eq!(l.get("isCa").unwrap().as_bool(), Some(false));
    assert_eq!(l.get("expired").unwrap().as_bool(), Some(false));
    assert_eq!(
        l.get("spkiSha256").unwrap().as_str().unwrap(),
        hex(HashAlg::Sha256.digest(&spki).as_bytes())
    );
    assert!(format!("{:?}", l.get("dnsNames").unwrap()).contains("api.test"));
    assert_eq!(certs[1].get("isCa").unwrap().as_bool(), Some(true));
    // Not PEM, garbage DER, and too much input are errors, not panics.
    assert!(inspect_certificate("hello").is_err());
    assert!(inspect_certificate(&pem(b"\x30\x03\x02\x01\x00")).is_err());
    // Valid PEM past the cap is refused for its size, before parsing.
    let one = pem(&leaf);
    let big = one.repeat(MAX_INPUT / one.len() + 1);
    assert!(big.len() > MAX_INPUT);
    let e = inspect_certificate(&big).unwrap_err();
    assert!(e.contains("larger than"), "{e}");
    let e = verify_chain(&big, &pem(&ca), None, false).unwrap_err();
    assert!(e.contains("larger than"), "{e}");
}

#[test]
fn verify_answers_with_validity_or_the_error_and_action() {
    let (ca, leaf, _) = chain();
    let field = |v: &Json, k: &str| v.get(k).and_then(|x| x.as_str()).map(String::from);
    let ok = verify_chain(&pem(&leaf), &pem(&ca), Some("api.test"), false).unwrap();
    assert_eq!(ok.get("valid").unwrap().as_bool(), Some(true), "{ok:?}");
    let wrong_name = verify_chain(&pem(&leaf), &pem(&ca), Some("other.test"), false).unwrap();
    assert_eq!(
        field(&wrong_name, "error").as_deref(),
        Some("error:certificate-name-mismatch")
    );
    assert_eq!(
        field(&wrong_name, "action").as_deref(),
        Some("recovery:ask-user")
    );
    let (other_ca, _, _) = chain();
    let untrusted = verify_chain(&pem(&leaf), &pem(&other_ca), None, false).unwrap();
    assert_eq!(
        field(&untrusted, "error").as_deref(),
        Some("error:unknown-ca")
    );
    let as_client = verify_chain(&pem(&leaf), &pem(&ca), None, true).unwrap();
    assert_eq!(as_client.get("valid").unwrap().as_bool(), Some(false));
    assert!(verify_chain("nope", &pem(&ca), None, false).is_err());
}

fn check(json: &str) -> Json {
    check_config(&ic_json::parse(json).unwrap()).unwrap()
}

fn valid(v: &Json) -> bool {
    v.get("valid").and_then(|x| x.as_bool()) == Some(true)
}

fn list(v: &Json, k: &str) -> Vec<String> {
    v.get(k)
        .and_then(|x| x.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

#[test]
fn check_config_builds_and_judges_configurations() {
    let v = check(r#"{"side":"client"}"#);
    assert!(valid(&v), "{v:?}");
    assert!(list(&v, "relaxations").is_empty());
    let v = check(r#"{"side":"client","revocation":"off","echGrease":false}"#);
    assert_eq!(
        list(&v, "relaxations"),
        ["relaxation:revocation-off", "relaxation:no-ech-grease"]
    );
    // Requirements that cannot be enforced.
    let v =
        check(r#"{"side":"client","earlyData":true,"require":["property:server-authenticated"]}"#);
    assert!(!valid(&v));
    assert_eq!(
        v.get("action").unwrap().as_str(),
        Some("recovery:fix-caller")
    );
    // An intent: mutual authentication needs an identity.
    let v = check(r#"{"side":"client","intent":"intent:agent-to-agent-mtls"}"#);
    assert!(!valid(&v), "{v:?}");
    let v = check(r#"{"side":"client","intent":"agent-to-agent-mtls","identity":true}"#);
    assert!(valid(&v), "{v:?}");
    assert!(list(&v, "required").contains(&"property:mutual-authentication".to_string()));
    assert_eq!(
        v.get("profile").unwrap().as_str(),
        Some("profile:post-quantum")
    );
    // Servers.
    let v = check(r#"{"side":"server","sniFallback":true,"externalPsk":true,"selfieGuard":false}"#);
    assert!(valid(&v), "{v:?}");
    assert_eq!(
        list(&v, "relaxations"),
        ["relaxation:sni-fallback", "relaxation:selfie-guard-off"]
    );
    let v =
        check(r#"{"side":"server","clientAuth":"on-demand","require":["mutual-authentication"]}"#);
    assert!(!valid(&v));
    let v = check(r#"{"side":"server","profile":"profile:cnsa-2"}"#);
    assert_eq!(
        v.get("profile").unwrap().as_str(),
        Some("profile:cnsa-2"),
        "{v:?}"
    );
    // Malformed descriptions are errors, not panics.
    for bad in [
        r#"[]"#,
        r#"{}"#,
        r#"{"side":"proxy"}"#,
        r#"{"side":"client","profile":"profile:nope"}"#,
        r#"{"side":"client","require":["property:nope"]}"#,
        r#"{"side":"client","require":"x"}"#,
        r#"{"side":"client","fips":"yes"}"#,
        r#"{"side":"client","earlyData":"yes"}"#,
        r#"{"side":"client","erlyData":true}"#,
        r#"{"side":"client","profile":3}"#,
    ] {
        assert!(
            check_config(&ic_json::parse(bad).unwrap()).is_err(),
            "{bad}"
        );
    }
}
