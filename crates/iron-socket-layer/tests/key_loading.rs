//! Loading private keys from PKCS#8, against an independent implementation.
//!
//! The fixtures in `tests/data/throwaway-keys` were made by OpenSSL 3.5 (see
//! the README there): each key, the public key OpenSSL derives from it, and a
//! signature OpenSSL made with it. A key loaded here must have the same public
//! key as OpenSSL says, must verify OpenSSL's signature, and must produce
//! signatures of its own that verify. `REQ-SIG-004`.

use iron_socket_layer::crypto::sign::{verify, PublicKey, SigningKey};
use iron_socket_layer::enums::SignatureScheme;
use iron_socket_layer::ErrorKind;

fn fixture(name: &str) -> Vec<u8> {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/throwaway-keys/");
    std::fs::read(format!("{path}{name}")).unwrap_or_else(|e| panic!("{name}: {e}"))
}

fn pem(name: &str) -> String {
    String::from_utf8(fixture(name)).unwrap()
}

fn rng() -> ic_drbg::Rng {
    ic_drbg::Rng::from_os().unwrap()
}

/// Every key type OpenSSL wrote, with the scheme it signed under.
const KEYS: &[(&str, SignatureScheme)] = &[
    ("p256", SignatureScheme::EcdsaSecp256r1Sha256),
    ("p384", SignatureScheme::EcdsaSecp384r1Sha384),
    ("p521", SignatureScheme::EcdsaSecp521r1Sha512),
    ("ed25519", SignatureScheme::Ed25519),
    ("rsa2048", SignatureScheme::RsaPssRsaeSha256),
    ("mldsa44-seed", SignatureScheme::MlDsa44),
    ("mldsa65-seed", SignatureScheme::MlDsa65),
    ("mldsa87-seed", SignatureScheme::MlDsa87),
];

#[test]
fn keys_written_by_openssl_load_with_the_public_key_openssl_derives() {
    let msg = fixture("msg.bin");
    for (name, scheme) in KEYS {
        let key = SigningKey::from_pem(&pem(&format!("{name}.pem")))
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        let spki = fixture(&format!("{name}.spki.der"));
        assert_eq!(
            key.spki(),
            &spki[..],
            "{name}: public key differs from OpenSSL's"
        );
        assert!(key.schemes().contains(scheme), "{name}");

        let public = PublicKey::from_spki(&spki).unwrap();
        // OpenSSL's signature verifies under the key as we read it...
        verify(*scheme, &public, &msg, &fixture(&format!("{name}.sig")))
            .unwrap_or_else(|e| panic!("{name}: OpenSSL's signature: {e}"));
        // ...and so does ours.
        let ours = key.sign(*scheme, &msg, &mut rng()).unwrap();
        verify(*scheme, &public, &msg, &ours).unwrap_or_else(|e| panic!("{name}: ours: {e}"));
    }
}

#[test]
fn der_and_pem_load_the_same_key() {
    for (name, _) in KEYS {
        let text = pem(&format!("{name}.pem"));
        let b64: String = text.lines().filter(|l| !l.starts_with("-----")).collect();
        let der = decode_base64(&b64);
        let from_der = SigningKey::from_pkcs8_der(&der).unwrap();
        let from_pem = SigningKey::from_pem(&text).unwrap();
        assert_eq!(from_der.spki(), from_pem.spki(), "{name}");
    }
}

#[test]
fn ml_dsa_seed_and_both_forms_are_the_same_key() {
    for set in ["mldsa44", "mldsa65", "mldsa87"] {
        let seed = SigningKey::from_pem(&pem(&format!("{set}-seed.pem"))).unwrap();
        let both = SigningKey::from_pem(&pem(&format!("{set}-both.pem"))).unwrap();
        assert_eq!(seed.spki(), both.spki(), "{set}");
        assert_eq!(
            both.spki(),
            &fixture(&format!("{set}-both.spki.der"))[..],
            "{set}"
        );
    }
}

#[test]
fn an_ml_dsa_file_whose_halves_disagree_is_refused() {
    for set in ["mldsa44", "mldsa65", "mldsa87"] {
        let text = pem(&format!("{set}-both.pem"));
        let b64: String = text.lines().filter(|l| !l.starts_with("-----")).collect();
        let mut der = decode_base64(&b64);
        // The expanded key is the last field: change its final byte.
        let last = der.len() - 1;
        der[last] ^= 1;
        let err = SigningKey::from_pkcs8_der(&der).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidConfig, "{set}: {err}");
        assert!(
            err.to_string().contains("does not match its seed"),
            "{set}: {err}"
        );
    }
}

#[test]
fn forms_that_cannot_sign_or_are_not_pkcs8_are_refused() {
    for (name, why) in [
        ("x25519.pem", "an X25519 key cannot sign"),
        ("rsa1024.pem", "RSA below 2048 bits"),
        ("p256-sec1.pem", "SEC1, not PKCS#8"),
        ("p256-encrypted.pem", "encrypted PKCS#8"),
    ] {
        let err = match SigningKey::from_pem(&pem(name)) {
            Ok(_) => panic!("{name} loaded: {why}"),
            Err(e) => e,
        };
        assert_eq!(
            err.kind(),
            ErrorKind::InvalidConfig,
            "{name} ({why}): {err}"
        );
    }
    assert_eq!(
        SigningKey::from_pem("no key here").err().map(|e| e.kind()),
        Some(ErrorKind::InvalidConfig)
    );
}

/// Standard base64, enough for the fixtures (no dependency for one test).
fn decode_base64(s: &str) -> Vec<u8> {
    let val = |c: u8| match c {
        b'A'..=b'Z' => c - b'A',
        b'a'..=b'z' => c - b'a' + 26,
        b'0'..=b'9' => c - b'0' + 52,
        b'+' => 62,
        b'/' => 63,
        _ => panic!("not base64: {c}"),
    };
    let bytes: Vec<u8> = s.bytes().filter(|&c| c != b'=').collect();
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    for chunk in bytes.chunks(4) {
        let mut acc = 0u32;
        for (i, &c) in chunk.iter().enumerate() {
            acc |= u32::from(val(c)) << (18 - 6 * i);
        }
        out.extend_from_slice(&acc.to_be_bytes()[1..chunk.len()]);
    }
    out
}
