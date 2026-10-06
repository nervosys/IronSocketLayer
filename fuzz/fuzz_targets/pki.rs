//! X.509 certificates and path validation, CRLs, OCSP responses and ECH
//! configuration lists: everything a peer or a network fetch hands us as DER
//! or TLS-encoded bytes outside the handshake itself.
#![no_main]

use ironsocketlayer::x509::{self, crl::CrlStore, Certificate, ServerName, Usage, VerifyOptions};
use isl_fuzz::{client_config, pki, NAME, NOW};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((&sel, body)) = data.split_first() else {
        return;
    };
    let p = pki();
    let schemes = client_config().common.schemes.clone();
    match sel % 5 {
        0 => {
            if let Ok(c) = Certificate::parse(body) {
                let _ = (
                    c.serial(),
                    c.der(),
                    c.spki_der(),
                    c.subject_der(),
                    c.issuer_der(),
                );
                let _ = (c.not_before(), c.not_after(), c.is_ca(), c.common_name());
                let _ = (c.dns_names(), c.ip_addresses(), c.signature_scheme());
                let _ = c
                    .subject_public_key()
                    .map(|k| (k.kind_id(), k.classical_bits()));
            }
            let _ = x509::verify_name(body, &ServerName::Dns(NAME));
        }
        1 => {
            // The input as a leaf, then as an intermediate under a real leaf.
            let opts = VerifyOptions {
                now: NOW,
                usage: Usage::ServerAuth,
                allowed_schemes: &schemes,
                max_depth: 4,
                min_rsa_bits: 2048,
                crls: None,
                require_crl: false,
            };
            let _ = x509::verify_chain(body, &[], &p.roots, &opts);
            let _ = x509::verify_chain(&p.leaf, &[body], &p.roots, &opts);
        }
        2 => {
            let mut store = CrlStore::new();
            if store.add_der(body).is_ok() {
                let opts = VerifyOptions {
                    now: NOW,
                    usage: Usage::ServerAuth,
                    allowed_schemes: &schemes,
                    max_depth: 4,
                    min_rsa_bits: 2048,
                    crls: Some(&store),
                    require_crl: true,
                };
                let _ = x509::verify_chain(&p.leaf, &[], &p.roots, &opts);
            }
        }
        3 => {
            let ca = Certificate::parse(&p.ca_cert).unwrap();
            let _ = x509::ocsp::verify_response(
                body,
                &p.leaf,
                ca.subject_der(),
                ca.spki_der(),
                NOW,
                &schemes,
            );
        }
        _ => {
            if let Ok(list) = ironsocketlayer::ech::parse_config_list(body) {
                for c in &list {
                    let _ = (c.usable_suite(), c.hpke_info());
                }
            }
            let _ = ironsocketlayer::ech::select_config(body);
        }
    }
});
