//! The two path validators, `x509::verify_chain` and
//! `x509::verify_chain_fixed`, must reach the same verdict, down to the
//! error kind. The fuzzer mutates the to-be-signed bytes of an intermediate
//! (with name constraints) and a leaf; the harness re-signs them with the
//! fixture keys, so signatures always verify and every later check runs.
#![no_main]

use ironsocketlayer::x509::{self, Usage, VerifyOptions};
use isl_fuzz::{client_config, diff_pki, sign_tbs, NOW};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 3 {
        return;
    }
    let sel = data[0];
    let n = usize::from(u16::from_be_bytes([data[1], data[2]]));
    let rest = &data[3..];
    if n > rest.len() {
        return;
    }
    let (int_tbs, leaf_tbs) = rest.split_at(n);
    let d = diff_pki();
    let schemes = client_config().common.schemes.clone();
    let opts = VerifyOptions {
        now: NOW,
        usage: if sel & 2 == 0 {
            Usage::ServerAuth
        } else {
            Usage::ClientAuth
        },
        allowed_schemes: &schemes,
        max_depth: 4,
        min_rsa_bits: 2048,
        crls: None,
        require_crl: false,
    };
    let (leaf, ints) = if sel & 1 == 0 {
        (
            sign_tbs(leaf_tbs, &d.int_key),
            vec![sign_tbs(int_tbs, &d.root_key)],
        )
    } else {
        (sign_tbs(leaf_tbs, &d.root_key), Vec::new())
    };
    let ints: Vec<&[u8]> = ints.iter().map(Vec::as_slice).collect();
    let owned = x509::verify_chain(&leaf, &ints, &d.roots, &opts)
        .map(|_| ())
        .map_err(|e| e.kind());
    let fixed = x509::verify_chain_fixed(&leaf, &ints, &d.roots, &opts)
        .map(|_| ())
        .map_err(|e| e.kind());
    assert_eq!(owned, fixed, "the path validators disagree");
});
