//! Once IronCrypto is in its error state, no connection is made and no
//! record is sent or opened. Since IronCrypto 0.3 its hashes and MACs refuse
//! there as well, so a transcript hash, a Finished MAC or a key pin cannot
//! be made from a module that failed. `REQ-ERR-002`.
//!
//! The state cannot be left, so this file is a process of its own and has
//! one test.

mod common;

use std::sync::Arc;

use common::*;
use ironsocketlayer::config::{PeerVerification, Profile};
use ironsocketlayer::crypto::sign::KeyKind;
use ironsocketlayer::crypto::HashAlg;
use ironsocketlayer::error::Recovery;
use ironsocketlayer::ErrorKind;

/// REQ-ERR-002: every refusal is `error:fips-module`, whose action is to fix
/// the environment. Not `error:entropy`: that one is retried, and a module
/// in its error state never leaves it.
#[test]
fn nothing_connects_or_is_sent_in_the_error_state() {
    let pki = Pki::new(KeyKind::EcdsaP256, "server.test");
    let client = Arc::new(pki.client_config(Profile::Default));
    let server = Arc::new(pki.server_config(Profile::Default));
    let (mut c, mut s) = connect(client.clone(), server.clone(), "server.test").unwrap();
    exchange(&mut c, &mut s);
    // A record sealed while the module worked, to be opened after.
    c.send(b"sealed before").unwrap();
    let record = c.take_tls();

    ic_core::module::enter_error_state();

    let refused = |e: ironsocketlayer::Error| {
        assert_eq!(e.kind(), ErrorKind::FipsModule, "{e}");
        assert_eq!(e.recovery(), Recovery::FixEnvironment, "{e}");
        assert!(!e.kind().retryable(), "{e}");
    };
    let failed = connect(client, server, "server.test").err().unwrap();
    refused(failed.client.or(failed.server).unwrap());
    refused(c.send(b"after").unwrap_err());
    refused(s.read_tls(&record).unwrap_err());
    refused(HashAlg::Sha256.digest(b"transcript").unwrap_err());
    refused(PeerVerification::pin_spki(&pki.server_spki()).unwrap_err());
}
