//! The owned and the fixed-capacity servers, configured alike, must agree on
//! whether a client's first flight is refused. Two documented differences
//! are not compared: the fixed engine's capacity limits, and the extensions
//! of features the fixed engine does not implement (ECH, post-handshake
//! authentication, PSKs and early data), which it ignores as unknown where
//! the owned engine checks their syntax.
#![no_main]

use std::sync::Arc;

use ironsocketlayer::fixed::{Connection as Fixed, Limits};
use ironsocketlayer::{Connection, ErrorKind};
use isl_fuzz::{
    chunks, client_hello_extension_types, fixed_rng, fixed_server_config, FixedBuffers,
};
use libfuzzer_sys::fuzz_target;

/// Extensions of features the fixed engine does not implement: ECH,
/// pre_shared_key, early_data, psk_key_exchange_modes, post_handshake_auth.
const UNIMPLEMENTED_IN_FIXED: &[u16] = &[0xfe0d, 0x0029, 0x002a, 0x002d, 0x0031];

fuzz_target!(|data: &[u8]| {
    let sc = fixed_server_config();
    let mut owned = Connection::server(Arc::clone(&sc)).unwrap();
    let mut rng = fixed_rng().unwrap();
    let mut buffers = FixedBuffers::default();
    let mut fixed = Fixed::server(&sc, &mut *rng, buffers.storage(), Limits::default()).unwrap();
    let (mut o, mut f) = (None, None);
    for chunk in chunks(data) {
        if o.is_none() {
            if let Err(e) = owned.read_tls(chunk) {
                o = Some(e.kind());
            }
            let _ = owned.take_tls();
        }
        if f.is_none() {
            match fixed.receive(chunk) {
                Ok(()) => {
                    let n = fixed.outgoing().len();
                    let _ = fixed.consume_outgoing(n);
                }
                Err(e) => f = Some(e.kind()),
            }
        }
    }
    if f == Some(ErrorKind::CapacityExceeded)
        || o == Some(ErrorKind::CapacityExceeded)
        || client_hello_extension_types(&chunks(data).concat())
            .is_some_and(|t| t.iter().any(|x| UNIMPLEMENTED_IN_FIXED.contains(x)))
    {
        return;
    }
    if o.is_some() != f.is_some() {
        // On Windows the abort can beat libFuzzer to writing the crash file:
        // print the input so it can be reproduced.
        let hex: String = data.iter().map(|b| format!("{b:02x}")).collect();
        eprintln!("DISAGREE owned={o:?} fixed={f:?} input={hex}");
        panic!("owned {o:?} / fixed {f:?}: the engines disagree");
    }
});
