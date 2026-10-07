//! The owned and the fixed-capacity clients, configured alike, must agree on
//! whether the server's plaintext records (ServerHello, HelloRetryRequest,
//! ChangeCipherSpec, alerts) are refused. With the fixed DRBG both send a
//! ClientHello with the same session id, suites, groups and key-share group,
//! so a ServerHello means the same to both. Their key shares, and so their
//! handshake keys, differ: the input is cut before the first
//! application_data record, which only one of them could decrypt. As in
//! `hello_differential`, the fixed engine's capacity limits are not compared.
#![no_main]

use ironsocketlayer::fixed::{Connection as Fixed, Limits};
use ironsocketlayer::{Connection, ErrorKind};
use isl_fuzz::{chunks, fixed_client_config, fixed_rng, FixedBuffers, NAME};
use libfuzzer_sys::fuzz_target;

/// The length of the stream's prefix before its first application_data
/// record (a partial record at the end is kept).
fn plaintext_prefix(stream: &[u8]) -> usize {
    let mut i = 0usize;
    while i + 5 <= stream.len() {
        if stream[i] == 23 {
            return i;
        }
        i += 5 + usize::from(u16::from_be_bytes([stream[i + 3], stream[i + 4]]));
    }
    stream.len()
}

fuzz_target!(|data: &[u8]| {
    let cc = fixed_client_config();
    let mut owned = Connection::client(cc.clone(), NAME).unwrap();
    let _ = owned.take_tls();
    let mut rng = fixed_rng().unwrap();
    let mut buffers = FixedBuffers::default();
    let mut fixed =
        Fixed::client(&cc, NAME, &mut *rng, buffers.storage(), Limits::default()).unwrap();
    let n = fixed.outgoing().len();
    fixed.consume_outgoing(n).unwrap();

    let parts = chunks(data);
    let mut left = plaintext_prefix(&parts.concat());
    let (mut o, mut f) = (None, None);
    for chunk in parts {
        let chunk = &chunk[..chunk.len().min(left)];
        left -= chunk.len();
        if chunk.is_empty() {
            break;
        }
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
    if f == Some(ErrorKind::CapacityExceeded) || o == Some(ErrorKind::CapacityExceeded) {
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
