//! A whole TLS server connection, fed the input as a sequence of reads. The
//! server has ECH, 0-RTT, an external PSK, optional client certificates and
//! HelloRetryRequest cookies switched on, so a ClientHello can reach all of
//! them. Seeds are real ClientHellos (`seed-corpus`).
#![no_main]

use ironsocketlayer::Connection;
use isl_fuzz::{chunks, server_config};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut s = Connection::server(server_config()).unwrap();
    let mut buf = [0u8; 256];
    for chunk in chunks(data) {
        let failed = s.read_tls(chunk).is_err();
        let _ = s.take_tls();
        while s.recv(&mut buf) > 0 {}
        if failed {
            // A failed connection must stay failed, whatever arrives next.
            assert!(s.read_tls(b"\x16\x03\x03\x00\x01\x00").is_err());
            assert!(s.send(b"x").is_err());
            break;
        }
    }
    let _ = s.report().to_json();
});
