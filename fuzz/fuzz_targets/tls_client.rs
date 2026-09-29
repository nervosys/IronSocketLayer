//! A TLS client that has sent its ClientHello, fed the input as the server's
//! reply. With the fixed DRBG the ClientHello is the same every run, so a
//! recorded server flight (`seed-corpus`) decrypts, and the fuzzer mutates
//! from a handshake that would otherwise succeed.
#![no_main]

use iron_socket_layer::Connection;
use isl_fuzz::{chunks, client_config, NAME};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut c = Connection::client(client_config(), NAME).unwrap();
    let _ = c.take_tls();
    let mut buf = [0u8; 256];
    for chunk in chunks(data) {
        let failed = c.read_tls(chunk).is_err();
        let _ = c.take_tls();
        while c.recv(&mut buf) > 0 {}
        if failed {
            assert!(c.read_tls(b"\x16\x03\x03\x00\x01\x00").is_err());
            break;
        }
    }
    let _ = c.report().to_json();
});
