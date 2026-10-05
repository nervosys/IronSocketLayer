//! The fixed-capacity TLS server (`iron_socket_layer::fixed`), fed the input
//! as a sequence of reads into caller-owned buffers. A refused input must
//! latch: the next call returns the same error and nothing is queued.
//! Seeds include a real plain ClientHello (`seed-corpus`).
#![no_main]

use iron_socket_layer::fixed::{Connection, Limits, Storage};
use isl_fuzz::{chunks, fixed_rng, fixed_server_config};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let sc = fixed_server_config();
    let mut rng = fixed_rng().unwrap();
    let (mut record, mut handshake, mut outgoing, mut application) = (
        vec![0u8; 16_645],
        vec![0u8; 32_768],
        vec![0u8; 65_536],
        vec![0u8; 32_768],
    );
    let (mut certificates, mut private_key, mut public_key, mut scratch) = (
        vec![0u8; 32_768],
        vec![0u8; 3_234],
        vec![0u8; 1_665],
        vec![0u8; 32_768],
    );
    let storage = Storage {
        record: &mut record,
        handshake: &mut handshake,
        outgoing: &mut outgoing,
        application: &mut application,
        certificates: &mut certificates,
        private_key: &mut private_key,
        public_key: &mut public_key,
        scratch: &mut scratch,
    };
    let mut s = Connection::server(&sc, &mut *rng, storage, Limits::default()).unwrap();
    let mut buf = [0u8; 256];
    for chunk in chunks(data) {
        match s.receive(chunk) {
            Ok(()) => {
                let n = s.outgoing().len();
                s.consume_outgoing(n).unwrap();
                while s.read_application(&mut buf).unwrap() > 0 {}
            }
            Err(e) => {
                assert_eq!(s.receive(b"\x16\x03\x03\x00\x01\x00").unwrap_err(), e);
                assert!(s.outgoing().is_empty());
                break;
            }
        }
    }
});
