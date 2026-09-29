//! A QUIC server's TLS layer: CRYPTO-frame data at a level the fuzzer picks,
//! including the transport-parameters extension a ClientHello carries.
#![no_main]

use iron_socket_layer::quic::{QuicConnection, Version};
use iron_socket_layer::Level;
use isl_fuzz::{chunks, server_config};
use libfuzzer_sys::fuzz_target;

/// initial_max_data = 1 MiB, initial_max_streams_bidi = 100.
const PARAMS: &[u8] = &[0x04, 0x04, 0x80, 0x10, 0x00, 0x00, 0x08, 0x01, 0x64];

fuzz_target!(|data: &[u8]| {
    let Some((&sel, rest)) = data.split_first() else {
        return;
    };
    let version = if sel & 0x80 != 0 {
        Version::V2
    } else {
        Version::V1
    };
    let mut q = QuicConnection::server(server_config(), PARAMS, version).unwrap();
    for (i, chunk) in chunks(rest).into_iter().enumerate() {
        let level = match (sel >> (2 * (i % 3))) & 3 {
            0 | 3 => Level::Initial,
            1 => Level::Handshake,
            _ => Level::Application,
        };
        if q.read_handshake(level, chunk).is_err() {
            break;
        }
        while q.write_handshake().is_some() {}
        while let Ok(Some(_)) = q.next_key_change() {}
    }
    let _ = q.peer_transport_parameters();
});
