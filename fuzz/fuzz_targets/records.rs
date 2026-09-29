//! The record framer: headers, lengths and the limits on them.
#![no_main]

use iron_socket_layer::record;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut buf = data.to_vec();
    while let Ok(Some(rec)) = record::take_record(&mut buf) {
        let _ = rec.content_type();
    }
});
