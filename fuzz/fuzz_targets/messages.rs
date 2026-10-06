//! Every handshake-message decoder, chosen by the first byte, plus the
//! handshake framing that feeds them. Decryption is not in the way here, so
//! this reaches the parsers the TLS targets can only reach in plaintext.
#![no_main]

use ironsocketlayer::msgs::{self, *};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((&sel, body)) = data.split_first() else {
        return;
    };
    let _ = match sel % 9 {
        0 => {
            // Exercise encoded inner hellos without an HPKE authentication gate.
            // Reusing the bytes as the outer also permits resolving references
            // to extension types carried alongside the compression marker.
            let _ = ironsocketlayer::ech::reconstruct_inner(body, body, &[]);
            ClientHello::decode(body).map(drop)
        }
        1 => ServerHello::decode(body).map(drop),
        2 => EncryptedExtensions::decode(body).map(drop),
        3 => CertificateRequest::decode(body).map(drop),
        4 => CertificateMsg::decode(body).map(drop),
        5 => CertificateVerify::decode(body).map(drop),
        6 => NewSessionTicket::decode(body).map(drop),
        7 => msgs::decode_key_update(body).map(drop),
        _ => {
            let mut buf = body.to_vec();
            while let Ok(Some(_)) = msgs::take_message(&mut buf, 1 << 16) {}
            Ok(())
        }
    };
});
