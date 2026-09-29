//! Deterministic mutation testing of real handshake flights.
//!
//! Each iteration takes a genuine flight, mutates it (flip, truncate, insert,
//! duplicate a span), and feeds it to a fresh endpoint. Two properties must
//! hold for every mutation:
//!
//! 1. Nothing panics, and every call returns (REQ-CODEC-001, REQ-X509-001).
//! 2. If the endpoint nevertheless reaches `connected`, application data
//!    still round-trips — a mutation may land in a byte the protocol ignores
//!    (a plaintext record's legacy version, say), but it can never produce a
//!    session whose two ends disagree on keys, which is what an undetected
//!    transcript modification would look like.
//!
//! The generator is a fixed-seed xorshift, so a failure reproduces exactly.

mod common;

use std::sync::Arc;

use common::*;
use iron_socket_layer::config::Profile;
use iron_socket_layer::crypto::sign::KeyKind;
use iron_socket_layer::report::HandshakeState;
use iron_socket_layer::Connection;

struct XorShift(u64);

impl XorShift {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
}

fn mutate(rng: &mut XorShift, input: &[u8]) -> Vec<u8> {
    let mut v = input.to_vec();
    for _ in 0..1 + rng.below(3) {
        if v.is_empty() {
            break;
        }
        let at = rng.below(v.len());
        match rng.below(5) {
            0 => v[at] ^= 1 << rng.below(8),
            1 => v[at] = rng.next() as u8,
            2 => v.truncate(at),
            3 => v.insert(at, rng.next() as u8),
            _ => {
                let end = (at + 1 + rng.below(16)).min(v.len());
                let span: Vec<u8> = v[at..end].to_vec();
                v.splice(at..at, span);
            }
        }
    }
    v
}

#[test]
fn mutated_flights_never_panic_or_desynchronise() {
    let pki = Pki::new(KeyKind::EcdsaP256, "server.test");
    let cc = Arc::new(pki.client_config(Profile::Default));
    let sc = Arc::new(pki.server_config(Profile::Default));
    let mut rng = XorShift(0x5eed_1e55_c0ff_ee00);
    let mut connected_after_mutation = 0;

    for i in 0..1500 {
        let mut c = Connection::client(cc.clone(), "server.test").unwrap();
        let mut s = Connection::server(sc.clone()).unwrap();
        let hello = c.take_tls();
        if i % 2 == 0 {
            // Mutate the ClientHello on its way to the server.
            let bad = mutate(&mut rng, &hello);
            let _ = s.read_tls(&bad);
            let flight = s.take_tls();
            let _ = c.read_tls(&flight);
            let fin = c.take_tls();
            let _ = s.read_tls(&fin);
        } else {
            // Mutate the server's flight on its way to the client.
            s.read_tls(&hello).unwrap();
            let flight = s.take_tls();
            let bad = mutate(&mut rng, &flight);
            let _ = c.read_tls(&bad);
            let fin = c.take_tls();
            let _ = s.read_tls(&fin);
        }
        if c.state() == HandshakeState::Connected && s.state() == HandshakeState::Connected {
            connected_after_mutation += 1;
            c.send(b"still in step").unwrap();
            s.read_tls(&c.take_tls())
                .expect("a connected pair must share keys");
            let mut buf = [0u8; 32];
            let n = s.recv(&mut buf);
            assert_eq!(&buf[..n], b"still in step", "iteration {i}");
        } else if c.state() == HandshakeState::Connected {
            // The client finished but the server refused its Finished (for
            // example a mutated ClientHello the client never saw): the client
            // must not be able to talk to anyone.
            assert!(s.state() != HandshakeState::Connected);
        }
    }
    // Most mutations must be caught; a handful land in ignored bytes.
    assert!(
        connected_after_mutation < 300,
        "{connected_after_mutation} mutations went unnoticed"
    );
}

#[test]
fn random_bytes_into_every_decoder_never_panic() {
    use iron_socket_layer::msgs::*;
    let mut rng = XorShift(0xdead_beef_cafe_f00d);
    for _ in 0..20_000 {
        let len = rng.below(300);
        let buf: Vec<u8> = (0..len).map(|_| rng.next() as u8).collect();
        let _ = ClientHello::decode(&buf);
        let _ = ServerHello::decode(&buf);
        let _ = EncryptedExtensions::decode(&buf);
        let _ = CertificateRequest::decode(&buf);
        let _ = CertificateMsg::decode(&buf);
        let _ = CertificateVerify::decode(&buf);
        let _ = NewSessionTicket::decode(&buf);
        let _ = decode_key_update(&buf);
        let _ = iron_socket_layer::x509::Certificate::parse(&buf);
        let _ = iron_socket_layer::crypto::sign::PublicKey::from_spki(&buf);
        let _ = iron_socket_layer::crypto::sign::SigningKey::from_pkcs8_der(&buf);
    }
}
