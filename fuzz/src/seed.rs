//! Write seed inputs for every target into `corpus/<target>/`. Most come from
//! real, successful handshakes between the fixture client and server; raw ECH
//! reconstruction cases reach the parser without HPKE authentication. With
//! the fixed clock and DRBG the handshake seeds are the bytes the targets see.
//!
//! `cargo run --bin seed-corpus` from `fuzz/`.

use std::fs;
use std::path::Path;
use std::sync::Arc;

use ironsocketlayer::codec::{nested, put_u16, put_vec, Prefix};
use ironsocketlayer::config::ClientConfig;
use ironsocketlayer::quic::{QuicConnection, Version};
use ironsocketlayer::x509::{crl, ocsp};
use ironsocketlayer::{Connection, Level};
use isl_fuzz::*;

fn write(target: &str, name: &str, bytes: &[u8]) {
    let dir = Path::new("corpus").join(target);
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join(name), bytes).unwrap();
}

fn with_sel(sel: u8, body: &[u8]) -> Vec<u8> {
    let mut v = vec![sel];
    v.extend_from_slice(body);
    v
}

/// Run a TLS handshake, returning each side's flights in order.
fn tls(cc: Arc<ClientConfig>) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
    let mut c = Connection::client(cc, NAME).unwrap();
    let mut s = Connection::server(server_config()).unwrap();
    let (mut from_c, mut from_s) = (vec![], vec![]);
    for _ in 0..6 {
        let x = c.take_tls();
        if !x.is_empty() {
            s.read_tls(&x).unwrap();
            from_c.push(x);
        }
        let y = s.take_tls();
        if !y.is_empty() {
            c.read_tls(&y).unwrap();
            from_s.push(y);
        }
    }
    assert!(!c.is_handshaking() && !s.is_handshaking());
    (from_c, from_s)
}

fn refs(v: &[Vec<u8>]) -> Vec<&[u8]> {
    v.iter().map(|x| x.as_slice()).collect()
}

// Raw encoded hellos reach ECH reconstruction without requiring valid HPKE.
// The messages target supplies these bytes as both inner and outer, so the
// reference types must also be present in the extension list.
fn ech_reconstruction_seed(duplicate: bool) -> Vec<u8> {
    let mut body = vec![3, 3];
    body.extend_from_slice(&[9; 32]);
    body.extend_from_slice(&[0, 0, 2, 0x13, 1, 1, 0]);
    let markers: &[(u16, &[u8])] = if duplicate {
        &[(0xfd00, &[2, 0, 10]), (0xfd00, &[2, 0, 51])]
    } else {
        &[(0xfd00, &[4, 0, 10, 0, 51])]
    };
    nested(&mut body, Prefix::U16, |out| {
        for &(ty, value) in [(10, &[0, 2, 0, 29][..]), (51, &[0, 0][..])]
            .iter()
            .chain(markers.iter())
        {
            put_u16(out, ty);
            put_vec(out, Prefix::U16, value)?;
        }
        Ok(())
    })
    .unwrap();
    let result = ironsocketlayer::ech::reconstruct_inner(&body, &body, &[]);
    if duplicate {
        assert_eq!(
            result.unwrap_err().kind(),
            ironsocketlayer::ErrorKind::IllegalParameter
        );
    } else {
        result.unwrap();
    }
    with_sel(0, &body)
}

fn main() {
    let p = pki();

    // TLS: the default client (ECH, ALPN) and an external-PSK client.
    let (c1, s1) = tls(client_config());
    write("tls_server", "ech-full", &frame_chunks(&refs(&c1)));
    write(
        "tls_server",
        "ech-clienthello",
        &frame_chunks(&refs(&c1[..1])),
    );
    write(
        "tls_client",
        "ech-server-flights",
        &frame_chunks(&refs(&s1)),
    );

    let mut pc = (*client_config()).clone();
    pc.external_psk = Some(psk());
    pc.ech_configs = None;
    let (c2, _) = tls(Arc::new(pc));
    write("tls_server", "external-psk", &frame_chunks(&refs(&c2)));

    // A plain ClientHello for the fixed-capacity engine, which refuses ECH.
    let mut fc = (*client_config()).clone();
    fc.ech_configs = None;
    let fixed_hello = Connection::client(Arc::new(fc), NAME).unwrap().take_tls();
    write(
        "fixed_server",
        "plain-clienthello",
        &frame_chunks(&[&fixed_hello]),
    );
    // The same hello for both servers at once, whole and fragmented, without
    // ECH GREASE: the comparison skips hellos with ECH, which the fixed
    // engine does not implement.
    let mut dc = (*client_config()).clone();
    dc.ech_configs = None;
    dc.ech_grease = false;
    let plain_hello = Connection::client(Arc::new(dc), NAME).unwrap().take_tls();
    write(
        "hello_differential",
        "plain-clienthello",
        &frame_chunks(&[&plain_hello]),
    );
    let (head, tail) = plain_hello.split_at(7);
    write(
        "hello_differential",
        "fragmented-clienthello",
        &frame_chunks(&[head, tail]),
    );
    // The differential chain: through the intermediate and from the root,
    // for server and client usage.
    for sel in 0..4u8 {
        write("pki_differential", &format!("chain-{sel}"), &diff_seed(sel));
    }

    // The fixed-capacity client's view: the server's reply to its (fixed-DRBG,
    // so reproducible) ClientHello, from an owned server.
    {
        let cc = fixed_client_config();
        let mut rng = fixed_rng().unwrap();
        let mut buffers = FixedBuffers::default();
        let mut c = ironsocketlayer::fixed::Connection::client(
            &cc,
            NAME,
            &mut *rng,
            buffers.storage(),
            ironsocketlayer::fixed::Limits::default(),
        )
        .unwrap();
        let mut s = Connection::server(fixed_server_config()).unwrap();
        s.read_tls(c.outgoing()).unwrap();
        let n = c.outgoing().len();
        c.consume_outgoing(n).unwrap();
        let flight = s.take_tls();
        c.receive(&flight).unwrap();
        assert!(c.is_connected(), "the fixed client seed must complete");
        write("fixed_client", "server-flight", &frame_chunks(&[&flight]));
    }

    // ML-KEM-1024 key shares: the hybrid and the pure group.
    for (name, group) in [
        (
            "secp384r1mlkem1024",
            ironsocketlayer::enums::NamedGroup::SecP384r1MlKem1024,
        ),
        ("mlkem1024", ironsocketlayer::enums::NamedGroup::MlKem1024),
        ("mlkem512", ironsocketlayer::enums::NamedGroup::MlKem512),
    ] {
        let mut kc = (*client_config()).clone();
        kc.common.groups = vec![group];
        kc.initial_key_shares = 1;
        let (c3, _) = tls(Arc::new(kc));
        write("tls_server", name, &frame_chunks(&refs(&c3)));
    }

    // Handshake messages: the ClientHello body (record header and handshake
    // header stripped), and the record stream itself.
    let ch = &c1[0];
    write("messages", "clienthello", &with_sel(0, &ch[9..]));
    write(
        "messages",
        "ech-inner-reconstruction",
        &ech_reconstruction_seed(false),
    );
    write(
        "messages",
        "ech-duplicate-compression",
        &ech_reconstruction_seed(true),
    );
    write("messages", "framing", &with_sel(8, &ch[5..]));
    write("records", "clienthello", ch);
    write("records", "server-flights", &s1.concat());

    // QUIC: the Initial CRYPTO data, then the client's Handshake flight.
    const PARAMS: &[u8] = &[0x04, 0x04, 0x80, 0x10, 0x00, 0x00, 0x08, 0x01, 0x64];
    for (label, version, sel) in [("v1", Version::V1, 0x04u8), ("v2", Version::V2, 0x84)] {
        let mut qc = QuicConnection::client(client_config(), NAME, PARAMS, version).unwrap();
        let mut qs = QuicConnection::server(server_config(), PARAMS, version).unwrap();
        let mut client_data = vec![];
        for _ in 0..4 {
            while let Some((level, d)) = qc.write_handshake() {
                qs.read_handshake(level, &d).unwrap();
                client_data.push((level, d));
            }
            while let Some((level, d)) = qs.write_handshake() {
                qc.read_handshake(level, &d).unwrap();
            }
            while let Ok(Some(_)) = qc.next_key_change() {}
            while let Ok(Some(_)) = qs.next_key_change() {}
        }
        assert!(!qc.is_handshaking());
        assert_eq!(client_data[0].0, Level::Initial);
        let parts: Vec<&[u8]> = client_data.iter().map(|(_, d)| d.as_slice()).collect();
        write("quic_server", label, &with_sel(sel, &frame_chunks(&parts)));
    }

    // PKI inputs.
    let mut r = fixed_rng().unwrap();
    write("pki", "leaf", &with_sel(0, &p.leaf));
    write("pki", "leaf-chain", &with_sel(1, &p.leaf));
    write("pki", "ca-as-intermediate", &with_sel(1, &p.ca_cert));
    let crl = crl::build(
        &p.ca_cert,
        &p.ca_key,
        &[(&[9u8; 16], NOW - 60)],
        NOW - 3600,
        NOW + 3600,
        1,
        &mut *r,
    )
    .unwrap();
    write("pki", "crl", &with_sel(2, &crl));
    let resp = ocsp::build_response(
        &p.leaf,
        &p.ca_cert,
        &p.ca_key,
        ocsp::CertStatus::Good,
        NOW - 60,
        NOW + 3600,
        &mut *r,
    )
    .unwrap();
    write("pki", "ocsp", &with_sel(3, &resp));
    write("pki", "ech-configs", &with_sel(4, p.ech.config_list()));
    // Post-quantum certificates, self-signed, for the X.509 parser.
    for (name, kind) in [
        (
            "mldsa44-cert",
            ironsocketlayer::crypto::sign::KeyKind::MlDsa44,
        ),
        (
            "mldsa65-cert",
            ironsocketlayer::crypto::sign::KeyKind::MlDsa65,
        ),
        (
            "mldsa87-cert",
            ironsocketlayer::crypto::sign::KeyKind::MlDsa87,
        ),
    ] {
        let key = ironsocketlayer::crypto::sign::SigningKey::generate(kind, &mut *r).unwrap();
        let cert = ironsocketlayer::x509::self_signed(
            &ironsocketlayer::x509::CertificateParams {
                subject_cn: NAME,
                dns_names: &[NAME],
                ip_addresses: &[],
                not_before: NOW - 86_400,
                not_after: NOW + 86_400,
                is_ca: false,
                path_len: None,
                usage: &[ironsocketlayer::x509::Usage::ServerAuth],
                serial: [3; 16],
            },
            &key,
            &mut *r,
        )
        .unwrap();
        write("pki", name, &with_sel(0, &cert));
    }
    // The seeds are only useful if replaying them reproduces the handshake:
    // check that, along the targets' own code path.
    let replay = |mut conn: Connection, seed: &[u8]| {
        let _ = conn.take_tls();
        for chunk in chunks(seed) {
            conn.read_tls(chunk).unwrap();
            let _ = conn.take_tls();
        }
        assert!(
            !conn.is_handshaking(),
            "seed did not reproduce the handshake"
        );
    };
    replay(
        Connection::server(server_config()).unwrap(),
        &frame_chunks(&refs(&c1)),
    );
    replay(
        Connection::client(client_config(), NAME).unwrap(),
        &frame_chunks(&refs(&s1)),
    );
    println!("corpus written; TLS seeds replay to completed handshakes");
}
