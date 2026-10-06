//! RFC 8446 conformance of each side toward a non-conforming peer.
//!
//! Each case takes a real hello from one side, changes one field, and hands
//! it to the other side, which must refuse it with the error for that rule.
//! The hellos are plaintext, so a single field can be changed without
//! touching any keys; the checks on encrypted messages are covered elsewhere.

mod common;

/// REQ-MSG-018: the RFC 8446 section 4.2 table governs every decoder.
/// REQ-MSG-019: RFCs 8449, 9001 and 9849 supply the additional contexts.
#[test]
fn recognized_extensions_require_their_standard_message_context() {
    // Column order: CH, SH, HRR, EE, CR, CT, NST. Wire IDs and allowed
    // columns are transcribed from the published table, independently of the checker.
    let table: &[(u16, &[usize])] = &[
        (0, &[0, 3]),
        (1, &[0, 3]),
        (5, &[0, 4, 5]),
        (10, &[0, 3]),
        (13, &[0, 4]),
        (16, &[0, 3]),
        (18, &[0, 4, 5]),
        (21, &[0]),
        (41, &[0, 1]),
        (42, &[0, 3, 6]),
        (43, &[0, 1, 2]),
        (44, &[0, 2]),
        (45, &[0]),
        (47, &[0, 4]),
        (48, &[4]),
        (49, &[0]),
        (50, &[0, 4]),
        (51, &[0, 1, 2]),
        // RFC 8449 section 7, RFC 9001 section 8.2, RFC 9849 section 11.1.
        (28, &[0, 3]),
        (57, &[0, 3]),
        (0xfe0d, &[0, 2, 3]),
        // RFC 9849 section 5.1: only in EncodedClientHelloInner, which
        // reconstruct_inner processes before the ordinary ClientHello decoder.
        (0xfd00, &[]),
    ];
    let pki = Pki::new(KeyKind::EcdsaP256, "server.test");
    let mut client =
        Connection::client(Arc::new(pki.client_config(Profile::Default)), "server.test").unwrap();
    let (_, hello) = first_message(&client.take_tls());
    let decode = |column: usize, ty: u16, value: &[u8]| -> Result<()> {
        let mut extensions = Vec::new();
        if column == 1 || column == 2 {
            extensions.extend_from_slice(&[0, 43, 0, 2, 3, 4]);
        } else if column == 4 {
            extensions.extend_from_slice(&[0, 13, 0, 4, 0, 2, 4, 3]);
        }
        put_u16(&mut extensions, ty);
        put_vec(&mut extensions, Prefix::U16, value).unwrap();
        let mut body = Vec::new();
        match column {
            0 => ClientHello::decode(&with_client_hello_extension(&hello, ty, Some(value), false))
                .map(|_| ()),
            1 | 2 => {
                body.extend_from_slice(&[3, 3]);
                body.extend_from_slice(if column == 2 {
                    &msgs::HRR_RANDOM
                } else {
                    &[7; 32]
                });
                body.extend_from_slice(&[0, 0x13, 1, 0]);
                put_vec(&mut body, Prefix::U16, &extensions).unwrap();
                ServerHello::decode(&body).map(|_| ())
            }
            3 => {
                put_vec(&mut body, Prefix::U16, &extensions).unwrap();
                EncryptedExtensions::decode(&body).map(|_| ())
            }
            4 => {
                body.push(0);
                put_vec(&mut body, Prefix::U16, &extensions).unwrap();
                CertificateRequest::decode(&body).map(|_| ())
            }
            5 => {
                let mut entry = Vec::new();
                put_vec(&mut entry, Prefix::U24, &[1]).unwrap();
                put_vec(&mut entry, Prefix::U16, &extensions).unwrap();
                body.push(0);
                put_vec(&mut body, Prefix::U24, &entry).unwrap();
                CertificateMsg::decode(&body).map(|_| ())
            }
            6 => {
                body.extend_from_slice(&[0; 8]);
                body.extend_from_slice(&[0, 0, 1, 1]);
                put_vec(&mut body, Prefix::U16, &extensions).unwrap();
                msgs::NewSessionTicket::decode(&body).map(|_| ())
            }
            _ => unreachable!(),
        }
    };
    for column in 0..7 {
        // Unknown types remain structurally acceptable; response negotiation is
        // checked separately by the state machines.
        decode(column, 0xbeef, &[7]).unwrap();
        for &(ty, allowed) in table {
            if !allowed.contains(&column) {
                let err = decode(column, ty, &[]).expect_err("forbidden extension was accepted");
                assert_eq!(
                    err.kind(),
                    ErrorKind::IllegalParameter,
                    "type {ty}, column {column}"
                );
                assert!(err
                    .to_string()
                    .contains("extension forbidden in this handshake message"));
            }
        }
    }
    // Legal, recognized extensions without dedicated decoders still get ignored.
    for &(ty, columns) in &[
        (1, &[0usize, 3][..]),
        (18, &[0usize, 4, 5][..]),
        (21, &[0usize][..]),
        (47, &[0usize, 4][..]),
        (48, &[4usize][..]),
    ] {
        for &column in columns {
            decode(column, ty, &[0, 0]).unwrap();
        }
    }
    for &(ty, columns, value) in &[
        (28, &[0usize, 3][..], &[0u8, 64][..]),
        (57, &[0usize, 3][..], &[7u8][..]),
        (0xfe0d, &[0usize][..], &[1u8][..]),
        (0xfe0d, &[2usize][..], &[7u8; 8][..]),
        (0xfe0d, &[3usize][..], &[0u8, 0][..]),
    ] {
        for &column in columns {
            decode(column, ty, value).unwrap();
        }
    }
    // Valid compression replaces supported_groups with a reference in the
    // encoded inner hello. Reconstruction removes the marker before decoding.
    let mut inner = ClientHello::decode(&hello).unwrap();
    inner.session_id.clear();
    inner.ech = Some(msgs::EchHello::Inner);
    let encoded = with_client_hello_extension(&inner.encode().unwrap(), 10, None, false);
    let encoded = with_client_hello_extension(&encoded, 0xfd00, Some(&[2, 0, 10]), false);
    assert_eq!(
        ClientHello::decode(&encoded).err().map(|e| e.kind()),
        Some(ErrorKind::IllegalParameter)
    );
    let rebuilt =
        ironsocketlayer::ech::reconstruct_inner(&encoded, &hello, &inner.session_id).unwrap();
    let rebuilt = ClientHello::decode(&rebuilt).unwrap();
    assert_eq!(rebuilt.groups, inner.groups);
    assert_eq!(rebuilt.ech, inner.ech);
    assert!(!rebuilt
        .other_extensions
        .contains(&ironsocketlayer::enums::ExtensionType::EchOuterExtensions));
    // A forbidden ClientHello extension also produces the required fatal alert.
    for ty in [48, 0xfd00] {
        let mut server = Connection::server(Arc::new(pki.server_config(Profile::Default))).unwrap();
        let err = server
            .read_tls(&record_of(
                HandshakeType::ClientHello,
                &with_client_hello_extension(&hello, ty, Some(&[]), false),
            ))
            .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::IllegalParameter);
        assert_eq!(server.report().state, Some(HandshakeState::Failed));
        assert_eq!(server.take_tls(), [21, 3, 3, 0, 2, 2, 47]);
    }
}

use std::sync::Arc;

use common::*;
use ironsocketlayer::codec::{put_u16, put_vec, Prefix, Reader};
use ironsocketlayer::config::Profile;
use ironsocketlayer::crypto::sign::KeyKind;
use ironsocketlayer::enums::{
    CipherSuite, ContentType, HandshakeType, NamedGroup, ProtocolVersion,
};
use ironsocketlayer::msgs::{
    self, CertificateMsg, CertificateRequest, ClientHello, EncryptedExtensions, ServerHello,
};
use ironsocketlayer::record;
use ironsocketlayer::report::HandshakeState;
use ironsocketlayer::{Connection, ErrorKind, Result};

/// The body of the first handshake message in a flight's first record.
fn first_message(flight: &[u8]) -> (HandshakeType, Vec<u8>) {
    assert_eq!(flight[0], 22, "a handshake record first");
    let len = u16::from_be_bytes([flight[3], flight[4]]) as usize;
    let rec = &flight[5..5 + len];
    let ty = HandshakeType::from_wire(rec[0]);
    let n = u32::from_be_bytes([0, rec[1], rec[2], rec[3]]) as usize;
    (ty, rec[4..4 + n].to_vec())
}

/// A plaintext handshake record carrying one message.
fn record_of(ty: HandshakeType, body: &[u8]) -> Vec<u8> {
    let msg = msgs::frame(ty, body).unwrap();
    let mut out = Vec::new();
    record::write_plaintext(ContentType::Handshake, &msg, &mut out);
    out
}

/// Replace one extension while preserving a real ClientHello's other fields.
fn with_client_hello_extension(body: &[u8], ty: u16, value: Option<&[u8]>, first: bool) -> Vec<u8> {
    let mut reader = Reader::new(body);
    reader.u16().unwrap();
    reader.take(32).unwrap();
    reader.vec8().unwrap();
    reader.vec16().unwrap();
    reader.vec8().unwrap();
    let prefix_len = body.len() - reader.remaining();
    let mut original = reader.sub16().unwrap();
    reader.finish().unwrap();
    let mut retained = Vec::new();
    while !original.is_empty() {
        let original_type = original.u16().unwrap();
        let original_value = original.vec16().unwrap();
        if original_type != ty {
            put_u16(&mut retained, original_type);
            put_vec(&mut retained, Prefix::U16, original_value).unwrap();
        }
    }
    let mut extension = Vec::new();
    if let Some(value) = value {
        put_u16(&mut extension, ty);
        put_vec(&mut extension, Prefix::U16, value).unwrap();
    }
    let extensions = if first {
        [extension, retained].concat()
    } else {
        [retained, extension].concat()
    };
    let mut encoded = body[..prefix_len].to_vec();
    put_vec(&mut encoded, Prefix::U16, &extensions).unwrap();
    encoded
}

fn refused(r: Result<()>, want: &str) {
    let e = r.expect_err(want);
    assert!(e.to_string().contains(want), "wanted {want:?}, got {e}");
}

/// The server refuses ClientHellos that break RFC 8446's rules.
#[test]
fn the_server_refuses_non_conforming_client_hellos() {
    let pki = Pki::new(KeyKind::EcdsaP256, "server.test");
    let cc = Arc::new(pki.client_config(Profile::Default));
    let sc = Arc::new(pki.server_config(Profile::Default).with_alpn(&[b"h2"]));
    let hello = || {
        let mut c = Connection::client(cc.clone(), "server.test").unwrap();
        let (ty, body) = first_message(&c.take_tls());
        assert_eq!(ty, HandshakeType::ClientHello);
        ClientHello::decode(&body).unwrap()
    };
    let offer = |ch: &ClientHello| {
        let mut s = Connection::server(sc.clone()).unwrap();
        s.read_tls(&record_of(
            HandshakeType::ClientHello,
            &ch.encode().unwrap(),
        ))
    };
    // Unchanged, apart from an ALPN offer this server requires, it proceeds.
    let mut base = hello();
    base.alpn = vec![b"h2".to_vec()];
    offer(&base).unwrap();

    type Edit = fn(&mut ClientHello);
    let cases: &[(Edit, &str)] = &[
        (
            |c| c.versions = vec![ProtocolVersion::Tls12],
            "client does not offer TLS 1.3",
        ),
        (
            |c| c.key_shares[0].0 = NamedGroup::Secp521r1,
            "key share for a group not in supported_groups",
        ),
        (
            |c| c.suites = vec![CipherSuite::TlsAes128CcmSha256],
            "no cipher suite in common",
        ),
        (
            |c| {
                c.groups = vec![NamedGroup::X448];
                c.key_shares.clear();
            },
            "no key exchange group in common",
        ),
        (
            |c| c.alpn = vec![b"http/1.1".to_vec()],
            "no ALPN protocol in common",
        ),
        (
            |c| c.quic_params = Some(vec![1, 2]),
            "QUIC transport parameters over TCP",
        ),
    ];
    for (edit, want) in cases {
        let mut ch = base.clone();
        edit(&mut ch);
        refused(offer(&ch), want);
    }
    for (ty, want) in [
        (13, "ClientHello without signature_algorithms"),
        // RFC 8446 §9.2: key_share without supported_groups (REQ-MSG-022).
        (10, "supported_groups and key_share must come together"),
        // And supported_groups without key_share: once a HelloRetryRequest.
        (51, "supported_groups and key_share must come together"),
    ] {
        let body = with_client_hello_extension(&base.encode().unwrap(), ty, None, false);
        let mut server = Connection::server(sc.clone()).unwrap();
        let error = server
            .read_tls(&record_of(HandshakeType::ClientHello, &body))
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::MissingExtension);
        assert_eq!(error.context(), want);
    }
}

/// REQ-MSG-007: RFC 8446 section 4.2.10 selects Empty for ClientHello.
/// Mutate only the extension body in a genuine flight, retaining valid lengths.
#[test]
fn client_hello_early_data_indications_require_empty_bodies() {
    let pki = Pki::new(KeyKind::EcdsaP256, "server.test");
    let cc = Arc::new(pki.client_config(Profile::Default));
    let sc = Arc::new(pki.server_config(Profile::Default));
    let mut client = Connection::client(cc, "server.test").unwrap();
    let (ty, body) = first_message(&client.take_tls());
    assert_eq!(ty, HandshakeType::ClientHello);
    assert!(!ClientHello::decode(&body).unwrap().early_data);
    let mut control = Connection::server(sc.clone()).unwrap();
    control.read_tls(&record_of(ty, &body)).unwrap();
    let with_indication =
        |value: &[u8], first| with_client_hello_extension(&body, 42, Some(value), first);
    for first in [false, true] {
        assert!(
            ClientHello::decode(&with_indication(&[], first))
                .unwrap()
                .early_data
        );
    }
    let mut cases: Vec<_> = (0..=u8::MAX).map(|byte| vec![byte]).collect();
    // Four bytes are the NewSessionTicket form, not the ClientHello form.
    cases.push(vec![0, 0, 0, 1]);
    for len in [2, 3, 4, 16, 256, 1024] {
        cases.push(vec![0; len]);
        cases.push(vec![0xff; len]);
    }
    for value in cases {
        for first in [false, true] {
            let encoded = with_indication(&value, first);
            let error = match ClientHello::decode(&encoded) {
                Err(error) => error,
                Ok(_) => panic!("nonempty EarlyData body must fail decoding"),
            };
            assert_eq!(error.kind(), ErrorKind::Decode);
            assert_eq!(error.context(), "early_data in ClientHello must be empty");
            let mut server = Connection::server(sc.clone()).unwrap();
            let error = server.read_tls(&record_of(ty, &encoded)).unwrap_err();
            assert_eq!(error.kind(), ErrorKind::Decode);
            assert_eq!(error.context(), "early_data in ClientHello must be empty");
            assert_eq!(server.state(), HandshakeState::Failed);
            assert_eq!(server.available(), 0);
        }
    }
}

/// REQ-MSG-008: RFC 8446 section 4.2.9 defines ke_modes<1..255>.
/// An absent extension is permitted without PSKs; unknown mode values remain parseable.
#[test]
fn client_hello_psk_modes_require_nonempty_lists() {
    let pki = Pki::new(KeyKind::EcdsaP256, "server.test");
    let cc = Arc::new(pki.client_config(Profile::Default));
    let sc = Arc::new(pki.server_config(Profile::Default));
    let mut client = Connection::client(cc, "server.test").unwrap();
    let (ty, body) = first_message(&client.take_tls());
    assert_eq!(ty, HandshakeType::ClientHello);
    assert!(ClientHello::decode(&body).unwrap().psk.is_none());
    let mut modes: Vec<_> = (0..=u8::MAX).map(|byte| vec![byte]).collect();
    modes.push(vec![0, 1]);
    for len in [2, 254, 255] {
        modes.push(vec![1; len]);
        modes.push(vec![0xff; len]);
    }
    for first in [false, true] {
        let absent = with_client_hello_extension(&body, 45, None, first);
        assert!(ClientHello::decode(&absent).unwrap().psk_modes.is_empty());
        Connection::server(sc.clone())
            .unwrap()
            .read_tls(&record_of(ty, &absent))
            .unwrap();
        let empty = with_client_hello_extension(&body, 45, Some(&[0]), first);
        let error = match ClientHello::decode(&empty) {
            Err(error) => error,
            Ok(_) => panic!("a present PSK modes list cannot be empty"),
        };
        assert_eq!(error.kind(), ErrorKind::Decode);
        assert_eq!(error.context(), "empty PSK key exchange modes");
        let mut server = Connection::server(sc.clone()).unwrap();
        let error = server.read_tls(&record_of(ty, &empty)).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Decode);
        assert_eq!(error.context(), "empty PSK key exchange modes");
        assert_eq!(server.state(), HandshakeState::Failed);
        assert_eq!(server.available(), 0);
        for list in &modes {
            let mut value = Vec::new();
            put_vec(&mut value, Prefix::U8, list).unwrap();
            let encoded = with_client_hello_extension(&body, 45, Some(&value), first);
            assert_eq!(ClientHello::decode(&encoded).unwrap().psk_modes, *list);
        }
    }
}

/// REQ-MSG-009: RFC 6066 section 3 requires server_name_list<1..2^16-1>.
#[test]
fn client_hello_server_name_lists_require_an_entry() {
    let pki = Pki::new(KeyKind::EcdsaP256, "server.test");
    let cc = Arc::new(pki.client_config(Profile::Default));
    let sc = Arc::new(pki.server_config(Profile::Default));
    let mut client = Connection::client(cc, "server.test").unwrap();
    let (ty, body) = first_message(&client.take_tls());
    assert_eq!(ty, HandshakeType::ClientHello);
    for first in [false, true] {
        let absent = with_client_hello_extension(&body, 0, None, first);
        assert!(ClientHello::decode(&absent).unwrap().server_name.is_none());
        Connection::server(sc.clone())
            .unwrap()
            .read_tls(&record_of(ty, &absent))
            .unwrap();
        let empty = with_client_hello_extension(&body, 0, Some(&[0, 0]), first);
        let error = match ClientHello::decode(&empty) {
            Err(error) => error,
            Ok(_) => panic!("a present server_name list cannot be empty"),
        };
        assert_eq!(error.kind(), ErrorKind::Decode);
        assert_eq!(error.context(), "empty server_name list");
        let mut server = Connection::server(sc.clone()).unwrap();
        let error = server.read_tls(&record_of(ty, &empty)).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Decode);
        assert_eq!(error.context(), "empty server_name list");
        assert_eq!(server.state(), HandshakeState::Failed);
        assert_eq!(server.available(), 0);
        let mut entry = vec![0];
        put_vec(&mut entry, Prefix::U16, b"server.test").unwrap();
        let mut value = Vec::new();
        put_vec(&mut value, Prefix::U16, &entry).unwrap();
        let valid = with_client_hello_extension(&body, 0, Some(&value), first);
        assert_eq!(
            ClientHello::decode(&valid).unwrap().server_name.as_deref(),
            Some("server.test")
        );
        Connection::server(sc.clone())
            .unwrap()
            .read_tls(&record_of(ty, &valid))
            .unwrap();
    }
}

/// REQ-MSG-010: RFC 8446 sections 4.2.1, 4.2.3 and 4.2.7 require
/// nonempty two-byte lists, including server groups and requested signatures.
#[test]
fn negotiation_u16_lists_require_an_entry() {
    let pki = Pki::new(KeyKind::EcdsaP256, "server.test");
    let cc = Arc::new(pki.client_config(Profile::Default));
    let sc = Arc::new(pki.server_config(Profile::Default));
    let mut client = Connection::client(cc, "server.test").unwrap();
    let (ty, body) = first_message(&client.take_tls());
    for (extension, prefix) in [
        (10, Prefix::U16),
        (13, Prefix::U16),
        (50, Prefix::U16),
        (43, Prefix::U8),
    ] {
        for first in [false, true] {
            for (list, context) in [
                (&[][..], "empty u16 list"),
                (&[0x0a][..], "odd-length u16 list"),
            ] {
                let mut value = Vec::new();
                put_vec(&mut value, prefix, list).unwrap();
                let encoded = with_client_hello_extension(&body, extension, Some(&value), first);
                let error = match ClientHello::decode(&encoded) {
                    Err(error) => error,
                    Ok(_) => panic!("a negotiation list requires complete entries"),
                };
                assert_eq!(error.kind(), ErrorKind::Decode);
                assert_eq!(error.context(), context);
                let mut server = Connection::server(sc.clone()).unwrap();
                let error = server.read_tls(&record_of(ty, &encoded)).unwrap_err();
                assert_eq!(error.kind(), ErrorKind::Decode);
                assert_eq!(error.context(), context);
                assert_eq!(server.state(), HandshakeState::Failed);
                assert_eq!(server.available(), 0);
            }
            // Unknown entries remain parseable, with order and multiplicity preserved.
            for count in [1, 2, 127] {
                let list = [0x0a, 0x0a].repeat(count);
                let mut value = Vec::new();
                put_vec(&mut value, prefix, &list).unwrap();
                let encoded = with_client_hello_extension(&body, extension, Some(&value), first);
                let hello = ClientHello::decode(&encoded).unwrap();
                let parsed: Vec<u16> = match extension {
                    10 => hello.groups.iter().map(|entry| entry.to_wire()).collect(),
                    13 => hello.sig_algs.iter().map(|entry| entry.to_wire()).collect(),
                    50 => hello
                        .sig_algs_cert
                        .unwrap()
                        .iter()
                        .map(|entry| entry.to_wire())
                        .collect(),
                    43 => hello.versions.iter().map(|entry| entry.to_wire()).collect(),
                    _ => unreachable!(),
                };
                assert_eq!(parsed, vec![0x0a0a; count]);
            }
        }
    }
    for extension in [10, 13] {
        for (list, expected) in [
            (&[][..], Some("empty u16 list")),
            (&[0x0a][..], Some("odd-length u16 list")),
            (&[0x0a, 0x0a][..], None),
        ] {
            let mut value = Vec::new();
            put_vec(&mut value, Prefix::U16, list).unwrap();
            let mut extensions = Vec::new();
            put_u16(&mut extensions, extension);
            put_vec(&mut extensions, Prefix::U16, &value).unwrap();
            let mut encoded = Vec::new();
            put_vec(&mut encoded, Prefix::U16, &extensions).unwrap();
            let result = if extension == 10 {
                EncryptedExtensions::decode(&encoded).map(|ee| {
                    ee.groups
                        .iter()
                        .map(|entry| entry.to_wire())
                        .collect::<Vec<_>>()
                })
            } else {
                encoded.insert(0, 0); // Empty certificate_request_context.
                CertificateRequest::decode(&encoded).map(|cr| {
                    cr.sig_algs
                        .iter()
                        .map(|entry| entry.to_wire())
                        .collect::<Vec<_>>()
                })
            };
            if let Some(context) = expected {
                let error = result.unwrap_err();
                assert_eq!(error.kind(), ErrorKind::Decode);
                assert_eq!(error.context(), context);
            } else {
                assert_eq!(result.unwrap(), [0x0a0a]);
            }
        }
    }
}

/// REQ-MSG-011: RFC 6066 section 8 frames each ResponderID as <1..2^16-1>,
/// within a list that may be empty. Validate the TLS framing even for ignored IDs.
#[test]
fn client_hello_ocsp_responder_ids_require_complete_nonempty_vectors() {
    let pki = Pki::new(KeyKind::EcdsaP256, "server.test");
    let cc = Arc::new(pki.client_config(Profile::Default));
    let sc = Arc::new(pki.server_config(Profile::Default));
    let mut client = Connection::client(cc, "server.test").unwrap();
    let (ty, body) = first_message(&client.take_tls());
    // ResponderID byKey: explicit [2] wrapping a 20-byte KeyHash OCTET STRING.
    let mut responder_id = vec![0xa2, 22, 4, 20];
    responder_id.extend_from_slice(&[0x5a; 20]);
    let mut entry = Vec::new();
    put_vec(&mut entry, Prefix::U16, &responder_id).unwrap();
    let request = |ids: &[u8]| {
        let mut value = vec![1];
        put_vec(&mut value, Prefix::U16, ids).unwrap();
        put_vec(&mut value, Prefix::U16, &[]).unwrap();
        value
    };
    for first in [false, true] {
        for ids in [vec![], entry.clone(), entry.repeat(2)] {
            let encoded = with_client_hello_extension(&body, 5, Some(&request(&ids)), first);
            assert!(ClientHello::decode(&encoded).unwrap().status_request);
            Connection::server(sc.clone())
                .unwrap()
                .read_tls(&record_of(ty, &encoded))
                .unwrap();
        }
        for (malformed, context) in [
            (&[0][..], "truncated structure"),
            (&[0, 0][..], "empty OCSP responder ID"),
            (&[0, 1][..], "truncated structure"),
            (&[0, 2, 0x30][..], "truncated structure"),
        ] {
            for valid_first in [false, true] {
                let mut ids = if valid_first { entry.clone() } else { vec![] };
                ids.extend_from_slice(malformed);
                let encoded = with_client_hello_extension(&body, 5, Some(&request(&ids)), first);
                let error = match ClientHello::decode(&encoded) {
                    Err(error) => error,
                    Ok(_) => panic!("an OCSP responder list requires complete nonempty entries"),
                };
                assert_eq!(error.kind(), ErrorKind::Decode);
                assert_eq!(error.context(), context);
                let mut server = Connection::server(sc.clone()).unwrap();
                let error = server.read_tls(&record_of(ty, &encoded)).unwrap_err();
                assert_eq!(error.kind(), ErrorKind::Decode);
                assert_eq!(error.context(), context);
                assert_eq!(server.state(), HandshakeState::Failed);
                assert_eq!(server.available(), 0);
            }
        }
    }
}

/// REQ-MSG-012: RFC 8446 sections 4.2 and 4.4.2 require unique extension
/// types within each CertificateEntry, including ignored extension types.
#[test]
fn certificate_entry_extensions_are_unique_per_certificate() {
    let pki = Pki::new(KeyKind::EcdsaP256, "server.test");
    let chain = [pki.server_chain[0].clone(), pki.ca_cert.clone()];
    let staple = pki.staple(
        ironsocketlayer::x509::ocsp::CertStatus::Good,
        now(),
        now() + 3600,
    );
    let mut status = vec![1];
    put_vec(&mut status, Prefix::U24, &staple).unwrap();
    let extension = |ty: u16, body: &[u8]| {
        let mut out = Vec::new();
        put_u16(&mut out, ty);
        put_vec(&mut out, Prefix::U16, body).unwrap();
        out
    };
    let message = |blocks: &[Vec<u8>]| {
        let mut list = Vec::new();
        for (cert, block) in chain.iter().zip(blocks) {
            put_vec(&mut list, Prefix::U24, cert).unwrap();
            put_vec(&mut list, Prefix::U16, block).unwrap();
        }
        let mut out = vec![0];
        put_vec(&mut out, Prefix::U24, &list).unwrap();
        out
    };
    for (ty, value) in [(5, status.as_slice()), (0xfe01, &[1, 2][..])] {
        let single = extension(ty, value);
        let decoded = CertificateMsg::decode(&message(&[single.clone(), single.clone()])).unwrap();
        assert_eq!(decoded.chain, chain);
        assert_eq!(
            decoded.ocsp.as_deref(),
            if ty == 5 {
                Some(staple.as_slice())
            } else {
                None
            }
        );
        for position in [0, 1] {
            for separated in [false, true] {
                let mut duplicate = single.clone();
                if separated {
                    duplicate.extend_from_slice(&extension(0xfe02, &[3]));
                }
                // Differing values must not evade type-based duplicate detection.
                duplicate.extend_from_slice(&extension(ty, if ty == 5 { value } else { &[4] }));
                let mut blocks = [vec![], vec![]];
                blocks[position] = duplicate;
                let error = CertificateMsg::decode(&message(&blocks)).unwrap_err();
                assert_eq!(error.kind(), ErrorKind::IllegalParameter);
                assert_eq!(error.context(), "duplicate extension");
            }
        }
    }
    let decoded = CertificateMsg::decode(&message(&[vec![], vec![]])).unwrap();
    assert_eq!(decoded.chain, chain);
    assert!(decoded.ocsp.is_none());
}

/// REQ-MSG-013: RFC 8446 section 4.4.2.1 requires CertificateStatus framing
/// on every certificate's status_request, including responses not retained.
#[test]
fn certificate_status_framing_is_checked_on_every_entry() {
    let pki = Pki::new(KeyKind::EcdsaP256, "server.test");
    let chain = [pki.server_chain[0].clone(), pki.ca_cert.clone()];
    let staple = pki.staple(
        ironsocketlayer::x509::ocsp::CertStatus::Good,
        now(),
        now() + 3600,
    );
    let mut status = vec![1];
    put_vec(&mut status, Prefix::U24, &staple).unwrap();
    let message = |statuses: &[Option<&[u8]>]| {
        let mut list = Vec::new();
        for (cert, status) in chain.iter().zip(statuses) {
            put_vec(&mut list, Prefix::U24, cert).unwrap();
            let mut extensions = Vec::new();
            if let Some(status) = status {
                put_u16(&mut extensions, 5);
                put_vec(&mut extensions, Prefix::U16, status).unwrap();
            }
            put_vec(&mut list, Prefix::U16, &extensions).unwrap();
        }
        let mut out = vec![0];
        put_vec(&mut out, Prefix::U24, &list).unwrap();
        out
    };
    for statuses in [
        [Some(status.as_slice()), Some(status.as_slice())],
        [Some(status.as_slice()), None],
        [None, Some(status.as_slice())],
        [None, None],
    ] {
        let decoded = CertificateMsg::decode(&message(&statuses)).unwrap();
        assert_eq!(decoded.chain, chain);
        assert_eq!(
            decoded.ocsp.as_deref(),
            statuses[0].map(|_| staple.as_slice())
        );
    }
    let mut malformed: Vec<Vec<u8>> = (0..status.len())
        .map(|len| status[..len].to_vec())
        .collect();
    malformed.push(vec![1, 0, 0, 0]); // Empty OCSP response.
    let mut trailing = status.clone();
    trailing.push(0);
    malformed.push(trailing);
    for status_type in 0..=u8::MAX {
        if status_type != 1 {
            let mut unknown = status.clone();
            unknown[0] = status_type;
            malformed.push(unknown);
        }
    }
    for position in [0, 1] {
        for malformed in &malformed {
            let mut statuses = [Some(status.as_slice()), Some(status.as_slice())];
            statuses[position] = Some(malformed);
            let error = match CertificateMsg::decode(&message(&statuses)) {
                Err(error) => error,
                Ok(_) => panic!("every CertificateStatus requires complete valid TLS framing"),
            };
            assert_eq!(error.kind(), ErrorKind::Decode);
        }
    }
}

/// REQ-MSG-014: RFC 8446 sections 4.1.3 and 4.1.4 require 0x0303 in the
/// legacy_version of a TLS 1.3 ServerHello or HelloRetryRequest.
#[test]
fn tls13_server_hellos_require_the_tls12_legacy_version() {
    let pki = Pki::new(KeyKind::EcdsaP256, "server.test");
    for retry in [false, true] {
        let mut cc = pki.client_config(Profile::Default);
        cc.common.groups = vec![NamedGroup::X25519, NamedGroup::Secp384r1];
        cc.initial_key_shares = 1;
        let cc = Arc::new(cc);
        let mut sc = pki.server_config(Profile::Default);
        sc.common.groups = vec![if retry {
            NamedGroup::Secp384r1
        } else {
            NamedGroup::X25519
        }];
        let sc = Arc::new(sc);
        let exchange = || {
            let mut client = Connection::client(cc.clone(), "server.test").unwrap();
            let mut server = Connection::server(sc.clone()).unwrap();
            server.read_tls(&client.take_tls()).unwrap();
            let (ty, body) = first_message(&server.take_tls());
            assert_eq!(ty, HandshakeType::ServerHello);
            assert_eq!(ServerHello::decode(&body).unwrap().is_retry(), retry);
            (client, body)
        };
        let (mut client, body) = exchange();
        assert_eq!(&body[..2], &[3, 3]);
        client
            .read_tls(&record_of(HandshakeType::ServerHello, &body))
            .unwrap();
        for version in 0..=u16::MAX {
            if version == 0x0303 {
                continue;
            }
            let mut encoded = body.clone();
            encoded[..2].copy_from_slice(&version.to_be_bytes());
            let error = match ServerHello::decode(&encoded) {
                Err(error) => error,
                Ok(_) => panic!("TLS 1.3 ServerHello legacy_version must be 0x0303"),
            };
            if version == 0x0300 {
                assert_eq!(error.kind(), ErrorKind::ProtocolVersion);
                assert_eq!(error.context(), "SSL 3.0 legacy_version is forbidden");
            } else if version < 0x0300 {
                // REQ-MSG-021: not TLS at all.
                assert_eq!(error.kind(), ErrorKind::ProtocolVersion);
                assert_eq!(error.context(), "legacy_version below SSL 3.0");
            } else {
                assert_eq!(error.kind(), ErrorKind::IllegalParameter);
                assert_eq!(
                    error.context(),
                    "TLS 1.3 ServerHello legacy_version must be 0x0303"
                );
            }
        }
        for version in [0u16, 0x0300, 0x0301, 0x0302, 0x0304, 0xffff] {
            let (mut client, mut encoded) = exchange();
            encoded[..2].copy_from_slice(&version.to_be_bytes());
            let error = client
                .read_tls(&record_of(HandshakeType::ServerHello, &encoded))
                .unwrap_err();
            if version == 0x0300 {
                assert_eq!(error.kind(), ErrorKind::ProtocolVersion);
                assert_eq!(error.context(), "SSL 3.0 legacy_version is forbidden");
                let alert = client.take_tls();
                assert_eq!(alert, [21, 3, 3, 0, 2, 2, 70]);
            } else if version < 0x0300 {
                assert_eq!(error.kind(), ErrorKind::ProtocolVersion);
                assert_eq!(error.context(), "legacy_version below SSL 3.0");
                assert_eq!(client.take_tls(), [21, 3, 3, 0, 2, 2, 70]);
            } else {
                assert_eq!(error.kind(), ErrorKind::IllegalParameter);
                assert_eq!(
                    error.context(),
                    "TLS 1.3 ServerHello legacy_version must be 0x0303"
                );
            }
            assert_eq!(client.state(), HandshakeState::Failed);
            assert_eq!(client.available(), 0);
        }
    }
}

/// REQ-MSG-015: RFC 8446 sections 4.1.2 and 4.2.10 prohibit early_data
/// in the ClientHello following HelloRetryRequest.
#[test]
fn a_second_client_hello_cannot_offer_early_data() {
    let pki = Pki::new(KeyKind::EcdsaP256, "server.test");
    for cookie in [false, true] {
        let mut cc = pki.client_config(Profile::Default);
        cc.common.groups = vec![NamedGroup::X25519, NamedGroup::Secp384r1];
        cc.initial_key_shares = 1;
        let cc = Arc::new(cc);
        let mut sc = pki.server_config(Profile::Default);
        sc.common.groups = vec![NamedGroup::Secp384r1];
        sc.retry_cookie = cookie;
        let sc = Arc::new(sc);
        let exchange = || {
            let mut client = Connection::client(cc.clone(), "server.test").unwrap();
            let mut server = Connection::server(sc.clone()).unwrap();
            server.read_tls(&client.take_tls()).unwrap();
            let retry = server.take_tls();
            let (_, body) = first_message(&retry);
            assert!(ServerHello::decode(&body).unwrap().is_retry());
            client.read_tls(&retry).unwrap();
            let flight = client.take_tls();
            let at = if flight[0] == 20 { 6 } else { 0 };
            let (ty, body) = first_message(&flight[at..]);
            assert_eq!(ty, HandshakeType::ClientHello);
            let hello = ClientHello::decode(&body).unwrap();
            assert!(!hello.early_data);
            assert_eq!(hello.cookie.is_some(), cookie);
            (server, body)
        };
        let (mut server, body) = exchange();
        server
            .read_tls(&record_of(HandshakeType::ClientHello, &body))
            .unwrap();
        for first in [false, true] {
            let (mut server, body) = exchange();
            let encoded = with_client_hello_extension(&body, 42, Some(&[]), first);
            assert!(ClientHello::decode(&encoded).unwrap().early_data);
            let error = server
                .read_tls(&record_of(HandshakeType::ClientHello, &encoded))
                .unwrap_err();
            assert_eq!(error.kind(), ErrorKind::IllegalParameter);
            assert_eq!(error.context(), "early_data in second ClientHello");
            assert_eq!(server.state(), HandshakeState::Failed);
            assert_eq!(server.available(), 0);
        }
    }
}

/// REQ-MSG-016: RFC 8446 section 4.1.2 allows only specific changes after
/// HelloRetryRequest; decoded negotiation and capability extensions remain fixed.
#[test]
fn second_client_hello_negotiation_extensions_stay_unchanged() {
    let pki = Pki::new(KeyKind::EcdsaP256, "server.test");
    let mut cc = pki
        .client_config(Profile::Default)
        .with_alpn(&[b"h2", b"http/1.1"]);
    cc.common.groups = vec![NamedGroup::X25519, NamedGroup::Secp384r1];
    cc.initial_key_shares = 1;
    let cc = Arc::new(cc);
    type Edit = fn(&mut ClientHello);
    let cases: &[(&str, Edit)] = &[
        ("SNI value", |ch| ch.server_name = Some("other.test".into())),
        ("SNI removal", |ch| ch.server_name = None),
        ("group order", |ch| ch.groups.reverse()),
        ("signature order", |ch| ch.sig_algs.reverse()),
        ("certificate signatures", |ch| {
            ch.sig_algs_cert = Some(ch.sig_algs.clone())
        }),
        ("versions", |ch| ch.versions.push(ProtocolVersion::Tls12)),
        ("ALPN order", |ch| ch.alpn.reverse()),
        ("ALPN removal", |ch| ch.alpn.clear()),
        ("record limit", |ch| ch.record_size_limit = Some(1024)),
        ("OCSP request", |ch| ch.status_request = !ch.status_request),
        ("post-handshake auth", |ch| {
            ch.post_handshake_auth = !ch.post_handshake_auth
        }),
        ("PSK modes", |ch| ch.psk_modes.push(0xfe)),
    ];
    for cookie in [false, true] {
        let mut sc = pki.server_config(Profile::Default);
        sc.common.groups = vec![NamedGroup::Secp384r1];
        sc.retry_cookie = cookie;
        let sc = Arc::new(sc);
        let exchange = || {
            let mut client = Connection::client(cc.clone(), "server.test").unwrap();
            let mut server = Connection::server(sc.clone()).unwrap();
            server.read_tls(&client.take_tls()).unwrap();
            let retry = server.take_tls();
            let (_, body) = first_message(&retry);
            assert!(ServerHello::decode(&body).unwrap().is_retry());
            client.read_tls(&retry).unwrap();
            let flight = client.take_tls();
            let at = if flight[0] == 20 { 6 } else { 0 };
            let (_, body) = first_message(&flight[at..]);
            (client, server, ClientHello::decode(&body).unwrap())
        };
        let (mut client, mut server, hello) = exchange();
        server
            .read_tls(&record_of(
                HandshakeType::ClientHello,
                &hello.encode().unwrap(),
            ))
            .unwrap();
        client.read_tls(&server.take_tls()).unwrap();
        server.read_tls(&client.take_tls()).unwrap();
        assert_eq!(client.state(), HandshakeState::Connected);
        assert_eq!(server.state(), HandshakeState::Connected);
        for (name, edit) in cases {
            let (_, mut server, mut hello) = exchange();
            let original = hello.clone();
            edit(&mut hello);
            assert_ne!(hello, original, "{name} must change the test input");
            let error = server
                .read_tls(&record_of(
                    HandshakeType::ClientHello,
                    &hello.encode().unwrap(),
                ))
                .unwrap_err();
            assert_eq!(error.kind(), ErrorKind::IllegalParameter, "{name}");
            assert_eq!(
                error.context(),
                "second ClientHello changed an immutable extension",
                "{name}"
            );
            assert_eq!(server.state(), HandshakeState::Failed);
            assert_eq!(server.available(), 0);
        }
    }
}

/// REQ-MSG-016: QUIC transport parameters also remain unchanged on TLS retry.
#[test]
fn second_client_hello_quic_parameters_stay_unchanged() {
    use ironsocketlayer::quic::{QuicConnection, Version};
    use ironsocketlayer::Level;
    let pki = Pki::new(KeyKind::EcdsaP256, "server.test");
    let mut cc = pki.client_config(Profile::Default).with_alpn(&[b"h3"]);
    cc.common.groups = vec![NamedGroup::X25519, NamedGroup::Secp384r1];
    cc.initial_key_shares = 1;
    let cc = Arc::new(cc);
    for version in [Version::V1, Version::V2] {
        for cookie in [false, true] {
            let mut sc = pki.server_config(Profile::Default).with_alpn(&[b"h3"]);
            sc.common.groups = vec![NamedGroup::Secp384r1];
            sc.retry_cookie = cookie;
            let sc = Arc::new(sc);
            let exchange = || {
                let mut client =
                    QuicConnection::client(cc.clone(), "server.test", b"client-params", version)
                        .unwrap();
                let mut server =
                    QuicConnection::server(sc.clone(), b"server-params", version).unwrap();
                let (level, hello) = client.write_handshake().unwrap();
                assert_eq!(level, Level::Initial);
                server.read_handshake(level, &hello).unwrap();
                let (level, retry) = server.write_handshake().unwrap();
                client.read_handshake(level, &retry).unwrap();
                let (level, hello) = client.write_handshake().unwrap();
                assert_eq!(level, Level::Initial);
                let mut reader = Reader::new(&hello);
                assert_eq!(reader.u8().unwrap(), HandshakeType::ClientHello.to_wire());
                let body = reader.vec24().unwrap();
                reader.finish().unwrap();
                let hello = ClientHello::decode(body).unwrap();
                assert_eq!(hello.quic_params.as_deref(), Some(&b"client-params"[..]));
                (server, hello)
            };
            let (mut server, hello) = exchange();
            server
                .read_handshake(
                    Level::Initial,
                    &msgs::frame(HandshakeType::ClientHello, &hello.encode().unwrap()).unwrap(),
                )
                .unwrap();
            let (mut server, mut hello) = exchange();
            hello.quic_params = Some(b"changed-params".to_vec());
            let error = server
                .read_handshake(
                    Level::Initial,
                    &msgs::frame(HandshakeType::ClientHello, &hello.encode().unwrap()).unwrap(),
                )
                .unwrap_err();
            assert_eq!(error.kind(), ErrorKind::IllegalParameter);
            assert_eq!(
                error.context(),
                "second ClientHello changed an immutable extension"
            );
            assert_eq!(server.state(), HandshakeState::Failed);
        }
    }
}

/// REQ-MSG-017: RFC 8446 appendix D.5 requires protocol_version for
/// SSL 3.0 legacy_version, even if supported_versions offers TLS 1.3.
#[test]
fn ssl3_legacy_client_hellos_are_refused_with_protocol_version() {
    let pki = Pki::new(KeyKind::EcdsaP256, "server.test");
    let cc = Arc::new(pki.client_config(Profile::Default));
    let sc = Arc::new(pki.server_config(Profile::Default));
    let mut client = Connection::client(cc, "server.test").unwrap();
    let (ty, body) = first_message(&client.take_tls());
    assert!(ClientHello::decode(&body)
        .unwrap()
        .versions
        .contains(&ProtocolVersion::Tls13));
    Connection::server(sc.clone())
        .unwrap()
        .read_tls(&record_of(ty, &body))
        .unwrap();
    let mut encoded = body;
    encoded[..2].copy_from_slice(&[3, 0]);
    let error = match ClientHello::decode(&encoded) {
        Err(error) => error,
        Ok(_) => panic!("SSL 3.0 legacy_version requires protocol_version"),
    };
    assert_eq!(error.kind(), ErrorKind::ProtocolVersion);
    assert_eq!(error.context(), "SSL 3.0 legacy_version is forbidden");
    let mut server = Connection::server(sc).unwrap();
    let error = server.read_tls(&record_of(ty, &encoded)).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::ProtocolVersion);
    assert_eq!(error.context(), "SSL 3.0 legacy_version is forbidden");
    assert_eq!(server.state(), HandshakeState::Failed);
    assert_eq!(server.available(), 0);
    assert_eq!(server.take_tls(), [21, 3, 3, 0, 2, 2, 70]);
}

/// The client refuses ServerHellos that break RFC 8446's rules.
#[test]
fn the_client_refuses_non_conforming_server_hellos() {
    let pki = Pki::new(KeyKind::EcdsaP256, "server.test");
    let cc = Arc::new(pki.client_config(Profile::Default));
    let sc = Arc::new(pki.server_config(Profile::Default));
    // A client that has sent its hello, and the ServerHello it was answered
    // with.
    let exchange = || {
        let mut c = Connection::client(cc.clone(), "server.test").unwrap();
        let mut s = Connection::server(sc.clone()).unwrap();
        s.read_tls(&c.take_tls()).unwrap();
        let (ty, body) = first_message(&s.take_tls());
        assert_eq!(ty, HandshakeType::ServerHello);
        (c, ServerHello::decode(&body).unwrap())
    };
    let answer = |c: &mut Connection, sh: &ServerHello| {
        c.read_tls(&record_of(
            HandshakeType::ServerHello,
            &sh.encode().unwrap(),
        ))
    };
    let (mut c, sh) = exchange();
    answer(&mut c, &sh).unwrap();

    type Edit = fn(&mut ServerHello);
    let cases: &[(Edit, &str)] = &[
        (
            |s| s.session_id[0] ^= 1,
            "legacy_session_id_echo does not match",
        ),
        (
            |s| s.suite = Some(CipherSuite::TlsAes128CcmSha256),
            "server selected a suite not offered",
        ),
        (|s| s.key_share = None, "ServerHello without key_share"),
        (
            |s| s.key_share.as_mut().unwrap().0 = NamedGroup::Secp521r1,
            "server key share for a group not shared",
        ),
        (
            |s| s.selected_psk = Some(0),
            "server selected a PSK that was not offered",
        ),
    ];
    for (edit, want) in cases {
        let (mut c, mut sh) = exchange();
        edit(&mut sh);
        refused(answer(&mut c, &sh), want);
    }
    // Our encoder always writes TLS 1.3, so a server selecting TLS 1.2 in
    // supported_versions is made by rewriting the extension's bytes.
    let (mut c, sh) = exchange();
    let mut body = sh.encode().unwrap();
    let ext = [0x00, 0x2b, 0x00, 0x02, 0x03, 0x04];
    let at = body.windows(6).position(|w| w == ext).unwrap();
    body[at + 5] = 0x03;
    refused(
        c.read_tls(&record_of(HandshakeType::ServerHello, &body)),
        "server selected a version not offered",
    );
}

/// The client refuses HelloRetryRequests that break RFC 8446 §4.1.4, and a
/// ServerHello that changes the suite a retry chose.
#[test]
fn the_client_refuses_non_conforming_retries() {
    let pki = Pki::new(KeyKind::EcdsaP256, "server.test");
    let mut cc = pki.client_config(Profile::Default);
    cc.common.groups = vec![NamedGroup::X25519, NamedGroup::Secp384r1];
    cc.initial_key_shares = 1;
    let cc = Arc::new(cc);
    let mut sc = pki.server_config(Profile::Default);
    sc.common.groups = vec![NamedGroup::Secp384r1];
    let sc = Arc::new(sc);
    // A client and server, and the retry the server answered with.
    let exchange = || {
        let mut c = Connection::client(cc.clone(), "server.test").unwrap();
        let mut s = Connection::server(sc.clone()).unwrap();
        s.read_tls(&c.take_tls()).unwrap();
        let (ty, body) = first_message(&s.take_tls());
        assert_eq!(ty, HandshakeType::ServerHello);
        let hrr = ServerHello::decode(&body).unwrap();
        assert!(hrr.is_retry());
        (c, s, hrr)
    };
    let answer = |c: &mut Connection, sh: &ServerHello| {
        c.read_tls(&record_of(
            HandshakeType::ServerHello,
            &sh.encode().unwrap(),
        ))
    };
    let (mut c, _, hrr) = exchange();
    answer(&mut c, &hrr).unwrap();

    type Edit = fn(&mut ServerHello);
    let cases: &[(Edit, &str)] = &[
        (
            |h| h.hrr_group = Some(NamedGroup::X25519),
            "retry names a group already shared",
        ),
        (
            |h| h.hrr_group = Some(NamedGroup::Secp521r1),
            "retry names a group not offered",
        ),
        (
            |h| {
                h.hrr_group = None;
                h.cookie = None;
            },
            "HelloRetryRequest would change nothing",
        ),
    ];
    for (edit, want) in cases {
        let (mut c, _, mut hrr) = exchange();
        edit(&mut hrr);
        refused(answer(&mut c, &hrr), want);
    }

    // A second retry, after the client has answered the first.
    let (mut c, _, hrr) = exchange();
    answer(&mut c, &hrr).unwrap();
    let _second_hello = c.take_tls();
    refused(answer(&mut c, &hrr), "second HelloRetryRequest");

    // The real server's ServerHello, with the suite changed from the retry's.
    let (mut c, mut s, hrr) = exchange();
    answer(&mut c, &hrr).unwrap();
    s.read_tls(&c.take_tls()).unwrap();
    let flight = s.take_tls();
    // Skip any ChangeCipherSpec record before the ServerHello.
    let at = if flight[0] == 20 { 6 } else { 0 };
    let (ty, body) = first_message(&flight[at..]);
    assert_eq!(ty, HandshakeType::ServerHello);
    let mut sh = ServerHello::decode(&body).unwrap();
    let other = [
        CipherSuite::TlsAes128GcmSha256,
        CipherSuite::TlsAes256GcmSha384,
        CipherSuite::TlsChaCha20Poly1305Sha256,
    ]
    .into_iter()
    .find(|x| Some(*x) != hrr.suite)
    .unwrap();
    sh.suite = Some(other);
    refused(answer(&mut c, &sh), "suite changed after HelloRetryRequest");
}

/// REQ-ECH-001: the server refuses outer hellos that misuse ECH: the inner
/// marker in an outer hello and, after a retry, a second hello that drops ECH
/// or brings a new encapsulated key (which must be empty the second time).
#[test]
fn the_server_refuses_misused_ech() {
    use ironsocketlayer::ech::EchServer;
    use ironsocketlayer::msgs::EchHello;
    const REAL: &str = "secret-backend.test";
    const PUBLIC: &str = "public.test";
    let pki = Pki::new(KeyKind::EcdsaP256, REAL);
    let ech = Arc::new(
        EchServer::generate(3, PUBLIC, 64, &mut ic_drbg::Rng::from_os().unwrap()).unwrap(),
    );
    let mut sc = ironsocketlayer::config::ServerConfig::new(
        Profile::Default,
        pki.identity_for(&[REAL, PUBLIC]),
    )
    .unwrap();
    sc.ech = Some(ech.clone());
    sc.common.groups = vec![NamedGroup::Secp384r1];
    let sc = Arc::new(sc);
    let mut cc = pki.client_config(Profile::Default);
    cc.ech_configs = Some(ech.config_list().to_vec());
    cc.common.groups = vec![NamedGroup::X25519, NamedGroup::Secp384r1];
    cc.initial_key_shares = 1;
    let cc = Arc::new(cc);

    // The inner marker in the outer hello.
    let mut c = Connection::client(cc.clone(), REAL).unwrap();
    let (_, body) = first_message(&c.take_tls());
    let mut ch = ClientHello::decode(&body).unwrap();
    ch.ech = Some(EchHello::Inner);
    let mut s = Connection::server(sc.clone()).unwrap();
    refused(
        s.read_tls(&record_of(
            HandshakeType::ClientHello,
            &ch.encode().unwrap(),
        )),
        "inner ECH marker in an outer ClientHello",
    );

    // After a retry: the second outer hello, changed.
    let second = |edit: fn(&mut ClientHello)| {
        let mut c = Connection::client(cc.clone(), REAL).unwrap();
        let mut s = Connection::server(sc.clone()).unwrap();
        s.read_tls(&c.take_tls()).unwrap();
        c.read_tls(&s.take_tls()).unwrap();
        let flight = c.take_tls();
        let at = if flight[0] == 20 { 6 } else { 0 };
        let (ty, body) = first_message(&flight[at..]);
        assert_eq!(ty, HandshakeType::ClientHello);
        let mut ch = ClientHello::decode(&body).unwrap();
        edit(&mut ch);
        s.read_tls(&record_of(
            HandshakeType::ClientHello,
            &ch.encode().unwrap(),
        ))
    };
    refused(second(|ch| ch.ech = None), "second ClientHello dropped ECH");
    refused(
        second(|ch| {
            if let Some(EchHello::Outer { enc, .. }) = &mut ch.ech {
                *enc = vec![7; 32];
            }
        }),
        "second ECH hello with a new enc",
    );
}

/// RFC 8446 §4.2.9: a ClientHello offering a PSK must carry
/// psk_key_exchange_modes. REQ-PSK-001.
#[test]
fn a_psk_offer_without_key_exchange_modes_is_refused() {
    let pki = Pki::new(KeyKind::EcdsaP256, "server.test");
    let cc = Arc::new(pki.client_config(Profile::Default));
    let sc = Arc::new(pki.server_config(Profile::Default));
    // A first connection leaves a ticket in the client's store.
    let (mut c, mut s) = connect(cc.clone(), sc.clone(), "server.test").unwrap();
    exchange(&mut c, &mut s);
    let mut c = Connection::client(cc, "server.test").unwrap();
    let (_, body) = first_message(&c.take_tls());
    let mut ch = ClientHello::decode(&body).unwrap();
    assert!(ch.psk.is_some(), "the second hello offers the ticket");
    ch.psk_modes.clear();
    let mut s = Connection::server(sc).unwrap();
    refused(
        s.read_tls(&record_of(
            HandshakeType::ClientHello,
            &ch.encode().unwrap(),
        )),
        "pre_shared_key without psk_key_exchange_modes",
    );
}

/// REQ-ECH-007: accepted ECH retries keep their HPKE parameters and extension.
#[test]
fn accepted_ech_retries_require_unchanged_parameters() {
    use ironsocketlayer::ech::EchServer;
    use ironsocketlayer::msgs::EchHello;
    use ironsocketlayer::report::Property;
    const REAL: &str = "secret-backend.test";
    const PUBLIC: &str = "public.test";
    let pki = Pki::new(KeyKind::EcdsaP256, REAL);
    let ech = Arc::new(
        EchServer::generate(3, PUBLIC, 64, &mut ic_drbg::Rng::from_os().unwrap()).unwrap(),
    );
    let mut cc = pki.client_config(Profile::Default);
    cc.ech_configs = Some(ech.config_list().to_vec());
    cc.common.groups = vec![NamedGroup::X25519, NamedGroup::Secp384r1];
    cc.initial_key_shares = 1;
    let cc = Arc::new(cc);
    for cookie in [false, true] {
        let mut sc = ironsocketlayer::config::ServerConfig::new(
            Profile::Default,
            pki.identity_for(&[REAL, PUBLIC]),
        )
        .unwrap();
        sc.ech = Some(ech.clone());
        sc.common.groups = vec![NamedGroup::Secp384r1];
        sc.retry_cookie = cookie;
        let sc = Arc::new(sc);
        for change in 0..6 {
            let mut client = Connection::client(cc.clone(), REAL).unwrap();
            let mut server = Connection::server(sc.clone()).unwrap();
            server.read_tls(&client.take_tls()).unwrap();
            client.read_tls(&server.take_tls()).unwrap();
            assert!(client.report().hello_retry);
            let second = client.take_tls();
            if change == 0 {
                server.read_tls(&second).unwrap();
                client.read_tls(&server.take_tls()).unwrap();
                server.read_tls(&client.take_tls()).unwrap();
                for conn in [&client, &server] {
                    assert_eq!(conn.report().state, Some(HandshakeState::Connected));
                    assert!(conn.report().has(Property::EncryptedClientHello));
                }
                continue;
            }
            let at = if second[0] == 20 { 6 } else { 0 };
            let (_, body) = first_message(&second[at..]);
            let mut ch = ClientHello::decode(&body).unwrap();
            if change == 5 {
                ch.ech = None;
            } else if let Some(EchHello::Outer {
                suite,
                config_id,
                enc,
                ..
            }) = ch.ech.as_mut()
            {
                assert!(enc.is_empty());
                match change {
                    1 => *config_id ^= 1,
                    2 => suite.0 ^= 1,
                    3 => suite.1 ^= 1,
                    4 => enc.push(7),
                    _ => unreachable!(),
                }
            } else {
                panic!("accepted ECH retry has no outer extension");
            }
            let err = server
                .read_tls(&record_of(
                    HandshakeType::ClientHello,
                    &ch.encode().unwrap(),
                ))
                .unwrap_err();
            let (kind, alert, context) = match change {
                5 => (
                    ErrorKind::MissingExtension,
                    109,
                    "second ClientHello dropped ECH",
                ),
                4 => (
                    ErrorKind::IllegalParameter,
                    47,
                    "second ECH hello with a new enc",
                ),
                _ => (
                    ErrorKind::IllegalParameter,
                    47,
                    "second ECH hello changed cipher_suite or config_id",
                ),
            };
            assert_eq!(err.kind(), kind, "change {change}, cookie {cookie}");
            assert!(err.to_string().contains(context));
            assert_eq!(server.report().state, Some(HandshakeState::Failed));
            assert_eq!(server.take_tls(), [21, 3, 3, 0, 2, 2, alert]);
        }
    }
}
