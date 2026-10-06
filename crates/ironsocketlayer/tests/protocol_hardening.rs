//! Protocol regressions found by the 2026-10-06 security audit. A hand-built
//! TLS 1.3 client, from the crate public primitives, sends records the real
//! engines never produce.
mod common;
mod fixed_support;

use std::sync::Arc;

use common::*;
use fixed_support::Buffers;
use ironsocketlayer::config::{Profile, ServerConfig};
use ironsocketlayer::crypto::kx::KeyShare;
use ironsocketlayer::crypto::sign::KeyKind;
use ironsocketlayer::crypto::{Hash, HashAlg};
use ironsocketlayer::ech::EchServer;
use ironsocketlayer::enums::{
    CipherSuite, ContentType, HandshakeType, NamedGroup, ProtocolVersion, SignatureScheme,
};
use ironsocketlayer::fixed;
use ironsocketlayer::key_schedule::{self, EarlyStage};
use ironsocketlayer::msgs::{self, ClientHello, ServerHello};
use ironsocketlayer::record::{self, Protector};
use ironsocketlayer::{Connection, ErrorKind};

const SUITE: CipherSuite = CipherSuite::TlsAes128GcmSha256;

trait Peer {
    fn feed(&mut self, b: &[u8]) -> ironsocketlayer::Result<()>;
    fn take(&mut self) -> Vec<u8>;
}
impl Peer for Connection {
    fn feed(&mut self, b: &[u8]) -> ironsocketlayer::Result<()> {
        self.read_tls(b)
    }
    fn take(&mut self) -> Vec<u8> {
        self.take_tls()
    }
}
impl Peer for fixed::Connection<'_> {
    fn feed(&mut self, b: &[u8]) -> ironsocketlayer::Result<()> {
        self.receive(b)
    }
    fn take(&mut self) -> Vec<u8> {
        let v = self.outgoing().to_vec();
        self.consume_outgoing(v.len()).unwrap();
        v
    }
}

/// A hand-rolled TLS 1.3 client built from the crate's public primitives,
/// so that records the real engines never produce can be sent.
struct Raw {
    write: Protector,
}

fn raw_handshake(peer: &mut impl Peer) -> Raw {
    let mut rng = ic_drbg::Rng::from_os().unwrap();
    let ks = KeyShare::generate(NamedGroup::X25519, &mut rng).unwrap();
    let ch = ClientHello {
        random: [7; 32],
        session_id: vec![1; 32],
        suites: vec![SUITE],
        server_name: Some("server.test".into()),
        groups: vec![NamedGroup::X25519],
        sig_algs: vec![SignatureScheme::EcdsaSecp256r1Sha256],
        versions: vec![ProtocolVersion::Tls13],
        key_shares: vec![(NamedGroup::X25519, ks.public().to_vec())],
        ..Default::default()
    };
    let chm = msgs::frame(HandshakeType::ClientHello, &ch.encode().unwrap()).unwrap();
    let mut rec = vec![22, 3, 1];
    rec.extend((chm.len() as u16).to_be_bytes());
    rec.extend(&chm);
    peer.feed(&rec).unwrap();
    let mut out = peer.take();
    let mut th = Hash::new(HashAlg::Sha256);
    th.update(&chm);
    let r = record::take_record(&mut out).unwrap().unwrap();
    assert_eq!(r.header[0], 22);
    let shm = r.body;
    let sh = ServerHello::decode(&shm[4..]).unwrap();
    th.update(&shm);
    let (_, share) = sh.key_share.unwrap();
    let shared = ks.complete(&share).unwrap();
    let hs = EarlyStage::new(HashAlg::Sha256, None)
        .unwrap()
        .into_handshake(shared.get())
        .unwrap();
    let h1 = th.peek();
    let c_hs = hs.client_traffic(h1.as_bytes()).unwrap();
    let s_hs = hs.server_traffic(h1.as_bytes()).unwrap();
    let mut sread = Protector::new(SUITE, &s_hs).unwrap();
    let mut buf = Vec::new();
    let mut done = false;
    while let Some(r) = record::take_record(&mut out).unwrap() {
        if r.header[0] == 20 {
            continue;
        }
        let mut body = r.body;
        let (ty, n) = sread.open(&r.header, &mut body).unwrap();
        assert_eq!(ty, ContentType::Handshake);
        buf.extend_from_slice(&body[..n]);
        while let Some((t, m)) = msgs::take_message(&mut buf, 1 << 20).unwrap() {
            th.update(&m);
            if t == HandshakeType::Finished {
                done = true;
            }
        }
    }
    assert!(done, "server flight incomplete");
    let h2 = th.peek();
    let master = hs.into_master().unwrap();
    let c_ap = master.client_traffic(h2.as_bytes()).unwrap();
    let fin = key_schedule::finished_mac(HashAlg::Sha256, c_hs.as_bytes(), h2.as_bytes()).unwrap();
    let finm = msgs::frame(HandshakeType::Finished, fin.as_bytes()).unwrap();
    let mut w = Protector::new(SUITE, &c_hs).unwrap();
    let mut wire = Vec::new();
    w.seal(ContentType::Handshake, &finm, 0, &mut wire).unwrap();
    peer.feed(&wire).unwrap();
    let _ = peer.take();
    Raw {
        write: Protector::new(SUITE, &c_ap).unwrap(),
    }
}

fn server_config(pki: &Pki) -> ServerConfig {
    let mut sc = pki.server_config(Profile::Default);
    sc.tickets = None;
    sc.common.suites = vec![SUITE];
    sc.common.groups = vec![NamedGroup::X25519];
    sc
}

fn seal(p: &mut Protector, ty: ContentType, content: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    p.seal(ty, content, 0, &mut v).unwrap();
    v
}

/// REQ-REC-008: a message that changes the read key ends its record. Two
/// KeyUpdates in one record are refused by both engines.
#[test]
fn both_engines_refuse_messages_after_a_key_change_in_the_same_record() {
    let pki = Pki::new(KeyKind::EcdsaP256, "server.test");
    let sc = server_config(&pki);
    let mut b = Buffers::new();
    let mut rng = ic_drbg::Rng::from_os().unwrap();
    let mut s =
        fixed::Connection::server(&sc, &mut rng, b.storage(), fixed::Limits::default()).unwrap();
    let mut raw = raw_handshake(&mut s);
    assert!(s.is_connected());
    let rec = seal(
        &mut raw.write,
        ContentType::Handshake,
        &[24, 0, 0, 1, 0, 24, 0, 0, 1, 0],
    );
    assert_eq!(
        s.receive(&rec).unwrap_err().kind(),
        ErrorKind::UnexpectedMessage
    );

    let mut s = Connection::server(Arc::new(server_config(&pki))).unwrap();
    let mut raw = raw_handshake(&mut s);
    let rec = seal(
        &mut raw.write,
        ContentType::Handshake,
        &[24, 0, 0, 1, 0, 24, 0, 0, 1, 0],
    );
    assert_eq!(
        s.read_tls(&rec).unwrap_err().kind(),
        ErrorKind::UnexpectedMessage
    );
}

/// REQ-REC-008: the fixed client refuses a plaintext message after the
/// ServerHello in the same record.
#[test]
fn the_fixed_client_refuses_plaintext_after_the_server_hello() {
    let pki = Pki::new(KeyKind::EcdsaP256, "server.test");
    let mut cc = pki.client_config(Profile::Default);
    cc.tickets = None;
    cc.common.suites = vec![SUITE];
    cc.common.groups = vec![NamedGroup::X25519];
    let sc = server_config(&pki);
    let (mut cb, mut sb) = (Buffers::new(), Buffers::new());
    let mut cr = ic_drbg::Rng::from_os().unwrap();
    let mut sr = ic_drbg::Rng::from_os().unwrap();
    let mut c = fixed::Connection::client(
        &cc,
        "server.test",
        &mut cr,
        cb.storage(),
        fixed::Limits::default(),
    )
    .unwrap();
    let mut s =
        fixed::Connection::server(&sc, &mut sr, sb.storage(), fixed::Limits::default()).unwrap();
    let ch = c.take();
    s.receive(&ch).unwrap();
    let mut flight = s.take();
    let sh = record::take_record(&mut flight).unwrap().unwrap();
    let mut body = sh.body.clone();
    body.extend_from_slice(&[8, 0, 0, 2, 0, 0]); // a plaintext EncryptedExtensions
    let mut rec = vec![22, 3, 3];
    rec.extend((body.len() as u16).to_be_bytes());
    rec.extend(&body);
    assert_eq!(
        c.receive(&rec).unwrap_err().kind(),
        ErrorKind::UnexpectedMessage
    );
}

/// REQ-CONN-009: the owned engine refuses application data between the
/// fragments of a handshake message.
#[test]
fn application_data_inside_a_fragmented_handshake_message_is_refused() {
    let pki = Pki::new(KeyKind::EcdsaP256, "server.test");
    let mut s = Connection::server(Arc::new(server_config(&pki))).unwrap();
    let mut raw = raw_handshake(&mut s);
    let mut wire = seal(&mut raw.write, ContentType::Handshake, &[24, 0]);
    wire.extend(seal(&mut raw.write, ContentType::ApplicationData, b"x"));
    wire.extend(seal(&mut raw.write, ContentType::Handshake, &[0, 1, 0]));
    assert_eq!(
        s.read_tls(&wire).unwrap_err().kind(),
        ErrorKind::UnexpectedMessage
    );
}

/// REQ-CONN-004: at most two compatibility ChangeCipherSpec records.
#[test]
fn change_cipher_spec_records_are_bounded() {
    let pki = Pki::new(KeyKind::EcdsaP256, "server.test");
    let mut c =
        Connection::client(Arc::new(pki.client_config(Profile::Default)), "server.test").unwrap();
    let mut s = Connection::server(Arc::new(pki.server_config(Profile::Default))).unwrap();
    s.read_tls(&c.take_tls()).unwrap();
    s.read_tls(&[20u8, 3, 3, 0, 1, 1]).unwrap();
    s.read_tls(&[20u8, 3, 3, 0, 1, 1]).unwrap();
    assert_eq!(
        s.read_tls(&[20u8, 3, 3, 0, 1, 1]).unwrap_err().kind(),
        ErrorKind::UnexpectedMessage
    );
}

/// REQ-CONN-010: a silent receiver answers many KeyUpdate requests with one
/// update, so the peer cannot reflect each of its own.
#[test]
fn key_update_requests_are_answered_once_while_silent() {
    let pki = Pki::new(KeyKind::EcdsaP256, "server.test");
    let (mut c, mut s) = connect(
        Arc::new(pki.client_config(Profile::Default)),
        Arc::new(pki.server_config(Profile::Default)),
        "server.test",
    )
    .unwrap();
    for _ in 0..100 {
        c.key_update(true).unwrap();
    }
    s.read_tls(&c.take_tls()).unwrap();
    assert_eq!(s.report().key_updates_received, 100);
    assert_eq!(s.report().key_updates_sent, 1);
    c.read_tls(&s.take_tls()).unwrap();
    // After the server writes, a new request is answered again.
    s.send(b"data").unwrap();
    c.key_update(true).unwrap();
    s.read_tls(&c.take_tls()).unwrap();
    assert_eq!(s.report().key_updates_sent, 2);
    // And data still flows.
    c.read_tls(&s.take_tls()).unwrap();
    let mut buf = [0u8; 8];
    assert_eq!(c.recv(&mut buf), 4);
}

/// REQ-ECH-010: retry configurations from a handshake that failed for any
/// reason other than ech_rejected are not handed out: they were never
/// authenticated as the public name's.
#[test]
fn ech_retry_configs_are_withheld_after_an_authentication_failure() {
    const REAL: &str = "secret-backend.test";
    const PUBLIC: &str = "public.test";
    let mut r = ic_drbg::Rng::from_os().unwrap();
    let real = Pki::new(KeyKind::EcdsaP256, REAL);
    let genuine = EchServer::generate(3, PUBLIC, 64, &mut r).unwrap();
    let evil = Pki::new(KeyKind::EcdsaP256, PUBLIC);
    let evil_ech = Arc::new(EchServer::generate(9, PUBLIC, 64, &mut r).unwrap());
    let mut sc = ServerConfig::new(Profile::Default, evil.identity_for(&[PUBLIC])).unwrap();
    sc.ech = Some(evil_ech);
    let mut cc = real.client_config(Profile::Default);
    cc.ech_configs = Some(genuine.config_list().to_vec());
    let mut c = Connection::client(Arc::new(cc), REAL).unwrap();
    let mut s = Connection::server(Arc::new(sc)).unwrap();
    for _ in 0..4 {
        let _ = s.read_tls(&c.take_tls());
        let _ = c.read_tls(&s.take_tls());
    }
    assert_eq!(c.error().unwrap().kind(), ErrorKind::UnknownCa);
    assert_eq!(c.ech_retry_configs(), None);
}

/// REQ-CONN-011: TlsStream reports a transport that ends without
/// close_notify as UnexpectedEof, not as a clean end of stream.
#[test]
fn tls_stream_reports_truncation() {
    use ironsocketlayer::stream::TlsStream;
    use std::io::{Read, Write};
    use std::net::{Shutdown, TcpListener, TcpStream};
    let pki = Pki::new(KeyKind::EcdsaP256, "server.test");
    let sc = Arc::new(pki.server_config(Profile::Default));
    let cc = Arc::new(pki.client_config(Profile::Default));
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    let t = std::thread::spawn(move || {
        let mut s = TlsStream::accept(l.accept().unwrap().0, sc).unwrap();
        s.write_all(b"amount=1000").unwrap();
        s.get_ref().shutdown(Shutdown::Both).unwrap(); // FIN, no close_notify
    });
    let mut c = TlsStream::connect(TcpStream::connect(addr).unwrap(), cc, "server.test").unwrap();
    let mut got = Vec::new();
    let e = c.read_to_end(&mut got).unwrap_err();
    t.join().unwrap();
    assert_eq!(e.kind(), std::io::ErrorKind::UnexpectedEof);
    assert_eq!(got, b"amount=1000", "what did arrive is still delivered");
    assert!(!c.connection().peer_closed());
}

/// REQ-MSG-020: a ClientHello's extensions and key shares are bounded
/// before the duplicate checks that grow with their square.
#[test]
fn client_hello_extensions_and_key_shares_are_bounded() {
    let hello = |exts: &[u8]| {
        let mut body = vec![3, 3];
        body.extend_from_slice(&[7u8; 32]);
        body.push(0);
        body.extend_from_slice(&[0, 2, 0x13, 0x01, 1, 0]);
        body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        body.extend_from_slice(exts);
        let mut hs = vec![1u8];
        hs.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        hs.extend_from_slice(&body);
        let mut out = Vec::new();
        for chunk in hs.chunks(16384) {
            out.extend_from_slice(&[22, 3, 1]);
            out.extend_from_slice(&(chunk.len() as u16).to_be_bytes());
            out.extend_from_slice(chunk);
        }
        out
    };
    let pki = Pki::new(KeyKind::EcdsaP256, "server.test");
    let sc = Arc::new(pki.server_config(Profile::Default));
    let mut many = Vec::new();
    for i in 0..200u16 {
        many.extend_from_slice(&(0x4000 + i).to_be_bytes());
        many.extend_from_slice(&[0, 0]);
    }
    let e = Connection::server(sc.clone())
        .unwrap()
        .read_tls(&hello(&many))
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Decode, "{e}");
    assert!(e.to_string().contains("too many extensions"), "{e}");
    // Twenty key shares for distinct (unknown) groups.
    let mut shares = Vec::new();
    for g in 0..20u16 {
        shares.extend_from_slice(&(0x7000 + g).to_be_bytes());
        shares.extend_from_slice(&[0, 1, 0xaa]);
    }
    let mut ks = (shares.len() as u16).to_be_bytes().to_vec();
    ks.extend(shares);
    let mut ext = vec![0x00, 0x33];
    ext.extend_from_slice(&(ks.len() as u16).to_be_bytes());
    ext.extend(ks);
    let e = Connection::server(sc)
        .unwrap()
        .read_tls(&hello(&ext))
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::IllegalParameter, "{e}");
    assert!(e.to_string().contains("too many key shares"), "{e}");
}

fn external_psk(id: &[u8], key: u8) -> ironsocketlayer::config::ExternalPsk {
    ironsocketlayer::config::ExternalPsk::new(id, &[key; 32], HashAlg::Sha256).unwrap()
}

/// REQ-EPSK-005: a server refuses an external-PSK ClientHello that this
/// process sent itself, the "Selfie" reflection (RFC 9257 §4.1).
#[test]
fn a_reflected_external_psk_hello_is_refused() {
    use ironsocketlayer::config::ClientConfig;
    let cc = Arc::new(ClientConfig::external_psk(Profile::Default, external_psk(b"node-a", 1)).unwrap());
    let mut sc = ServerConfig::external_psk_only(Profile::Default, vec![external_psk(b"node-a", 1)])
        .unwrap();
    assert!(sc.selfie_guard, "the guard is on by default");
    let failure = connect(cc.clone(), Arc::new(sc.clone()), "node-a.local").unwrap_err();
    let e = failure.server.expect("the server refused");
    assert_eq!(e.kind(), ErrorKind::DecryptError, "{e}");
    assert!(e.to_string().contains("Selfie"), "{e}");
    // Control: the same exchange with the guard off completes.
    sc.selfie_guard = false;
    assert!(connect(cc, Arc::new(sc), "node-a.local").is_ok());
}

/// REQ-EPSK-006: a server that requires client certificates does not take an
/// external PSK in their place; and a PSK-only server cannot require them.
#[test]
fn a_required_client_certificate_is_not_waived_for_an_external_psk() {
    use ironsocketlayer::config::{ClientAuth, PeerVerification};
    let pki = Pki::new(KeyKind::EcdsaP256, "server.test");
    let mut cc = pki.client_config(Profile::Default);
    cc.external_psk = Some(external_psk(b"agent", 2));
    let mut sc = pki
        .server_config(Profile::Default)
        .with_client_auth(ClientAuth::Required(PeerVerification::Roots(pki.roots())));
    sc.external_psks = vec![external_psk(b"agent", 2)];
    sc.selfie_guard = false;
    let failure = connect(Arc::new(cc), Arc::new(sc), "server.test").unwrap_err();
    let e = failure.server.expect("the server refused");
    assert_eq!(e.kind(), ErrorKind::CertificateRequired, "{e}");
    let only = ServerConfig::external_psk_only(Profile::Default, vec![external_psk(b"agent", 2)])
        .unwrap()
        .with_client_auth(ClientAuth::Required(PeerVerification::Roots(pki.roots())));
    assert_eq!(only.validate().unwrap_err().kind(), ErrorKind::InvalidConfig);
}

/// REQ-EPSK-007: a server with only external PSKs answers an unknown
/// identity with the same alert as a known identity with a wrong key.
#[test]
fn unknown_and_wrongly_keyed_psk_identities_fail_alike() {
    use ironsocketlayer::config::ClientConfig;
    use ironsocketlayer::enums::AlertDescription;
    let mut sc = ServerConfig::external_psk_only(Profile::Default, vec![external_psk(b"known", 3)])
        .unwrap();
    sc.selfie_guard = false;
    let sc = Arc::new(sc);
    let mut alerts = Vec::new();
    for (id, key) in [(&b"known"[..], 4), (&b"unknown"[..], 3)] {
        let cc = Arc::new(ClientConfig::external_psk(Profile::Default, external_psk(id, key)).unwrap());
        let failure = connect(cc, sc.clone(), "gw.local").unwrap_err();
        let s = failure.server.expect("the server refused");
        assert_eq!(s.kind(), ErrorKind::DecryptError, "{s}");
        alerts.push(failure.client.and_then(|e| e.peer_alert()));
    }
    assert_eq!(alerts, [Some(AlertDescription::DecryptError); 2]);
}

/// REQ-NEG-002: a server refuses an SNI that none of its certificates covers
/// with unrecognized_name, in both engines, unless told to fall back; a client
/// that sends no SNI still gets the default certificate.
#[test]
fn an_unknown_server_name_is_refused_with_unrecognized_name() {
    use ironsocketlayer::enums::AlertDescription;
    let pki = Pki::new(KeyKind::EcdsaP256, "server.test");
    let mut cc = pki.client_config(Profile::Default);
    let sc = pki.server_config(Profile::Default);
    let failure = connect(Arc::new(cc.clone()), Arc::new(sc.clone()), "other.test").unwrap_err();
    let s = failure.server.expect("the server refused");
    assert_eq!(s.kind(), ErrorKind::UnrecognizedName, "{s}");
    assert_eq!(
        failure.client.and_then(|e| e.peer_alert()),
        Some(AlertDescription::UnrecognizedName)
    );
    // With the fallback, the server answers and the client refuses the name.
    let mut fallback = sc.clone();
    fallback.sni_fallback = true;
    let failure = connect(Arc::new(cc.clone()), Arc::new(fallback), "other.test").unwrap_err();
    assert_eq!(
        failure.client.map(|e| e.kind()),
        Some(ErrorKind::CertificateNameMismatch)
    );
    // No SNI: the default certificate, which covers the name checked.
    cc.send_sni = false;
    assert!(connect(Arc::new(cc), Arc::new(sc), "server.test").is_ok());
}
