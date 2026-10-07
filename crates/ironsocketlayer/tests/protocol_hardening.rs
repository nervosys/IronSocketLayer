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
use ironsocketlayer::report::HandshakeState;
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

/// REQ-CONN-004: one compatibility ChangeCipherSpec record (RFC 8446
/// appendix D.4); a second is unexpected_message, as tlsfuzzer's
/// test-tls13-multiple-ccs-messages expects.
#[test]
fn change_cipher_spec_records_are_bounded() {
    let pki = Pki::new(KeyKind::EcdsaP256, "server.test");
    let mut c =
        Connection::client(Arc::new(pki.client_config(Profile::Default)), "server.test").unwrap();
    let mut s = Connection::server(Arc::new(pki.server_config(Profile::Default))).unwrap();
    s.read_tls(&c.take_tls()).unwrap();
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

/// REQ-MSG-020: a ClientHello may carry as many extensions and key shares
/// as fit in it (RFC 8446 sets no lower limit, and tlsfuzzer checks that
/// servers accept over a thousand unknown extensions); duplicates are still
/// refused, and finding them costs O(n log n), so even the largest hello
/// decodes quickly.
#[test]
fn client_hello_extensions_and_key_shares_scale() {
    let body = |exts: &[u8]| {
        let mut body = vec![3, 3];
        body.extend_from_slice(&[7u8; 32]);
        body.push(0);
        body.extend_from_slice(&[0, 2, 0x13, 0x01, 1, 0]);
        body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        body.extend_from_slice(exts);
        body
    };
    let empty_unknown = |n: u16| {
        let mut out = Vec::new();
        for i in 0..n {
            out.extend_from_slice(&(0x4000 + i).to_be_bytes());
            out.extend_from_slice(&[0, 0]);
        }
        out
    };
    // As many empty unknown extensions as an extension block holds.
    let most = (65_535 / 4) as u16 - 1;
    let exts = empty_unknown(most);
    let started = std::time::Instant::now();
    let ch = ClientHello::decode(&body(&exts)).unwrap();
    assert_eq!(ch.other_extensions.len(), usize::from(most));
    assert!(started.elapsed() < std::time::Duration::from_secs(1));
    // One repeat anywhere is refused.
    let mut dup = empty_unknown(1500);
    dup.extend_from_slice(&0x4000u16.to_be_bytes());
    dup.extend_from_slice(&[0, 0]);
    let e = ClientHello::decode(&body(&dup)).unwrap_err();
    assert_eq!(e.kind(), ErrorKind::IllegalParameter, "{e}");
    assert_eq!(e.context(), "duplicate extension");

    // As many one-byte key shares for distinct groups as fit.
    let key_shares = |groups: &[u16]| {
        let mut shares = Vec::new();
        for g in groups {
            shares.extend_from_slice(&g.to_be_bytes());
            shares.extend_from_slice(&[0, 1, 0xaa]);
        }
        let mut ks = (shares.len() as u16).to_be_bytes().to_vec();
        ks.extend(shares);
        let mut ext = vec![0x00, 0x33];
        ext.extend_from_slice(&(ks.len() as u16).to_be_bytes());
        ext.extend(ks);
        ext
    };
    let groups: Vec<u16> = (0..12_000u16).map(|g| 0x1000 + g).collect();
    let started = std::time::Instant::now();
    let ch = ClientHello::decode(&body(&key_shares(&groups))).unwrap();
    assert_eq!(ch.key_shares.len(), groups.len());
    assert!(started.elapsed() < std::time::Duration::from_secs(1));
    let mut repeated = groups[..2000].to_vec();
    repeated.push(groups[0]);
    let e = ClientHello::decode(&body(&key_shares(&repeated))).unwrap_err();
    assert_eq!(e.kind(), ErrorKind::IllegalParameter, "{e}");
    assert_eq!(e.context(), "two key shares for one group");
}

fn external_psk(id: &[u8], key: u8) -> ironsocketlayer::config::ExternalPsk {
    ironsocketlayer::config::ExternalPsk::new(id, &[key; 32], HashAlg::Sha256).unwrap()
}

/// REQ-EPSK-005: a server refuses an external-PSK ClientHello that this
/// process sent itself, the "Selfie" reflection (RFC 9257 §4.1).
#[test]
fn a_reflected_external_psk_hello_is_refused() {
    use ironsocketlayer::config::ClientConfig;
    let cc =
        Arc::new(ClientConfig::external_psk(Profile::Default, external_psk(b"node-a", 1)).unwrap());
    let mut sc =
        ServerConfig::external_psk_only(Profile::Default, vec![external_psk(b"node-a", 1)])
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
    assert_eq!(
        only.validate().unwrap_err().kind(),
        ErrorKind::InvalidConfig
    );
}

/// REQ-EPSK-007: a server with only external PSKs answers an unknown
/// identity with the same alert as a known identity with a wrong key.
#[test]
fn unknown_and_wrongly_keyed_psk_identities_fail_alike() {
    use ironsocketlayer::config::ClientConfig;
    use ironsocketlayer::enums::AlertDescription;
    let mut sc =
        ServerConfig::external_psk_only(Profile::Default, vec![external_psk(b"known", 3)]).unwrap();
    sc.selfie_guard = false;
    let sc = Arc::new(sc);
    let mut alerts = Vec::new();
    for (id, key) in [(&b"known"[..], 4), (&b"unknown"[..], 3)] {
        let cc =
            Arc::new(ClientConfig::external_psk(Profile::Default, external_psk(id, key)).unwrap());
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

/// Move records both ways until neither side has anything to send.
fn pump_both(c: &mut Connection, s: &mut Connection) -> ironsocketlayer::Result<()> {
    for _ in 0..4 {
        let to_c = s.take_tls();
        if !to_c.is_empty() {
            c.read_tls(&to_c)?;
        }
        let to_s = c.take_tls();
        if !to_s.is_empty() {
            s.read_tls(&to_s)?;
        }
    }
    Ok(())
}

/// REQ-PHA-005: a client answers at most 16 post-handshake
/// CertificateRequests on one connection, so a server cannot make it sign
/// without end.
#[test]
fn post_handshake_certificate_requests_are_bounded() {
    use ironsocketlayer::client::MAX_POST_HANDSHAKE_REQUESTS;
    use ironsocketlayer::config::{ClientAuth, PeerVerification};
    let pki = Pki::new(KeyKind::EcdsaP256, "server.test");
    let mut cc = pki
        .client_config(Profile::Default)
        .with_identity(pki.client_identity(KeyKind::EcdsaP256, "agent-7"));
    cc.post_handshake_auth = true;
    let sc = pki
        .server_config(Profile::Default)
        .with_client_auth(ClientAuth::OnDemand(PeerVerification::Roots(pki.roots())));
    let (mut c, mut s) = connect(Arc::new(cc), Arc::new(sc), "server.test").unwrap();
    for _ in 0..MAX_POST_HANDSHAKE_REQUESTS {
        s.request_client_auth().unwrap();
        pump_both(&mut c, &mut s).unwrap();
    }
    s.request_client_auth().unwrap();
    let e = pump_both(&mut c, &mut s).unwrap_err();
    assert_eq!(e.kind(), ErrorKind::CapacityExceeded, "{e}");
    assert_eq!(
        c.error().map(|e| e.kind()),
        Some(ErrorKind::CapacityExceeded)
    );
}

/// REQ-CONN-012: received application data the application has not read is
/// bounded; past the bound the connection fails closed.
#[test]
fn unread_application_data_is_bounded() {
    let pki = Pki::new(KeyKind::EcdsaP256, "server.test");
    let mut cc = pki.client_config(Profile::Default);
    cc.common.max_buffered_plaintext = 4096;
    let (mut c, mut s) = connect(
        Arc::new(cc),
        Arc::new(pki.server_config(Profile::Default)),
        "server.test",
    )
    .unwrap();
    // Read as it arrives: any amount passes.
    let mut buf = vec![0u8; 4096];
    for _ in 0..4 {
        s.send(&[7u8; 4000]).unwrap();
        c.read_tls(&s.take_tls()).unwrap();
        assert_eq!(c.recv(&mut buf), 4000);
    }
    // Left unread, the bound holds.
    s.send(&[7u8; 4000]).unwrap();
    s.send(&[7u8; 200]).unwrap();
    let e = c.read_tls(&s.take_tls()).unwrap_err();
    assert_eq!(e.kind(), ErrorKind::CapacityExceeded, "{e}");
    assert!(c.available() <= 4096);
}

/// REQ-0RTT-006: a full replay guard refuses early data, and the server
/// reports that the guard was full rather than a replay.
#[test]
fn a_full_replay_guard_is_reported() {
    use ironsocketlayer::config::EarlyDataPolicy;
    use ironsocketlayer::resumption::MemoryReplayGuard;
    let pki = Pki::new(KeyKind::EcdsaP256, "server.test");
    let mut cc = pki.client_config(Profile::Default);
    cc.early_data = true;
    let cc = Arc::new(cc);
    let mut sc = pki.server_config(Profile::Default);
    let mut policy = EarlyDataPolicy::new(16_384);
    policy.replay = Arc::new(MemoryReplayGuard::with_capacity(1));
    sc.early_data = Some(policy);
    let sc = Arc::new(sc);
    let ticket = |cc: &Arc<_>| {
        let (mut c, mut s) = connect(Arc::clone(cc), sc.clone(), "server.test").unwrap();
        c.read_tls(&s.take_tls()).unwrap();
    };
    let early = |cc: &Arc<_>| {
        let mut c =
            Connection::client_with_early_data(Arc::clone(cc), "server.test", b"GET /").unwrap();
        let mut s = Connection::server(sc.clone()).unwrap();
        s.read_tls(&c.take_tls()).unwrap();
        pump_both(&mut c, &mut s).unwrap();
        s
    };
    ticket(&cc);
    let s = early(&cc);
    assert_eq!(s.report().early_data, "early-data:accepted");
    ticket(&cc);
    let s = early(&cc);
    assert_eq!(s.report().early_data, "early-data:rejected");
    assert!(
        s.report()
            .events
            .iter()
            .any(|e| e.id == "event:replay-guard-full"),
        "{}",
        s.report().to_json()
    );
}

/// REQ-CONN-012: accepted 0-RTT data the server has not read counts against
/// the same bound.
#[test]
fn unread_early_data_is_bounded() {
    use ironsocketlayer::config::EarlyDataPolicy;
    let pki = Pki::new(KeyKind::EcdsaP256, "server.test");
    let mut cc = pki.client_config(Profile::Default);
    cc.early_data = true;
    let cc = Arc::new(cc);
    let mut sc = pki.server_config(Profile::Default);
    sc.early_data = Some(EarlyDataPolicy::new(16_384));
    sc.common.max_buffered_plaintext = 1000;
    let sc = Arc::new(sc);
    let (mut c, mut s) = connect(cc.clone(), sc.clone(), "server.test").unwrap();
    c.read_tls(&s.take_tls()).unwrap();
    let mut c = Connection::client_with_early_data(cc, "server.test", &[1u8; 1500]).unwrap();
    let mut s = Connection::server(sc).unwrap();
    let e = s.read_tls(&c.take_tls()).unwrap_err();
    assert_eq!(e.kind(), ErrorKind::CapacityExceeded, "{e}");
}

/// The ClientHello in the first record of `flight`.
fn client_hello_in(flight: &[u8]) -> ClientHello {
    let mut flight = flight.to_vec();
    let rec = record::take_record(&mut flight).unwrap().unwrap();
    ClientHello::decode(&rec.body[4..]).unwrap()
}

/// REQ-ECH-011: the fixed client sends GREASE too, repeats it unchanged
/// after HelloRetryRequest, ignores the retry configurations an ECH server
/// answers with, and sends none when `ech_grease` is off.
#[test]
fn the_fixed_client_greases_ech() {
    use ironsocketlayer::config::ClientConfig;
    let pki = Pki::new(KeyKind::EcdsaP256, "server.test");
    let fixed_client = |grease: bool| {
        let mut cc: ClientConfig = pki.client_config(Profile::Default);
        cc.tickets = None;
        cc.ech_grease = grease;
        cc.common.groups = vec![NamedGroup::X25519, NamedGroup::Secp384r1];
        cc.initial_key_shares = 1;
        cc
    };
    let ech = Arc::new(
        EchServer::generate(3, "server.test", 64, &mut ic_drbg::Rng::from_os().unwrap()).unwrap(),
    );
    let mut sc = pki.server_config(Profile::Default);
    sc.ech = Some(ech);
    sc.common.groups = vec![NamedGroup::Secp384r1]; // forces HelloRetryRequest
    let sc = Arc::new(sc);

    let cc = fixed_client(true);
    let mut b = Buffers::new();
    let mut rng = ic_drbg::Rng::from_os().unwrap();
    let mut c = fixed::Connection::client(
        &cc,
        "server.test",
        &mut rng,
        b.storage(),
        fixed::Limits::default(),
    )
    .unwrap();
    let mut s = Connection::server(sc.clone()).unwrap();
    let first = c.take();
    let grease = client_hello_in(&first).ech.expect("a GREASE extension");
    assert!(matches!(grease, msgs::EchHello::Outer { ref enc, .. } if enc.len() == 32));
    s.feed(&first).unwrap();
    c.feed(&s.take()).unwrap();
    let second = c.take();
    assert_eq!(
        client_hello_in(&second).ech,
        Some(grease),
        "repeated after HRR"
    );
    s.feed(&second).unwrap();
    for _ in 0..4 {
        let to_c = s.take();
        if !to_c.is_empty() {
            c.feed(&to_c).unwrap();
        }
        let to_s = c.take();
        if !to_s.is_empty() {
            s.feed(&to_s).unwrap();
        }
    }
    assert!(s.report().hello_retry);
    assert_eq!(
        s.report().ech,
        "ech:rejected",
        "the server sent retry configurations"
    );
    assert_eq!(c.report().state, HandshakeState::Connected);
    assert!(!s.is_handshaking(), "{:?}", s.error());

    // Off: no extension.
    let cc = fixed_client(false);
    let mut b = Buffers::new();
    let mut rng = ic_drbg::Rng::from_os().unwrap();
    let mut c = fixed::Connection::client(
        &cc,
        "server.test",
        &mut rng,
        b.storage(),
        fixed::Limits::default(),
    )
    .unwrap();
    assert_eq!(client_hello_in(&c.take()).ech, None);
}

/// REQ-REC-010: the record layer's legacy version is ignored apart from its
/// major byte (RFC 8446 §5.1: "MUST be ignored for all purposes"), in both
/// engines; tlsfuzzer, for one, sends 0x0300. A record that is not TLS at
/// all (here the start of an HTTP request) is refused.
#[test]
fn the_legacy_record_version_is_ignored() {
    let pki = Pki::new(KeyKind::EcdsaP256, "server.test");
    let mut cc = pki.client_config(Profile::Default);
    cc.common.groups = vec![NamedGroup::X25519];
    cc.ech_grease = false;
    let cc = Arc::new(cc);
    let sc = server_config(&pki);
    for minor in [0x00, 0x01, 0x02, 0x03, 0x04, 0xff] {
        let mut hello = Connection::client(cc.clone(), "server.test")
            .unwrap()
            .take_tls();
        hello[2] = minor;
        let mut owned = Connection::server(Arc::new(sc.clone())).unwrap();
        owned
            .read_tls(&hello)
            .unwrap_or_else(|e| panic!("owned, 0x03{minor:02x}: {e}"));
        assert!(
            !owned.take_tls().is_empty(),
            "owned answered 0x03{minor:02x}"
        );
        let mut b = Buffers::new();
        let mut rng = ic_drbg::Rng::from_os().unwrap();
        let mut fixed =
            fixed::Connection::server(&sc, &mut rng, b.storage(), fixed::Limits::default())
                .unwrap();
        fixed
            .receive(&hello)
            .unwrap_or_else(|e| panic!("fixed, 0x03{minor:02x}: {e}"));
    }
    // Not TLS: an HTTP request, and a handshake record of major version 2.
    let http = b"GET / HTTP/1.1
Host: x

"
    .to_vec();
    let mut hello = Connection::client(cc.clone(), "server.test")
        .unwrap()
        .take_tls();
    hello[1] = 0x02;
    for (bytes, owned_kind) in [
        (http, ErrorKind::UnexpectedMessage),
        (hello, ErrorKind::Decode),
    ] {
        let mut owned = Connection::server(Arc::new(sc.clone())).unwrap();
        assert_eq!(owned.read_tls(&bytes).unwrap_err().kind(), owned_kind);
        let mut b = Buffers::new();
        let mut rng = ic_drbg::Rng::from_os().unwrap();
        let mut fixed =
            fixed::Connection::server(&sc, &mut rng, b.storage(), fixed::Limits::default())
                .unwrap();
        assert!(fixed.receive(&bytes).is_err());
    }
}

/// The client side of a handshake up to, not including, the client's
/// Finished: its handshake write key and the server's application read key.
fn raw_before_client_finished(peer: &mut impl Peer) -> (Protector, Protector) {
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
    let shm = record::take_record(&mut out).unwrap().unwrap().body;
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
    while let Some(r) = record::take_record(&mut out).unwrap() {
        if r.header[0] == 20 {
            continue;
        }
        let mut body = r.body;
        let (_, n) = sread.open(&r.header, &mut body).unwrap();
        buf.extend_from_slice(&body[..n]);
        while let Some((_, m)) = msgs::take_message(&mut buf, 1 << 20).unwrap() {
            th.update(&m);
        }
    }
    let h2 = th.peek();
    let s_ap = hs
        .into_master()
        .unwrap()
        .server_traffic(h2.as_bytes())
        .unwrap();
    (
        Protector::new(SUITE, &c_hs).unwrap(),
        Protector::new(SUITE, &s_ap).unwrap(),
    )
}

/// Application data before the client's Finished, even empty, is refused
/// with an unexpected_message alert the client can read (under the server's
/// application key, which it has switched to after its own Finished).
/// Found by tlsfuzzer's test-tls13-zero-length-data.
#[test]
fn application_data_before_the_client_finished_gets_a_readable_alert() {
    for payload in [&b""[..], b"early"] {
        let pki = Pki::new(KeyKind::EcdsaP256, "server.test");
        let mut s = Connection::server(Arc::new(server_config(&pki))).unwrap();
        let (mut w, mut r) = raw_before_client_finished(&mut s);
        let rec = seal(&mut w, ContentType::ApplicationData, payload);
        assert_eq!(
            s.read_tls(&rec).unwrap_err().kind(),
            ErrorKind::UnexpectedMessage
        );
        let mut out = s.take_tls();
        let alert = record::take_record(&mut out)
            .unwrap()
            .expect("an alert record");
        let mut body = alert.body;
        let (ty, n) = r.open(&alert.header, &mut body).expect("readable");
        assert_eq!(ty, ContentType::Alert);
        assert_eq!(&body[..n], &[2, 10]);
    }
}

/// REQ-MSG-021, REQ-MSG-022, REQ-REC-011: three refusals tlsfuzzer checks.
/// A ClientHello legacy_version below SSL 3.0 is protocol_version; a TLS 1.3
/// ClientHello with supported_groups but no key_share (or the reverse) is
/// missing_extension (RFC 8446 §9.2; tests/conformance.rs), where it used to
/// draw a HelloRetryRequest; and an empty alert record is unexpected_message.
#[test]
fn tlsfuzzer_refusals() {
    let pki = Pki::new(KeyKind::EcdsaP256, "server.test");
    let sc = Arc::new(server_config(&pki));
    let hello = |edit: &dyn Fn(&mut ClientHello)| {
        let mut ch = ClientHello {
            random: [7; 32],
            session_id: vec![1; 32],
            suites: vec![SUITE],
            server_name: Some("server.test".into()),
            groups: vec![NamedGroup::X25519],
            sig_algs: vec![SignatureScheme::EcdsaSecp256r1Sha256],
            versions: vec![ProtocolVersion::Tls13],
            key_shares: vec![(NamedGroup::X25519, vec![9; 32])],
            ..Default::default()
        };
        edit(&mut ch);
        let m = msgs::frame(HandshakeType::ClientHello, &ch.encode().unwrap()).unwrap();
        let mut rec = vec![22, 3, 1];
        rec.extend((m.len() as u16).to_be_bytes());
        rec.extend(m);
        rec
    };
    let refused = |rec: &[u8]| {
        let mut s = Connection::server(sc.clone()).unwrap();
        s.read_tls(rec).unwrap_err()
    };
    for v in [0x0000u16, 0x0002, 0x0200, 0x02ff] {
        let mut rec = hello(&|_| {});
        rec[9..11].copy_from_slice(&v.to_be_bytes());
        assert_eq!(refused(&rec).kind(), ErrorKind::ProtocolVersion, "{v:#06x}");
    }
    // An omitted key_share is tests/conformance.rs's; an empty one, which
    // RFC 8446 §4.2.8 allows, still draws a HelloRetryRequest.
    let mut s = Connection::server(sc.clone()).unwrap();
    s.read_tls(&hello(&|ch| ch.key_shares.clear())).unwrap();
    let flight = s.take_tls();
    let r = record::take_record(&mut flight.clone()).unwrap().unwrap();
    let sh = ServerHello::decode(&r.body[4..]).unwrap();
    assert!(sh.is_retry());
    // An empty alert record, encrypted (with and without padding), as
    // tlsfuzzer sends it.
    for pad in [0usize, 5] {
        let pki = Pki::new(KeyKind::EcdsaP256, "server.test");
        let mut s = Connection::server(Arc::new(server_config(&pki))).unwrap();
        let mut raw = raw_handshake(&mut s);
        let mut rec = Vec::new();
        raw.write
            .seal(ContentType::Alert, b"", pad, &mut rec)
            .unwrap();
        let e = s.read_tls(&rec).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::UnexpectedMessage, "{e}");
        assert_eq!(e.context(), "empty alert record");
    }
}

/// REQ-KS-004: a client Finished padded or truncated (tlsfuzzer's
/// test-tls13-finished) is decode_error; one of the right length that does
/// not verify stays decrypt_error. One announced as 16 MiB is refused on its
/// header alone.
#[test]
fn a_finished_of_the_wrong_length_is_decode_error() {
    {
        let pki = Pki::new(KeyKind::EcdsaP256, "server.test");
        let mut s = Connection::server(Arc::new(server_config(&pki))).unwrap();
        let (mut w, _) = raw_before_client_finished(&mut s);
        let header = [20u8, 0xff, 0xff, 0xff];
        let rec = seal(&mut w, ContentType::Handshake, &header);
        let e = s.read_tls(&rec).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Decode, "{e}");
        // One alert, and nothing more however much follows.
        let mut out = s.take_tls();
        assert!(record::take_record(&mut out).unwrap().is_some());
        assert!(out.is_empty(), "exactly one record");
        let more = seal(&mut w, ContentType::Handshake, &[0u8; 1000]);
        assert!(s.read_tls(&more).is_err());
        assert!(s.take_tls().is_empty(), "no second alert");
    }
    for (len, kind) in [
        (28usize, ErrorKind::Decode),
        (40, ErrorKind::Decode),
        (32, ErrorKind::DecryptError),
    ] {
        let pki = Pki::new(KeyKind::EcdsaP256, "server.test");
        let mut s = Connection::server(Arc::new(server_config(&pki))).unwrap();
        let (mut w, _) = raw_before_client_finished(&mut s);
        let fin = msgs::frame(HandshakeType::Finished, &vec![0x5a; len]).unwrap();
        let rec = seal(&mut w, ContentType::Handshake, &fin);
        assert_eq!(s.read_tls(&rec).unwrap_err().kind(), kind, "{len}");
    }
}

/// REQ-0RTT-008: with no 0-RTT to skip, an application-data record before
/// any keys, even an empty one, is unexpected_message: a zero skip budget
/// covers a zero-length record no better than any other. Found by
/// tlsfuzzer's test-tls13-zero-length-data, which sends one between the
/// fragments of a ClientHello.
#[test]
fn an_empty_application_data_record_before_keys_is_refused() {
    let pki = Pki::new(KeyKind::EcdsaP256, "server.test");
    let sc = Arc::new(server_config(&pki));
    // Alone, before anything.
    let mut s = Connection::server(sc.clone()).unwrap();
    let e = s.read_tls(&[23, 3, 3, 0, 0]).unwrap_err();
    assert_eq!(e.kind(), ErrorKind::UnexpectedMessage, "{e}");
    // Between two fragments of a ClientHello.
    let hello = Connection::client(Arc::new(pki.client_config(Profile::Default)), "server.test")
        .unwrap()
        .take_tls();
    let mut first = vec![22, 3, 1, 0, 2];
    first.extend_from_slice(&hello[5..7]);
    let mut s = Connection::server(sc).unwrap();
    s.read_tls(&first).unwrap();
    let e = s.read_tls(&[23, 3, 3, 0, 0]).unwrap_err();
    assert_eq!(e.kind(), ErrorKind::UnexpectedMessage, "{e}");
    assert!(!s.take_tls().is_empty(), "an alert");
}

/// REQ-FIX-006: both servers refuse a ClientHello whose
/// signature_algorithms_cert is malformed; the fixed engine, which does not
/// use the extension, used to ignore it. Found by the hello_differential
/// fuzz target.
#[test]
fn both_engines_refuse_a_malformed_signature_algorithms_cert() {
    let pki = Pki::new(KeyKind::EcdsaP256, "server.test");
    let sc = server_config(&pki);
    let ch = ClientHello {
        random: [7; 32],
        session_id: vec![1; 32],
        suites: vec![SUITE],
        server_name: Some("server.test".into()),
        groups: vec![NamedGroup::X25519],
        sig_algs: vec![SignatureScheme::EcdsaSecp256r1Sha256],
        sig_algs_cert: Some(vec![SignatureScheme::EcdsaSecp256r1Sha256]),
        versions: vec![ProtocolVersion::Tls13],
        key_shares: vec![(
            NamedGroup::X25519,
            KeyShare::generate(NamedGroup::X25519, &mut ic_drbg::Rng::from_os().unwrap())
                .unwrap()
                .public()
                .to_vec(),
        )],
        ..Default::default()
    };
    let mut body = ch.encode().unwrap();
    // signature_algorithms_cert (0x0032): its list length runs past its body.
    let at = body
        .windows(4)
        .position(|w| w == [0x00, 0x32, 0x00, 0x04])
        .expect("signature_algorithms_cert");
    body[at + 4] = 0x24;
    let m = msgs::frame(HandshakeType::ClientHello, &body).unwrap();
    let mut rec = vec![22, 3, 1];
    rec.extend((m.len() as u16).to_be_bytes());
    rec.extend(&m);
    let mut owned = Connection::server(Arc::new(sc.clone())).unwrap();
    assert_eq!(owned.read_tls(&rec).unwrap_err().kind(), ErrorKind::Decode);
    let mut b = Buffers::new();
    let mut rng = ic_drbg::Rng::from_os().unwrap();
    let mut fixed =
        fixed::Connection::server(&sc, &mut rng, b.storage(), fixed::Limits::default()).unwrap();
    assert!(fixed.receive(&rec).is_err());
}

/// REQ-REC-010: a record header announcing more than 2^14 + 256 bytes is
/// refused on the header alone, by both engines. Found by the
/// hello_differential fuzz target.
#[test]
fn an_oversized_record_header_is_refused_at_once() {
    let pki = Pki::new(KeyKind::EcdsaP256, "server.test");
    let sc = server_config(&pki);
    let header = [22u8, 3, 3, 0x41, 0x01]; // 16641 bytes
    let mut owned = Connection::server(Arc::new(sc.clone())).unwrap();
    assert_eq!(
        owned.read_tls(&header).unwrap_err().kind(),
        ErrorKind::RecordOverflow
    );
    let mut b = Buffers::new();
    let mut rng = ic_drbg::Rng::from_os().unwrap();
    let mut fixed =
        fixed::Connection::server(&sc, &mut rng, b.storage(), fixed::Limits::default()).unwrap();
    assert_eq!(
        fixed.receive(&header).unwrap_err().kind(),
        ErrorKind::RecordOverflow
    );
}

/// REQ-REC-004: both servers refuse a zero-length record other than
/// application data on its header alone, rather than when the next byte
/// arrives. Found by the hello_differential fuzz target.
#[test]
fn both_engines_refuse_an_empty_record_on_its_header() {
    let pki = Pki::new(KeyKind::EcdsaP256, "server.test");
    let sc = server_config(&pki);
    for ty in [20u8, 21, 22] {
        let header = [ty, 3, 3, 0, 0];
        let mut owned = Connection::server(Arc::new(sc.clone())).unwrap();
        assert_eq!(
            owned.read_tls(&header).unwrap_err().kind(),
            ErrorKind::Decode,
            "owned, type {ty}"
        );
        let mut b = Buffers::new();
        let mut rng = ic_drbg::Rng::from_os().unwrap();
        let mut fixed =
            fixed::Connection::server(&sc, &mut rng, b.storage(), fixed::Limits::default())
                .unwrap();
        assert_eq!(
            fixed.receive(&header).unwrap_err().kind(),
            ErrorKind::Decode,
            "fixed, type {ty}"
        );
    }
}

/// REQ-FIX-007: both servers skip a server_name entry of a type other than
/// host_name and use the host_name entry (RFC 6066 §3). Found by the
/// hello_differential fuzz target.
#[test]
fn both_engines_skip_server_name_entries_of_other_types() {
    let pki = Pki::new(KeyKind::EcdsaP256, "server.test");
    let sc = server_config(&pki);
    let mut cc = pki.client_config(Profile::Default);
    cc.common.groups = vec![NamedGroup::X25519];
    cc.ech_grease = false;
    let mut hello = Connection::client(Arc::new(cc), "server.test")
        .unwrap()
        .take_tls();
    // server_name: list length 14, host_name (0) "server.test"; retype the
    // entry by inserting an entry of type 0x18 before it.
    let sni = [0x00u8, 0x00, 0x00, 0x10, 0x00, 0x0e, 0x00, 0x00, 0x0b];
    let at = hello
        .windows(sni.len())
        .position(|w| w == sni)
        .expect("server_name");
    let extra = [0x18u8, 0x00, 0x01, b'x'];
    // Grow the extension, the list, the extensions block, the handshake
    // message and the record by the inserted entry.
    hello.splice(at + 6..at + 6, extra);
    let grow = |v: &mut Vec<u8>, i: usize, by: u16| {
        let n = u16::from_be_bytes([v[i], v[i + 1]]) + by;
        v[i..i + 2].copy_from_slice(&n.to_be_bytes());
    };
    grow(&mut hello, at + 2, 4);
    grow(&mut hello, at + 4, 4);
    grow(&mut hello, 3, 4);
    let hs_len = u32::from_be_bytes([0, hello[6], hello[7], hello[8]]) + 4;
    hello[6..9].copy_from_slice(&hs_len.to_be_bytes()[1..]);
    // The extensions block length: after version, random, session id,
    // suites and compression.
    let body = 9;
    let mut p = body + 2 + 32;
    p += 1 + hello[p] as usize;
    p += 2 + u16::from_be_bytes([hello[p], hello[p + 1]]) as usize;
    p += 1 + hello[p] as usize;
    grow(&mut hello, p, 4);
    let ch = ClientHello::decode(&hello[9..]).unwrap();
    assert_eq!(ch.server_name.as_deref(), Some("server.test"));
    let mut owned = Connection::server(Arc::new(sc.clone())).unwrap();
    owned.read_tls(&hello).unwrap();
    let mut b = Buffers::new();
    let mut rng = ic_drbg::Rng::from_os().unwrap();
    let mut fixed =
        fixed::Connection::server(&sc, &mut rng, b.storage(), fixed::Limits::default()).unwrap();
    fixed.receive(&hello).unwrap();
}

/// REQ-FIX-008: both servers ignore a ClientHello legacy_version above SSL
/// 3.0 (the version comes from supported_versions) and refuse SSL 3.0 and
/// below with protocol_version. Found by the hello_differential fuzz
/// target; tlsfuzzer's test-tls13-legacy-version checks the same.
#[test]
fn both_engines_treat_the_legacy_version_alike() {
    let pki = Pki::new(KeyKind::EcdsaP256, "server.test");
    let sc = server_config(&pki);
    let mut cc = pki.client_config(Profile::Default);
    cc.common.groups = vec![NamedGroup::X25519];
    cc.ech_grease = false;
    let hello = Connection::client(Arc::new(cc), "server.test")
        .unwrap()
        .take_tls();
    for (version, refused) in [
        (0x0303u16, false),
        (0x0304, false),
        (0x0301, false),
        (0xffff, false),
        (0x0300, true),
        (0x0200, true),
    ] {
        let mut h = hello.clone();
        h[9..11].copy_from_slice(&version.to_be_bytes());
        let mut owned = Connection::server(Arc::new(sc.clone())).unwrap();
        let o = owned.read_tls(&h);
        let mut b = Buffers::new();
        let mut rng = ic_drbg::Rng::from_os().unwrap();
        let mut fixed =
            fixed::Connection::server(&sc, &mut rng, b.storage(), fixed::Limits::default())
                .unwrap();
        let f = fixed.receive(&h);
        assert_eq!(o.is_err(), refused, "owned {version:#06x}");
        assert_eq!(f.is_err(), refused, "fixed {version:#06x}");
        if refused {
            assert_eq!(o.unwrap_err().kind(), ErrorKind::ProtocolVersion);
            assert_eq!(f.unwrap_err().kind(), ErrorKind::ProtocolVersion);
        }
    }
}
