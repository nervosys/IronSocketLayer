//! Fixtures shared by the fuzz targets and the seed-corpus generator.
//!
//! Everything is deterministic: a fixed clock and a DRBG from a fixed seed,
//! so a crashing input reproduces exactly, on any machine, with
//! `cargo fuzz run <target> <crash-file>`.

use std::sync::{Arc, OnceLock};

use ic_core::traits::RandomSource;
use ironsocketlayer::config::{
    ClientAuth, ClientConfig, EarlyDataPolicy, ExternalPsk, Identity, PeerVerification, Profile,
    ServerConfig,
};
use ironsocketlayer::crypto::sign::{KeyKind, SigningKey};
use ironsocketlayer::crypto::HashAlg;
use ironsocketlayer::ech::EchServer;
use ironsocketlayer::x509::{self, CertificateParams, RootStore, Usage};
use ironsocketlayer::Result;

/// 2026-09-28T00:00:00Z. Certificates are valid for a day either side.
pub const NOW: u64 = 1_790_553_600;

/// The name the server certificate is issued for.
pub const NAME: &str = "fuzz.test";

/// The ECH public name.
pub const PUBLIC_NAME: &str = "public.fuzz.test";

fn clock() -> u64 {
    NOW
}

/// A DRBG from a fixed seed. Each call starts the same stream, so a
/// connection's randomness depends only on the inputs it has been fed.
pub fn fixed_rng() -> Result<Box<dyn RandomSource + Send>> {
    let rng = ic_drbg::Rng::from_entropy(&[0x5a; 48], b"isl-fuzz")
        .map_err(|_| ironsocketlayer::Error::new(ironsocketlayer::ErrorKind::Entropy, "drbg"))?;
    Ok(Box::new(rng))
}

fn rng() -> Box<dyn RandomSource + Send> {
    fixed_rng().expect("fixed DRBG")
}

/// A CA, a server certificate issued by it, and the keys.
pub struct Pki {
    pub ca_cert: Vec<u8>,
    pub ca_key: SigningKey,
    pub leaf: Vec<u8>,
    pub identity: Identity,
    pub roots: RootStore,
    pub ech: Arc<EchServer>,
}

/// The fixtures, built once per process.
pub fn pki() -> &'static Pki {
    static PKI: OnceLock<Pki> = OnceLock::new();
    PKI.get_or_init(|| {
        let mut r = rng();
        let ca_key = SigningKey::generate(KeyKind::EcdsaP256, &mut *r).unwrap();
        let ca_cert = x509::self_signed(
            &CertificateParams {
                subject_cn: "IronSocketLayer Fuzz Root",
                dns_names: &[],
                ip_addresses: &[],
                not_before: NOW - 86_400,
                not_after: NOW + 86_400,
                is_ca: true,
                path_len: Some(1),
                usage: &[],
                serial: [1; 16],
            },
            &ca_key,
            &mut *r,
        )
        .unwrap();
        let leaf_key = SigningKey::generate(KeyKind::EcdsaP256, &mut *r).unwrap();
        let leaf = x509::issue(
            &CertificateParams {
                subject_cn: NAME,
                dns_names: &[NAME, PUBLIC_NAME],
                ip_addresses: &[],
                not_before: NOW - 86_400,
                not_after: NOW + 86_400,
                is_ca: false,
                path_len: None,
                usage: &[Usage::ServerAuth],
                serial: [2; 16],
            },
            leaf_key.spki(),
            &ca_cert,
            &ca_key,
            &mut *r,
        )
        .unwrap();
        let mut roots = RootStore::new();
        roots.add_der(&ca_cert).unwrap();
        let ech = Arc::new(EchServer::generate(7, PUBLIC_NAME, 64, &mut *r).unwrap());
        let identity = Identity::new(vec![leaf.clone()], leaf_key).unwrap();
        Pki {
            ca_cert,
            ca_key,
            leaf,
            identity,
            roots,
            ech,
        }
    })
}

/// The external PSK both sides share.
pub fn psk() -> ExternalPsk {
    ExternalPsk::new(b"fuzz-psk", &[0x42; 32], HashAlg::Sha256).unwrap()
}

/// A server with as many peer-reachable paths switched on as can coexist:
/// ECH, 0-RTT, an external PSK, optional client certificates, tickets and a
/// HelloRetryRequest cookie.
pub fn server_config() -> Arc<ServerConfig> {
    static SC: OnceLock<Arc<ServerConfig>> = OnceLock::new();
    SC.get_or_init(|| {
        let p = pki();
        let mut sc = ServerConfig::new(Profile::Default, p.identity.clone())
            .unwrap()
            .with_alpn(&[b"h2", b"http/1.1"])
            .with_client_auth(ClientAuth::Optional(PeerVerification::Roots(
                p.roots.clone(),
            )));
        sc.common.clock = clock;
        sc.common.rng = fixed_rng;
        sc.ech = Some(p.ech.clone());
        sc.early_data = Some(EarlyDataPolicy::new(16_384));
        sc.external_psks = vec![psk()];
        // The seed recorder drives client and server in one process with the
        // same key, which the Selfie guard (REQ-EPSK-005) would refuse.
        sc.selfie_guard = false;
        sc.retry_cookie = true;
        // Every group this build implements, so a ClientHello can reach each
        // key-share parser (ML-KEM-1024 included), not only the defaults.
        sc.common.groups = ironsocketlayer::crypto::kx::IMPLEMENTED_GROUPS.to_vec();
        // ServerConfig::new drew ticket keys from the OS; redraw them from the
        // fixed DRBG so recorded tickets open in every run.
        sc.tickets = Some(Arc::new(
            ironsocketlayer::resumption::TicketKeys::generate(&mut *rng()).unwrap(),
        ));
        Arc::new(sc)
    })
    .clone()
}

/// A server the fixed-capacity engine accepts: every group and optional
/// client certificates, but none of the features it refuses (ECH, PSKs,
/// tickets, 0-RTT, retry cookies, on-demand client authentication).
pub fn fixed_server_config() -> Arc<ServerConfig> {
    static SC: OnceLock<Arc<ServerConfig>> = OnceLock::new();
    SC.get_or_init(|| {
        let p = pki();
        let mut sc = ServerConfig::new(Profile::Default, p.identity.clone())
            .unwrap()
            .with_alpn(&[b"h2", b"http/1.1"])
            .with_client_auth(ClientAuth::Optional(PeerVerification::Roots(
                p.roots.clone(),
            )));
        sc.common.clock = clock;
        sc.common.rng = fixed_rng;
        sc.common.groups = ironsocketlayer::crypto::kx::IMPLEMENTED_GROUPS.to_vec();
        sc.tickets = None;
        Arc::new(sc)
    })
    .clone()
}

/// The fixed-capacity client: [`client_config`] without ECH, which the fixed
/// engine refuses.
pub fn fixed_client_config() -> Arc<ClientConfig> {
    static CC: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    CC.get_or_init(|| {
        let mut cc = (*client_config()).clone();
        cc.ech_configs = None;
        Arc::new(cc)
    })
    .clone()
}

/// Caller-owned storage for one fixed-capacity connection, sized as in the
/// library's own tests.
pub struct FixedBuffers([Vec<u8>; 8]);

impl Default for FixedBuffers {
    fn default() -> Self {
        Self([16_645, 32_768, 65_536, 32_768, 32_768, 3_234, 1_665, 32_768].map(|n| vec![0u8; n]))
    }
}

impl FixedBuffers {
    /// Lend the buffers to a connection.
    pub fn storage(&mut self) -> ironsocketlayer::fixed::Storage<'_> {
        let [record, handshake, outgoing, application, certificates, private_key, public_key, scratch] =
            &mut self.0;
        ironsocketlayer::fixed::Storage {
            record,
            handshake,
            outgoing,
            application,
            certificates,
            private_key,
            public_key,
            scratch,
        }
    }
}

/// A client that offers ECH and ALPN, verifying against the fixture CA.
pub fn client_config() -> Arc<ClientConfig> {
    static CC: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    CC.get_or_init(|| {
        let p = pki();
        let mut cc = ClientConfig::new(Profile::Default, p.roots.clone())
            .unwrap()
            .with_alpn(&[b"h2"]);
        cc.common.clock = clock;
        cc.common.rng = fixed_rng;
        cc.ech_configs = Some(p.ech.config_list().to_vec());
        cc.tickets = None;
        Arc::new(cc)
    })
    .clone()
}

/// Split fuzz input into chunks: each starts with a one-byte length (0 means
/// "the rest"), so the fuzzer controls how bytes are fed as well as what.
pub fn chunks(mut data: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    while let Some((&n, rest)) = data.split_first() {
        let n = if n == 0 {
            rest.len()
        } else {
            (n as usize).min(rest.len())
        };
        out.push(&rest[..n]);
        data = &rest[n..];
    }
    out
}

/// The inverse of [`chunks`], for writing seeds.
pub fn frame_chunks(parts: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    for p in parts {
        for c in p.chunks(255) {
            out.push(c.len() as u8);
            out.extend_from_slice(c);
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Differential fixtures: certificates whose to-be-signed bytes the fuzzer
// mutates and the harness re-signs, so signatures always verify and both
// path validators reach their deepest checks.

fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    ironsocketlayer::crypto::sign::push_tlv(&mut out, tag, body);
    out
}

fn dn(cn: &str) -> Vec<u8> {
    let atv = [tlv(0x06, &[0x55, 0x04, 0x03]), tlv(0x0c, cn.as_bytes())].concat();
    tlv(0x30, &tlv(0x31, &tlv(0x30, &atv)))
}

fn ext(oid: &[u8], critical: bool, value: &[u8]) -> Vec<u8> {
    let mut b = tlv(0x06, oid);
    if critical {
        b.extend(tlv(0x01, &[0xff]));
    }
    b.extend(tlv(0x04, value));
    tlv(0x30, &b)
}

const ECDSA_SHA256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];

fn tbs(serial: u8, issuer: &str, subject: &str, spki: &[u8], exts: &[Vec<u8>]) -> Vec<u8> {
    let validity = [tlv(0x17, b"260927000000Z"), tlv(0x17, b"260929000000Z")].concat();
    tlv(
        0x30,
        &[
            tlv(0xa0, &tlv(0x02, &[2])),
            tlv(0x02, &[serial]),
            tlv(0x30, &tlv(0x06, ECDSA_SHA256)),
            dn(issuer),
            tlv(0x30, &validity),
            dn(subject),
            spki.to_vec(),
            tlv(0xa3, &tlv(0x30, &exts.concat())),
        ]
        .concat(),
    )
}

/// A certificate from `tbs`, signed by `key` (ECDSA P-256, SHA-256) with the
/// fixed DRBG.
pub fn sign_tbs(tbs: &[u8], key: &SigningKey) -> Vec<u8> {
    let sig = key
        .sign(
            ironsocketlayer::enums::SignatureScheme::EcdsaSecp256r1Sha256,
            tbs,
            &mut *rng(),
        )
        .unwrap();
    let mut bits = vec![0u8];
    bits.extend(sig);
    tlv(
        0x30,
        &[
            tbs.to_vec(),
            tlv(0x30, &tlv(0x06, ECDSA_SHA256)),
            tlv(0x03, &bits),
        ]
        .concat(),
    )
}

/// A root, an intermediate with name constraints (permitted dNSName
/// fuzz.test, excluded bad.fuzz.test, permitted iPAddress 10.0.0.0/8), and a
/// leaf under it; the keys sign whatever TBS the fuzzer makes of them.
pub struct DiffPki {
    pub root_key: SigningKey,
    pub int_key: SigningKey,
    pub int_tbs: Vec<u8>,
    pub leaf_tbs: Vec<u8>,
    pub roots: RootStore,
}

/// The differential fixtures, built once per process.
pub fn diff_pki() -> &'static DiffPki {
    static D: OnceLock<DiffPki> = OnceLock::new();
    D.get_or_init(|| {
        let mut r = rng();
        let root_key = SigningKey::generate(KeyKind::EcdsaP256, &mut *r).unwrap();
        let int_key = SigningKey::generate(KeyKind::EcdsaP256, &mut *r).unwrap();
        let leaf_key = SigningKey::generate(KeyKind::EcdsaP256, &mut *r).unwrap();
        let ca_bc = ext(&[0x55, 0x1d, 0x13], true, &tlv(0x30, &[0x01, 0x01, 0xff]));
        let ca_ku = ext(&[0x55, 0x1d, 0x0f], true, &tlv(0x03, &[0x01, 0x06]));
        let root = sign_tbs(
            &tbs(
                1,
                "Diff Root",
                "Diff Root",
                root_key.spki(),
                &[ca_bc.clone(), ca_ku.clone()],
            ),
            &root_key,
        );
        let subtree = |t: u8, v: &[u8]| tlv(0x30, &tlv(t, v));
        let permitted = [
            subtree(0x82, b"fuzz.test"),
            subtree(0x87, &[10, 0, 0, 0, 255, 0, 0, 0]),
        ]
        .concat();
        let excluded = subtree(0x82, b"bad.fuzz.test");
        let nc = ext(
            &[0x55, 0x1d, 0x1e],
            true,
            &tlv(
                0x30,
                &[tlv(0xa0, &permitted), tlv(0xa1, &excluded)].concat(),
            ),
        );
        let int_tbs = tbs(
            2,
            "Diff Root",
            "Diff Int",
            int_key.spki(),
            &[ca_bc, ca_ku, nc],
        );
        let san = ext(
            &[0x55, 0x1d, 0x11],
            false,
            &tlv(
                0x30,
                &[tlv(0x82, b"a.fuzz.test"), tlv(0x87, &[10, 1, 2, 3])].concat(),
            ),
        );
        let leaf_bc = ext(&[0x55, 0x1d, 0x13], true, &tlv(0x30, &[]));
        let leaf_ku = ext(&[0x55, 0x1d, 0x0f], true, &tlv(0x03, &[0x07, 0x80]));
        let eku = ext(
            &[0x55, 0x1d, 0x25],
            false,
            &tlv(
                0x30,
                &tlv(0x06, &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01]),
            ),
        );
        let leaf_tbs = tbs(
            3,
            "Diff Int",
            "a.fuzz.test",
            leaf_key.spki(),
            &[leaf_bc, leaf_ku, eku, san],
        );
        let mut roots = RootStore::new();
        roots.add_der(&root).unwrap();
        DiffPki {
            root_key,
            int_key,
            int_tbs,
            leaf_tbs,
            roots,
        }
    })
}

/// The pki_differential input for the fixture chain: selector, the
/// intermediate's TBS behind a two-byte length, then the leaf's TBS.
pub fn diff_seed(sel: u8) -> Vec<u8> {
    let d = diff_pki();
    let mut out = vec![sel];
    out.extend((d.int_tbs.len() as u16).to_be_bytes());
    out.extend(&d.int_tbs);
    out.extend(&d.leaf_tbs);
    out
}

/// The extension types of the ClientHello carried in the handshake records of
/// `stream`, or `None` if no complete hello header can be found. Bounds are
/// checked throughout: a fuzz harness must not panic on its own parsing.
pub fn client_hello_extension_types(stream: &[u8]) -> Option<Vec<u16>> {
    let mut hs = Vec::new();
    let mut i = 0usize;
    while i + 5 <= stream.len() {
        let len = usize::from(u16::from_be_bytes([stream[i + 3], stream[i + 4]]));
        let end = (i + 5 + len).min(stream.len());
        if stream[i] == 22 {
            hs.extend_from_slice(&stream[i + 5..end]);
        }
        i += 5 + len;
    }
    let body = hs.get(4..)?;
    let at = |p: usize| body.get(p).copied().map(usize::from);
    let u16_at = |p: usize| Some(at(p)? << 8 | at(p + 1)?);
    let mut p = 2 + 32;
    p += 1 + at(p)?;
    p += 2 + u16_at(p)?;
    p += 1 + at(p)?;
    let ext_len = u16_at(p)?;
    let start = p + 2;
    let stop = (start + ext_len).min(body.len());
    let mut q = start;
    let mut types = Vec::new();
    while q + 4 <= stop {
        types.push(u16_at(q)? as u16);
        q += 4 + u16_at(q + 2)?;
    }
    Some(types)
}
