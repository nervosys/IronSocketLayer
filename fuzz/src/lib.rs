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
