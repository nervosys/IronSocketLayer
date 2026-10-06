//! Shared test fixtures: a throwaway PKI and an in-memory byte pump.

#![allow(dead_code)]

use std::sync::Arc;

use ironsocketlayer::config::{ClientConfig, Identity, Profile, ServerConfig};
use ironsocketlayer::crypto::sign::{KeyKind, SigningKey};
use ironsocketlayer::x509::{self, CertificateParams, RootStore, Usage};
use ironsocketlayer::{Connection, Error};

pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn rng() -> ic_drbg::Rng {
    ic_drbg::Rng::from_os().unwrap()
}

fn serial() -> [u8; 16] {
    rng().random_array().unwrap()
}

/// A root CA and a server certificate issued by it.
pub struct Pki {
    pub ca_cert: Vec<u8>,
    ca_key: Arc<SigningKey>,
    pub server_chain: Vec<Vec<u8>>,
    server_key: Arc<SigningKey>,
}

impl Pki {
    pub fn new(server_kind: KeyKind, name: &str) -> Self {
        Self::with_kinds(KeyKind::EcdsaP384, server_kind, name)
    }

    pub fn with_kinds(ca_kind: KeyKind, server_kind: KeyKind, name: &str) -> Self {
        let mut r = rng();
        let ca_key = SigningKey::generate(ca_kind, &mut r).unwrap();
        let t = now();
        let ca_cert = x509::self_signed(
            &CertificateParams {
                subject_cn: "IronSocketLayer Test Root",
                dns_names: &[],
                ip_addresses: &[],
                not_before: t - 3600,
                not_after: t + 86_400,
                is_ca: true,
                path_len: Some(1),
                usage: &[],
                serial: serial(),
            },
            &ca_key,
            &mut r,
        )
        .unwrap();
        let mut pki = Self {
            ca_cert,
            ca_key: Arc::new(ca_key),
            server_chain: vec![],
            server_key: Arc::new(SigningKey::generate(server_kind, &mut r).unwrap()),
        };
        pki.server_chain = vec![pki.issue_leaf(&pki.server_key, name, Usage::ServerAuth)];
        pki
    }

    /// A second leaf under the same CA as `other`.
    pub fn with_ca(other: &Pki, server_kind: KeyKind, name: &str) -> Self {
        let mut r = rng();
        let mut pki = Self {
            ca_cert: other.ca_cert.clone(),
            ca_key: other.ca_key.clone(),
            server_chain: vec![],
            server_key: Arc::new(SigningKey::generate(server_kind, &mut r).unwrap()),
        };
        pki.server_chain = vec![pki.issue_leaf(&pki.server_key, name, Usage::ServerAuth)];
        pki
    }

    fn issue_leaf(&self, key: &SigningKey, name: &str, usage: Usage) -> Vec<u8> {
        let t = now();
        let names = [name];
        x509::issue(
            &CertificateParams {
                subject_cn: name,
                dns_names: if usage == Usage::ServerAuth {
                    &names
                } else {
                    &[]
                },
                ip_addresses: &[],
                not_before: t - 3600,
                not_after: t + 86_400,
                is_ca: false,
                path_len: None,
                usage: &[usage],
                serial: serial(),
            },
            key.spki(),
            &self.ca_cert,
            &self.ca_key,
            &mut rng(),
        )
        .unwrap()
    }

    /// An OCSP response from this PKI's CA about the server certificate.
    pub fn staple(
        &self,
        status: ironsocketlayer::x509::ocsp::CertStatus,
        this: u64,
        next: u64,
    ) -> Vec<u8> {
        ironsocketlayer::x509::ocsp::build_response(
            &self.server_chain[0],
            &self.ca_cert,
            &self.ca_key,
            status,
            this,
            next,
            &mut rng(),
        )
        .unwrap()
    }

    /// A server identity whose certificate covers every name in `names`.
    pub fn identity_for(&self, names: &[&str]) -> Identity {
        let key = SigningKey::generate(KeyKind::EcdsaP256, &mut rng()).unwrap();
        let t = now();
        let cert = x509::issue(
            &CertificateParams {
                subject_cn: names[0],
                dns_names: names,
                ip_addresses: &[],
                not_before: t - 3600,
                not_after: t + 86_400,
                is_ca: false,
                path_len: None,
                usage: &[Usage::ServerAuth],
                serial: serial(),
            },
            key.spki(),
            &self.ca_cert,
            &self.ca_key,
            &mut rng(),
        )
        .unwrap();
        Identity::new(vec![cert], key).unwrap()
    }

    /// A CRL from this PKI's CA revoking `serials`, current for an hour.
    pub fn crl(&self, serials: &[&[u8]]) -> Vec<u8> {
        let t = now();
        let revoked: Vec<(&[u8], u64)> = serials.iter().map(|s| (*s, t - 10)).collect();
        x509::crl::build(
            &self.ca_cert,
            &self.ca_key,
            &revoked,
            t - 60,
            t + 3600,
            1,
            &mut rng(),
        )
        .unwrap()
    }

    /// The CA certificate and key, for building deeper chains in a test.
    pub fn ca(&self) -> (&[u8], &SigningKey) {
        (&self.ca_cert, &self.ca_key)
    }

    pub fn roots(&self) -> RootStore {
        let mut r = RootStore::new();
        r.add_der(&self.ca_cert).unwrap();
        r
    }

    pub fn server_spki(&self) -> Vec<u8> {
        self.server_key.spki().to_vec()
    }

    pub fn server_identity(&self) -> Identity {
        Identity {
            ocsp: None,
            chain: self.server_chain.clone(),
            key: self.server_key.clone(),
        }
    }

    pub fn client_identity(&self, kind: KeyKind, cn: &str) -> Identity {
        let key = SigningKey::generate(kind, &mut rng()).unwrap();
        let cert = self.issue_leaf(&key, cn, Usage::ClientAuth);
        Identity::new(vec![cert], key).unwrap()
    }

    pub fn client_config(&self, profile: Profile) -> ClientConfig {
        let mut config = ClientConfig::new(profile, self.roots()).unwrap();
        if self.server_key.kind_id() == "key:ml-dsa-44" {
            config
                .common
                .schemes
                .push(ironsocketlayer::enums::SignatureScheme::MlDsa44);
        }
        config
    }

    pub fn server_config(&self, profile: Profile) -> ServerConfig {
        let mut config = ServerConfig::new(profile, self.server_identity()).unwrap();
        if self.server_key.kind_id() == "key:ml-dsa-44" {
            config
                .common
                .schemes
                .push(ironsocketlayer::enums::SignatureScheme::MlDsa44);
        }
        config
    }
}

/// Both sides' errors when a handshake fails.
#[derive(Debug)]
pub struct Failure {
    pub client: Option<Error>,
    pub server: Option<Error>,
}

/// Pump bytes until both sides finish or one fails.
pub fn connect(
    client: Arc<ClientConfig>,
    server: Arc<ServerConfig>,
    name: &str,
) -> Result<(Connection, Connection), Failure> {
    let mut c = Connection::client(client, name).map_err(|e| Failure {
        client: Some(e),
        server: None,
    })?;
    let mut s = Connection::server(server).map_err(|e| Failure {
        client: None,
        server: Some(e),
    })?;
    for _ in 0..16 {
        let to_server = c.take_tls();
        if !to_server.is_empty() {
            let _ = s.read_tls(&to_server);
        }
        let to_client = s.take_tls();
        if !to_client.is_empty() {
            let _ = c.read_tls(&to_client);
        }
        let to_server = c.take_tls();
        if !to_server.is_empty() {
            let _ = s.read_tls(&to_server);
        }
        if c.error().is_some() || s.error().is_some() {
            // Deliver any final alert.
            let a = s.take_tls();
            let _ = c.read_tls(&a);
            let b = c.take_tls();
            let _ = s.read_tls(&b);
            return Err(Failure {
                client: c.error(),
                server: s.error(),
            });
        }
        if !c.is_handshaking() && !s.is_handshaking() {
            return Ok((c, s));
        }
    }
    Err(Failure {
        client: c.error(),
        server: s.error(),
    })
}

/// Send data each way and check it arrives intact.
pub fn exchange(c: &mut Connection, s: &mut Connection) {
    let big = vec![0x5au8; 40_000];
    c.send(b"ping from client").unwrap();
    c.send(&big).unwrap();
    s.read_tls(&c.take_tls()).unwrap();
    let mut buf = vec![0u8; 50_000];
    let n = s.recv(&mut buf);
    assert_eq!(&buf[..16], b"ping from client");
    assert_eq!(n, 16 + big.len());
    s.send(b"pong from server").unwrap();
    c.read_tls(&s.take_tls()).unwrap();
    let n = c.recv(&mut buf);
    assert_eq!(&buf[..n], b"pong from server");
    // Deliver anything a key update produced.
    let x = c.take_tls();
    if !x.is_empty() {
        s.read_tls(&x).unwrap();
    }
}
