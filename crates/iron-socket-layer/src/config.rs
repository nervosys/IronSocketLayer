//! Configuration: profiles first, knobs second.
//!
//! An agent should not assemble a TLS configuration from primitives any more
//! than it should pick a cipher from memory. It names a [`Profile`] — or an
//! intent, which the ontology maps to one — and gets the suites, groups and
//! schemes that profile defines, already checked against this build and, when
//! the profile demands it, against the FIPS module.
//!
//! There is deliberately **no option to disable certificate verification**.
//! An agent that needs to talk to a peer without a PKI pins the peer's public
//! key ([`PeerVerification::PinnedSpki`]), which is both stricter than a CA
//! chain and easier to provision.
//!
//! Requirement trace: `REQ-CFG-001` (a profile's lists equal the ontology's),
//! `REQ-CFG-002` (nothing unimplemented is ever offered),
//! `REQ-CFG-003` (FIPS profiles refuse to build unless the module is
//! operational in approved mode and every algorithm passes `ic_fips::check`),
//! `REQ-CFG-004` (an unavailable profile is an error, never a substitute).

use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use ic_core::traits::RandomSource;

use crate::crypto::sign::{SigningKey, VERIFY_SCHEMES};
use crate::crypto::{kx, HashAlg};
use crate::enums::{CipherSuite, NamedGroup, SignatureScheme};
use crate::error::{Error, ErrorKind, Result};
use crate::record::{suite_params, IMPLEMENTED_SUITES};
use crate::x509::RootStore;

/// A named security profile. Each corresponds to a `profile:*` ontology entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Profile {
    /// Modern interoperable defaults: hybrid post-quantum key exchange first.
    Default,
    /// Post-quantum key exchange only; classical-only groups refused.
    PostQuantum,
    /// Only algorithms IronCrypto's FIPS module approves, with the module
    /// gate enforced. IronCrypto is **not** CMVP-validated.
    Fips140_3,
    /// CNSA 1.0: P-384 and AES-256.
    Cnsa1,
    /// CNSA 2.0: needs ML-DSA-87, which this build lacks (ML-KEM-1024 is
    /// implemented).
    /// Building it fails; an agent must not substitute another profile.
    Cnsa2,
    /// A deliberately narrow profile for DO-178C DAL-A programmes: one suite,
    /// one group, one scheme, mutual authentication, FIPS gate on.
    DalA,
}

impl Profile {
    /// Every profile.
    pub const ALL: &'static [Profile] = &[
        Self::Default,
        Self::PostQuantum,
        Self::Fips140_3,
        Self::Cnsa1,
        Self::Cnsa2,
        Self::DalA,
    ];

    /// Ontology identifier.
    pub const fn id(self) -> &'static str {
        match self {
            Self::Default => "profile:default",
            Self::PostQuantum => "profile:post-quantum",
            Self::Fips140_3 => "profile:fips-140-3",
            Self::Cnsa1 => "profile:cnsa-1",
            Self::Cnsa2 => "profile:cnsa-2",
            Self::DalA => "profile:dal-a",
        }
    }

    /// Look up by ontology identifier.
    pub fn from_id(id: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|p| p.id() == id)
    }

    /// Cipher suites, in preference order.
    pub const fn suites(self) -> &'static [CipherSuite] {
        use CipherSuite as C;
        match self {
            Self::Default => &[
                C::TlsAes128GcmSha256,
                C::TlsAes256GcmSha384,
                C::TlsChaCha20Poly1305Sha256,
            ],
            Self::PostQuantum => &[
                C::TlsAes256GcmSha384,
                C::TlsChaCha20Poly1305Sha256,
                C::TlsAes128GcmSha256,
            ],
            Self::Fips140_3 => &[C::TlsAes256GcmSha384, C::TlsAes128GcmSha256],
            Self::Cnsa1 | Self::DalA => &[C::TlsAes256GcmSha384],
            Self::Cnsa2 => &[],
        }
    }

    /// Key exchange groups, in preference order.
    pub const fn groups(self) -> &'static [NamedGroup] {
        use NamedGroup as G;
        match self {
            Self::Default => &[G::X25519MlKem768, G::X25519, G::Secp256r1, G::Secp384r1],
            Self::PostQuantum => &[G::X25519MlKem768, G::SecP256r1MlKem768, G::MlKem768],
            Self::Fips140_3 => &[
                G::SecP256r1MlKem768,
                G::Secp256r1,
                G::Secp384r1,
                G::Secp521r1,
            ],
            Self::Cnsa1 | Self::DalA => &[G::Secp384r1],
            Self::Cnsa2 => &[],
        }
    }

    /// Signature schemes accepted from the peer (handshake and certificates).
    pub const fn schemes(self) -> &'static [SignatureScheme] {
        use SignatureScheme as S;
        match self {
            Self::Default => &[
                S::EcdsaSecp256r1Sha256,
                S::Ed25519,
                S::EcdsaSecp384r1Sha384,
                S::EcdsaSecp521r1Sha512,
                S::RsaPssRsaeSha256,
                S::RsaPssRsaeSha384,
                S::RsaPssRsaeSha512,
                S::MlDsa65,
                S::RsaPkcs1Sha256,
                S::RsaPkcs1Sha384,
                S::RsaPkcs1Sha512,
            ],
            Self::PostQuantum => &[
                S::MlDsa65,
                S::EcdsaSecp256r1Sha256,
                S::Ed25519,
                S::EcdsaSecp384r1Sha384,
                S::EcdsaSecp521r1Sha512,
                S::RsaPssRsaeSha256,
                S::RsaPssRsaeSha384,
                S::RsaPssRsaeSha512,
                S::RsaPkcs1Sha256,
                S::RsaPkcs1Sha384,
                S::RsaPkcs1Sha512,
            ],
            Self::Fips140_3 => &[
                S::EcdsaSecp256r1Sha256,
                S::EcdsaSecp384r1Sha384,
                S::EcdsaSecp521r1Sha512,
                S::RsaPssRsaeSha256,
                S::RsaPssRsaeSha384,
                S::RsaPssRsaeSha512,
                S::MlDsa65,
                S::RsaPkcs1Sha256,
                S::RsaPkcs1Sha384,
                S::RsaPkcs1Sha512,
            ],
            Self::Cnsa1 => &[S::EcdsaSecp384r1Sha384, S::RsaPssRsaeSha384],
            Self::DalA => &[S::EcdsaSecp384r1Sha384],
            Self::Cnsa2 => &[],
        }
    }

    /// Whether the IronCrypto FIPS module gate is enforced.
    /// CNSA suites are for National Security Systems, which require
    /// FIPS-approved algorithms, so both CNSA profiles are gated too.
    pub const fn requires_fips(self) -> bool {
        matches!(
            self,
            Self::Fips140_3 | Self::Cnsa1 | Self::Cnsa2 | Self::DalA
        )
    }

    /// Whether the peer must authenticate with a certificate on both sides.
    pub const fn requires_mutual_auth(self) -> bool {
        matches!(self, Self::DalA)
    }

    /// Smallest RSA modulus accepted, in bits.
    pub const fn min_rsa_bits(self) -> usize {
        match self {
            Self::Cnsa1 | Self::Cnsa2 | Self::DalA => 3072,
            _ => 2048,
        }
    }

    /// Whether this build can provide the profile at all. `REQ-CFG-004`.
    pub const fn available(self) -> bool {
        !matches!(self, Self::Cnsa2)
    }

    /// How many key shares a client sends in its first flight. Two for the
    /// default profile — the hybrid and X25519 — so a classical-only server
    /// does not cost a HelloRetryRequest.
    pub const fn initial_key_shares(self) -> usize {
        match self {
            Self::Default => 2,
            _ => 1,
        }
    }
}

/// Returns the current time in Unix seconds.
pub type Clock = fn() -> u64;

/// Creates a random source for one connection.
pub type RngFactory = fn() -> Result<Box<dyn RandomSource + Send>>;

#[cfg(feature = "std")]
fn system_clock() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(feature = "std")]
fn os_rng() -> Result<Box<dyn RandomSource + Send>> {
    let rng = ic_drbg::Rng::from_os()
        .map_err(|_| Error::new(ErrorKind::Entropy, "OS entropy unavailable"))?;
    Ok(Box::new(rng))
}

#[cfg(not(feature = "std"))]
fn no_clock() -> u64 {
    0
}

#[cfg(not(feature = "std"))]
fn no_rng() -> Result<Box<dyn RandomSource + Send>> {
    Err(Error::new(
        ErrorKind::InvalidConfig,
        "no_std build: set Config::rng",
    ))
}

/// How the peer's identity is checked. There is no "accept anything".
#[derive(Clone, Debug)]
pub enum PeerVerification {
    /// Build a path to one of these trust anchors (RFC 5280).
    Roots(RootStore),
    /// Accept exactly these public keys: SHA-256 of the end-entity
    /// `SubjectPublicKeyInfo`. The certificate's validity and names are still
    /// checked unless `check_names` is false.
    PinnedSpki {
        /// SHA-256 digests of accepted `SubjectPublicKeyInfo`s.
        sha256: Vec<[u8; 32]>,
        /// Whether to check the certificate covers the server name.
        check_names: bool,
    },
}

impl PeerVerification {
    /// Pin a single `SubjectPublicKeyInfo`.
    pub fn pin_spki(spki_der: &[u8]) -> Self {
        let d = HashAlg::Sha256.digest(spki_der);
        let mut h = [0u8; 32];
        h.copy_from_slice(d.as_bytes());
        Self::PinnedSpki {
            sha256: alloc::vec![h],
            check_names: false,
        }
    }

    /// Stable identifier for reports.
    pub fn id(&self) -> &'static str {
        match self {
            Self::Roots(_) => "verification:pkix",
            Self::PinnedSpki { .. } => "verification:pinned-spki",
        }
    }
}

/// A certificate chain and the key for its end-entity certificate.
#[derive(Clone)]
pub struct Identity {
    /// DER certificates, end-entity first.
    pub chain: Vec<Vec<u8>>,
    /// The end-entity private key.
    pub key: Arc<SigningKey>,
    /// A DER OCSP response for the end-entity certificate, stapled when the
    /// client asks for status. The operator keeps it fresh; see
    /// [`crate::x509::ocsp::build_response`] for a private CA.
    pub ocsp: Option<Arc<Vec<u8>>>,
}

impl core::fmt::Debug for Identity {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Identity({} certs, {:?})", self.chain.len(), self.key)
    }
}

impl Identity {
    /// Pair a chain with its key, checking that they belong together.
    pub fn new(chain: Vec<Vec<u8>>, key: SigningKey) -> Result<Self> {
        let leaf = chain.first().ok_or(Error::new(
            ErrorKind::InvalidConfig,
            "empty certificate chain",
        ))?;
        let cert = crate::x509::Certificate::parse(leaf).map_err(|_| {
            Error::new(
                ErrorKind::InvalidConfig,
                "end-entity certificate does not parse",
            )
        })?;
        if cert.spki_der() != key.spki() {
            return Err(Error::new(
                ErrorKind::InvalidConfig,
                "private key does not match the certificate",
            ));
        }
        Ok(Self {
            chain,
            key: Arc::new(key),
            ocsp: None,
        })
    }

    /// Staple `response` (DER OCSP) to this identity's certificate.
    pub fn with_ocsp(mut self, response: Vec<u8>) -> Self {
        self.ocsp = Some(Arc::new(response));
        self
    }
}

/// What a client does about certificate revocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Revocation {
    /// Do not ask for or check revocation status.
    Off,
    /// Ask for an OCSP staple; if one arrives it must be valid and good.
    /// A server that staples nothing is accepted. The default.
    IfStapled,
    /// Require a valid staple saying the certificate is good.
    RequireStaple,
}

impl Revocation {
    /// Stable identifier.
    pub const fn id(self) -> &'static str {
        match self {
            Self::Off => "revocation-policy:off",
            Self::IfStapled => "revocation-policy:if-stapled",
            Self::RequireStaple => "revocation-policy:require-staple",
        }
    }
}

/// An external pre-shared key (RFC 8446 §2.2, RFC 9257): an identity and a
/// secret provisioned out of band, bound to one hash.
///
/// Use each key between exactly two parties. Identities travel in the clear.
#[derive(Clone)]
pub struct ExternalPsk {
    /// The identity sent to the server.
    pub identity: Vec<u8>,
    key: crate::crypto::SecretVec,
    /// The hash the key is bound to; only suites using it can use the key.
    pub hash: HashAlg,
}

impl core::fmt::Debug for ExternalPsk {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "ExternalPsk({} byte identity, {:?})",
            self.identity.len(),
            self.hash
        )
    }
}

/// Smallest external PSK accepted: 256 bits, so it keeps 128-bit strength
/// against a quantum search. `REQ-EPSK-003`.
pub const MIN_EXTERNAL_PSK_LEN: usize = 32;

impl ExternalPsk {
    /// A key of 32 to 64 bytes for `identity` (1 to 1024 bytes).
    pub fn new(identity: &[u8], key: &[u8], hash: HashAlg) -> Result<Self> {
        if identity.is_empty() || identity.len() > 1024 {
            return Err(Error::new(
                ErrorKind::InvalidConfig,
                "PSK identity must be 1..=1024 bytes",
            ));
        }
        if key.len() < MIN_EXTERNAL_PSK_LEN || key.len() > crate::crypto::MAX_HASH_LEN {
            return Err(Error::new(
                ErrorKind::InvalidConfig,
                "external PSK must be 32..=64 bytes of key material",
            ));
        }
        Ok(Self {
            identity: identity.to_vec(),
            key: crate::crypto::SecretVec::new(key.to_vec()),
            hash,
        })
    }

    /// The key.
    pub fn key(&self) -> &[u8] {
        self.key.get()
    }
}

/// When a server accepts 0-RTT data (RFC 8446 §8).
#[derive(Clone, Debug)]
pub struct EarlyDataPolicy {
    /// Most early bytes per connection (advertised in tickets).
    pub max_early_data: u32,
    /// Records ClientHellos that carried early data; a repeat is refused.
    pub replay: Arc<dyn crate::resumption::ReplayGuard>,
    /// How far the client's ticket age may differ from the server's view,
    /// in milliseconds.
    pub max_skew_ms: u32,
}

impl EarlyDataPolicy {
    /// Accept up to `max_early_data` bytes, with an in-memory replay guard and
    /// a 10-second freshness window.
    #[cfg(feature = "std")]
    pub fn new(max_early_data: u32) -> Self {
        Self {
            max_early_data,
            replay: Arc::new(crate::resumption::MemoryReplayGuard::default()),
            max_skew_ms: 10_000,
        }
    }
}

/// Settings shared by both sides.
#[derive(Clone)]
pub struct Common {
    /// The profile these settings came from.
    pub profile: Profile,
    /// Suites, preference order.
    pub suites: Vec<CipherSuite>,
    /// Groups, preference order.
    pub groups: Vec<NamedGroup>,
    /// Schemes accepted from the peer.
    pub schemes: Vec<SignatureScheme>,
    /// ALPN protocols, preference order.
    pub alpn: Vec<Vec<u8>>,
    /// Fail the handshake if ALPN was offered and nothing matched.
    pub require_alpn: bool,
    /// Largest handshake message accepted, in bytes.
    pub max_handshake_message: usize,
    /// Records of zero padding appended to each protected record's inner
    /// plaintext, to blunt length analysis (0 disables).
    pub record_padding: usize,
    /// Largest protected record this endpoint accepts, as a TLSInnerPlaintext
    /// length (RFC 8449): content plus type byte plus padding, 64 to 16385.
    /// `None` does not send the extension. Constrained devices set it low so
    /// a peer cannot make them buffer 16 KiB records. Ignored under QUIC.
    pub record_size_limit: Option<u16>,
    /// CRLs to check the peer's certificate path against (RFC 5280 §5); a
    /// certificate listed by an authentic CRL is refused.
    pub crls: Option<Arc<crate::x509::crl::CrlStore>>,
    /// Refuse a peer unless every certificate on its path is shown good by a
    /// current CRL from its issuer.
    pub require_crl: bool,
    /// Enforce the FIPS module gate.
    pub fips: bool,
    /// Current time.
    pub clock: Clock,
    /// Randomness.
    pub rng: RngFactory,
}

impl core::fmt::Debug for Common {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Common")
            .field("profile", &self.profile)
            .field("suites", &self.suites)
            .field("groups", &self.groups)
            .field("schemes", &self.schemes)
            .field("fips", &self.fips)
            .finish()
    }
}

impl Common {
    fn for_profile(profile: Profile) -> Result<Self> {
        if !profile.available() {
            // REQ-CFG-004.
            return Err(Error::new(
                ErrorKind::InvalidConfig,
                "profile unavailable in this build (CNSA 2.0 needs ML-DSA-87); do not substitute",
            ));
        }
        Ok(Self {
            profile,
            suites: profile.suites().to_vec(),
            groups: profile.groups().to_vec(),
            schemes: profile.schemes().to_vec(),
            alpn: Vec::new(),
            require_alpn: false,
            max_handshake_message: 128 * 1024,
            record_padding: 0,
            record_size_limit: None,
            crls: None,
            require_crl: false,
            fips: profile.requires_fips(),
            #[cfg(feature = "std")]
            clock: system_clock,
            #[cfg(not(feature = "std"))]
            clock: no_clock,
            #[cfg(feature = "std")]
            rng: os_rng,
            #[cfg(not(feature = "std"))]
            rng: no_rng,
        })
    }

    /// Check the configuration can produce a handshake, and pass the FIPS gate
    /// when required. `REQ-CFG-002`, `REQ-CFG-003`.
    pub fn validate(&self) -> Result<()> {
        if self.suites.is_empty() || self.groups.is_empty() || self.schemes.is_empty() {
            return Err(Error::new(
                ErrorKind::InvalidConfig,
                "no suites, groups or schemes",
            ));
        }
        if self.suites.iter().any(|s| suite_params(*s).is_none()) {
            return Err(Error::new(
                ErrorKind::InvalidConfig,
                "a configured suite is not implemented",
            ));
        }
        if self.groups.iter().any(|g| !kx::is_implemented(*g)) {
            return Err(Error::new(
                ErrorKind::InvalidConfig,
                "a configured group is not implemented",
            ));
        }
        if self.schemes.iter().any(|s| !VERIFY_SCHEMES.contains(s)) {
            return Err(Error::new(
                ErrorKind::InvalidConfig,
                "a configured scheme is not implemented",
            ));
        }
        if !self.schemes.iter().any(|s| s.allowed_in_handshake()) {
            return Err(Error::new(
                ErrorKind::InvalidConfig,
                "no scheme may sign a TLS 1.3 handshake",
            ));
        }
        if self.alpn.iter().any(|p| p.is_empty() || p.len() > 255) {
            return Err(Error::new(
                ErrorKind::InvalidConfig,
                "ALPN names must be 1..=255 bytes",
            ));
        }
        if let Some(l) = self.record_size_limit {
            if !(crate::msgs::MIN_RECORD_SIZE_LIMIT..=crate::msgs::MAX_RECORD_SIZE_LIMIT)
                .contains(&l)
            {
                return Err(Error::new(
                    ErrorKind::InvalidConfig,
                    "record_size_limit must be 64..=16385",
                ));
            }
        }
        if self.fips {
            crate::policy::fips_gate(self)?;
        }
        Ok(())
    }

    /// Randomness for one connection.
    pub fn new_rng(&self) -> Result<Box<dyn RandomSource + Send>> {
        (self.rng)()
    }
}

#[cfg(feature = "std")]
fn default_ticket_store(profile: Profile) -> Option<Arc<dyn crate::resumption::TicketStore>> {
    // DAL-A keeps the handshake to one path: no resumption.
    (profile != Profile::DalA).then(|| {
        Arc::new(crate::resumption::MemoryTicketStore::default())
            as Arc<dyn crate::resumption::TicketStore>
    })
}

#[cfg(not(feature = "std"))]
fn default_ticket_store(_: Profile) -> Option<Arc<dyn crate::resumption::TicketStore>> {
    None
}

/// Client configuration.
#[derive(Clone, Debug)]
pub struct ClientConfig {
    /// Shared settings.
    pub common: Common,
    /// How the server is verified.
    pub verification: PeerVerification,
    /// Client certificate, sent if the server asks.
    pub identity: Option<Identity>,
    /// Send SNI.
    pub send_sni: bool,
    /// Key shares in the first flight.
    pub initial_key_shares: usize,
    /// Certificate revocation checking (OCSP stapling).
    pub revocation: Revocation,
    /// Offer to authenticate with `identity` after the handshake, when the
    /// server asks (RFC 8446 §4.6.2). Not available over QUIC.
    pub post_handshake_auth: bool,
    /// Authenticate with an external PSK instead of certificates. With no
    /// trust anchors, a server that does not accept it is refused.
    pub external_psk: Option<ExternalPsk>,
    /// Permit 0-RTT data given to `Connection::client_with_early_data`.
    /// Off by default: early data is replayable and not forward-secret.
    pub early_data: bool,
    /// An `ECHConfigList` for the server (from its DNS HTTPS record). When
    /// set, the real server name is sent only encrypted; if no configuration
    /// in the list is usable the connection fails rather than expose it.
    pub ech_configs: Option<Vec<u8>>,
    /// Where session tickets are kept, keyed by server name; `None` disables
    /// resumption. Shared by every connection made with this configuration.
    pub tickets: Option<Arc<dyn crate::resumption::TicketStore>>,
}

impl ClientConfig {
    /// A configuration for `profile`, verifying against `roots`.
    pub fn new(profile: Profile, roots: RootStore) -> Result<Self> {
        Ok(Self {
            common: Common::for_profile(profile)?,
            verification: PeerVerification::Roots(roots),
            identity: None,
            send_sni: true,
            initial_key_shares: profile.initial_key_shares(),
            revocation: Revocation::IfStapled,
            post_handshake_auth: false,
            external_psk: None,
            early_data: false,
            ech_configs: None,
            tickets: default_ticket_store(profile),
        })
    }

    /// Whether there is nothing but an external PSK to authenticate the server.
    pub(crate) fn verification_is_empty(&self) -> bool {
        matches!(&self.verification, PeerVerification::Roots(r) if r.is_empty())
    }

    /// A configuration that authenticates with an external PSK only.
    pub fn external_psk(profile: Profile, psk: ExternalPsk) -> Result<Self> {
        let mut c = Self::new(profile, RootStore::new())?;
        c.external_psk = Some(psk);
        Ok(c)
    }

    /// A configuration that accepts exactly one server public key.
    pub fn pinned(profile: Profile, spki_der: &[u8]) -> Result<Self> {
        let mut c = Self::new(profile, RootStore::new())?;
        c.verification = PeerVerification::pin_spki(spki_der);
        Ok(c)
    }

    /// Set ALPN protocols.
    pub fn with_alpn(mut self, protocols: &[&[u8]]) -> Self {
        self.common.alpn = protocols.iter().map(|p| p.to_vec()).collect();
        self
    }

    /// Present `identity` if the server requests a certificate.
    pub fn with_identity(mut self, identity: Identity) -> Self {
        self.identity = Some(identity);
        self
    }

    /// Check the configuration.
    pub fn validate(&self) -> Result<()> {
        self.common.validate()?;
        if self.common.profile.requires_mutual_auth() && self.identity.is_none() {
            return Err(Error::new(
                ErrorKind::InvalidConfig,
                "profile requires a client identity",
            ));
        }
        if let PeerVerification::Roots(r) = &self.verification {
            if r.is_empty() && self.external_psk.is_none() {
                return Err(Error::new(
                    ErrorKind::InvalidConfig,
                    "no trust anchors: add roots or pin the server key",
                ));
            }
        }
        if let Some(psk) = &self.external_psk {
            if self.ech_configs.is_some() {
                return Err(Error::new(
                    ErrorKind::InvalidConfig,
                    "ECH and an external PSK cannot be combined in this build",
                ));
            }
            let usable = self
                .common
                .suites
                .iter()
                .any(|s| suite_params(*s).map(|(_, h)| h) == Some(psk.hash));
            if !usable {
                return Err(Error::new(
                    ErrorKind::InvalidConfig,
                    "no configured suite uses the external PSK's hash",
                ));
            }
        }
        Ok(())
    }
}

/// When the server asks for a client certificate.
#[derive(Clone, Debug)]
pub enum ClientAuth {
    /// Never.
    None,
    /// Ask; accept a client that sends none.
    Optional(PeerVerification),
    /// Ask; refuse a client that sends none.
    Required(PeerVerification),
    /// Do not ask during the handshake; verify with this when the application
    /// calls `Connection::request_client_auth` later (step-up
    /// authentication, RFC 8446 §4.6.2).
    OnDemand(PeerVerification),
}

/// Server configuration.
#[derive(Clone, Debug)]
pub struct ServerConfig {
    /// Shared settings.
    pub common: Common,
    /// Certificates to present; chosen by SNI, else the first.
    pub identities: Vec<Identity>,
    /// Client authentication.
    pub client_auth: ClientAuth,
    /// Prefer the server's suite order over the client's.
    pub prefer_server_order: bool,
    /// Send a cookie in HelloRetryRequest (stateless-retry preparation).
    pub retry_cookie: bool,
    /// 0-RTT acceptance; `None` (the default) rejects all early data.
    pub early_data: Option<EarlyDataPolicy>,
    /// External PSKs clients may authenticate with, by identity.
    pub external_psks: Vec<ExternalPsk>,
    /// ECH keys; clients that encrypt to them have their real ClientHello
    /// decrypted, others get `retry_configs`.
    pub ech: Option<Arc<crate::ech::EchServer>>,
    /// Ticket keys; `None` disables resumption.
    pub tickets: Option<Arc<crate::resumption::TicketKeys>>,
    /// Tickets issued after each handshake.
    pub tickets_per_handshake: u8,
    /// Ticket lifetime in seconds (at most seven days).
    pub ticket_lifetime: u32,
}

impl ServerConfig {
    /// A configuration for `profile` presenting `identity`.
    pub fn new(profile: Profile, identity: Identity) -> Result<Self> {
        let common = Common::for_profile(profile)?;
        // DAL-A keeps the handshake to one path: no resumption. Without a
        // random source (no_std, none configured yet) tickets start disabled.
        let tickets = if profile == Profile::DalA {
            None
        } else {
            common
                .new_rng()
                .ok()
                .and_then(|mut rng| crate::resumption::TicketKeys::generate(&mut *rng).ok())
                .map(Arc::new)
        };
        Ok(Self {
            common,
            tickets,
            early_data: None,
            external_psks: Vec::new(),
            ech: None,
            tickets_per_handshake: 1,
            ticket_lifetime: 86_400,
            identities: alloc::vec![identity],
            client_auth: ClientAuth::None,
            prefer_server_order: true,
            retry_cookie: false,
        })
    }

    /// Set ALPN protocols, in server preference order.
    pub fn with_alpn(mut self, protocols: &[&[u8]]) -> Self {
        self.common.alpn = protocols.iter().map(|p| p.to_vec()).collect();
        self
    }

    /// A server that authenticates only with external PSKs: no certificate.
    pub fn external_psk_only(profile: Profile, psks: Vec<ExternalPsk>) -> Result<Self> {
        let common = Common::for_profile(profile)?;
        Ok(Self {
            common,
            identities: Vec::new(),
            client_auth: ClientAuth::None,
            prefer_server_order: true,
            retry_cookie: false,
            tickets: None,
            early_data: None,
            external_psks: psks,
            ech: None,
            tickets_per_handshake: 0,
            ticket_lifetime: 0,
        })
    }

    /// Require clients to authenticate.
    pub fn with_client_auth(mut self, auth: ClientAuth) -> Self {
        self.client_auth = auth;
        self
    }

    /// Check the configuration.
    pub fn validate(&self) -> Result<()> {
        self.common.validate()?;
        if self.identities.is_empty() && self.external_psks.is_empty() {
            return Err(Error::new(
                ErrorKind::InvalidConfig,
                "server has neither a certificate nor an external PSK",
            ));
        }
        for id in &self.identities {
            if id
                .key
                .choose_scheme(&self.common.schemes, &self.common.schemes)
                .is_none()
            {
                return Err(Error::new(
                    ErrorKind::InvalidConfig,
                    "a server key cannot sign with any scheme the profile allows",
                ));
            }
        }
        if self.common.profile.requires_mutual_auth()
            && !matches!(self.client_auth, ClientAuth::Required(_))
        {
            return Err(Error::new(
                ErrorKind::InvalidConfig,
                "profile requires mandatory client authentication",
            ));
        }
        Ok(())
    }
}

/// The suites this build implements, for capability reports.
pub fn implemented_suites() -> &'static [CipherSuite] {
    IMPLEMENTED_SUITES
}

/// Human-readable name for a server identity, for logs.
pub fn describe_identity(id: &Identity) -> String {
    let mut s = String::from(id.key.kind_id());
    s.push_str(" chain of ");
    s.push_str(match id.chain.len() {
        1 => "1",
        2 => "2",
        3 => "3",
        _ => "4+",
    });
    s
}
