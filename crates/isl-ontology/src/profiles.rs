//! Profiles: named, complete parameter sets, and the lists `ironsocketlayer`
//! configures itself from.
//!
//! The `pub const` slices below are the single source of truth: the
//! configuration builder in `ironsocketlayer` reads them rather than repeating
//! them, so a profile cannot say one thing here and do another there.

/// Whether a profile can be used in this build.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProfileStatus {
    /// Every component is implemented.
    Available,
    /// A required component is not implemented. Do not substitute.
    Unavailable,
}

impl ProfileStatus {
    /// Stable identifier.
    pub const fn id(self) -> &'static str {
        match self {
            Self::Available => "available",
            Self::Unavailable => "unavailable",
        }
    }
}

/// A named parameter set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Profile {
    /// Stable identifier, `profile:` prefixed.
    pub id: &'static str,
    /// Display name.
    pub name: &'static str,
    /// One sentence.
    pub summary: &'static str,
    /// Whether it can be used.
    pub status: ProfileStatus,
    /// Why not, when unavailable.
    pub status_reason: &'static str,
    /// Cipher suites, most preferred first.
    pub suites: &'static [&'static str],
    /// Key-exchange groups, most preferred first. The first is sent as a key
    /// share.
    pub groups: &'static [&'static str],
    /// Signature schemes accepted and offered, most preferred first.
    /// PKCS#1 v1.5 schemes are accepted in certificates only.
    pub sigschemes: &'static [&'static str],
    /// Whether both sides must authenticate.
    pub mutual_auth_required: bool,
    /// Whether every algorithm is checked with `ic_fips::check`, and the
    /// module must be operational in approved mode.
    pub fips_gate: bool,
    /// Whether every negotiated group must be post-quantum.
    pub post_quantum_required: bool,
    /// Smallest RSA modulus accepted, in bits.
    pub min_rsa_bits: u16,
    /// Why this set.
    pub rationale: &'static str,
    /// Anything else worth knowing.
    pub notes: &'static str,
}

/// `profile:default` suites.
pub const DEFAULT_SUITES: &[&str] = &[
    "suite:tls-aes-128-gcm-sha256",
    "suite:tls-aes-256-gcm-sha384",
    "suite:tls-chacha20-poly1305-sha256",
];
/// `profile:default` groups.
pub const DEFAULT_GROUPS: &[&str] = &[
    "group:x25519mlkem768",
    "group:x25519",
    "group:secp256r1",
    "group:secp384r1",
];
/// Every implemented signature scheme, classical first.
pub const DEFAULT_SIGSCHEMES: &[&str] = &[
    "sigscheme:ecdsa-secp256r1-sha256",
    "sigscheme:ed25519",
    "sigscheme:ecdsa-secp384r1-sha384",
    "sigscheme:ecdsa-secp521r1-sha512",
    "sigscheme:rsa-pss-rsae-sha256",
    "sigscheme:rsa-pss-rsae-sha384",
    "sigscheme:rsa-pss-rsae-sha512",
    "sigscheme:mldsa65",
    "sigscheme:mldsa87",
    "sigscheme:rsa-pkcs1-sha256",
    "sigscheme:rsa-pkcs1-sha384",
    "sigscheme:rsa-pkcs1-sha512",
];

/// `profile:post-quantum` suites.
pub const POST_QUANTUM_SUITES: &[&str] = &[
    "suite:tls-aes-256-gcm-sha384",
    "suite:tls-chacha20-poly1305-sha256",
    "suite:tls-aes-128-gcm-sha256",
];
/// `profile:post-quantum` groups. Classical-only groups are refused.
pub const POST_QUANTUM_GROUPS: &[&str] = &[
    "group:x25519mlkem768",
    "group:secp256r1mlkem768",
    "group:mlkem768",
];
/// `profile:post-quantum` signature schemes, ML-DSA first.
pub const POST_QUANTUM_SIGSCHEMES: &[&str] = &[
    "sigscheme:mldsa65",
    "sigscheme:mldsa87",
    "sigscheme:ecdsa-secp256r1-sha256",
    "sigscheme:ed25519",
    "sigscheme:ecdsa-secp384r1-sha384",
    "sigscheme:ecdsa-secp521r1-sha512",
    "sigscheme:rsa-pss-rsae-sha256",
    "sigscheme:rsa-pss-rsae-sha384",
    "sigscheme:rsa-pss-rsae-sha512",
    "sigscheme:rsa-pkcs1-sha256",
    "sigscheme:rsa-pkcs1-sha384",
    "sigscheme:rsa-pkcs1-sha512",
];

/// `profile:fips-140-3` suites.
pub const FIPS_SUITES: &[&str] = &[
    "suite:tls-aes-256-gcm-sha384",
    "suite:tls-aes-128-gcm-sha256",
];
/// `profile:fips-140-3` groups.
pub const FIPS_GROUPS: &[&str] = &[
    "group:secp256r1mlkem768",
    "group:secp256r1",
    "group:secp384r1",
    "group:secp521r1",
];
/// `profile:fips-140-3` signature schemes.
pub const FIPS_SIGSCHEMES: &[&str] = &[
    "sigscheme:ecdsa-secp256r1-sha256",
    "sigscheme:ecdsa-secp384r1-sha384",
    "sigscheme:ecdsa-secp521r1-sha512",
    "sigscheme:rsa-pss-rsae-sha256",
    "sigscheme:rsa-pss-rsae-sha384",
    "sigscheme:rsa-pss-rsae-sha512",
    "sigscheme:mldsa65",
    "sigscheme:mldsa87",
    "sigscheme:rsa-pkcs1-sha256",
    "sigscheme:rsa-pkcs1-sha384",
    "sigscheme:rsa-pkcs1-sha512",
];

/// `profile:cnsa-1` suites.
pub const CNSA1_SUITES: &[&str] = &["suite:tls-aes-256-gcm-sha384"];
/// `profile:cnsa-1` groups.
pub const CNSA1_GROUPS: &[&str] = &["group:secp384r1"];
/// `profile:cnsa-1` signature schemes.
pub const CNSA1_SIGSCHEMES: &[&str] = &[
    "sigscheme:ecdsa-secp384r1-sha384",
    "sigscheme:rsa-pss-rsae-sha384",
];

/// `profile:cnsa-2` suites.
pub const CNSA2_SUITES: &[&str] = &["suite:tls-aes-256-gcm-sha384"];
/// `profile:cnsa-2` groups: pure ML-KEM-1024.
pub const CNSA2_GROUPS: &[&str] = &["group:mlkem1024"];
/// `profile:cnsa-2` signature schemes: ML-DSA-87, in the handshake and in
/// every certificate on the path.
pub const CNSA2_SIGSCHEMES: &[&str] = &["sigscheme:mldsa87"];

/// `profile:dal-a` suites.
pub const DAL_A_SUITES: &[&str] = &["suite:tls-aes-256-gcm-sha384"];
/// `profile:dal-a` groups.
pub const DAL_A_GROUPS: &[&str] = &["group:secp384r1"];
/// `profile:dal-a` signature schemes.
pub const DAL_A_SIGSCHEMES: &[&str] = &["sigscheme:ecdsa-secp384r1-sha384"];

const NOT_VALIDATED: &str = "IronCrypto implements the FIPS 140-3 operational discipline but is NOT CMVP-validated. This profile restricts IronSocketLayer to approved algorithms and routes them through the ic_fips gate; it does not make a deployment FIPS-validated.";

/// Every profile.
pub static PROFILES: &[Profile] = &[
    Profile {
        id: "profile:default",
        name: "Default",
        summary: "Modern Internet interoperability with hybrid post-quantum key exchange preferred.",
        status: ProfileStatus::Available,
        status_reason: "",
        suites: DEFAULT_SUITES,
        groups: DEFAULT_GROUPS,
        sigschemes: DEFAULT_SIGSCHEMES,
        mutual_auth_required: false,
        fips_gate: false,
        post_quantum_required: false,
        min_rsa_bits: 2048,
        rationale: "X25519MLKEM768 first protects against harvest-now-decrypt-later where the peer supports it; classical groups remain so every TLS 1.3 server still connects.",
        notes: "A peer that picks a classical group is accepted; the SessionReport records that the session is not post-quantum.",
    },
    Profile {
        id: "profile:post-quantum",
        name: "Post-quantum",
        summary: "Refuses any session whose key exchange is not post-quantum.",
        status: ProfileStatus::Available,
        status_reason: "",
        suites: POST_QUANTUM_SUITES,
        groups: POST_QUANTUM_GROUPS,
        sigschemes: POST_QUANTUM_SIGSCHEMES,
        mutual_auth_required: false,
        fips_gate: false,
        post_quantum_required: true,
        min_rsa_bits: 2048,
        rationale: "Traffic recorded today can be decrypted once a quantum computer exists; only an ML-KEM component prevents that. AES-256 keeps 128-bit strength against Grover.",
        notes: "Authentication is still classical unless the peer uses ML-DSA certificates; an attacker needs a quantum computer during the handshake to exploit that, not afterwards.",
    },
    Profile {
        id: "profile:fips-140-3",
        name: "FIPS 140-3",
        summary: "Approved algorithms only, each checked through the IronCrypto FIPS module in approved mode.",
        status: ProfileStatus::Available,
        status_reason: "",
        suites: FIPS_SUITES,
        groups: FIPS_GROUPS,
        sigschemes: FIPS_SIGSCHEMES,
        mutual_auth_required: false,
        fips_gate: true,
        post_quantum_required: false,
        min_rsa_bits: 2048,
        rationale: "SP 800-52r2 suites and groups; SecP256r1MLKEM768 first because both of its components are approved.",
        notes: NOT_VALIDATED,
    },
    Profile {
        id: "profile:cnsa-1",
        name: "CNSA 1.0",
        summary: "The NSA Commercial National Security Algorithm suite 1.0: AES-256, P-384, SHA-384.",
        status: ProfileStatus::Available,
        status_reason: "",
        suites: CNSA1_SUITES,
        groups: CNSA1_GROUPS,
        sigschemes: CNSA1_SIGSCHEMES,
        mutual_auth_required: false,
        fips_gate: true,
        post_quantum_required: false,
        min_rsa_bits: 3072,
        rationale: "CNSA 1.0 fixes a single parameter set; it is the transitional baseline until CNSA 2.0.",
        notes: NOT_VALIDATED,
    },
    Profile {
        id: "profile:cnsa-2",
        name: "CNSA 2.0",
        summary: "The NSA CNSA 2.0 suite: ML-KEM-1024 and ML-DSA-87 with AES-256.",
        status: ProfileStatus::Available,
        status_reason: "",
        suites: CNSA2_SUITES,
        groups: CNSA2_GROUPS,
        sigschemes: CNSA2_SIGSCHEMES,
        mutual_auth_required: false,
        fips_gate: true,
        post_quantum_required: true,
        min_rsa_bits: 3072,
        rationale: "CNSA 2.0 fixes one post-quantum parameter set at category 5 for National Security Systems: every group and every signature on the path is post-quantum, and every algorithm is FIPS-approved. The peer needs an ML-DSA-87 certificate chain. Do not substitute ML-KEM-768 or ML-DSA-65: they do not meet CNSA 2.0.",
        notes: NOT_VALIDATED,
    },
    Profile {
        id: "profile:dal-a",
        name: "DO-178C DAL-A restricted",
        summary: "One suite, one group, one signature scheme, mutual authentication, FIPS gate on.",
        status: ProfileStatus::Available,
        status_reason: "",
        suites: DAL_A_SUITES,
        groups: DAL_A_GROUPS,
        sigschemes: DAL_A_SIGSCHEMES,
        mutual_auth_required: true,
        fips_gate: true,
        post_quantum_required: false,
        min_rsa_bits: 3072,
        rationale: "DAL-A requires MC/DC structural coverage of every executable decision. Fixing the parameter set removes the negotiation branches that would otherwise each need coverage and verification evidence, and mutual authentication removes anonymous-client paths. Fewer reachable branches is less certification evidence to produce and review.",
        notes: "This profile is designed to support a DO-178C DAL-A certification effort. It is not a certification: DAL-A is granted to a specific airborne system by a certification authority, with evidence (plans, requirements trace, reviews, MC/DC coverage, tool qualification) produced for that system. IronSocketLayer has not been certified at any level.",
    },
];

/// Look up a profile by id.
pub fn get(id: &str) -> Option<&'static Profile> {
    PROFILES.iter().find(|p| p.id == id)
}
