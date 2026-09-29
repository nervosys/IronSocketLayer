//! The closed vocabulary every entry is expressed in.
//!
//! Every field an agent might branch on is an enum with a stable identifier.
//! Prose (`summary`, `notes`, constraint text) exists for humans and is never
//! load-bearing: an agent can act correctly using only the enums.

/// What kind of protocol element an entry describes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Kind {
    /// A protocol version (`version:`).
    ProtocolVersion,
    /// A record content type (`content:`).
    ContentType,
    /// A handshake message (`message:`).
    HandshakeMessage,
    /// A TLS 1.3 cipher suite (`suite:`).
    CipherSuite,
    /// A key-exchange group (`group:`).
    NamedGroup,
    /// A signature scheme (`sigscheme:`).
    SignatureScheme,
    /// An extension (`ext:`).
    Extension,
    /// An alert description (`alert:`).
    Alert,
    /// A KeyUpdate request value (`key-update:`).
    KeyUpdateRequest,
}

impl Kind {
    /// Every kind.
    pub const ALL: &'static [Kind] = &[
        Self::ProtocolVersion,
        Self::ContentType,
        Self::HandshakeMessage,
        Self::CipherSuite,
        Self::NamedGroup,
        Self::SignatureScheme,
        Self::Extension,
        Self::Alert,
        Self::KeyUpdateRequest,
    ];

    /// Stable identifier.
    pub const fn id(self) -> &'static str {
        match self {
            Self::ProtocolVersion => "protocol-version",
            Self::ContentType => "content-type",
            Self::HandshakeMessage => "handshake-message",
            Self::CipherSuite => "cipher-suite",
            Self::NamedGroup => "named-group",
            Self::SignatureScheme => "signature-scheme",
            Self::Extension => "extension",
            Self::Alert => "alert",
            Self::KeyUpdateRequest => "key-update-request",
        }
    }

    /// The id prefix every entry of this kind carries.
    pub const fn prefix(self) -> &'static str {
        match self {
            Self::ProtocolVersion => "version:",
            Self::ContentType => "content:",
            Self::HandshakeMessage => "message:",
            Self::CipherSuite => "suite:",
            Self::NamedGroup => "group:",
            Self::SignatureScheme => "sigscheme:",
            Self::Extension => "ext:",
            Self::Alert => "alert:",
            Self::KeyUpdateRequest => "key-update:",
        }
    }

    /// Look a kind up by its identifier.
    pub fn from_id(id: &str) -> Option<Kind> {
        Self::ALL.iter().copied().find(|k| k.id() == id)
    }
}

/// Whether this build implements an entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ImplStatus {
    /// Implemented and negotiable in this build.
    Implemented,
    /// The code point is recognised and reported by name, but never negotiated.
    NamedOnly,
    /// Intended for a later release. Not negotiated today.
    Planned,
    /// Deliberately left out; `status_reason` says why.
    Excluded,
}

impl ImplStatus {
    /// Every status.
    pub const ALL: &'static [ImplStatus] = &[
        Self::Implemented,
        Self::NamedOnly,
        Self::Planned,
        Self::Excluded,
    ];

    /// Stable identifier.
    pub const fn id(self) -> &'static str {
        match self {
            Self::Implemented => "implemented",
            Self::NamedOnly => "named-only",
            Self::Planned => "planned",
            Self::Excluded => "excluded",
        }
    }
}

/// FIPS 140-3 standing of the cryptography an entry uses, following
/// IronCrypto's own registry. Nothing here is a CMVP validation claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FipsStatus {
    /// Every cryptographic component is approved in IronCrypto's registry.
    Approved,
    /// At least one component is not approved.
    NotApproved,
    /// Forbidden in approved mode and in every profile (SHA-1 signatures).
    Disallowed,
    /// Not a cryptographic function (framing, alerts, messages).
    NotApplicable,
}

impl FipsStatus {
    /// Every status.
    pub const ALL: &'static [FipsStatus] = &[
        Self::Approved,
        Self::NotApproved,
        Self::Disallowed,
        Self::NotApplicable,
    ];

    /// Stable identifier.
    pub const fn id(self) -> &'static str {
        match self {
            Self::Approved => "approved",
            Self::NotApproved => "not-approved",
            Self::Disallowed => "disallowed",
            Self::NotApplicable => "not-applicable",
        }
    }
}

/// How bad it is to violate a constraint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Severity {
    /// Do not emit code or configuration that violates it.
    Critical,
    /// Do not violate it without telling the user.
    Serious,
    /// Prefer to honour it.
    Advisory,
}

impl Severity {
    /// Every severity.
    pub const ALL: &'static [Severity] = &[Self::Critical, Self::Serious, Self::Advisory];

    /// Stable identifier.
    pub const fn id(self) -> &'static str {
        match self {
            Self::Critical => "critical",
            Self::Serious => "serious",
            Self::Advisory => "advisory",
        }
    }
}

/// A usage rule, with the consequence of breaking it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Constraint {
    /// Stable identifier, unique within its entry.
    pub id: &'static str,
    /// What must be done.
    pub requirement: &'static str,
    /// What happens otherwise.
    pub consequence: &'static str,
    /// How binding it is.
    pub severity: Severity,
}

/// Security strength in bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Strength {
    /// Against a classical adversary. 0 where not meaningful.
    pub classical: u16,
    /// Against a quantum adversary. 0 where broken or not meaningful.
    pub quantum: u16,
}

impl Strength {
    /// Not a cryptographic entry.
    pub const NONE: Strength = Strength {
        classical: 0,
        quantum: 0,
    };
}

/// A typed edge between entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Relation {
    /// The source uses the target. Targets with an `ic:` prefix are
    /// IronCrypto algorithm ids.
    BuiltOn,
    /// The source replaces the target.
    Supersedes,
    /// The target replaces the source.
    SupersededBy,
    /// Commonly used together.
    PairsWith,
    /// The source is carried in, or only meaningful with, the target.
    CarriedIn,
    /// Negotiating the source requires the target.
    Requires,
}

impl Relation {
    /// Every relation.
    pub const ALL: &'static [Relation] = &[
        Self::BuiltOn,
        Self::Supersedes,
        Self::SupersededBy,
        Self::PairsWith,
        Self::CarriedIn,
        Self::Requires,
    ];

    /// Stable identifier.
    pub const fn id(self) -> &'static str {
        match self {
            Self::BuiltOn => "built-on",
            Self::Supersedes => "supersedes",
            Self::SupersededBy => "superseded-by",
            Self::PairsWith => "pairs-with",
            Self::CarriedIn => "carried-in",
            Self::Requires => "requires",
        }
    }
}

/// One edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Edge {
    /// The relation.
    pub relation: Relation,
    /// The target id.
    pub target: &'static str,
}

/// One protocol element.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Entry {
    /// Stable identifier, prefixed by kind.
    pub id: &'static str,
    /// Display name, as the RFC writes it.
    pub name: &'static str,
    /// What kind of element.
    pub kind: Kind,
    /// The code point on the wire.
    pub code: u16,
    /// One sentence.
    pub summary: &'static str,
    /// Whether this build implements it.
    pub status: ImplStatus,
    /// Why, when the status is not `Implemented`.
    pub status_reason: &'static str,
    /// FIPS 140-3 standing of its cryptography.
    pub fips: FipsStatus,
    /// Whether it resists a quantum adversary.
    pub post_quantum: bool,
    /// Security strength.
    pub strength: Strength,
    /// Defining documents.
    pub standards: &'static [&'static str],
    /// Usage rules.
    pub constraints: &'static [Constraint],
    /// Edges to other entries and to IronCrypto.
    pub edges: &'static [Edge],
    /// Anything else worth knowing.
    pub notes: &'static str,
}

impl Entry {
    /// A template: fill in what differs with struct-update syntax.
    pub const BASE: Entry = Entry {
        id: "",
        name: "",
        kind: Kind::Extension,
        code: 0,
        summary: "",
        status: ImplStatus::Implemented,
        status_reason: "",
        fips: FipsStatus::NotApplicable,
        post_quantum: false,
        strength: Strength::NONE,
        standards: &["RFC 8446"],
        constraints: &[],
        edges: &[],
        notes: "",
    };

    /// Whether the entry is negotiated by this build.
    pub const fn implemented(&self) -> bool {
        matches!(self.status, ImplStatus::Implemented)
    }
}
