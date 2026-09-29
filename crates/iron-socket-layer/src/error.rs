//! Errors an agent can act on without reading prose.
//!
//! Every failure carries a closed [`ErrorKind`] with a stable identifier, the
//! TLS alert it maps to, whether retrying could help, and whether the caller
//! can correct it. The human- and agent-readable explanation for each kind —
//! what it means and how to recover — lives in the ontology
//! (`isl_ontology::errors`), so an agent can fetch the recovery procedure by the
//! same identifier the error carries. `tests/ontology_agreement.rs` checks that
//! every kind here has a catalog entry and the reverse.

use core::fmt;

use crate::enums::AlertDescription;

/// Result type used throughout the crate.
pub type Result<T> = core::result::Result<T, Error>;

/// What went wrong, as a closed vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ErrorKind {
    /// A message or record could not be parsed.
    Decode,
    /// A message arrived that the handshake state does not permit.
    UnexpectedMessage,
    /// A field was syntactically valid but semantically forbidden.
    IllegalParameter,
    /// The peers share no acceptable version, suite, group or signature scheme.
    HandshakeFailure,
    /// The peer does not speak TLS 1.3 or later.
    ProtocolVersion,
    /// A mandatory extension was missing.
    MissingExtension,
    /// An extension appeared where it is not permitted, or was not requested.
    UnsupportedExtension,
    /// A record failed authenticated decryption.
    BadRecordMac,
    /// A record exceeded the size the protocol or the peer permits.
    RecordOverflow,
    /// A handshake signature or Finished MAC did not verify.
    DecryptError,
    /// The certificate could not be parsed or its signature did not verify.
    BadCertificate,
    /// The certificate uses an algorithm or form this build does not support.
    UnsupportedCertificate,
    /// The certificate is outside its validity period.
    CertificateExpired,
    /// The certificate has been revoked by its issuer.
    CertificateRevoked,
    /// A certificate status (OCSP) response was invalid, stale or missing
    /// where one was required.
    BadCertificateStatus,
    /// The chain does not lead to a configured trust anchor.
    UnknownCa,
    /// The certificate does not cover the name the connection is for.
    CertificateNameMismatch,
    /// The certificate is not permitted for this use (key usage, CA flags).
    CertificateUsage,
    /// The peer was required to authenticate and did not.
    CertificateRequired,
    /// No application protocol in common.
    NoApplicationProtocol,
    /// The server did not accept Encrypted Client Hello; its retry
    /// configurations are available on the connection.
    EchRejected,
    /// The negotiated parameters are valid TLS but violate the local policy.
    PolicyViolation,
    /// The FIPS module refused the algorithm, or is not operational.
    FipsModule,
    /// The peer sent a fatal alert.
    PeerAlert,
    /// The connection was closed cleanly and cannot carry more data.
    Closed,
    /// A key reached its usage limit and must be updated before more data.
    KeyExhausted,
    /// The API was used out of order.
    InvalidState,
    /// The configuration cannot produce a working handshake.
    InvalidConfig,
    /// A cryptographic primitive failed for a reason other than authentication.
    Crypto,
    /// Randomness was unavailable.
    Entropy,
    /// An internal invariant failed.
    Internal,
}

impl ErrorKind {
    /// Every kind, for enumeration by tests and by the ontology exporter.
    pub const ALL: &'static [ErrorKind] = &[
        Self::Decode,
        Self::UnexpectedMessage,
        Self::IllegalParameter,
        Self::HandshakeFailure,
        Self::ProtocolVersion,
        Self::MissingExtension,
        Self::UnsupportedExtension,
        Self::BadRecordMac,
        Self::RecordOverflow,
        Self::DecryptError,
        Self::BadCertificate,
        Self::UnsupportedCertificate,
        Self::CertificateExpired,
        Self::CertificateRevoked,
        Self::BadCertificateStatus,
        Self::UnknownCa,
        Self::CertificateNameMismatch,
        Self::CertificateUsage,
        Self::CertificateRequired,
        Self::NoApplicationProtocol,
        Self::EchRejected,
        Self::PolicyViolation,
        Self::FipsModule,
        Self::PeerAlert,
        Self::Closed,
        Self::KeyExhausted,
        Self::InvalidState,
        Self::InvalidConfig,
        Self::Crypto,
        Self::Entropy,
        Self::Internal,
    ];

    /// Stable identifier; the key into `isl_ontology::errors`.
    pub const fn id(self) -> &'static str {
        match self {
            Self::Decode => "error:decode",
            Self::UnexpectedMessage => "error:unexpected-message",
            Self::IllegalParameter => "error:illegal-parameter",
            Self::HandshakeFailure => "error:handshake-failure",
            Self::ProtocolVersion => "error:protocol-version",
            Self::MissingExtension => "error:missing-extension",
            Self::UnsupportedExtension => "error:unsupported-extension",
            Self::BadRecordMac => "error:bad-record-mac",
            Self::RecordOverflow => "error:record-overflow",
            Self::DecryptError => "error:decrypt-error",
            Self::BadCertificate => "error:bad-certificate",
            Self::UnsupportedCertificate => "error:unsupported-certificate",
            Self::CertificateExpired => "error:certificate-expired",
            Self::CertificateRevoked => "error:certificate-revoked",
            Self::BadCertificateStatus => "error:bad-certificate-status",
            Self::UnknownCa => "error:unknown-ca",
            Self::CertificateNameMismatch => "error:certificate-name-mismatch",
            Self::CertificateUsage => "error:certificate-usage",
            Self::CertificateRequired => "error:certificate-required",
            Self::NoApplicationProtocol => "error:no-application-protocol",
            Self::EchRejected => "error:ech-rejected",
            Self::PolicyViolation => "error:policy-violation",
            Self::FipsModule => "error:fips-module",
            Self::PeerAlert => "error:peer-alert",
            Self::Closed => "error:closed",
            Self::KeyExhausted => "error:key-exhausted",
            Self::InvalidState => "error:invalid-state",
            Self::InvalidConfig => "error:invalid-config",
            Self::Crypto => "error:crypto",
            Self::Entropy => "error:entropy",
            Self::Internal => "error:internal",
        }
    }

    /// The alert this endpoint sends when it fails this way, if any.
    ///
    /// `None` for failures that are local (API misuse, closure) or that the
    /// peer announced itself.
    pub const fn alert(self) -> Option<AlertDescription> {
        use AlertDescription as A;
        Some(match self {
            Self::Decode => A::DecodeError,
            Self::UnexpectedMessage => A::UnexpectedMessage,
            Self::IllegalParameter => A::IllegalParameter,
            Self::HandshakeFailure => A::HandshakeFailure,
            Self::ProtocolVersion => A::ProtocolVersion,
            Self::MissingExtension => A::MissingExtension,
            Self::UnsupportedExtension => A::UnsupportedExtension,
            Self::BadRecordMac => A::BadRecordMac,
            Self::RecordOverflow => A::RecordOverflow,
            Self::DecryptError => A::DecryptError,
            Self::BadCertificate | Self::CertificateNameMismatch | Self::CertificateUsage => {
                A::BadCertificate
            }
            Self::UnsupportedCertificate => A::UnsupportedCertificate,
            Self::CertificateExpired => A::CertificateExpired,
            Self::CertificateRevoked => A::CertificateRevoked,
            Self::BadCertificateStatus => A::BadCertificateStatusResponse,
            Self::UnknownCa => A::UnknownCa,
            Self::CertificateRequired => A::CertificateRequired,
            Self::NoApplicationProtocol => A::NoApplicationProtocol,
            Self::EchRejected => A::EchRequired,
            Self::PolicyViolation => A::InsufficientSecurity,
            Self::FipsModule
            | Self::Crypto
            | Self::Entropy
            | Self::Internal
            | Self::KeyExhausted => A::InternalError,
            Self::PeerAlert | Self::Closed | Self::InvalidState | Self::InvalidConfig => {
                return None
            }
        })
    }

    /// Whether a fresh attempt could plausibly succeed without changes.
    pub const fn retryable(self) -> bool {
        matches!(self, Self::Entropy | Self::KeyExhausted)
    }

    /// Whether the local caller can fix it by changing configuration or usage.
    pub const fn caller_correctable(self) -> bool {
        matches!(
            self,
            Self::InvalidConfig
                | Self::InvalidState
                | Self::PolicyViolation
                | Self::FipsModule
                | Self::UnknownCa
                | Self::CertificateNameMismatch
                | Self::NoApplicationProtocol
                | Self::HandshakeFailure
                | Self::CertificateRequired
                | Self::EchRejected
        )
    }

    /// Whether the failure is attributable to the remote peer.
    pub const fn peer_fault(self) -> bool {
        matches!(
            self,
            Self::Decode
                | Self::UnexpectedMessage
                | Self::IllegalParameter
                | Self::ProtocolVersion
                | Self::MissingExtension
                | Self::UnsupportedExtension
                | Self::BadRecordMac
                | Self::RecordOverflow
                | Self::DecryptError
                | Self::BadCertificate
                | Self::CertificateExpired
                | Self::CertificateRevoked
                | Self::BadCertificateStatus
                | Self::PeerAlert
        )
    }
}

/// An error: a kind, a static context string, and the peer's alert when the
/// peer is the one who failed the connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Error {
    kind: ErrorKind,
    context: &'static str,
    peer_alert: Option<AlertDescription>,
}

impl Error {
    /// Construct an error.
    pub const fn new(kind: ErrorKind, context: &'static str) -> Self {
        Self {
            kind,
            context,
            peer_alert: None,
        }
    }

    /// An error recording that the peer sent `alert`.
    pub const fn from_peer(alert: AlertDescription) -> Self {
        Self {
            kind: ErrorKind::PeerAlert,
            context: "peer sent a fatal alert",
            peer_alert: Some(alert),
        }
    }

    /// What went wrong.
    pub const fn kind(&self) -> ErrorKind {
        self.kind
    }

    /// Where it went wrong, as fixed text.
    pub const fn context(&self) -> &'static str {
        self.context
    }

    /// The alert the peer sent, for [`ErrorKind::PeerAlert`].
    pub const fn peer_alert(&self) -> Option<AlertDescription> {
        self.peer_alert
    }

    /// The ontology identifier of the kind.
    pub const fn id(&self) -> &'static str {
        self.kind.id()
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.kind.id(), self.context)?;
        if let Some(a) = self.peer_alert {
            write!(f, " ({a})")?;
        }
        Ok(())
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

impl From<ic_core::Error> for Error {
    fn from(e: ic_core::Error) -> Self {
        use ic_core::ErrorKind as K;
        let kind = match e.kind() {
            K::AuthenticationFailed => ErrorKind::DecryptError,
            K::NotApprovedInFipsMode | K::ModuleErrorState | K::SelfTestFailed => {
                ErrorKind::FipsModule
            }
            K::EntropyFailure => ErrorKind::Entropy,
            K::MalformedEncoding => ErrorKind::Decode,
            K::InvalidLength | K::InvalidParameter => ErrorKind::IllegalParameter,
            K::Unsupported => ErrorKind::Crypto,
            K::CounterExhausted => ErrorKind::KeyExhausted,
            _ => ErrorKind::Crypto,
        };
        Error::new(kind, e.context())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifiers_are_unique_and_namespaced() {
        for (i, a) in ErrorKind::ALL.iter().enumerate() {
            assert!(a.id().starts_with("error:"));
            for b in &ErrorKind::ALL[i + 1..] {
                assert_ne!(a.id(), b.id());
            }
        }
    }

    #[test]
    fn local_failures_do_not_send_alerts() {
        assert_eq!(ErrorKind::InvalidState.alert(), None);
        assert_eq!(ErrorKind::PeerAlert.alert(), None);
        assert_eq!(
            ErrorKind::Decode.alert(),
            Some(AlertDescription::DecodeError)
        );
    }
}
