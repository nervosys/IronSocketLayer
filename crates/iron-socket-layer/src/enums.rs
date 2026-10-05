//! Protocol code points, each with a stable ontology identifier.
//!
//! Every enum here keeps unknown values as `Unknown(raw)` rather than failing
//! at parse time: TLS requires ignoring unknown extensions, groups and schemes
//! a peer offers, and the ontology needs to be able to name what was offered.
//!
//! The `id()` of every known variant is a key into [`isl_ontology`], and a
//! cross-layer test (`tests/ontology_agreement.rs`) fails if the two disagree.

macro_rules! wire_enum {
    (
        $(#[$meta:meta])*
        $name:ident: $ty:ty {
            $( $(#[$vmeta:meta])* $var:ident = $val:literal => $id:literal, )*
        }
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        #[non_exhaustive]
        pub enum $name {
            $( $(#[$vmeta])* $var, )*
            /// A code point this build does not name.
            Unknown($ty),
        }

        impl $name {
            /// Every named variant, in declaration order.
            pub const ALL: &'static [$name] = &[ $( $name::$var, )* ];

            /// The value on the wire.
            pub const fn to_wire(self) -> $ty {
                match self {
                    $( $name::$var => $val, )*
                    $name::Unknown(v) => v,
                }
            }

            /// Interpret a wire value. Never fails.
            pub const fn from_wire(v: $ty) -> Self {
                match v {
                    $( $val => $name::$var, )*
                    other => $name::Unknown(other),
                }
            }

            /// Stable ontology identifier, or `"unknown"`.
            pub const fn id(self) -> &'static str {
                match self {
                    $( $name::$var => $id, )*
                    $name::Unknown(_) => "unknown",
                }
            }

            /// Look up a variant by its ontology identifier.
            pub fn from_id(id: &str) -> Option<Self> {
                match id {
                    $( $id => Some($name::$var), )*
                    _ => None,
                }
            }
        }

        impl core::fmt::Display for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                match self {
                    $name::Unknown(v) => write!(f, "unknown(0x{:x})", v),
                    known => f.write_str(known.id()),
                }
            }
        }
    };
}

wire_enum! {
    /// `ProtocolVersion` (RFC 8446 §4.1.2, §4.2.1).
    ProtocolVersion: u16 {
        /// TLS 1.2. Appears only as `legacy_version`; never negotiated.
        Tls12 = 0x0303 => "version:tls1.2",
        /// TLS 1.3, RFC 8446.
        Tls13 = 0x0304 => "version:tls1.3",
    }
}

wire_enum! {
    /// Record `ContentType` (RFC 8446 §5.1).
    ContentType: u8 {
        /// Only legal as the inner type of padding-only records; never sent.
        Invalid = 0 => "content:invalid",
        /// Middlebox-compatibility `ChangeCipherSpec`, ignored in TLS 1.3.
        ChangeCipherSpec = 20 => "content:change-cipher-spec",
        /// Alerts.
        Alert = 21 => "content:alert",
        /// Handshake messages.
        Handshake = 22 => "content:handshake",
        /// Application data, and the outer type of every protected record.
        ApplicationData = 23 => "content:application-data",
    }
}

wire_enum! {
    /// `HandshakeType` (RFC 8446 §4).
    HandshakeType: u8 {
        /// ClientHello.
        ClientHello = 1 => "message:client-hello",
        /// ServerHello, and HelloRetryRequest which shares its code point.
        ServerHello = 2 => "message:server-hello",
        /// NewSessionTicket.
        NewSessionTicket = 4 => "message:new-session-ticket",
        /// EndOfEarlyData.
        EndOfEarlyData = 5 => "message:end-of-early-data",
        /// EncryptedExtensions.
        EncryptedExtensions = 8 => "message:encrypted-extensions",
        /// Certificate.
        Certificate = 11 => "message:certificate",
        /// CertificateRequest.
        CertificateRequest = 13 => "message:certificate-request",
        /// CertificateVerify.
        CertificateVerify = 15 => "message:certificate-verify",
        /// Finished.
        Finished = 20 => "message:finished",
        /// KeyUpdate.
        KeyUpdate = 24 => "message:key-update",
        /// The synthetic `message_hash` that replaces ClientHello1 after a retry.
        MessageHash = 254 => "message:message-hash",
    }
}

wire_enum! {
    /// TLS 1.3 cipher suites (RFC 8446 §B.4).
    CipherSuite: u16 {
        /// AES-128-GCM with SHA-256.
        TlsAes128GcmSha256 = 0x1301 => "suite:tls-aes-128-gcm-sha256",
        /// AES-256-GCM with SHA-384.
        TlsAes256GcmSha384 = 0x1302 => "suite:tls-aes-256-gcm-sha384",
        /// ChaCha20-Poly1305 with SHA-256.
        TlsChaCha20Poly1305Sha256 = 0x1303 => "suite:tls-chacha20-poly1305-sha256",
        /// AES-128-CCM with SHA-256. Named, not implemented.
        TlsAes128CcmSha256 = 0x1304 => "suite:tls-aes-128-ccm-sha256",
        /// AES-128-CCM-8 with SHA-256. Named, not implemented.
        TlsAes128Ccm8Sha256 = 0x1305 => "suite:tls-aes-128-ccm-8-sha256",
    }
}

wire_enum! {
    /// `NamedGroup` for key exchange (RFC 8446 §4.2.7, draft-ietf-tls-ecdhe-mlkem,
    /// draft-ietf-tls-mlkem).
    NamedGroup: u16 {
        /// NIST P-256 ECDHE.
        Secp256r1 = 0x0017 => "group:secp256r1",
        /// NIST P-384 ECDHE.
        Secp384r1 = 0x0018 => "group:secp384r1",
        /// NIST P-521 ECDHE.
        Secp521r1 = 0x0019 => "group:secp521r1",
        /// X25519 ECDHE.
        X25519 = 0x001d => "group:x25519",
        /// X448. Named, not implemented.
        X448 = 0x001e => "group:x448",
        /// Finite-field DHE 2048. Named, not implemented.
        Ffdhe2048 = 0x0100 => "group:ffdhe2048",
        /// Pure ML-KEM-512. Available by explicit configuration.
        MlKem512 = 0x0200 => "group:mlkem512",
        /// Pure ML-KEM-768.
        MlKem768 = 0x0201 => "group:mlkem768",
        /// Pure ML-KEM-1024.
        MlKem1024 = 0x0202 => "group:mlkem1024",
        /// Hybrid P-256 ECDHE + ML-KEM-768.
        SecP256r1MlKem768 = 0x11eb => "group:secp256r1mlkem768",
        /// Hybrid X25519 + ML-KEM-768.
        X25519MlKem768 = 0x11ec => "group:x25519mlkem768",
        /// Hybrid P-384 ECDHE + ML-KEM-1024.
        SecP384r1MlKem1024 = 0x11ed => "group:secp384r1mlkem1024",
    }
}

wire_enum! {
    /// `SignatureScheme` (RFC 8446 §4.2.3, draft-ietf-tls-mldsa).
    SignatureScheme: u16 {
        /// RSASSA-PKCS1-v1_5 with SHA-1. Disallowed everywhere.
        RsaPkcs1Sha1 = 0x0201 => "sigscheme:rsa-pkcs1-sha1",
        /// ECDSA with SHA-1. Disallowed everywhere.
        EcdsaSha1 = 0x0203 => "sigscheme:ecdsa-sha1",
        /// RSASSA-PKCS1-v1_5 with SHA-256. Certificates only.
        RsaPkcs1Sha256 = 0x0401 => "sigscheme:rsa-pkcs1-sha256",
        /// ECDSA P-256 with SHA-256.
        EcdsaSecp256r1Sha256 = 0x0403 => "sigscheme:ecdsa-secp256r1-sha256",
        /// RSASSA-PKCS1-v1_5 with SHA-384. Certificates only.
        RsaPkcs1Sha384 = 0x0501 => "sigscheme:rsa-pkcs1-sha384",
        /// ECDSA P-384 with SHA-384.
        EcdsaSecp384r1Sha384 = 0x0503 => "sigscheme:ecdsa-secp384r1-sha384",
        /// RSASSA-PKCS1-v1_5 with SHA-512. Certificates only.
        RsaPkcs1Sha512 = 0x0601 => "sigscheme:rsa-pkcs1-sha512",
        /// ECDSA P-521 with SHA-512.
        EcdsaSecp521r1Sha512 = 0x0603 => "sigscheme:ecdsa-secp521r1-sha512",
        /// RSASSA-PSS, rsaEncryption key, SHA-256.
        RsaPssRsaeSha256 = 0x0804 => "sigscheme:rsa-pss-rsae-sha256",
        /// RSASSA-PSS, rsaEncryption key, SHA-384.
        RsaPssRsaeSha384 = 0x0805 => "sigscheme:rsa-pss-rsae-sha384",
        /// RSASSA-PSS, rsaEncryption key, SHA-512.
        RsaPssRsaeSha512 = 0x0806 => "sigscheme:rsa-pss-rsae-sha512",
        /// Ed25519.
        Ed25519 = 0x0807 => "sigscheme:ed25519",
        /// Ed448. Named, not implemented.
        Ed448 = 0x0808 => "sigscheme:ed448",
        /// RSASSA-PSS, RSASSA-PSS key, SHA-256. Named, not implemented.
        RsaPssPssSha256 = 0x0809 => "sigscheme:rsa-pss-pss-sha256",
        /// ML-DSA-44. Available by explicit configuration.
        MlDsa44 = 0x0904 => "sigscheme:mldsa44",
        /// ML-DSA-65.
        MlDsa65 = 0x0905 => "sigscheme:mldsa65",
        /// ML-DSA-87.
        MlDsa87 = 0x0906 => "sigscheme:mldsa87",
    }
}

wire_enum! {
    /// `ExtensionType` (RFC 8446 §4.2 and the IANA registry).
    ExtensionType: u16 {
        /// Server Name Indication, RFC 6066.
        ServerName = 0 => "ext:server-name",
        /// Maximum fragment length, RFC 6066. Superseded by record_size_limit.
        MaxFragmentLength = 1 => "ext:max-fragment-length",
        /// OCSP status request, RFC 6066.
        StatusRequest = 5 => "ext:status-request",
        /// Supported groups, RFC 8446.
        SupportedGroups = 10 => "ext:supported-groups",
        /// Signature algorithms, RFC 8446.
        SignatureAlgorithms = 13 => "ext:signature-algorithms",
        /// ALPN, RFC 7301.
        ApplicationLayerProtocolNegotiation = 16 => "ext:alpn",
        /// Signed certificate timestamps, RFC 6962.
        SignedCertificateTimestamp = 18 => "ext:signed-certificate-timestamp",
        /// Padding, RFC 7685.
        Padding = 21 => "ext:padding",
        /// Record size limit, RFC 8449.
        RecordSizeLimit = 28 => "ext:record-size-limit",
        /// Pre-shared key, RFC 8446.
        PreSharedKey = 41 => "ext:pre-shared-key",
        /// Early data, RFC 8446.
        EarlyData = 42 => "ext:early-data",
        /// Supported versions, RFC 8446.
        SupportedVersions = 43 => "ext:supported-versions",
        /// Cookie, RFC 8446.
        Cookie = 44 => "ext:cookie",
        /// PSK key exchange modes, RFC 8446.
        PskKeyExchangeModes = 45 => "ext:psk-key-exchange-modes",
        /// Certificate authorities, RFC 8446.
        CertificateAuthorities = 47 => "ext:certificate-authorities",
        /// OID filters, RFC 8446.
        OidFilters = 48 => "ext:oid-filters",
        /// Post-handshake client authentication, RFC 8446.
        PostHandshakeAuth = 49 => "ext:post-handshake-auth",
        /// Signature algorithms for certificates, RFC 8446.
        SignatureAlgorithmsCert = 50 => "ext:signature-algorithms-cert",
        /// Key share, RFC 8446.
        KeyShare = 51 => "ext:key-share",
        /// QUIC transport parameters, RFC 9001.
        QuicTransportParameters = 57 => "ext:quic-transport-parameters",
        /// Encrypted Client Hello, draft-ietf-tls-esni.
        EncryptedClientHello = 0xfe0d => "ext:encrypted-client-hello",
        /// ECH outer-extension references inside an encoded inner hello.
        EchOuterExtensions = 0xfd00 => "ext:ech-outer-extensions",
    }
}

wire_enum! {
    /// `AlertDescription` (RFC 8446 §6).
    AlertDescription: u8 {
        /// Orderly closure.
        CloseNotify = 0 => "alert:close-notify",
        /// A message arrived that the state machine does not permit.
        UnexpectedMessage = 10 => "alert:unexpected-message",
        /// A record failed AEAD authentication.
        BadRecordMac = 20 => "alert:bad-record-mac",
        /// A record exceeded the permitted size.
        RecordOverflow = 22 => "alert:record-overflow",
        /// No acceptable set of parameters.
        HandshakeFailure = 40 => "alert:handshake-failure",
        /// A certificate was corrupt or its signature did not verify.
        BadCertificate = 42 => "alert:bad-certificate",
        /// A certificate of an unsupported type.
        UnsupportedCertificate = 43 => "alert:unsupported-certificate",
        /// A certificate was revoked.
        CertificateRevoked = 44 => "alert:certificate-revoked",
        /// A certificate was outside its validity period.
        CertificateExpired = 45 => "alert:certificate-expired",
        /// Some other certificate problem.
        CertificateUnknown = 46 => "alert:certificate-unknown",
        /// A field was out of range or inconsistent.
        IllegalParameter = 47 => "alert:illegal-parameter",
        /// The chain did not lead to a trusted anchor.
        UnknownCa = 48 => "alert:unknown-ca",
        /// Access control refused the peer.
        AccessDenied = 49 => "alert:access-denied",
        /// A message could not be decoded.
        DecodeError = 50 => "alert:decode-error",
        /// A handshake signature or Finished MAC failed.
        DecryptError = 51 => "alert:decrypt-error",
        /// The peer offered no version this endpoint accepts.
        ProtocolVersion = 70 => "alert:protocol-version",
        /// Parameters were acceptable to TLS but not to local policy.
        InsufficientSecurity = 71 => "alert:insufficient-security",
        /// A failure unrelated to the peer.
        InternalError = 80 => "alert:internal-error",
        /// A fallback retry was detected.
        InappropriateFallback = 86 => "alert:inappropriate-fallback",
        /// The user cancelled the handshake.
        UserCanceled = 90 => "alert:user-canceled",
        /// A mandatory extension was absent.
        MissingExtension = 109 => "alert:missing-extension",
        /// An extension appeared where it is not permitted.
        UnsupportedExtension = 110 => "alert:unsupported-extension",
        /// No certificate for the requested server name.
        UnrecognizedName = 112 => "alert:unrecognized-name",
        /// An invalid OCSP response.
        BadCertificateStatusResponse = 113 => "alert:bad-certificate-status-response",
        /// An unknown PSK identity.
        UnknownPskIdentity = 115 => "alert:unknown-psk-identity",
        /// A client certificate was required and not sent.
        CertificateRequired = 116 => "alert:certificate-required",
        /// No mutually supported application protocol.
        NoApplicationProtocol = 120 => "alert:no-application-protocol",
        /// ECH was offered and not accepted; retry with the server's configs.
        EchRequired = 121 => "alert:ech-required",
    }
}

wire_enum! {
    /// `KeyUpdateRequest` (RFC 8446 §4.6.3).
    KeyUpdateRequest: u8 {
        /// The peer need not respond.
        UpdateNotRequested = 0 => "key-update:not-requested",
        /// The peer must send its own KeyUpdate.
        UpdateRequested = 1 => "key-update:requested",
    }
}

impl SignatureScheme {
    /// Whether the scheme resists a quantum adversary (ML-DSA).
    pub const fn is_post_quantum(self) -> bool {
        matches!(self, Self::MlDsa44 | Self::MlDsa65 | Self::MlDsa87)
    }

    /// Whether RFC 8446 permits this scheme in `CertificateVerify`.
    ///
    /// PKCS#1 v1.5 and SHA-1 schemes may appear in certificates but never sign
    /// a TLS 1.3 handshake (§4.4.3).
    pub const fn allowed_in_handshake(self) -> bool {
        !matches!(
            self,
            Self::RsaPkcs1Sha1
                | Self::EcdsaSha1
                | Self::RsaPkcs1Sha256
                | Self::RsaPkcs1Sha384
                | Self::RsaPkcs1Sha512
                | Self::Unknown(_)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_values_round_trip_and_ids_are_unique() {
        fn check<T: Copy + PartialEq + core::fmt::Debug>(
            all: &[T],
            id: fn(T) -> &'static str,
            back: fn(&str) -> Option<T>,
        ) {
            for (i, a) in all.iter().enumerate() {
                assert_eq!(back(id(*a)), Some(*a));
                for b in &all[i + 1..] {
                    assert_ne!(id(*a), id(*b));
                }
            }
        }
        check(CipherSuite::ALL, CipherSuite::id, CipherSuite::from_id);
        check(NamedGroup::ALL, NamedGroup::id, NamedGroup::from_id);
        check(
            SignatureScheme::ALL,
            SignatureScheme::id,
            SignatureScheme::from_id,
        );
        check(
            ExtensionType::ALL,
            ExtensionType::id,
            ExtensionType::from_id,
        );
        check(
            AlertDescription::ALL,
            AlertDescription::id,
            AlertDescription::from_id,
        );
        for g in NamedGroup::ALL {
            assert_eq!(NamedGroup::from_wire(g.to_wire()), *g);
        }
        assert_eq!(NamedGroup::from_wire(0x1234), NamedGroup::Unknown(0x1234));
    }
}
