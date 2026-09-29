//! The registry: one entry per protocol element this build can name.
//!
//! Identifiers equal what `iron_socket_layer`' enums return from `id()`, and the
//! `implemented` set equals what it negotiates; the cross-layer test
//! `crates/iron-socket-layer/tests/ontology_agreement.rs` fails if either drifts.

use crate::types::{
    Constraint, Edge, Entry, FipsStatus, ImplStatus, Kind, Relation, Severity, Strength,
};

const fn built(target: &'static str) -> Edge {
    Edge {
        relation: Relation::BuiltOn,
        target,
    }
}
const fn pairs(target: &'static str) -> Edge {
    Edge {
        relation: Relation::PairsWith,
        target,
    }
}
const fn carried(target: &'static str) -> Edge {
    Edge {
        relation: Relation::CarriedIn,
        target,
    }
}
const fn requires(target: &'static str) -> Edge {
    Edge {
        relation: Relation::Requires,
        target,
    }
}
const fn superseded_by(target: &'static str) -> Edge {
    Edge {
        relation: Relation::SupersededBy,
        target,
    }
}
const fn supersedes(target: &'static str) -> Edge {
    Edge {
        relation: Relation::Supersedes,
        target,
    }
}

const fn critical(
    id: &'static str,
    requirement: &'static str,
    consequence: &'static str,
) -> Constraint {
    Constraint {
        id,
        requirement,
        consequence,
        severity: Severity::Critical,
    }
}
const fn serious(
    id: &'static str,
    requirement: &'static str,
    consequence: &'static str,
) -> Constraint {
    Constraint {
        id,
        requirement,
        consequence,
        severity: Severity::Serious,
    }
}
const fn advisory(
    id: &'static str,
    requirement: &'static str,
    consequence: &'static str,
) -> Constraint {
    Constraint {
        id,
        requirement,
        consequence,
        severity: Severity::Advisory,
    }
}

const S128: Strength = Strength {
    classical: 128,
    quantum: 64,
};
const S256: Strength = Strength {
    classical: 256,
    quantum: 128,
};
const ECC128: Strength = Strength {
    classical: 128,
    quantum: 0,
};
const ECC192: Strength = Strength {
    classical: 192,
    quantum: 0,
};
const ECC256: Strength = Strength {
    classical: 256,
    quantum: 0,
};
const PQ_L3: Strength = Strength {
    classical: 192,
    quantum: 192,
};
const HYBRID_128_192: Strength = Strength {
    classical: 192,
    quantum: 192,
};

// ---------------------------------------------------------------------------
// Shared constraints
// ---------------------------------------------------------------------------

const GCM_LIMIT: Constraint = serious(
    "update-key-before-2-24-records",
    "Send a KeyUpdate before 2^24 records are protected under one traffic key.",
    "RFC 8446 §5.5: past 2^24.5 full-size records the AES-GCM confidentiality margin falls below 2^-57. IronSocketLayer enforces this and returns error:key-exhausted if the peer will not update.",
);
const SEQ_NONCE: Constraint = critical(
    "nonce-from-sequence-number",
    "Derive every record nonce from the traffic IV XORed with the 64-bit record sequence number; never reuse a sequence number under one key.",
    "A repeated (key, nonce) leaks the GHASH/Poly1305 key and the XOR of two plaintexts. IronSocketLayer owns the sequence number; do not re-implement record protection around it.",
);
const NO_CHACHA_FIPS: Constraint = serious(
    "not-in-fips-profile",
    "Do not offer this suite under profile:fips-140-3, profile:cnsa-1 or profile:dal-a.",
    "ChaCha20-Poly1305 is not a FIPS-approved AEAD; offering it breaks the approved-mode boundary.",
);
const VALIDATE_SHARE: Constraint = critical(
    "validate-peer-share",
    "Reject a key share whose length or encoding is wrong for the group, and a point that is not on the curve.",
    "Invalid-curve and small-subgroup shares leak the ephemeral private key or force a known secret.",
);
const UNCOMPRESSED_ONLY: Constraint = serious(
    "uncompressed-points-only",
    "Send and accept only the uncompressed SEC1 point form (0x04 || X || Y).",
    "RFC 8446 §4.2.8.2 defines no other form for TLS 1.3; a compressed point is illegal_parameter.",
);
const X25519_ZERO: Constraint = critical(
    "reject-all-zero-secret",
    "Abort with illegal_parameter if the X25519 output is all zeros.",
    "RFC 8446 §7.4.2: a low-order peer point yields a zero secret the attacker knows.",
);
const ONE_SHOT_EPHEMERAL: Constraint = critical(
    "ephemeral-single-use",
    "Generate a fresh ephemeral key for every handshake and zeroize it after use.",
    "Reusing an ephemeral key forfeits forward secrecy across connections.",
);
const KEM_ENCAPS_CHECK: Constraint = critical(
    "check-encapsulation-key",
    "Run the FIPS 203 encapsulation-key check (modulus check) before encapsulating to a peer's key.",
    "An unchecked key lets a malicious client bias or learn the shared secret.",
);
const HYBRID_ORDER: Constraint = critical(
    "component-order",
    "Concatenate the shares and the secrets in the order the group defines; the two hybrid groups do not use the same order.",
    "A swapped order produces a handshake that only fails against other implementations.",
);
const PKCS1_CERT_ONLY: Constraint = critical(
    "certificates-only",
    "Accept this scheme in certificate signatures only; never produce or accept it in CertificateVerify.",
    "RFC 8446 §4.4.3 forbids PKCS#1 v1.5 for handshake signatures; accepting one reopens the Bleichenbacher-style forgery surface.",
);
const PSS_SALT: Constraint = serious(
    "salt-equals-digest-length",
    "Use a PSS salt exactly as long as the digest.",
    "RFC 8446 §4.2.3 requires it; peers reject other lengths.",
);
const RSA_MIN: Constraint = serious(
    "rsa-2048-minimum",
    "Refuse RSA moduli below 2048 bits (3072 under profile:cnsa-1).",
    "Smaller moduli fall below 112-bit security (SP 800-57 Part 1).",
);
const ECDSA_DER: Constraint = advisory(
    "der-encoded-signature",
    "Carry ECDSA signatures as a DER Ecdsa-Sig-Value, not fixed-width r||s.",
    "Fixed-width signatures are rejected by every conforming peer.",
);
const SHA1_NEVER: Constraint = critical(
    "never-use",
    "Never offer, accept or verify this scheme.",
    "SHA-1 collisions are practical (SHAttered, 2017); a chain signed with it can be forged.",
);
const MLDSA_CTX: Constraint = serious(
    "empty-context",
    "Sign and verify pure ML-DSA with an empty context string, over the full CertificateVerify content.",
    "draft-ietf-tls-mldsa uses pure ML-DSA with an empty context; HashML-DSA or a context produces signatures no peer verifies.",
);
const UNKNOWN_EXT_IGNORE: Constraint = critical(
    "ignore-unknown",
    "Ignore unknown extensions in ClientHello; reject unsolicited extensions in server messages.",
    "RFC 8446 §4.2: failing on unknown client extensions breaks forward compatibility; accepting unsolicited server extensions is unsupported_extension.",
);
const ZERO_RTT_REPLAY: Constraint = critical(
    "replayable",
    "Only send idempotent requests as 0-RTT data, and require server-side anti-replay.",
    "RFC 8446 §8: early data has no forward secrecy and can be replayed by a network attacker.",
);

// ---------------------------------------------------------------------------
// Entries
// ---------------------------------------------------------------------------

/// Every entry, grouped by kind.
pub static REGISTRY: &[Entry] = &[
    // --- versions -------------------------------------------------------------
    Entry {
        id: "version:tls1.3",
        name: "TLS 1.3",
        kind: Kind::ProtocolVersion,
        code: 0x0304,
        summary: "The only protocol version IronSocketLayer negotiates.",
        edges: &[carried("ext:supported-versions"), supersedes("version:tls1.2")],
        constraints: &[critical(
            "negotiate-via-supported-versions",
            "Negotiate the version only through the supported_versions extension; legacy_version stays 0x0303.",
            "A server that reads legacy_version can be steered into a downgrade.",
        )],
        ..Entry::BASE
    },
    Entry {
        id: "version:tls1.2",
        name: "TLS 1.2",
        kind: Kind::ProtocolVersion,
        code: 0x0303,
        summary: "Appears only as the frozen legacy_version field; never negotiated.",
        status: ImplStatus::Excluded,
        status_reason: "TLS 1.3 and later only, by design: TLS 1.2's renegotiation, static RSA and CBC suites are a certification and attack surface an agentic stack does not need.",
        standards: &["RFC 5246"],
        edges: &[superseded_by("version:tls1.3")],
        ..Entry::BASE
    },
    // --- content types --------------------------------------------------------
    Entry { id: "content:invalid", name: "invalid", kind: Kind::ContentType, code: 0, summary: "Never sent; an inner content type of zero means the record is all padding and is a decode error.", ..Entry::BASE },
    Entry { id: "content:change-cipher-spec", name: "change_cipher_spec", kind: Kind::ContentType, code: 20, summary: "Sent once for middlebox compatibility and otherwise ignored; never sent under QUIC.", notes: "A value other than 0x01, or one arriving after the handshake, is unexpected_message.", ..Entry::BASE },
    Entry { id: "content:alert", name: "alert", kind: Kind::ContentType, code: 21, summary: "Alert records; encrypted once handshake keys are in use.", ..Entry::BASE },
    Entry { id: "content:handshake", name: "handshake", kind: Kind::ContentType, code: 22, summary: "Handshake messages, which may span records but may not interleave with other content types.", constraints: &[critical("key-change-on-record-boundary", "Reject handshake data buffered across a key change.", "RFC 8446 §5.1: data straddling a key change would be authenticated under the wrong key.")], ..Entry::BASE },
    Entry { id: "content:application-data", name: "application_data", kind: Kind::ContentType, code: 23, summary: "Application data, and the outer content type of every protected record.", ..Entry::BASE },
    // --- handshake messages ---------------------------------------------------
    Entry { id: "message:client-hello", name: "ClientHello", kind: Kind::HandshakeMessage, code: 1, summary: "Opens the handshake: offered suites, groups, key shares and signature schemes.", ..Entry::BASE },
    Entry { id: "message:server-hello", name: "ServerHello", kind: Kind::HandshakeMessage, code: 2, summary: "Selects the suite and key share; with the special random it is a HelloRetryRequest.", notes: "HelloRetryRequest random is SHA-256(\"HelloRetryRequest\").", ..Entry::BASE },
    Entry { id: "message:new-session-ticket", name: "NewSessionTicket", kind: Kind::HandshakeMessage, code: 4, summary: "Post-handshake resumption ticket.", status: ImplStatus::Implemented, fips: FipsStatus::Approved, constraints: &[critical("single-use-tickets", "Use each ticket for at most one connection.", "A reused ticket links the two connections for any observer (RFC 8446 §C.4)."), serious("rotate-ticket-keys", "Rotate the server's ticket key before it seals 2^32 tickets.", "Tickets are sealed with AES-256-GCM under random 96-bit nonces, which collide with meaningful probability beyond that.")], edges: &[requires("ext:pre-shared-key"), built("ic:aes-256-gcm")], notes: "Servers issue stateless tickets sealed with AES-256-GCM (iron_socket_layer::resumption::TicketKeys); clients keep them in a TicketStore and hand each out once.", ..Entry::BASE },
    Entry { id: "message:end-of-early-data", name: "EndOfEarlyData", kind: Kind::HandshakeMessage, code: 5, summary: "Ends 0-RTT data.", status: ImplStatus::Implemented, edges: &[requires("ext:early-data")], ..Entry::BASE },
    Entry { id: "message:encrypted-extensions", name: "EncryptedExtensions", kind: Kind::HandshakeMessage, code: 8, summary: "Server extensions that need not be in the clear: ALPN, QUIC transport parameters.", ..Entry::BASE },
    Entry { id: "message:certificate", name: "Certificate", kind: Kind::HandshakeMessage, code: 11, summary: "The sender's certificate chain, leaf first.", ..Entry::BASE },
    Entry { id: "message:certificate-request", name: "CertificateRequest", kind: Kind::HandshakeMessage, code: 13, summary: "The server asks the client to authenticate (mutual TLS).", ..Entry::BASE },
    Entry { id: "message:certificate-verify", name: "CertificateVerify", kind: Kind::HandshakeMessage, code: 15, summary: "A signature over the transcript proving possession of the certificate's key.", constraints: &[critical("context-string", "Sign 64 spaces, the role-specific context string, a zero byte and the transcript hash.", "Omitting the context string lets a server signature be replayed as a client one.")], ..Entry::BASE },
    Entry { id: "message:finished", name: "Finished", kind: Kind::HandshakeMessage, code: 20, summary: "An HMAC over the transcript under the finished key; authenticates the handshake.", constraints: &[critical("constant-time-compare", "Compare the Finished MAC in constant time.", "A timing leak lets an attacker forge the MAC byte by byte.")], ..Entry::BASE },
    Entry { id: "message:key-update", name: "KeyUpdate", kind: Kind::HandshakeMessage, code: 24, summary: "Ratchets a direction's traffic secret; used to stay inside AEAD usage limits.", edges: &[carried("content:handshake")], notes: "Not used under QUIC, which updates keys with the Key Phase bit (RFC 9001 §6).", ..Entry::BASE },
    Entry { id: "message:message-hash", name: "message_hash", kind: Kind::HandshakeMessage, code: 254, summary: "Synthetic message that replaces ClientHello1 in the transcript after a HelloRetryRequest; never sent.", ..Entry::BASE },
    // --- cipher suites --------------------------------------------------------
    Entry {
        id: "suite:tls-aes-128-gcm-sha256",
        name: "TLS_AES_128_GCM_SHA256",
        kind: Kind::CipherSuite,
        code: 0x1301,
        summary: "AES-128-GCM with SHA-256; the mandatory-to-implement suite.",
        fips: FipsStatus::Approved,
        strength: S128,
        standards: &["RFC 8446", "SP 800-38D", "SP 800-52r2"],
        constraints: &[SEQ_NONCE, GCM_LIMIT],
        edges: &[built("ic:aes-128-gcm"), built("ic:hkdf-sha2-256"), built("ic:hmac-sha2-256"), built("ic:sha2-256")],
        notes: "Under QUIC the header-protection key is AES-128 in ECB on a 16-byte sample (RFC 9001 §5.4.3).",
        ..Entry::BASE
    },
    Entry {
        id: "suite:tls-aes-256-gcm-sha384",
        name: "TLS_AES_256_GCM_SHA384",
        kind: Kind::CipherSuite,
        code: 0x1302,
        summary: "AES-256-GCM with SHA-384; retains 128-bit strength against Grover and is the CNSA choice.",
        fips: FipsStatus::Approved,
        strength: S256,
        standards: &["RFC 8446", "SP 800-38D", "SP 800-52r2", "CNSA 1.0"],
        constraints: &[SEQ_NONCE, GCM_LIMIT],
        edges: &[built("ic:aes-256-gcm"), built("ic:hkdf-sha2-384"), built("ic:hmac-sha2-384"), built("ic:sha2-384")],
        ..Entry::BASE
    },
    Entry {
        id: "suite:tls-chacha20-poly1305-sha256",
        name: "TLS_CHACHA20_POLY1305_SHA256",
        kind: Kind::CipherSuite,
        code: 0x1303,
        summary: "ChaCha20-Poly1305 with SHA-256; constant-time and fast without AES hardware.",
        fips: FipsStatus::NotApproved,
        strength: S256,
        standards: &["RFC 8446", "RFC 8439"],
        constraints: &[SEQ_NONCE, NO_CHACHA_FIPS],
        edges: &[built("ic:chacha20-poly1305"), built("ic:hkdf-sha2-256"), built("ic:hmac-sha2-256"), built("ic:sha2-256")],
        ..Entry::BASE
    },
    Entry {
        id: "suite:tls-aes-128-ccm-sha256",
        name: "TLS_AES_128_CCM_SHA256",
        kind: Kind::CipherSuite,
        code: 0x1304,
        summary: "AES-128-CCM with SHA-256, for constrained devices.",
        status: ImplStatus::NamedOnly,
        status_reason: "IronCrypto does not implement CCM; recognised when offered, never selected.",
        fips: FipsStatus::Approved,
        strength: S128,
        standards: &["RFC 8446", "SP 800-38C"],
        ..Entry::BASE
    },
    Entry {
        id: "suite:tls-aes-128-ccm-8-sha256",
        name: "TLS_AES_128_CCM_8_SHA256",
        kind: Kind::CipherSuite,
        code: 0x1305,
        summary: "AES-128-CCM with an 8-byte tag.",
        status: ImplStatus::Excluded,
        status_reason: "A 64-bit tag gives inadequate forgery resistance for general use; RFC 8446 marks it for specialised environments only.",
        fips: FipsStatus::Approved,
        strength: S128,
        standards: &["RFC 8446", "SP 800-38C"],
        ..Entry::BASE
    },
    // --- groups ---------------------------------------------------------------
    Entry {
        id: "group:secp256r1",
        name: "secp256r1",
        kind: Kind::NamedGroup,
        code: 0x0017,
        summary: "ECDHE over NIST P-256.",
        fips: FipsStatus::Approved,
        strength: ECC128,
        standards: &["RFC 8446", "SP 800-56A", "SP 800-186"],
        constraints: &[VALIDATE_SHARE, UNCOMPRESSED_ONLY, ONE_SHOT_EPHEMERAL],
        edges: &[built("ic:ecdh-p256")],
        ..Entry::BASE
    },
    Entry {
        id: "group:secp384r1",
        name: "secp384r1",
        kind: Kind::NamedGroup,
        code: 0x0018,
        summary: "ECDHE over NIST P-384; the CNSA 1.0 group.",
        fips: FipsStatus::Approved,
        strength: ECC192,
        standards: &["RFC 8446", "SP 800-56A", "SP 800-186", "CNSA 1.0"],
        constraints: &[VALIDATE_SHARE, UNCOMPRESSED_ONLY, ONE_SHOT_EPHEMERAL],
        edges: &[built("ic:ecdh-p384")],
        ..Entry::BASE
    },
    Entry {
        id: "group:secp521r1",
        name: "secp521r1",
        kind: Kind::NamedGroup,
        code: 0x0019,
        summary: "ECDHE over NIST P-521.",
        fips: FipsStatus::Approved,
        strength: ECC256,
        standards: &["RFC 8446", "SP 800-56A", "SP 800-186"],
        constraints: &[VALIDATE_SHARE, UNCOMPRESSED_ONLY, ONE_SHOT_EPHEMERAL],
        edges: &[built("ic:ecdh-p521")],
        ..Entry::BASE
    },
    Entry {
        id: "group:x25519",
        name: "x25519",
        kind: Kind::NamedGroup,
        code: 0x001d,
        summary: "ECDHE over Curve25519; the most widely deployed classical group.",
        fips: FipsStatus::NotApproved,
        strength: ECC128,
        standards: &["RFC 8446", "RFC 7748"],
        constraints: &[X25519_ZERO, ONE_SHOT_EPHEMERAL],
        edges: &[built("ic:x25519"), superseded_by("group:x25519mlkem768")],
        ..Entry::BASE
    },
    Entry {
        id: "group:x448",
        name: "x448",
        kind: Kind::NamedGroup,
        code: 0x001e,
        summary: "ECDHE over Curve448.",
        status: ImplStatus::NamedOnly,
        status_reason: "IronCrypto does not implement X448.",
        fips: FipsStatus::NotApproved,
        strength: Strength { classical: 224, quantum: 0 },
        standards: &["RFC 8446", "RFC 7748"],
        ..Entry::BASE
    },
    Entry {
        id: "group:ffdhe2048",
        name: "ffdhe2048",
        kind: Kind::NamedGroup,
        code: 0x0100,
        summary: "Finite-field Diffie-Hellman, 2048-bit group.",
        status: ImplStatus::Excluded,
        status_reason: "Slow, large and weaker than the elliptic-curve groups; nothing modern needs it.",
        fips: FipsStatus::Approved,
        strength: Strength { classical: 112, quantum: 0 },
        standards: &["RFC 7919"],
        ..Entry::BASE
    },
    Entry {
        id: "group:mlkem512",
        name: "MLKEM512",
        kind: Kind::NamedGroup,
        code: 0x0200,
        summary: "Pure ML-KEM-512 key establishment.",
        status: ImplStatus::NamedOnly,
        status_reason: "IronCrypto implements ML-KEM-768 only.",
        fips: FipsStatus::Approved,
        post_quantum: true,
        strength: Strength { classical: 128, quantum: 128 },
        standards: &["draft-ietf-tls-mlkem", "FIPS 203"],
        ..Entry::BASE
    },
    Entry {
        id: "group:mlkem768",
        name: "MLKEM768",
        kind: Kind::NamedGroup,
        code: 0x0201,
        summary: "Pure ML-KEM-768 key establishment, with no classical component.",
        fips: FipsStatus::Approved,
        post_quantum: true,
        strength: PQ_L3,
        standards: &["draft-ietf-tls-mlkem", "FIPS 203"],
        constraints: &[KEM_ENCAPS_CHECK, ONE_SHOT_EPHEMERAL, advisory(
            "prefer-hybrid",
            "Prefer a hybrid group unless a policy requires pure post-quantum.",
            "A hybrid stays secure if either component holds; pure ML-KEM rests on one, younger assumption.",
        )],
        edges: &[built("ic:ml-kem-768")],
        ..Entry::BASE
    },
    Entry {
        id: "group:mlkem1024",
        name: "MLKEM1024",
        kind: Kind::NamedGroup,
        code: 0x0202,
        summary: "Pure ML-KEM-1024; the CNSA 2.0 key establishment.",
        fips: FipsStatus::Approved,
        post_quantum: true,
        strength: Strength { classical: 256, quantum: 256 },
        standards: &["draft-ietf-tls-mlkem", "FIPS 203", "CNSA 2.0"],
        constraints: &[KEM_ENCAPS_CHECK, ONE_SHOT_EPHEMERAL],
        edges: &[built("ic:ml-kem-1024")],
        notes: "Client share: ML-KEM-1024 ek (1568). Server share: ciphertext (1568). Not offered by default: the shares are large. Do not substitute ML-KEM-768 where CNSA 2.0 is required.",
        ..Entry::BASE
    },
    Entry {
        id: "group:secp256r1mlkem768",
        name: "SecP256r1MLKEM768",
        kind: Kind::NamedGroup,
        code: 0x11eb,
        summary: "Hybrid P-256 ECDHE + ML-KEM-768 with both components FIPS-approved.",
        fips: FipsStatus::Approved,
        post_quantum: true,
        strength: HYBRID_128_192,
        standards: &["draft-ietf-tls-ecdhe-mlkem", "FIPS 203", "SP 800-56A", "SP 800-56Cr2"],
        constraints: &[HYBRID_ORDER, VALIDATE_SHARE, KEM_ENCAPS_CHECK, ONE_SHOT_EPHEMERAL],
        edges: &[built("ic:ecdh-p256"), built("ic:ml-kem-768"), pairs("group:secp256r1")],
        notes: "Client share: P-256 point (65) || ML-KEM ek (1184). Server share: P-256 point (65) || ciphertext (1088). Secret: ECDH secret || ML-KEM secret.",
        ..Entry::BASE
    },
    Entry {
        id: "group:x25519mlkem768",
        name: "X25519MLKEM768",
        kind: Kind::NamedGroup,
        code: 0x11ec,
        summary: "Hybrid X25519 + ML-KEM-768; the default post-quantum group on the public Internet.",
        fips: FipsStatus::NotApproved,
        post_quantum: true,
        strength: HYBRID_128_192,
        standards: &["draft-ietf-tls-ecdhe-mlkem", "FIPS 203", "RFC 7748"],
        constraints: &[HYBRID_ORDER, X25519_ZERO, KEM_ENCAPS_CHECK, ONE_SHOT_EPHEMERAL],
        edges: &[built("ic:ml-kem-768"), built("ic:x25519"), supersedes("group:x25519")],
        notes: "Client share: ML-KEM ek (1184) || X25519 (32). Server share: ciphertext (1088) || X25519 (32). Secret: ML-KEM secret || X25519 secret. Because the approved ML-KEM secret comes first, SP 800-56Cr2 can be read to permit this combination in approved mode, treating the X25519 secret as auxiliary input; that is an argument, not an approval, and profile:fips-140-3 does not rely on it.",
        ..Entry::BASE
    },
    Entry {
        id: "group:secp384r1mlkem1024",
        name: "SecP384r1MLKEM1024",
        kind: Kind::NamedGroup,
        code: 0x11ed,
        summary: "Hybrid P-384 ECDHE + ML-KEM-1024 with both components FIPS-approved.",
        fips: FipsStatus::Approved,
        post_quantum: true,
        strength: Strength { classical: 192, quantum: 256 },
        standards: &["draft-ietf-tls-ecdhe-mlkem", "FIPS 203", "SP 800-56A", "SP 800-56Cr2"],
        constraints: &[HYBRID_ORDER, VALIDATE_SHARE, KEM_ENCAPS_CHECK, ONE_SHOT_EPHEMERAL],
        edges: &[built("ic:ecdh-p384"), built("ic:ml-kem-1024"), pairs("group:secp384r1")],
        notes: "Client share: P-384 point (97) || ML-KEM ek (1568). Server share: P-384 point (97) || ciphertext (1568). Secret: ECDH secret || ML-KEM secret. Not offered by default: the shares are large.",
        ..Entry::BASE
    },
    // --- signature schemes ----------------------------------------------------
    Entry {
        id: "sigscheme:rsa-pkcs1-sha1",
        name: "rsa_pkcs1_sha1",
        kind: Kind::SignatureScheme,
        code: 0x0201,
        summary: "RSASSA-PKCS1-v1_5 with SHA-1.",
        status: ImplStatus::Excluded,
        status_reason: "SHA-1 is broken for signatures.",
        fips: FipsStatus::Disallowed,
        constraints: &[SHA1_NEVER],
        ..Entry::BASE
    },
    Entry {
        id: "sigscheme:ecdsa-sha1",
        name: "ecdsa_sha1",
        kind: Kind::SignatureScheme,
        code: 0x0203,
        summary: "ECDSA with SHA-1.",
        status: ImplStatus::Excluded,
        status_reason: "SHA-1 is broken for signatures.",
        fips: FipsStatus::Disallowed,
        constraints: &[SHA1_NEVER],
        ..Entry::BASE
    },
    Entry {
        id: "sigscheme:rsa-pkcs1-sha256",
        name: "rsa_pkcs1_sha256",
        kind: Kind::SignatureScheme,
        code: 0x0401,
        summary: "RSASSA-PKCS1-v1_5 with SHA-256; certificate signatures only.",
        fips: FipsStatus::Approved,
        strength: Strength { classical: 112, quantum: 0 },
        standards: &["RFC 8446", "RFC 8017", "FIPS 186-5"],
        constraints: &[PKCS1_CERT_ONLY, RSA_MIN],
        edges: &[built("ic:rsa-pkcs1-sha256"), carried("ext:signature-algorithms-cert")],
        ..Entry::BASE
    },
    Entry {
        id: "sigscheme:ecdsa-secp256r1-sha256",
        name: "ecdsa_secp256r1_sha256",
        kind: Kind::SignatureScheme,
        code: 0x0403,
        summary: "ECDSA over P-256 with SHA-256.",
        fips: FipsStatus::Approved,
        strength: ECC128,
        standards: &["RFC 8446", "FIPS 186-5"],
        constraints: &[ECDSA_DER],
        edges: &[built("ic:ecdsa-p256-sha256")],
        notes: "IronCrypto derives the nonce per RFC 6979, so ECDSA nonce reuse cannot occur.",
        ..Entry::BASE
    },
    Entry {
        id: "sigscheme:rsa-pkcs1-sha384",
        name: "rsa_pkcs1_sha384",
        kind: Kind::SignatureScheme,
        code: 0x0501,
        summary: "RSASSA-PKCS1-v1_5 with SHA-384; certificate signatures only.",
        fips: FipsStatus::Approved,
        strength: Strength { classical: 112, quantum: 0 },
        standards: &["RFC 8446", "RFC 8017", "FIPS 186-5"],
        constraints: &[PKCS1_CERT_ONLY, RSA_MIN],
        edges: &[built("ic:rsa-pkcs1-sha384"), carried("ext:signature-algorithms-cert")],
        ..Entry::BASE
    },
    Entry {
        id: "sigscheme:ecdsa-secp384r1-sha384",
        name: "ecdsa_secp384r1_sha384",
        kind: Kind::SignatureScheme,
        code: 0x0503,
        summary: "ECDSA over P-384 with SHA-384; the CNSA 1.0 signature.",
        fips: FipsStatus::Approved,
        strength: ECC192,
        standards: &["RFC 8446", "FIPS 186-5", "CNSA 1.0"],
        constraints: &[ECDSA_DER],
        edges: &[built("ic:ecdsa-p384-sha384")],
        ..Entry::BASE
    },
    Entry {
        id: "sigscheme:rsa-pkcs1-sha512",
        name: "rsa_pkcs1_sha512",
        kind: Kind::SignatureScheme,
        code: 0x0601,
        summary: "RSASSA-PKCS1-v1_5 with SHA-512; certificate signatures only.",
        fips: FipsStatus::Approved,
        strength: Strength { classical: 112, quantum: 0 },
        standards: &["RFC 8446", "RFC 8017", "FIPS 186-5"],
        constraints: &[PKCS1_CERT_ONLY, RSA_MIN],
        edges: &[built("ic:rsa-pkcs1-sha512"), carried("ext:signature-algorithms-cert")],
        ..Entry::BASE
    },
    Entry {
        id: "sigscheme:ecdsa-secp521r1-sha512",
        name: "ecdsa_secp521r1_sha512",
        kind: Kind::SignatureScheme,
        code: 0x0603,
        summary: "ECDSA over P-521 with SHA-512.",
        fips: FipsStatus::Approved,
        strength: ECC256,
        standards: &["RFC 8446", "FIPS 186-5"],
        constraints: &[ECDSA_DER],
        edges: &[built("ic:ecdsa-p521-sha512")],
        ..Entry::BASE
    },
    Entry {
        id: "sigscheme:rsa-pss-rsae-sha256",
        name: "rsa_pss_rsae_sha256",
        kind: Kind::SignatureScheme,
        code: 0x0804,
        summary: "RSASSA-PSS with SHA-256 and an rsaEncryption key.",
        fips: FipsStatus::Approved,
        strength: Strength { classical: 112, quantum: 0 },
        standards: &["RFC 8446", "RFC 8017", "FIPS 186-5"],
        constraints: &[PSS_SALT, RSA_MIN],
        edges: &[built("ic:rsa-pss-sha256")],
        ..Entry::BASE
    },
    Entry {
        id: "sigscheme:rsa-pss-rsae-sha384",
        name: "rsa_pss_rsae_sha384",
        kind: Kind::SignatureScheme,
        code: 0x0805,
        summary: "RSASSA-PSS with SHA-384 and an rsaEncryption key.",
        fips: FipsStatus::Approved,
        strength: Strength { classical: 112, quantum: 0 },
        standards: &["RFC 8446", "RFC 8017", "FIPS 186-5"],
        constraints: &[PSS_SALT, RSA_MIN],
        edges: &[built("ic:rsa-pss-sha384")],
        ..Entry::BASE
    },
    Entry {
        id: "sigscheme:rsa-pss-rsae-sha512",
        name: "rsa_pss_rsae_sha512",
        kind: Kind::SignatureScheme,
        code: 0x0806,
        summary: "RSASSA-PSS with SHA-512 and an rsaEncryption key.",
        fips: FipsStatus::Approved,
        strength: Strength { classical: 112, quantum: 0 },
        standards: &["RFC 8446", "RFC 8017", "FIPS 186-5"],
        constraints: &[PSS_SALT, RSA_MIN],
        edges: &[built("ic:rsa-pss-sha512")],
        ..Entry::BASE
    },
    Entry {
        id: "sigscheme:ed25519",
        name: "ed25519",
        kind: Kind::SignatureScheme,
        code: 0x0807,
        summary: "EdDSA over edwards25519; deterministic, small and fast.",
        fips: FipsStatus::NotApproved,
        strength: ECC128,
        standards: &["RFC 8446", "RFC 8032"],
        edges: &[built("ic:ed25519")],
        notes: "Not approved in IronCrypto's registry, which is what IronSocketLayer follows.",
        ..Entry::BASE
    },
    Entry {
        id: "sigscheme:ed448",
        name: "ed448",
        kind: Kind::SignatureScheme,
        code: 0x0808,
        summary: "EdDSA over edwards448.",
        status: ImplStatus::NamedOnly,
        status_reason: "IronCrypto does not implement Ed448.",
        fips: FipsStatus::NotApproved,
        strength: Strength { classical: 224, quantum: 0 },
        standards: &["RFC 8446", "RFC 8032"],
        ..Entry::BASE
    },
    Entry {
        id: "sigscheme:rsa-pss-pss-sha256",
        name: "rsa_pss_pss_sha256",
        kind: Kind::SignatureScheme,
        code: 0x0809,
        summary: "RSASSA-PSS with SHA-256 and an RSASSA-PSS-restricted key.",
        status: ImplStatus::Planned,
        status_reason: "RSASSA-PSS key parameters in certificates are not parsed yet.",
        fips: FipsStatus::Approved,
        strength: Strength { classical: 112, quantum: 0 },
        standards: &["RFC 8446", "RFC 4055"],
        ..Entry::BASE
    },
    Entry {
        id: "sigscheme:mldsa44",
        name: "mldsa44",
        kind: Kind::SignatureScheme,
        code: 0x0904,
        summary: "ML-DSA-44 (FIPS 204, category 2).",
        status: ImplStatus::NamedOnly,
        status_reason: "IronCrypto implements ML-DSA-65 only.",
        fips: FipsStatus::Approved,
        post_quantum: true,
        strength: Strength { classical: 128, quantum: 128 },
        standards: &["draft-ietf-tls-mldsa", "FIPS 204"],
        ..Entry::BASE
    },
    Entry {
        id: "sigscheme:mldsa65",
        name: "mldsa65",
        kind: Kind::SignatureScheme,
        code: 0x0905,
        summary: "ML-DSA-65 (FIPS 204, category 3); post-quantum handshake and certificate signatures.",
        fips: FipsStatus::Approved,
        post_quantum: true,
        strength: PQ_L3,
        standards: &["draft-ietf-tls-mldsa", "FIPS 204", "draft-ietf-lamps-dilithium-certificates"],
        constraints: &[MLDSA_CTX, advisory(
            "size",
            "Budget for 3309-byte signatures and 1952-byte public keys.",
            "Chains of ML-DSA certificates can exceed the QUIC anti-amplification budget and add round trips.",
        )],
        edges: &[built("ic:ml-dsa-65")],
        ..Entry::BASE
    },
    Entry {
        id: "sigscheme:mldsa87",
        name: "mldsa87",
        kind: Kind::SignatureScheme,
        code: 0x0906,
        summary: "ML-DSA-87 (FIPS 204, category 5); the CNSA 2.0 signature.",
        status: ImplStatus::NamedOnly,
        status_reason: "IronCrypto does not implement ML-DSA-87. Do not substitute ML-DSA-65 where CNSA 2.0 is required.",
        fips: FipsStatus::Approved,
        post_quantum: true,
        strength: Strength { classical: 256, quantum: 256 },
        standards: &["draft-ietf-tls-mldsa", "FIPS 204", "CNSA 2.0"],
        ..Entry::BASE
    },
    // --- extensions -----------------------------------------------------------
    Entry { id: "ext:server-name", name: "server_name", kind: Kind::Extension, code: 0, summary: "Server Name Indication: the host name the client wants.", standards: &["RFC 6066"], constraints: &[serious("always-send-for-hostnames", "Send SNI whenever connecting to a DNS name, and verify the certificate against that same name.", "Without it virtual-hosted servers return the wrong certificate; without the name check any certificate for any host is accepted.")], ..Entry::BASE },
    Entry { id: "ext:max-fragment-length", name: "max_fragment_length", kind: Kind::Extension, code: 1, summary: "Negotiates a smaller maximum record size.", status: ImplStatus::Excluded, status_reason: "Superseded by record_size_limit (RFC 8449), which is implemented.", standards: &["RFC 6066"], edges: &[superseded_by("ext:record-size-limit")], ..Entry::BASE },
    Entry { id: "ext:status-request", name: "status_request", kind: Kind::Extension, code: 5, summary: "OCSP stapling.", status: ImplStatus::Implemented, standards: &["RFC 6066", "RFC 6960", "RFC 8446"], constraints: &[critical("revoked-is-fatal", "Abort with certificate_revoked when a valid staple says the certificate is revoked.", "Continuing talks to a peer whose key its issuer has disowned."), critical("staple-from-issuer", "Accept a staple only if the issuer, or a responder the issuer certified with id-kp-OCSPSigning, signed it.", "Anyone else could vouch for a revoked certificate."), serious("staple-must-be-current", "Refuse staples whose nextUpdate has passed (five minutes of skew allowed).", "A stale good response can outlive a revocation."), advisory("sha1-certid", "SHA-1 CertIDs are matched by serial number, with the issuer bound by the signature, because IronCrypto has no SHA-1.", "SHA-256 CertIDs are checked in full.")], notes: "Client policy: Revocation::{Off, IfStapled (default), RequireStaple}. Servers staple a DER response set on Identity::with_ocsp; x509::ocsp::build_response mints one for a private CA. CRLs complement it: Common::crls with x509::crl::CrlStore, checked along the whole path on both sides; x509::crl::build issues one.", ..Entry::BASE },
    Entry { id: "ext:supported-groups", name: "supported_groups", kind: Kind::Extension, code: 10, summary: "Key-exchange groups the client supports, most preferred first.", constraints: &[UNKNOWN_EXT_IGNORE], ..Entry::BASE },
    Entry { id: "ext:signature-algorithms", name: "signature_algorithms", kind: Kind::Extension, code: 13, summary: "Signature schemes the sender accepts in CertificateVerify (and certificates, absent signature_algorithms_cert).", ..Entry::BASE },
    Entry { id: "ext:alpn", name: "application_layer_protocol_negotiation", kind: Kind::Extension, code: 16, summary: "Application protocol negotiation (h2, http/1.1, h3, mcp).", standards: &["RFC 7301"], constraints: &[serious("fail-closed", "If both sides configure ALPN and share no protocol, abort with no_application_protocol.", "Silently falling back lets a peer speak an unexpected protocol over an authenticated channel.")], ..Entry::BASE },
    Entry { id: "ext:signed-certificate-timestamp", name: "signed_certificate_timestamp", kind: Kind::Extension, code: 18, summary: "Certificate Transparency timestamps.", status: ImplStatus::Planned, status_reason: "CT verification is planned.", standards: &["RFC 6962"], ..Entry::BASE },
    Entry { id: "ext:padding", name: "padding", kind: Kind::Extension, code: 21, summary: "ClientHello padding for broken middleboxes.", status: ImplStatus::NamedOnly, status_reason: "Not needed by TLS 1.3 ClientHellos this stack produces.", standards: &["RFC 7685"], ..Entry::BASE },
    Entry { id: "ext:record-size-limit", name: "record_size_limit", kind: Kind::Extension, code: 28, summary: "Advertises the largest record the endpoint will accept; useful on constrained devices.", status: ImplStatus::Implemented, constraints: &[critical("minimum-64", "Refuse a limit below 64 with illegal_parameter.", "RFC 8449 §4."), serious("enforce-only-when-negotiated", "Apply limits only when both endpoints sent the extension, and never under QUIC.", "An unnegotiated limit rejects conforming records.")], notes: "Set Common::record_size_limit (64..=16385). Counts the TLSInnerPlaintext: content, type byte and padding.", standards: &["RFC 8449"], edges: &[supersedes("ext:max-fragment-length")], ..Entry::BASE },
    Entry { id: "ext:pre-shared-key", name: "pre_shared_key", kind: Kind::Extension, code: 41, summary: "PSK identities and binders for resumption and external PSKs.", status: ImplStatus::Implemented, constraints: &[critical("last-extension", "pre_shared_key must be the last extension in ClientHello.", "RFC 8446 §4.2.11: binders are computed over the truncated hello; anything after them is unauthenticated."), critical("verify-binder-before-use", "Verify the binder of the chosen PSK before using it, and abort with decrypt_error if it fails.", "An unverified PSK lets an attacker who replays a ticket steer the key schedule."), serious("bind-ticket-to-name", "Resume only for the server name, hash and client-authentication status the ticket was issued under.", "A ticket from one virtual host or one unauthenticated session otherwise grants another's standing.")], notes: "Resumption tickets, and external PSKs (config::ExternalPsk, 32 to 64 bytes, bound to one hash, binder label \"ext binder\"; psk_dhe_ke only, so a fresh key exchange always runs). With an external PSK and no trust anchors the client refuses any handshake that does not use the PSK.", ..Entry::BASE },
    Entry { id: "ext:early-data", name: "early_data", kind: Kind::Extension, code: 42, summary: "Indicates 0-RTT data.", status: ImplStatus::Implemented, constraints: &[ZERO_RTT_REPLAY, critical("single-use-and-fresh", "Accept early data only on the server's own ticket, for the first PSK identity, with the same suite and ALPN, within the ticket-age window, and never twice (a replay guard keyed on the binder).", "Each missing check is a way to replay, or to steer, data the server acts on before the handshake completes."), serious("opt-in-only", "Send early data only when the application supplied it for that purpose and configured ClientConfig::early_data.", "Early data travels without forward secrecy.")], edges: &[requires("ext:pre-shared-key")], notes: "TLS over TCP and QUIC. Under QUIC the ticket carries max_early_data_size 0xffffffff, the 0-RTT keys are handed to the QUIC stack (QuicConnection::client_with_early_data, Level::Early), and the server refuses 0-RTT if its transport parameters changed since the ticket. Server: ServerConfig::early_data = Some(EarlyDataPolicy::new(max)). Client: ClientConfig::early_data = true and Connection::client_with_early_data; rejected data is returned by take_rejected_early_data, never resent automatically.", ..Entry::BASE },
    Entry { id: "ext:supported-versions", name: "supported_versions", kind: Kind::Extension, code: 43, summary: "The real version negotiation mechanism of TLS 1.3.", constraints: &[critical("required", "Abort if a ServerHello lacks supported_versions selecting 0x0304.", "Its absence means the peer negotiated TLS 1.2 or lower, which this stack refuses.")], ..Entry::BASE },
    Entry { id: "ext:cookie", name: "cookie", kind: Kind::Extension, code: 44, summary: "Server state echoed by the client after HelloRetryRequest.", ..Entry::BASE },
    Entry { id: "ext:psk-key-exchange-modes", name: "psk_key_exchange_modes", kind: Kind::Extension, code: 45, summary: "Which PSK modes (psk_ke, psk_dhe_ke) the client supports.", status: ImplStatus::Implemented, constraints: &[critical("psk-dhe-ke-only", "Offer and accept psk_dhe_ke only, never psk_ke.", "psk_ke resumes without a fresh key exchange: no forward secrecy, and no post-quantum protection for the resumed session.")], edges: &[pairs("ext:pre-shared-key")], ..Entry::BASE },
    Entry { id: "ext:certificate-authorities", name: "certificate_authorities", kind: Kind::Extension, code: 47, summary: "Distinguished names of acceptable CAs.", status: ImplStatus::Planned, status_reason: "Useful for selecting client certificates; planned.", ..Entry::BASE },
    Entry { id: "ext:oid-filters", name: "oid_filters", kind: Kind::Extension, code: 48, summary: "Certificate extension constraints in CertificateRequest.", status: ImplStatus::NamedOnly, status_reason: "Rarely deployed.", ..Entry::BASE },
    Entry { id: "ext:post-handshake-auth", name: "post_handshake_auth", kind: Kind::Extension, code: 49, summary: "Client willingness to authenticate after the handshake.", status: ImplStatus::Implemented, standards: &["RFC 8446"], constraints: &[critical("never-over-quic", "Do not offer or use post-handshake authentication over QUIC.", "RFC 9001 §4.4 forbids it; QUIC has no record layer to carry it."), serious("step-up-before-privilege", "Request the client certificate before a privileged operation, and authorise the operation only after it verifies.", "Authentication that arrives after the privileged action protects nothing."), advisory("declined-is-unauthenticated", "Treat a declined request (an empty Certificate) as no authentication.", "The session continues; the report does not gain mutual-authentication.")], notes: "Client: ClientConfig::post_handshake_auth with an identity. Server: ClientAuth::OnDemand(verification) and Connection::request_client_auth(); the answer is verified as it arrives, CRLs included.", ..Entry::BASE },
    Entry { id: "ext:signature-algorithms-cert", name: "signature_algorithms_cert", kind: Kind::Extension, code: 50, summary: "Signature schemes accepted in certificates, when different from CertificateVerify.", ..Entry::BASE },
    Entry { id: "ext:key-share", name: "key_share", kind: Kind::Extension, code: 51, summary: "Ephemeral key-exchange shares.", constraints: &[VALIDATE_SHARE, critical("one-share-per-group", "Reject a ClientHello with two shares for the same group, or a server share for a group the client did not offer.", "RFC 8446 §4.2.8: either is illegal_parameter and signals a confused or hostile peer.")], ..Entry::BASE },
    Entry { id: "ext:quic-transport-parameters", name: "quic_transport_parameters", kind: Kind::Extension, code: 57, summary: "QUIC transport parameters, carried in ClientHello and EncryptedExtensions.", standards: &["RFC 9001", "RFC 9000"], constraints: &[critical("required-under-quic", "Abort with missing_extension if a QUIC peer omits it; never send it over TCP.", "RFC 9001 §8.2.")], ..Entry::BASE },
    Entry { id: "ext:encrypted-client-hello", name: "encrypted_client_hello", kind: Kind::Extension, code: 0xfe0d, summary: "Encrypts the inner ClientHello, hiding SNI from the network.", status: ImplStatus::Implemented, standards: &["draft-ietf-tls-esni", "RFC 9180"], constraints: &[critical("never-fall-back-to-plaintext-sni", "If ECH is configured and cannot be used, fail; never send the real name in the clear instead.", "A silent fallback reveals exactly what ECH was meant to hide, to an observer who can simply block ECH."), critical("abort-on-rejection", "When the server does not confirm ECH, authenticate it as the public name, then abort with ech_required and retry with its retry_configs.", "Continuing would send the application's data to the public-name server."), serious("fetch-configs-authentically", "Obtain the ECHConfigList over an authenticated channel (DNS-over-HTTPS or DNSSEC).", "An attacker who substitutes the configuration can decrypt the inner hello.")], notes: "Client: set ClientConfig::ech_configs to the ECHConfigList from the host's DNS HTTPS record (isl probe --ech fetches it over DNS-over-HTTPS). Server: ServerConfig::ech with ech::EchServer. HPKE: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128/256-GCM and ChaCha20-Poly1305. The inner hello carries no resumption PSK.", edges: &[built("ic:x25519"), built("ic:hkdf-sha2-256")], ..Entry::BASE },
    Entry { id: "ext:ech-outer-extensions", name: "ech_outer_extensions", kind: Kind::Extension, code: 0xfd00, summary: "Inside an encoded inner ClientHello, refers to extensions copied from the outer one.", status: ImplStatus::Implemented, standards: &["draft-ietf-tls-esni"], constraints: &[critical("references-must-resolve", "Every referenced extension must appear in the outer hello, in order, and never encrypted_client_hello itself.", "Otherwise the server's reconstructed inner hello differs from the client's, or loops.")], notes: "The server expands references; this client does not compress.", edges: &[pairs("ext:encrypted-client-hello")], ..Entry::BASE },
    // --- alerts ---------------------------------------------------------------
    Entry { id: "alert:close-notify", name: "close_notify", kind: Kind::Alert, code: 0, summary: "Orderly closure; data after it is not accepted.", constraints: &[serious("detect-truncation", "Treat end of stream without close_notify as a possible truncation attack.", "An attacker can cut a response short and the application will not know.")], ..Entry::BASE },
    Entry { id: "alert:unexpected-message", name: "unexpected_message", kind: Kind::Alert, code: 10, summary: "A message arrived that the state machine does not permit.", ..Entry::BASE },
    Entry { id: "alert:bad-record-mac", name: "bad_record_mac", kind: Kind::Alert, code: 20, summary: "A record failed authenticated decryption.", ..Entry::BASE },
    Entry { id: "alert:record-overflow", name: "record_overflow", kind: Kind::Alert, code: 22, summary: "A record exceeded the permitted size.", ..Entry::BASE },
    Entry { id: "alert:handshake-failure", name: "handshake_failure", kind: Kind::Alert, code: 40, summary: "No acceptable set of parameters.", ..Entry::BASE },
    Entry { id: "alert:bad-certificate", name: "bad_certificate", kind: Kind::Alert, code: 42, summary: "A certificate was corrupt, mis-signed, or unusable for this purpose.", ..Entry::BASE },
    Entry { id: "alert:unsupported-certificate", name: "unsupported_certificate", kind: Kind::Alert, code: 43, summary: "A certificate of an unsupported type or algorithm.", ..Entry::BASE },
    Entry { id: "alert:certificate-revoked", name: "certificate_revoked", kind: Kind::Alert, code: 44, summary: "A certificate was revoked by its signer.", ..Entry::BASE },
    Entry { id: "alert:certificate-expired", name: "certificate_expired", kind: Kind::Alert, code: 45, summary: "A certificate was outside its validity period.", ..Entry::BASE },
    Entry { id: "alert:certificate-unknown", name: "certificate_unknown", kind: Kind::Alert, code: 46, summary: "Some other certificate problem.", ..Entry::BASE },
    Entry { id: "alert:illegal-parameter", name: "illegal_parameter", kind: Kind::Alert, code: 47, summary: "A field was out of range or inconsistent.", ..Entry::BASE },
    Entry { id: "alert:unknown-ca", name: "unknown_ca", kind: Kind::Alert, code: 48, summary: "The chain did not lead to a trusted anchor.", ..Entry::BASE },
    Entry { id: "alert:access-denied", name: "access_denied", kind: Kind::Alert, code: 49, summary: "Access control refused the authenticated peer.", ..Entry::BASE },
    Entry { id: "alert:decode-error", name: "decode_error", kind: Kind::Alert, code: 50, summary: "A message could not be decoded.", ..Entry::BASE },
    Entry { id: "alert:decrypt-error", name: "decrypt_error", kind: Kind::Alert, code: 51, summary: "A handshake signature or Finished MAC failed.", ..Entry::BASE },
    Entry { id: "alert:protocol-version", name: "protocol_version", kind: Kind::Alert, code: 70, summary: "The peer offered no acceptable protocol version.", ..Entry::BASE },
    Entry { id: "alert:insufficient-security", name: "insufficient_security", kind: Kind::Alert, code: 71, summary: "Parameters were valid TLS but below local policy.", ..Entry::BASE },
    Entry { id: "alert:internal-error", name: "internal_error", kind: Kind::Alert, code: 80, summary: "A failure unrelated to the peer.", ..Entry::BASE },
    Entry { id: "alert:inappropriate-fallback", name: "inappropriate_fallback", kind: Kind::Alert, code: 86, summary: "A downgrade retry was detected.", ..Entry::BASE },
    Entry { id: "alert:user-canceled", name: "user_canceled", kind: Kind::Alert, code: 90, summary: "The user cancelled the handshake.", ..Entry::BASE },
    Entry { id: "alert:missing-extension", name: "missing_extension", kind: Kind::Alert, code: 109, summary: "A mandatory extension was absent.", ..Entry::BASE },
    Entry { id: "alert:unsupported-extension", name: "unsupported_extension", kind: Kind::Alert, code: 110, summary: "An extension appeared where it is not permitted.", ..Entry::BASE },
    Entry { id: "alert:unrecognized-name", name: "unrecognized_name", kind: Kind::Alert, code: 112, summary: "No certificate for the requested server name.", ..Entry::BASE },
    Entry { id: "alert:bad-certificate-status-response", name: "bad_certificate_status_response", kind: Kind::Alert, code: 113, summary: "An invalid OCSP response.", ..Entry::BASE },
    Entry { id: "alert:unknown-psk-identity", name: "unknown_psk_identity", kind: Kind::Alert, code: 115, summary: "An unknown PSK identity.", ..Entry::BASE },
    Entry { id: "alert:certificate-required", name: "certificate_required", kind: Kind::Alert, code: 116, summary: "A client certificate was required and not sent.", ..Entry::BASE },
    Entry { id: "alert:no-application-protocol", name: "no_application_protocol", kind: Kind::Alert, code: 120, summary: "No mutually supported application protocol.", ..Entry::BASE },
    Entry { id: "alert:ech-required", name: "ech_required", kind: Kind::Alert, code: 121, summary: "The client offered ECH, the server did not accept it, and the client will retry with the server's retry configurations.", standards: &["draft-ietf-tls-esni"], ..Entry::BASE },
    // --- key update -----------------------------------------------------------
    Entry { id: "key-update:not-requested", name: "update_not_requested", kind: Kind::KeyUpdateRequest, code: 0, summary: "The sender updated its key; the receiver need not respond.", edges: &[carried("message:key-update")], ..Entry::BASE },
    Entry { id: "key-update:requested", name: "update_requested", kind: Kind::KeyUpdateRequest, code: 1, summary: "The receiver must send its own KeyUpdate before more application data.", edges: &[carried("message:key-update")], constraints: &[serious("respond-once", "Answer with update_not_requested, never with update_requested.", "Answering a request with a request loops forever.")], ..Entry::BASE },
];
