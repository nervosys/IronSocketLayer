//! What a connection negotiated and guarantees, as data.
//!
//! An agent should not have to infer from a successful `connect` what it just
//! got. [`SessionReport`] states it: the version, suite, group and schemes by
//! ontology id; which security properties hold (`property:*`); the FIPS
//! service indicators; the peer's chain; and an audit trail of typed events.
//! [`SessionReport::to_json`] renders it with stable camelCase keys, so an
//! agent or a policy engine can assert on it directly.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write as _;

use crate::enums::{AlertDescription, CipherSuite, NamedGroup, ProtocolVersion, SignatureScheme};
use crate::policy::Indicators;

/// Which end of the connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Side {
    /// Initiator.
    Client,
    /// Responder.
    Server,
}

impl Side {
    /// Stable identifier.
    pub const fn id(self) -> &'static str {
        match self {
            Self::Client => "side:client",
            Self::Server => "side:server",
        }
    }
}

/// A security property a session may provide. Each is a `property:*`
/// ontology entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Property {
    /// Confidentiality and integrity of application data.
    Confidentiality,
    /// Compromise of long-term keys does not expose past sessions.
    ForwardSecrecy,
    /// Key exchange resists a future quantum adversary.
    PostQuantumKeyExchange,
    /// Peer authentication resists a quantum adversary (ML-DSA).
    PostQuantumAuthentication,
    /// The server proved possession of a verified certificate key.
    ServerAuthenticated,
    /// The client also proved possession of a verified certificate key.
    MutualAuthentication,
    /// Every algorithm used was approved by the FIPS module (not validation).
    FipsApprovedAlgorithms,
    /// The peer's identity was fixed in advance by public-key pinning.
    PinnedPeer,
    /// A current, signed OCSP response said the peer's certificate is good.
    RevocationChecked,
    /// The server name and ClientHello extensions travelled encrypted (ECH).
    EncryptedClientHello,
    /// Both ends proved possession of an external pre-shared key; no
    /// certificate was involved.
    PskAuthenticated,
}

impl Property {
    /// Stable identifier.
    pub const fn id(self) -> &'static str {
        match self {
            Self::Confidentiality => "property:confidentiality",
            Self::ForwardSecrecy => "property:forward-secrecy",
            Self::PostQuantumKeyExchange => "property:post-quantum-key-exchange",
            Self::PostQuantumAuthentication => "property:post-quantum-authentication",
            Self::ServerAuthenticated => "property:server-authenticated",
            Self::MutualAuthentication => "property:mutual-authentication",
            Self::FipsApprovedAlgorithms => "property:fips-approved-algorithms",
            Self::PinnedPeer => "property:pinned-peer",
            Self::RevocationChecked => "property:revocation-checked",
            Self::EncryptedClientHello => "property:encrypted-client-hello",
            Self::PskAuthenticated => "property:psk-authenticated",
        }
    }

    /// Every property.
    pub const ALL: &'static [Property] = &[
        Self::Confidentiality,
        Self::ForwardSecrecy,
        Self::PostQuantumKeyExchange,
        Self::PostQuantumAuthentication,
        Self::ServerAuthenticated,
        Self::MutualAuthentication,
        Self::FipsApprovedAlgorithms,
        Self::PinnedPeer,
        Self::RevocationChecked,
        Self::EncryptedClientHello,
        Self::PskAuthenticated,
    ];
}

/// One entry in the audit trail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    /// `event:*` identifier.
    pub id: &'static str,
    /// Optional detail (an ontology id, a count, a name).
    pub detail: String,
}

/// Handshake state, by ontology identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum HandshakeState {
    /// Client: nothing sent yet.
    Start,
    /// Client: ClientHello sent.
    WaitServerHello,
    /// Client: handshake keys installed.
    WaitEncryptedExtensions,
    /// Client: expecting CertificateRequest or Certificate.
    WaitCertificateRequest,
    /// Expecting the peer's Certificate.
    WaitCertificate,
    /// Expecting the peer's CertificateVerify.
    WaitCertificateVerify,
    /// Expecting the peer's Finished.
    WaitFinished,
    /// Server: expecting ClientHello.
    WaitClientHello,
    /// Handshake complete; application data flows.
    Connected,
    /// Closed cleanly.
    Closed,
    /// Failed; the report carries the error.
    Failed,
}

impl HandshakeState {
    /// Stable identifier.
    pub const fn id(self) -> &'static str {
        match self {
            Self::Start => "state:start",
            Self::WaitServerHello => "state:wait-server-hello",
            Self::WaitEncryptedExtensions => "state:wait-encrypted-extensions",
            Self::WaitCertificateRequest => "state:wait-certificate-request",
            Self::WaitCertificate => "state:wait-certificate",
            Self::WaitCertificateVerify => "state:wait-certificate-verify",
            Self::WaitFinished => "state:wait-finished",
            Self::WaitClientHello => "state:wait-client-hello",
            Self::Connected => "state:connected",
            Self::Closed => "state:closed",
            Self::Failed => "state:failed",
        }
    }

    /// Every state.
    pub const ALL: &'static [HandshakeState] = &[
        Self::Start,
        Self::WaitServerHello,
        Self::WaitEncryptedExtensions,
        Self::WaitCertificateRequest,
        Self::WaitCertificate,
        Self::WaitCertificateVerify,
        Self::WaitFinished,
        Self::WaitClientHello,
        Self::Connected,
        Self::Closed,
        Self::Failed,
    ];
}

/// The negotiated parameters and guarantees of a session.
#[derive(Debug, Clone, Default)]
pub struct SessionReport {
    /// Which side produced this report.
    pub side: Option<Side>,
    /// Transport: `transport:tls-over-tcp` or `transport:quic`.
    pub transport: &'static str,
    /// Profile id.
    pub profile: &'static str,
    /// Handshake state.
    pub state: Option<HandshakeState>,
    /// Negotiated version.
    pub version: Option<ProtocolVersion>,
    /// Negotiated suite.
    pub suite: Option<CipherSuite>,
    /// Negotiated group.
    pub group: Option<NamedGroup>,
    /// Scheme the peer signed CertificateVerify with.
    pub peer_signature_scheme: Option<SignatureScheme>,
    /// Scheme this endpoint signed with.
    pub local_signature_scheme: Option<SignatureScheme>,
    /// Selected ALPN protocol.
    pub alpn: Option<Vec<u8>>,
    /// Server name (SNI) requested or received.
    pub server_name: Option<String>,
    /// Whether a HelloRetryRequest occurred.
    pub hello_retry: bool,
    /// Whether the session was resumed from a ticket (PSK with (EC)DHE).
    pub resumed: bool,
    /// 0-RTT: `early-data:accepted`, `early-data:rejected` or
    /// `early-data:not-offered`. Accepted early data was replayable.
    pub early_data: &'static str,
    /// Revocation status of the peer certificate: `revocation:good`,
    /// `revocation:unknown`, or `revocation:not-checked`.
    pub revocation: &'static str,
    /// Encrypted Client Hello: `ech:accepted`, `ech:rejected` or
    /// `ech:not-offered`.
    pub ech: &'static str,
    /// Peer verification method id.
    pub verification: &'static str,
    /// Peer end-entity key kind.
    pub peer_key: Option<&'static str>,
    /// Peer end-entity subject common name (informational only).
    pub peer_subject_cn: Option<String>,
    /// The names the peer's end-entity certificate was issued for: its
    /// subject alternative dNSNames, then its iPAddresses as text. These are
    /// the names a validated path vouches for; authorize on these, not on
    /// the common name. Empty for external-PSK sessions. REQ-RPT-003.
    pub peer_names: Vec<String>,
    /// The safe defaults the configuration gave up for this session, by
    /// id; empty when it gave up none. REQ-CFG-006.
    pub relaxations: Vec<crate::config::Relaxation>,
    /// Peer end-entity `notAfter`, Unix seconds.
    pub peer_not_after: Option<u64>,
    /// Certificates the peer sent.
    pub peer_chain_len: usize,
    /// Weakest classical strength along the verified chain, in bits.
    pub peer_chain_min_bits: Option<u16>,
    /// Properties that hold.
    pub properties: Vec<Property>,
    /// Whether a FIPS profile was enforced.
    pub fips_enforced: bool,
    /// FIPS service indicators for the negotiated algorithms.
    pub fips_indicators: Indicators,
    /// KeyUpdates sent / received.
    pub key_updates_sent: u32,
    /// KeyUpdates received.
    pub key_updates_received: u32,
    /// Session tickets received (resumption is planned, tickets are counted).
    pub tickets_received: u32,
    /// Application bytes sent.
    pub bytes_sent: u64,
    /// Application bytes received.
    pub bytes_received: u64,
    /// Error id, if the session failed.
    pub error: Option<&'static str>,
    /// Error context.
    pub error_context: Option<&'static str>,
    /// Alert sent to the peer.
    pub alert_sent: Option<AlertDescription>,
    /// Alert received from the peer.
    pub alert_received: Option<AlertDescription>,
    /// Audit trail.
    pub events: Vec<Event>,
}

impl SessionReport {
    /// Whether `p` holds.
    pub fn has(&self, p: Property) -> bool {
        self.properties.contains(&p)
    }

    /// `REQ-RPT-002`: the trail keeps the first 256 events, and an event
    /// without detail serializes without a detail member.
    pub(crate) fn event(&mut self, id: &'static str, detail: &str) {
        // Bounded: a hostile peer must not grow the trail without limit.
        if self.events.len() < 256 {
            self.events.push(Event {
                id,
                detail: String::from(detail),
            });
        }
    }

    pub(crate) fn add(&mut self, p: Property) {
        if !self.properties.contains(&p) {
            self.properties.push(p);
        }
    }

    /// Render as JSON with stable camelCase keys.
    pub fn to_json(&self) -> String {
        let mut o = JsonObject::new();
        o.str_opt("side", self.side.map(|s| s.id()));
        o.str("transport", self.transport);
        o.str("profile", self.profile);
        o.str_opt("state", self.state.map(|s| s.id()));
        o.str_opt("version", self.version.map(|v| v.id()));
        o.str_opt("cipherSuite", self.suite.map(|v| v.id()));
        o.str_opt("keyExchangeGroup", self.group.map(|v| v.id()));
        o.str_opt(
            "peerSignatureScheme",
            self.peer_signature_scheme.map(|v| v.id()),
        );
        o.str_opt(
            "localSignatureScheme",
            self.local_signature_scheme.map(|v| v.id()),
        );
        let alpn = self
            .alpn
            .as_ref()
            .map(|a| String::from_utf8_lossy(a).into_owned());
        o.str_opt("alpn", alpn.as_deref());
        o.str_opt("serverName", self.server_name.as_deref());
        o.bool("helloRetry", self.hello_retry);
        o.bool("resumed", self.resumed);
        o.str(
            "earlyData",
            if self.early_data.is_empty() {
                "early-data:not-offered"
            } else {
                self.early_data
            },
        );
        o.str(
            "ech",
            if self.ech.is_empty() {
                "ech:not-offered"
            } else {
                self.ech
            },
        );
        o.str(
            "revocation",
            if self.revocation.is_empty() {
                "revocation:not-checked"
            } else {
                self.revocation
            },
        );
        o.str("verification", self.verification);
        o.str_opt("peerKey", self.peer_key);
        o.str_opt("peerSubjectCommonName", self.peer_subject_cn.as_deref());
        o.raw(
            "peerNames",
            &json_str_array(self.peer_names.iter().map(String::as_str)),
        );
        o.raw(
            "relaxations",
            &json_str_array(self.relaxations.iter().map(|r| r.id())),
        );
        o.num_opt("peerNotAfter", self.peer_not_after);
        o.num("peerChainLength", self.peer_chain_len as u64);
        o.num_opt(
            "peerChainMinClassicalBits",
            self.peer_chain_min_bits.map(u64::from),
        );
        o.raw(
            "properties",
            &json_str_array(self.properties.iter().map(|p| p.id())),
        );
        let mut fips = JsonObject::new();
        fips.bool("enforced", self.fips_enforced);
        fips.bool("allApproved", self.fips_indicators.all_approved());
        fips.bool("validated", false);
        let mut ind = String::from("[");
        for (i, (alg, indicator)) in self.fips_indicators.entries.iter().enumerate() {
            if i > 0 {
                ind.push(',');
            }
            let mut e = JsonObject::new();
            e.str("algorithm", &alloc::format!("ic:{alg}"));
            e.str("indicator", indicator);
            ind.push_str(&e.finish());
        }
        ind.push(']');
        fips.raw("indicators", &ind);
        o.raw("fips", &fips.finish());
        o.num("keyUpdatesSent", u64::from(self.key_updates_sent));
        o.num("keyUpdatesReceived", u64::from(self.key_updates_received));
        o.num("ticketsReceived", u64::from(self.tickets_received));
        o.num("bytesSent", self.bytes_sent);
        o.num("bytesReceived", self.bytes_received);
        o.str_opt("error", self.error);
        o.str_opt("errorContext", self.error_context);
        o.str_opt("alertSent", self.alert_sent.map(|a| a.id()));
        o.str_opt("alertReceived", self.alert_received.map(|a| a.id()));
        let mut ev = String::from("[");
        for (i, e) in self.events.iter().enumerate() {
            if i > 0 {
                ev.push(',');
            }
            let mut x = JsonObject::new();
            x.str("event", e.id);
            if !e.detail.is_empty() {
                x.str("detail", &e.detail);
            }
            ev.push_str(&x.finish());
        }
        ev.push(']');
        o.raw("events", &ev);
        o.finish()
    }
}

/// Escape a string as a JSON string literal.
pub fn json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn json_str_array<'a>(items: impl Iterator<Item = &'a str>) -> String {
    let mut s = String::from("[");
    for (i, it) in items.enumerate() {
        if i > 0 {
            s.push(',');
        }
        s.push_str(&json_string(it));
    }
    s.push(']');
    s
}

/// A minimal JSON object writer (no_std).
pub struct JsonObject {
    buf: String,
    first: bool,
}

impl Default for JsonObject {
    fn default() -> Self {
        Self::new()
    }
}

impl JsonObject {
    /// Start an object.
    pub fn new() -> Self {
        Self {
            buf: String::from("{"),
            first: true,
        }
    }

    fn key(&mut self, k: &str) {
        if !self.first {
            self.buf.push(',');
        }
        self.first = false;
        self.buf.push_str(&json_string(k));
        self.buf.push(':');
    }

    /// A string field.
    pub fn str(&mut self, k: &str, v: &str) {
        self.key(k);
        self.buf.push_str(&json_string(v));
    }

    /// A string or null.
    pub fn str_opt(&mut self, k: &str, v: Option<&str>) {
        match v {
            Some(v) => self.str(k, v),
            None => self.raw(k, "null"),
        }
    }

    /// A boolean.
    pub fn bool(&mut self, k: &str, v: bool) {
        self.raw(k, if v { "true" } else { "false" });
    }

    /// A number.
    pub fn num(&mut self, k: &str, v: u64) {
        self.key(k);
        let _ = write!(self.buf, "{v}");
    }

    /// A number or null.
    pub fn num_opt(&mut self, k: &str, v: Option<u64>) {
        match v {
            Some(v) => self.num(k, v),
            None => self.raw(k, "null"),
        }
    }

    /// Pre-rendered JSON.
    pub fn raw(&mut self, k: &str, json: &str) {
        self.key(k);
        self.buf.push_str(json);
    }

    /// Close and return.
    pub fn finish(mut self) -> String {
        self.buf.push('}');
        self.buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_escapes_and_nulls() {
        let mut r = SessionReport {
            transport: "transport:tls-over-tcp",
            profile: "profile:default",
            ..Default::default()
        };
        r.server_name = Some("a\"b\n".into());
        r.event("event:test", "x\u{1}");
        let j = r.to_json();
        assert!(j.contains(r#""serverName":"a\"b\n""#));
        assert!(j.contains(r#""version":null"#));
        assert!(j.contains(r#""validated":false"#));
        assert!(j.contains("\\u0001"));
    }

    /// The audit trail is bounded (no LLR row; the robustness rule of
    /// AGENTS.md, which REQ-CODEC-001 states for the decoder): events past
    /// the 256th are dropped, so a peer that provokes events without end
    /// cannot grow a report without limit, and the first 256 are kept.
    #[test]
    fn the_event_trail_keeps_the_first_256_events() {
        let mut r = SessionReport::default();
        for i in 0..300 {
            r.event("event:test", &alloc::format!("{i}"));
        }
        assert_eq!(r.events.len(), 256);
        assert_eq!(r.events[0].detail, "0");
        assert_eq!(r.events[255].detail, "255");
    }

    /// An event recorded without detail is written to the JSON report as its
    /// id alone, with no empty `detail` member (no LLR row covers the report
    /// format).
    #[test]
    fn an_event_without_detail_has_no_detail_member() {
        let mut r = SessionReport::default();
        r.event("event:ech-accepted", "");
        r.event("event:test", "d");
        let j = r.to_json();
        assert!(
            j.contains(
                r#""events":[{"event":"event:ech-accepted"},{"event":"event:test","detail":"d"}]"#
            ),
            "{j}"
        );
    }
}
