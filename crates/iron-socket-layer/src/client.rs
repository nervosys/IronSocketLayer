//! The client handshake state machine (RFC 8446 §2, Appendix A.1).
//!
//! ```text
//! START --ClientHello--> WAIT_SH --(HRR)--> ClientHello2 --> WAIT_SH
//!                           | ServerHello
//!                           v
//!                        WAIT_EE --> WAIT_CERT_CR --(CertificateRequest)--> WAIT_CERT
//!                                         | Certificate                          |
//!                                         v                                      v
//!                                      WAIT_CV <---------------------------------+
//!                                         | CertificateVerify
//!                                         v
//!                                      WAIT_FINISHED --Finished--> [cert, cv,] Finished --> CONNECTED
//! ```
//!
//! Every transition checks the message type against the state first, so a
//! message out of order is `unexpected_message` before any of its content is
//! looked at.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::config::{ClientConfig, PeerVerification, Revocation};
use crate::conn::{self, Core, Level};
use crate::crypto::hpke;
use crate::crypto::kx::{self, KeyShare};
use crate::crypto::{sign, HashAlg, Output};
use crate::ech::{self, EchConfig};
use crate::enums::{
    CipherSuite, ExtensionType, HandshakeType, NamedGroup, ProtocolVersion, SignatureScheme,
};
use crate::error::{Error, ErrorKind, Result};
use crate::key_schedule::{self, EarlyStage, HandshakeStage, MasterStage};
use crate::msgs::{
    self, CertificateMsg, CertificateRequest, CertificateVerify, ClientHello, EncryptedExtensions,
    ServerHello,
};
use crate::record::suite_params;
use crate::report::HandshakeState as S;
use crate::resumption::{PeerSummary, StoredTicket, PSK_DHE_KE};
use crate::x509::{self, ServerName, Usage};

/// Owned form of the name the client connects to.
#[derive(Debug, Clone)]
pub(crate) enum TargetName {
    Dns(String),
    Ip(x509::IpAddr),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EchStatus {
    Offered,
    Accepted,
    Rejected,
}

/// Client-side ECH state.
struct EchState {
    config: EchConfig,
    suite: (u16, u16),
    ctx: Option<hpke::Context>,
    outer: ClientHello,
    outer_msg: Vec<u8>,
    status: EchStatus,
}

pub(crate) struct ClientHs {
    config: Arc<ClientConfig>,
    name: TargetName,
    hello: ClientHello,
    shares: Vec<KeyShare>,
    retried: bool,
    retry_suite: Option<CipherSuite>,
    hs: Option<HandshakeStage>,
    client_hs_secret: Option<Output>,
    server_hs_secret: Option<Output>,
    cert_request: Option<CertificateRequest>,
    pq_chain: bool,
    /// The name exactly as the caller gave it; the ticket store's key.
    name_key: String,
    /// The ticket offered in this handshake, if any.
    ticket: Option<StoredTicket>,
    resumed: bool,
    resumption_master: Option<Output>,
    peer: PeerSummary,
    ech: Option<EchState>,
    /// Whether the server accepted our external PSK.
    external_accepted: bool,
    /// Data to send as 0-RTT, and what became of it.
    early_payload: Option<Vec<u8>>,
    early: EarlyStatus,
    /// The suite the 0-RTT data was sent under (the ticket's).
    early_suite: Option<CipherSuite>,
    /// QUIC: offer 0-RTT; the data travels in QUIC packets, not here.
    quic_early: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EarlyStatus {
    NotOffered,
    Offered,
    Accepted,
    Rejected,
}

fn unexpected(ty: HandshakeType) -> Error {
    let _ = ty;
    Error::new(
        ErrorKind::UnexpectedMessage,
        "handshake message not permitted in this state",
    )
}

impl ClientHs {
    pub(crate) fn new(config: Arc<ClientConfig>, server_name: &str) -> Result<Self> {
        let name = match ServerName::parse(server_name).map_err(|_| {
            Error::new(
                ErrorKind::InvalidConfig,
                "server name is neither a DNS name nor an IP address",
            )
        })? {
            ServerName::Dns(d) => TargetName::Dns(String::from(d)),
            ServerName::Ip(ip) => TargetName::Ip(ip),
        };
        Ok(Self {
            config,
            name,
            hello: ClientHello::default(),
            shares: Vec::new(),
            retried: false,
            retry_suite: None,
            hs: None,
            client_hs_secret: None,
            server_hs_secret: None,
            cert_request: None,
            pq_chain: false,
            name_key: String::from(server_name),
            ticket: None,
            resumed: false,
            resumption_master: None,
            peer: PeerSummary::default(),
            ech: None,
            external_accepted: false,
            early_payload: None,
            early: EarlyStatus::NotOffered,
            early_suite: None,
            quic_early: false,
        })
    }

    pub(crate) fn set_quic_early(&mut self) {
        self.quic_early = true;
    }

    pub(crate) fn set_early_payload(&mut self, data: Option<Vec<u8>>) {
        self.early_payload = data.filter(|d| !d.is_empty());
    }

    /// Record that 0-RTT was not accepted and hand the data back.
    fn early_rejected(&mut self, core: &mut Core) {
        if self.early == EarlyStatus::Offered {
            self.early = EarlyStatus::Rejected;
            core.rejected_early_data = self.early_payload.take();
            core.report.early_data = "early-data:rejected";
            core.report.event("event:early-data-rejected", "");
        }
    }

    fn handshake_schemes(&self) -> Vec<SignatureScheme> {
        self.config
            .common
            .schemes
            .iter()
            .copied()
            .filter(|s| s.allowed_in_handshake())
            .collect()
    }

    pub(crate) fn start(&mut self, core: &mut Core) -> Result<()> {
        let mut random = [0u8; 32];
        crate::crypto::fill_random(core.rng(), &mut random)?;
        let session_id = if core.is_quic() {
            // RFC 9001 §8.4: QUIC clients MUST NOT use middlebox compatibility mode.
            Vec::new()
        } else {
            let mut sid = alloc::vec![0u8; 32];
            crate::crypto::fill_random(core.rng(), &mut sid)?;
            sid
        };
        let n = self
            .config
            .initial_key_shares
            .clamp(1, self.config.common.groups.len());
        for &g in &self.config.common.groups[..n] {
            self.shares.push(KeyShare::generate(g, core.rng())?);
        }
        let handshake = self.handshake_schemes();
        let cert_schemes = if handshake.len() != self.config.common.schemes.len() {
            Some(self.config.common.schemes.clone())
        } else {
            None
        };
        let server_name = match (&self.name, self.config.send_sni) {
            (TargetName::Dns(d), true) => Some(d.clone()),
            _ => None,
        };
        if core.is_quic() && self.config.common.alpn.is_empty() {
            return Err(Error::new(
                ErrorKind::InvalidConfig,
                "QUIC requires ALPN (RFC 9001 §8.1)",
            ));
        }
        self.hello = ClientHello {
            random,
            session_id,
            suites: self.config.common.suites.clone(),
            server_name: server_name.clone(),
            groups: self.config.common.groups.clone(),
            sig_algs: handshake,
            sig_algs_cert: cert_schemes,
            versions: alloc::vec![ProtocolVersion::Tls13],
            key_shares: self
                .shares
                .iter()
                .map(|s| (s.group(), s.public().to_vec()))
                .collect(),
            alpn: self.config.common.alpn.clone(),
            quic_params: core.local_quic_params(),
            record_size_limit: if core.is_quic() {
                None
            } else {
                self.config.common.record_size_limit
            },
            status_request: self.config.revocation != Revocation::Off,
            // RFC 9001 §4.4: never under QUIC.
            post_handshake_auth: self.config.post_handshake_auth
                && !core.is_quic()
                && self.config.identity.is_some(),
            ..Default::default()
        };
        core.report.server_name = server_name.or_else(|| match &self.name {
            TargetName::Dns(d) => Some(d.clone()),
            TargetName::Ip(_) => None,
        });
        core.report.verification = self.config.verification.id();
        if let Some(list) = self.config.ech_configs.clone() {
            // REQ-ECH-004: configured ECH is used or the connection fails.
            let TargetName::Dns(_) = &self.name else {
                return Err(Error::new(
                    ErrorKind::InvalidConfig,
                    "ECH needs a DNS server name",
                ));
            };
            let (config, suite) = ech::select_config(&list)?;
            self.hello.ech = Some(msgs::EchHello::Inner);
            let mut outer = self.hello.clone();
            crate::crypto::fill_random(core.rng(), &mut outer.random)?;
            outer.server_name = Some(config.public_name.clone());
            outer.psk = None;
            self.ech = Some(EchState {
                config,
                suite,
                ctx: None,
                outer,
                outer_msg: Vec::new(),
                status: EchStatus::Offered,
            });
            core.report.ech = "ech:offered";
            // A ClientHelloInner carries no resumption PSK in this build.
            if self.config.tickets.is_some() {
                self.hello.psk_modes = alloc::vec![PSK_DHE_KE];
            }
            self.send_ech_hellos(core)?;
        } else if let Some(psk) = self.config.external_psk.clone() {
            // REQ-EPSK-001: psk_dhe_ke only, like resumption; age is 0.
            self.hello.psk_modes = alloc::vec![PSK_DHE_KE];
            self.hello.psk = Some(msgs::OfferedPsks {
                identities: alloc::vec![msgs::PskIdentity {
                    identity: psk.identity.clone(),
                    obfuscated_ticket_age: 0
                }],
                binders: alloc::vec![alloc::vec![0u8; psk.hash.len()]],
            });
            core.report.event("event:external-psk-offered", "");
            self.send_hello(core)?;
        } else {
            self.offer_ticket(core);
            self.send_hello(core)?;
        }
        // Data given for 0-RTT that could not be sent early goes back to the
        // caller rather than being dropped.
        if self.early == EarlyStatus::NotOffered {
            core.rejected_early_data = self.early_payload.take();
        }
        core.set_state(S::WaitServerHello);
        Ok(())
    }

    /// Offer a stored ticket for this server, if one is usable. `REQ-PSK-001`.
    fn offer_ticket(&mut self, core: &mut Core) {
        let Some(store) = &self.config.tickets else {
            return;
        };
        // Advertise psk_dhe_ke whenever resumption is enabled, ticket or not:
        // servers issue tickets only to clients that say they can use them.
        self.hello.psk_modes = alloc::vec![PSK_DHE_KE];
        let now = core.now();
        let Some(t) = store.take(&self.name_key, now) else {
            return;
        };
        // The resumed session must use a suite with the ticket's hash.
        let hash = suite_params(t.suite).map(|(_, h)| h);
        let compatible = self
            .hello
            .suites
            .iter()
            .any(|s| suite_params(*s).map(|(_, h)| h) == hash);
        if !compatible {
            return;
        }
        self.hello.psk_modes = alloc::vec![PSK_DHE_KE];
        self.hello.psk = Some(msgs::OfferedPsks {
            identities: alloc::vec![msgs::PskIdentity {
                identity: t.ticket.clone(),
                obfuscated_ticket_age: t.obfuscated_age(now),
            }],
            binders: alloc::vec![alloc::vec![0u8; t.psk.len()]],
        });
        core.report.event("event:ticket-offered", t.suite.id());
        // REQ-0RTT-001: 0-RTT only when asked for, allowed by the ticket, not
        // under QUIC, and with the ALPN the ticket's session used.
        let alpn_ok = match &t.alpn {
            Some(p) => self.hello.alpn.contains(p),
            None => true,
        };
        // REQ-0RTT-005: under QUIC the ticket must carry 0xffffffff and the
        // server's transport parameters, which the stack then reuses.
        let wanted = if core.is_quic() {
            self.quic_early && t.max_early_data == u32::MAX && t.quic_params.is_some()
        } else {
            self.early_payload
                .as_ref()
                .is_some_and(|d| d.len() <= t.max_early_data as usize)
        };
        if wanted && self.config.early_data && alpn_ok {
            self.hello.early_data = true;
            self.early = EarlyStatus::Offered;
            core.remembered_quic_params = t.quic_params.clone();
        }
        self.ticket = Some(t);
    }

    /// Seal the inner hello into the outer one and send the outer; record
    /// whichever the transcript follows. `REQ-ECH-001`.
    fn send_ech_hellos(&mut self, core: &mut Core) -> Result<()> {
        let Some(st) = self.ech.as_mut() else {
            return Ok(());
        };
        let inner_msg = msgs::frame(HandshakeType::ClientHello, &self.hello.encode()?)?;
        let mut encoding = self.hello.clone();
        encoding.session_id = Vec::new();
        let mut encoded = encoding.encode()?;
        let name_len = self.hello.server_name.as_ref().map(|n| n.len());
        let pad = ech::padding_len(encoded.len(), name_len, st.config.maximum_name_length);
        encoded.resize(encoded.len() + pad, 0);
        let enc = match &st.ctx {
            None => {
                let (enc, ctx) = hpke::setup_sender(
                    &st.config.public_key,
                    &st.config.hpke_info(),
                    st.suite.1,
                    core.rng(),
                )?;
                st.ctx = Some(ctx);
                enc
            }
            // A second hello reuses the context and sends an empty enc.
            Some(_) => Vec::new(),
        };
        st.outer.key_shares = self.hello.key_shares.clone();
        st.outer.cookie = self.hello.cookie.clone();
        st.outer.ech = Some(msgs::EchHello::Outer {
            suite: st.suite,
            config_id: st.config.config_id,
            enc: enc.clone(),
            payload: alloc::vec![0u8; encoded.len() + crate::crypto::TAG_LEN],
        });
        let aad = st.outer.encode()?;
        let ctx = st
            .ctx
            .as_mut()
            .ok_or(Error::new(ErrorKind::Internal, "hpke context"))?;
        let payload = ctx.seal(&aad, &encoded)?;
        st.outer.ech = Some(msgs::EchHello::Outer {
            suite: st.suite,
            config_id: st.config.config_id,
            enc,
            payload,
        });
        let outer_msg = msgs::frame(HandshakeType::ClientHello, &st.outer.encode()?)?;
        let rejected = st.status == EchStatus::Rejected;
        core.transcript
            .add(if rejected { &outer_msg } else { &inner_msg });
        core.send_handshake_bytes(&outer_msg)?;
        st.outer_msg = outer_msg;
        core.report.event("event:sent", "message:client-hello");
        core.report
            .event("event:ech-offered", st.config.public_name.as_str());
        Ok(())
    }

    /// Decide acceptance from a confirmation value. `REQ-ECH-002`.
    fn ech_confirmed(
        &self,
        core: &Core,
        hash: HashAlg,
        label: &[u8],
        zeroed_msg: &[u8],
        received: &[u8],
    ) -> Result<bool> {
        let th = core.transcript.hash_with(hash, zeroed_msg)?;
        let expected = ech::confirmation(hash, &self.hello.random, label, th.as_bytes())?;
        Ok(ic_core::ct::verify(&expected, received))
    }

    /// Switch to the outer hello after a rejection: the transcript, the
    /// hello every later check consults, and the name to authenticate.
    fn ech_reject(
        &mut self,
        core: &mut Core,
        hash: HashAlg,
        retried_msg: Option<&[u8]>,
    ) -> Result<()> {
        let Some(st) = self.ech.as_mut() else {
            return Ok(());
        };
        st.status = EchStatus::Rejected;
        core.transcript = crate::conn::Transcript::new();
        core.transcript.add(&st.outer_msg);
        if let Some(hrr) = retried_msg {
            core.transcript.start(hash)?;
            core.transcript.rollup_for_retry()?;
            core.transcript.add(hrr);
        }
        self.hello = st.outer.clone();
        core.report.ech = "ech:rejected";
        core.report.server_name = Some(st.config.public_name.clone());
        core.report.event("event:ech-rejected", "");
        Ok(())
    }

    /// Encode, bind (when offering a PSK), record and send the ClientHello.
    fn send_hello(&mut self, core: &mut Core) -> Result<()> {
        let body = self.hello.encode()?;
        let mut msg = msgs::frame(HandshakeType::ClientHello, &body)?;
        if let (Some(ext), Some(psk)) = (&self.config.external_psk, &self.hello.psk) {
            let cut = msg.len() - psk.binders_len();
            let th = core.transcript.hash_with(ext.hash, &msg[..cut])?;
            let binder =
                EarlyStage::new(ext.hash, Some(ext.key()))?.external_binder(th.as_bytes())?;
            let n = binder.len();
            let end = msg.len();
            msg[end - n..].copy_from_slice(binder.as_bytes());
        } else if let (Some(t), Some(psk)) = (&self.ticket, &self.hello.psk) {
            let (_, hash) =
                suite_params(t.suite).ok_or(Error::new(ErrorKind::Internal, "suite"))?;
            // pre_shared_key is the last extension, so the binders are the
            // message's final bytes and the part they cover is a prefix.
            let cut = msg.len() - psk.binders_len();
            let th = core.transcript.hash_with(hash, &msg[..cut])?;
            let binder =
                EarlyStage::new(hash, Some(t.psk.as_bytes()))?.resumption_binder(th.as_bytes())?;
            let n = binder.len();
            let end = msg.len();
            msg[end - n..].copy_from_slice(binder.as_bytes());
        }
        core.emit_framed(HandshakeType::ClientHello, &msg)?;
        // 0-RTT: CCS, then the early data under client_early_traffic_secret.
        if self.early == EarlyStatus::Offered && !self.retried {
            let t = self
                .ticket
                .as_ref()
                .ok_or(Error::new(ErrorKind::Internal, "ticket"))?;
            let (_, hash) =
                suite_params(t.suite).ok_or(Error::new(ErrorKind::Internal, "suite"))?;
            let ch_hash = core.transcript.hash_with(hash, &[])?;
            let secret = EarlyStage::new(hash, Some(t.psk.as_bytes()))?
                .client_early_traffic(ch_hash.as_bytes())?;
            core.suite = Some(t.suite);
            self.early_suite = Some(t.suite);
            if core.is_quic() {
                // The stack sends 0-RTT packets under this key.
                core.export_quic_key(Level::Early, true, &secret)?;
            } else {
                core.send_ccs();
                core.install_write(Level::Early, &secret)?;
                let data = self.early_payload.clone().unwrap_or_default();
                core.send_early(&data)?;
            }
            core.report.early_data = "early-data:offered";
            core.report.event("event:early-data-sent", "");
        }
        Ok(())
    }

    pub(crate) fn handle(&mut self, core: &mut Core, ty: HandshakeType, msg: &[u8]) -> Result<()> {
        let body = msg.get(4..).unwrap_or(&[]);
        match (core.state, ty) {
            (S::WaitServerHello, HandshakeType::ServerHello) => {
                let sh = ServerHello::decode(body)?;
                if sh.is_retry() {
                    self.on_retry(core, sh, msg)
                } else {
                    self.on_server_hello(core, sh, msg)
                }
            }
            (S::WaitEncryptedExtensions, HandshakeType::EncryptedExtensions) => {
                self.on_encrypted_extensions(core, body, msg)
            }
            (S::WaitCertificateRequest, HandshakeType::CertificateRequest) => {
                let cr = CertificateRequest::decode(body)?;
                if !cr.context.is_empty() {
                    return Err(Error::new(
                        ErrorKind::IllegalParameter,
                        "handshake CertificateRequest must have an empty context",
                    ));
                }
                core.transcript.add(msg);
                self.cert_request = Some(cr);
                core.set_state(S::WaitCertificate);
                Ok(())
            }
            (S::WaitCertificateRequest | S::WaitCertificate, HandshakeType::Certificate) => {
                self.on_certificate(core, body, msg)
            }
            (S::WaitCertificateVerify, HandshakeType::CertificateVerify) => {
                self.on_certificate_verify(core, body, msg)
            }
            (S::WaitFinished, HandshakeType::Finished) => self.on_finished(core, body, msg),
            (S::Connected, HandshakeType::NewSessionTicket) => self.on_ticket(core, body),
            (S::Connected, HandshakeType::CertificateRequest) => {
                self.on_post_handshake_request(core, body, msg)
            }
            _ => Err(unexpected(ty)),
        }
    }

    /// A ServerHello must answer only what was offered. `REQ-MSG-006`.
    fn check_common_hello(&self, sh: &ServerHello) -> Result<CipherSuite> {
        match sh.selected_version {
            Some(ProtocolVersion::Tls13) => {}
            Some(_) => {
                return Err(Error::new(
                    ErrorKind::IllegalParameter,
                    "server selected a version not offered",
                ))
            }
            None => {
                return Err(Error::new(
                    ErrorKind::ProtocolVersion,
                    "server does not support TLS 1.3",
                ))
            }
        }
        if sh.session_id != self.hello.session_id {
            return Err(Error::new(
                ErrorKind::IllegalParameter,
                "legacy_session_id_echo does not match",
            ));
        }
        let suite = sh.suite.ok_or(Error::new(ErrorKind::Decode, "suite"))?;
        if !self.hello.suites.contains(&suite) {
            return Err(Error::new(
                ErrorKind::IllegalParameter,
                "server selected a suite not offered",
            ));
        }
        if let Some(prev) = self.retry_suite {
            if prev != suite {
                return Err(Error::new(
                    ErrorKind::IllegalParameter,
                    "suite changed after HelloRetryRequest",
                ));
            }
        }
        if !sh.other_extensions.is_empty() {
            return Err(Error::new(
                ErrorKind::UnsupportedExtension,
                "ServerHello carries an extension not offered",
            ));
        }
        Ok(suite)
    }

    fn on_retry(&mut self, core: &mut Core, sh: ServerHello, msg: &[u8]) -> Result<()> {
        if self.retried {
            return Err(Error::new(
                ErrorKind::UnexpectedMessage,
                "second HelloRetryRequest",
            ));
        }
        let suite = self.check_common_hello(&sh)?;
        let (_, hash) =
            suite_params(suite).ok_or(Error::new(ErrorKind::IllegalParameter, "suite"))?;
        let new_group = match sh.hrr_group {
            Some(g) => {
                if !self.hello.groups.contains(&g) {
                    return Err(Error::new(
                        ErrorKind::IllegalParameter,
                        "retry names a group not offered",
                    ));
                }
                if self.shares.iter().any(|s| s.group() == g) {
                    return Err(Error::new(
                        ErrorKind::IllegalParameter,
                        "retry names a group already shared",
                    ));
                }
                Some(g)
            }
            None => None,
        };
        if new_group.is_none() && sh.cookie.is_none() {
            return Err(Error::new(
                ErrorKind::IllegalParameter,
                "HelloRetryRequest would change nothing",
            ));
        }
        core.suite = Some(suite);
        let ech_offered = matches!(&self.ech, Some(st) if st.status == EchStatus::Offered);
        if ech_offered {
            // The HRR confirmation covers message_hash(ClientHelloInner1) and
            // the HRR with the confirmation bytes zeroed.
            let accepted = match (sh.ech_confirmation, sh.ech_confirmation_at) {
                (Some(conf), Some(at)) => {
                    let mut zeroed = msg.to_vec();
                    let at = at + 4;
                    zeroed
                        .get_mut(at..at + 8)
                        .ok_or(Error::new(ErrorKind::Decode, "ech confirmation"))?
                        .fill(0);
                    let mut probe = core.transcript.clone();
                    probe.start(hash)?;
                    probe.rollup_for_retry()?;
                    let th = probe.hash_with(hash, &zeroed)?;
                    let expected = ech::confirmation(
                        hash,
                        &self.hello.random,
                        ech::HRR_ACCEPT_LABEL,
                        th.as_bytes(),
                    )?;
                    ic_core::ct::verify(&expected, &conf)
                }
                _ => false,
            };
            if accepted {
                if let Some(st) = self.ech.as_mut() {
                    st.status = EchStatus::Accepted;
                }
                core.transcript.start(hash)?;
                core.transcript.rollup_for_retry()?;
                core.transcript.add(msg);
            } else {
                self.ech_reject(core, hash, Some(msg))?;
            }
        } else {
            core.transcript.start(hash)?;
            core.transcript.rollup_for_retry()?;
            core.transcript.add(msg);
        }
        if let Some(g) = new_group {
            self.shares = alloc::vec![KeyShare::generate(g, core.rng())?];
        }
        self.hello.key_shares = self
            .shares
            .iter()
            .map(|s| (s.group(), s.public().to_vec()))
            .collect();
        self.hello.cookie = sh.cookie.clone();
        self.retried = true;
        self.retry_suite = Some(suite);
        core.report.hello_retry = true;
        core.report.event(
            "event:hello-retry",
            new_group.map(|g| g.id()).unwrap_or("cookie"),
        );
        // A HelloRetryRequest ends 0-RTT: the second hello goes in the clear
        // and carries no early_data.
        if self.early == EarlyStatus::Offered {
            core.clear_write();
            self.hello.early_data = false;
            self.early_rejected(core);
        }
        // A ticket whose hash differs from the retry's suite cannot be used
        // in the second hello; drop it rather than bind it to the wrong hash.
        if let Some(t) = &self.ticket {
            if suite_params(t.suite).map(|(_, h)| h) != Some(hash) {
                self.ticket = None;
                self.hello.psk = None;
            }
        }
        core.allow_ccs(true);
        if !core.is_quic() {
            core.send_ccs();
        }
        match &self.ech {
            Some(st) if st.status == EchStatus::Accepted => {
                // Both hellos again; the outer from the same HPKE context.
                self.send_ech_hellos(core)
            }
            Some(_) => {
                // Rejected: the outer hello is now the hello, and it keeps its
                // ECH extension so the server sees a consistent retry.
                let body = self.hello.encode()?;
                let m = msgs::frame(HandshakeType::ClientHello, &body)?;
                core.emit_framed(HandshakeType::ClientHello, &m)
            }
            None => self.send_hello(core),
        }
    }

    fn on_server_hello(&mut self, core: &mut Core, sh: ServerHello, msg: &[u8]) -> Result<()> {
        let suite = self.check_common_hello(&sh)?;
        let (_, hash) =
            suite_params(suite).ok_or(Error::new(ErrorKind::IllegalParameter, "suite"))?;
        let (group, share) = sh.key_share.clone().ok_or(Error::new(
            ErrorKind::MissingExtension,
            "ServerHello without key_share",
        ))?;
        let idx = self
            .shares
            .iter()
            .position(|s| s.group() == group)
            .ok_or(Error::new(
                ErrorKind::IllegalParameter,
                "server key share for a group not shared",
            ))?;
        let mine = self.shares.swap_remove(idx);
        self.shares.clear();
        let shared = mine.complete(&share)?;
        // The ticket is spent whether or not the server accepts it.
        let ticket = self.ticket.take();
        let external = self
            .config
            .external_psk
            .clone()
            .filter(|_| self.hello.psk.is_some());
        let psk = match (sh.selected_psk, &ticket) {
            (None, _) if external.is_some() && self.config.verification_is_empty() => {
                // REQ-EPSK-004: no trust anchors to fall back on.
                return Err(Error::new(
                    ErrorKind::HandshakeFailure,
                    "server did not accept the external PSK and no trust anchors are configured",
                ));
            }
            (None, _) => None,
            (Some(0), _) if external.is_some() => {
                let ext = external
                    .as_ref()
                    .ok_or(Error::new(ErrorKind::Internal, "psk"))?;
                if ext.hash != hash {
                    return Err(Error::new(
                        ErrorKind::IllegalParameter,
                        "suite hash differs from the external PSK's",
                    ));
                }
                self.external_accepted = true;
                Some(Output::from_slice(ext.key())?)
            }
            (Some(0), Some(t)) => {
                if suite_params(t.suite).map(|(_, h)| h) != Some(hash) {
                    return Err(Error::new(
                        ErrorKind::IllegalParameter,
                        "resumed with a suite of another hash",
                    ));
                }
                Some(t.psk.clone())
            }
            (Some(_), _) => {
                return Err(Error::new(
                    ErrorKind::IllegalParameter,
                    "server selected a PSK that was not offered",
                ))
            }
        };
        core.suite = Some(suite);
        if let Some(status) = self.ech.as_ref().map(|s| s.status) {
            let mut zeroed = msg.to_vec();
            // Random is at 4 (header) + 2 (legacy_version); its last 8 bytes.
            zeroed
                .get_mut(30..38)
                .ok_or(Error::new(ErrorKind::Decode, "server hello"))?
                .fill(0);
            let confirmed = status != EchStatus::Rejected
                && self.ech_confirmed(core, hash, ech::ACCEPT_LABEL, &zeroed, &sh.random[24..])?;
            match (status, confirmed) {
                (_, true) => {
                    if let Some(st) = self.ech.as_mut() {
                        st.status = EchStatus::Accepted;
                    }
                    core.report.ech = "ech:accepted";
                    core.report
                        .add(crate::report::Property::EncryptedClientHello);
                    core.report.event("event:ech-accepted", "");
                }
                (EchStatus::Accepted, false) => {
                    return Err(Error::new(
                        ErrorKind::IllegalParameter,
                        "ECH accepted at HelloRetryRequest but not confirmed in ServerHello",
                    ))
                }
                (EchStatus::Offered, false) => self.ech_reject(core, hash, None)?,
                (EchStatus::Rejected, false) => {}
            }
        }
        core.transcript.start(hash)?;
        core.transcript.add(msg);
        let hs = EarlyStage::new(hash, psk.as_ref().map(|p| p.as_bytes()))?
            .into_handshake(shared.get())?;
        if let (Some(_), Some(t)) = (&psk, ticket) {
            self.resumed = true;
            self.peer = t.peer.clone();
            core.report.resumed = true;
            core.report.event("event:session-resumed", suite.id());
        }
        let th = core.transcript.current()?;
        let c = hs.client_traffic(th.as_bytes())?;
        let s = hs.server_traffic(th.as_bytes())?;
        core.report.version = Some(ProtocolVersion::Tls13);
        core.report.suite = Some(suite);
        core.report.group = Some(group);
        core.allow_ccs(true);
        core.install_read(Level::Handshake, &s)?;
        if !core.is_quic() {
            core.send_ccs();
        }
        let psk_taken = sh.selected_psk.is_some() && self.resumed;
        if self.early == EarlyStatus::Offered && psk_taken && self.early_suite == Some(suite) {
            // TLS: keep the early write key until EncryptedExtensions says
            // whether the server took the data; EndOfEarlyData goes under it.
            // QUIC: 0-RTT and Handshake keys are independent.
            if core.is_quic() {
                core.install_write(Level::Handshake, &c)?;
            }
        } else {
            self.early_rejected(core);
            core.install_write(Level::Handshake, &c)?;
        }
        self.hs = Some(hs);
        self.client_hs_secret = Some(c);
        self.server_hs_secret = Some(s);
        core.set_state(S::WaitEncryptedExtensions);
        Ok(())
    }

    fn on_encrypted_extensions(&mut self, core: &mut Core, body: &[u8], msg: &[u8]) -> Result<()> {
        let ee = EncryptedExtensions::decode(body)?;
        if let Some(p) = &ee.alpn {
            if !self.hello.alpn.contains(p) {
                return Err(Error::new(
                    ErrorKind::IllegalParameter,
                    "server selected an ALPN protocol not offered",
                ));
            }
        } else if !self.hello.alpn.is_empty() && (self.config.common.require_alpn || core.is_quic())
        {
            return Err(Error::new(
                ErrorKind::NoApplicationProtocol,
                "server selected no ALPN protocol",
            ));
        }
        if ee.server_name_ack && self.hello.server_name.is_none() {
            return Err(Error::new(
                ErrorKind::UnsupportedExtension,
                "server_name acknowledged but not sent",
            ));
        }
        match (core.is_quic(), ee.quic_params.clone()) {
            (true, Some(p)) => core.set_peer_quic_params(p),
            (true, None) => {
                return Err(Error::new(
                    ErrorKind::MissingExtension,
                    "server sent no QUIC transport parameters",
                ))
            }
            (false, Some(_)) => {
                return Err(Error::new(
                    ErrorKind::UnsupportedExtension,
                    "QUIC transport parameters over TCP",
                ))
            }
            (false, None) => {}
        }
        if let Some(bad) = ee.other_extensions.first() {
            return Err(Error::new(
                if matches!(bad, ExtensionType::Unknown(_)) || *bad == ExtensionType::EarlyData {
                    ErrorKind::UnsupportedExtension
                } else {
                    ErrorKind::IllegalParameter
                },
                "EncryptedExtensions carries an extension not offered",
            ));
        }
        match (ee.record_size_limit, self.hello.record_size_limit) {
            (Some(_), None) => {
                return Err(Error::new(
                    ErrorKind::UnsupportedExtension,
                    "record_size_limit answered but not offered",
                ))
            }
            (Some(theirs), Some(ours)) => {
                core.peer_record_limit = Some(usize::from(theirs));
                core.local_record_limit = Some(usize::from(ours));
                core.report.event("event:record-size-limit", "");
            }
            _ => {}
        }
        if let Some(list) = ee.ech_retry_configs {
            match self.ech.as_ref().map(|s| s.status) {
                None => {
                    return Err(Error::new(
                        ErrorKind::UnsupportedExtension,
                        "encrypted_client_hello in EncryptedExtensions but not offered",
                    ))
                }
                Some(EchStatus::Rejected) => {
                    ech::parse_config_list(&list)?;
                    core.ech_retry_configs = Some(list);
                }
                // Retry configs after acceptance carry no instruction.
                Some(_) => {}
            }
        }
        match (ee.early_data, self.early) {
            (true, EarlyStatus::Offered) => {
                self.early = EarlyStatus::Accepted;
                core.report.early_data = "early-data:accepted";
                core.report.event("event:early-data-accepted", "");
            }
            (true, _) => {
                return Err(Error::new(
                    ErrorKind::IllegalParameter,
                    "server accepted early data that was not sent",
                ))
            }
            (false, EarlyStatus::Offered) if core.is_quic() => self.early_rejected(core),
            (false, EarlyStatus::Offered) => {
                self.early_rejected(core);
                let c = self
                    .client_hs_secret
                    .clone()
                    .ok_or(Error::new(ErrorKind::Internal, "secret"))?;
                core.install_write(Level::Handshake, &c)?;
            }
            (false, _) => {}
        }
        core.report.alpn = ee.alpn;
        core.transcript.add(msg);
        // A resumed session was authenticated when the ticket was issued.
        core.set_state(if self.resumed || self.external_accepted {
            S::WaitFinished
        } else {
            S::WaitCertificateRequest
        });
        Ok(())
    }

    fn on_certificate(&mut self, core: &mut Core, body: &[u8], msg: &[u8]) -> Result<()> {
        let cert = CertificateMsg::decode(body)?;
        if !cert.context.is_empty() {
            return Err(Error::new(
                ErrorKind::IllegalParameter,
                "server Certificate must have an empty context",
            ));
        }
        let leaf = cert.chain.first().ok_or(Error::new(
            ErrorKind::Decode,
            "server sent an empty Certificate",
        ))?;
        let now = core.now();
        match &self.config.verification {
            PeerVerification::Roots(roots) => {
                let inter: Vec<&[u8]> = cert.chain[1..].iter().map(|c| c.as_slice()).collect();
                let opts = x509::VerifyOptions {
                    now,
                    usage: Usage::ServerAuth,
                    allowed_schemes: &self.config.common.schemes,
                    max_depth: 8,
                    min_rsa_bits: self.config.common.profile.min_rsa_bits(),
                    crls: self.config.common.crls.as_deref(),
                    require_crl: self.config.common.require_crl,
                };
                let chain = x509::verify_chain(leaf, &inter, roots, &opts)?;
                self.name_check(leaf)?;
                self.check_revocation(core, cert.ocsp.as_deref(), leaf, &chain, now)?;
                conn::note_crl(core, chain.crl_checked);
                self.pq_chain =
                    !chain.schemes.is_empty() && chain.schemes.iter().all(|s| s.is_post_quantum());
                core.report.peer_chain_min_bits = Some(chain.min_classical_bits);
            }
            PeerVerification::PinnedSpki {
                sha256,
                check_names,
            } => {
                check_pinned(leaf, sha256, now)?;
                if *check_names {
                    self.name_check(leaf)?;
                }
                self.pq_chain = true;
            }
        }
        conn::describe_peer(core, leaf);
        core.report.peer_chain_len = cert.chain.len();
        core.peer_chain = cert.chain;
        core.transcript.add(msg);
        core.set_state(S::WaitCertificateVerify);
        Ok(())
    }

    /// Apply the revocation policy to the server's staple.
    /// `REQ-OCSP-003`, `REQ-OCSP-005`.
    fn check_revocation(
        &self,
        core: &mut Core,
        staple: Option<&[u8]>,
        leaf: &[u8],
        chain: &x509::ChainReport,
        now: u64,
    ) -> Result<()> {
        let policy = self.config.revocation;
        let Some(resp) = staple else {
            if policy == Revocation::RequireStaple {
                return Err(Error::new(
                    ErrorKind::BadCertificateStatus,
                    "server provided no OCSP staple",
                ));
            }
            core.report.revocation = "revocation:not-checked";
            return Ok(());
        };
        if policy == Revocation::Off {
            return Err(Error::new(
                ErrorKind::UnsupportedExtension,
                "OCSP staple sent but not requested",
            ));
        }
        // A staple that is present must be valid, whatever the policy: a
        // broken or stale one is not treated as absent.
        let v = x509::ocsp::verify_response(
            resp,
            leaf,
            &chain.issuer_subject,
            &chain.issuer_spki,
            now,
            &self.config.common.schemes,
        )?;
        core.report.revocation = v.status.id();
        core.report.event("event:ocsp-verified", v.status.id());
        match v.status {
            x509::ocsp::CertStatus::Good => {
                core.report.add(crate::report::Property::RevocationChecked);
                Ok(())
            }
            _ if policy == Revocation::RequireStaple => Err(Error::new(
                ErrorKind::BadCertificateStatus,
                "OCSP responder does not know the certificate",
            )),
            _ => Ok(()),
        }
    }

    fn name_check(&self, leaf: &[u8]) -> Result<()> {
        // REQ-ECH-003: after rejection the server speaks for the public name.
        if let Some(st) = &self.ech {
            if st.status == EchStatus::Rejected {
                return x509::verify_name(leaf, &ServerName::Dns(&st.config.public_name));
            }
        }
        let name = match &self.name {
            TargetName::Dns(d) => ServerName::Dns(d),
            TargetName::Ip(ip) => ServerName::Ip(*ip),
        };
        x509::verify_name(leaf, &name)
    }

    fn on_certificate_verify(&mut self, core: &mut Core, body: &[u8], msg: &[u8]) -> Result<()> {
        let cv = CertificateVerify::decode(body)?;
        if !self.hello.sig_algs.contains(&cv.scheme) {
            return Err(Error::new(
                ErrorKind::IllegalParameter,
                "CertificateVerify uses a scheme not offered",
            ));
        }
        let leaf = core
            .peer_chain
            .first()
            .ok_or(Error::new(ErrorKind::Internal, "no chain"))?;
        let cert = x509::Certificate::parse(leaf)?;
        let key = cert.subject_public_key()?;
        let th = core.transcript.current()?;
        let input = msgs::certificate_verify_input(true, th.as_bytes());
        sign::verify(cv.scheme, &key, &input, &cv.signature)?;
        // PQ authentication needs the handshake signature *and* the chain to be ML-DSA.
        self.pq_chain &= cv.scheme.is_post_quantum();
        core.report.peer_signature_scheme = Some(cv.scheme);
        core.transcript.add(msg);
        core.set_state(S::WaitFinished);
        Ok(())
    }

    fn on_finished(&mut self, core: &mut Core, body: &[u8], msg: &[u8]) -> Result<()> {
        let suite = core
            .suite
            .ok_or(Error::new(ErrorKind::Internal, "no suite"))?;
        let (_, hash) = suite_params(suite).ok_or(Error::new(ErrorKind::Internal, "suite"))?;
        let s_hs = self
            .server_hs_secret
            .take()
            .ok_or(Error::new(ErrorKind::Internal, "no secret"))?;
        let th = core.transcript.current()?;
        key_schedule::verify_finished(hash, s_hs.as_bytes(), th.as_bytes(), body)?;
        // REQ-ECH-003: the handshake as the public name authenticated the
        // retry configurations; now refuse to go further without ECH.
        if matches!(&self.ech, Some(st) if st.status == EchStatus::Rejected) {
            return Err(Error::new(
                ErrorKind::EchRejected,
                "server did not accept ECH; retry with Connection::ech_retry_configs",
            ));
        }
        core.transcript.add(msg);

        let hs = self
            .hs
            .take()
            .ok_or(Error::new(ErrorKind::Internal, "no schedule"))?;
        let master: MasterStage = hs.into_master()?;
        let th = core.transcript.current()?;
        let c_ap = master.client_traffic(th.as_bytes())?;
        let s_ap = master.server_traffic(th.as_bytes())?;
        core.exporter_secret = Some(master.exporter(th.as_bytes())?);

        // REQ-0RTT-003: EndOfEarlyData under the early key, then the
        // handshake key for the rest of the flight.
        if self.early == EarlyStatus::Accepted && !core.is_quic() {
            core.emit(HandshakeType::EndOfEarlyData, &[])?;
            let c = self
                .client_hs_secret
                .clone()
                .ok_or(Error::new(ErrorKind::Internal, "secret"))?;
            core.install_write(Level::Handshake, &c)?;
        }
        // Our second flight, under the handshake write key.
        let mut mutual = false;
        if let Some(cr) = self.cert_request.take() {
            mutual = self.send_client_auth(core, &cr, hash)?;
        }
        let c_hs = self
            .client_hs_secret
            .take()
            .ok_or(Error::new(ErrorKind::Internal, "no secret"))?;
        let th = core.transcript.current()?;
        let verify = key_schedule::finished_mac(hash, c_hs.as_bytes(), th.as_bytes())?;
        core.emit(HandshakeType::Finished, verify.as_bytes())?;

        core.install_read(Level::Application, &s_ap)?;
        core.install_write(Level::Application, &c_ap)?;
        let th = core.transcript.current()?;
        self.resumption_master = Some(master.resumption(th.as_bytes())?);
        if self.external_accepted {
            // REQ-EPSK-002: the server's Finished, keyed from the PSK, is its
            // proof of holding it.
            core.report.verification = "verification:external-psk";
            core.report.event("event:external-psk-accepted", "");
            let pq = self
                .config
                .external_psk
                .as_ref()
                .map(|p| p.key().len() >= 32)
                .unwrap_or(false);
            self.peer = PeerSummary {
                verification: "verification:external-psk",
                post_quantum_authentication: pq,
                revocation: "revocation:not-checked",
                ..PeerSummary::default()
            };
            return conn::finish_report(core, pq, false, false, false);
        }
        if self.resumed {
            // Report what the original, fully authenticated session established.
            core.report.peer_key = self.peer.key;
            core.report.peer_subject_cn = self.peer.subject_cn.clone();
            core.report.peer_not_after = self.peer.not_after;
            core.report.verification = self.peer.verification;
            core.report.revocation = self.peer.revocation;
            if self.peer.revocation == "revocation:good" {
                core.report.add(crate::report::Property::RevocationChecked);
            }
            let p = self.peer.clone();
            let cert_auth = p.verification != "verification:external-psk";
            return conn::finish_report(
                core,
                p.post_quantum_authentication,
                p.mutual,
                p.pinned,
                cert_auth,
            );
        }
        let pinned = matches!(
            self.config.verification,
            PeerVerification::PinnedSpki { .. }
        );
        // Post-quantum authentication holds only if every signature in the
        // session -- the server's chain and CertificateVerify, and ours if we
        // authenticated -- is ML-DSA.
        let local_pq = !mutual
            || core
                .report
                .local_signature_scheme
                .is_some_and(|s| s.is_post_quantum());
        let pq_auth = self.pq_chain && local_pq;
        self.peer = PeerSummary {
            key: core.report.peer_key,
            subject_cn: core.report.peer_subject_cn.clone(),
            not_after: core.report.peer_not_after,
            verification: self.config.verification.id(),
            post_quantum_authentication: pq_auth,
            mutual,
            pinned,
            revocation: core.report.revocation,
        };
        conn::finish_report(core, pq_auth, mutual, pinned, true)
    }

    /// Answer a post-handshake CertificateRequest (§4.6.2): Certificate,
    /// CertificateVerify and Finished over the handshake transcript plus this
    /// request, under the current application key. `REQ-PHA-001..003`.
    fn on_post_handshake_request(
        &mut self,
        core: &mut Core,
        body: &[u8],
        msg: &[u8],
    ) -> Result<()> {
        if !self.hello.post_handshake_auth {
            return Err(Error::new(
                ErrorKind::UnexpectedMessage,
                "CertificateRequest without post_handshake_auth",
            ));
        }
        let cr = CertificateRequest::decode(body)?;
        if cr.context.is_empty() {
            return Err(Error::new(
                ErrorKind::IllegalParameter,
                "post-handshake CertificateRequest with an empty context",
            ));
        }
        let suite = core
            .suite
            .ok_or(Error::new(ErrorKind::Internal, "no suite"))?;
        let (_, hash) = suite_params(suite).ok_or(Error::new(ErrorKind::Internal, "suite"))?;
        let mut t = core.transcript.clone();
        t.add(msg);
        let chosen = self.config.identity.as_ref().and_then(|id| {
            id.key
                .choose_scheme(&cr.sig_algs, &self.config.common.schemes)
                .map(|s| (id.clone(), s))
        });
        let chain = chosen
            .as_ref()
            .map(|(id, _)| id.chain.clone())
            .unwrap_or_default();
        let cert = msgs::frame(
            HandshakeType::Certificate,
            &CertificateMsg {
                context: cr.context.clone(),
                chain,
                ocsp: None,
            }
            .encode()?,
        )?;
        t.add(&cert);
        let mut out = cert;
        if let Some((identity, scheme)) = &chosen {
            let th = t.current()?;
            let input = msgs::certificate_verify_input(false, th.as_bytes());
            let signature = identity.key.sign(*scheme, &input, core.rng())?;
            let cv = msgs::frame(
                HandshakeType::CertificateVerify,
                &CertificateVerify {
                    scheme: *scheme,
                    signature,
                }
                .encode()?,
            )?;
            t.add(&cv);
            out.extend_from_slice(&cv);
        }
        let base = core.current_secret(true)?;
        let th = t.current()?;
        let fin = key_schedule::finished_mac(hash, base.as_bytes(), th.as_bytes())?;
        out.extend_from_slice(&msgs::frame(HandshakeType::Finished, fin.as_bytes())?);
        core.send_handshake_bytes(&out)?;
        core.report.event(
            "event:post-handshake-auth-answered",
            if chosen.is_some() {
                "certificate"
            } else {
                "declined"
            },
        );
        if let Some((_, scheme)) = chosen {
            core.report.local_signature_scheme = Some(scheme);
            core.report
                .add(crate::report::Property::MutualAuthentication);
        }
        Ok(())
    }

    /// Keep a NewSessionTicket for the next connection to this name.
    fn on_ticket(&mut self, core: &mut Core, body: &[u8]) -> Result<()> {
        let nst = msgs::NewSessionTicket::decode(body)?;
        core.report.tickets_received += 1;
        core.report.event("event:ticket-received", "");
        let (Some(store), Some(res), Some(suite)) =
            (&self.config.tickets, &self.resumption_master, core.suite)
        else {
            return Ok(());
        };
        if nst.lifetime == 0 {
            return Ok(());
        }
        let (_, hash) = suite_params(suite).ok_or(Error::new(ErrorKind::Internal, "suite"))?;
        let psk = key_schedule::resumption_psk(hash, res.as_bytes(), &nst.nonce)?;
        store.put(StoredTicket {
            server_name: self.name_key.clone(),
            suite,
            ticket: nst.ticket,
            psk,
            age_add: nst.age_add,
            lifetime: nst.lifetime.min(crate::resumption::MAX_TICKET_LIFETIME),
            received_at: core.now(),
            max_early_data: nst.max_early_data.unwrap_or(0),
            alpn: core.report.alpn.clone(),
            quic_params: core.peer_quic_params(),
            peer: self.peer.clone(),
        });
        Ok(())
    }

    /// Answer a CertificateRequest. Returns whether a certificate was sent.
    fn send_client_auth(
        &mut self,
        core: &mut Core,
        cr: &CertificateRequest,
        _hash: HashAlg,
    ) -> Result<bool> {
        let chosen = self.config.identity.as_ref().and_then(|id| {
            id.key
                .choose_scheme(&cr.sig_algs, &self.config.common.schemes)
                .map(|s| (id.clone(), s))
        });
        let Some((identity, scheme)) = chosen else {
            // No usable identity: an empty Certificate lets the server decide.
            let empty = CertificateMsg {
                context: Vec::new(),
                chain: Vec::new(),
                ocsp: None,
            };
            core.emit(HandshakeType::Certificate, &empty.encode()?)?;
            core.report.event("event:client-certificate-declined", "");
            return Ok(false);
        };
        let cert = CertificateMsg {
            context: Vec::new(),
            chain: identity.chain.clone(),
            ocsp: None,
        };
        core.emit(HandshakeType::Certificate, &cert.encode()?)?;
        let th = core.transcript.current()?;
        let input = msgs::certificate_verify_input(false, th.as_bytes());
        let signature = identity.key.sign(scheme, &input, core.rng())?;
        let cv = CertificateVerify { scheme, signature };
        core.emit(HandshakeType::CertificateVerify, &cv.encode()?)?;
        core.report.local_signature_scheme = Some(scheme);
        Ok(true)
    }
}

/// Check a pinned end-entity certificate: its key digest and its validity.
pub(crate) fn check_pinned(leaf: &[u8], pins: &[[u8; 32]], now: u64) -> Result<()> {
    let cert = x509::Certificate::parse(leaf)?;
    let d = HashAlg::Sha256.digest(cert.spki_der());
    if !pins.iter().any(|p| ic_core::ct::verify(p, d.as_bytes())) {
        return Err(Error::new(
            ErrorKind::UnknownCa,
            "peer key is not the pinned key",
        ));
    }
    if now < cert.not_before() || now > cert.not_after() {
        return Err(Error::new(
            ErrorKind::CertificateExpired,
            "pinned certificate outside its validity period",
        ));
    }
    // The key must be one we can verify with.
    cert.subject_public_key()?;
    Ok(())
}

/// Groups a client sends shares for first, for a given config (used by tests).
pub fn initial_share_groups(config: &ClientConfig) -> Vec<NamedGroup> {
    let n = config
        .initial_key_shares
        .clamp(1, config.common.groups.len().max(1));
    config
        .common
        .groups
        .iter()
        .copied()
        .take(n)
        .filter(|g| kx::is_implemented(*g))
        .collect()
}
