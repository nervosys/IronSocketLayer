//! The server handshake state machine (RFC 8446 §2, Appendix A.2).
//!
//! ```text
//! WAIT_CH --ClientHello--> (HRR --> WAIT_CH)
//!    | ServerHello, EncryptedExtensions, [CertificateRequest], Certificate,
//!    | CertificateVerify, Finished
//!    v
//! [WAIT_CERT --> WAIT_CV] --> WAIT_FINISHED --Finished--> CONNECTED
//! ```
//!
//! Selection is by server preference: the first configured suite the client
//! offers; the first configured group the client sent a share for, or else a
//! HelloRetryRequest for the first configured group it supports.

use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::config::{ClientAuth, Identity, PeerVerification, ServerConfig};
use crate::conn::{self, Core, Level};
use crate::crypto::hpke;
use crate::crypto::{kx, sign, Output};
use crate::ech;
use crate::enums::{CipherSuite, HandshakeType, NamedGroup, ProtocolVersion, SignatureScheme};
use crate::error::{Error, ErrorKind, Result};
use crate::key_schedule::{self, EarlyStage, MasterStage};
use crate::msgs::{
    self, CertificateMsg, CertificateRequest, CertificateVerify, ClientHello, EncryptedExtensions,
    ServerHello, HRR_RANDOM,
};
use crate::record::suite_params;
use crate::report::HandshakeState as S;
use crate::resumption::{TicketState, PSK_DHE_KE};
use crate::x509::{self, ServerName, Usage};

pub(crate) struct ServerHs {
    config: Arc<ServerConfig>,
    retried: bool,
    retry_group: Option<NamedGroup>,
    retry_cookie: Option<Vec<u8>>,
    first_hello: Option<ClientHello>,
    client_hs_secret: Option<Output>,
    client_ap_secret: Option<Output>,
    requested_client_cert: bool,
    cr_schemes: Vec<SignatureScheme>,
    client_pq_chain: bool,
    client_authenticated: bool,
    master: Option<MasterStage>,
    resumed: Option<TicketState>,
    /// HPKE context after accepting ECH in the first hello.
    ech_ctx: Option<hpke::Context>,
    /// Cipher suite and configuration ID of the accepted outer hello.
    ech_parameters: Option<((u16, u16), u8)>,
    ech_offered: bool,
    ech_accepted: bool,
    /// Whether the client advertised psk_dhe_ke, i.e. can use a ticket.
    client_accepts_tickets: bool,
    /// The client offered post_handshake_auth.
    client_offers_pha: bool,
    /// This session was authenticated by an external PSK.
    external_session: bool,
    /// Accepted 0-RTT: the handshake read key, installed at EndOfEarlyData.
    pending_hs_read: Option<Output>,
    /// An outstanding post-handshake CertificateRequest.
    pending_pha: Option<PendingPha>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum PhaStage {
    Certificate,
    CertificateVerify,
    Finished,
}

/// State of an outstanding post-handshake authentication.
struct PendingPha {
    context: Vec<u8>,
    transcript: crate::conn::Transcript,
    schemes: Vec<SignatureScheme>,
    stage: PhaStage,
    chain: Vec<Vec<u8>>,
    pq_chain: bool,
    scheme: Option<SignatureScheme>,
}

fn unexpected() -> Error {
    Error::new(
        ErrorKind::UnexpectedMessage,
        "handshake message not permitted in this state",
    )
}

impl ServerHs {
    pub(crate) fn new(config: Arc<ServerConfig>) -> Self {
        Self {
            config,
            retried: false,
            retry_group: None,
            retry_cookie: None,
            first_hello: None,
            client_hs_secret: None,
            client_ap_secret: None,
            requested_client_cert: false,
            cr_schemes: Vec::new(),
            client_pq_chain: false,
            client_authenticated: false,
            master: None,
            resumed: None,
            client_accepts_tickets: false,
            ech_ctx: None,
            ech_parameters: None,
            ech_offered: false,
            ech_accepted: false,
            client_offers_pha: false,
            external_session: false,
            pending_hs_read: None,
            pending_pha: None,
        }
    }

    /// Accept one of the client's tickets, if any is ours, current, for this
    /// name and hash, and meets the client-authentication requirement.
    /// Returns its index and state. `REQ-PSK-002`, `REQ-PSK-003`, `REQ-PSK-005`.
    fn try_resume(
        &self,
        core: &Core,
        ch: &ClientHello,
        msg: &[u8],
        hash: crate::crypto::HashAlg,
    ) -> Result<Option<(u16, TicketState)>> {
        let Some(offered) = &ch.psk else {
            return Ok(None);
        };
        if ch.psk_modes.is_empty() {
            return Err(Error::new(
                ErrorKind::MissingExtension,
                "pre_shared_key without psk_key_exchange_modes",
            ));
        }
        let requires_client_cert = matches!(self.config.client_auth, ClientAuth::Required(_));
        // External PSKs first. REQ-EPSK-001, REQ-EPSK-002. REQ-EPSK-006: not
        // when a client certificate is required; the client then gets the
        // certificate handshake, and must present one.
        if ch.psk_modes.contains(&PSK_DHE_KE) && !requires_client_cert {
            for (i, id) in offered.identities.iter().enumerate() {
                let Some(ext) = self
                    .config
                    .external_psks
                    .iter()
                    .find(|p| p.identity == id.identity)
                else {
                    continue;
                };
                if ext.hash != hash {
                    continue;
                }
                let cut = msg.len() - offered.binders_len();
                let th = core.transcript.hash_with(hash, &msg[..cut])?;
                let expected =
                    EarlyStage::new(hash, Some(ext.key()))?.external_binder(th.as_bytes())?;
                let received = offered.binders.get(i).map(|b| b.as_slice()).unwrap_or(&[]);
                if !ic_core::ct::verify(expected.as_bytes(), received) {
                    return Err(Error::new(
                        ErrorKind::DecryptError,
                        "external PSK binder did not verify",
                    ));
                }
                // REQ-EPSK-005: our own ClientHello, reflected back to us.
                if self.config.selfie_guard
                    && crate::resumption::is_own_external_psk_hello(&ch.random)
                {
                    return Err(Error::new(
                        ErrorKind::DecryptError,
                        "reflected ClientHello: this process sent it (Selfie)",
                    ));
                }
                let state = TicketState {
                    suite: CipherSuite::TlsAes128GcmSha256,
                    created: core.now(),
                    lifetime: 0,
                    psk: ext.key().to_vec(),
                    server_name: ch.server_name.clone().unwrap_or_default(),
                    client_authenticated: false,
                    post_quantum_authentication: ext.key().len() >= 32,
                    client_leaf: Vec::new(),
                    external_psk: true,
                    age_add: 0,
                    alpn: Vec::new(),
                    max_early_data: 0,
                    quic_params: Vec::new(),
                };
                return Ok(Some((i as u16, state)));
            }
        }
        // REQ-PSK-001: resumption without a fresh (EC)DHE is never accepted.
        let Some(keys) = &self.config.tickets else {
            return Ok(None);
        };
        if !ch.psk_modes.contains(&PSK_DHE_KE) {
            return Ok(None);
        }
        let now = core.now();
        let sni = ch.server_name.as_deref().unwrap_or("");
        for (i, id) in offered.identities.iter().enumerate() {
            let Some(state) = keys.open(&id.identity) else {
                continue;
            };
            let current = now >= state.created.saturating_sub(60)
                && now < state.created.saturating_add(u64::from(state.lifetime));
            let same_hash = suite_params(state.suite).map(|(_, h)| h) == Some(hash);
            if !current || !same_hash || state.server_name != sni {
                continue;
            }
            if requires_client_cert && !state.client_authenticated {
                continue;
            }
            // The binder proves the client holds the PSK and binds it to this
            // hello; a wrong binder on a ticket we accept is fatal (§4.2.11).
            let cut = msg.len() - offered.binders_len();
            let th = core.transcript.hash_with(hash, &msg[..cut])?;
            let expected =
                EarlyStage::new(hash, Some(&state.psk))?.resumption_binder(th.as_bytes())?;
            let received = offered.binders.get(i).map(|b| b.as_slice()).unwrap_or(&[]);
            if !ic_core::ct::verify(expected.as_bytes(), received) {
                return Err(Error::new(
                    ErrorKind::DecryptError,
                    "PSK binder did not verify",
                ));
            }
            return Ok(Some((i as u16, state)));
        }
        Ok(None)
    }

    /// REQ-EPSK-007: a server with nothing but external PSKs answers an
    /// offered PSK it does not know as it answers a wrong binder, after the
    /// same binder computation, so its identities cannot be enumerated.
    fn refuse_unknown_psk(
        &self,
        core: &Core,
        ch: &ClientHello,
        msg: &[u8],
        hash: crate::crypto::HashAlg,
    ) -> Result<()> {
        let Some(offered) = &ch.psk else {
            return Ok(());
        };
        let cut = msg.len() - offered.binders_len();
        let th = core.transcript.hash_with(hash, &msg[..cut])?;
        let decoy = [0u8; crate::config::MIN_EXTERNAL_PSK_LEN];
        let expected = EarlyStage::new(hash, Some(&decoy))?.external_binder(th.as_bytes())?;
        let received = offered.binders.first().map(|b| b.as_slice()).unwrap_or(&[]);
        let _ = ic_core::ct::verify(expected.as_bytes(), received);
        Err(Error::new(
            ErrorKind::DecryptError,
            "external PSK binder did not verify",
        ))
    }

    pub(crate) fn handle(&mut self, core: &mut Core, ty: HandshakeType, msg: &[u8]) -> Result<()> {
        let body = msg.get(4..).unwrap_or(&[]);
        match (core.state, ty) {
            (S::WaitClientHello, HandshakeType::ClientHello) => {
                self.on_client_hello(core, body, msg)
            }
            (S::WaitCertificate, HandshakeType::Certificate) => {
                self.on_certificate(core, body, msg)
            }
            (S::WaitCertificateVerify, HandshakeType::CertificateVerify) => {
                self.on_certificate_verify(core, body, msg)
            }
            (S::WaitFinished, HandshakeType::EndOfEarlyData) if self.pending_hs_read.is_some() => {
                if !body.is_empty() {
                    return Err(Error::new(ErrorKind::Decode, "EndOfEarlyData has no body"));
                }
                core.transcript.add(msg);
                core.early_budget = None;
                let c_hs = self
                    .pending_hs_read
                    .take()
                    .ok_or(Error::new(ErrorKind::Internal, "secret"))?;
                core.install_read(Level::Handshake, &c_hs)?;
                core.report.event("event:end-of-early-data", "");
                Ok(())
            }
            (S::WaitFinished, HandshakeType::Finished) if self.pending_hs_read.is_some() => {
                Err(Error::new(
                    ErrorKind::UnexpectedMessage,
                    "Finished before EndOfEarlyData",
                ))
            }
            (S::WaitFinished, HandshakeType::Finished) => self.on_finished(core, body, msg),
            (
                S::Connected,
                HandshakeType::Certificate
                | HandshakeType::CertificateVerify
                | HandshakeType::Finished,
            ) if self.pending_pha.is_some() => self.on_post_handshake(core, ty, body, msg),
            _ => Err(unexpected()),
        }
    }

    /// Send a post-handshake CertificateRequest. `REQ-PHA-001`, `REQ-PHA-002`.
    pub(crate) fn request_client_auth(&mut self, core: &mut Core) -> Result<()> {
        if core.state != S::Connected || core.is_quic() {
            return Err(Error::new(
                ErrorKind::InvalidState,
                "post-handshake authentication needs an established TLS-over-TCP connection",
            ));
        }
        if !self.client_offers_pha {
            return Err(Error::new(
                ErrorKind::InvalidState,
                "the client did not offer post_handshake_auth",
            ));
        }
        if self.verification().is_none() {
            return Err(Error::new(
                ErrorKind::InvalidConfig,
                "set ClientAuth::OnDemand to verify post-handshake certificates",
            ));
        }
        if self.pending_pha.is_some() {
            return Err(Error::new(
                ErrorKind::InvalidState,
                "a CertificateRequest is already outstanding",
            ));
        }
        let mut context = alloc::vec![0u8; 32];
        crate::crypto::fill_random(core.rng(), &mut context)?;
        let schemes: Vec<SignatureScheme> = self
            .config
            .common
            .schemes
            .iter()
            .copied()
            .filter(|s| s.allowed_in_handshake())
            .collect();
        let cr = CertificateRequest {
            context: context.clone(),
            sig_algs: schemes.clone(),
        };
        let framed = msgs::frame(HandshakeType::CertificateRequest, &cr.encode()?)?;
        let mut transcript = core.transcript.clone();
        transcript.add(&framed);
        core.send_handshake_bytes(&framed)?;
        core.report.event("event:post-handshake-auth-requested", "");
        self.pending_pha = Some(PendingPha {
            context,
            transcript,
            schemes,
            stage: PhaStage::Certificate,
            chain: Vec::new(),
            pq_chain: false,
            scheme: None,
        });
        Ok(())
    }

    /// Verify the client's post-handshake answer, message by message.
    /// `REQ-PHA-002`, `REQ-PHA-003`, `REQ-PHA-004`.
    fn on_post_handshake(
        &mut self,
        core: &mut Core,
        ty: HandshakeType,
        body: &[u8],
        msg: &[u8],
    ) -> Result<()> {
        let mut p = self
            .pending_pha
            .take()
            .ok_or(Error::new(ErrorKind::Internal, "no pending request"))?;
        match (p.stage, ty) {
            (PhaStage::Certificate, HandshakeType::Certificate) => {
                let cert = CertificateMsg::decode(body)?;
                if cert.context != p.context {
                    return Err(Error::new(
                        ErrorKind::IllegalParameter,
                        "certificate_request_context does not match",
                    ));
                }
                p.transcript.add(msg);
                if cert.chain.is_empty() {
                    p.stage = PhaStage::Finished;
                } else {
                    p.pq_chain = self.verify_client_chain(core, &cert.chain)?;
                    p.chain = cert.chain;
                    p.stage = PhaStage::CertificateVerify;
                }
            }
            (PhaStage::CertificateVerify, HandshakeType::CertificateVerify) => {
                let cv = CertificateVerify::decode(body)?;
                if !p.schemes.contains(&cv.scheme) {
                    return Err(Error::new(
                        ErrorKind::IllegalParameter,
                        "CertificateVerify uses a scheme not requested",
                    ));
                }
                let leaf = p
                    .chain
                    .first()
                    .ok_or(Error::new(ErrorKind::Internal, "chain"))?;
                let key_cert = x509::Certificate::parse(leaf)?;
                let th = p.transcript.current()?;
                let input = msgs::certificate_verify_input(false, th.as_bytes());
                sign::verify(
                    cv.scheme,
                    &key_cert.subject_public_key()?,
                    &input,
                    &cv.signature,
                )?;
                p.transcript.add(msg);
                p.scheme = Some(cv.scheme);
                p.stage = PhaStage::Finished;
            }
            (PhaStage::Finished, HandshakeType::Finished) => {
                let suite = core
                    .suite
                    .ok_or(Error::new(ErrorKind::Internal, "no suite"))?;
                let (_, hash) =
                    suite_params(suite).ok_or(Error::new(ErrorKind::Internal, "suite"))?;
                let base = core.current_secret(false)?;
                let th = p.transcript.current()?;
                key_schedule::verify_finished(hash, base.as_bytes(), th.as_bytes(), body)?;
                match p.scheme {
                    Some(scheme) => {
                        let leaf = p.chain.first().cloned().unwrap_or_default();
                        conn::describe_peer(core, &leaf);
                        // REQ-RPT-004.
                        conn::note_expiry(core);
                        core.report.peer_chain_len = p.chain.len();
                        core.peer_chain = p.chain;
                        core.report.peer_signature_scheme = Some(scheme);
                        core.report
                            .add(crate::report::Property::MutualAuthentication);
                        // REQ-PHA-003: the handshake's rule applies; a client
                        // authenticated without ML-DSA end to end withdraws
                        // the post-quantum authentication claim.
                        if !(p.pq_chain && scheme.is_post_quantum()) {
                            core.report.properties.retain(|q| {
                                *q != crate::report::Property::PostQuantumAuthentication
                            });
                        }
                        core.report.event("event:post-handshake-auth", "verified");
                    }
                    None => {
                        // REQ-PHA-004: a declined request grants nothing.
                        core.report.event("event:post-handshake-auth", "declined");
                    }
                }
                return Ok(());
            }
            _ => return Err(unexpected()),
        }
        self.pending_pha = Some(p);
        Ok(())
    }

    /// Path-validate a client chain under the configured verification;
    /// returns whether it is ML-DSA end to end.
    fn verify_client_chain(&self, core: &mut Core, chain: &[Vec<u8>]) -> Result<bool> {
        let leaf = chain
            .first()
            .ok_or(Error::new(ErrorKind::Decode, "empty chain"))?;
        let now = core.now();
        match self
            .verification()
            .ok_or(Error::new(ErrorKind::Internal, "verification"))?
        {
            PeerVerification::Roots(roots) => {
                let inter: Vec<&[u8]> = chain[1..].iter().map(|c| c.as_slice()).collect();
                let opts = x509::VerifyOptions {
                    now,
                    usage: Usage::ClientAuth,
                    allowed_schemes: &self.config.common.schemes,
                    max_depth: 8,
                    min_rsa_bits: self.config.common.profile.min_rsa_bits(),
                    crls: self.config.common.crls.as_deref(),
                    require_crl: self.config.common.require_crl,
                };
                let report = x509::verify_chain(leaf, &inter, roots, &opts)?;
                conn::note_crl(core, report.crl_checked);
                Ok(
                    !report.schemes.is_empty()
                        && report.schemes.iter().all(|s| s.is_post_quantum()),
                )
            }
            PeerVerification::PinnedSpki { sha256, .. } => {
                let opts = x509::VerifyOptions {
                    now,
                    usage: Usage::ClientAuth,
                    allowed_schemes: &self.config.common.schemes,
                    max_depth: 8,
                    min_rsa_bits: self.config.common.profile.min_rsa_bits(),
                    crls: None,
                    require_crl: false,
                };
                crate::client::check_pinned(leaf, sha256, &opts)?;
                Ok(true)
            }
        }
    }

    /// Decrypt an ECH outer hello, returning the inner hello and its
    /// reconstructed bytes, or `None` to continue with the outer hello.
    /// REQ-ECH-007: accepted ECH retries retain cipher_suite and config_id,
    /// use empty enc, and require the extension (RFC 9849 section 7.1.1).
    fn open_ech(
        &mut self,
        outer: &ClientHello,
        body: &[u8],
    ) -> Result<Option<(ClientHello, Vec<u8>)>> {
        let Some(ech_ext) = &outer.ech else {
            if self.ech_accepted {
                return Err(Error::new(
                    ErrorKind::MissingExtension,
                    "second ClientHello dropped ECH",
                ));
            }
            return Ok(None);
        };
        let msgs::EchHello::Outer {
            suite,
            config_id,
            enc,
            payload,
        } = ech_ext
        else {
            return Err(Error::new(
                ErrorKind::IllegalParameter,
                "inner ECH marker in an outer ClientHello",
            ));
        };
        self.ech_offered = true;
        let Some(server) = self.config.ech.clone() else {
            return Ok(None);
        };
        let (start, len) = outer
            .ech_payload_at
            .ok_or(Error::new(ErrorKind::Internal, "ech payload position"))?;
        let mut aad = body.to_vec();
        aad.get_mut(start..start + len)
            .ok_or(Error::new(ErrorKind::Decode, "ech payload"))?
            .fill(0);
        let encoded = if self.retried && self.ech_accepted {
            if self.ech_parameters != Some((*suite, *config_id)) {
                return Err(Error::new(
                    ErrorKind::IllegalParameter,
                    "second ECH hello changed cipher_suite or config_id",
                ));
            }
            // The second hello must reuse the context, with an empty enc.
            if !enc.is_empty() {
                return Err(Error::new(
                    ErrorKind::IllegalParameter,
                    "second ECH hello with a new enc",
                ));
            }
            let ctx = self
                .ech_ctx
                .as_mut()
                .ok_or(Error::new(ErrorKind::Internal, "hpke context"))?;
            ctx.open(&aad, payload).map_err(|_| {
                Error::new(
                    ErrorKind::DecryptError,
                    "second ClientHelloInner did not decrypt",
                )
            })?
        } else if self.retried {
            return Ok(None);
        } else {
            let Some((cfg, key)) = server.find(*config_id, *suite) else {
                return Ok(None);
            };
            let Ok(mut ctx) = hpke::setup_receiver(enc, key, &cfg.hpke_info(), suite.1) else {
                return Ok(None);
            };
            let Ok(encoded) = ctx.open(&aad, payload) else {
                return Ok(None);
            };
            self.ech_ctx = Some(ctx);
            encoded
        };
        let inner_body = ech::reconstruct_inner(&encoded, body, &outer.session_id)?;
        let inner = ClientHello::decode(&inner_body)?;
        if inner.ech != Some(msgs::EchHello::Inner) {
            return Err(Error::new(
                ErrorKind::IllegalParameter,
                "ClientHelloInner lacks the inner ECH marker",
            ));
        }
        self.ech_accepted = true;
        self.ech_parameters = Some((*suite, *config_id));
        Ok(Some((
            inner,
            msgs::frame(HandshakeType::ClientHello, &inner_body)?,
        )))
    }

    /// Decide whether to accept the client's 0-RTT data. `REQ-0RTT-001`,
    /// `REQ-0RTT-002`: only on our own ticket, the first identity, the same
    /// suite and ALPN, no retry, within the freshness window, and never twice.
    fn accept_early(
        &self,
        core: &mut Core,
        ch: &ClientHello,
        resumption: &Option<(u16, TicketState)>,
        suite: CipherSuite,
        alpn: Option<&[u8]>,
    ) -> Result<bool> {
        let (Some(policy), true, false) = (&self.config.early_data, ch.early_data, self.retried)
        else {
            return Ok(false);
        };
        let Some((0, st)) = resumption else {
            return Ok(false);
        };
        // REQ-0RTT-005: QUIC tickets carry 0xffffffff, and the transport
        // parameters must be exactly those the ticket was issued under.
        if core.is_quic()
            && (st.max_early_data != u32::MAX
                || Some(st.quic_params.clone()) != core.local_quic_params())
        {
            return Ok(false);
        }
        // REQ-0RTT-003: the client was promised the ticket's limit, and is
        // held to it once its data is accepted. A ticket promising more
        // than the current policy allows is declined, never cut short.
        if st.external_psk
            || st.max_early_data == 0
            || (!core.is_quic() && st.max_early_data > policy.max_early_data)
            || st.suite != suite
            || alpn.unwrap_or(&[]) != st.alpn.as_slice()
        {
            return Ok(false);
        }
        let Some(offered) = &ch.psk else {
            return Ok(false);
        };
        let (Some(id), Some(binder)) = (offered.identities.first(), offered.binders.first()) else {
            return Ok(false);
        };
        let now = core.now();
        let client_age_ms = u64::from(id.obfuscated_ticket_age.wrapping_sub(st.age_add));
        let server_age_ms = now.saturating_sub(st.created).saturating_mul(1000);
        // The server knows the age to the second; allow that on top of the skew.
        if client_age_ms.abs_diff(server_age_ms) > u64::from(policy.max_skew_ms) + 1000 {
            return Ok(false);
        }
        let key = crate::crypto::HashAlg::Sha256.digest(binder);
        let mut k = [0u8; 32];
        k.copy_from_slice(key.as_bytes());
        let expires = now + u64::from(policy.max_skew_ms) / 1000 + 2;
        let fresh = policy.replay.insert_fresh(k, now, expires);
        // REQ-0RTT-006: say why, when the guard is full rather than a replay.
        if !fresh && policy.replay.is_full(now) {
            core.report.event("event:replay-guard-full", "");
        }
        Ok(fresh)
    }

    fn choose_suite(&self, ch: &ClientHello) -> Result<CipherSuite> {
        let mut ours = self.config.common.suites.clone();
        // A client offering one of our external PSKs gets a suite with that
        // PSK's hash, if one is possible.
        let psk_hash = ch.psk.as_ref().and_then(|o| {
            o.identities.iter().find_map(|id| {
                self.config
                    .external_psks
                    .iter()
                    .find(|p| p.identity == id.identity)
                    .map(|p| p.hash)
            })
        });
        if let Some(h) = psk_hash {
            let fits: Vec<CipherSuite> = ours
                .iter()
                .copied()
                .filter(|s| suite_params(*s).map(|(_, x)| x) == Some(h) && ch.suites.contains(s))
                .collect();
            if !fits.is_empty() {
                ours = fits;
            }
        }
        let ours = &ours;
        // REQ-NEG-001: the server's preference order, or the client's when
        // the server is configured not to prefer its own.
        let pick = if self.config.prefer_server_order {
            ours.iter().copied().find(|s| ch.suites.contains(s))
        } else {
            ch.suites.iter().copied().find(|s| ours.contains(s))
        };
        pick.ok_or(Error::new(
            ErrorKind::HandshakeFailure,
            "no cipher suite in common",
        ))
    }

    fn choose_identity(&self, ch: &ClientHello) -> Result<(Identity, SignatureScheme, bool)> {
        let schemes = &self.config.common.schemes;
        let by_name = ch.server_name.as_deref().and_then(|sni| {
            self.config.identities.iter().find(|id| {
                id.chain
                    .first()
                    .map(|leaf| x509::verify_name(leaf, &ServerName::Dns(sni)).is_ok())
                    .unwrap_or(false)
                    && id.key.choose_scheme(&ch.sig_algs, schemes).is_some()
            })
        });
        if let Some(id) = by_name {
            let s = id
                .key
                .choose_scheme(&ch.sig_algs, schemes)
                .ok_or(Error::new(ErrorKind::Internal, "scheme"))?;
            return Ok((id.clone(), s, true));
        }
        // REQ-NEG-002: a name we hold no certificate for is refused, not
        // answered with a certificate for another name (RFC 6066 §3).
        if let Some(sni) = ch.server_name.as_deref() {
            let covered = self.config.identities.iter().any(|id| {
                id.chain
                    .first()
                    .is_some_and(|leaf| x509::verify_name(leaf, &ServerName::Dns(sni)).is_ok())
            });
            if !covered && !self.config.sni_fallback {
                return Err(Error::new(
                    ErrorKind::UnrecognizedName,
                    "no certificate for the requested server name",
                ));
            }
        }
        for id in &self.config.identities {
            if let Some(s) = id.key.choose_scheme(&ch.sig_algs, schemes) {
                return Ok((id.clone(), s, false));
            }
        }
        Err(Error::new(
            ErrorKind::HandshakeFailure,
            "no certificate the client can verify",
        ))
    }

    fn choose_alpn(&self, core: &Core, ch: &ClientHello) -> Result<Option<Vec<u8>>> {
        let ours = &self.config.common.alpn;
        if ours.is_empty() || ch.alpn.is_empty() {
            if core.is_quic() {
                return Err(Error::new(
                    ErrorKind::NoApplicationProtocol,
                    "QUIC requires ALPN (RFC 9001 §8.1)",
                ));
            }
            if !ours.is_empty() && self.config.common.require_alpn {
                return Err(Error::new(
                    ErrorKind::NoApplicationProtocol,
                    "client offered no ALPN protocol",
                ));
            }
            return Ok(None);
        }
        ours.iter()
            .find(|p| ch.alpn.contains(p))
            .cloned()
            .map(Some)
            .ok_or(Error::new(
                ErrorKind::NoApplicationProtocol,
                "no ALPN protocol in common",
            ))
    }

    fn on_client_hello(&mut self, core: &mut Core, body: &[u8], msg: &[u8]) -> Result<()> {
        let outer = ClientHello::decode(body)?;
        let (ch, inner_msg) = match self.open_ech(&outer, body)? {
            Some((inner, m)) => (inner, Some(m)),
            None => (outer, None),
        };
        let msg: &[u8] = inner_msg.as_deref().unwrap_or(msg);
        // REQ-0RTT-004: until the early data is accepted, the 0-RTT records
        // that follow this hello are skipped -- including after a
        // HelloRetryRequest, which rejects them.
        if ch.early_data && !self.retried {
            let bound = self
                .config
                .early_data
                .as_ref()
                .map(|p| p.max_early_data as usize)
                .unwrap_or(0);
            core.skip_early_budget = bound.max(16_384).saturating_add(16 * 1024);
        }
        core.report.ech = match (self.ech_offered, self.ech_accepted) {
            (false, _) => "ech:not-offered",
            (true, true) => "ech:accepted",
            (true, false) => "ech:rejected",
        };
        // REQ-MSG-006: a ClientHello must follow RFC 8446's rules.
        if !ch.versions.contains(&ProtocolVersion::Tls13) {
            return Err(Error::new(
                ErrorKind::ProtocolVersion,
                "client does not offer TLS 1.3",
            ));
        }
        if ch.sig_algs.is_empty() {
            return Err(Error::new(
                ErrorKind::MissingExtension,
                "ClientHello without signature_algorithms",
            ));
        }
        if ch.groups.is_empty() || (ch.key_shares.is_empty() && ch.groups.is_empty()) {
            return Err(Error::new(
                ErrorKind::MissingExtension,
                "ClientHello without supported_groups",
            ));
        }
        // Every share must be for a group the client says it supports (§4.2.8).
        if ch.key_shares.iter().any(|(g, _)| !ch.groups.contains(g)) {
            return Err(Error::new(
                ErrorKind::IllegalParameter,
                "key share for a group not in supported_groups",
            ));
        }
        match (core.is_quic(), &ch.quic_params) {
            (true, Some(p)) => core.set_peer_quic_params(p.clone()),
            (true, None) => {
                return Err(Error::new(
                    ErrorKind::MissingExtension,
                    "client sent no QUIC transport parameters",
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
        if core.is_quic() && !ch.session_id.is_empty() {
            return Err(Error::new(
                ErrorKind::IllegalParameter,
                "QUIC ClientHello with a legacy_session_id",
            ));
        }

        if self.retried {
            self.check_second_hello(&ch)?;
        }
        let suite = match (self.retried, core.suite) {
            (true, Some(s)) => s,
            _ => self.choose_suite(&ch)?,
        };
        let (_, hash) = suite_params(suite).ok_or(Error::new(ErrorKind::Internal, "suite"))?;
        core.report.server_name = ch.server_name.clone();

        // Group: a share we can use now, or a retry for one the client supports.
        let groups = &self.config.common.groups;
        let share = groups.iter().find_map(|g| {
            ch.key_shares
                .iter()
                .find(|(cg, _)| cg == g)
                .map(|(cg, s)| (*cg, s.clone()))
        });
        let Some((group, client_share)) = share else {
            let target = groups.iter().copied().find(|g| ch.groups.contains(g));
            return match (target, self.retried) {
                (Some(g), false) => self.send_retry(core, ch, msg, suite, g),
                (Some(_), true) => Err(Error::new(
                    ErrorKind::IllegalParameter,
                    "second ClientHello still lacks the share",
                )),
                (None, _) => Err(Error::new(
                    ErrorKind::HandshakeFailure,
                    "no key exchange group in common",
                )),
            };
        };
        let resumption = self.try_resume(core, &ch, msg, hash)?;
        if resumption.is_none() && self.config.identities.is_empty() {
            self.refuse_unknown_psk(core, &ch, msg, hash)?;
        }
        self.client_accepts_tickets = ch.psk_modes.contains(&PSK_DHE_KE);
        self.client_offers_pha = ch.post_handshake_auth && !core.is_quic();
        // A resumed session was authenticated when its ticket was issued; no
        // certificate is chosen or sent.
        let auth = match resumption {
            Some(_) => None,
            None => Some(self.choose_identity(&ch)?),
        };
        let sni_matched = match (&auth, &resumption) {
            (Some((_, _, m)), _) => *m,
            (None, Some((_, st))) => !st.server_name.is_empty(),
            (None, None) => false,
        };
        let alpn = self.choose_alpn(core, &ch)?;
        let early_ok = self.accept_early(core, &ch, &resumption, suite, alpn.as_deref())?;
        if early_ok {
            // Accepted early data must decrypt; nothing is skipped.
            core.skip_early_budget = 0;
        }

        let (server_share, shared) = kx::respond(group, &client_share, core.rng())?;
        let mut random = [0u8; 32];
        crate::crypto::fill_random(core.rng(), &mut random)?;
        let mut sh = ServerHello {
            random,
            session_id: ch.session_id.clone(),
            suite: Some(suite),
            selected_version: Some(ProtocolVersion::Tls13),
            key_share: Some((group, server_share)),
            selected_psk: resumption.as_ref().map(|(i, _)| *i),
            ..Default::default()
        };
        core.suite = Some(suite);
        core.transcript.start(hash)?;
        core.transcript.add(msg);
        let ch_hash = core.transcript.current()?;
        if self.ech_accepted {
            // REQ-ECH-002: the last 8 bytes of the random confirm acceptance.
            sh.random[24..].fill(0);
            let zeroed = msgs::frame(HandshakeType::ServerHello, &sh.encode()?)?;
            let th = core.transcript.hash_with(hash, &zeroed)?;
            let conf = ech::confirmation(hash, &ch.random, ech::ACCEPT_LABEL, th.as_bytes())?;
            sh.random[24..].copy_from_slice(&conf);
            core.report
                .add(crate::report::Property::EncryptedClientHello);
        }
        core.emit(HandshakeType::ServerHello, &sh.encode()?)?;
        let compat = !ch.session_id.is_empty() && !core.is_quic();
        if compat {
            core.send_ccs();
        }
        core.allow_ccs(!core.is_quic());

        let psk = resumption.as_ref().map(|(_, st)| st.psk.as_slice());
        let hs = EarlyStage::new(hash, psk)?.into_handshake(shared.get())?;
        let th = core.transcript.current()?;
        let c_hs = hs.client_traffic(th.as_bytes())?;
        let s_hs = hs.server_traffic(th.as_bytes())?;
        core.install_write(Level::Handshake, &s_hs)?;
        if early_ok {
            let psk = resumption.as_ref().map(|(_, st)| st.psk.as_slice());
            let early = EarlyStage::new(hash, psk)?.client_early_traffic(ch_hash.as_bytes())?;
            if core.is_quic() {
                // QUIC reads 0-RTT packets with this key and Handshake
                // packets with the handshake key, side by side.
                core.export_quic_key(Level::Early, false, &early)?;
                core.install_read(Level::Handshake, &c_hs)?;
            } else {
                core.install_read(Level::Early, &early)?;
                self.pending_hs_read = Some(c_hs.clone());
            }
            core.early_budget = resumption
                .as_ref()
                .map(|(_, st)| st.max_early_data as usize);
            core.report.early_data = "early-data:accepted";
            core.report.event("event:early-data-accepted", "");
        } else {
            if ch.early_data {
                core.report.early_data = "early-data:rejected";
            }
            core.install_read(Level::Handshake, &c_hs)?;
        }
        core.report.version = Some(ProtocolVersion::Tls13);
        core.report.suite = Some(suite);
        core.report.group = Some(group);
        core.report.verification = match &self.config.client_auth {
            ClientAuth::None => "verification:none-requested",
            ClientAuth::Optional(v) | ClientAuth::Required(v) | ClientAuth::OnDemand(v) => v.id(),
        };

        // RFC 8449: answer only a client that sent the extension, never under QUIC.
        let record_size_limit = match (ch.record_size_limit, core.is_quic()) {
            (Some(theirs), false) => {
                let ours = self
                    .config
                    .common
                    .record_size_limit
                    .unwrap_or(msgs::MAX_RECORD_SIZE_LIMIT);
                core.peer_record_limit = Some(usize::from(theirs));
                Some(ours)
            }
            _ => None,
        };
        // ECH offered and not accepted: give the client keys to retry with.
        let ech_retry_configs = match (&self.config.ech, self.ech_offered && !self.ech_accepted) {
            (Some(server), true) => Some(server.config_list().to_vec()),
            _ => None,
        };
        let ee = EncryptedExtensions {
            early_data: early_ok,
            ech_retry_configs,
            record_size_limit,
            alpn: alpn.clone(),
            server_name_ack: sni_matched,
            quic_params: core.local_quic_params(),
            ..Default::default()
        };
        core.emit(HandshakeType::EncryptedExtensions, &ee.encode()?)?;
        // Our limit binds the client's records from its next flight on.
        core.local_record_limit = record_size_limit.map(usize::from);
        core.report.alpn = alpn;

        if let Some((_, state)) = resumption
            .clone()
            .filter(|(_, st)| st.external_psk && st.lifetime == 0)
        {
            // An external PSK, not a ticket: nobody resumed anything.
            core.report.verification = "verification:external-psk";
            core.report.event("event:external-psk-accepted", "");
            self.external_session = true;
            self.resumed = Some(state);
        } else if let Some((_, state)) = resumption {
            core.report.resumed = true;
            core.report.event("event:session-resumed", suite.id());
            if !state.client_leaf.is_empty() {
                conn::describe_peer(core, &state.client_leaf);
            }
            self.client_authenticated = state.client_authenticated;
            self.resumed = Some(state);
        } else if matches!(
            self.config.client_auth,
            ClientAuth::Optional(_) | ClientAuth::Required(_)
        ) {
            self.cr_schemes = self
                .config
                .common
                .schemes
                .iter()
                .copied()
                .filter(|s| s.allowed_in_handshake())
                .collect();
            let cr = CertificateRequest {
                context: Vec::new(),
                sig_algs: self.cr_schemes.clone(),
            };
            core.emit(HandshakeType::CertificateRequest, &cr.encode()?)?;
            self.requested_client_cert = true;
        }

        if let Some((identity, scheme, _)) = auth {
            // Staple only when asked (RFC 8446 §4.4.2.1).
            let ocsp = match (&identity.ocsp, ch.status_request) {
                (Some(r), true) => Some(r.as_ref().clone()),
                _ => None,
            };
            let stapled = ocsp.is_some();
            conn::describe_local(core, &identity.chain);
            let cert = CertificateMsg {
                context: Vec::new(),
                chain: identity.chain.clone(),
                ocsp,
            };
            if stapled {
                core.report.event("event:ocsp-stapled", "");
            }
            core.emit(HandshakeType::Certificate, &cert.encode()?)?;
            let th = core.transcript.current()?;
            let input = msgs::certificate_verify_input(true, th.as_bytes());
            let signature = identity.key.sign(scheme, &input, core.rng())?;
            core.emit(
                HandshakeType::CertificateVerify,
                &CertificateVerify { scheme, signature }.encode()?,
            )?;
            core.report.local_signature_scheme = Some(scheme);
        }

        let th = core.transcript.current()?;
        let fin = key_schedule::finished_mac(hash, s_hs.as_bytes(), th.as_bytes())?;
        core.emit(HandshakeType::Finished, fin.as_bytes())?;

        let master = hs.into_master()?;
        let th = core.transcript.current()?;
        let s_ap = master.server_traffic(th.as_bytes())?;
        self.client_ap_secret = Some(master.client_traffic(th.as_bytes())?);
        core.exporter_secret = Some(master.exporter(th.as_bytes())?);
        core.install_write(Level::Application, &s_ap)?;
        self.master = Some(master);
        self.client_hs_secret = Some(c_hs);
        core.set_state(if self.requested_client_cert {
            S::WaitCertificate
        } else {
            S::WaitFinished
        });
        Ok(())
    }

    fn send_retry(
        &mut self,
        core: &mut Core,
        ch: ClientHello,
        msg: &[u8],
        suite: CipherSuite,
        group: NamedGroup,
    ) -> Result<()> {
        let (_, hash) = suite_params(suite).ok_or(Error::new(ErrorKind::Internal, "suite"))?;
        let cookie = if self.config.retry_cookie {
            let mut c = alloc::vec![0u8; 32];
            crate::crypto::fill_random(core.rng(), &mut c)?;
            Some(c)
        } else {
            None
        };
        let mut hrr = ServerHello {
            random: HRR_RANDOM,
            session_id: ch.session_id.clone(),
            suite: Some(suite),
            selected_version: Some(ProtocolVersion::Tls13),
            hrr_group: Some(group),
            cookie: cookie.clone(),
            ..Default::default()
        };
        core.suite = Some(suite);
        core.transcript.start(hash)?;
        core.transcript.add(msg);
        core.transcript.rollup_for_retry()?;
        if self.ech_accepted {
            hrr.ech_confirmation = Some([0; 8]);
            let zeroed = msgs::frame(HandshakeType::ServerHello, &hrr.encode()?)?;
            let th = core.transcript.hash_with(hash, &zeroed)?;
            hrr.ech_confirmation = Some(ech::confirmation(
                hash,
                &ch.random,
                ech::HRR_ACCEPT_LABEL,
                th.as_bytes(),
            )?);
        }
        core.emit(HandshakeType::ServerHello, &hrr.encode()?)?;
        if !ch.session_id.is_empty() && !core.is_quic() {
            core.send_ccs();
        }
        core.allow_ccs(!core.is_quic());
        self.retried = true;
        self.retry_group = Some(group);
        self.retry_cookie = cookie;
        self.first_hello = Some(ch);
        core.report.hello_retry = true;
        core.report.event("event:hello-retry", group.id());
        Ok(())
    }

    /// ClientHello2 must be ClientHello1 with only the permitted changes
    /// (§4.1.2): the requested share and the cookie as sent. `REQ-MSG-005`.
    /// REQ-MSG-015: a second ClientHello never carries an early_data indication.
    /// REQ-MSG-016: decoded negotiation and capability extensions stay unchanged on retry.
    fn check_second_hello(&self, ch: &ClientHello) -> Result<()> {
        let first = self
            .first_hello
            .as_ref()
            .ok_or(Error::new(ErrorKind::Internal, "no first hello"))?;
        let illegal = |m| Error::new(ErrorKind::IllegalParameter, m);
        if ch.early_data {
            return Err(illegal("early_data in second ClientHello"));
        }
        if ch.server_name != first.server_name
            || ch.groups != first.groups
            || ch.sig_algs != first.sig_algs
            || ch.sig_algs_cert != first.sig_algs_cert
            || ch.versions != first.versions
            || ch.alpn != first.alpn
            || ch.quic_params != first.quic_params
            || ch.record_size_limit != first.record_size_limit
            || ch.status_request != first.status_request
            || ch.post_handshake_auth != first.post_handshake_auth
            || ch.psk_modes != first.psk_modes
        {
            return Err(illegal("second ClientHello changed an immutable extension"));
        }
        if ch.random != first.random
            || ch.session_id != first.session_id
            || ch.suites != first.suites
        {
            return Err(illegal("second ClientHello changed a field it must not"));
        }
        match self.retry_group {
            Some(g) if ch.key_shares.len() != 1 || ch.key_shares[0].0 != g => {
                return Err(illegal(
                    "second ClientHello does not carry exactly the requested share",
                ))
            }
            _ => {}
        }
        // The cookie is no secret (it went out in the clear), but whatever a
        // peer sends that is checked against a value of ours is compared in
        // constant time, so that no case needs arguing.
        let cookie_ok = match (&ch.cookie, &self.retry_cookie) {
            (Some(got), Some(ours)) => ic_core::ct::verify(got, ours),
            (None, None) => true,
            _ => false,
        };
        if !cookie_ok {
            return Err(illegal("cookie does not match"));
        }
        Ok(())
    }

    fn verification(&self) -> Option<&PeerVerification> {
        match &self.config.client_auth {
            ClientAuth::None => None,
            ClientAuth::Optional(v) | ClientAuth::Required(v) | ClientAuth::OnDemand(v) => Some(v),
        }
    }

    fn on_certificate(&mut self, core: &mut Core, body: &[u8], msg: &[u8]) -> Result<()> {
        let cert = CertificateMsg::decode(body)?;
        if !cert.context.is_empty() {
            return Err(Error::new(
                ErrorKind::IllegalParameter,
                "client Certificate context must be empty",
            ));
        }
        core.transcript.add(msg);
        let Some(leaf) = cert.chain.first() else {
            if matches!(self.config.client_auth, ClientAuth::Required(_)) {
                return Err(Error::new(
                    ErrorKind::CertificateRequired,
                    "client sent no certificate",
                ));
            }
            core.report.event("event:client-certificate-absent", "");
            core.set_state(S::WaitFinished);
            return Ok(());
        };
        let now = core.now();
        let v = self
            .verification()
            .ok_or(Error::new(ErrorKind::Internal, "verification"))?;
        match v {
            PeerVerification::Roots(roots) => {
                let inter: Vec<&[u8]> = cert.chain[1..].iter().map(|c| c.as_slice()).collect();
                let opts = x509::VerifyOptions {
                    now,
                    usage: Usage::ClientAuth,
                    allowed_schemes: &self.config.common.schemes,
                    max_depth: 8,
                    min_rsa_bits: self.config.common.profile.min_rsa_bits(),
                    crls: self.config.common.crls.as_deref(),
                    require_crl: self.config.common.require_crl,
                };
                let report = x509::verify_chain(leaf, &inter, roots, &opts)?;
                conn::note_crl(core, report.crl_checked);
                self.client_pq_chain = !report.schemes.is_empty()
                    && report.schemes.iter().all(|s| s.is_post_quantum());
                core.report.peer_chain_min_bits = Some(report.min_classical_bits);
            }
            PeerVerification::PinnedSpki { sha256, .. } => {
                let opts = x509::VerifyOptions {
                    now,
                    usage: Usage::ClientAuth,
                    allowed_schemes: &self.config.common.schemes,
                    max_depth: 8,
                    min_rsa_bits: self.config.common.profile.min_rsa_bits(),
                    crls: None,
                    require_crl: false,
                };
                crate::client::check_pinned(leaf, sha256, &opts)?;
                self.client_pq_chain = true;
            }
        }
        conn::describe_peer(core, leaf);
        core.report.peer_chain_len = cert.chain.len();
        core.peer_chain = cert.chain;
        core.set_state(S::WaitCertificateVerify);
        Ok(())
    }

    fn on_certificate_verify(&mut self, core: &mut Core, body: &[u8], msg: &[u8]) -> Result<()> {
        let cv = CertificateVerify::decode(body)?;
        if !self.cr_schemes.contains(&cv.scheme) {
            return Err(Error::new(
                ErrorKind::IllegalParameter,
                "CertificateVerify uses a scheme not requested",
            ));
        }
        let leaf = core
            .peer_chain
            .first()
            .ok_or(Error::new(ErrorKind::Internal, "no chain"))?;
        let cert = x509::Certificate::parse(leaf)?;
        let key = cert.subject_public_key()?;
        let th = core.transcript.current()?;
        let input = msgs::certificate_verify_input(false, th.as_bytes());
        sign::verify(cv.scheme, &key, &input, &cv.signature)?;
        self.client_pq_chain &= cv.scheme.is_post_quantum();
        self.client_authenticated = true;
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
        let c_hs = self
            .client_hs_secret
            .take()
            .ok_or(Error::new(ErrorKind::Internal, "no secret"))?;
        let th = core.transcript.current()?;
        key_schedule::verify_finished(hash, c_hs.as_bytes(), th.as_bytes(), body)?;
        core.transcript.add(msg);
        let c_ap = self
            .client_ap_secret
            .take()
            .ok_or(Error::new(ErrorKind::Internal, "no secret"))?;
        core.install_read(Level::Application, &c_ap)?;
        let pinned = matches!(
            self.verification(),
            Some(PeerVerification::PinnedSpki { .. })
        ) && self.client_authenticated;
        let local_pq = core
            .report
            .local_signature_scheme
            .is_some_and(|s| s.is_post_quantum());
        let pq_auth = match &self.resumed {
            Some(st) => st.post_quantum_authentication,
            None => local_pq && (!self.client_authenticated || self.client_pq_chain),
        };
        let cert_auth = !self.external_session
            && !self
                .resumed
                .as_ref()
                .map(|r| r.external_psk)
                .unwrap_or(false);
        if !cert_auth && self.external_session {
            core.report.verification = "verification:external-psk";
        }
        conn::finish_report(core, pq_auth, self.client_authenticated, pinned, cert_auth)?;
        self.send_tickets(core, suite, hash, pq_auth)
    }

    /// Issue session tickets after the handshake (§4.6.1).
    fn send_tickets(
        &mut self,
        core: &mut Core,
        suite: CipherSuite,
        hash: crate::crypto::HashAlg,
        pq_auth: bool,
    ) -> Result<()> {
        let (Some(keys), Some(master)) = (self.config.tickets.clone(), self.master.take()) else {
            return Ok(());
        };
        if !self.client_accepts_tickets {
            return Ok(());
        }
        let th = core.transcript.current()?;
        let res = master.resumption(th.as_bytes())?;
        let lifetime = self
            .config
            .ticket_lifetime
            .min(crate::resumption::MAX_TICKET_LIFETIME);
        let client_leaf = if self.client_authenticated {
            match &self.resumed {
                Some(st) => st.client_leaf.clone(),
                None => core.peer_chain.first().cloned().unwrap_or_default(),
            }
        } else {
            Vec::new()
        };
        for n in 0..self.config.tickets_per_handshake {
            let nonce = alloc::vec![n];
            let psk = key_schedule::resumption_psk(hash, res.as_bytes(), &nonce)?;
            let state = TicketState {
                suite,
                created: core.now(),
                lifetime,
                psk: psk.as_bytes().to_vec(),
                server_name: core.report.server_name.clone().unwrap_or_default(),
                client_authenticated: self.client_authenticated,
                post_quantum_authentication: pq_auth,
                client_leaf: client_leaf.clone(),
                external_psk: self
                    .resumed
                    .as_ref()
                    .map(|r| r.external_psk)
                    .unwrap_or(false),
                age_add: 0,
                alpn: core.report.alpn.clone().unwrap_or_default(),
                max_early_data: match (&self.config.early_data, core.is_quic()) {
                    (Some(_), true) => u32::MAX,
                    (Some(p), false) => p.max_early_data,
                    (None, _) => 0,
                },
                quic_params: core.local_quic_params().unwrap_or_default(),
            };
            let mut age_add = [0u8; 4];
            crate::crypto::fill_random(core.rng(), &mut age_add)?;
            let mut state = state;
            state.age_add = u32::from_be_bytes(age_add);
            let max_early_data = state.max_early_data;
            let ticket = keys.seal(&state, core.rng())?;
            let nst = msgs::NewSessionTicket {
                lifetime,
                age_add: state.age_add,
                nonce,
                ticket,
                max_early_data: (max_early_data > 0).then_some(max_early_data),
            };
            // Post-handshake: sent under the application key, not transcribed.
            let msg = msgs::frame(HandshakeType::NewSessionTicket, &nst.encode()?)?;
            core.send_handshake_bytes(&msg)?;
            core.report.event("event:ticket-sent", "");
        }
        Ok(())
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    //! Messages that arrive only under record protection over TCP, handed to
    //! the state machine as the record layer would after decryption.

    use super::*;
    use crate::config::{ClientConfig, EarlyDataPolicy, Profile};
    use crate::conn::{Connection, Role};
    use crate::crypto::sign::{KeyKind, SigningKey};
    use crate::x509::{CertificateParams, RootStore};

    fn now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    /// A self-signed end-entity certificate for `usage`, and its key.
    fn certificate(cn: &str, dns: &[&str], usage: Usage) -> (Vec<u8>, SigningKey) {
        let mut rng = ic_drbg::Rng::from_os().unwrap();
        let key = SigningKey::generate(KeyKind::EcdsaP256, &mut rng).unwrap();
        let t = now();
        let cert = x509::self_signed(
            &CertificateParams {
                subject_cn: cn,
                dns_names: dns,
                ip_addresses: &[],
                not_before: t - 60,
                not_after: t + 3600,
                is_ca: false,
                path_len: None,
                usage: &[usage],
                serial: [3; 16],
            },
            &key,
            &mut rng,
        )
        .unwrap();
        (cert, key)
    }

    fn configs() -> (ClientConfig, ServerConfig) {
        let (cert, key) = certificate("s.test", &["s.test"], Usage::ServerAuth);
        let mut roots = RootStore::new();
        roots.add_der(&cert).unwrap();
        let sc = ServerConfig::new(
            Profile::Default,
            Identity::new(alloc::vec![cert], key).unwrap(),
        )
        .unwrap();
        let cc = ClientConfig::new(Profile::Default, roots).unwrap();
        (cc, sc)
    }

    fn pump(c: &mut Connection, s: &mut Connection) {
        for _ in 0..4 {
            s.read_tls(&c.take_tls()).unwrap();
            c.read_tls(&s.take_tls()).unwrap();
        }
    }

    /// Feed one plaintext handshake message to the server's state machine.
    fn inject(s: &mut Connection, ty: HandshakeType, body: &[u8]) -> Result<()> {
        let m = msgs::frame(ty, body).unwrap();
        s.core.hs_buf.extend_from_slice(&m);
        s.process_handshake()
    }

    /// A server that has just accepted 0-RTT from a resuming client.
    fn accepted_early() -> Connection {
        let (mut cc, mut sc) = configs();
        cc.early_data = true;
        sc.early_data = Some(EarlyDataPolicy::new(16_384));
        let (cc, sc) = (Arc::new(cc), Arc::new(sc));
        let mut c = Connection::client(cc.clone(), "s.test").unwrap();
        let mut s = Connection::server(sc.clone()).unwrap();
        pump(&mut c, &mut s);
        assert_eq!(c.report().tickets_received, 1);
        let mut c = Connection::client_with_early_data(cc, "s.test", b"early").unwrap();
        let mut s = Connection::server(sc).unwrap();
        s.read_tls(&c.take_tls()).unwrap();
        assert_eq!(s.report().early_data, "early-data:accepted");
        assert_eq!(s.state(), S::WaitFinished);
        s
    }

    /// REQ-0RTT-003: accepted early data ends with an EndOfEarlyData that
    /// has no body (RFC 8446 §4.5) and that precedes the client's Finished;
    /// a body is a decode_error, a Finished first is unexpected_message.
    #[test]
    fn end_of_early_data_is_empty_and_comes_before_finished() {
        let mut s = accepted_early();
        let e = inject(&mut s, HandshakeType::EndOfEarlyData, &[0]).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Decode);
        assert_eq!(e.context(), "EndOfEarlyData has no body");

        let mut s = accepted_early();
        let e = inject(&mut s, HandshakeType::Finished, &[0; 32]).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::UnexpectedMessage);
        assert_eq!(e.context(), "Finished before EndOfEarlyData");

        // The conforming order is accepted.
        let mut s = accepted_early();
        inject(&mut s, HandshakeType::EndOfEarlyData, &[]).unwrap();
        assert!(s
            .report()
            .events
            .iter()
            .any(|e| e.id == "event:end-of-early-data"));
    }

    /// REQ-PHA-003, REQ-SIG-002: a post-handshake CertificateVerify must use
    /// a scheme the CertificateRequest offered; PKCS#1 v1.5, never offered
    /// for a handshake signature, is illegal_parameter before any signature
    /// is checked.
    #[test]
    fn a_step_up_certificate_verify_must_use_a_requested_scheme() {
        let (cc, sc) = configs();
        let (agent, agent_key) = certificate("agent", &[], Usage::ClientAuth);
        let mut anchors = RootStore::new();
        anchors.add_der(&agent).unwrap();
        let mut cc =
            cc.with_identity(Identity::new(alloc::vec![agent.clone()], agent_key).unwrap());
        cc.post_handshake_auth = true;
        let sc = sc.with_client_auth(ClientAuth::OnDemand(PeerVerification::Roots(anchors)));
        let mut c = Connection::client(Arc::new(cc), "s.test").unwrap();
        let mut s = Connection::server(Arc::new(sc)).unwrap();
        pump(&mut c, &mut s);
        assert_eq!(s.state(), S::Connected);
        s.request_client_auth().unwrap();
        let _request = s.take_tls();
        let (context, schemes) = match &s.role {
            Role::Server(hs) => {
                let p = hs.pending_pha.as_ref().unwrap();
                (p.context.clone(), p.schemes.clone())
            }
            Role::Client(_) => unreachable!(),
        };
        assert!(!schemes.contains(&SignatureScheme::RsaPkcs1Sha256));
        let cert = CertificateMsg {
            context,
            chain: alloc::vec![agent],
            ocsp: None,
        };
        inject(&mut s, HandshakeType::Certificate, &cert.encode().unwrap()).unwrap();
        let cv = CertificateVerify {
            scheme: SignatureScheme::RsaPkcs1Sha256,
            signature: alloc::vec![0; 256],
        };
        let e = inject(
            &mut s,
            HandshakeType::CertificateVerify,
            &cv.encode().unwrap(),
        )
        .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::IllegalParameter);
        assert_eq!(e.context(), "CertificateVerify uses a scheme not requested");
        assert!(!s
            .report()
            .has(crate::report::Property::MutualAuthentication));
    }
}

/// Describe the server's selection rule, for the ontology and for agents.
pub const SELECTION_RULE: &str = "suite: first configured suite the client offers (server order unless \
prefer_server_order is false); group: first configured group the client sent a share for, else a \
HelloRetryRequest for the first configured group it supports; certificate: the identity whose \
end-entity certificate covers the SNI name, else the first one whose key can sign with a scheme the \
client offers.";
