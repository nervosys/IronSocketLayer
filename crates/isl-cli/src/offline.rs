//! Offline inspection: certificates, chains and configurations, without
//! opening a connection. Shared by the command line and the MCP server, like
//! `ops`, so these tools add nothing an agent could use to reach the
//! network. Inputs are size-capped before parsing.

use ic_json::Json;
use ironsocketlayer::config::{
    ClientAuth, ClientConfig, Identity, IntentPolicy, PeerVerification, Profile, Revocation,
    ServerConfig,
};
use ironsocketlayer::crypto::sign::PublicKey;
use ironsocketlayer::crypto::sign::{KeyKind, SigningKey};
use ironsocketlayer::crypto::HashAlg;
use ironsocketlayer::enums::SignatureScheme;
use ironsocketlayer::report::Property;
use ironsocketlayer::x509::{
    self, CertificateParams, Limits, Purpose, RootStore, ServerName, VerifyOptions,
};

/// Largest PEM text accepted.
pub const MAX_INPUT: usize = 256 * 1024;

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn capped(text: &str, what: &str) -> Result<(), String> {
    if text.len() > MAX_INPUT {
        return Err(format!("{what} is larger than {MAX_INPUT} bytes"));
    }
    Ok(())
}

fn strings<'a>(items: impl Iterator<Item = &'a str>) -> Json {
    Json::Array(items.map(Json::str).collect())
}

fn opt_str(v: Option<&str>) -> Json {
    v.map(Json::str).unwrap_or(Json::Null)
}

/// What each certificate in a PEM text says: names, validity, CA flag, key
/// and signature, and the SHA-256 of its SubjectPublicKeyInfo (the value a
/// pin is made of).
pub fn inspect_certificate(pem: &str) -> Result<Json, String> {
    capped(pem, "the PEM text")?;
    let ders = crate::net::pem_blocks(pem, "CERTIFICATE")?;
    let t = now();
    let mut out = Vec::new();
    for der in &ders {
        let c = x509::Certificate::parse(der).map_err(|e| {
            let e = ironsocketlayer::Error::from(e);
            format!("{}: {}", e.id(), e)
        })?;
        let not_after = c.not_after();
        let spki_sha256 = HashAlg::Sha256
            .digest(c.spki_der())
            .map_err(|e| format!("{}: {}", e.id(), e))?;
        out.push(Json::object([
            ("subjectCommonName", opt_str(c.common_name())),
            ("issuerCommonName", opt_str(c.issuer_common_name())),
            ("serial", Json::str(hex(c.serial()))),
            ("notBefore", Json::num(c.not_before() as f64)),
            ("notAfter", Json::num(not_after as f64)),
            ("expired", Json::Bool(t > not_after)),
            ("notYetValid", Json::Bool(t < c.not_before())),
            ("secondsLeft", Json::num(not_after.saturating_sub(t) as f64)),
            ("isCa", Json::Bool(c.is_ca())),
            ("dnsNames", strings(c.dns_names().into_iter())),
            (
                "ipAddresses",
                Json::Array(
                    c.ip_addresses()
                        .iter()
                        .map(|ip| Json::str(ip.to_string()))
                        .collect(),
                ),
            ),
            (
                "key",
                opt_str(PublicKey::from_spki(c.spki_der()).ok().map(|k| k.kind_id())),
            ),
            (
                "signatureScheme",
                opt_str(
                    c.signature_scheme()
                        .ok()
                        .and_then(SignatureScheme::from_algorithm)
                        .map(|s| s.id()),
                ),
            ),
            ("spkiSha256", Json::str(hex(spki_sha256.as_bytes()))),
        ]));
    }
    Ok(Json::Array(out))
}

fn error_json(e: &ironsocketlayer::Error) -> Json {
    Json::object([
        ("valid", Json::Bool(false)),
        ("error", Json::str(e.id())),
        ("context", Json::str(e.context())),
        ("action", Json::str(e.recovery().id())),
    ])
}

/// Validate a chain (leaf first) against roots, as a handshake would: path,
/// validity now, usage, and the name when one is given.
pub fn verify_chain(
    chain_pem: &str,
    roots_pem: &str,
    name: Option<&str>,
    client: bool,
) -> Result<Json, String> {
    capped(chain_pem, "the chain")?;
    capped(roots_pem, "the roots")?;
    let chain = crate::net::pem_blocks(chain_pem, "CERTIFICATE")?;
    let mut roots = RootStore::new();
    roots.add_pem_bundle(roots_pem).map_err(|e| {
        let e = ironsocketlayer::Error::from(e);
        format!("roots: {}: {}", e.id(), e)
    })?;
    let usage = if client {
        Purpose::TlsClient
    } else {
        Purpose::TlsServer
    };
    // An operator's own chain, examined offline: the offline bounds.
    let opts = VerifyOptions::new(now(), usage, x509::VERIFY_ALGORITHMS, Limits::DEFAULT);
    let ints: Vec<&[u8]> = chain[1..].iter().map(Vec::as_slice).collect();
    let report = match x509::verify_chain(&chain[0], &ints, &roots, &opts) {
        Ok(r) => r,
        Err(e) => return Ok(error_json(&e.into())),
    };
    if let Some(n) = name {
        let target = ServerName::parse(n).map_err(|e| format!("name: {e}"))?;
        if let Err(e) = x509::verify_name(&chain[0], &target) {
            return Ok(error_json(&e.into()));
        }
    }
    Ok(Json::object([
        ("valid", Json::Bool(true)),
        ("depth", Json::num(report.depth as f64)),
        (
            "leafKey",
            opt_str(
                x509::Certificate::parse(&chain[0])
                    .ok()
                    .and_then(|c| PublicKey::from_spki(c.spki_der()).ok())
                    .map(|k| k.kind_id()),
            ),
        ),
        (
            "schemes",
            strings(
                report
                    .schemes
                    .iter()
                    .filter_map(|a| SignatureScheme::from_algorithm(*a))
                    .map(|s| s.id()),
            ),
        ),
        ("anchor", opt_str(report.anchor_subject_cn.as_deref())),
        ("leafNotAfter", Json::num(report.leaf_not_after as f64)),
        (
            "minClassicalBits",
            Json::num(f64::from(report.min_classical_bits)),
        ),
        ("nameChecked", Json::Bool(name.is_some())),
    ]))
}

fn text<'a>(cfg: &'a Json, key: &str) -> Option<&'a str> {
    cfg.get(key).and_then(|v| v.as_str())
}

fn boolean(cfg: &Json, key: &str) -> Result<Option<bool>, String> {
    match cfg.get(key) {
        None | Some(Json::Null) => Ok(None),
        Some(v) => v
            .as_bool()
            .map(Some)
            .ok_or_else(|| format!("'{key}' must be true or false")),
    }
}

/// A throwaway identity whose key the profile can sign with: only to build
/// a configuration for checking, never used to connect.
fn stand_in_identity(profile: Profile) -> Result<Identity, String> {
    let kind = match profile {
        Profile::Cnsa2 => KeyKind::MlDsa87,
        Profile::Cnsa1 | Profile::DalA => KeyKind::EcdsaP384,
        _ => KeyKind::EcdsaP256,
    };
    let mut rng = ClientConfig::new(Profile::Default, RootStore::new())
        .map_err(|e| e.to_string())?
        .common
        .new_rng()
        .map_err(|_| "no random source".to_string())?;
    let rng = &mut *rng;
    let key = SigningKey::generate(kind, rng).map_err(|e| e.to_string())?;
    let t = now();
    let cert = x509::self_signed(
        &{
            let mut params =
                CertificateParams::new("check-config", t.saturating_sub(60), t + 3600, [1; 16]);
            params.dns_names = &["check-config.invalid"];
            params.usage = &[Purpose::TlsServer, Purpose::TlsClient];
            params
        },
        &key,
        rng,
    )
    .map_err(|e| e.to_string())?;
    Identity::new(vec![cert], key).map_err(|e| e.to_string())
}

fn property(id: &str) -> Result<Property, String> {
    Property::ALL
        .iter()
        .copied()
        .find(|p| p.id() == id || p.id().strip_prefix("property:") == Some(id))
        .ok_or_else(|| format!("unknown property '{id}'"))
}

/// The contents of an OBJECT IDENTIFIER written in dotted decimal, as
/// `CertificatePolicies` names a policy: "1.2.3.4" is `2a 03 04`.
fn oid_contents(dotted: &str) -> Result<Vec<u8>, String> {
    let bad = || format!("'{dotted}' is not an object identifier in dotted decimal");
    let arcs = dotted
        .split('.')
        .map(|arc| {
            // Digits only: `parse` alone would take a sign, and refuses "".
            if !arc.bytes().all(|b| b.is_ascii_digit()) {
                return Err(bad());
            }
            arc.parse::<u64>().map_err(|_| bad())
        })
        .collect::<Result<Vec<u64>, String>>()?;
    let (first, second) = match arcs[..] {
        [first, second, ..] if first < 2 && second < 40 || first == 2 => (first, second),
        _ => return Err(bad()),
    };
    let head = first.checked_mul(40).and_then(|v| v.checked_add(second));
    let mut out = Vec::new();
    for arc in core::iter::once(head.ok_or_else(bad)?).chain(arcs[2..].iter().copied()) {
        let groups = (64 - arc.leading_zeros()).div_ceil(7).max(1);
        for i in (0..groups).rev() {
            let more = if i == 0 { 0 } else { 0x80 };
            out.push((arc >> (7 * i) & 0x7f) as u8 | more);
        }
    }
    Ok(out)
}

/// The `certificatePolicies` object of a description: `acceptable`, a list
/// of policies in dotted decimal, and the flags `requireExplicit`,
/// `inhibitMapping` and `inhibitAny`.
fn certificate_policies(
    cfg: &Json,
) -> Result<Option<ironsocketlayer::config::CertificatePolicies>, String> {
    const KEYS: &[&str] = &[
        "acceptable",
        "requireExplicit",
        "inhibitMapping",
        "inhibitAny",
    ];
    let described = match cfg.get("certificatePolicies") {
        None | Some(Json::Null) => return Ok(None),
        Some(object @ Json::Object(map)) => {
            if let Some(k) = map.keys().find(|k| !KEYS.contains(&k.as_str())) {
                return Err(format!(
                    "unknown key '{k}' in 'certificatePolicies'; expected one of: {}",
                    KEYS.join(", ")
                ));
            }
            object
        }
        Some(_) => return Err("'certificatePolicies' must be an object".into()),
    };
    let acceptable = match described.get("acceptable") {
        None | Some(Json::Null) => Vec::new(),
        Some(Json::Array(items)) => items
            .iter()
            .map(|v| {
                oid_contents(
                    v.as_str()
                        .ok_or("'acceptable' must be a list of object identifiers")?,
                )
            })
            .collect::<Result<Vec<_>, String>>()?,
        Some(_) => return Err("'acceptable' must be a list of object identifiers".into()),
    };
    Ok(Some(ironsocketlayer::config::CertificatePolicies {
        acceptable,
        require_explicit: boolean(described, "requireExplicit")?.unwrap_or(false),
        inhibit_mapping: boolean(described, "inhibitMapping")?.unwrap_or(false),
        inhibit_any: boolean(described, "inhibitAny")?.unwrap_or(false),
    }))
}

/// Build the configuration a JSON description names, with the real
/// constructors and validation, and say whether it is valid, why not, and
/// what it requires and gives up.
///
/// Keys: `side` (`client` or `server`, required); `intent` with optional
/// `fips`, `postQuantum`, `mutual`, or `profile`; `require` (property ids);
/// `revocation` (`off`, `if-stapled`, `require-staple`); `earlyData`,
/// `echGrease`, `echConfigs`, `identity` (client); `clientAuth` (`none`,
/// `optional`, `required`, `on-demand`), `sniFallback`, `selfieGuard`,
/// `externalPsk` (server); `certificatePolicies`, an object of `acceptable`
/// (policies in dotted decimal), `requireExplicit`, `inhibitMapping` and
/// `inhibitAny`, for the peer's path (either side).
pub fn check_config(cfg: &Json) -> Result<Json, String> {
    if !matches!(cfg, Json::Object(_)) {
        return Err("the configuration must be a JSON object".into());
    }
    // A misspelt key or a mistyped value is an error: silently ignoring it
    // would report a configuration the caller did not describe.
    const KEYS: &[&str] = &[
        "side",
        "intent",
        "fips",
        "postQuantum",
        "mutual",
        "profile",
        "require",
        "revocation",
        "earlyData",
        "echGrease",
        "echConfigs",
        "identity",
        "clientAuth",
        "sniFallback",
        "selfieGuard",
        "externalPsk",
        "certificatePolicies",
    ];
    const BOOLS: &[&str] = &[
        "fips",
        "postQuantum",
        "mutual",
        "earlyData",
        "echGrease",
        "echConfigs",
        "identity",
        "sniFallback",
        "selfieGuard",
        "externalPsk",
    ];
    const STRINGS: &[&str] = &["side", "intent", "profile", "revocation", "clientAuth"];
    if let Json::Object(map) = cfg {
        if let Some(k) = map.keys().find(|k| !KEYS.contains(&k.as_str())) {
            return Err(format!(
                "unknown key '{k}'; expected one of: {}",
                KEYS.join(", ")
            ));
        }
    }
    for k in BOOLS {
        boolean(cfg, k)?;
    }
    for k in STRINGS {
        if cfg.get(k).is_some_and(|v| v.as_str().is_none()) {
            return Err(format!("'{k}' must be a string"));
        }
    }
    let side = text(cfg, "side").ok_or("missing 'side': client or server")?;
    let policy = IntentPolicy {
        require_fips: boolean(cfg, "fips")?.unwrap_or(false),
        require_post_quantum: boolean(cfg, "postQuantum")?.unwrap_or(false),
        require_mutual_auth: boolean(cfg, "mutual")?.unwrap_or(false),
    };
    let profile = match text(cfg, "profile") {
        Some(p) => Some(Profile::from_id(p).ok_or_else(|| format!("unknown profile '{p}'"))?),
        None => None,
    };
    let required = match cfg.get("require") {
        None | Some(Json::Null) => None,
        Some(Json::Array(items)) => Some(
            items
                .iter()
                .map(|v| property(v.as_str().unwrap_or("")))
                .collect::<Result<Vec<_>, _>>()?,
        ),
        Some(_) => return Err("'require' must be a list of property ids".into()),
    };
    let policies = certificate_policies(cfg)?;
    let built: ironsocketlayer::Result<(Json, Json, Json, Json)> = match side {
        "client" => (|| {
            let pin = PeerVerification::pin_spki(b"check-config")?;
            let mut c = match text(cfg, "intent") {
                Some(i) => ClientConfig::for_intent(i, &policy, RootStore::new())?,
                None => ClientConfig::new(profile.unwrap_or(Profile::Default), RootStore::new())?,
            };
            // A stand-in trust anchor: what is checked here is the rest.
            c.verification = pin;
            if let Some(r) = &required {
                c.common.required_properties = r.clone();
            }
            if let Some(p) = &policies {
                c.common.certificate_policies = p.clone();
            }
            if let Some(r) = text(cfg, "revocation") {
                c.revocation = match r {
                    "off" => Revocation::Off,
                    "if-stapled" => Revocation::IfStapled,
                    "require-staple" => Revocation::RequireStaple,
                    _ => {
                        return Err(ironsocketlayer::Error::new(
                            ironsocketlayer::ErrorKind::InvalidConfig,
                            "unknown revocation policy",
                        ))
                    }
                };
            }
            if let Ok(Some(v)) = boolean(cfg, "earlyData") {
                c.early_data = v;
            }
            if let Ok(Some(v)) = boolean(cfg, "echGrease") {
                c.ech_grease = v;
            }
            if let Ok(Some(true)) = boolean(cfg, "echConfigs") {
                c.ech_configs = Some(Vec::new());
            }
            if let Ok(Some(true)) = boolean(cfg, "identity") {
                c.identity = Some(stand_in_identity(c.common.profile).map_err(|_| {
                    ironsocketlayer::Error::new(
                        ironsocketlayer::ErrorKind::Internal,
                        "could not make a stand-in identity",
                    )
                })?);
            }
            let r = c.validate();
            Ok((
                result_json(r),
                Json::str(c.common.profile.id()),
                strings(c.relaxations().iter().map(|r| r.id())),
                strings(c.common.required_properties.iter().map(|p| p.id())),
            ))
        })(),
        "server" => (|| {
            let base = profile.unwrap_or(Profile::Default);
            let identity = stand_in_identity(match text(cfg, "intent") {
                Some(i) => {
                    ClientConfig::for_intent(i, &policy, RootStore::new())?
                        .common
                        .profile
                }
                None => base,
            })
            .map_err(|_| {
                ironsocketlayer::Error::new(
                    ironsocketlayer::ErrorKind::Internal,
                    "could not make a stand-in identity",
                )
            })?;
            let mut s = match text(cfg, "intent") {
                Some(i) => ServerConfig::for_intent(i, &policy, identity)?,
                None => ServerConfig::new(base, identity)?,
            };
            if let Some(r) = &required {
                s.common.required_properties = r.clone();
            }
            if let Some(p) = &policies {
                s.common.certificate_policies = p.clone();
            }
            let roots = || PeerVerification::pin_spki(b"check-config");
            if let Some(a) = text(cfg, "clientAuth") {
                s.client_auth = match a {
                    "none" => ClientAuth::None,
                    "optional" => ClientAuth::Optional(roots()?),
                    "required" => ClientAuth::Required(roots()?),
                    "on-demand" => ClientAuth::OnDemand(roots()?),
                    _ => {
                        return Err(ironsocketlayer::Error::new(
                            ironsocketlayer::ErrorKind::InvalidConfig,
                            "unknown client authentication",
                        ))
                    }
                };
            }
            if let Ok(Some(v)) = boolean(cfg, "sniFallback") {
                s.sni_fallback = v;
            }
            if let Ok(Some(v)) = boolean(cfg, "selfieGuard") {
                s.selfie_guard = v;
            }
            if let Ok(Some(true)) = boolean(cfg, "earlyData") {
                s.early_data = Some(ironsocketlayer::config::EarlyDataPolicy::new(16_384));
            }
            if let Ok(Some(true)) = boolean(cfg, "externalPsk") {
                s.external_psks = vec![ironsocketlayer::config::ExternalPsk::new(
                    b"check-config",
                    &[0x42; 32],
                    HashAlg::Sha256,
                )?];
            }
            let r = s.validate();
            Ok((
                result_json(r),
                Json::str(s.common.profile.id()),
                strings(s.relaxations().iter().map(|r| r.id())),
                strings(s.common.required_properties.iter().map(|p| p.id())),
            ))
        })(),
        other => return Err(format!("'side' must be client or server, not '{other}'")),
    };
    match built {
        Ok((validity, profile, relaxations, required)) => {
            let mut map = match validity {
                Json::Object(m) => m,
                _ => Default::default(),
            };
            map.insert("profile".into(), profile);
            map.insert("relaxations".into(), relaxations);
            map.insert("required".into(), required);
            if let Some(p) = &policies {
                // What was understood, so that a caller can see a policy
                // was read as the one it meant.
                map.insert(
                    "certificatePolicies".into(),
                    Json::object([
                        ("acceptable", Json::Number(p.acceptable.len() as f64)),
                        ("requireExplicit", Json::Bool(p.require_explicit)),
                        ("inhibitMapping", Json::Bool(p.inhibit_mapping)),
                        ("inhibitAny", Json::Bool(p.inhibit_any)),
                    ]),
                );
            }
            Ok(Json::Object(map))
        }
        Err(e) => Ok(error_json(&e)),
    }
}

fn result_json(r: ironsocketlayer::Result<()>) -> Json {
    match r {
        Ok(()) => Json::object([("valid", Json::Bool(true))]),
        Err(e) => error_json(&e),
    }
}

#[cfg(test)]
#[path = "offline_tests.rs"]
mod tests;
