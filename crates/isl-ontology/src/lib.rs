//! The IronSocketLayer ontology: TLS 1.3 and QUIC-TLS as data an agent can reason
//! over.
//!
//! Four registries, each keyed by stable, prefixed identifiers:
//!
//! - [`REGISTRY`]: every protocol element this build can name — versions,
//!   content types, handshake messages, cipher suites, groups, signature
//!   schemes, extensions, alerts — with its wire code, implementation status,
//!   FIPS standing, strength, usage constraints, and typed edges, including
//!   `built-on` edges into IronCrypto's ontology (`ic:` prefix).
//! - [`errors::CATALOG`]: what every `ironsocketlayer` error means and how to
//!   recover from it.
//! - [`profiles::PROFILES`]: complete parameter sets, whose lists
//!   `ironsocketlayer` configures itself from.
//! - [`select::INTENTS`]: deployment situations, and [`recommend`], which maps
//!   an intent and a policy to a profile — or says plainly that none fits.
//!
//! Static data throughout; `no_std` with `alloc`. The exporters (JSON,
//! JSON-LD, Turtle, JSON Schema, Markdown) need `std`.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![warn(clippy::all)]

extern crate alloc;

pub mod errors;
pub mod profiles;
pub mod registry;
pub mod select;
pub mod types;

#[cfg(feature = "std")]
pub mod export;

pub use profiles::{Profile, ProfileStatus, PROFILES};
pub use registry::REGISTRY;
pub use select::{recommend, Intent, NoRecommendation, Policy, Recommendation, Rejected, INTENTS};
pub use types::{
    Constraint, Edge, Entry, FipsStatus, ImplStatus, Kind, Relation, Severity, Strength,
};

/// Ontology schema version. Bumped when a field or term changes meaning.
pub const ONTOLOGY_VERSION: &str = "1.0";

/// Crate version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Prefix of edge targets that live in IronCrypto's ontology.
pub const IC_PREFIX: &str = "ic:";

/// Look up a protocol element by id.
pub fn get(id: &str) -> Option<&'static Entry> {
    REGISTRY.iter().find(|e| e.id == id)
}

/// Every protocol element.
pub fn all() -> impl Iterator<Item = &'static Entry> {
    REGISTRY.iter()
}

/// Every protocol element of one kind.
pub fn by_kind(kind: Kind) -> impl Iterator<Item = &'static Entry> {
    REGISTRY.iter().filter(move |e| e.kind == kind)
}

/// Look up a protocol element by kind and wire code.
pub fn by_code(kind: Kind, code: u16) -> Option<&'static Entry> {
    REGISTRY.iter().find(|e| e.kind == kind && e.code == code)
}

/// Direction of an edge relative to the entry asked about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// The entry is the source.
    Outgoing,
    /// The entry is the target.
    Incoming,
}

impl Direction {
    /// Stable identifier.
    pub const fn id(self) -> &'static str {
        match self {
            Self::Outgoing => "outgoing",
            Self::Incoming => "incoming",
        }
    }
}

/// One edge seen from a particular entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Related {
    /// The relation.
    pub relation: Relation,
    /// Which way it points.
    pub direction: Direction,
    /// The entry at the other end.
    pub other: &'static str,
}

/// Every edge touching `id`, in both directions. Also accepts `ic:` ids, to
/// find what in TLS is built on an IronCrypto algorithm.
pub fn related(id: &str) -> alloc::vec::Vec<Related> {
    let mut out = alloc::vec::Vec::new();
    for e in REGISTRY {
        for edge in e.edges {
            if e.id == id {
                out.push(Related {
                    relation: edge.relation,
                    direction: Direction::Outgoing,
                    other: edge.target,
                });
            } else if edge.target == id {
                out.push(Related {
                    relation: edge.relation,
                    direction: Direction::Incoming,
                    other: e.id,
                });
            }
        }
    }
    out
}

/// Every known identifier: entries, errors, profiles and intents.
pub fn all_ids() -> impl Iterator<Item = &'static str> {
    REGISTRY
        .iter()
        .map(|e| e.id)
        .chain(errors::CATALOG.iter().map(|e| e.id))
        .chain(PROFILES.iter().map(|p| p.id))
        .chain(INTENTS.iter().map(|i| i.id))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_unique_and_prefixed() {
        let ids: alloc::vec::Vec<&str> = all_ids().collect();
        for (i, a) in ids.iter().enumerate() {
            for b in &ids[i + 1..] {
                assert_ne!(a, b, "duplicate id");
            }
        }
        for e in REGISTRY {
            assert!(
                e.id.starts_with(e.kind.prefix()),
                "{} lacks prefix {}",
                e.id,
                e.kind.prefix()
            );
            assert!(!e.summary.is_empty() && !e.name.is_empty(), "{}", e.id);
            assert_eq!(
                e.status == ImplStatus::Implemented,
                e.status_reason.is_empty(),
                "{}: status reason iff not implemented",
                e.id
            );
        }
        for e in errors::CATALOG {
            assert!(e.id.starts_with("error:") && !e.recovery.is_empty());
        }
        for p in PROFILES {
            assert!(p.id.starts_with("profile:"));
        }
    }

    #[test]
    fn codes_are_unique_within_a_kind() {
        for (i, a) in REGISTRY.iter().enumerate() {
            for b in &REGISTRY[i + 1..] {
                assert!(
                    !(a.kind == b.kind && a.code == b.code),
                    "{} and {} share a code",
                    a.id,
                    b.id
                );
            }
        }
    }

    #[test]
    fn every_local_edge_target_exists() {
        for e in REGISTRY {
            for edge in e.edges {
                if !edge.target.starts_with(IC_PREFIX) {
                    assert!(
                        get(edge.target).is_some(),
                        "{} -> {} dangles",
                        e.id,
                        edge.target
                    );
                }
            }
            for (i, c) in e.constraints.iter().enumerate() {
                for d in &e.constraints[i + 1..] {
                    assert_ne!(c.id, d.id, "{}", e.id);
                }
            }
        }
        for a in errors::CATALOG {
            if let Some(alert) = a.alert {
                assert_eq!(get(alert).map(|e| e.kind), Some(Kind::Alert), "{}", a.id);
            }
        }
    }

    #[test]
    fn available_profiles_reference_only_implemented_entries() {
        for p in PROFILES {
            let lists = [
                (p.suites, Kind::CipherSuite),
                (p.groups, Kind::NamedGroup),
                (p.sigschemes, Kind::SignatureScheme),
            ];
            let mut all_implemented = true;
            for (list, kind) in lists {
                assert!(!list.is_empty(), "{}", p.id);
                for id in list {
                    let e = get(id).unwrap_or_else(|| panic!("{} names unknown {}", p.id, id));
                    assert_eq!(e.kind, kind, "{} lists {} in the wrong place", p.id, id);
                    all_implemented &= e.implemented();
                    if p.fips_gate && p.status == ProfileStatus::Available {
                        assert_eq!(
                            e.fips,
                            FipsStatus::Approved,
                            "{} admits non-approved {}",
                            p.id,
                            id
                        );
                    }
                }
            }
            assert_eq!(
                p.status == ProfileStatus::Available,
                all_implemented,
                "{}: status must match implementation",
                p.id
            );
        }
    }

    #[test]
    fn related_sees_both_directions() {
        let r = related("group:x25519");
        assert!(r
            .iter()
            .any(|x| x.direction == Direction::Outgoing && x.other == "ic:x25519"));
        assert!(r
            .iter()
            .any(|x| x.direction == Direction::Incoming && x.other == "group:x25519mlkem768"));
        assert!(related("ic:ml-kem-768").len() >= 3);
    }
}
