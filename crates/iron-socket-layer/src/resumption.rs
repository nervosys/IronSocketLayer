//! Session resumption (RFC 8446 §2.2, §4.6.1): tickets and their storage.
//!
//! Only PSK **with (EC)DHE** (`psk_dhe_ke`) is implemented. Every resumed
//! handshake still runs a fresh key exchange, so resumption keeps forward
//! secrecy, and with a post-quantum group keeps post-quantum confidentiality.
//! `psk_ke` (PSK alone) is never offered or accepted, and 0-RTT early data is
//! not implemented.
//!
//! Server tickets are **stateless**: the resumption PSK and the facts the
//! server needs to trust it again are sealed with AES-256-GCM under a ticket
//! key only the server holds. Client tickets are **single use**: the store
//! hands a ticket out once (RFC 8446 §C.4), so a network observer cannot link
//! two connections by a repeated ticket.
//!
//! Requirement trace: `REQ-PSK-001` (only `psk_dhe_ke`), `REQ-PSK-002`
//! (binders verified before a PSK is used; a bad binder is `decrypt_error`),
//! `REQ-PSK-003` (tickets are authenticated and expire; a forged or expired
//! ticket falls back to a full handshake), `REQ-PSK-004` (tickets are used
//! once), `REQ-PSK-005` (a ticket resumes only for the server name and hash it
//! was issued for, and not across a client-authentication requirement it did
//! not meet).

use alloc::string::String;
use alloc::vec::Vec;

use ic_core::traits::RandomSource;

use crate::codec::{put_u16, put_u32, put_u8, put_vec, Prefix, Reader};
use crate::crypto::{self, AeadAlg, AeadKey, Output, NONCE_LEN, TAG_LEN};
use crate::enums::CipherSuite;
use crate::error::{Error, ErrorKind, Result};

/// Longest ticket lifetime RFC 8446 permits: seven days.
pub const MAX_TICKET_LIFETIME: u32 = 604_800;

/// `psk_dhe_ke` (§4.2.9), the only mode offered or accepted. `REQ-PSK-001`.
pub const PSK_DHE_KE: u8 = 1;

/// What the client knew about the server when the ticket was issued, so a
/// resumed session reports the same facts.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PeerSummary {
    /// End-entity key kind.
    pub key: Option<&'static str>,
    /// Subject common name (informational only).
    pub subject_cn: Option<String>,
    /// End-entity `notAfter`.
    pub not_after: Option<u64>,
    /// Verification method id.
    pub verification: &'static str,
    /// Whether the original session was post-quantum authenticated.
    pub post_quantum_authentication: bool,
    /// Whether the original session was mutually authenticated.
    pub mutual: bool,
    /// Whether the original session was authenticated by a pinned key.
    pub pinned: bool,
    /// Revocation status established by the original session.
    pub revocation: &'static str,
}

/// A ticket the client holds.
#[derive(Clone)]
pub struct StoredTicket {
    /// The name the client connected to.
    pub server_name: String,
    /// The suite of the session that issued it; resumption needs its hash.
    pub suite: CipherSuite,
    /// The opaque ticket.
    pub ticket: Vec<u8>,
    /// The resumption PSK.
    pub psk: Output,
    /// Ticket age obfuscation value.
    pub age_add: u32,
    /// Lifetime in seconds.
    pub lifetime: u32,
    /// When it was received, Unix seconds.
    pub received_at: u64,
    /// The most 0-RTT bytes the server accepts on this ticket (0: none).
    pub max_early_data: u32,
    /// The ALPN protocol of the session that issued it; 0-RTT is sent only
    /// when the same protocol is offered.
    pub alpn: Option<Vec<u8>>,
    /// QUIC: the server's transport parameters from that session, which a
    /// client must reuse for 0-RTT (RFC 9001 §7.4.1).
    pub quic_params: Option<Vec<u8>>,
    /// Facts about the server from the original session.
    pub peer: PeerSummary,
}

impl core::fmt::Debug for StoredTicket {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "StoredTicket({}, {}, {} bytes)",
            self.server_name,
            self.suite,
            self.ticket.len()
        )
    }
}

impl StoredTicket {
    /// Whether the ticket is still usable at `now`.
    pub fn valid_at(&self, now: u64) -> bool {
        now >= self.received_at && now - self.received_at < u64::from(self.lifetime)
    }

    /// `obfuscated_ticket_age` for `now` (§4.2.11.1).
    pub fn obfuscated_age(&self, now: u64) -> u32 {
        let age_ms = now.saturating_sub(self.received_at).saturating_mul(1000);
        (age_ms as u32).wrapping_add(self.age_add)
    }
}

/// Records the ClientHellos that carried 0-RTT data, so a replayed one is
/// refused (RFC 8446 §8.2). `REQ-0RTT-002`.
pub trait ReplayGuard: Send + Sync + core::fmt::Debug {
    /// Record `key` (a digest of the ClientHello's PSK binder) until
    /// `expires`; return `false` if it was already recorded or cannot be
    /// recorded. Must fail closed.
    fn insert_fresh(&self, key: [u8; 32], now: u64, expires: u64) -> bool;
}

/// An in-memory [`ReplayGuard`]. When full it refuses rather than forgets.
///
/// A hash map (std's randomly keyed SipHash, so a peer cannot choose keys
/// that collide), so recording a ClientHello costs the same however many are
/// held: the guard is on the path of every 0-RTT attempt, and a list scanned
/// on each would let a flood of them make every one slower. Expired entries
/// are dropped when the map fills.
#[cfg(feature = "std")]
#[derive(Debug, Default)]
pub struct MemoryReplayGuard {
    seen: std::sync::Mutex<std::collections::HashMap<[u8; 32], u64>>,
}

#[cfg(feature = "std")]
impl MemoryReplayGuard {
    /// Most ClientHellos remembered at once.
    pub const CAPACITY: usize = 65_536;
}

#[cfg(feature = "std")]
impl ReplayGuard for MemoryReplayGuard {
    fn insert_fresh(&self, key: [u8; 32], now: u64, expires: u64) -> bool {
        use std::collections::hash_map::Entry;
        let Ok(mut seen) = self.seen.lock() else {
            return false;
        };
        if seen.len() >= Self::CAPACITY {
            seen.retain(|_, e| *e > now);
        }
        let full = seen.len() >= Self::CAPACITY;
        match seen.entry(key) {
            // Still remembered: a replay.
            Entry::Occupied(e) if *e.get() > now => false,
            // Remembered once but expired: record it afresh.
            Entry::Occupied(mut e) => {
                e.insert(expires);
                true
            }
            // New, and room for it; when full, refuse rather than forget.
            Entry::Vacant(e) if !full => {
                e.insert(expires);
                true
            }
            Entry::Vacant(_) => false,
        }
    }
}

/// Where a client keeps tickets between connections.
///
/// Implementations must hand each ticket out at most once. `REQ-PSK-004`.
pub trait TicketStore: Send + Sync + core::fmt::Debug {
    /// Keep a ticket.
    fn put(&self, ticket: StoredTicket);
    /// Remove and return a usable ticket for `server_name`, if any.
    fn take(&self, server_name: &str, now: u64) -> Option<StoredTicket>;
}

/// An in-memory [`TicketStore`], bounded in total and per server, evicting
/// the oldest ticket first. `REQ-PSK-006`.
#[cfg(feature = "std")]
#[derive(Debug, Default)]
pub struct MemoryTicketStore {
    tickets: std::sync::Mutex<Vec<StoredTicket>>,
}

#[cfg(feature = "std")]
impl MemoryTicketStore {
    /// Most tickets held in total.
    pub const CAPACITY: usize = 256;
    /// Most tickets held per server name.
    pub const PER_SERVER: usize = 4;

    /// Tickets currently held.
    pub fn len(&self) -> usize {
        self.tickets.lock().map(|t| t.len()).unwrap_or(0)
    }

    /// Whether empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(feature = "std")]
impl TicketStore for MemoryTicketStore {
    fn put(&self, ticket: StoredTicket) {
        let Ok(mut all) = self.tickets.lock() else {
            return;
        };
        let same: Vec<usize> = all
            .iter()
            .enumerate()
            .filter(|(_, t)| t.server_name == ticket.server_name)
            .map(|(i, _)| i)
            .collect();
        if same.len() >= Self::PER_SERVER {
            all.remove(same[0]);
        }
        if all.len() >= Self::CAPACITY {
            all.remove(0);
        }
        all.push(ticket);
    }

    fn take(&self, server_name: &str, now: u64) -> Option<StoredTicket> {
        let mut all = self.tickets.lock().ok()?;
        all.retain(|t| t.valid_at(now));
        let i = all.iter().rposition(|t| t.server_name == server_name)?;
        Some(all.remove(i))
    }
}

/// What a server seals into a ticket.
#[derive(Clone, PartialEq, Eq)]
pub struct TicketState {
    /// Suite of the issuing session.
    pub suite: CipherSuite,
    /// When issued, Unix seconds.
    pub created: u64,
    /// Lifetime in seconds.
    pub lifetime: u32,
    /// The resumption PSK.
    pub psk: Vec<u8>,
    /// SNI of the issuing session (empty if none).
    pub server_name: String,
    /// Whether the client authenticated with a certificate.
    pub client_authenticated: bool,
    /// Whether the issuing session was post-quantum authenticated.
    pub post_quantum_authentication: bool,
    /// The client's end-entity certificate, when it authenticated.
    pub client_leaf: Vec<u8>,
    /// Whether the issuing session was authenticated by an external PSK
    /// rather than a certificate.
    pub external_psk: bool,
    /// The ticket's age obfuscation value, for the 0-RTT freshness check.
    pub age_add: u32,
    /// ALPN protocol of the issuing session (empty for none).
    pub alpn: Vec<u8>,
    /// 0-RTT bytes this ticket admits (0: none; `u32::MAX` under QUIC).
    pub max_early_data: u32,
    /// QUIC: the server's transport parameters when it issued the ticket;
    /// 0-RTT is refused if they have changed.
    pub quic_params: Vec<u8>,
}

impl core::fmt::Debug for TicketState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "TicketState({}, created {})", self.suite, self.created)
    }
}

impl Drop for TicketState {
    fn drop(&mut self) {
        ic_core::Zeroize::zeroize(self.psk.as_mut_slice());
    }
}

const STATE_VERSION: u8 = 3;
/// Largest client certificate carried in a ticket; a larger one is omitted and
/// the resumed session reports no client certificate details.
const MAX_LEAF_IN_TICKET: usize = 16 * 1024;

impl TicketState {
    fn encode(&self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(96 + self.client_leaf.len());
        put_u8(&mut out, STATE_VERSION);
        put_u16(&mut out, self.suite.to_wire());
        out.extend_from_slice(&self.created.to_be_bytes());
        put_u32(&mut out, self.lifetime);
        put_vec(&mut out, Prefix::U8, &self.psk)?;
        put_vec(&mut out, Prefix::U16, self.server_name.as_bytes())?;
        put_u8(
            &mut out,
            u8::from(self.client_authenticated)
                | (u8::from(self.post_quantum_authentication) << 1)
                | (u8::from(self.external_psk) << 2),
        );
        let leaf: &[u8] = if self.client_leaf.len() <= MAX_LEAF_IN_TICKET {
            &self.client_leaf
        } else {
            &[]
        };
        put_vec(&mut out, Prefix::U24, leaf)?;
        put_u32(&mut out, self.age_add);
        put_vec(&mut out, Prefix::U8, &self.alpn)?;
        put_u32(&mut out, self.max_early_data);
        put_vec(&mut out, Prefix::U16, &self.quic_params)?;
        Ok(out)
    }

    fn decode(b: &[u8]) -> Result<Self> {
        let mut r = Reader::new(b);
        if r.u8()? != STATE_VERSION {
            return Err(Error::new(ErrorKind::Decode, "ticket state version"));
        }
        let suite = CipherSuite::from_wire(r.u16()?);
        let created = u64::from_be_bytes(r.array::<8>()?);
        let lifetime = r.u32()?;
        let psk = r.vec8()?.to_vec();
        let server_name = String::from_utf8(r.vec16()?.to_vec())
            .map_err(|_| Error::new(ErrorKind::Decode, "ticket name"))?;
        let flags = r.u8()?;
        let client_leaf = r.vec24()?.to_vec();
        let age_add = r.u32()?;
        let alpn = r.vec8()?.to_vec();
        let max_early_data = r.u32()?;
        let quic_params = r.vec16()?.to_vec();
        r.finish()?;
        Ok(Self {
            suite,
            created,
            lifetime,
            psk,
            server_name,
            client_authenticated: flags & 1 != 0,
            post_quantum_authentication: flags & 2 != 0,
            client_leaf,
            external_psk: flags & 4 != 0,
            age_add,
            alpn,
            max_early_data,
            quic_params,
        })
    }
}

const KEY_NAME_LEN: usize = 16;

struct TicketKey {
    name: [u8; KEY_NAME_LEN],
    aead: AeadKey,
}

impl TicketKey {
    fn generate(rng: &mut dyn RandomSource) -> Result<Self> {
        let mut name = [0u8; KEY_NAME_LEN];
        crypto::fill_random(rng, &mut name)?;
        let mut key = crypto::SecretVec::new(alloc::vec![0u8; 32]);
        crypto::fill_random(rng, key.get_mut())?;
        Ok(Self {
            name,
            aead: AeadKey::new(AeadAlg::Aes256Gcm, key.get())?,
        })
    }
}

/// A server's ticket-encryption keys: the current one, which seals, and the
/// previous one, which still opens, so rotation does not strand live tickets.
///
/// AES-256-GCM with random 96-bit nonces: rotate before a key has sealed 2^32
/// tickets (the constraint `ic:aes-256-gcm` states). Build a new
/// `ServerConfig` with [`TicketKeys::rotated`] to rotate.
pub struct TicketKeys {
    current: TicketKey,
    previous: Option<TicketKey>,
}

impl core::fmt::Debug for TicketKeys {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "TicketKeys(previous: {})", self.previous.is_some())
    }
}

impl TicketKeys {
    /// Fresh keys.
    pub fn generate(rng: &mut dyn RandomSource) -> Result<Self> {
        Ok(Self {
            current: TicketKey::generate(rng)?,
            previous: None,
        })
    }

    /// A new current key; the old current key becomes the previous one and
    /// the old previous key is discarded.
    pub fn rotated(self, rng: &mut dyn RandomSource) -> Result<Self> {
        Ok(Self {
            current: TicketKey::generate(rng)?,
            previous: Some(self.current),
        })
    }

    /// Seal `state` into a ticket: `key name ‖ nonce ‖ ciphertext ‖ tag`.
    pub fn seal(&self, state: &TicketState, rng: &mut dyn RandomSource) -> Result<Vec<u8>> {
        let mut plain = crypto::SecretVec::new(state.encode()?);
        let mut nonce = [0u8; NONCE_LEN];
        crypto::fill_random(rng, &mut nonce)?;
        let mut tag = [0u8; TAG_LEN];
        self.current
            .aead
            .seal(&nonce, &self.current.name, plain.get_mut(), &mut tag)?;
        let mut out = Vec::with_capacity(KEY_NAME_LEN + NONCE_LEN + plain.get().len() + TAG_LEN);
        out.extend_from_slice(&self.current.name);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(plain.get());
        out.extend_from_slice(&tag);
        Ok(out)
    }

    /// Open a ticket, or `None` if no key of ours sealed it or it was altered.
    /// `REQ-PSK-003`.
    pub fn open(&self, ticket: &[u8]) -> Option<TicketState> {
        if ticket.len() < KEY_NAME_LEN + NONCE_LEN + TAG_LEN {
            return None;
        }
        let (name, rest) = ticket.split_at(KEY_NAME_LEN);
        let key = [Some(&self.current), self.previous.as_ref()]
            .into_iter()
            .flatten()
            .find(|k| ic_core::ct::verify(&k.name, name))?;
        let (nonce, rest) = rest.split_at(NONCE_LEN);
        let (ct, tag) = rest.split_at(rest.len() - TAG_LEN);
        let nonce: [u8; NONCE_LEN] = nonce.try_into().ok()?;
        let mut plain = crypto::SecretVec::new(ct.to_vec());
        key.aead.open(&nonce, name, plain.get_mut(), tag).ok()?;
        TicketState::decode(plain.get()).ok()
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;

    fn state() -> TicketState {
        TicketState {
            suite: CipherSuite::TlsAes256GcmSha384,
            created: 1_700_000_000,
            lifetime: 3600,
            psk: alloc::vec![9; 48],
            server_name: "a.test".into(),
            client_authenticated: true,
            post_quantum_authentication: false,
            client_leaf: alloc::vec![1, 2, 3],
            external_psk: false,
            age_add: 77,
            alpn: b"h2".to_vec(),
            max_early_data: 16384,
            quic_params: alloc::vec![1, 2, 3],
        }
    }

    /// REQ-PSK-003: tickets round-trip, and any alteration or foreign key
    /// yields nothing rather than an error a peer could probe.
    #[test]
    fn tickets_seal_open_and_resist_tampering() {
        let mut rng = ic_drbg::Rng::from_os().unwrap();
        let keys = TicketKeys::generate(&mut rng).unwrap();
        let t = keys.seal(&state(), &mut rng).unwrap();
        assert_eq!(keys.open(&t), Some(state()));
        for i in [0, KEY_NAME_LEN, KEY_NAME_LEN + NONCE_LEN + 1, t.len() - 1] {
            let mut bad = t.clone();
            bad[i] ^= 1;
            assert!(keys.open(&bad).is_none(), "byte {i}");
        }
        assert!(keys.open(&t[..t.len() - 1]).is_none());
        let other = TicketKeys::generate(&mut rng).unwrap();
        assert!(other.open(&t).is_none());
        // After one rotation the old ticket still opens; after two it does not.
        let keys = keys.rotated(&mut rng).unwrap();
        assert!(keys.open(&t).is_some());
        let keys = keys.rotated(&mut rng).unwrap();
        assert!(keys.open(&t).is_none());
    }

    /// REQ-PSK-004: a stored ticket is handed out once, only for its server,
    /// and only while valid.
    #[test]
    fn the_store_hands_each_ticket_out_once() {
        let store = MemoryTicketStore::default();
        let t = StoredTicket {
            server_name: "a.test".into(),
            suite: CipherSuite::TlsAes128GcmSha256,
            ticket: alloc::vec![1; 8],
            psk: Output::zeros(32),
            age_add: 7,
            lifetime: 100,
            received_at: 1000,
            max_early_data: 0,
            alpn: None,
            quic_params: None,
            peer: PeerSummary::default(),
        };
        store.put(t.clone());
        assert!(store.take("b.test", 1000).is_none());
        assert!(
            store.take("a.test", 1100).is_none(),
            "expired ticket handed out"
        );
        store.put(t.clone());
        assert!(store.take("a.test", 1050).is_some());
        assert!(
            store.take("a.test", 1050).is_none(),
            "ticket handed out twice"
        );
        for _ in 0..10 {
            store.put(t.clone());
        }
        assert_eq!(store.len(), MemoryTicketStore::PER_SERVER);
        assert_eq!(t.obfuscated_age(1002), 2000u32.wrapping_add(7));
    }

    /// REQ-PSK-006: the store is bounded in total as well as per server, and
    /// evicts the oldest ticket, so servers cannot grow it without limit.
    #[test]
    fn the_store_is_bounded_in_total_and_evicts_the_oldest() {
        let store = MemoryTicketStore::default();
        let ticket = |i: usize| StoredTicket {
            server_name: alloc::format!("s{i}.test"),
            suite: CipherSuite::TlsAes128GcmSha256,
            ticket: alloc::vec![1; 8],
            psk: Output::zeros(32),
            age_add: 0,
            lifetime: 100,
            received_at: 1000,
            max_early_data: 0,
            alpn: None,
            quic_params: None,
            peer: PeerSummary::default(),
        };
        for i in 0..=MemoryTicketStore::CAPACITY {
            store.put(ticket(i));
        }
        assert_eq!(store.len(), MemoryTicketStore::CAPACITY);
        assert!(store.take("s0.test", 1000).is_none(), "the oldest was kept");
        assert!(store.take("s1.test", 1000).is_some());
        let last = alloc::format!("s{}.test", MemoryTicketStore::CAPACITY);
        assert!(store.take(&last, 1000).is_some());
    }

    /// REQ-0RTT-002: the guard refuses a replay while it is remembered,
    /// forgets it after it expires, and when full refuses new first flights
    /// rather than forgetting old ones.
    #[test]
    fn the_replay_guard_refuses_replays_and_fails_closed_when_full() {
        let g = MemoryReplayGuard::default();
        let key = |i: u32| {
            let mut k = [0u8; 32];
            k[..4].copy_from_slice(&i.to_be_bytes());
            k
        };
        assert!(g.insert_fresh(key(0), 100, 200));
        assert!(!g.insert_fresh(key(0), 150, 250), "replay accepted");
        assert!(
            g.insert_fresh(key(0), 200, 300),
            "expired entry still refused"
        );
        for i in 1..MemoryReplayGuard::CAPACITY as u32 {
            assert!(g.insert_fresh(key(i), 200, 300));
        }
        // Full of live entries: a new one is refused, and nothing is forgotten.
        assert!(
            !g.insert_fresh(key(u32::MAX), 250, 350),
            "accepted when full"
        );
        assert!(!g.insert_fresh(key(1), 250, 350), "forgot a live entry");
        // Once they expire, room returns.
        assert!(g.insert_fresh(key(u32::MAX), 300, 400));
    }

    /// REQ-PSK-006: a ticket sealed in another state format does not decode,
    /// so it gives a full handshake rather than a misread session.
    #[test]
    fn a_ticket_state_in_another_format_is_refused() {
        let mut plain = state().encode().unwrap();
        assert_eq!(TicketState::decode(&plain).unwrap(), state());
        for v in [0u8, STATE_VERSION - 1, STATE_VERSION + 1] {
            plain[0] = v;
            let e = TicketState::decode(&plain).unwrap_err();
            assert!(e.to_string().contains("ticket state version"), "{v}: {e}");
        }
    }
}
