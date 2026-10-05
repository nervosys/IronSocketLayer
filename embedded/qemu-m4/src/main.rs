//! The fixed-capacity engine on an emulated Cortex-M4 (QEMU MPS2-AN386).
//!
//! For each case it builds certificates and configuration first, then runs a
//! whole mutual-TLS session between a fixed client and a fixed server in this
//! one thread: both constructors, the handshake, data both ways, KeyUpdate, an
//! exporter and close_notify. It reports:
//!
//! * peak stack, by painting the free stack with a pattern before the session
//!   and finding the deepest word the session overwrote;
//! * allocator calls after initialization (after both constructors), which
//!   must be zero;
//! * that a buffer one size too small fails with `capacity-exceeded` and
//!   latches.
//!
//! QEMU executes Cortex-M4 instructions but models no timing, caches or wait
//! states, so it gives no timing evidence. The clock and the random source
//! are fixed: this image is a measurement, never a deployment.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;
use core::alloc::{GlobalAlloc, Layout};
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};

use cortex_m_rt::entry;
use cortex_m_semihosting::{debug, hprintln};
use ic_core::traits::{Drbg as _, RandomSource};
use iron_socket_layer::config::{
    ClientAuth, ClientConfig, Identity, PeerVerification, Profile, ServerConfig,
};
use iron_socket_layer::crypto::sign::{KeyKind, SigningKey};
use iron_socket_layer::enums::{NamedGroup, SignatureScheme};
use iron_socket_layer::fixed::{Connection, Limits, Storage};
use iron_socket_layer::x509::{self, CertificateParams, RootStore, Usage};
use iron_socket_layer::ErrorKind;

/// A fixed "now": 2026-10-05.
const NOW: u64 = 1_791_158_400;
const HEAP_SIZE: usize = 3 << 20;
const PATTERN: u32 = 0xA5C3_5A3C;

// ---------------------------------------------------------------------------
// A counting allocator over a linked-list heap.

struct Counting {
    heap: embedded_alloc::LlffHeap,
    gated: AtomicBool,
    calls: AtomicUsize,
    in_use: AtomicUsize,
    peak: AtomicUsize,
}

// SAFETY: forwards each call with its exact layout to the inner heap.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if self.gated.load(Ordering::Relaxed) {
            self.calls.fetch_add(1, Ordering::Relaxed);
        }
        let used = self.in_use.fetch_add(layout.size(), Ordering::Relaxed) + layout.size();
        self.peak.fetch_max(used, Ordering::Relaxed);
        unsafe { self.heap.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        self.in_use.fetch_sub(layout.size(), Ordering::Relaxed);
        unsafe { self.heap.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static HEAP: Counting = Counting {
    heap: embedded_alloc::LlffHeap::empty(),
    gated: AtomicBool::new(false),
    calls: AtomicUsize::new(0),
    in_use: AtomicUsize::new(0),
    peak: AtomicUsize::new(0),
};

// ---------------------------------------------------------------------------
// Stack painting.

extern "C" {
    /// End of the statically allocated RAM (cortex-m-rt's link.x); the stack
    /// grows down towards it.
    static __sheap: u32;
}

fn sp() -> usize {
    cortex_m::register::msp::read() as usize
}

/// Run `f` and return the deepest stack it used, in bytes below the caller's
/// stack pointer. Everything between the end of static RAM and just below the
/// current stack pointer is painted first.
#[inline(never)]
fn stack_used(f: &mut dyn FnMut()) -> usize {
    let top = sp() - 64;
    // __sheap is the linker's end-of-statics symbol; only its address is taken.
    let bottom = core::ptr::addr_of!(__sheap) as usize + 64;
    let mut p = bottom & !3;
    while p < top {
        // SAFETY: [bottom, top) is free stack below the live frames.
        unsafe { core::ptr::write_volatile(p as *mut u32, PATTERN) };
        p += 4;
    }
    f();
    let mut q = bottom & !3;
    // SAFETY: as above; reading back what was painted.
    while q < top && unsafe { core::ptr::read_volatile(q as *const u32) } == PATTERN {
        q += 4;
    }
    assert!(q > bottom, "the stack overran the painted region");
    top - q
}

// ---------------------------------------------------------------------------
// Fixtures.

static SEED: AtomicU32 = AtomicU32::new(1);

/// HMAC-DRBG from a fixed seed, different for each instance. A measurement
/// image only: there is no entropy source here.
struct FixedRng(ic_drbg::HmacDrbgSha256);

impl RandomSource for FixedRng {
    fn fill(&mut self, out: &mut [u8]) -> ic_core::Result<()> {
        for block in out.chunks_mut(4096) {
            self.0.generate(&[], block)?;
        }
        Ok(())
    }
}

fn rng() -> FixedRng {
    let n = SEED.fetch_add(1, Ordering::Relaxed);
    let mut entropy = [0x5au8; 48];
    entropy[..4].copy_from_slice(&n.to_be_bytes());
    FixedRng(ic_drbg::HmacDrbgSha256::instantiate(&entropy, b"nonce", b"isl-qemu-m4").unwrap())
}

fn rng_factory() -> iron_socket_layer::Result<Box<dyn RandomSource + Send>> {
    Ok(Box::new(rng()))
}

fn clock() -> u64 {
    NOW
}

fn cert(
    cn: &str,
    names: &[&str],
    ca: bool,
    usage: &[Usage],
    spki: &[u8],
    issuer: Option<(&[u8], &SigningKey)>,
    key: &SigningKey,
) -> Vec<u8> {
    let params = CertificateParams {
        subject_cn: cn,
        dns_names: names,
        ip_addresses: &[],
        not_before: NOW - 3600,
        not_after: NOW + 86_400,
        is_ca: ca,
        path_len: if ca { Some(1) } else { None },
        usage,
        serial: [SEED.fetch_add(1, Ordering::Relaxed) as u8 | 1; 16],
    };
    match issuer {
        None => x509::self_signed(&params, key, &mut rng()).unwrap(),
        Some((ca_cert, ca_key)) => x509::issue(&params, spki, ca_cert, ca_key, &mut rng()).unwrap(),
    }
}

fn configs(kind: KeyKind, group: NamedGroup) -> (ClientConfig, ServerConfig) {
    let ca_key = SigningKey::generate(kind, &mut rng()).unwrap();
    let ca = cert("QEMU Root", &[], true, &[], &[], None, &ca_key);
    let leaf = |cn: &str, names: &[&str], usage: Usage| {
        let key = SigningKey::generate(kind, &mut rng()).unwrap();
        let c = cert(
            cn,
            names,
            false,
            &[usage],
            key.spki(),
            Some((&ca, &ca_key)),
            &key,
        );
        Identity::new(vec![c], key).unwrap()
    };
    let mut roots = RootStore::new();
    roots.add_der(&ca).unwrap();
    let mut cc = ClientConfig::new(Profile::Default, roots.clone()).unwrap();
    let mut sc = ServerConfig::new(
        Profile::Default,
        leaf("server.test", &["server.test"], Usage::ServerAuth),
    )
    .unwrap();
    cc.identity = Some(leaf("device", &[], Usage::ClientAuth));
    sc.client_auth = ClientAuth::Required(PeerVerification::Roots(roots));
    cc.tickets = None;
    sc.tickets = None;
    for common in [&mut cc.common, &mut sc.common] {
        common.clock = clock;
        common.rng = rng_factory;
        common.groups = vec![group];
        if kind == KeyKind::MlDsa44 {
            common.schemes.push(SignatureScheme::MlDsa44);
        }
    }
    (cc, sc)
}

struct Buffers([Vec<u8>; 8]);

impl Buffers {
    fn new() -> Self {
        Self([16_645, 32_768, 65_536, 32_768, 32_768, 3_234, 1_665, 32_768].map(|n| vec![0u8; n]))
    }
    fn storage(&mut self) -> Storage<'_> {
        let [record, handshake, outgoing, application, certificates, private_key, public_key, scratch] =
            &mut self.0;
        Storage {
            record,
            handshake,
            outgoing,
            application,
            certificates,
            private_key,
            public_key,
            scratch,
        }
    }
}

fn flush(from: &mut Connection<'_>, to: &mut Connection<'_>) -> iron_socket_layer::Result<()> {
    let n = from.outgoing().len();
    to.receive(from.outgoing())?;
    from.consume_outgoing(n)
}

/// One whole session. Returns allocator calls made after both constructors.
fn session(cc: &ClientConfig, sc: &ServerConfig, cb: &mut Buffers, sb: &mut Buffers) -> usize {
    let (mut cr, mut sr) = (rng(), rng());
    let mut c =
        Connection::client(cc, "server.test", &mut cr, cb.storage(), Limits::default()).unwrap();
    let mut s = Connection::server(sc, &mut sr, sb.storage(), Limits::default()).unwrap();
    HEAP.calls.store(0, Ordering::Relaxed);
    HEAP.gated.store(true, Ordering::Relaxed);
    for _ in 0..4 {
        flush(&mut c, &mut s).unwrap();
        flush(&mut s, &mut c).unwrap();
    }
    assert!(c.is_connected() && s.is_connected());
    assert!(c
        .report()
        .has(iron_socket_layer::report::Property::MutualAuthentication));
    let mut out = [0u8; 16];
    c.write_application(b"to server").unwrap();
    flush(&mut c, &mut s).unwrap();
    assert_eq!(s.read_application(&mut out).unwrap(), 9);
    c.key_update(true).unwrap();
    flush(&mut c, &mut s).unwrap();
    flush(&mut s, &mut c).unwrap();
    s.write_application(b"to client").unwrap();
    flush(&mut s, &mut c).unwrap();
    assert_eq!(c.read_application(&mut out).unwrap(), 9);
    let (mut ce, mut se) = ([0u8; 32], [0u8; 32]);
    c.export(b"qemu", b"", &mut ce).unwrap();
    s.export(b"qemu", b"", &mut se).unwrap();
    assert_eq!(ce, se);
    c.close().unwrap();
    flush(&mut c, &mut s).unwrap();
    s.close().unwrap();
    flush(&mut s, &mut c).unwrap();
    assert!(c.peer_closed() && s.peer_closed());
    HEAP.gated.store(false, Ordering::Relaxed);
    HEAP.calls.load(Ordering::Relaxed)
}

/// A client whose handshake buffer cannot hold the server's flight fails
/// with capacity-exceeded, latched, with nothing queued.
fn capacity_failure(cc: &ClientConfig, sc: &ServerConfig) {
    let mut cb = Buffers::new();
    cb.0[1] = vec![0u8; 256];
    let mut sb = Buffers::new();
    let (mut cr, mut sr) = (rng(), rng());
    let mut c =
        Connection::client(cc, "server.test", &mut cr, cb.storage(), Limits::default()).unwrap();
    let mut s = Connection::server(sc, &mut sr, sb.storage(), Limits::default()).unwrap();
    flush(&mut c, &mut s).unwrap();
    let n = s.outgoing().len();
    let e = c.receive(s.outgoing()).unwrap_err();
    s.consume_outgoing(n).unwrap();
    assert_eq!(e.kind(), ErrorKind::CapacityExceeded);
    assert_eq!(
        c.receive(b"\x16\x03\x03\x00\x01\x00").unwrap_err().kind(),
        ErrorKind::CapacityExceeded
    );
    assert!(c.outgoing().is_empty());
}

#[entry]
fn main() -> ! {
    static mut MEMORY: [MaybeUninit<u8>; HEAP_SIZE] = [MaybeUninit::uninit(); HEAP_SIZE];
    // SAFETY: `entry` gives this function the only reference to MEMORY.
    unsafe {
        HEAP.heap
            .init(core::ptr::addr_of_mut!(*MEMORY) as usize, HEAP_SIZE)
    };

    hprintln!("isl-qemu-m4: fixed engine on Cortex-M4 (QEMU MPS2-AN386)");
    let cases = [
        (KeyKind::EcdsaP256, NamedGroup::X25519),
        (KeyKind::EcdsaP256, NamedGroup::X25519MlKem768),
        (KeyKind::EcdsaP384, NamedGroup::SecP384r1MlKem1024),
        (KeyKind::Ed25519, NamedGroup::X25519MlKem768),
        (KeyKind::MlDsa44, NamedGroup::MlKem512),
        (KeyKind::MlDsa65, NamedGroup::X25519MlKem768),
        (KeyKind::MlDsa87, NamedGroup::SecP384r1MlKem1024),
        (KeyKind::MlDsa87, NamedGroup::MlKem1024),
    ];
    let mut worst = 0;
    for (kind, group) in cases {
        let (cc, sc) = configs(kind, group);
        let (mut cb, mut sb) = (Buffers::new(), Buffers::new());
        HEAP.peak
            .store(HEAP.in_use.load(Ordering::Relaxed), Ordering::Relaxed);
        let mut calls = usize::MAX;
        let stack = stack_used(&mut || calls = session(&cc, &sc, &mut cb, &mut sb));
        assert_eq!(calls, 0, "allocation after initialization");
        worst = worst.max(stack);
        hprintln!(
            "session {} {}: stack {} bytes, allocations after init {}",
            kind.id(),
            group.id(),
            stack,
            calls
        );
        if kind == KeyKind::EcdsaP256 && group == NamedGroup::X25519 {
            capacity_failure(&cc, &sc);
            hprintln!("capacity: an undersized handshake buffer is capacity-exceeded, latched");
        }
    }
    hprintln!("largest session stack: {} bytes", worst);
    hprintln!("PASS");
    debug::exit(debug::EXIT_SUCCESS);
    loop {
        cortex_m::asm::wfi();
    }
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    hprintln!("FAIL: {}", info);
    debug::exit(debug::EXIT_FAILURE);
    loop {
        cortex_m::asm::wfi();
    }
}
