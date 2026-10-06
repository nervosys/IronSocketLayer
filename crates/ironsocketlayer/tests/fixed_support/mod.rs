//! Shared by the fixed-engine test binaries: a counting global allocator and
//! caller-owned buffers. The library retains forbid(unsafe_code); the unsafe
//! delegation below is solely the standard GlobalAlloc instrumentation
//! interface, never protocol code. Each binary that includes this module gets
//! its own allocator instance.
#![allow(dead_code)]

use ironsocketlayer::fixed::{Connection, Storage};
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::io::{Read, Write};
use std::net::TcpStream;

thread_local! { static GATE: Cell<bool> = const { Cell::new(false) }; static ALLOCATIONS: Cell<usize> = const { Cell::new(0) }; }
struct CountingAllocator;
fn count() {
    if GATE.try_with(Cell::get).unwrap_or(false) {
        let _ = ALLOCATIONS.try_with(|n| n.set(n.get() + 1));
        GATE.with(|g| g.set(false));
        if std::env::var_os("ISL_TRACE_ALLOC").is_some() {
            eprintln!("ALLOC {}", std::backtrace::Backtrace::force_capture());
        }
        GATE.with(|g| g.set(true));
    }
}
// SAFETY: each operation forwards its exact pointer/layout contract to System.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        count();
        unsafe { System.alloc(layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        count();
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, n: usize) -> *mut u8 {
        count();
        unsafe { System.realloc(ptr, layout, n) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
}
#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;
struct Gate;
impl Gate {
    fn new() -> Self {
        ALLOCATIONS.with(|n| n.set(0));
        GATE.with(|g| g.set(true));
        Self
    }
}
impl Drop for Gate {
    fn drop(&mut self) {
        GATE.with(|g| g.set(false));
    }
}
pub fn no_alloc<T>(f: impl FnOnce() -> T) -> T {
    let gate = Gate::new();
    let value = f();
    drop(gate);
    assert_eq!(
        ALLOCATIONS.with(Cell::get),
        0,
        "allocation after initialization"
    );
    value
}

pub struct Buffers {
    pub record: Vec<u8>,
    pub handshake: Vec<u8>,
    pub outgoing: Vec<u8>,
    pub application: Vec<u8>,
    pub certificates: Vec<u8>,
    pub private_key: Vec<u8>,
    pub public_key: Vec<u8>,
    pub scratch: Vec<u8>,
}
impl Buffers {
    pub fn new() -> Self {
        Self {
            record: vec![0; 16645],
            handshake: vec![0; 32768],
            outgoing: vec![0; 65536],
            application: vec![0; 32768],
            certificates: vec![0; 32768],
            private_key: vec![0; 3234],
            public_key: vec![0; 1665],
            scratch: vec![0; 32768],
        }
    }
    pub fn storage(&mut self) -> Storage<'_> {
        Storage {
            record: &mut self.record,
            handshake: &mut self.handshake,
            outgoing: &mut self.outgoing,
            application: &mut self.application,
            certificates: &mut self.certificates,
            private_key: &mut self.private_key,
            public_key: &mut self.public_key,
            scratch: &mut self.scratch,
        }
    }
}

/// Move bytes between a fixed connection and a socket. Decrypted data is
/// appended to `app`. Returns when `done` holds or the transport ends; the
/// caller then checks what arrived and whether the close was authenticated.
pub fn drive(
    conn: &mut Connection<'_>,
    sock: &mut TcpStream,
    app: &mut Vec<u8>,
    mut done: impl FnMut(&Connection<'_>, &[u8]) -> bool,
) -> Result<(), String> {
    let mut wire = vec![0u8; 16 * 1024 + 512];
    let mut plain = [0u8; 4096];
    loop {
        let queued = conn.outgoing().len();
        if queued > 0 {
            sock.write_all(conn.outgoing()).map_err(|e| e.to_string())?;
            no_alloc(|| conn.consume_outgoing(queued)).map_err(|e| e.to_string())?;
        }
        loop {
            let n = no_alloc(|| conn.read_application(&mut plain)).map_err(|e| e.to_string())?;
            if n == 0 {
                break;
            }
            app.extend_from_slice(&plain[..n]);
        }
        if done(conn, app) {
            return Ok(());
        }
        let n = match sock.read(&mut wire) {
            Ok(0) | Err(_) => return Ok(()),
            Ok(n) => n,
        };
        no_alloc(|| conn.receive(&wire[..n])).map_err(|e| e.to_string())?;
    }
}

/// Send application bytes and flush them.
pub fn send(conn: &mut Connection<'_>, sock: &mut TcpStream, bytes: &[u8]) -> Result<(), String> {
    no_alloc(|| conn.write_application(bytes)).map_err(|e| e.to_string())?;
    let mut ignored = Vec::new();
    drive(conn, sock, &mut ignored, |_, _| true)
}
