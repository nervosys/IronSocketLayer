//! A byte queue that leaves no copy of what passed through it.
//!
//! Received application data is the caller's secret as much as a key is: an
//! HTTPS response can carry a token or a derived key. A `Vec` or `VecDeque`
//! leaves it behind three ways: bytes already read stay in the allocation,
//! growing moves the contents and frees the old allocation unwiped, and
//! dropping frees the last one unwiped. [`WipeBuf`] closes all three.
//! `REQ-CONN-017`.

use alloc::vec;
use alloc::vec::Vec;

use ic_core::Zeroize;

/// Smallest storage allocated.
const MIN_CAPACITY: usize = 4096;

/// A contiguous first-in, first-out byte buffer that wipes bytes as they
/// leave, the old storage when it grows, and everything when it is dropped.
///
/// The storage is always fully initialized, and every byte outside the live
/// range is zero. That is what lets a test read the whole of it, without
/// `unsafe`, and see that nothing is left.
pub(crate) struct WipeBuf {
    buf: Vec<u8>,
    head: usize,
    tail: usize,
}

impl WipeBuf {
    /// An empty buffer; nothing is allocated until bytes arrive.
    pub(crate) const fn new() -> Self {
        Self {
            buf: Vec::new(),
            head: 0,
            tail: 0,
        }
    }

    /// Bytes held.
    pub(crate) fn len(&self) -> usize {
        self.tail - self.head
    }

    /// The bytes held, oldest first.
    pub(crate) fn as_slice(&self) -> &[u8] {
        &self.buf[self.head..self.tail]
    }

    /// The bytes held, for work in place.
    pub(crate) fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.buf[self.head..self.tail]
    }

    /// Append `data`.
    pub(crate) fn extend_from_slice(&mut self, data: &[u8]) {
        // The storage this replaced is already wiped; dropping it frees it.
        drop(self.make_room(data.len()));
        let end = self.tail + data.len();
        self.buf[self.tail..end].copy_from_slice(data);
        self.tail = end;
    }

    /// Make room for `extra` more bytes after the live range, returning the
    /// storage this replaced, wiped, when it had to grow.
    fn make_room(&mut self, extra: usize) -> Option<Vec<u8>> {
        if self.buf.len() - self.tail >= extra {
            return None;
        }
        let live = self.len();
        let need = live.saturating_add(extra);
        if need <= self.buf.len() {
            // Slide the live bytes to the front and wipe where they were.
            self.buf.copy_within(self.head..self.tail, 0);
            self.buf[live..self.tail].zeroize();
            self.head = 0;
            self.tail = live;
            return None;
        }
        let capacity = need.max(self.buf.len().saturating_mul(2)).max(MIN_CAPACITY);
        let mut grown = vec![0u8; capacity];
        grown[..live].copy_from_slice(&self.buf[self.head..self.tail]);
        let mut old = core::mem::replace(&mut self.buf, grown);
        old.as_mut_slice().zeroize();
        self.head = 0;
        self.tail = live;
        Some(old)
    }

    /// Wipe and discard the oldest `n` bytes (all of them, if fewer are held).
    pub(crate) fn consume(&mut self, n: usize) {
        let n = n.min(self.len());
        self.buf[self.head..self.head + n].zeroize();
        self.head += n;
        if self.head == self.tail {
            self.head = 0;
            self.tail = 0;
        }
    }

    /// Move the oldest bytes into `out`, returning how many, and wipe them
    /// here.
    pub(crate) fn read(&mut self, out: &mut [u8]) -> usize {
        let n = out.len().min(self.len());
        out[..n].copy_from_slice(&self.buf[self.head..self.head + n]);
        self.consume(n);
        n
    }

    /// Wipe and discard everything held.
    pub(crate) fn wipe(&mut self) {
        self.buf.as_mut_slice().zeroize();
        self.head = 0;
        self.tail = 0;
    }

    /// The whole storage, live or not.
    #[cfg(test)]
    pub(crate) fn storage(&self) -> &[u8] {
        &self.buf
    }
}

impl Drop for WipeBuf {
    fn drop(&mut self) {
        self.buf.as_mut_slice().zeroize();
    }
}

impl core::fmt::Debug for WipeBuf {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "WipeBuf({} bytes)", self.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every byte of the storage outside the live range is zero.
    fn nothing_stray(b: &WipeBuf) {
        assert!(b.storage()[..b.head].iter().all(|x| *x == 0), "before");
        assert!(b.storage()[b.tail..].iter().all(|x| *x == 0), "after");
    }

    /// REQ-CONN-017: bytes read out or consumed are gone from the storage,
    /// not merely skipped.
    #[test]
    fn consumed_bytes_are_wiped() {
        let mut b = WipeBuf::new();
        b.extend_from_slice(&[0xa5; 1000]);
        let mut out = [0u8; 300];
        assert_eq!(b.read(&mut out), 300);
        assert_eq!(out, [0xa5; 300]);
        assert_eq!(b.len(), 700);
        nothing_stray(&b);
        b.consume(699);
        assert_eq!(b.as_slice(), [0xa5]);
        nothing_stray(&b);
        // More than is held takes what there is.
        b.consume(usize::MAX);
        assert_eq!(b.len(), 0);
        assert!(b.storage().iter().all(|x| *x == 0));
        assert_eq!(b.read(&mut out), 0);
    }

    /// REQ-CONN-017: sliding the live bytes forward to make room leaves no
    /// copy where they were.
    #[test]
    fn compaction_leaves_no_copy() {
        let mut b = WipeBuf::new();
        b.extend_from_slice(&[0xa5; MIN_CAPACITY]);
        b.consume(MIN_CAPACITY - 10);
        let storage = b.storage().len();
        b.extend_from_slice(&[0x5a; 100]);
        assert_eq!(b.storage().len(), storage, "it compacted, not grew");
        assert_eq!(b.head, 0);
        assert_eq!(&b.as_slice()[..10], [0xa5; 10]);
        assert_eq!(&b.as_slice()[10..], [0x5a; 100]);
        nothing_stray(&b);
    }

    /// REQ-CONN-017: the storage a growing buffer leaves behind is wiped
    /// before it is freed, and the bytes arrive intact in the new one.
    #[test]
    fn growth_wipes_the_old_storage() {
        let mut b = WipeBuf::new();
        b.extend_from_slice(&[0xa5; MIN_CAPACITY]);
        let old = b.make_room(1).expect("full storage has to grow");
        assert_eq!(old.len(), MIN_CAPACITY);
        assert!(
            old.iter().all(|x| *x == 0),
            "plaintext left in freed storage"
        );
        assert_eq!(b.as_slice(), [0xa5; MIN_CAPACITY]);
        nothing_stray(&b);
        // Room that is already there replaces nothing.
        assert!(b.make_room(1).is_none());
    }

    /// REQ-CONN-017: wiping on failure empties the whole storage.
    #[test]
    fn wipe_empties_the_storage() {
        let mut b = WipeBuf::new();
        b.extend_from_slice(&[0xa5; 5000]);
        b.as_mut_slice()[0] = 0x11;
        b.wipe();
        assert_eq!(b.len(), 0);
        assert!(!b.storage().is_empty());
        assert!(b.storage().iter().all(|x| *x == 0));
    }
}
