//! Wire encoding for TLS presentation-language structures (RFC 8446 §3).
//!
//! Every read is bounds-checked and returns [`Error`] rather than panicking:
//! the input is attacker-controlled by definition. A [`Reader`] never reads
//! past its slice, and a length-prefixed sub-reader is confined to exactly the
//! bytes its prefix names, so an inner structure cannot consume its parent's
//! trailing fields.
//!
//! Requirement trace: `REQ-CODEC-001` (no panic on any input),
//! `REQ-CODEC-002` (length prefixes bound nested parsing),
//! `REQ-CODEC-003` (trailing data is rejected where the grammar ends).

use alloc::vec::Vec;

use crate::error::{Error, ErrorKind, Result};

/// A cursor over untrusted bytes.
#[derive(Debug, Clone)]
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    /// Read from the start of `buf`.
    pub const fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// Bytes not yet consumed.
    pub fn rest(&self) -> &'a [u8] {
        self.buf.get(self.pos..).unwrap_or(&[])
    }

    /// Number of bytes not yet consumed.
    pub fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    /// True when every byte has been consumed.
    pub fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    /// Fail unless every byte has been consumed. `REQ-CODEC-003`.
    pub fn finish(&self) -> Result<()> {
        if self.is_empty() {
            Ok(())
        } else {
            Err(Error::new(
                ErrorKind::Decode,
                "trailing bytes after structure",
            ))
        }
    }

    /// Take exactly `n` bytes.
    pub fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or(Error::new(ErrorKind::Decode, "length overflow"))?;
        let out = self
            .buf
            .get(self.pos..end)
            .ok_or(Error::new(ErrorKind::Decode, "truncated structure"))?;
        self.pos = end;
        Ok(out)
    }

    /// Take a fixed-size array.
    pub fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        let bytes = self.take(N)?;
        let mut out = [0u8; N];
        out.copy_from_slice(bytes);
        Ok(out)
    }

    /// Read a `uint8`.
    pub fn u8(&mut self) -> Result<u8> {
        Ok(self.array::<1>()?[0])
    }

    /// Read a big-endian `uint16`.
    pub fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(self.array::<2>()?))
    }

    /// Read a big-endian `uint24`.
    pub fn u24(&mut self) -> Result<u32> {
        let b = self.array::<3>()?;
        Ok(u32::from_be_bytes([0, b[0], b[1], b[2]]))
    }

    /// Read a big-endian `uint32`.
    pub fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.array::<4>()?))
    }

    /// Read an opaque vector with a one-byte length prefix.
    pub fn vec8(&mut self) -> Result<&'a [u8]> {
        let n = self.u8()? as usize;
        self.take(n)
    }

    /// Read an opaque vector with a two-byte length prefix.
    pub fn vec16(&mut self) -> Result<&'a [u8]> {
        let n = self.u16()? as usize;
        self.take(n)
    }

    /// Read an opaque vector with a three-byte length prefix.
    pub fn vec24(&mut self) -> Result<&'a [u8]> {
        let n = self.u24()? as usize;
        self.take(n)
    }

    /// A sub-reader over a one-byte-prefixed vector. `REQ-CODEC-002`.
    pub fn sub8(&mut self) -> Result<Reader<'a>> {
        Ok(Reader::new(self.vec8()?))
    }

    /// A sub-reader over a two-byte-prefixed vector. `REQ-CODEC-002`.
    pub fn sub16(&mut self) -> Result<Reader<'a>> {
        Ok(Reader::new(self.vec16()?))
    }

    /// A sub-reader over a three-byte-prefixed vector. `REQ-CODEC-002`.
    pub fn sub24(&mut self) -> Result<Reader<'a>> {
        Ok(Reader::new(self.vec24()?))
    }
}

/// Append a `uint8`.
pub fn put_u8(out: &mut Vec<u8>, v: u8) {
    out.push(v);
}

/// Append a big-endian `uint16`.
pub fn put_u16(out: &mut Vec<u8>, v: u16) {
    out.extend_from_slice(&v.to_be_bytes());
}

/// Append a big-endian `uint24`. Values above `2^24 - 1` are a caller bug and
/// are refused rather than truncated.
pub fn put_u24(out: &mut Vec<u8>, v: u32) -> Result<()> {
    if v > 0x00ff_ffff {
        return Err(Error::new(ErrorKind::Internal, "uint24 overflow"));
    }
    let b = v.to_be_bytes();
    out.extend_from_slice(&b[1..]);
    Ok(())
}

/// Append a big-endian `uint32`.
pub fn put_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_be_bytes());
}

/// Width of a length prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Prefix {
    /// One byte.
    U8,
    /// Two bytes.
    U16,
    /// Three bytes.
    U24,
}

impl Prefix {
    const fn width(self) -> usize {
        match self {
            Self::U8 => 1,
            Self::U16 => 2,
            Self::U24 => 3,
        }
    }

    const fn max(self) -> usize {
        match self {
            Self::U8 => 0xff,
            Self::U16 => 0xffff,
            Self::U24 => 0x00ff_ffff,
        }
    }
}

/// Append `body` behind a length prefix.
pub fn put_vec(out: &mut Vec<u8>, prefix: Prefix, body: &[u8]) -> Result<()> {
    nested(out, prefix, |o| {
        o.extend_from_slice(body);
        Ok(())
    })
}

/// Write a length-prefixed structure whose length is only known once written.
///
/// The prefix is reserved, `f` writes the body, and the prefix is then filled
/// in. A body longer than the prefix can express is an error, never a silently
/// wrapped length.
pub fn nested<F>(out: &mut Vec<u8>, prefix: Prefix, f: F) -> Result<()>
where
    F: FnOnce(&mut Vec<u8>) -> Result<()>,
{
    let at = out.len();
    out.resize(at + prefix.width(), 0);
    f(out)?;
    let len = out.len() - at - prefix.width();
    if len > prefix.max() {
        return Err(Error::new(
            ErrorKind::Internal,
            "structure exceeds its length prefix",
        ));
    }
    let be = (len as u32).to_be_bytes();
    let slot = out
        .get_mut(at..at + prefix.width())
        .ok_or(Error::new(ErrorKind::Internal, "length slot"))?;
    slot.copy_from_slice(&be[4 - prefix.width()..]);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_are_bounded() {
        let mut r = Reader::new(&[0x00, 0x03, 1, 2]);
        assert_eq!(r.vec16().unwrap_err().kind(), ErrorKind::Decode);
        let mut r = Reader::new(&[]);
        assert!(r.u8().is_err());
        assert!(r.u24().is_err());
        let mut r = Reader::new(&[0xff; 3]);
        assert_eq!(r.u24().unwrap(), 0x00ff_ffff);
        assert!(r.finish().is_ok());
    }

    #[test]
    fn a_sub_reader_cannot_escape_its_prefix() {
        // Prefix says 1 byte; the inner reader must not see the second.
        let data = [0x01, 0xaa, 0xbb];
        let mut r = Reader::new(&data);
        let mut inner = r.sub8().unwrap();
        assert_eq!(inner.u8().unwrap(), 0xaa);
        assert!(inner.u8().is_err());
        assert_eq!(r.u8().unwrap(), 0xbb);
    }

    #[test]
    fn nested_writes_round_trip() {
        let mut out = Vec::new();
        nested(&mut out, Prefix::U24, |o| {
            put_vec(o, Prefix::U8, b"abc")?;
            put_u16(o, 7);
            Ok(())
        })
        .unwrap();
        let mut r = Reader::new(&out);
        let mut inner = r.sub24().unwrap();
        assert_eq!(inner.vec8().unwrap(), b"abc");
        assert_eq!(inner.u16().unwrap(), 7);
        inner.finish().unwrap();
        r.finish().unwrap();
    }

    /// REQ-CODEC-003.
    #[test]
    fn trailing_bytes_are_refused() {
        let mut r = Reader::new(&[1, 2, 3]);
        r.u16().unwrap();
        assert_eq!(r.finish().unwrap_err().kind(), ErrorKind::Decode);
        r.u8().unwrap();
        r.finish().unwrap();
    }

    #[test]
    fn an_oversized_body_is_refused() {
        let mut out = Vec::new();
        let big = [0u8; 256];
        assert!(put_vec(&mut out, Prefix::U8, &big).is_err());
        assert!(put_u24(&mut out, 0x0100_0000).is_err());
    }
}
