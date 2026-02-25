//! Low-level I/O primitives shared by all parsers.
//!
//! Each function reads exactly the bytes it promises or returns an error -
//! there is no partial-read ambiguity.

use std::io::Read;

use crate::{Error, Result};

/// Read one byte.
#[inline]
pub(crate) fn u8<R: Read>(r: &mut R) -> Result<u8> {
    let mut b = [0u8; 1];
    r.read_exact(&mut b)?;
    Ok(b[0])
}

/// Read a little-endian `u16`.
#[inline]
pub(crate) fn le_u16<R: Read>(r: &mut R) -> Result<u16> {
    let mut b = [0u8; 2];
    r.read_exact(&mut b)?;
    Ok(u16::from_le_bytes(b))
}

/// Read a little-endian `u32`.
#[inline]
pub(crate) fn le_u32<R: Read>(r: &mut R) -> Result<u32> {
    let mut b = [0u8; 4];
    r.read_exact(&mut b)?;
    Ok(u32::from_le_bytes(b))
}

/// Read a little-endian `u64`.
#[inline]
pub(crate) fn le_u64<R: Read>(r: &mut R) -> Result<u64> {
    let mut b = [0u8; 8];
    r.read_exact(&mut b)?;
    Ok(u64::from_le_bytes(b))
}

/// Read a big-endian `u16`.
#[inline]
pub(crate) fn be_u16<R: Read>(r: &mut R) -> Result<u16> {
    let mut b = [0u8; 2];
    r.read_exact(&mut b)?;
    Ok(u16::from_be_bytes(b))
}

/// Read a big-endian `u32`.
#[inline]
pub(crate) fn be_u32<R: Read>(r: &mut R) -> Result<u32> {
    let mut b = [0u8; 4];
    r.read_exact(&mut b)?;
    Ok(u32::from_be_bytes(b))
}

/// Read a `u16` with caller-supplied endianness.
#[inline]
pub(crate) fn end_u16<R: Read>(r: &mut R, le: bool) -> Result<u16> {
    if le { le_u16(r) } else { be_u16(r) }
}

/// Read a `u32` with caller-supplied endianness.
#[inline]
pub(crate) fn end_u32<R: Read>(r: &mut R, le: bool) -> Result<u32> {
    if le { le_u32(r) } else { be_u32(r) }
}

/// Read exactly `N` bytes into a fixed-size array.
#[inline]
pub(crate) fn bytesa<const N: usize>(r: &mut impl Read) -> Result<[u8; N]> {
    let mut b = [0u8; N];
    r.read_exact(&mut b)?;
    Ok(b)
}

/// Read exactly `len` bytes into a `Vec`.
#[inline]
pub(crate) fn bytesv<R: Read>(r: &mut R, len: usize) -> Result<Vec<u8>> {
    let mut b = vec![0u8; len];
    r.read_exact(&mut b)?;
    Ok(b)
}

/// Verify that the next `N` bytes in the stream match `expected`.
///
/// Returns [`Error::BadMagic`] on mismatch.
#[inline]
pub(crate) fn magic<R: Read, const N: usize>(r: &mut R, expected: &[u8; N]) -> Result<()> {
    let got = bytesa::<N>(r)?;
    if &got != expected {
        return Err(Error::BadMagic);
    }
    Ok(())
}

/// Extract a null-terminated UTF-8 string from a byte slice at `offset`.
///
/// Returns [`Error::InvalidRange`] if `offset` is out of bounds, or
/// [`Error::UnterminatedName`] if no null byte is found.
#[inline]
pub(crate) fn null_string(buf: &[u8], offset: usize) -> Result<String> {
    let slice = buf.get(offset..).ok_or(Error::InvalidRange)?;
    let end = slice
        .iter()
        .position(|&b| b == 0)
        .ok_or(Error::UnterminatedName)?;
    Ok(String::from_utf8_lossy(&slice[..end]).into_owned())
}

/// Read a null-terminated UTF-8 string byte-by-byte from a reader.
pub(crate) fn read_null_string<R: Read>(r: &mut R) -> Result<String> {
    let mut bytes = Vec::new();
    loop {
        let b = u8(r)?;
        if b == 0 {
            break;
        }
        bytes.push(b);
    }
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}
