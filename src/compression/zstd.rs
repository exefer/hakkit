//! Zstandard decompression (requires the `compression` feature).
//!
//! Zstd is Nintendo's preferred compression algorithm for modern Switch
//! content. It appears in two contexts within hakkit:
//!
//! * **SARC archives** - a `.sarc.zs` (or just `.zs`) file is a complete SARC
//!   blob compressed as a single Zstd stream. Decompress the whole file first
//!   with [`decompress_zstd`], then parse the resulting bytes with
//!   [`crate::formats::sarc::Sarc::parse`].
//!
//! * **NCZ blocks** - each compressed block inside a `.ncz` file is an
//!   independent Zstd stream prefixed by its compressed byte length. Use
//!   [`decompress_zstd_with_size`] when the decompressed size is known in
//!   advance (it is recorded in the NCZ section descriptor) to avoid
//!   reallocations on large NCA sections.

#![cfg(feature = "compression")]

use std::io;

use crate::{Error, Result};

/// Decompress a complete Zstandard-compressed buffer.
///
/// Returns [`Error::Zstd`] on any decompression failure.
pub fn decompress_zstd(data: &[u8]) -> Result<Vec<u8>> {
    zstd::decode_all(data).map_err(|_| Error::Zstd)
}

/// Decompress a Zstandard-compressed buffer when the decompressed size is
/// known ahead of time.
///
/// Pre-allocating with `decompressed_size` avoids incremental `Vec`
/// reallocations, which matters for large NCA section payloads (often
/// hundreds of megabytes).
///
/// Returns [`Error::Zstd`] if the decoder cannot be initialised, or
/// [`Error::Io`] if streaming the output fails.
pub fn decompress_zstd_with_size(data: &[u8], decompressed_size: usize) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(decompressed_size);
    let mut decoder = zstd::Decoder::new(data)?;
    io::copy(&mut decoder, &mut out)?;
    Ok(out)
}
