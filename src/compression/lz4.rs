//! LZ4 decompression (requires the `compression` feature).
//!
//! LZ4 appears in some older Nintendo internal formats and tooling. The
//! compressed data is expected to be in the **size-prepended block format**:
//! a little-endian `u32` giving the decompressed byte count, immediately
//! followed by the raw LZ4 block data. This matches the layout produced and
//! consumed by [`lz4_flex::decompress_size_prepended`]`.
//!
//! For the formats more commonly encountered in this library (SARC `.zs`
//! archives, NCZ section blocks) see [`crate::compression::zstd`].

#![cfg(feature = "compression")]

use crate::{Error, Result};

/// Decompress an LZ4-compressed buffer.
///
/// `data` must begin with a little-endian `u32` decompressed-size prefix
/// followed by the raw LZ4 block.
///
/// Returns [`Error::Lz4`] on any decompression failure.
pub fn decompress_lz4(data: &[u8]) -> Result<Vec<u8>> {
    lz4_flex::decompress_size_prepended(data).map_err(|_| Error::Lz4)
}
