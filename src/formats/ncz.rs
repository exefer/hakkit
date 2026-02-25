//! NCZ - Zstandard-compressed NCA sections (used inside NSZ archives).
//!
//! An NSZ file is **not** a distinct binary format; it is an NSP (PFS0)
//! where individual NCA entries have been compressed with a Nintendo-specific
//! scheme and renamed from `.nca` to `.ncz`.
//!
//! ## NCZ Layout
//! ```text
//! [0x000]          Standard NCA header (0x400 bytes, still encrypted)
//! [0x400]          Magic "NCZSECTN"                    (8 bytes)
//! [0x408]          SectionCount                        (u64 LE)
//! [0x410 + N×0x38] Section descriptors                 (N × 0x38 bytes)
//! [...]            Zstandard-compressed data blocks
//! ```
//!
//! Each block starts with a `u32 LE` giving the compressed byte length,
//! followed by that many bytes of Zstd-compressed data.
//!
//! ## Section Descriptor (0x38 bytes)
//! ```text
//! [0x00] Offset      - within the plaintext NCA (u64 LE)
//! [0x08] Size        - decompressed (u64 LE)
//! [0x10] CryptoType  (u8)
//! [0x11] Reserved    (7 bytes)
//! [0x18] CryptoKey   (16 bytes)
//! [0x28] CryptoCounter (16 bytes)
//! ```
//!
//! ## Typical usage with hakkit
//! 1. Parse the NSZ as a `Pfs0`.
//! 2. For entries with a `.ncz` extension, read the raw bytes.
//! 3. Parse the NcZ header with [`NczHeader::parse`].
//! 4. Decompress each block with `compression::zstd`.
//! 5. Reconstruct the plaintext NCA and feed it to `Nca::parse`.

use std::io::{Read, Seek, SeekFrom};

use crate::Result;
use crate::utils::{bytesa, bytesv, le_u64, magic, u8};

/// Parsed NCZ header (the part after the standard NCA header).
#[derive(Debug)]
pub struct NczHeader {
    /// Section descriptors describing each encrypted/compressed region.
    pub sections: Vec<NczSection>,
    /// Absolute byte offset (within the NCZ stream) where the compressed
    /// data blocks begin.
    pub blocks_offset: u64,
}

/// Descriptor for one NCA section within an NCZ file.
#[derive(Debug, Clone)]
pub struct NczSection {
    /// Byte offset of this section within the plaintext NCA.
    pub offset: u64,
    /// Decompressed size in bytes.
    pub size: u64,
    /// Encryption type identifier (matches NCA FsHeader EncryptionType).
    pub crypto_type: u8,
    /// AES key for this section (16 bytes).
    pub crypto_key: [u8; 16],
    /// AES counter / IV for this section (16 bytes).
    pub crypto_counter: [u8; 16],
}

impl NczHeader {
    /// Parse the NCZ-specific header from `r`.
    ///
    /// `r` must be positioned immediately **after** the 0x400-byte NCA header,
    /// i.e. at the `NCZSECTN` magic.
    pub fn parse<R: Read + Seek>(r: &mut R) -> Result<Self> {
        magic(r, b"NCZSECTN")?;

        let section_count = le_u64(r)?;
        let mut sections = Vec::with_capacity(section_count as usize);
        for _ in 0..section_count {
            let offset = le_u64(r)?;
            let size = le_u64(r)?;
            let crypto_type = u8(r)?;
            let _reserved = bytesa::<7>(r)?;
            let crypto_key = bytesa::<16>(r)?;
            let crypto_counter = bytesa::<16>(r)?;
            sections.push(NczSection {
                offset,
                size,
                crypto_type,
                crypto_key,
                crypto_counter,
            });
        }

        let blocks_offset = r.stream_position()?;

        Ok(Self {
            sections,
            blocks_offset,
        })
    }
}

/// Read all Zstandard-compressed blocks from an NCZ stream.
///
/// `r` must be positioned at `header.blocks_offset`. Returns the raw
/// compressed payloads in order; callers decompress them individually.
///
/// Each block is prefixed with a `u32 LE` giving its compressed byte length.
pub fn read_compressed_blocks<R: Read + Seek>(
    r: &mut R,
    header: &NczHeader,
) -> Result<Vec<Vec<u8>>> {
    r.seek(SeekFrom::Start(header.blocks_offset))?;
    let mut blocks = Vec::new();
    loop {
        // Peek at four bytes to detect end-of-stream.
        let size_buf = {
            let mut b = [0u8; 4];
            match r.read(&mut b) {
                Ok(0) => break,
                Ok(4) => b,
                Ok(_) => break, // short read = end of data
                Err(_) => break,
            }
        };
        let compressed_size = u32::from_le_bytes(size_buf) as usize;
        if compressed_size == 0 {
            break;
        }
        let block = bytesv(r, compressed_size)?;
        blocks.push(block);
    }
    Ok(blocks)
}
