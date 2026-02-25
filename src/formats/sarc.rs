//! SARC (SEAD ARChive) - general-purpose Nintendo archive.
//!
//! Used pervasively in Switch (and Wii U/3DS) game content. Often delivered
//! with a `.zs` suffix when Zstandard-compressed, or `.szs` for Yaz0.
//!
//! ## Layout
//! ```text
//! [0x00] SARC header  (0x14 bytes)
//! [0x14] SFAT header  (0x0C bytes) + FAT entries (FileCount × 0x10)
//! [...]  SFNT header  (0x08 bytes) + null-terminated filenames (4-byte aligned)
//! [...]  Data section (begins at offset given in SARC header)
//! ```
//!
//! ## Endianness
//! Determined by BOM: `0xFEFF` = Big Endian, `0xFFFE` = Little Endian.
//!
//! ## SARC Header (0x14 bytes)
//! ```text
//! [0x00] Magic "SARC"       (4 bytes)
//! [0x04] HeaderSize (0x14)  (u16 LE)
//! [0x06] BOM                (u16 LE)
//! [0x08] TotalFileSize      (u32, endian per BOM)
//! [0x0C] DataOffset         (u32, endian per BOM)
//! [0x10] Version (0x0100)   (u16 LE)
//! [0x12] Padding
//! ```
//!
//! ## SFAT Header (0x0C bytes)
//! ```text
//! [0x00] Magic "SFAT"           (4 bytes)
//! [0x04] HeaderSize (0x0C)      (u16)
//! [0x06] FileCount (max 0x3FFF) (u16, endian per BOM)
//! [0x08] HashMultiplier (101)   (u32, endian per BOM)
//! ```
//!
//! ## SFAT Entry (0x10 bytes)
//! ```text
//! [0x00] FilenameHash           (u32, endian per BOM)
//! [0x04] FilenameAttrs          (u32, endian per BOM)
//!         0 = no name; else 0xAABBBBBB where BBBBBB = name-table word offset
//! [0x08] DataStart              (u32, endian per BOM) - relative to data section
//! [0x0C] DataEnd                (u32, endian per BOM)
//! ```
//! Entries are sorted by hash; runtime uses binary search.
//!
//! ## SFNT Header (0x08 bytes)
//! ```text
//! [0x00] Magic "SFNT"     (4 bytes)
//! [0x04] HeaderSize (8)   (u16)
//! [0x06] Padding
//! [0x08] Null-terminated filenames, 4-byte aligned
//! ```
//!
//! ## Filename Hash
//! Each byte is sign-extended as i8 before accumulating:
//! ```rust
//! fn hash(name: &[u8], multiplier: u32) -> u32 {
//!     let mut h: u32 = 0;
//!     for &b in name {
//!         h = h.wrapping_mul(multiplier).wrapping_add(b as i8 as u32);
//!     }
//!     h
//! }
//! ```

use std::io::{Read, Seek, SeekFrom, Take};
use std::ops::Index;

use crate::utils::{end_u16, end_u32, le_u16, magic, read_null_string};
use crate::{Error, Result};

/// Parsed SARC archive (metadata only).
///
/// File data is accessed via [`SarcReader`].
#[derive(Debug)]
pub struct Sarc {
    /// All file entries.
    pub files: Vec<SarcFile>,
    /// Whether the archive uses little-endian encoding.
    pub le: bool,
    /// Format version from the SARC header (normally 0x0100).
    pub version: u16,
    /// Hash multiplier from the SFAT header (always 101 = 0x65).
    pub hash_multiplier: u32,
    /// Absolute stream offset where file data begins.
    pub(crate) data_offset: u64,
}

/// A single file entry inside a SARC archive.
#[derive(Debug, Clone)]
pub struct SarcFile {
    /// Filename ([`None`] if the archive has no name table entry for this file).
    pub name: Option<String>,
    /// CRC hash of the filename.
    pub hash: u32,
    /// Start byte offset within the SARC data section.
    pub data_start: u32,
    /// End byte offset within the SARC data section (exclusive).
    pub data_end: u32,
}

impl SarcFile {
    /// Size of this file's data in bytes.
    pub fn size(&self) -> u64 {
        self.data_end.saturating_sub(self.data_start) as u64
    }
}

impl Sarc {
    /// Parse a SARC archive from `r`.
    ///
    /// `r` must be positioned at the very beginning of the SARC magic.
    pub fn parse<R: Read + Seek>(r: &mut R) -> Result<Self> {
        let sarc_start = r.stream_position()?;

        magic(r, b"SARC")?;

        let header_size = le_u16(r)?;
        if header_size != 0x14 {
            return Err(Error::Parse("unexpected SARC header size"));
        }

        // BOM is always written LE regardless of archive endianness.
        let bom = le_u16(r)?;
        let le = match bom {
            0xFFFE => true,
            0xFEFF => false,
            _ => return Err(Error::Parse("invalid SARC BOM")),
        };

        let _total_size = end_u32(r, le)?;
        let data_offset = end_u32(r, le)? as u64;
        let version = le_u16(r)?;
        let _padding = le_u16(r)?;

        // SFAT header (0x0C bytes)
        magic(r, b"SFAT")?;
        let sfat_size = le_u16(r)?;
        if sfat_size != 0x0C {
            return Err(Error::Parse("unexpected SFAT header size"));
        }
        let file_count = end_u16(r, le)?;
        let hash_multiplier = end_u32(r, le)?;

        if file_count > 0x3FFF {
            return Err(Error::Parse("SARC file count exceeds maximum"));
        }

        // FAT entries
        let mut fat = Vec::with_capacity(file_count as usize);
        for _ in 0..file_count {
            let hash = end_u32(r, le)?;
            let name_attrs = end_u32(r, le)?;
            let data_start = end_u32(r, le)?;
            let data_end = end_u32(r, le)?;
            fat.push((hash, name_attrs, data_start, data_end));
        }

        // SFNT header (0x08 bytes)
        magic(r, b"SFNT")?;
        let sfnt_size = le_u16(r)?;
        if sfnt_size != 8 {
            return Err(Error::Parse("unexpected SFNT header size"));
        }
        let _sfnt_padding = le_u16(r)?;

        // Name table starts immediately after SFNT header.
        let name_table_start = r.stream_position()?;

        let mut files = Vec::with_capacity(file_count as usize);
        for (hash, name_attrs, data_start, data_end) in fat {
            let name = if name_attrs == 0 {
                None
            } else {
                // name_attrs = 0xAABBBBBB; BBBBBB is the word offset (× 4) into
                // the name table.
                let word_off = (name_attrs & 0x00FFFFFF) as u64;
                let byte_off = word_off * 4;
                let saved_pos = r.stream_position()?;
                r.seek(SeekFrom::Start(name_table_start + byte_off))?;
                let name = read_null_string(r)?;
                r.seek(SeekFrom::Start(saved_pos))?;
                Some(name)
            };
            files.push(SarcFile {
                name,
                hash,
                data_start,
                data_end,
            });
        }

        Ok(Self {
            files,
            le,
            version,
            hash_multiplier,
            data_offset: sarc_start + data_offset,
        })
    }

    /// Compute the canonical hash for a filename using this archive's
    /// multiplier.
    pub fn hash_filename(&self, name: &str) -> u32 {
        sarc_hash(name.as_bytes(), self.hash_multiplier)
    }

    /// Find a file by its exact name.
    ///
    /// Uses hash-then-name comparison.
    pub fn get_file_by_name(&self, name: &str) -> Option<&SarcFile> {
        let target = sarc_hash(name.as_bytes(), self.hash_multiplier);
        self.files
            .iter()
            .find(|f| f.hash == target && f.name.as_deref() == Some(name))
    }
}

/// Streaming reader wrapper over a parsed [`Sarc`] archive.
pub struct SarcReader<R> {
    inner: R,
    /// Parsed metadata.
    pub sarc: Sarc,
}

impl<R: Read + Seek> SarcReader<R> {
    /// Parse a SARC archive and wrap the provided reader.
    pub fn new(mut reader: R) -> Result<Self> {
        let sarc = Sarc::parse(&mut reader)?;
        Ok(Self {
            inner: reader,
            sarc,
        })
    }

    /// Open a file for streaming access.
    ///
    /// Seeks to the file's start and returns a [`Take`] limited to its byte
    /// range. The borrow ends when the [`Take`] is dropped.
    pub fn read_file(&mut self, file: &SarcFile) -> Result<Take<&mut R>> {
        self.inner.seek(SeekFrom::Start(
            self.sarc.data_offset + file.data_start as u64,
        ))?;
        Ok(self.inner.by_ref().take(file.size()))
    }

    /// Iterate over all file entries.
    pub fn files(&self) -> impl Iterator<Item = &SarcFile> {
        self.sarc.files.iter()
    }

    /// Find a file by name. Returns [`None`] if not found.
    pub fn get_file_by_name(&self, name: &str) -> Option<&SarcFile> {
        self.sarc.get_file_by_name(name)
    }

    /// Consume the reader, returning the inner reader.
    pub fn into_inner(self) -> R {
        self.inner
    }
}

impl<R: Read + Seek> Index<&str> for SarcReader<R> {
    type Output = SarcFile;

    /// Index by file name.
    ///
    /// # Panics
    /// Panics if the file name does not exist in the archive.
    fn index(&self, index: &str) -> &Self::Output {
        self.get_file_by_name(index)
            .unwrap_or_else(|| panic!("no file '{index}' in SARC"))
    }
}

/// SARC filename hash algorithm.
///
/// Each byte is sign-extended (cast to `i8`) before accumulating. This is
/// required to correctly handle non-ASCII characters in Switch game paths.
pub fn sarc_hash(name: &[u8], multiplier: u32) -> u32 {
    let mut h: u32 = 0;
    for &b in name {
        h = h.wrapping_mul(multiplier).wrapping_add(b as i8 as u32);
    }
    h
}
