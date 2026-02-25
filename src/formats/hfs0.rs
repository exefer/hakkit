//! HFS0 (Hierarchical FileSystem 0 / SHA-256 FileSystem) - hashed archive.
//!
//! Used inside XCI game cards. The root HFS0 begins at offset 0x10000 in an
//! XCI and contains named sub-partitions (`normal`, `logo`, `update`,
//! `secure`).
//!
//! ## Layout
//! ```text
//! [0x00] Magic "HFS0"              (4 bytes)
//! [0x04] FileCount                 (u32 LE)
//! [0x08] StringTableSize           (u32 LE)
//! [0x0C] Reserved                  (4 bytes)
//! [0x10] EntryTable                (FileCount × 0x40 bytes)
//! [0x10 + FileCount×0x40]
//!        StringTable               (StringTableSize bytes)
//! [(after StringTable)]
//!        FileData                  (remaining bytes)
//! ```
//!
//! ## File Entry (0x40 bytes)
//! ```text
//! [0x00] DataOffset - relative to the data section start (u64 LE)
//! [0x08] DataSize   - in bytes (u64 LE)
//! [0x10] NameOffset - byte offset into the string table (u32 LE)
//! [0x14] HashedRegionSize - number of leading bytes covered by the hash (u32 LE)
//! [0x18] Reserved   (u32)
//! [0x1C] Reserved   (u32)
//! [0x20] SHA-256 hash of the first HashedRegionSize bytes (32 bytes)
//! ```
//!
//! ## XCI Root Partitions
//! * `normal` - CNMT NCA + icon NCA (empty on ≥4.0.0 firmware).
//! * `logo`   - [4.0.0+] supersedes normal partition content.
//! * `update` - system update NCAs.
//! * `secure` - all game NCAs (encrypted).

use std::io::{Read, Seek, SeekFrom, Take};
use std::ops::Index;

use crate::Result;
use crate::utils::{bytesa, bytesv, le_u32, le_u64, magic, null_string};

/// Parsed HFS0 container (metadata only).
///
/// File data is accessed via [`Hfs0Reader`].
#[derive(Debug)]
pub struct Hfs0 {
    /// All file entries in declaration order.
    pub files: Vec<Hfs0File>,
    /// Absolute byte offset (from stream start) where file data begins.
    pub(crate) data_offset: u64,
}

/// Metadata for a single file inside an HFS0.
#[derive(Debug, Clone)]
pub struct Hfs0File {
    /// File name decoded from the string table.
    pub name: String,
    /// Offset relative to the HFS0 data section.
    pub offset: u64,
    /// File size in bytes.
    pub size: u64,
    /// Number of leading bytes covered by `sha256`.
    pub hashed_region_size: u32,
    /// SHA-256 hash of the first `hashed_region_size` bytes.
    pub sha256: [u8; 32],
}

impl Hfs0 {
    /// Parse an HFS0 container from `r`.
    ///
    /// The reader must be positioned at the HFS0 magic.
    /// File contents are not read; use [`Hfs0Reader`] for data access.
    pub fn parse<R: Read + Seek>(r: &mut R) -> Result<Self> {
        let base = r.stream_position()?;

        magic(r, b"HFS0")?;
        let file_count = le_u32(r)?;
        let string_table_size = le_u32(r)?;
        let _reserved = le_u32(r)?;

        let mut entries = Vec::with_capacity(file_count as usize);
        for _ in 0..file_count {
            let offset = le_u64(r)?;
            let size = le_u64(r)?;
            let name_offset = le_u32(r)?;
            let hashed_region_size = le_u32(r)?;
            let _reserved1 = le_u32(r)?;
            let _reserved2 = le_u32(r)?;
            let sha256 = bytesa::<32>(r)?;
            entries.push((offset, size, name_offset, hashed_region_size, sha256));
        }

        let string_table = bytesv(r, string_table_size as usize)?;

        let mut files = Vec::with_capacity(file_count as usize);
        for (offset, size, name_offset, hashed_region_size, sha256) in entries {
            let name = null_string(&string_table, name_offset as usize)?;
            files.push(Hfs0File {
                name,
                offset,
                size,
                hashed_region_size,
                sha256,
            });
        }

        // Data section begins immediately after the header + entry table + string table.
        let entry_table_size = file_count as u64 * 0x40;
        let data_offset = base + 0x10 + entry_table_size + string_table_size as u64;

        Ok(Self { files, data_offset })
    }
}

/// Streaming reader wrapper around an [`Hfs0`] container.
pub struct Hfs0Reader<R> {
    inner: R,
    /// Parsed metadata.
    pub hfs0: Hfs0,
}

impl<R: Read + Seek> Hfs0Reader<R> {
    /// Parse an HFS0 and wrap the provided reader.
    pub fn new(mut reader: R) -> Result<Self> {
        let hfs0 = Hfs0::parse(&mut reader)?;
        Ok(Self {
            inner: reader,
            hfs0,
        })
    }

    /// Open a file for streaming access.
    ///
    /// Seeks to the file's start and returns a [`Take`] limited to its byte
    /// range. The borrow ends when the [`Take`] is dropped.
    pub fn read_file(&mut self, file: &Hfs0File) -> Result<Take<&mut R>> {
        self.inner
            .seek(SeekFrom::Start(self.hfs0.data_offset + file.offset))?;
        Ok(self.inner.by_ref().take(file.size))
    }

    /// Iterate over all file entries.
    pub fn files(&self) -> impl Iterator<Item = &Hfs0File> {
        self.hfs0.files.iter()
    }

    /// Find a file by name. Returns [`None`] if not found.
    pub fn get_file_by_name(&self, name: &str) -> Option<&Hfs0File> {
        self.hfs0.files.iter().find(|f| f.name == name)
    }

    /// Consume the reader, returning the inner reader.
    pub fn into_inner(self) -> R {
        self.inner
    }
}

impl<R: Read + Seek> Index<&str> for Hfs0Reader<R> {
    type Output = Hfs0File;

    /// Index by file name.
    ///
    /// # Panics
    /// Panics if the file name does not exist.
    fn index(&self, index: &str) -> &Self::Output {
        self.get_file_by_name(index)
            .unwrap_or_else(|| panic!("no file '{index}' in HFS0"))
    }
}
