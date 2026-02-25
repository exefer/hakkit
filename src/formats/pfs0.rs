//! PFS0 (PartitionFS) - flat archive container.
//!
//! Used as the outer container for NSP files and embedded inside NCAs as the
//! ExeFS and Logo sections.
//!
//! ## Layout
//! ```text
//! [0x00] Magic "PFS0"              (4 bytes)
//! [0x04] FileCount                 (u32 LE)
//! [0x08] StringTableSize           (u32 LE)
//! [0x0C] Reserved (always 0)       (4 bytes)
//! [0x10] EntryTable                (FileCount × 0x18 bytes)
//! [0x10 + FileCount×0x18]
//!        StringTable               (StringTableSize bytes)
//! [0x10 + FileCount×0x18 + StringTableSize]
//!        FileData                  (remaining bytes)
//! ```
//!
//! ## File Entry (0x18 bytes)
//! ```text
//! [0x00] Offset  - relative to the data section start (u64 LE)
//! [0x08] Size    - in bytes (u64 LE)
//! [0x10] NameOffset - byte offset into the string table (u32 LE)
//! [0x14] Reserved   (u32)
//! ```
//!
//! ## Notes
//! * No directory support; no per-file hashing (contrast with HFS0).
//! * The data section begins at `0x10 + FileCount×0x18 + StringTableSize`.

use std::io::{Read, Seek, SeekFrom, Take};
use std::ops::Index;

use crate::Result;
use crate::utils::{bytesv, le_u32, le_u64, magic, null_string};

/// Parsed PFS0 container (metadata only).
///
/// File data is accessed via [`Pfs0Reader`].
#[derive(Debug)]
pub struct Pfs0 {
    /// All file entries in declaration order.
    pub files: Vec<Pfs0File>,
    /// Absolute byte offset (from the start of the container) to the file
    /// data section.
    pub(crate) data_offset: u64,
}

/// Metadata for a single file inside a PFS0.
#[derive(Debug, Clone)]
pub struct Pfs0File {
    /// File name decoded from the string table.
    pub name: String,
    /// Offset relative to the PFS0 data section.
    pub offset: u64,
    /// File size in bytes.
    pub size: u64,
}

impl Pfs0 {
    /// Parse a PFS0 container from `r`.
    ///
    /// The reader must be positioned at the very start of the PFS0 magic.
    /// File contents are not read; use [`Pfs0Reader`] for data access.
    pub fn parse<R: Read + Seek>(r: &mut R) -> Result<Self> {
        // Record the start so we can compute data_offset relative to r's origin.
        let base = r.stream_position()?;

        magic(r, b"PFS0")?;
        let file_count = le_u32(r)?;
        let string_table_size = le_u32(r)?;
        let _reserved = le_u32(r)?;

        let mut entries = Vec::with_capacity(file_count as usize);
        for _ in 0..file_count {
            let offset = le_u64(r)?;
            let size = le_u64(r)?;
            let name_offset = le_u32(r)?;
            let _reserved = le_u32(r)?;
            entries.push((offset, size, name_offset));
        }

        let string_table = bytesv(r, string_table_size as usize)?;

        let mut files = Vec::with_capacity(file_count as usize);
        for (offset, size, name_offset) in entries {
            let name = null_string(&string_table, name_offset as usize)?;
            files.push(Pfs0File { name, offset, size });
        }

        // data_offset is absolute within the stream.
        let header_size = 0x10u64;
        let entries_size = file_count as u64 * 0x18;
        let data_offset = base + header_size + entries_size + string_table_size as u64;

        Ok(Self { files, data_offset })
    }
}

/// Streaming reader wrapper around a [`Pfs0`] container.
///
/// Owns the underlying reader and provides zero-copy bounded access to file
/// contents via [`Take<&mut R>`].
pub struct Pfs0Reader<R> {
    inner: R,
    /// Parsed metadata.
    pub pfs0: Pfs0,
}

impl<R: Read + Seek> Pfs0Reader<R> {
    /// Parse a PFS0 and wrap the provided reader.
    pub fn new(mut reader: R) -> Result<Self> {
        let pfs0 = Pfs0::parse(&mut reader)?;
        Ok(Self {
            inner: reader,
            pfs0,
        })
    }

    /// Open a file for streaming access.
    ///
    /// Seeks to the file's start and returns a [`Take`] limited to its byte
    /// range. The borrow ends when the [`Take`] is dropped.
    pub fn read_file(&mut self, file: &Pfs0File) -> Result<Take<&mut R>> {
        self.inner
            .seek(SeekFrom::Start(self.pfs0.data_offset + file.offset))?;
        Ok(self.inner.by_ref().take(file.size))
    }

    /// Iterate over all file entries.
    pub fn files(&self) -> impl Iterator<Item = &Pfs0File> {
        self.pfs0.files.iter()
    }

    /// Find a file by name. Returns [`None`] if not found.
    pub fn get_file_by_name(&self, name: &str) -> Option<&Pfs0File> {
        self.pfs0.files.iter().find(|f| f.name == name)
    }

    /// Consume the reader, returning the inner reader.
    pub fn into_inner(self) -> R {
        self.inner
    }
}

impl<R: Read + Seek> Index<&str> for Pfs0Reader<R> {
    type Output = Pfs0File;

    /// Index by file name.
    ///
    /// # Panics
    /// Panics if the file name does not exist in the archive.
    fn index(&self, index: &str) -> &Self::Output {
        self.get_file_by_name(index)
            .unwrap_or_else(|| panic!("no file '{index}' in PFS0"))
    }
}
