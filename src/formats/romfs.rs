//! RomFS (Read-Only Filesystem) - Nintendo Switch game asset container.
//!
//! RomFS is used as a section filesystem inside NCAs. It is accessed through
//! an IVFC hash-tree container; this parser locates Level 3 (the actual data)
//! by reading the IVFC header embedded in the NCA FsHeader's `hash_data` field
//! and seeking to the Level 3 data offset.
//!
//! The caller is responsible for decrypting the NCA section before parsing.
//!
//! ## IVFC Superblock (first 0xE0 bytes of FsHeader.hash_data for RomFS sections)
//! ```text
//! [0x00] Magic "IVFC"                (4 bytes)
//! [0x04] Magic number 0x10000        (u32 LE)
//! [0x08] MasterHashSize              (u32 LE)
//! [0x0C] Level1LogicalOffset         (u64 LE)
//! [0x14] Level1HashDataSize          (u64 LE)
//! [0x1C] Level1BlockSizeLog2         (u32 LE)
//! [0x20] Reserved                    (4 bytes)
//! [0x24] Level2LogicalOffset         (u64 LE)
//! [0x2C] Level2HashDataSize          (u64 LE)
//! [0x34] Level2BlockSizeLog2         (u32 LE)
//! [0x38] Reserved                    (4 bytes)
//! [0x3C] Level3LogicalOffset         (u64 LE) ← start of Level 3 data
//! [0x44] Level3HashDataSize          (u64 LE)
//! [0x4C] Level3BlockSizeLog2         (u32 LE)
//! [0x50] Reserved                    (4 bytes)
//! [0x54] Reserved                    (4 bytes)
//! [0x58] OptionalInfoSize            (u32 LE)
//! ```
//!
//! ## Level 3 Layout (at Level3LogicalOffset within the section)
//! ```text
//! [0x00] Level3Header    (0x28 bytes)
//! [0x28] DirHashTable    (DirHashTableSize bytes, u32 LE bucket array)
//! [var]  DirMetaTable    (DirMetaTableSize bytes)
//! [var]  FileHashTable   (FileHashTableSize bytes, u32 LE bucket array)
//! [var]  FileMetaTable   (FileMetaTableSize bytes)
//! [var]  FileData        (begins at Level3Header.FileDataOffset)
//! ```
//!
//! ## Level 3 Header (0x28 bytes)
//! ```text
//! [0x00] HeaderLength          (u32 LE, always 0x28)
//! [0x04] DirHashTableOffset    (u32 LE, relative to Level 3 start)
//! [0x08] DirHashTableSize      (u32 LE)
//! [0x0C] DirMetaTableOffset    (u32 LE, relative to Level 3 start)
//! [0x10] DirMetaTableSize      (u32 LE)
//! [0x14] FileHashTableOffset   (u32 LE, relative to Level 3 start)
//! [0x18] FileHashTableSize     (u32 LE)
//! [0x1C] FileMetaTableOffset   (u32 LE, relative to Level 3 start)
//! [0x20] FileMetaTableSize     (u32 LE)
//! [0x24] FileDataOffset        (u32 LE, relative to Level 3 start)
//! ```
//!
//! ## Directory Metadata Entry (variable length, 4-byte aligned)
//! ```text
//! [0x00] ParentOffset     (u32 LE) - self if root
//! [0x04] SiblingOffset    (u32 LE) - 0xFFFFFFFF if none
//! [0x08] ChildDirOffset   (u32 LE) - 0xFFFFFFFF if none
//! [0x0C] FirstFileOffset  (u32 LE) - 0xFFFFFFFF if none
//! [0x10] HashSiblingOffset(u32 LE) - next entry in hash bucket chain
//! [0x14] NameLength       (u32 LE)
//! [0x18] Name             (NameLength bytes, UTF-8, padded to 4-byte boundary)
//! ```
//!
//! ## File Metadata Entry (variable length, 4-byte aligned)
//! ```text
//! [0x00] ParentDirOffset  (u32 LE)
//! [0x04] SiblingOffset    (u32 LE) - 0xFFFFFFFF if none
//! [0x08] DataOffset       (u64 LE) - relative to FileData section
//! [0x10] DataSize         (u64 LE)
//! [0x18] HashSiblingOffset(u32 LE) - next entry in hash bucket chain
//! [0x1C] NameLength       (u32 LE)
//! [0x20] Name             (NameLength bytes, UTF-8, padded to 4-byte boundary)
//! ```

use std::io::{Cursor, Read, Seek, SeekFrom, Take};

use crate::utils::{bytesv, le_u32, le_u64, magic};
use crate::{Error, Result};

/// Sentinel value meaning "no entry" in all offset fields.
pub const ROMFS_ENTRY_EMPTY: u32 = 0xFFFF_FFFF;

/// Expected size of the Level 3 header.
const LEVEL3_HEADER_SIZE: u32 = 0x28;

/// Parsed IVFC superblock (the first ~0x5C bytes of a RomFS section's hash data).
///
/// This is embedded in `FsHeader.hash_data` for sections whose `hash_type` is
/// `HierarchicalIntegrity`. Only the Level 3 offset and block size are needed
/// for parsing; the hash levels are used for verification (not implemented here).
#[derive(Debug, Clone)]
pub struct IvfcHeader {
    /// Master hash size in bytes.
    pub master_hash_size: u32,
    /// Level 1 logical offset within the section.
    pub level1_offset: u64,
    /// Level 1 hash data size.
    pub level1_size: u64,
    /// Level 1 block size as log2 (block size = 1 << level1_block_size_log2).
    pub level1_block_size_log2: u32,
    /// Level 2 logical offset within the section.
    pub level2_offset: u64,
    /// Level 2 hash data size.
    pub level2_size: u64,
    /// Level 2 block size as log2.
    pub level2_block_size_log2: u32,
    /// Level 3 (data) logical offset within the section.
    /// Add this to the absolute NCA section start offset to get an absolute
    /// stream position for the Level 3 header.
    pub level3_offset: u64,
    /// Level 3 hash data size (i.e., the total size of the Level 3 data).
    pub level3_size: u64,
    /// Level 3 block size as log2.
    pub level3_block_size_log2: u32,
}

impl IvfcHeader {
    /// Parse an IVFC header from a byte slice (e.g., `FsHeader.hash_data`).
    ///
    /// The slice must be at least 0x5C bytes long and start with the `IVFC`
    /// magic at offset 0.
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < 0x5C {
            return Err(Error::UnexpectedEof);
        }
        let mut c = Cursor::new(data);
        Self::parse(&mut c)
    }

    /// Parse an IVFC header from `r`.
    ///
    /// The reader must be positioned at the `IVFC` magic.
    pub fn parse<R: Read>(r: &mut R) -> Result<Self> {
        magic(r, b"IVFC")?;

        let magic_num = le_u32(r)?;
        if magic_num != 0x10000 {
            return Err(Error::Parse("unexpected IVFC magic number"));
        }

        let master_hash_size = le_u32(r)?;

        let level1_offset = le_u64(r)?;
        let level1_size = le_u64(r)?;
        let level1_block_size_log2 = le_u32(r)?;
        let _reserved1 = le_u32(r)?;

        let level2_offset = le_u64(r)?;
        let level2_size = le_u64(r)?;
        let level2_block_size_log2 = le_u32(r)?;
        let _reserved2 = le_u32(r)?;

        let level3_offset = le_u64(r)?;
        let level3_size = le_u64(r)?;
        let level3_block_size_log2 = le_u32(r)?;
        let _reserved3 = le_u32(r)?;

        Ok(Self {
            master_hash_size,
            level1_offset,
            level1_size,
            level1_block_size_log2,
            level2_offset,
            level2_size,
            level2_block_size_log2,
            level3_offset,
            level3_size,
            level3_block_size_log2,
        })
    }
}

/// Parsed Level 3 header - the root of the actual RomFS directory tree.
#[derive(Debug, Clone)]
pub struct Level3Header {
    /// Offset of the directory hash table relative to Level 3 start.
    pub dir_hash_table_offset: u32,
    /// Size of the directory hash table in bytes.
    pub dir_hash_table_size: u32,
    /// Offset of the directory metadata table relative to Level 3 start.
    pub dir_meta_table_offset: u32,
    /// Size of the directory metadata table in bytes.
    pub dir_meta_table_size: u32,
    /// Offset of the file hash table relative to Level 3 start.
    pub file_hash_table_offset: u32,
    /// Size of the file hash table in bytes.
    pub file_hash_table_size: u32,
    /// Offset of the file metadata table relative to Level 3 start.
    pub file_meta_table_offset: u32,
    /// Size of the file metadata table in bytes.
    pub file_meta_table_size: u32,
    /// Offset of the file data section relative to Level 3 start.
    pub file_data_offset: u32,
}

/// A directory entry in the RomFS tree.
#[derive(Debug, Clone)]
pub struct RomFsDir {
    /// Directory name. Empty string for the root directory.
    pub name: String,
    /// Absolute path from root (e.g., `""` for root, `"/Actor"`, `"/Actor/Pack"`).
    pub path: String,
    /// Offset of this entry within the directory metadata table.
    #[allow(dead_code)]
    pub(crate) meta_offset: u32,
    /// Indices of child directory entries in [`RomFs::dirs`].
    pub children: Vec<usize>,
    /// Indices of file entries in [`RomFs::files`] that live directly in this directory.
    pub files: Vec<usize>,
}

/// A file entry in the RomFS tree.
#[derive(Debug, Clone)]
pub struct RomFsFile {
    /// File name (just the base name, not the full path).
    pub name: String,
    /// Absolute path from root (e.g., `"/control.nacp"`).
    pub path: String,
    /// Data offset relative to the Level 3 file data section start.
    pub data_offset: u64,
    /// File size in bytes.
    pub data_size: u64,
}

/// Parsed RomFS directory tree (metadata only; file data is not loaded).
///
/// # Parsing
///
/// The reader must be positioned at the **start of the Level 3 data**
/// (i.e., at `section_base + ivfc.level3_offset`). Use [`IvfcHeader`] to
/// determine this offset from the NCA `FsHeader.hash_data`.
///
/// # Data access
///
/// File data offsets are relative to `self.file_data_base`, which is the
/// absolute stream position of the Level 3 file data section. To read a file:
///
/// ```rust,ignore
/// let abs_offset = romfs.file_data_base + file.data_offset;
/// reader.seek(SeekFrom::Start(abs_offset))?;
/// let mut buf = vec![0u8; file.data_size as usize];
/// reader.read_exact(&mut buf)?;
/// ```
///
/// Or use the [`RomFsReader`] wrapper for a more ergonomic API.
#[derive(Debug)]
pub struct RomFs {
    /// All directories, root at index 0.
    pub dirs: Vec<RomFsDir>,
    /// All files in the filesystem.
    pub files: Vec<RomFsFile>,
    /// Absolute stream offset of the Level 3 file data section.
    /// Add `RomFsFile::data_offset` to get an absolute seek position.
    pub file_data_base: u64,
}

impl RomFs {
    /// Parse a RomFS from `r`, which must be positioned at the Level 3 start.
    ///
    /// On return the reader's position is unspecified; use [`RomFsReader`] for
    /// subsequent data access.
    pub fn parse<R: Read + Seek>(r: &mut R) -> Result<Self> {
        let level3_base = r.stream_position()?;

        // Level 3 header (0x28 bytes)
        let header_length = le_u32(r)?;
        if header_length != LEVEL3_HEADER_SIZE {
            return Err(Error::Parse("unexpected RomFS Level 3 header size"));
        }
        let dir_hash_table_offset = le_u32(r)?;
        let dir_hash_table_size = le_u32(r)?;
        let dir_meta_table_offset = le_u32(r)?;
        let dir_meta_table_size = le_u32(r)?;
        let file_hash_table_offset = le_u32(r)?;
        let file_hash_table_size = le_u32(r)?;
        let file_meta_table_offset = le_u32(r)?;
        let file_meta_table_size = le_u32(r)?;
        let file_data_offset = le_u32(r)?;

        let _ = (dir_hash_table_offset, dir_hash_table_size);
        let _ = (file_hash_table_offset, file_hash_table_size);

        let file_data_base = level3_base + file_data_offset as u64;

        r.seek(SeekFrom::Start(level3_base + dir_meta_table_offset as u64))?;
        let dir_table = bytesv(r, dir_meta_table_size as usize)?;

        r.seek(SeekFrom::Start(level3_base + file_meta_table_offset as u64))?;
        let file_table = bytesv(r, file_meta_table_size as usize)?;

        let (dirs, files) = build_tree(&dir_table, &file_table)?;

        Ok(Self {
            dirs,
            files,
            file_data_base,
        })
    }

    /// Look up a file by its absolute path (e.g., `"/control.nacp"`).
    ///
    /// The lookup is O(n) over `self.files`. For repeated lookups consider
    /// building a `HashMap` from the file list.
    pub fn get_file(&self, path: &str) -> Option<&RomFsFile> {
        self.files.iter().find(|f| f.path == path)
    }

    /// Look up a directory by its absolute path (e.g., `"/Actor"`).
    pub fn get_dir(&self, path: &str) -> Option<&RomFsDir> {
        self.dirs.iter().find(|d| d.path == path)
    }

    /// Iterate over all files, yielding `(path, &RomFsFile)` pairs.
    pub fn files(&self) -> impl Iterator<Item = (&str, &RomFsFile)> {
        self.files.iter().map(|f| (f.path.as_str(), f))
    }
}

/// Build the full directory and file trees from the raw metadata tables.
///
/// Returns `(dirs, files)` where `dirs[0]` is always the root directory.
fn build_tree(dir_table: &[u8], file_table: &[u8]) -> Result<(Vec<RomFsDir>, Vec<RomFsFile>)> {
    // First pass: parse every directory entry from the binary table.
    // We collect them in table-offset order; the root is always at offset 0.
    let mut raw_dirs: Vec<(u32, RawDirEntry)> = Vec::new(); // (meta_offset, entry)
    {
        let mut pos = 0usize;
        while pos < dir_table.len() {
            if pos + 0x18 > dir_table.len() {
                break;
            }
            let entry = parse_raw_dir(&dir_table[pos..])?;
            let name_len = entry.name_length as usize;
            raw_dirs.push((pos as u32, entry));
            // Advance past the fixed fields (0x18) + name (aligned to 4 bytes).
            pos += 0x18 + align4(name_len);
        }
    }

    // Build a map from meta_offset → index in raw_dirs.
    let dir_idx_of: std::collections::HashMap<u32, usize> = raw_dirs
        .iter()
        .enumerate()
        .map(|(i, (off, _))| (*off, i))
        .collect();

    // Compute the full path for each directory.
    // Root (index 0, offset 0) has an empty path "".
    let mut dir_paths = vec![String::new(); raw_dirs.len()];
    // Process in order: since parent offsets always point to entries that
    // appear earlier in the table (the format is built recursively from root),
    // a single forward pass is sufficient.
    for i in 0..raw_dirs.len() {
        let (_, ref entry) = raw_dirs[i];
        let parent_idx = *dir_idx_of
            .get(&entry.parent_offset)
            .ok_or(Error::InvalidRange)?;
        let path = if i == 0 {
            // Root directory.
            String::new()
        } else {
            let parent_path = &dir_paths[parent_idx];
            format!("{}/{}", parent_path, entry.name)
        };
        dir_paths[i] = path;
    }

    // Second pass: parse every file entry.
    let mut raw_files: Vec<(u32, RawFileEntry)> = Vec::new();
    {
        let mut pos = 0usize;
        while pos < file_table.len() {
            if pos + 0x20 > file_table.len() {
                break;
            }
            let entry = parse_raw_file(&file_table[pos..])?;
            let name_len = entry.name_length as usize;
            raw_files.push((pos as u32, entry));
            let _ = raw_files.last().unwrap(); // suppress unused warning
            pos += 0x20 + align4(name_len);
        }
    }

    // Build file offset -> index map.
    let file_idx_of: std::collections::HashMap<u32, usize> = raw_files
        .iter()
        .enumerate()
        .map(|(i, (off, _))| (*off, i))
        .collect();

    // Allocate output vectors.
    let mut dirs: Vec<RomFsDir> = raw_dirs
        .iter()
        .enumerate()
        .map(|(i, (off, _))| RomFsDir {
            name: raw_dirs[i].1.name.clone(),
            path: dir_paths[i].clone(),
            meta_offset: *off,
            children: Vec::new(),
            files: Vec::new(),
        })
        .collect();

    let mut files: Vec<RomFsFile> = raw_files
        .iter()
        .map(|(_, entry)| {
            let parent_idx = *dir_idx_of.get(&entry.parent_dir_offset).unwrap_or(&0);
            let parent_path = &dir_paths[parent_idx];
            let path = format!("{}/{}", parent_path, entry.name);
            RomFsFile {
                name: entry.name.clone(),
                path,
                data_offset: entry.data_offset,
                data_size: entry.data_size,
            }
        })
        .collect();

    // Wire up parent → child dir and parent → file relationships
    // by walking the linked lists stored in the raw entries.
    for (dir_i, (_, raw)) in raw_dirs.iter().enumerate() {
        // Child directories: follow child_dir_offset → sibling_offset chain.
        let mut child_off = raw.child_dir_offset;
        while child_off != ROMFS_ENTRY_EMPTY {
            if let Some(&child_i) = dir_idx_of.get(&child_off) {
                dirs[dir_i].children.push(child_i);
                child_off = raw_dirs[child_i].1.sibling_offset;
            } else {
                break;
            }
        }

        // Files in this directory: follow first_file_offset → sibling_offset chain.
        let mut file_off = raw.first_file_offset;
        while file_off != ROMFS_ENTRY_EMPTY {
            if let Some(&file_i) = file_idx_of.get(&file_off) {
                dirs[dir_i].files.push(file_i);
                file_off = raw_files[file_i].1.sibling_offset;
            } else {
                break;
            }
        }
    }

    // Fix file paths now that we have resolved all parent directories.
    for (file_i, (_, raw)) in raw_files.iter().enumerate() {
        if let Some(&parent_i) = dir_idx_of.get(&raw.parent_dir_offset) {
            let parent_path = &dir_paths[parent_i];
            files[file_i].path = format!("{}/{}", parent_path, raw.name);
        }
    }

    Ok((dirs, files))
}

struct RawDirEntry {
    parent_offset: u32,
    sibling_offset: u32,
    child_dir_offset: u32,
    first_file_offset: u32,
    #[allow(dead_code)]
    hash_sibling_offset: u32,
    name_length: u32,
    name: String,
}

struct RawFileEntry {
    parent_dir_offset: u32,
    sibling_offset: u32,
    data_offset: u64,
    data_size: u64,
    #[allow(dead_code)]
    hash_sibling_offset: u32,
    name_length: u32,
    name: String,
}

fn parse_raw_dir(buf: &[u8]) -> Result<RawDirEntry> {
    if buf.len() < 0x18 {
        return Err(Error::UnexpectedEof);
    }
    let mut c = Cursor::new(buf);
    let parent_offset = le_u32(&mut c)?;
    let sibling_offset = le_u32(&mut c)?;
    let child_dir_offset = le_u32(&mut c)?;
    let first_file_offset = le_u32(&mut c)?;
    let hash_sibling_offset = le_u32(&mut c)?;
    let name_length = le_u32(&mut c)?;

    let name_bytes = bytesv(&mut c, name_length as usize)?;
    let name = String::from_utf8_lossy(&name_bytes).into_owned();

    Ok(RawDirEntry {
        parent_offset,
        sibling_offset,
        child_dir_offset,
        first_file_offset,
        hash_sibling_offset,
        name_length,
        name,
    })
}

fn parse_raw_file(buf: &[u8]) -> Result<RawFileEntry> {
    if buf.len() < 0x20 {
        return Err(Error::UnexpectedEof);
    }
    let mut c = Cursor::new(buf);
    let parent_dir_offset = le_u32(&mut c)?;
    let sibling_offset = le_u32(&mut c)?;
    let data_offset = le_u64(&mut c)?;
    let data_size = le_u64(&mut c)?;
    let hash_sibling_offset = le_u32(&mut c)?;
    let name_length = le_u32(&mut c)?;

    let name_bytes = bytesv(&mut c, name_length as usize)?;
    let name = String::from_utf8_lossy(&name_bytes).into_owned();

    Ok(RawFileEntry {
        parent_dir_offset,
        sibling_offset,
        data_offset,
        data_size,
        hash_sibling_offset,
        name_length,
        name,
    })
}

/// Round `n` up to the next multiple of 4.
#[inline]
fn align4(n: usize) -> usize {
    (n + 3) & !3
}

/// Streaming reader wrapper around a parsed [`RomFs`] tree.
///
/// Owns the underlying reader and provides zero-copy bounded access to file
/// contents via [`Take<&mut R>`].
pub struct RomFsReader<R> {
    inner: R,
    /// Parsed metadata.
    pub romfs: RomFs,
}

impl<R: Read + Seek> RomFsReader<R> {
    /// Parse a RomFS and wrap the provided reader.
    ///
    /// The reader must be positioned at the Level 3 start.
    pub fn new(mut reader: R) -> Result<Self> {
        let romfs = RomFs::parse(&mut reader)?;
        Ok(Self {
            inner: reader,
            romfs,
        })
    }

    /// Open a file for streaming access.
    ///
    /// Seeks to the file's absolute position and returns a [`Take`] limited
    /// to its byte length. The borrow ends when the [`Take`] is dropped.
    pub fn read_file(&mut self, file: &RomFsFile) -> Result<Take<&mut R>> {
        let abs = self.romfs.file_data_base + file.data_offset;
        self.inner.seek(SeekFrom::Start(abs))?;
        Ok(self.inner.by_ref().take(file.data_size))
    }

    /// Open a file by path for streaming access.
    ///
    /// Returns [`Error::InvalidRange`] if the path does not exist.
    pub fn read_file_by_path(&mut self, path: &str) -> Result<Take<&mut R>> {
        // Resolve the file first before borrowing self.inner.
        let (abs, size) = self
            .romfs
            .get_file(path)
            .map(|f| (self.romfs.file_data_base + f.data_offset, f.data_size))
            .ok_or(Error::InvalidRange)?;
        self.inner.seek(SeekFrom::Start(abs))?;
        Ok(self.inner.by_ref().take(size))
    }

    /// Iterate over all files.
    pub fn files(&self) -> impl Iterator<Item = &RomFsFile> {
        self.romfs.files.iter()
    }

    /// Iterate over all directories.
    pub fn dirs(&self) -> impl Iterator<Item = &RomFsDir> {
        self.romfs.dirs.iter()
    }

    /// Consume the reader, returning the inner reader.
    pub fn into_inner(self) -> R {
        self.inner
    }
}
