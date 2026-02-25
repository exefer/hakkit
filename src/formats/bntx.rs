//! BNTX (Binary NX Texture) - Nintendo Switch texture container.
//!
//! Contains one or more GPU textures with a relocation table for pointer
//! fixup. This parser resolves name pointers by seeking directly; it does
//! **not** process the relocation table (the layout is predictable enough
//! that absolute offsets work correctly for read-only parsing).
//!
//! ## Layout
//! ```text
//! [0x00] BNTX header  (0x20 bytes)
//! [0x20] NX section   (0x28 bytes)
//! [InfoPtrsOffset]
//!        Array of u64 pointers to BRTI blocks (TextureCount entries)
//! [...]  BRTI blocks  (one per texture, each 0x90 bytes)
//! [...]  String pool, data blocks, relocation table
//! ```
//!
//! ## BNTX Header (0x20 bytes)
//! ```text
//! [0x00] Magic "BNTX"                       (4 bytes)
//! [0x04] DataLength (0, unused)             (u32 LE)
//! [0x08] Padding / version                  (8 bytes)
//! [0x10] BOM (0xFEFF=BE, 0xFFFE=LE)         (u16 LE)
//! [0x12] FormatRevision (0x0400)            (u16 LE)
//! [0x14] NameOffset (rel-ptr)               (u32 LE)
//! [0x18] StringPoolOffset (rel)             (u16 LE)
//! [0x1A] RelocTableOffset (rel)             (u16 LE)
//! [0x1C] FileSize                           (u32 LE)
//! ```
//!
//! ## NX Section (at 0x20)
//! ```text
//! [0x00] Magic "NX  "                        (4 bytes)
//! [0x04] TextureCount                        (u32 LE)
//! [0x08] InfoPtrsOffset (abs ptr)            (u64 LE)
//! [0x10] DataBlkOffset  (abs ptr)            (u64 LE)
//! [0x18] DictOffset     (abs ptr)            (u64 LE)
//! [0x20] StrDictOffset                       (u32 LE)
//! ```
//!
//! ## BRTI (Texture Info, per texture, 0x90 bytes)
//! ```text
//! [0x00] Magic "BRTI"                       (4 bytes)
//! [0x04] Length (always 0x90)               (u32 LE)
//! [0x08] DataLength                         (u64 LE)
//! [0x10] Flags                              (u8)
//! [0x11] Dimensions (1=1D,2=2D,3=3D,6=Cube) (u8)
//! [0x12] TileMode                           (u16 LE)
//! [0x14] SwizzleValue                       (u16 LE)
//! [0x16] MipmapCount                        (u16 LE)
//! [0x18] MultiSampleCount                   (u16 LE)
//! [0x1A] Reserved                           (u16)
//! [0x1C] Format                             (u32 LE)
//! [0x20] AccessFlags                        (u32 LE)
//! [0x24] Width                              (u32 LE)
//! [0x28] Height                             (u32 LE)
//! [0x2C] Depth                              (u32 LE)
//! [0x30] ArrayCount                         (u32 LE)
//! [0x34] BlockHeightLog2                    (u32 LE)
//! [0x38] Reserved (0x14 bytes)
//! [0x4C] DataOffset (rel to DataBlkOffset)  (u32 LE)
//! [0x50] NameOffset (abs ptr)               (u64 LE)
//! [0x58] ParentOffset (abs ptr)             (u64 LE)
//! [0x60] PtrsOffset   (abs ptr)             (u64 LE)
//! ```
//!
//! ## Name encoding
//! Names are length-prefixed: a `u16 LE` byte count followed by that many
//! UTF-8 bytes (no null terminator).

use std::io::{Read, Seek, SeekFrom};

use crate::utils::{bytesv, le_u16, le_u32, le_u64, magic, u8};
use crate::{Error, Result};

/// Metadata for a single texture stored in a BNTX file.
#[derive(Debug, Clone)]
pub struct TextureInfo {
    /// Texture name (resolved from the string pool).
    pub name: String,
    /// Width in pixels.
    pub width: u32,
    /// Height in pixels.
    pub height: u32,
    /// Depth (for 3D textures) or face count (for cube maps).
    pub depth: u32,
    /// Number of array slices.
    pub array_count: u32,
    /// Number of mip levels.
    pub mipmap_count: u16,
    /// Raw format identifier (see BNTX format table).
    pub format: u32,
    /// Byte offset of GPU data relative to the BNTX data block start
    /// (`DataBlkOffset` in the NX section). Add `data_block_offset` from
    /// [`Bntx`] to get an absolute file offset.
    pub data_offset_rel: u32,
    /// Total size of GPU data in bytes.
    pub data_length: u64,
}

/// Parsed BNTX texture container.
#[derive(Debug)]
pub struct Bntx {
    /// Number of textures.
    pub texture_count: u32,
    /// Metadata for each texture. GPU data is not loaded into memory;
    /// callers use `data_block_offset + tex.data_offset_rel` to locate it.
    pub textures: Vec<TextureInfo>,
    /// Whether the file uses little-endian encoding.
    pub le: bool,
    /// Absolute offset of the GPU data block within the file
    /// (NX section `DataBlkOffset`).
    pub data_block_offset: u64,
}

impl Bntx {
    /// Parse a BNTX file from `r`.
    ///
    /// BNTX uses absolute internal pointers, so the reader must support
    /// `Seek` and the stream must start at the beginning of the file.
    pub fn parse<R: Read + Seek>(r: &mut R) -> Result<Self> {
        // BNTX header (0x20 bytes)
        magic(r, b"BNTX")?;
        let _data_length = le_u32(r)?; // always 0
        let _version = le_u32(r)?;
        let _version_hi = le_u32(r)?;

        // BOM is always written LE regardless of file endianness.
        let bom = le_u16(r)?;
        let le = match bom {
            0xFFFE => true,
            0xFEFF => false,
            _ => return Err(Error::Parse("invalid BNTX BOM")),
        };

        let _format_revision = le_u16(r)?;
        let _name_offset = le_u32(r)?;
        let _string_pool_off = le_u16(r)?;
        let _reloc_table_off = le_u16(r)?;
        let _file_size = le_u32(r)?;
        // r is now at 0x20

        // NX section (0x28 bytes)
        magic(r, b"NX  ")?;
        let texture_count = le_u32(r)?;
        let info_ptrs_offset = le_u64(r)?;
        let data_block_offset = le_u64(r)?;
        let _dict_offset = le_u64(r)?;
        let _str_dict_offset = le_u32(r)?;
        // r is now at 0x48

        // BRTI pointer array
        r.seek(SeekFrom::Start(info_ptrs_offset))?;
        let mut brti_offsets = Vec::with_capacity(texture_count as usize);
        for _ in 0..texture_count {
            brti_offsets.push(le_u64(r)?);
        }

        // Parse each BRTI
        let mut textures = Vec::with_capacity(texture_count as usize);
        for brti_abs in brti_offsets {
            r.seek(SeekFrom::Start(brti_abs))?;
            textures.push(parse_brti(r)?);
        }

        Ok(Bntx {
            texture_count,
            textures,
            le,
            data_block_offset,
        })
    }

    /// Return the absolute file offset of the GPU data for `tex`.
    pub fn texture_data_offset(&self, tex: &TextureInfo) -> u64 {
        self.data_block_offset + tex.data_offset_rel as u64
    }
}

fn parse_brti<R: Read + Seek>(r: &mut R) -> Result<TextureInfo> {
    magic(r, b"BRTI")?;
    let _length = le_u32(r)?; // always 0x90
    let data_length = le_u64(r)?;
    let _flags = u8(r)?;
    let _dimensions = u8(r)?;
    let _tile_mode = le_u16(r)?;
    let _swizzle = le_u16(r)?;
    let mipmap_count = le_u16(r)?;
    let _ms_count = le_u16(r)?;
    let _reserved0 = le_u16(r)?;
    let format = le_u32(r)?;
    let _access_flags = le_u32(r)?;
    let width = le_u32(r)?;
    let height = le_u32(r)?;
    let depth = le_u32(r)?;
    let array_count = le_u32(r)?;
    let _block_height = le_u32(r)?;
    // 0x14 reserved bytes at BRTI+0x38
    r.seek(SeekFrom::Current(0x14))?;
    let data_offset_rel = le_u32(r)?;
    let name_abs = le_u64(r)?;
    let _parent = le_u64(r)?;
    let _ptrs = le_u64(r)?;

    let name = read_bntx_name(r, name_abs)?;

    Ok(TextureInfo {
        name,
        width,
        height,
        depth,
        array_count,
        mipmap_count,
        format,
        data_offset_rel,
        data_length,
    })
}

/// Read a length-prefixed string from the string pool.
///
/// The pointer `ptr` is the absolute byte offset of the `u16` length field.
/// Names have no null terminator.
fn read_bntx_name<R: Read + Seek>(r: &mut R, ptr: u64) -> Result<String> {
    r.seek(SeekFrom::Start(ptr))?;
    let len = le_u16(r)? as usize;
    let buf = bytesv(r, len)?;
    Ok(String::from_utf8_lossy(&buf).into_owned())
}
