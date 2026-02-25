//! XCI (NX Card Image) - physical game card dump format.
//!
//! ## Overall Layout
//! ```text
//! [0x0000–0x0FFF] CardKeyArea      (challenge-response authentication data)
//! [0x1000–0x11FF] CardHeader       (0x200 bytes; see below)
//! [0x1200–0x13FF] [11.0.0+] CardHeaderT2
//! [0x1400–0x17FF] [11.0.0+] CardHeaderT2CertArea
//! [0x1800–0x18FF] [11.0.0+] CardHeaderT2CertAreaModulus
//! [0x1900–0x7FFF] Reserved
//! [0x8000–0xFFFF] CertArea         (device certificate)
//! [0x10000+]      NormalArea → root HFS0
//! ```
//!
//! ## CardHeader (at 0x1000, 0x200 bytes total)
//! ```text
//! [+0x000] RSA-2048 signature over [+0x100..+0x200]     (0x100 bytes)
//! [+0x100] Magic "HEAD"                                  (4 bytes)
//! [+0x104] RomAreaStartPageAddress  (page × 0x200)       (u32 LE)
//! [+0x108] BackupAreaStartPageAddress (always 0xFFFFFFFF)(u32 LE)
//! [+0x10C] TitleKeyDecIndex | KekIndex                   (1 byte each nibble)
//! [+0x10D] RomSize                                       (1 byte)
//! [+0x10E] Version                                       (1 byte)
//! [+0x10F] Flags                                         (1 byte)
//! [+0x110] PackageId                                     (u64 LE)
//! [+0x118] ValidDataEndAddress (page units)              (u32 LE)
//! [+0x11C] Reserved                                      (4 bytes)
//! [+0x120] IV (reversed for AES-CBC)                     (16 bytes)
//! [+0x130] PartitionFsHeaderAddress (absolute byte offs) (u64 LE)
//! [+0x138] PartitionFsHeaderSize                         (u64 LE)
//! [+0x140] PartitionFsHeaderHash (SHA-256)               (32 bytes)
//! [+0x160] InitialDataHash (SHA-256)                     (32 bytes)
//! [+0x180] SelSec (1=T1, 2=T2)                           (u32 LE)
//! [+0x184] SelT1Key (always 2)                           (u32 LE)
//! [+0x188] SelKey   (always 0)                           (u32 LE)
//! [+0x18C] LimArea (page units)                          (u32 LE)
//! [+0x190] CardHeaderEncryptedData (AES-128-CBC)         (0x70 bytes)
//! ```
//!
//! ## RomSize byte values
//! | Value | Capacity |
//! |-------|----------|
//! | 0xFA  | 1 GB     |
//! | 0xF8  | 2 GB     |
//! | 0xF0  | 4 GB     |
//! | 0xE0  | 8 GB     |
//! | 0xE1  | 16 GB    |
//! | 0xE2  | 32 GB    |

use std::io::{Read, Seek, SeekFrom};

use super::hfs0::Hfs0;
use crate::Result;
use crate::utils::{bytesa, le_u32, le_u64, magic, u8};

/// Parsed XCI game card image.
///
/// Only the unencrypted fields of the CardHeader are captured here.
/// The AES-128-CBC encrypted `CardHeaderEncryptedData` region is not parsed.
#[derive(Debug)]
pub struct Xci {
    /// Absolute file offset of the root HFS0 header (from CardHeader +0x130).
    pub hfs0_offset: u64,
    /// Size of the root HFS0 region (from CardHeader +0x138).
    pub hfs0_size: u64,
    /// SHA-256 hash of the root HFS0 header (from CardHeader +0x140).
    pub hfs0_header_hash: [u8; 32],
    /// RomSize byte (see table in module docs for capacity mapping).
    pub rom_size: u8,
    /// PackageId used for challenge-response authentication.
    pub package_id: u64,
    /// Parsed root HFS0 listing the sub-partitions.
    pub root_partition: Hfs0,
}

impl Xci {
    /// Parse an XCI file.
    ///
    /// The reader must be positioned at the very start of the XCI file.
    /// No crypto is performed; fields within the encrypted `CardHeaderEncryptedData`
    /// region are not extracted.
    pub fn parse<R: Read + Seek>(r: &mut R) -> Result<Self> {
        // Skip CardKeyArea (0x1000 bytes) + RSA signature (0x100 bytes).
        // Magic "HEAD" is at absolute offset 0x1100.
        r.seek(SeekFrom::Start(0x1100))?;
        magic(r, b"HEAD")?;

        // 0x1104: RomAreaStartPageAddress
        let _rom_start = le_u32(r)?;
        // 0x1108: BackupAreaStartPageAddress (always 0xFFFFFFFF)
        let _backup = le_u32(r)?;
        // 0x110C: TitleKeyDecIndex (high nibble) | KekIndex (low nibble)
        let _key_indices = u8(r)?;
        // 0x110D: RomSize
        let rom_size = u8(r)?;
        // 0x110E: Version
        let _version = u8(r)?;
        // 0x110F: Flags
        let _flags = u8(r)?;
        // 0x1110: PackageId
        let package_id = le_u64(r)?;
        // 0x1118: ValidDataEndAddress
        let _valid_end = le_u32(r)?;
        // 0x111C: Reserved
        let _reserved = le_u32(r)?;
        // 0x1120: IV (0x10 bytes)
        let _iv = bytesa::<0x10>(r)?;
        // 0x1130: PartitionFsHeaderAddress
        let hfs0_offset = le_u64(r)?;
        // 0x1138: PartitionFsHeaderSize
        let hfs0_size = le_u64(r)?;
        // 0x1140: PartitionFsHeaderHash
        let hfs0_header_hash = bytesa::<0x20>(r)?;

        // Seek to root HFS0 and parse it.
        r.seek(SeekFrom::Start(hfs0_offset))?;
        let root_partition = Hfs0::parse(r)?;

        Ok(Self {
            hfs0_offset,
            hfs0_size,
            hfs0_header_hash,
            rom_size,
            package_id,
            root_partition,
        })
    }

    /// Return the ROM capacity as a human-readable string.
    pub fn rom_capacity(&self) -> &'static str {
        match self.rom_size {
            0xFA => "1 GB",
            0xF8 => "2 GB",
            0xF0 => "4 GB",
            0xE0 => "8 GB",
            0xE1 => "16 GB",
            0xE2 => "32 GB",
            _ => "unknown",
        }
    }
}
