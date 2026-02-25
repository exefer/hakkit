//! NPDM (Nintendo Program Descriptor Meta) - process security metadata.
//!
//! Found as `main.npdm` in the ExeFS section of a Program NCA.
//! Describes the memory model, thread configuration, and access-control
//! policy for a Switch title.
//!
//! ## File Layout
//! ```text
//! [0x00] Magic "META"                                   (4 bytes)
//! [0x04] Unknown / signature key generation             (u32 LE)
//! [0x08] Reserved                                       (4 bytes)
//! [0x0C] MMUFlags   (bit 0 = 64-bit mode)               (1 byte)
//! [0x0D] Reserved                                       (1 byte)
//! [0x0E] MainThreadPriority (0–63)                      (1 byte)
//! [0x0F] MainThreadCoreNumber                           (1 byte)
//! [0x10] Reserved                                       (4 bytes)
//! [0x14] SystemResourceSize                             (u32 LE)
//! [0x18] Version                                        (u32 LE)
//! [0x1C] MainThreadStackSize                            (u32 LE)
//! [0x20] TitleName (null-padded UTF-8, 16 bytes)
//! [0x30] ProductCode (null-padded, 16 bytes)
//! [0x40] Reserved (0x30 bytes)
//! [0x70] AciOffset  (relative to start of NPDM file)   (u32 LE)
//! [0x74] AciSize                                        (u32 LE)
//! [0x78] AcidOffset (relative to start of NPDM file)   (u32 LE)
//! [0x7C] AcidSize                                       (u32 LE)
//! ```
//!
//! ## ACI0 (Access Control Info) - at AciOffset
//! ```text
//! [0x00] Magic "ACI0"          (4 bytes)
//! [0x04] Reserved              (0xC bytes)
//! [0x10] ProgramId             (u64 LE)
//! [0x18] Reserved              (8 bytes)
//! [0x20] FsAccessControlOffset (u32 LE)
//! [0x24] FsAccessControlSize   (u32 LE)
//! [0x28] SvcAccessControlOffset(u32 LE)
//! [0x2C] SvcAccessControlSize  (u32 LE)
//! [0x30] KernelAccessControlOffset (u32 LE)
//! [0x34] KernelAccessControlSize   (u32 LE)
//! [0x38] Reserved              (8 bytes)
//! ```
//!
//! ## ACID (Access Control Info Descriptor) - at AcidOffset
//! ```text
//! [0x000] RSA-2048 signature   (0x100 bytes)
//! [0x100] RSA-2048 public key  (0x100 bytes)
//! [0x200] Magic "ACID"         (4 bytes)
//! [0x204] Size                 (u32 LE)
//! [0x208] Flags                (u32 LE)
//! [0x20C] Reserved             (u32 LE)
//! [0x210] ProgramIdMin         (u64 LE)
//! [0x218] ProgramIdMax         (u64 LE)
//! … FsAccessControl, SvcAccessControl, KernelAccessControl follow
//! ```

use std::io::{Read, Seek, SeekFrom};

use crate::Result;
use crate::utils::{bytesa, le_u32, le_u64, magic, u8};

/// Parsed NPDM file.
#[derive(Debug)]
pub struct Npdm {
    /// Whether the process runs in 64-bit mode.
    pub is_64bit: bool,
    /// Priority of the main thread (0–63).
    pub main_thread_priority: u8,
    /// Core number the main thread starts on.
    pub main_thread_core: u8,
    /// System resource size in bytes.
    pub system_resource_size: u32,
    /// Version field from META header.
    pub version: u32,
    /// Main thread stack size in bytes.
    pub main_thread_stack_size: u32,
    /// Human-readable title name (up to 16 bytes, null-padded).
    pub title_name: String,
    /// Product code string (up to 16 bytes, null-padded).
    pub product_code: String,
    /// Access control info for this title.
    pub aci: Aci0,
    /// Access control descriptor (signed policy from Nintendo / publisher).
    pub acid: Option<Acid>,
}

/// ACI0 - per-title access control info.
#[derive(Debug)]
pub struct Aci0 {
    /// Program (title) ID for this build.
    pub program_id: u64,
}

/// ACID - signed access control descriptor.
#[derive(Debug)]
pub struct Acid {
    /// ACID flags field.
    pub flags: u32,
    /// Minimum allowed program ID for this descriptor.
    pub program_id_min: u64,
    /// Maximum allowed program ID for this descriptor.
    pub program_id_max: u64,
}

impl Npdm {
    /// Parse an NPDM file from `r`.
    ///
    /// `r` must be positioned at the very start of the file (the "META" magic).
    pub fn parse<R: Read + Seek>(r: &mut R) -> Result<Self> {
        let base = r.stream_position()?;

        magic(r, b"META")?;
        let _unknown = le_u32(r)?;
        let _reserved0 = le_u32(r)?;
        let mmu_flags = u8(r)?;
        let is_64bit = (mmu_flags & 0x01) != 0;
        let _reserved1 = u8(r)?;
        let main_thread_priority = u8(r)?;
        let main_thread_core = u8(r)?;
        let _reserved2 = le_u32(r)?;
        let system_resource_size = le_u32(r)?;
        let version = le_u32(r)?;
        let main_thread_stack_size = le_u32(r)?;

        // TitleName: 0x10 null-padded UTF-8 bytes.
        let title_raw = bytesa::<0x10>(r)?;
        let title_name = null_padded_string(&title_raw);

        // ProductCode: 0x10 bytes.
        let pc_raw = bytesa::<0x10>(r)?;
        let product_code = null_padded_string(&pc_raw);

        // Reserved (0x30 bytes).
        let _reserved3 = bytesa::<0x30>(r)?;

        let aci_offset = le_u32(r)?;
        let _aci_size = le_u32(r)?;
        let acid_offset = le_u32(r)?;
        let _acid_size = le_u32(r)?;

        // Parse ACI0.
        r.seek(SeekFrom::Start(base + aci_offset as u64))?;
        let aci = Aci0::parse(r)?;

        // Parse ACID (optional - best effort).
        let acid = if acid_offset > 0 {
            r.seek(SeekFrom::Start(base + acid_offset as u64)).ok();
            Acid::parse(r).ok()
        } else {
            None
        };

        Ok(Self {
            is_64bit,
            main_thread_priority,
            main_thread_core,
            system_resource_size,
            version,
            main_thread_stack_size,
            title_name,
            product_code,
            aci,
            acid,
        })
    }
}

impl Aci0 {
    pub(crate) fn parse<R: Read + Seek>(r: &mut R) -> crate::Result<Self> {
        magic(r, b"ACI0")?;
        let _reserved = bytesa::<0xC>(r)?;
        let program_id = le_u64(r)?;
        Ok(Self { program_id })
    }
}

impl Acid {
    pub(crate) fn parse<R: Read + Seek>(r: &mut R) -> crate::Result<Self> {
        // RSA-2048 signature (0x100) + public key (0x100) = 0x200 bytes before
        // the "ACID" magic.
        let _sig = bytesa::<0x100>(r)?;
        let _pubkey = bytesa::<0x100>(r)?;
        magic(r, b"ACID")?;
        let _size = le_u32(r)?;
        let flags = le_u32(r)?;
        let _reserved = le_u32(r)?;
        let program_id_min = le_u64(r)?;
        let program_id_max = le_u64(r)?;
        Ok(Self {
            flags,
            program_id_min,
            program_id_max,
        })
    }
}

fn null_padded_string(buf: &[u8]) -> String {
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..end]).into_owned()
}
