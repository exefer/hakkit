//! NCA (Nintendo Content Archive) - primary encrypted content container.
//!
//! ## Encryption
//! The first 0xC00 bytes are AES-128-XTS encrypted (sector size 0x200, non-standard
//! reversed tweak). This parser expects **already-decrypted** bytes; the caller is
//! responsible for decryption via `crypto::nca`.
//!
//! ## Header Layout (after decryption, logical offsets from decrypted start)
//! ```text
//! [0x000] RSA-2048 sig[0]  (0x100) - fixed key, over [0x200..0x400]
//! [0x100] RSA-2048 sig[1]  (0x100) - NPDM key
//! [0x200] Magic            NCA3/NCA2/NCA1/NCA0
//! [0x204] DistributionType (1 byte)
//! [0x205] ContentType      (1 byte)
//! [0x206] KeyGenerationOld (1 byte)
//! [0x207] KeyAreaEncKeyIdx (1 byte)
//! [0x208] ContentSize      (u64 LE)
//! [0x210] ProgramId        (u64 LE)
//! [0x218] ContentIndex     (u32 LE)
//! [0x21C] SdkAddonVersion  (u32 LE)
//! [0x220] KeyGeneration    (1 byte)
//! [0x221] SignatureKeyGen  (1 byte, 9.0.0+)
//! [0x222] Reserved         (0xE bytes)
//! [0x230] RightsId         (0x10 bytes)
//! [0x240] FsEntries        (4 × 0x10 bytes)
//! [0x280] FsHeaderHashes   (4 × 0x20 bytes SHA-256)
//! [0x300] EncryptedKeyArea (4 × 0x10 bytes)
//! ```

use std::io::{Read, Seek, SeekFrom};

use crate::utils::{bytesa, le_u32, le_u64, u8};
use crate::{Error, Result};

/// Distribution type for an NCA.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DistributionType {
    Download,
    GameCard,
    Unknown(u8),
}

impl From<u8> for DistributionType {
    fn from(v: u8) -> Self {
        match v {
            0 => Self::Download,
            1 => Self::GameCard,
            x => Self::Unknown(x),
        }
    }
}

/// Content type for an NCA.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ContentType {
    Program,
    Meta,
    Control,
    Manual,
    Data,
    PublicData,
    Unknown(u8),
}

impl From<u8> for ContentType {
    fn from(v: u8) -> Self {
        match v {
            0 => Self::Program,
            1 => Self::Meta,
            2 => Self::Control,
            3 => Self::Manual,
            4 => Self::Data,
            5 => Self::PublicData,
            x => Self::Unknown(x),
        }
    }
}

/// A section entry pointing to a filesystem region within the NCA.
///
/// Offsets are in 0x200-byte media blocks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FsEntry {
    /// Start offset in media blocks (multiply by 0x200 for bytes).
    pub start_block: u32,
    /// End offset in media blocks.
    pub end_block: u32,
}

/// Parsed NCA header (from decrypted bytes).
#[derive(Debug)]
pub struct Nca {
    /// NCA format version: 0, 1, 2, or 3.
    pub version: u8,
    pub distribution_type: DistributionType,
    pub content_type: ContentType,
    /// Effective key generation (max of KeyGenerationOld and KeyGeneration).
    pub key_generation: u8,
    /// Key area encryption key index (0=App, 1=Ocean, 2=System).
    pub key_area_enc_key_index: u8,
    /// Total content size in bytes.
    pub content_size: u64,
    /// Title/program ID.
    pub program_id: u64,
    pub content_index: u32,
    pub sdk_addon_version: u32,
    /// Rights ID (all zeros if no titlekey crypto).
    pub rights_id: [u8; 16],
    /// Up to 4 filesystem section descriptors.
    pub fs_entries: [FsEntry; 4],
    /// SHA-256 hashes of the FsHeaders for each section.
    pub fs_header_hashes: [[u8; 32]; 4],
    /// Encrypted key area (4 × 16 bytes; used when rights_id is all zeros).
    pub encrypted_key_area: [[u8; 16]; 4],
}

impl Nca {
    /// Parse an NCA from a reader over **already-decrypted** NCA bytes.
    ///
    /// The reader should be positioned at the start of the decrypted NCA
    /// (i.e., before the first RSA signature at logical offset 0x000).
    pub fn parse<R: Read + Seek>(r: &mut R) -> Result<Self> {
        // Skip the two RSA-2048 signatures (2 × 0x100 = 0x200 bytes).
        r.seek(SeekFrom::Current(0x200))?;

        // Magic: NCA3, NCA2, NCA1, or NCA0.
        let magic = bytesa::<4>(r)?;
        let version = match &magic {
            b"NCA3" => 3,
            b"NCA2" => 2,
            b"NCA1" => 1,
            b"NCA0" => 0,
            _ => return Err(Error::BadMagic),
        };

        let distribution_type = DistributionType::from(u8(r)?);
        let content_type = ContentType::from(u8(r)?);
        let key_gen_old = u8(r)?;
        let key_area_enc_key_index = u8(r)?;
        let content_size = le_u64(r)?;
        let program_id = le_u64(r)?;
        let content_index = le_u32(r)?;
        let sdk_addon_version = le_u32(r)?;
        let key_gen_new = u8(r)?;
        let _sig_key_gen = u8(r)?;
        let _reserved = bytesa::<0xE>(r)?;

        // Effective key generation: whichever is newer.
        let key_generation = key_gen_old.max(key_gen_new);

        // RightsId (0x10 bytes)
        let rights_id = bytesa::<0x10>(r)?;

        // FsEntries (4 × 0x10)
        let mut fs_entries = [FsEntry {
            start_block: 0,
            end_block: 0,
        }; 4];
        for entry in &mut fs_entries {
            let start_block = le_u32(r)?;
            let end_block = le_u32(r)?;
            let _reserved = le_u64(r)?;
            *entry = FsEntry {
                start_block,
                end_block,
            };
        }

        // FsHeader SHA-256 hashes (4 × 0x20)
        let mut fs_header_hashes = [[0u8; 0x20]; 4];
        for hash in &mut fs_header_hashes {
            *hash = bytesa::<0x20>(r)?;
        }

        // Encrypted key area (4 × 0x10)
        let mut encrypted_key_area = [[0u8; 0x10]; 4];
        for key in &mut encrypted_key_area {
            *key = bytesa::<0x10>(r)?;
        }

        if version > 3 {
            return Err(Error::UnsupportedVersion(version));
        }

        Ok(Self {
            version,
            distribution_type,
            content_type,
            key_generation,
            key_area_enc_key_index,
            content_size,
            program_id,
            content_index,
            sdk_addon_version,
            rights_id,
            fs_entries,
            fs_header_hashes,
            encrypted_key_area,
        })
    }

    /// Returns true if the NCA uses titlekey crypto (RightsId is not all zeros).
    pub fn uses_titlekey_crypto(&self) -> bool {
        self.rights_id.iter().any(|&b| b != 0)
    }

    /// Returns the byte offset within the NCA of the given section.
    pub fn section_offset(&self, section: usize) -> Option<u64> {
        let e = self.fs_entries.get(section)?;
        if e.start_block == 0 && e.end_block == 0 {
            None
        } else {
            Some(e.start_block as u64 * 0x200)
        }
    }
}
