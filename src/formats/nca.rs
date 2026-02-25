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
//! [0x400] FsHeader[0]      (0x200 bytes)
//! [0x600] FsHeader[1]      (0x200 bytes)
//! [0x800] FsHeader[2]      (0x200 bytes)
//! [0xA00] FsHeader[3]      (0x200 bytes)
//! ```

use std::io::{Read, Seek, SeekFrom};

use crate::utils::{bytesa, le_u16, le_u32, le_u64, u8};
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

/// Filesystem type stored in an [`FsHeader`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsType {
    RomFs,
    PartitionFs,
    Unknown(u8),
}

impl From<u8> for FsType {
    fn from(v: u8) -> Self {
        match v {
            0 => Self::RomFs,
            1 => Self::PartitionFs,
            x => Self::Unknown(x),
        }
    }
}

/// Hash type stored in an [`FsHeader`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashType {
    Auto,
    None,
    HierarchicalSha256,
    HierarchicalIntegrity,
    AutoSha3,
    HierarchicalSha3256,
    HierarchicalIntegritySha3,
    Unknown(u8),
}

impl From<u8> for HashType {
    fn from(v: u8) -> Self {
        match v {
            0 => Self::Auto,
            1 => Self::None,
            2 => Self::HierarchicalSha256,
            3 => Self::HierarchicalIntegrity,
            4 => Self::AutoSha3,
            5 => Self::HierarchicalSha3256,
            6 => Self::HierarchicalIntegritySha3,
            x => Self::Unknown(x),
        }
    }
}

/// Encryption type stored in an [`FsHeader`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncryptionType {
    Auto,
    None,
    AesXts,
    AesCtr,
    AesCtrEx,
    AesCtrSkipLayerHash,
    AesCtrExSkipLayerHash,
    Unknown(u8),
}

impl From<u8> for EncryptionType {
    fn from(v: u8) -> Self {
        match v {
            0 => Self::Auto,
            1 => Self::None,
            2 => Self::AesXts,
            3 => Self::AesCtr,
            4 => Self::AesCtrEx,
            5 => Self::AesCtrSkipLayerHash,
            6 => Self::AesCtrExSkipLayerHash,
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

/// Per-section filesystem header located at `0x400 + section_index * 0x200`
/// in the decrypted NCA.
///
/// Contains the information needed to select the decryption algorithm and
/// build the AES-CTR counter for section data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FsHeader {
    /// Always 2.
    pub version: u16,
    pub fs_type: FsType,
    pub hash_type: HashType,
    pub encryption_type: EncryptionType,
    /// Raw 0xF8-byte hash data region (layout depends on `hash_type`).
    pub hash_data: [u8; 0xF8],
    /// Raw 0x40-byte patch info region.
    pub patch_info: [u8; 0x40],
    /// Upper 32 bits of the AES-CTR counter (stored big-endian in the counter).
    pub generation: u32,
    /// Bits [32..64] of the AES-CTR counter base (stored big-endian).
    pub secure_value: u32,
    /// Raw 0x30-byte sparse info region.
    pub sparse_info: [u8; 0x30],
    /// Raw 0x28-byte compression info region (present from 12.0.0).
    pub compression_info: [u8; 0x28],
    /// Raw 0x30-byte metadata hash data info region (present from 14.0.0).
    pub metadata_hash_data_info: [u8; 0x30],
}

impl FsHeader {
    /// Build the 16-byte AES-CTR counter base for this section.
    ///
    /// ```text
    /// [0x00..0x04]  SecureValue  (u32 BE)
    /// [0x04..0x08]  Generation   (u32 BE)
    /// [0x08..0x10]  block offset (u64 BE) - caller fills this in
    /// ```
    ///
    /// Set bytes `[8..16]` to `section_byte_offset / 0x10` in big-endian
    /// order before passing to `crypto::nca::decrypt_section_ctr`.
    pub fn build_ctr_base(&self) -> [u8; 16] {
        let mut ctr = [0u8; 16];
        ctr[0..4].copy_from_slice(&self.secure_value.to_be_bytes());
        ctr[4..8].copy_from_slice(&self.generation.to_be_bytes());
        // bytes [8..16] are the per-block offset, filled in by the caller
        ctr
    }
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
    pub fs_entries: [Option<FsEntry>; 4],
    /// SHA-256 hashes of the FsHeaders for each section.
    pub fs_header_hashes: [[u8; 32]; 4],
    /// Encrypted key area (4 × 16 bytes; used when rights_id is all zeros).
    pub encrypted_key_area: [[u8; 16]; 4],
    /// Up to 4 filesystem section headers.
    pub fs_headers: [Option<FsHeader>; 4],
}

impl Nca {
    /// Parse an NCA from `r` over **already-decrypted** NCA bytes.
    ///
    /// The reader must be positioned at the start of the decrypted NCA
    /// (i.e., before the first RSA signature at logical offset 0x000).
    pub fn parse<R: Read + Seek>(r: &mut R) -> Result<Self> {
        let base = r.stream_position()?;

        // Skip the two RSA-2048 signatures (2 × 0x100 = 0x200 bytes).
        r.seek(SeekFrom::Current(0x200))?;
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

        let rights_id = bytesa::<0x10>(r)?;

        let mut fs_entries = [None; 4];
        for entry in &mut fs_entries {
            let start_block = le_u32(r)?;
            let end_block = le_u32(r)?;
            let _reserved = le_u64(r)?;
            *entry = Some(FsEntry {
                start_block,
                end_block,
            });
        }

        let mut fs_header_hashes = [[0u8; 0x20]; 4];
        for hash in &mut fs_header_hashes {
            *hash = bytesa::<0x20>(r)?;
        }

        let mut encrypted_key_area = [[0u8; 0x10]; 4];
        for key in &mut encrypted_key_area {
            *key = bytesa::<0x10>(r)?;
        }

        let mut fs_headers = [None; 4];
        for (i, hdr) in fs_headers.iter_mut().enumerate() {
            if fs_entries[i].is_some() {
                let off = base + 0x400 + i as u64 * 0x200;
                r.seek(SeekFrom::Start(off))?;
                *hdr = Some(parse_fs_header(r)?);
            }
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
            fs_headers,
        })
    }

    /// Returns `true` if the NCA uses titlekey crypto (RightsId is not all zeros).
    pub fn uses_titlekey_crypto(&self) -> bool {
        self.rights_id.iter().any(|&b| b != 0)
    }

    /// Returns the absolute byte offset within the NCA of the given section,
    /// or `None` if the section is absent.
    pub fn section_offset(&self, section: usize) -> Option<u64> {
        let e = self.fs_entries.get(section)?.as_ref()?;
        Some(e.start_block as u64 * 0x200)
    }

    /// Returns the size in bytes of the given section, or `None` if absent.
    pub fn section_size(&self, section: usize) -> Option<u64> {
        let e = self.fs_entries.get(section)?.as_ref()?;
        Some((e.end_block - e.start_block) as u64 * 0x200)
    }

    /// Returns the [`FsHeader`] for the given section, or `None` if absent.
    pub fn fs_header(&self, section: usize) -> Option<&FsHeader> {
        self.fs_headers.get(section)?.as_ref()
    }
}

/// Parse one 0x200-byte FsHeader from the current stream position.
fn parse_fs_header<R: Read + Seek>(r: &mut R) -> Result<FsHeader> {
    let version = le_u16(r)?;
    let fs_type = FsType::from(u8(r)?);
    let hash_type = HashType::from(u8(r)?);
    let encryption_type = EncryptionType::from(u8(r)?);
    let _meta_data_hash_type = u8(r)?; // [14.0.0+] MetaDataHashType
    let _reserved0 = bytesa::<2>(r)?;

    let hash_data = bytesa::<0xF8>(r)?;
    let patch_info = bytesa::<0x40>(r)?;

    let generation = le_u32(r)?;
    let secure_value = le_u32(r)?;

    let sparse_info = bytesa::<0x30>(r)?;
    let compression_info = bytesa::<0x28>(r)?;
    let metadata_hash_data_info = bytesa::<0x30>(r)?;
    // remaining bytes to 0x200 are reserved padding

    Ok(FsHeader {
        version,
        fs_type,
        hash_type,
        encryption_type,
        hash_data,
        patch_info,
        generation,
        secure_value,
        sparse_info,
        compression_info,
        metadata_hash_data_info,
    })
}

/// A program NCA (`ContentType::Program`).
///
/// Section 0 = ExeFS (code + `main.npdm`), section 1 = RomFS.
#[derive(Debug)]
pub struct ProgramNca {
    pub header: Nca,
}

impl ProgramNca {
    /// Byte offset of the ExeFS section (section 0), or `None` if absent.
    pub fn exefs_offset(&self) -> Option<u64> {
        self.header.section_offset(0)
    }

    /// Size in bytes of the ExeFS section, or `None` if absent.
    pub fn exefs_size(&self) -> Option<u64> {
        self.header.section_size(0)
    }

    /// Byte offset of the RomFS section (section 1), or `None` if absent.
    pub fn romfs_offset(&self) -> Option<u64> {
        self.header.section_offset(1)
    }

    /// Size in bytes of the RomFS section, or `None` if absent.
    pub fn romfs_size(&self) -> Option<u64> {
        self.header.section_size(1)
    }

    /// [`FsHeader`] for the ExeFS section, or `None` if absent.
    pub fn exefs_fs_header(&self) -> Option<&FsHeader> {
        self.header.fs_header(0)
    }

    /// [`FsHeader`] for the RomFS section, or `None` if absent.
    pub fn romfs_fs_header(&self) -> Option<&FsHeader> {
        self.header.fs_header(1)
    }
}

/// A meta (CNMT) NCA (`ContentType::Meta`).
///
/// Section 0 is a PartitionFS holding the content meta XML and binary.
#[derive(Debug)]
pub struct MetaNca {
    pub header: Nca,
}

impl MetaNca {
    /// Byte offset of the meta PartitionFS section (section 0).
    pub fn meta_offset(&self) -> Option<u64> {
        self.header.section_offset(0)
    }

    /// [`FsHeader`] for the meta section.
    pub fn meta_fs_header(&self) -> Option<&FsHeader> {
        self.header.fs_header(0)
    }
}

/// A control NCA (`ContentType::Control`).
///
/// Section 0 is a RomFS containing `control.nacp` and icon images.
#[derive(Debug)]
pub struct ControlNca {
    pub header: Nca,
}

impl ControlNca {
    /// Byte offset of the control RomFS section (section 0).
    pub fn romfs_offset(&self) -> Option<u64> {
        self.header.section_offset(0)
    }

    /// [`FsHeader`] for the control RomFS section.
    pub fn romfs_fs_header(&self) -> Option<&FsHeader> {
        self.header.fs_header(0)
    }
}

/// A manual NCA (`ContentType::Manual`).
///
/// Section 1 is a RomFS containing the HTML manual documents.
#[derive(Debug)]
pub struct ManualNca {
    pub header: Nca,
}

impl ManualNca {
    /// Byte offset of the manual RomFS section (section 1).
    pub fn romfs_offset(&self) -> Option<u64> {
        self.header.section_offset(1)
    }

    /// [`FsHeader`] for the manual RomFS section.
    pub fn romfs_fs_header(&self) -> Option<&FsHeader> {
        self.header.fs_header(1)
    }
}

/// A data NCA (`ContentType::Data`).
#[derive(Debug)]
pub struct DataNca {
    pub header: Nca,
}

/// A public data NCA (`ContentType::PublicData`).
#[derive(Debug)]
pub struct PublicDataNca {
    pub header: Nca,
}

/// A typed NCA produced by converting a raw [`Nca`] via [`TryFrom`].
///
/// ```rust,ignore
/// use hakkit::formats::nca::{Nca, TypedNca};
///
/// let typed = TypedNca::try_from(nca)?;
/// match typed {
///     TypedNca::Program(p) => {
///         println!("program id: {:016X}", p.header.program_id);
///         println!("exefs @ {:?}", p.exefs_offset());
///     }
///     TypedNca::Control(c) => println!("control nca, key gen {}", c.header.key_generation),
///     _ => {}
/// }
/// ```
#[derive(Debug)]
pub enum TypedNca {
    Program(ProgramNca),
    Meta(MetaNca),
    Control(ControlNca),
    Manual(ManualNca),
    Data(DataNca),
    PublicData(PublicDataNca),
}

impl TypedNca {
    /// Return a reference to the underlying raw [`Nca`] header regardless of variant.
    pub fn header(&self) -> &Nca {
        match self {
            Self::Program(n) => &n.header,
            Self::Meta(n) => &n.header,
            Self::Control(n) => &n.header,
            Self::Manual(n) => &n.header,
            Self::Data(n) => &n.header,
            Self::PublicData(n) => &n.header,
        }
    }
}

impl TryFrom<Nca> for TypedNca {
    type Error = Error;

    /// Returns [`Error::Parse`] if the content type is unknown.
    fn try_from(nca: Nca) -> Result<Self> {
        match nca.content_type {
            ContentType::Program => Ok(Self::Program(ProgramNca { header: nca })),
            ContentType::Meta => Ok(Self::Meta(MetaNca { header: nca })),
            ContentType::Control => Ok(Self::Control(ControlNca { header: nca })),
            ContentType::Manual => Ok(Self::Manual(ManualNca { header: nca })),
            ContentType::Data => Ok(Self::Data(DataNca { header: nca })),
            ContentType::PublicData => Ok(Self::PublicData(PublicDataNca { header: nca })),
            ContentType::Unknown(_) => Err(Error::Parse("unknown NCA content type")),
        }
    }
}
