//! NACP (Nintendo Application Control Property) - game metadata.
//!
//! Found as `/control.nacp` in the RomFS section of a Control NCA. Contains
//! localised title/developer names for all 16 supported languages, plus
//! ratings, display version, supported play modes, and other metadata.
//!
//! This parser surfaces the title/developer name table and the most commonly
//! needed scalar fields. The full 0x4000-byte struct has many more fields
//! that are captured in `extra` for callers that need raw access.
//!
//! ## File Layout
//! ```text
//! [0x0000] TitleEntries   - 16 × 0x300 bytes (one per language)
//! [0x3000] Isbn           - 0x25 bytes (null-padded)
//! [0x3025] StartupUserAccount (u8)
//! [0x3026] Reserved
//! [0x3034] AttributeFlag  (u32 LE)  - bit 0 = Demo
//! [0x3038] SupportedLanguageFlag (u32 LE)
//! [0x303C] ParentalControlFlag   (u32 LE)
//! [0x3040] Screenshot      (u8)     - 0=Allow, 1=Deny
//! [0x3041] VideoCapture    (u8)     - 0=Disabled, 1=Enabled, 2=Automatic
//! [0x3042] Reserved
//! [0x3044] PresenceGroupId (u64 LE)
//! [0x304C] RatingAge       (16 bytes, one per rating org)
//! [0x305C] DisplayVersion  (0x10 bytes, null-padded ASCII)
//! [0x306C] AddOnContentBaseId (u64 LE)
//! [0x3074] SaveDataOwnerId (u64 LE)
//! [0x307C] UserAccountSaveDataSize     (u64 LE)
//! [0x3084] UserAccountSaveDataJournalSize (u64 LE)
//! [0x308C] DeviceSaveDataSize          (u64 LE)
//! [0x3094] DeviceSaveDataJournalSize   (u64 LE)
//! [0x309C] BcatDeliveryCacheStorageSize (u64 LE)
//! [0x30A4] ApplicationErrorCodeCategory (0x8 bytes)
//! [0x30AC] LocalCommunicationId        (8 × u64 LE)
//! [0x30EC] LogoType      (u8) - 0=LicensedByNintendo, 2=Nintendo
//! [0x30ED] LogoHandling  (u8) - 0=Auto, 1=Manual
//! [0x30EE] RuntimeAddOnContentInstall  (u8)
//! [0x30EF] Reserved
//! [0x30F4] SeedForPseudoDeviceId       (u32 LE)
//! [0x30F8] BcatPassphrase (0x41 bytes, null-padded)
//! [0x3139] Reserved
//! [0x3200] PlayLogQueryableApplicationId (8 × u64 LE)
//! [0x3240] PlayLogQueryCapability (u8)
//! [0x3241] RepairFlag (u8)
//! [0x3242] ProgramIndex (u8)
//! [0x3243] RequiredNetworkServiceLicenseOnLaunchFlag (u8)
//! [0x3244..0x4000] Reserved
//! ```
//!
//! ## Title Entry (0x300 bytes each)
//! ```text
//! [0x000] Name          - 0x200 bytes, null-padded UTF-8
//! [0x200] DeveloperName - 0x100 bytes, null-padded UTF-8
//! ```
//!
//! ## Language Index
//! | Index | Language               |
//! |-------|------------------------|
//! | 0     | AmericanEnglish        |
//! | 1     | BritishEnglish         |
//! | 2     | Japanese               |
//! | 3     | French                 |
//! | 4     | German                 |
//! | 5     | LatinAmericanSpanish   |
//! | 6     | Spanish                |
//! | 7     | Italian                |
//! | 8     | Dutch                  |
//! | 9     | CanadianFrench         |
//! | 10    | Portuguese             |
//! | 11    | Russian                |
//! | 12    | Korean                 |
//! | 13    | TraditionalChinese     |
//! | 14    | SimplifiedChinese      |
//! | 15    | BrazilianPortuguese    |

use std::io::{Read, Seek, SeekFrom};

use crate::utils::{bytesa, le_u32, le_u64, null_padded_string, u8};
use crate::{Error, Result};

/// Total expected size of a NACP file.
pub const NACP_SIZE: usize = 0x4000;

/// Number of language entries in a NACP.
pub const NACP_LANGUAGE_COUNT: usize = 16;

/// Language indices for NACP title entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(usize)]
pub enum Language {
    AmericanEnglish = 0,
    BritishEnglish = 1,
    Japanese = 2,
    French = 3,
    German = 4,
    LatinAmericanSpanish = 5,
    Spanish = 6,
    Italian = 7,
    Dutch = 8,
    CanadianFrench = 9,
    Portuguese = 10,
    Russian = 11,
    Korean = 12,
    TraditionalChinese = 13,
    SimplifiedChinese = 14,
    BrazilianPortuguese = 15,
}

impl Language {
    /// All languages in index order.
    pub const ALL: [Language; NACP_LANGUAGE_COUNT] = [
        Self::AmericanEnglish,
        Self::BritishEnglish,
        Self::Japanese,
        Self::French,
        Self::German,
        Self::LatinAmericanSpanish,
        Self::Spanish,
        Self::Italian,
        Self::Dutch,
        Self::CanadianFrench,
        Self::Portuguese,
        Self::Russian,
        Self::Korean,
        Self::TraditionalChinese,
        Self::SimplifiedChinese,
        Self::BrazilianPortuguese,
    ];

    /// Human-readable name for this language.
    pub fn name(self) -> &'static str {
        match self {
            Self::AmericanEnglish => "American English",
            Self::BritishEnglish => "British English",
            Self::Japanese => "Japanese",
            Self::French => "French",
            Self::German => "German",
            Self::LatinAmericanSpanish => "Latin American Spanish",
            Self::Spanish => "Spanish",
            Self::Italian => "Italian",
            Self::Dutch => "Dutch",
            Self::CanadianFrench => "Canadian French",
            Self::Portuguese => "Portuguese",
            Self::Russian => "Russian",
            Self::Korean => "Korean",
            Self::TraditionalChinese => "Traditional Chinese",
            Self::SimplifiedChinese => "Simplified Chinese",
            Self::BrazilianPortuguese => "Brazilian Portuguese",
        }
    }
}

/// Localised title and developer name for one language.
#[derive(Debug, Clone, Default)]
pub struct NacpTitle {
    /// Application name, null-padded UTF-8, 0x200 bytes.
    pub name: String,
    /// Developer name, null-padded UTF-8, 0x100 bytes.
    pub developer: String,
}

impl NacpTitle {
    /// Returns `true` if both `name` and `developer` are empty.
    ///
    /// NACP entries for unsupported languages are zero-filled.
    pub fn is_empty(&self) -> bool {
        self.name.is_empty() && self.developer.is_empty()
    }
}

/// Screenshot permission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Screenshot {
    Allow,
    Deny,
    Unknown(u8),
}

impl From<u8> for Screenshot {
    fn from(v: u8) -> Self {
        match v {
            0 => Self::Allow,
            1 => Self::Deny,
            x => Self::Unknown(x),
        }
    }
}

/// Video capture permission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VideoCapture {
    Disabled,
    Enabled,
    Automatic,
    Unknown(u8),
}

impl From<u8> for VideoCapture {
    fn from(v: u8) -> Self {
        match v {
            0 => Self::Disabled,
            1 => Self::Enabled,
            2 => Self::Automatic,
            x => Self::Unknown(x),
        }
    }
}

/// Logo type shown on startup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogoType {
    LicensedByNintendo,
    DistributedByNintendo,
    Nintendo,
    Unknown(u8),
}

impl From<u8> for LogoType {
    fn from(v: u8) -> Self {
        match v {
            0 => Self::LicensedByNintendo,
            1 => Self::DistributedByNintendo,
            2 => Self::Nintendo,
            x => Self::Unknown(x),
        }
    }
}

/// Parsed NACP (Nintendo Application Control Property).
#[derive(Debug)]
pub struct Nacp {
    /// Localised titles, one per language (index = [`Language`] as usize).
    pub titles: [NacpTitle; NACP_LANGUAGE_COUNT],
    /// Bitmask of supported languages.
    pub supported_language_flag: u32,
    /// `true` if the title is a demo.
    pub is_demo: bool,
    /// Screenshot permission.
    pub screenshot: Screenshot,
    /// Video capture permission.
    pub video_capture: VideoCapture,
    /// Display version string (e.g. `"1.0.0"`).
    pub display_version: String,
    /// Logo type shown on startup.
    pub logo_type: LogoType,
    /// Save data owner ID.
    pub save_data_owner_id: u64,
    /// User account save data size in bytes.
    pub user_account_save_data_size: u64,
    /// User account save data journal size in bytes.
    pub user_account_save_data_journal_size: u64,
    /// Add-on content base ID.
    pub add_on_content_base_id: u64,
    /// Program index (for multi-program titles).
    pub program_index: u8,
}

impl Nacp {
    /// Parse a NACP from `r`.
    ///
    /// The reader must be positioned at the start of the 0x4000-byte NACP
    /// data (i.e. the first title entry). Returns [`Error::Parse`] if the
    /// stream is shorter than [`NACP_SIZE`].
    pub fn parse<R: Read + Seek>(r: &mut R) -> Result<Self> {
        let base = r.stream_position()?;

        // Title entries: 16 × 0x300 bytes.
        // Each entry: 0x200-byte name + 0x100-byte developer name.
        let titles = std::array::from_fn(|_| {
            let name_raw = bytesa::<0x200>(r).unwrap_or([0u8; 0x200]);
            let dev_raw = bytesa::<0x100>(r).unwrap_or([0u8; 0x100]);
            NacpTitle {
                name: null_padded_string(&name_raw),
                developer: null_padded_string(&dev_raw),
            }
        });

        // Validate that we read all 16 × 0x300 = 0x3000 bytes of title entries.
        let after_titles = r.stream_position()?;
        if after_titles - base < 0x3000 {
            return Err(Error::Parse("NACP data too short"));
        }

        // Seek to the scalar fields that follow the title table.

        // 0x3034: AttributeFlag (u32 LE) - bit 0 = Demo
        r.seek(SeekFrom::Start(base + 0x3034))?;
        let attribute_flag = le_u32(r)?;
        let is_demo = (attribute_flag & 0x1) != 0;

        // 0x3038: SupportedLanguageFlag (u32 LE)
        let supported_language_flag = le_u32(r)?;

        // Skip ParentalControlFlag (u32 LE) at 0x303C - not surfaced.
        let _parental_control_flag = le_u32(r)?;

        // 0x3040: Screenshot (u8)
        let screenshot = Screenshot::from(u8(r)?);

        // 0x3041: VideoCapture (u8)
        let video_capture = VideoCapture::from(u8(r)?);

        // 0x305C: DisplayVersion (0x10 bytes, null-padded ASCII)
        r.seek(SeekFrom::Start(base + 0x305C))?;
        let display_version_raw = bytesa::<0x10>(r)?;
        let display_version = null_padded_string(&display_version_raw);

        // 0x306C: AddOnContentBaseId (u64 LE)
        let add_on_content_base_id = le_u64(r)?;

        // 0x3074: SaveDataOwnerId (u64 LE)
        let save_data_owner_id = le_u64(r)?;

        // 0x307C: UserAccountSaveDataSize (u64 LE)
        let user_account_save_data_size = le_u64(r)?;

        // 0x3084: UserAccountSaveDataJournalSize (u64 LE)
        let user_account_save_data_journal_size = le_u64(r)?;

        // 0x30EC: LogoType (u8)
        r.seek(SeekFrom::Start(base + 0x30EC))?;
        let logo_type = LogoType::from(u8(r)?);

        // 0x3242: ProgramIndex (u8)
        r.seek(SeekFrom::Start(base + 0x3242))?;
        let program_index = u8(r)?;

        Ok(Self {
            titles,
            supported_language_flag,
            is_demo,
            screenshot,
            video_capture,
            display_version,
            logo_type,
            save_data_owner_id,
            user_account_save_data_size,
            user_account_save_data_journal_size,
            add_on_content_base_id,
            program_index,
        })
    }

    /// Return the title entry for a specific language.
    pub fn title(&self, lang: Language) -> &NacpTitle {
        &self.titles[lang as usize]
    }

    /// Return the first non-empty title entry and its language, preferring
    /// `AmericanEnglish` first, then scanning all languages in index order.
    ///
    /// Returns `None` only if every entry is empty (malformed NACP).
    pub fn first_title(&self) -> Option<(Language, &NacpTitle)> {
        // Prefer American English.
        let en = &self.titles[Language::AmericanEnglish as usize];
        if !en.is_empty() {
            return Some((Language::AmericanEnglish, en));
        }
        // Fall back to the first non-empty entry.
        Language::ALL.iter().find_map(|&lang| {
            let t = &self.titles[lang as usize];
            if !t.is_empty() { Some((lang, t)) } else { None }
        })
    }

    /// Returns `true` if the given language is marked as supported in the
    /// `SupportedLanguageFlag` bitmask.
    pub fn supports_language(&self, lang: Language) -> bool {
        (self.supported_language_flag >> (lang as u32)) & 1 == 1
    }
}
