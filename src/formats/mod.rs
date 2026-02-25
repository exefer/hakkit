//! Parsers for Nintendo binary binary formats.
//!
//! Each submodule targets one format family. All parsers follow the same
//! conventions:
//!
//! * **Generic over** [`std::io::Read`] + [`std::io::Seek`] - pass a [`std::fs::File`], a
//!   [`std::io::Cursor`], a memory-mapped region, or anything else
//!   that implements both traits.
//! * **Metadata only** - the `parse` method reads headers and builds an
//!   in-memory description of the archive's contents. File data is never
//!   eagerly loaded.
//! * **Reader wrappers** - archive formats ([`pfs0::Pfs0`], [`hfs0::Hfs0`], [`sarc::Sarc`]) have a
//!   matching `*Reader<R>` type that owns the underlying reader and provides
//!   zero-copy bounded access to individual file contents via
//!   [`std::io::Take<&mut R>`].
//! * **Crypto and compression are separate** - parsers receive
//!   already-decrypted / already-decompressed bytes. Use
//!   [`crate::crypto::nca`] and [`crate::compression`] before parsing when
//!   necessary.
//!
//! ## Format overview
//!
//! | Module    | Format      | Description |
//! |-----------|-------------|-------------|
//! | [`bfttf`] | BFTTF/BFOTF | XOR-obfuscated TrueType/OpenType system font |
//! | [`bntx`]  | BNTX        | GPU texture container; one or more textures with mip chains |
//! | [`hfs0`]  | HFS0        | SHA-256-hashed archive embedded in XCI game cards |
//! | [`nacp`]  | NACP        | Application control property; title names, ratings, save data sizes |
//! | [`pfs0`]  | PFS0 / NSP  | Flat archive; outer container for NSP files and NCA ExeFS/Logo sections |
//! | [`nca`]   | NCA         | Primary encrypted content container; holds program, meta, control, and data content |
//! | [`ncz`]   | NCZ / NSZ   | Zstandard-compressed NCA sections packed inside an NSP/PFS0 |
//! | [`npdm`]  | NPDM        | Process security metadata (`main.npdm`) found in NCA ExeFS sections |
//! | [`romfs`] | RomFS       | Read-only game asset filesystem; Level 3 of the IVFC hash tree inside NCA RomFS sections |
//! | [`sarc`]  | SARC        | General-purpose game asset archive; often Zstd-compressed (`.zs` / `.szs`) |
//! | [`xci`]   | XCI         | Physical game card dump; root contains an HFS0 partition table |

pub mod bfttf;
pub mod bntx;
pub mod hfs0;
pub mod nacp;
pub mod nca;
pub mod ncz;
pub mod npdm;
pub mod pfs0;
pub mod romfs;
pub mod sarc;
pub mod xci;
