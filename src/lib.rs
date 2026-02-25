//! **hakkit** - a reusable Rust library for parsing Nintendo binary formats.
//!
//! # Supported formats
//! | Module | Format |
//! |--------|--------|
//! | [`formats::bfttf`] | BFTTF/BFOTF - XOR-encrypted font |
//! | [`formats::bntx`]  | BNTX - Binary NX Texture |
//! | [`formats::hfs0`]  | HFS0 - SHA-256-hashed archive (XCI) |
//! | [`formats::nacp`]  | NACP - Application control property (title, ratings, save data) |
//! | [`formats::nca`]   | NCA - Nintendo Content Archive |
//! | [`formats::ncz`]   | NCZ - Zstandard-compressed NCA (NSZ) |
//! | [`formats::npdm`]  | NPDM - Program Descriptor Meta |
//! | [`formats::pfs0`]  | PFS0 / NSP - PartitionFS flat archive |
//! | [`formats::romfs`] | RomFS - Read-only game asset filesystem |
//! | [`formats::sarc`]  | SARC - SEAD ARChive |
//! | [`formats::xci`]   | XCI - Physical game card dump |

pub mod compression;
pub mod crypto;
pub mod error;
pub mod formats;
pub mod keys;
mod utils;

pub use error::{Error, Result};
