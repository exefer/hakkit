//! **hakkit** - a reusable Rust library for parsing Nintendo binary formats.
//!
//! # Supported formats
//! | Module | Format |
//! |--------|--------|
//! | [`formats::pfs0`]  | PFS0 / NSP - PartitionFS flat archive |
//! | [`formats::hfs0`]  | HFS0 - SHA-256-hashed archive (XCI) |
//! | [`formats::xci`]   | XCI - Physical game card dump |
//! | [`formats::nca`]   | NCA - Nintendo Content Archive |
//! | [`formats::npdm`]  | NPDM - Program Descriptor Meta |
//! | [`formats::sarc`]  | SARC - SEAD ARChive |
//! | [`formats::bntx`]  | BNTX - Binary NX Texture |
//! | [`formats::bfttf`] | BFTTF/BFOTF - XOR-encrypted font |
//! | [`formats::ncz`]   | NCZ - Zstandard-compressed NCA (NSZ) |

pub mod compression;
pub mod crypto;
pub mod error;
pub mod formats;
pub mod keys;
pub mod utils;

pub use error::{Error, Result};
