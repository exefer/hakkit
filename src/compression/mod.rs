//! Compression and decompression helpers (requires the `compression` feature).
//!
//! All submodules are gated behind the `compression` Cargo feature so that
//! the core parsing library compiles with zero mandatory dependencies beyond
//! `std`. Enable it when you need to work with compressed content:
//!
//! ```toml
//! [dependencies]
//! hakkit = { version = "0.1", features = ["compression"] }
//! ```
//!
//! ## Submodules
//!
//! | Module | Algorithm | Typical use in hakkit |
//! |--------|-----------|-----------------------|
//! | [`lz4`]  | LZ4 block | Older Nintendo tooling |
//! | [`zstd`] | Zstandard | SARC `.zs` archives; NCZ section blocks |
//!
//! ## Choosing the right function
//!
//! * **SARC `.zs`** - the whole file is one Zstd stream; use
//!   [`zstd::decompress_zstd`], then parse the result with
//!   [`crate::formats::sarc::Sarc::parse`].
//! * **NCZ blocks** - each block is an independent Zstd stream and the
//!   decompressed size is known from the section descriptor; use
//!   [`zstd::decompress_zstd_with_size`] to avoid reallocations.
//! * **LZ4** - use [`lz4::decompress_lz4`] for the size-prepended block
//!   format used by older Nintendo tools.

#[cfg(feature = "compression")]
pub mod lz4;

#[cfg(feature = "compression")]
pub mod zstd;
