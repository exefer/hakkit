//! Cryptographic operations for Nintendo Switch content.
//!
//! This module contains pure-Rust AES implementations used to decrypt Switch
//! content. All functions accept already-loaded key material; key derivation
//! and key-file loading are handled by [`crate::keys::KeySet`].
//!
//! The implementations here are intended for **offline file-format parsing**
//! only. They are not constant-time and should not be used in contexts where
//! timing side-channels are a concern.
//!
//! ## Submodules
//!
//! | Module | Purpose |
//! |--------|---------|
//! | [`nca`] | AES-128-XTS header decryption, AES-128-CTR section decryption, AES-128-ECB key-area unwrapping |
//!
//! ## Key hierarchy (brief)
//!
//! ```text
//! prod.keys
//!   └── header_key (32 bytes)
//!         ├── key1 (bytes  0–15)  ─┐  AES-XTS decrypt NCA header
//!         └── key2 (bytes 16–31)  ─┘
//!
//!   └── key_area_key_{app,ocean,system}_XX (16 bytes each)
//!         └── AES-ECB unwrap EncryptedKeyArea entries in NCA header
//!               └── section key → AES-CTR decrypt section data
//! ```

pub mod nca;
