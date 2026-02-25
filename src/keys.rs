//! Key management for Nintendo Switch cryptography.
//!
//! Nintendo Switch titles use a layered key derivation scheme:
//!
//! * **Master keys** (`master_key_XX`) are the root secrets obtained from
//!   the security processor. There is one per firmware generation.
//! * **Key area encryption keys** (KAEK) are derived per content type
//!   (Application / Ocean / System) from the master key.
//! * **Title keys** decrypt individual NCAs; they are themselves wrapped
//!   with KAEK or with a per-title key.
//! * **Header key** decrypts the AES-XTS NCA header (0xC00 bytes).
//!
//! This module intentionally avoids cryptographic operations - it is a
//! plain data container. Callers load keys from `prod.keys` / `title.keys`
//! and pass them to the crypto functions in [`crate::crypto`].
//!
//! ## Key file format
//! Nintendo key files are simple `name = hex_value` text files, one entry
//! per line, comments prefixed with `;`.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read};
use std::result::Result as StdResult;

use crate::{Error, Result};

/// Maximum number of master key generations understood by this library.
pub const MAX_KEY_GENERATION: usize = 32;

/// Key area encryption key index (determines which KAEK derivation chain is
/// used for a particular NCA).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum KaekIndex {
    /// Application content (most games).
    Application = 0,
    /// Ocean content (game-card specific).
    Ocean = 1,
    /// System content (OS modules).
    System = 2,
}

impl TryFrom<u8> for KaekIndex {
    type Error = Error;
    fn try_from(v: u8) -> Result<Self> {
        match v {
            0 => Ok(Self::Application),
            1 => Ok(Self::Ocean),
            2 => Ok(Self::System),
            _ => Err(Error::Parse("invalid KAEK index")),
        }
    }
}

/// All keys needed to decrypt Switch content.
///
/// Fields that are absent will be [`None`] / zero-length; the crypto layer
/// will return an error rather than silently producing garbage output.
#[derive(Debug, Default)]
pub struct KeySet {
    /// AES-XTS key pair (two 16-byte keys) used to decrypt NCA headers.
    pub header_key: Option<[u8; 32]>,

    /// Key area encryption keys, indexed by [`KaekIndex`] then by generation.
    ///
    /// `kaek[index][generation]` is a 16-byte AES key.
    pub kaek: [[Option<[u8; 16]>; MAX_KEY_GENERATION]; 3],

    /// Title keys, keyed by 16-byte rights ID (hex string) → 16-byte key.
    pub title_keys: HashMap<[u8; 16], [u8; 16]>,
}

impl KeySet {
    /// Create an empty key set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Load keys from a `prod.keys`-style reader.
    ///
    /// Lines beginning with `;` and blank lines are ignored. Each valid line
    /// has the form `key_name = hexvalue`. Unknown key names are silently
    /// skipped so that the library remains forward-compatible.
    pub fn load_prod_keys<R: Read>(&mut self, reader: R) -> Result<()> {
        let buf = BufReader::new(reader);
        for line in buf.lines() {
            let line = line.map_err(Error::Io)?;
            let line = line.trim();
            if line.is_empty() || line.starts_with(';') {
                continue;
            }
            let Some((name, value)) = line.split_once('=') else {
                continue;
            };
            let name = name.trim();
            let value = value.trim();

            if name == "header_key" {
                if let Ok(bytes) = decode_hex_32(value) {
                    self.header_key = Some(bytes);
                }
                continue;
            }

            // key_area_key_application_XX / key_area_key_ocean_XX / key_area_key_system_XX
            for (idx, prefix) in [
                (0usize, "key_area_key_application_"),
                (1, "key_area_key_ocean_"),
                (2, "key_area_key_system_"),
            ] {
                if let Some(gen_str) = name.strip_prefix(prefix)
                    && let (Ok(r#gen), Ok(key)) =
                        (usize::from_str_radix(gen_str, 16), decode_hex_16(value))
                    && r#gen < MAX_KEY_GENERATION
                {
                    self.kaek[idx][r#gen] = Some(key);
                }
            }
        }
        Ok(())
    }

    /// Load title keys from a `title.keys`-style reader.
    ///
    /// Each line: `<32-hex-char rights_id> = <32-hex-char title_key>`.
    pub fn load_title_keys<R: Read>(&mut self, reader: R) -> Result<()> {
        let buf = BufReader::new(reader);
        for line in buf.lines() {
            let line = line.map_err(Error::Io)?;
            let line = line.trim();
            if line.is_empty() || line.starts_with(';') {
                continue;
            }
            let Some((rights, key)) = line.split_once('=') else {
                continue;
            };
            let rights = rights.trim();
            let key = key.trim();
            if let (Ok(r), Ok(k)) = (decode_hex_16(rights), decode_hex_16(key)) {
                self.title_keys.insert(r, k);
            }
        }
        Ok(())
    }

    /// Look up the KAEK for the given index and firmware generation.
    pub fn get_kaek(&self, index: KaekIndex, generation: u8) -> Option<&[u8; 16]> {
        let r#gen = generation as usize;
        if r#gen >= MAX_KEY_GENERATION {
            return None;
        }
        self.kaek[index as usize][r#gen].as_ref()
    }

    /// Look up a title key by rights ID.
    pub fn get_title_key(&self, rights_id: &[u8; 16]) -> Option<&[u8; 16]> {
        self.title_keys.get(rights_id)
    }
}

fn decode_hex_16(s: &str) -> StdResult<[u8; 16], ()> {
    decode_hex_n::<16>(s)
}

fn decode_hex_32(s: &str) -> StdResult<[u8; 32], ()> {
    decode_hex_n::<32>(s)
}

fn decode_hex_n<const N: usize>(s: &str) -> StdResult<[u8; N], ()> {
    let s = s.trim();
    if s.len() != N * 2 {
        return Err(());
    }
    let mut out = [0u8; N];
    for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
        let hi = hex_nibble(chunk[0])?;
        let lo = hex_nibble(chunk[1])?;
        out[i] = (hi << 4) | lo;
    }
    Ok(out)
}

fn hex_nibble(b: u8) -> StdResult<u8, ()> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(()),
    }
}
