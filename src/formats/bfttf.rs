//! BFTTF / BFOTF (Binary caFe TrueType/OpenType Font) - XOR-encrypted font.
//!
//! A standard TTF or OTF font file wrapped in simple XOR obfuscation.
//! Used as system fonts on Nintendo Switch and Wii U.
//!
//! * `.bfttf` - TrueType font
//! * `.bfotf` - OpenType font
//!
//! There is **no custom file header**; the entire file is XOR-encrypted.
//! After decryption the result is a standard font file:
//! * TTF: starts with `\x00\x01\x00\x00\x00`
//! * OTF: starts with `OTTO`
//! * TTC: starts with `ttcf`
//!
//! ## XOR Keys (16 bytes each, cycling over the entire file)
//!
//! | Platform | Key (hex) |
//! |----------|-----------|
//! | Wii U    | `2A CE F5 16 10 0D C4 C3 28 78 27 42 A5 5B F4 AB` |
//! | Switch   | `15 9A 7D 6F 16 6F D0 0C 67 E7 39 98 0B EB F6 62` |
//! | Windows  | `97 3B 5C 6C 26 F3 FA B5 A2 D5 8E B5 5A 4D D5 51` |

use std::io::Read;

use crate::{Error, Result};

/// Platform for which a BFTTF/BFOTF font is intended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FontPlatform {
    WiiU,
    Switch,
    Windows,
}

impl FontPlatform {
    /// The 16-byte XOR key for this platform.
    pub fn xor_key(self) -> &'static [u8; 16] {
        match self {
            FontPlatform::WiiU => &[
                0x2A, 0xCE, 0xF5, 0x16, 0x10, 0x0D, 0xC4, 0xC3, 0x28, 0x78, 0x27, 0x42, 0xA5, 0x5B,
                0xF4, 0xAB,
            ],
            FontPlatform::Switch => &[
                0x15, 0x9A, 0x7D, 0x6F, 0x16, 0x6F, 0xD0, 0x0C, 0x67, 0xE7, 0x39, 0x98, 0x0B, 0xEB,
                0xF6, 0x62,
            ],
            FontPlatform::Windows => &[
                0x97, 0x3B, 0x5C, 0x6C, 0x26, 0xF3, 0xFA, 0xB5, 0xA2, 0xD5, 0x8E, 0xB5, 0x5A, 0x4D,
                0xD5, 0x51,
            ],
        }
    }
}

/// Parsed BFTTF/BFOTF file (holds the raw encrypted bytes).
#[derive(Debug)]
pub struct Bfttf {
    /// Platform detected from the decrypted magic bytes.
    pub platform: FontPlatform,
    data: Vec<u8>,
}

impl Bfttf {
    /// Read a BFTTF/BFOTF from `r` and auto-detect the platform.
    ///
    /// Tries each XOR key and checks the resulting font magic.
    /// Returns [`Error::BadMagic`] if no platform matches.
    pub fn parse<R: Read>(r: &mut R) -> Result<Self> {
        let mut data = Vec::new();
        r.read_to_end(&mut data)?;

        for &platform in &[
            FontPlatform::Switch,
            FontPlatform::WiiU,
            FontPlatform::Windows,
        ] {
            if is_valid_font_after_xor(&data, platform.xor_key()) {
                return Ok(Self { platform, data });
            }
        }
        Err(Error::BadMagic)
    }

    /// Decrypt to raw TTF/OTF bytes.
    pub fn decrypt(&self) -> Vec<u8> {
        xor_with_key(&self.data, self.platform.xor_key())
    }
}

/// Decrypt a BFTTF/BFOTF byte slice for the given platform.
///
/// XOR is symmetric: `decrypt(encrypt(data)) == data`.
pub fn decrypt(data: &[u8], platform: FontPlatform) -> Vec<u8> {
    xor_with_key(data, platform.xor_key())
}

/// Encrypt a raw TTF/OTF byte slice into BFTTF/BFOTF format.
///
/// XOR is symmetric: `encrypt(decrypt(data)) == data`.
pub fn encrypt(data: &[u8], platform: FontPlatform) -> Vec<u8> {
    xor_with_key(data, platform.xor_key())
}

fn xor_with_key(data: &[u8], key: &[u8; 16]) -> Vec<u8> {
    data.iter()
        .enumerate()
        .map(|(i, &b)| b ^ key[i % 16])
        .collect()
}

fn is_valid_font_after_xor(data: &[u8], key: &[u8; 16]) -> bool {
    if data.len() < 5 {
        return false;
    }
    let head: [u8; 5] = std::array::from_fn(|i| data[i] ^ key[i % 16]);

    head.starts_with(&[0x00, 0x01, 0x00, 0x00, 0x00])  // TrueType
        || head.starts_with(b"OTTO")                   // OpenType
        || head.starts_with(b"ttcf") // TTC
}
