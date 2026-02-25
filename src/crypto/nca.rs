//! Cryptographic helpers for NCA files.
//!
//! ## AES-128-XTS - NCA header decryption
//!
//! The first 0xC00 bytes of every NCA are AES-128-XTS encrypted:
//! * Key material: two 16-byte halves of the 32-byte `header_key`.
//! * Sector size: 0x200 bytes.
//! * Tweak: byte-reversed sector index (Nintendo's non-standard variant -
//!   the sector number is stored big-endian rather than the standard
//!   little-endian).
//! * Sectors: 0x000-0x1FF = NCA header (sector 0), 0x200-0x3FF = NCA header
//!   (sector 1), 0x400-0x5FF = FsHeader 0 (sector 2), etc.
//!
//! For NCA2, each FsHeader is independently encrypted as sector 0 rather
//! than using the sector that corresponds to its position.
//!
//! ## AES-128-CTR - NCA section decryption
//!
//! Each NCA section uses AES-128-CTR. The 128-bit counter is built from the
//! `Generation` and `SecureValue` fields in the FsHeader combined with the
//! byte offset being decrypted, as described in the switchbrew wiki.
//!
//! ## Pure-Rust implementation note
//!
//! To keep the dependency footprint small, AES is implemented here with a
//! compact lookup-table approach. This is not constant-time and should not
//! be used for security-sensitive applications, but it is correct and
//! sufficient for offline file-format parsing.

// The AES S-box is a 256-entry substitution table applied byte-by-byte during SubBytes.
// It is constructed by: (1) taking the multiplicative inverse of each byte in GF(2^8) - mapping 0 to 0,
// then (2) applying a fixed affine transformation over GF(2) to remove any remaining algebraic structure.
// The affine step is what makes the S-box resistant to interpolation attacks in GF(2^8).
// Without it, AES could be described as a simple rational function and broken algebraically.
// https://en.wikipedia.org/wiki/Rijndael_S-box
const SBOX: [u8; 256] = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
];

// Multiply two bytes together in GF(2^8) under AES's chosen irreducible polynomial x^8+x^4+x^3+x+1.
// GF(2^8) is a finite field with 256 elements where addition is XOR and multiplication is defined
// by carry-less polynomial multiplication followed by reduction mod the irreducible polynomial.
// The polynomial 0x11B (= x^8+x^4+x^3+x+1) is the one Rijndael specifies; others would give a different field.
// This function is used by MixColumns and InvMixColumns to compute linear combinations of state bytes.
// https://en.wikipedia.org/wiki/Finite_field_arithmetic#Rijndael's_(AES)_finite_field
#[inline]
fn gmul(mut a: u8, mut b: u8) -> u8 {
    let mut p = 0u8; // product accumulator, starts at additive identity (zero in GF(2^8))
    for _ in 0..8 {
        if b & 1 != 0 {
            p ^= a;
        } // if current low bit of b is 1, add a into the product (XOR = addition in GF(2))
        let hi = a & 0x80 != 0; // remember if the high bit is set before we shift, so we know whether to reduce
        a <<= 1; // multiply a by x (shift left by 1 bit, same as increasing polynomial degree by 1)
        if hi {
            a ^= 0x1B;
        } // if a overflowed 8 bits, reduce mod 0x11B; 0x1B is the low 8 bits of 0x11B (drop the x^8 term)
        b >>= 1; // done with this bit of b, advance to the next
    }
    p
}

// AES operates on a 4x4 matrix of bytes called the "state", stored here as a flat 16-byte array.
// The layout is column-major: bytes [0..4] are column 0, bytes [4..8] are column 1, and so on.
// This matches the Rijndael specification and is important for ShiftRows/MixColumns to be correct.
// https://en.wikipedia.org/wiki/Advanced_Encryption_Standard#Description_of_the_cipher
type Block = [u8; 16];

// SubBytes: replace each byte of the state with the value at that index in the S-box.
// This is the only non-linear step in AES. Without non-linearity, the entire cipher would be
// a linear function of the key and plaintext, making it trivially breakable by linear algebra.
// The S-box's non-linearity specifically resists linear cryptanalysis and differential cryptanalysis.
// https://en.wikipedia.org/wiki/Advanced_Encryption_Standard#The_SubBytes_step
fn sub_bytes(s: &mut Block) {
    for b in s.iter_mut() {
        *b = SBOX[*b as usize];
    }
}

// ShiftRows: cyclically shift the bytes in each row of the 4x4 state matrix to the left.
// Row 0 is not shifted; row 1 shifts by 1; row 2 shifts by 2; row 3 shifts by 3.
// In column-major storage, row i consists of bytes at indices {i, i+4, i+8, i+12}.
// This step ensures that after MixColumns, every byte of each column came from a different original column,
// which is how AES achieves full diffusion across the state in just two rounds.
// https://en.wikipedia.org/wiki/Advanced_Encryption_Standard#The_ShiftRows_step
fn shift_rows(s: &mut Block) {
    // Row 1 (bytes at col-major indices 1, 5, 9, 13): left-rotate by 1 position
    let t = s[1];
    s[1] = s[5];
    s[5] = s[9];
    s[9] = s[13];
    s[13] = t;
    // Row 2 (bytes at col-major indices 2, 6, 10, 14): left-rotate by 2 - two swaps are equivalent to a double rotate
    s.swap(2, 10);
    s.swap(6, 14);
    // Row 3 (bytes at col-major indices 3, 7, 11, 15): left-rotate by 3 = right-rotate by 1
    let t = s[15];
    s[15] = s[11];
    s[11] = s[7];
    s[7] = s[3];
    s[3] = t;
}

// MixColumns: treat each column of the state as a 4-term polynomial over GF(2^8) and multiply
// it by the fixed polynomial a(x) = {03}x^3 + {01}x^2 + {01}x + {02}, working modulo x^4 + 1.
// This is equivalent to multiplying by a fixed 4x4 MDS (Maximum Distance Separable) matrix.
// An MDS matrix guarantees that any change in k input bytes affects all 4 output bytes (k=1..4),
// which is the formal definition of optimal diffusion. Combined with ShiftRows, any 1-byte change
// in the input will fully spread across the entire state after 2 rounds (the "avalanche effect").
// https://en.wikipedia.org/wiki/Rijndael_MixColumns
fn mix_columns(s: &mut Block) {
    for i in 0..4 {
        let b = i * 4; // byte offset of the start of column i in the column-major block
        let (s0, s1, s2, s3) = (s[b], s[b + 1], s[b + 2], s[b + 3]);
        // The MDS matrix for MixColumns has rows that are cyclic shifts of [2, 3, 1, 1] in GF(2^8).
        // Multiplying by 2 in GF(2^8) is a left shift + conditional XOR 0x1B (handled by gmul).
        // Multiplying by 3 = multiplying by (2 XOR 1), so gmul(3,x) = gmul(2,x) XOR x.
        s[b] = gmul(0x02, s0) ^ gmul(0x03, s1) ^ s2 ^ s3;
        s[b + 1] = s0 ^ gmul(0x02, s1) ^ gmul(0x03, s2) ^ s3;
        s[b + 2] = s0 ^ s1 ^ gmul(0x02, s2) ^ gmul(0x03, s3);
        s[b + 3] = gmul(0x03, s0) ^ s1 ^ s2 ^ gmul(0x02, s3);
    }
}

// AddRoundKey: XOR each byte of the state with the corresponding byte of the current round key.
// This is the only step that incorporates secret key material; all other steps are public transformations.
// XOR is used because it is its own inverse - the same operation works for both encryption and decryption.
// https://en.wikipedia.org/wiki/Advanced_Encryption_Standard#The_AddRoundKey_step
fn add_round_key(s: &mut Block, rk: &[u8]) {
    for (b, k) in s.iter_mut().zip(rk.iter()) {
        *b ^= k;
    }
}

// Expand a 16-byte AES-128 key into 176 bytes of round key material (11 round keys of 16 bytes each).
// The key schedule iteratively derives new 4-byte "words" from the previous ones using RotWord, SubWord,
// and XOR with a round constant (RCON). RCON values are powers of x in GF(2^8): RCON[i] = x^(i-1) mod 0x11B.
// The purpose of RCON is to break the symmetry between rounds - without it, round keys would have a regular
// structure that could be exploited in related-key attacks.
// https://en.wikipedia.org/wiki/AES_key_schedule
fn key_expand(key: &[u8; 16]) -> [u8; 176] {
    let mut w = [0u8; 176];
    w[..16].copy_from_slice(key); // round key 0 is just the original key itself
    let rcon: [u8; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]; // x^0 through x^9 in GF(2^8)
    for i in 4..44usize {
        let mut t = [
            w[(i - 1) * 4],
            w[(i - 1) * 4 + 1],
            w[(i - 1) * 4 + 2],
            w[(i - 1) * 4 + 3],
        ]; // t = last 4-byte word produced
        if i % 4 == 0 {
            // RotWord: cyclic left-rotate the 4-byte word by 1 byte to introduce positional dependence
            t = [t[1], t[2], t[3], t[0]];
            // SubWord: apply S-box to each byte of the rotated word to add non-linearity to the key schedule,
            // then XOR the first byte with RCON to make every round's transformation unique
            t = [
                SBOX[t[0] as usize] ^ rcon[i / 4 - 1], // RCON XOR prevents slide attacks and round-key symmetry
                SBOX[t[1] as usize],
                SBOX[t[2] as usize],
                SBOX[t[3] as usize],
            ];
        }
        // Each word W[i] = W[i-4] XOR t, creating a running chain that depends on all prior key material
        for j in 0..4 {
            w[i * 4 + j] = w[(i - 4) * 4 + j] ^ t[j];
        }
    }
    w
}

// Encrypt a single 16-byte block with AES-128 (the standard 10-round Rijndael cipher).
// Round structure: 1 initial AddRoundKey, then 9 full rounds, then a final round without MixColumns.
// Omitting MixColumns in the final round makes the inverse cipher structurally symmetric,
// allowing a hardware implementation to share SubBytes/ShiftRows logic between encrypt and decrypt.
// https://en.wikipedia.org/wiki/Advanced_Encryption_Standard#High-level_description_of_the_algorithm
fn aes128_encrypt_block(block: &Block, round_keys: &[u8; 176]) -> Block {
    let mut s = *block;
    add_round_key(&mut s, &round_keys[..16]); // initial key whitening before round 1 - prevents known-plaintext attacks on round 1 alone
    for round in 1..10 {
        sub_bytes(&mut s); // confusion: non-linear S-box substitution, the only non-linear step
        shift_rows(&mut s); // inter-column permutation that feeds bytes from different columns into MixColumns
        mix_columns(&mut s); // diffusion: each output byte of a column depends on all 4 input bytes of that column
        add_round_key(&mut s, &round_keys[round * 16..(round + 1) * 16]); // inject this round's key material
    }
    sub_bytes(&mut s); // final round: SubBytes without MixColumns (omitted to keep encrypt/decrypt inverse symmetric)
    shift_rows(&mut s); // final ShiftRows
    add_round_key(&mut s, &round_keys[160..]); // inject round key 10 (the last one)
    s
}

// XTS (XEX-based Tweaked-codebook mode with ciphertext Stealing) is a block cipher mode
// specifically designed for storage/disk encryption where each "sector" is a fixed-size unit.
// Unlike ECB, two identical sectors encrypt differently because they use different tweak values.
// Unlike CBC, sectors can be decrypted independently and in parallel, enabling fast random access.
// XTS is standardized in IEEE 1619-2007 and NIST SP 800-38E and is used in many disk encryption systems.
// https://en.wikipedia.org/wiki/Disk_encryption_theory#XTS

// Build the 16-byte XTS tweak input for a given sector number.
// IEEE 1619-2007 (standard XTS) stores the sector number as a 128-bit little-endian integer.
// Nintendo uses a non-standard big-endian encoding in the upper 8 bytes of the 16-byte block.
// This tweak value is then AES-encrypted with key2 before being used to whiten the data blocks.
fn make_xts_tweak(sector: u64) -> Block {
    let mut t = [0u8; 16];
    t[8..].copy_from_slice(&sector.to_be_bytes()); // non-standard: big-endian sector index in the upper half of the tweak block
    t
}

// Advance the XTS tweak polynomial by multiplying it by x in GF(2^128) mod x^128+x^7+x^2+x+1.
// This is a left-shift of the full 128-bit value by 1 bit, with conditional XOR of 0x87 on overflow.
// 0x87 = 0b10000111 represents the lower 7 bits of the GF(2^128) reduction polynomial (x^7+x^2+x+1),
// which is what you XOR in after dropping the x^128 term when the high bit overflows.
// This advances the tweak cheaply (no AES call needed) for each successive 16-byte block in a sector.
// https://en.wikipedia.org/wiki/Disk_encryption_theory#Xor–encrypt–xor_(XEX)
fn xts_mult_tweak(t: &mut Block) {
    let carry = t[15] >> 7; // save the bit shifting out of the MSB - if set, we must reduce afterward
    for i in (1..16).rev() {
        t[i] = (t[i] << 1) | (t[i - 1] >> 7); // shift entire 128-bit value left 1 bit, propagating carries byte by byte
    }
    t[0] <<= 1; // shift the lowest-address byte (no incoming carry from below)
    if carry != 0 {
        t[0] ^= 0x87; // reduce mod the GF(2^128) polynomial: XOR with the low 8 bits of x^128+x^7+x^2+x+1
    }
}

// Decrypt a single 0x200-byte (512-byte) XTS sector in-place.
// XTS decryption is: for each 16-byte block, pre-XOR with tweak T, AES-decrypt, post-XOR with same T.
// The double XOR with T (called "whitening") hides plaintext patterns without depending on other blocks.
// key1 is the block cipher key; key2 is only ever used to produce the initial encrypted tweak value.
// Keeping key1 and key2 separate prevents the whitening tweak from revealing information about key1.
// https://en.wikipedia.org/wiki/Disk_encryption_theory#XTS
fn xts_decrypt_sector(data: &mut [u8; 0x200], key1: &[u8; 16], key2: &[u8; 16], sector: u64) {
    let rk1 = key_expand(key1); // round keys for AES decryption of the actual data blocks
    let rk2 = key_expand(key2); // round keys for AES encryption of the tweak (only done once per sector)

    // T = E_k2(sector_number): encrypt the sector number with key2 to produce the initial tweak value.
    // Encrypting the sector number makes the tweak secret (requires key2 to predict), which is necessary
    // for XTS's security proof - a predictable tweak would let an attacker detect when sectors are identical.
    let mut t = aes128_encrypt_block(&make_xts_tweak(sector), &rk2);

    for block_start in (0..0x200usize).step_by(16) {
        let mut block = [0u8; 16];
        block.copy_from_slice(&data[block_start..block_start + 16]);

        for i in 0..16 {
            block[i] ^= t[i];
        } // pre-whitening: XOR ciphertext with tweak T before AES decryption
        block = aes128_decrypt_block(&block, &rk1); // AES decrypt the whitened block
        for i in 0..16 {
            block[i] ^= t[i];
        } // post-whitening: XOR decrypted result with the same T to recover plaintext

        data[block_start..block_start + 16].copy_from_slice(&block);
        xts_mult_tweak(&mut t); // advance T by multiplying by x in GF(2^128) for the next 16-byte block
    }
}

// The inverse S-box is the exact inverse lookup table of SBOX.
// Applying INV_SBOX after SBOX (or vice versa) returns the original byte, since the S-box is a bijection.
// It is precomputed as a flat table because computing the GF(2^8) inverse + inverse affine transform
// on the fly during decryption would be significantly slower than a single table lookup.
// https://en.wikipedia.org/wiki/Rijndael_S-box#Inverse_S-box
const INV_SBOX: [u8; 256] = [
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
];

// InvSubBytes: undo SubBytes by applying the inverse S-box to each byte of the state.
fn inv_sub_bytes(s: &mut Block) {
    for b in s.iter_mut() {
        *b = INV_SBOX[*b as usize];
    }
}

// InvShiftRows: undo ShiftRows by cyclically right-shifting each row by its row index.
// Row 0: no shift. Row 1: right-rotate by 1. Row 2: right-rotate by 2. Row 3: right-rotate by 3.
// Right-rotation by n is the inverse of left-rotation by n for a 4-element row.
// https://en.wikipedia.org/wiki/Advanced_Encryption_Standard#The_ShiftRows_step
fn inv_shift_rows(s: &mut Block) {
    // Row 1 (indices 1, 5, 9, 13): right-rotate by 1 (reverse of left-rotate by 1)
    let t = s[13];
    s[13] = s[9];
    s[9] = s[5];
    s[5] = s[1];
    s[1] = t;
    // Row 2 (indices 2, 6, 10, 14): right-rotate by 2 - same as left-rotate by 2, so two swaps still work
    s.swap(2, 10);
    s.swap(6, 14);
    // Row 3 (indices 3, 7, 11, 15): right-rotate by 3 (= left-rotate by 1 in reverse)
    let t = s[3];
    s[3] = s[7];
    s[7] = s[11];
    s[11] = s[15];
    s[15] = t;
}

// InvMixColumns: the inverse of MixColumns, using the inverse MDS matrix over GF(2^8).
// The inverse polynomial is a(x)^-1 mod x^4+1 = {0B}x^3 + {0D}x^2 + {09}x + {0E}.
// These coefficients are defined such that multiplying by both matrices in sequence gives the identity.
// https://en.wikipedia.org/wiki/Rijndael_MixColumns#InvMixColumns
fn inv_mix_columns(s: &mut Block) {
    for i in 0..4 {
        let b = i * 4;
        let (s0, s1, s2, s3) = (s[b], s[b + 1], s[b + 2], s[b + 3]);
        // Inverse MDS matrix rows are cyclic permutations of [0x0E, 0x0B, 0x0D, 0x09].
        // Verify correctness: for any column v, InvMixColumns(MixColumns(v)) must equal v.
        s[b] = gmul(0x0E, s0) ^ gmul(0x0B, s1) ^ gmul(0x0D, s2) ^ gmul(0x09, s3);
        s[b + 1] = gmul(0x09, s0) ^ gmul(0x0E, s1) ^ gmul(0x0B, s2) ^ gmul(0x0D, s3);
        s[b + 2] = gmul(0x0D, s0) ^ gmul(0x09, s1) ^ gmul(0x0E, s2) ^ gmul(0x0B, s3);
        s[b + 3] = gmul(0x0B, s0) ^ gmul(0x0D, s1) ^ gmul(0x09, s2) ^ gmul(0x0E, s3);
    }
}

// Decrypt a single 16-byte block with AES-128 using the inverse (decryption) cipher.
// The decryption round order applies inverse operations in reverse: InvShiftRows, InvSubBytes,
// AddRoundKey, InvMixColumns. The final (first applied, since we go in reverse) round omits InvMixColumns,
// mirroring how encryption's final round omits MixColumns.
// Note: InvShiftRows and InvSubBytes commute with each other, so their relative order doesn't matter.
// https://en.wikipedia.org/wiki/Advanced_Encryption_Standard#Description_of_the_cipher
fn aes128_decrypt_block(block: &Block, round_keys: &[u8; 176]) -> Block {
    let mut s = *block;
    add_round_key(&mut s, &round_keys[160..]); // undo the final AddRoundKey from encryption (round key 10)
    for round in (1..10).rev() {
        inv_shift_rows(&mut s); // undo ShiftRows first (commutes with InvSubBytes, order is arbitrary)
        inv_sub_bytes(&mut s); // undo SubBytes: apply inverse S-box to each byte
        add_round_key(&mut s, &round_keys[round * 16..(round + 1) * 16]); // undo round key injection
        inv_mix_columns(&mut s); // undo MixColumns using the inverse MDS matrix coefficients
    }
    inv_shift_rows(&mut s); // undo ShiftRows from encryption's round 1
    inv_sub_bytes(&mut s); // undo SubBytes from encryption's round 1
    add_round_key(&mut s, &round_keys[..16]); // undo the initial key whitening (round key 0)
    s
}

/// Decrypt the first 0xC00 bytes of an NCA using AES-128-XTS.
///
/// `header_key` is the 32-byte combined key (`header_key` from `prod.keys`).
/// The first 16 bytes are used as the AES cipher key and the second 16 bytes
/// as the tweak key, matching Nintendo's convention.
///
/// Returns the 0xC00-byte plaintext header region.
///
/// For NCA3, sectors are numbered 0-5 contiguously.
/// For NCA2, the two NCA header sectors (0-1) are decrypted normally, but
/// each FsHeader sector is decrypted independently as sector 0.
///
/// The NCA version is detected automatically from the decrypted header.
pub fn decrypt_header(encrypted: &[u8], header_key: &[u8; 32]) -> [u8; 0xC00] {
    assert!(
        encrypted.len() >= 0xC00,
        "NCA header region must be at least 0xC00 bytes"
    );

    // Split the 32-byte header_key into two independent 16-byte AES keys per the XTS specification.
    // k1 is the data encryption key (used to decrypt the actual content of each sector).
    // k2 is the tweak encryption key (used only to encrypt the sector number into the XTS tweak value).
    // They must be independent - reusing the same key for both halves would weaken XTS's security guarantees.
    let k1: [u8; 16] = header_key[..16].try_into().unwrap();
    let k2: [u8; 16] = header_key[16..].try_into().unwrap();

    let mut out = [0u8; 0xC00];

    // Decrypt the first two sectors (sectors 0 and 1), which hold the main NCA header structure.
    // Both NCA2 and NCA3 number these two sectors the same way, so no version check is needed yet.
    // The NCA header contains the magic, crypto type, key generation, and section table.
    for sector in 0..2usize {
        let off = sector * 0x200;
        let mut block: [u8; 0x200] = encrypted[off..off + 0x200].try_into().unwrap();
        xts_decrypt_sector(&mut block, &k1, &k2, sector as u64);
        out[off..off + 0x200].copy_from_slice(&block);
    }

    // Detect NCA version by reading the 4-byte magic from the decrypted output.
    // "NCA2" magic appears at offset 0x200 (the second 0x200-byte sector) in the decrypted header.
    // NCA3 (and later) will have "NCA3" there instead. The version determines how FsHeader sectors are numbered.
    let is_nca2 = &out[0x200..0x204] == b"NCA2";

    // Decrypt the four FsHeader blocks, located at offsets 0x400, 0x600, 0x800, 0xA00.
    // Each FsHeader describes one filesystem partition entry: crypto type, hash type, key generation, etc.
    // NCA3: FsHeaders use contiguous sector numbers 2, 3, 4, 5 (continuing from the NCA header sectors).
    // NCA2: each FsHeader is independently encrypted as sector 0, regardless of its position in the header.
    for fs in 0..4usize {
        let sector = if is_nca2 { 0 } else { (fs + 2) as u64 }; // NCA2 always decrypts each FsHeader with tweak for sector 0
        let off = 0x400 + fs * 0x200;
        let mut block: [u8; 0x200] = encrypted[off..off + 0x200].try_into().unwrap();
        xts_decrypt_sector(&mut block, &k1, &k2, sector);
        out[off..off + 0x200].copy_from_slice(&block);
    }

    out
}

/// Decrypt NCA section data in-place using AES-128-CTR.
///
/// CTR mode converts a block cipher into a stream cipher by encrypting a counter
/// value and XORing the resulting keystream with the plaintext/ciphertext.
/// This means no padding is required and any byte offset can be decrypted directly
/// without processing all prior bytes - critical for random-access NCA section reads.
/// The counter must never repeat for a given key; the SecureValue field in the FsHeader
/// makes it unique per section, and the offset component makes it unique per block within a section.
///
/// <https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Counter_(CTR)>
///
/// * `data` - The section data to decrypt (modified in-place).
/// * `key` - 16-byte section key (decrypted from the NCA key area using the KAEK).
/// * `counter` - 16-byte initial counter value, built from the `FsHeader` fields:
///     - bytes `[0..8]` = `SecureValue` (big-endian `u64`) - unique per section, prevents counter reuse across sections
///     - bytes `[8..16]` = offset within section / 0x10 (big-endian `u64`) - advances per 16-byte block
pub fn decrypt_section_ctr(data: &mut [u8], key: &[u8; 16], counter: &[u8; 16]) {
    let rk = key_expand(key);
    let mut ctr = *counter;
    let mut keystream = [0u8; 16]; // one AES-encrypted counter block = 16 bytes of keystream
    let mut ks_pos = 16; // index into keystream; initialized to 16 so the first byte triggers generation

    for byte in data.iter_mut() {
        if ks_pos == 16 {
            keystream = aes128_encrypt_block(&ctr, &rk); // encrypt the counter block to produce 16 fresh keystream bytes
            // Increment the counter as a 128-bit big-endian unsigned integer.
            // Big-endian increment matches Nintendo's CTR layout (high bytes at low addresses).
            // wrapping_add is used because counter overflow is expected and intentional.
            for i in (0..16).rev() {
                ctr[i] = ctr[i].wrapping_add(1);
                if ctr[i] != 0 {
                    break;
                } // no carry into the next byte, so stop propagating
            }
            ks_pos = 0;
        }
        *byte ^= keystream[ks_pos]; // XOR one byte of data with one byte of keystream (same op for encrypt and decrypt)
        ks_pos += 1;
    }
}

/// Decrypt a single 16-byte block with AES-128-ECB (used for NCA key area decryption).
///
/// ECB (Electronic Codebook) mode applies the block cipher directly with no IV, no chaining,
/// and no tweak. It is generally unsafe for encrypting multiple blocks of related data because
/// identical plaintext blocks always produce identical ciphertext blocks, leaking structure.
/// It is safe here because each 16-byte key in the NCA key area is an independent, randomly
/// distributed value - there is no structure for ECB to leak, and each key is decrypted once.
///
/// <https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Electronic_codebook_(ECB)>
pub fn decrypt_block_ecb(block: &[u8; 16], key: &[u8; 16]) -> [u8; 16] {
    let rk = key_expand(key);
    aes128_decrypt_block(block, &rk)
}
