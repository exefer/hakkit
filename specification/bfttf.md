# BFTTF / BFOTF (Binary caFe TrueType/OpenType Font)

A standard TTF or OTF font file wrapped in simple XOR encryption. Used as system fonts
on Nintendo Switch (and Wii U). The `.bfttf` extension = TrueType; `.bfotf` = OpenType.

## Structure

There is **no dedicated file header** beyond the encryption wrapper. The encrypted file
is simply an XOR-obfuscated TTF/OTF. After decryption, the result is a standard font
file starting with the TTF magic `\x00\x01\x00\x00\x00` or OTF magic `OTTO`.

## Encryption

Each byte at position `i` is XORed with a platform-specific key byte:
```rust
decrypted[i] = encrypted[i] ^ key[i % key.len()]
```

### Platform Keys

| Platform | Key (hex) |
|----------|-----------|
| Wii U    | `0x2A, 0xCE, 0xF5, 0x16, 0x10, 0x0D, 0xC4, 0xC3, 0x28, 0x78, 0x27, 0x42, 0xA5, 0x5B, 0xF4, 0xAB` |
| Switch   | `0x15, 0x9A, 0x7D, 0x6F, 0x16, 0x6F, 0xD0, 0x0C, 0x67, 0xE7, 0x39, 0x98, 0x0B, 0xEB, 0xF6, 0x62` |
| Windows  | `0x97, 0x3B, 0x5C, 0x6C, 0x26, 0xF3, 0xFA, 0xB5, 0xA2, 0xD5, 0x8E, 0xB5, 0x5A, 0x4D, 0xD5, 0x51` |

The Switch key is 16 bytes; the XOR cycles over them for the entire file.

## Usage in hakkit

`bfttf::decrypt(data: &[u8]) -> Vec<u8>` - returns raw TTF/OTF bytes.
`bfttf::encrypt(data: &[u8]) -> Vec<u8>` - wraps a TTF/OTF for use on Switch.

The `size` field in the existing stub is incorrect (there is no such field in the format).
The parser should be replaced with encrypt/decrypt free functions.

## References
- github.com/hadashisora/NintyFont formats/BFTTF.cpp
- gbatemp.net/threads/customising-a-system-font.527910
- BFTTFutil source code (widely available)
