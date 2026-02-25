# SARC (SEAD ARChive)

General-purpose archive used pervasively in Nintendo Switch games (and Wii U/3DS).
Often compressed with Zstd (`.zs` suffix) or Yaz0 (`.szs`).

## Endianness
Determined by BOM field: `0xFEFF` = Big Endian, `0xFFFE` = Little Endian.

## Header (0x14 bytes)
| Offset | Size | Description                          |
|--------|------|--------------------------------------|
| 0x00   | 0x4  | Magic `SARC`                         |
| 0x04   | 0x2  | Header size (must be 0x14)           |
| 0x06   | 0x2  | BOM (0xFEFF=BE, 0xFFFE=LE)           |
| 0x08   | 0x4  | Total file size                      |
| 0x0C   | 0x4  | Offset to data section               |
| 0x10   | 0x2  | Version (0x0100)                     |
| 0x12   | 0x2  | Padding                              |

## SFAT Section (starts immediately after SARC header)
| Offset | Size | Description                          |
|--------|------|--------------------------------------|
| 0x00   | 0x4  | Magic `SFAT`                         |
| 0x04   | 0x2  | Header size (must be 0x0C)           |
| 0x06   | 0x2  | FileCount (max 0x3FFF)               |
| 0x08   | 0x4  | HashMultiplier (always 0x65 = 101)   |

## SFAT FAT Entry (0x10 bytes each)
| Offset | Size | Description                                        |
|--------|------|----------------------------------------------------|
| 0x00   | 0x4  | Filename hash                                      |
| 0x04   | 0x4  | Filename attributes (0=no name; else 0xAABBBBBB)   |
| 0x08   | 0x4  | Start offset into data section                     |
| 0x0C   | 0x4  | End offset into data section                       |

Entries are sorted by filename hash (binary search used at runtime).
`BBBBBB` in attributes = byte offset into name table ÷ 4.

### Filename Hash Algorithm
```rust
fn hash(name: &[u8], multiplier: u32) -> u32 {
    let mut h: u32 = 0;
    for &b in name {
        h = h.wrapping_mul(multiplier).wrapping_add(b as i8 as u32);
    }
    h
}
```
Note: each byte is sign-extended (cast to i8 first) on Switch targets.

## SFNT Section
| Offset | Size | Description                               |
|--------|------|-------------------------------------------|
| 0x00   | 0x4  | Magic `SFNT`                              |
| 0x04   | 0x2  | Header size (must be 8)                   |
| 0x06   | 0x2  | Padding                                   |
| 0x08   | ...  | Null-terminated filenames, 4-byte aligned |

## Data Section
Starts at offset specified in SARC header. Files may have alignment padding between them
(alignment requirements vary by file type; textures often require 0x1000).

## References
- nintendo-formats.com/libs/sead/sarc.html
- zeldamods.org/wiki/SARC
- github.com/zeldamods/sarc
