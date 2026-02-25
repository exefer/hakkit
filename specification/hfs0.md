# HFS0 (Hierarchical FileSystem 0 / SHA-256 FileSystem)

SHA-256-hashed archive. Used inside XCI game cards. Root HFS0 at 0x10000 in XCI.

## Layout
| Offset                          | Size              | Description               |
|----------------------------------|------------------|---------------------------|
| 0x00                             | 0x4              | Magic `HFS0`              |
| 0x04                             | 0x4              | FileCount (u32 LE)        |
| 0x08                             | 0x4              | StringTableSize (u32 LE)  |
| 0x0C                             | 0x4              | Reserved                  |
| 0x10                             | FileCount × 0x4  | EntryTable                |
| 0x10 + FileCount×0x40            | StringTableSize  | StringTable               |
| (after StringTable)              | Remaining        | FileData                  |

## File Entry (0x40 bytes)
| Offset | Size | Description                                  |
|--------|------|----------------------------------------------|
| 0x00   | 0x8  | File offset, relative to data section        |
| 0x08   | 0x8  | File size in bytes                           |
| 0x10   | 0x4  | Byte offset into string table                |
| 0x14   | 0x4  | HashedRegionSize (prefix bytes hashed)       |
| 0x18   | 0x4  | Reserved                                     |
| 0x1C   | 0x4  | Reserved                                     |
| 0x20   | 0x20 | SHA-256 hash of first HashedRegionSize bytes |

## XCI Root HFS0 Partitions
The root HFS0 at offset 0x10000 lists sub-partitions:
- `normal` - CNMT NCA + icon NCA (≥4.0.0: empty)
- `logo` - [4.0.0+] replaces normal partition content
- `update` - system update NCAs
- `secure` - all game NCAs (encrypted)

## References
- switchbrew.org/wiki/XCI
- github.com/SciresM/hactool hfs.c
