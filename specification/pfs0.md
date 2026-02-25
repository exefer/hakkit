# PFS0 (PartitionFS)

Flat archive container. Used in NSP files and NCA ExeFS/Logo sections.

## Layout
| Offset                                  | Size              | Description               |
|-----------------------------------------|-------------------|---------------------------|
| 0x00                                    | 0x4               | Magic `PFS0`              |
| 0x04                                    | 0x4               | FileCount (u32 LE)        |
| 0x08                                    | 0x4               | StringTableSize (u32 LE)  |
| 0x0C                                    | 0x4               | Reserved (always 0)       |
| 0x10                                    | FileCount × 0x18  | EntryTable                |
| 0x10 + FileCount×0x18                   | StringTableSize   | StringTable               |
| 0x10 + FileCount×0x18 + StringTableSize | Remaining         | FileData                  |

## File Entry (0x18 bytes)
| Offset | Size | Description                             |
|--------|------|-----------------------------------------|
| 0x00   | 0x8  | File offset, relative to data section   |
| 0x08   | 0x8  | File size in bytes                      |
| 0x10   | 0x4  | Byte offset into string table           |
| 0x14   | 0x4  | Reserved                                |

## Notes
- No directory support, no hashing (contrast: HFS0 has SHA-256 per entry).
- Data section start = `0x10 + FileCount×0x18 + StringTableSize`.

## References
- switchbrew.org/wiki/NCA (PFS0 sub-section)
- github.com/SciresM/hactool pfs.c
