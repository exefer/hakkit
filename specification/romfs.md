# RomFS (Read-Only Filesystem)

Nintendo's read-only game asset filesystem. Used as a section filesystem
inside NCAs (typically section 1 of a Program NCA and section 0 of a Control
NCA). The raw RomFS data is wrapped in an **IVFC** integrity verification
tree; the actual directory/file data lives in Level 3 of that tree.

The caller must decrypt the NCA section before parsing.

## IVFC Superblock

The IVFC header is embedded in the first 0xE0 bytes of `FsHeader.hash_data`
for sections whose `HashType` is `HierarchicalIntegrity` (value 3). It
describes three levels of hash data plus the Level 3 payload.

| Offset | Size | Description                                    |
|--------|------|------------------------------------------------|
| 0x00   | 0x4  | Magic `IVFC`                                   |
| 0x04   | 0x4  | Magic number `0x00010000` (u32 LE)             |
| 0x08   | 0x4  | MasterHashSize (u32 LE)                        |
| 0x0C   | 0x8  | Level1LogicalOffset (u64 LE)                   |
| 0x14   | 0x8  | Level1HashDataSize (u64 LE)                    |
| 0x1C   | 0x4  | Level1BlockSizeLog2 (u32 LE)                   |
| 0x20   | 0x4  | Reserved                                       |
| 0x24   | 0x8  | Level2LogicalOffset (u64 LE)                   |
| 0x2C   | 0x8  | Level2HashDataSize (u64 LE)                    |
| 0x34   | 0x4  | Level2BlockSizeLog2 (u32 LE)                   |
| 0x38   | 0x4  | Reserved                                       |
| 0x3C   | 0x8  | Level3LogicalOffset (u64 LE) ← data start      |
| 0x44   | 0x8  | Level3HashDataSize (u64 LE)                    |
| 0x4C   | 0x4  | Level3BlockSizeLog2 (u32 LE)                   |
| 0x50   | 0x4  | Reserved                                       |
| 0x54   | 0x4  | Reserved                                       |
| 0x58   | 0x4  | OptionalInfoSize (u32 LE)                      |

`Level3LogicalOffset` is relative to the start of the NCA section. Add the
absolute NCA section offset to obtain the stream position of the Level 3 header.

## Level 3 Layout

The Level 3 region starts at `section_base + ivfc.level3_offset`.

```
[Level3LogicalOffset + 0x00]  Level3Header  (0x28 bytes)
[Level3LogicalOffset + 0x28]  DirHashTable  (DirHashTableSize bytes)
[Level3LogicalOffset + DirMetaTableOffset]
                               DirMetaTable  (DirMetaTableSize bytes)
[Level3LogicalOffset + FileHashTableOffset]
                               FileHashTable (FileHashTableSize bytes)
[Level3LogicalOffset + FileMetaTableOffset]
                               FileMetaTable (FileMetaTableSize bytes)
[Level3LogicalOffset + FileDataOffset]
                               FileData      (remaining bytes)
```

## Level 3 Header (0x28 bytes)

| Offset | Size | Description                                         |
|--------|------|-----------------------------------------------------|
| 0x00   | 0x4  | HeaderLength (u32 LE, always 0x28)                  |
| 0x04   | 0x4  | DirHashTableOffset (u32 LE, rel. to Level 3 start)  |
| 0x08   | 0x4  | DirHashTableSize (u32 LE)                           |
| 0x0C   | 0x4  | DirMetaTableOffset (u32 LE, rel. to Level 3 start)  |
| 0x10   | 0x4  | DirMetaTableSize (u32 LE)                           |
| 0x14   | 0x4  | FileHashTableOffset (u32 LE, rel. to Level 3 start) |
| 0x18   | 0x4  | FileHashTableSize (u32 LE)                          |
| 0x1C   | 0x4  | FileMetaTableOffset (u32 LE, rel. to Level 3 start) |
| 0x20   | 0x4  | FileMetaTableSize (u32 LE)                          |
| 0x24   | 0x4  | FileDataOffset (u32 LE, rel. to Level 3 start)      |

## Directory Metadata Entry (variable length)

Entries are packed contiguously; each entry is padded to a 4-byte boundary
after its name field. The root directory is always at offset 0.

| Offset | Size        | Description                                         |
|--------|-------------|-----------------------------------------------------|
| 0x00   | 0x4         | ParentOffset (u32 LE) - self if root                |
| 0x04   | 0x4         | SiblingOffset (u32 LE) - 0xFFFFFFFF if none         |
| 0x08   | 0x4         | ChildDirOffset (u32 LE) - 0xFFFFFFFF if none        |
| 0x0C   | 0x4         | FirstFileOffset (u32 LE) - 0xFFFFFFFF if none       |
| 0x10   | 0x4         | HashSiblingOffset (u32 LE) - next in hash bucket    |
| 0x14   | 0x4         | NameLength (u32 LE)                                 |
| 0x18   | NameLength  | Name (UTF-8, **not** null-terminated)               |
| +pad   | 0–3         | Zero padding to next 4-byte boundary                |

All sibling/child/file offsets are byte offsets into the respective metadata
table (not indices). The sentinel `0xFFFFFFFF` means "no entry".

## File Metadata Entry (variable length)

| Offset | Size        | Description                                         |
|--------|-------------|-----------------------------------------------------|
| 0x00   | 0x4         | ParentDirOffset (u32 LE)                            |
| 0x04   | 0x4         | SiblingOffset (u32 LE) - 0xFFFFFFFF if none         |
| 0x08   | 0x8         | DataOffset (u64 LE) - relative to FileData section  |
| 0x10   | 0x8         | DataSize (u64 LE)                                   |
| 0x18   | 0x4         | HashSiblingOffset (u32 LE) - next in hash bucket    |
| 0x1C   | 0x4         | NameLength (u32 LE)                                 |
| 0x20   | NameLength  | Name (UTF-8, **not** null-terminated)               |
| +pad   | 0–3         | Zero padding to next 4-byte boundary                |

## Hash Tables

Both the directory and file hash tables are arrays of `u32 LE` values. Each
slot holds the metadata-table offset of the first entry in that hash bucket.
Collisions are chained via the `HashSiblingOffset` field in each metadata
entry. Bucket count is `table_size / 4`.

The hash function used at runtime is not required for parsing; the hash
tables can be skipped entirely when building the full directory tree.

## Tree Traversal

To reconstruct the filesystem tree from the metadata tables:

1. Root directory is at `DirMetaTable + 0`.
2. For each directory, follow `ChildDirOffset` to find its first child
   directory, then follow successive `SiblingOffset` values to enumerate
   all siblings.
3. For each directory, follow `FirstFileOffset` into the file metadata table
   to find its first file; follow `SiblingOffset` to enumerate remaining
   files.
4. Absolute file data position = `section_base + ivfc.level3_offset
   + level3_header.file_data_offset + file_entry.data_offset`.

## Notes

- All integers are little-endian.
- Names are UTF-8 and are **not** null-terminated; use `NameLength` to read
  exactly the right number of bytes.
- Name fields are padded to a 4-byte boundary *after* `NameLength` bytes;
  the fixed-size part of each entry is 0x18 bytes (dir) or 0x20 bytes
  (file), so the total entry size is `fixed + align4(name_length)`.
- The `ParentOffset` of the root directory points to itself (offset 0).

## References

- switchbrew.org/wiki/RomFS
- github.com/SciresM/hactool romfs.c, ivfc.c
- github.com/nicoboss/nsz (IVFC description)
- 3dbrew.org/wiki/RomFS (3DS predecessor; Level 3 layout is identical)
