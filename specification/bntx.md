# BNTX (Binary NX Texture)

Texture container format used on Nintendo Switch. Contains one or more GPU textures
with a relocation table for pointer fixup.

## File Layout
| Offset | Size  | Description                              |
|--------|-------|------------------------------------------|
| 0x00   | 0x4   | Magic `BNTX`                             |
| 0x04   | 0x4   | DataLength (0, unused)                   |
| 0x08   | 0x8   | Padding / version info                   |
| 0x10   | 0x2   | ByteOrderMark (0xFEFF=BE, 0xFFFE=LE)     |
| 0x12   | 0x2   | FormatRevision (0x0400)                  |
| 0x14   | 0x4   | NameOffset (rel-ptr to null-term string) |
| 0x18   | 0x2   | StringPoolOffset (relative)              |
| 0x1A   | 0x2   | RelocTableOffset (relative from file)    |
| 0x1C   | 0x4   | FileSize                                 |
| 0x20   | ...   | NX section (`NX  `)                      |

## NX Section (at 0x20)
| Offset | Size | Description                                    |
|--------|------|------------------------------------------------|
| 0x00   | 0x4  | Magic `NX  ` (with two trailing spaces)        |
| 0x04   | 0x4  | TextureCount                                   |
| 0x08   | 0x8  | InfoPtrsOffset (ptr to array of BRTI offsets)  |
| 0x10   | 0x8  | DataBlkOffset                                  |
| 0x18   | 0x8  | DictOffset (ptr to texture name dict)          |
| 0x20   | 0x4  | StrDictOffset                                  |

## BRTI (Texture Info, per texture)
| Offset | Size | Description                             |
|--------|------|-----------------------------------------|
| 0x00   | 0x4  | Magic `BRTI`                            |
| 0x04   | 0x4  | Length (always 0x90)                    |
| 0x08   | 0x8  | DataLength                              |
| 0x10   | 0x1  | Flags                                   |
| 0x11   | 0x1  | Dimensions (1=1D, 2=2D, 3=3D, 6=CubeMap)          |
| 0x12   | 0x2  | TileMode                                |
| 0x14   | 0x2  | SwizzleValue                            |
| 0x16   | 0x2  | MipmapCount                             |
| 0x18   | 0x2  | MultiSampleCount                        |
| 0x1A   | 0x2  | Reserved                                |
| 0x1C   | 0x4  | Format (see format table)               |
| 0x20   | 0x4  | AccessFlags                             |
| 0x24   | 0x4  | Width                                   |
| 0x28   | 0x4  | Height                                  |
| 0x2C   | 0x4  | Depth                                   |
| 0x30   | 0x4  | ArrayCount                              |
| 0x34   | 0x4  | BlockHeightLog2                         |
| 0x38   | 0x14 | Reserved                                |
| 0x4C   | 0x4  | DataOffset (relative)                   |
| 0x50   | 0x8  | NameOffset (ptr to texture name)        |
| 0x58   | 0x8  | ParentOffset (ptr to NX section)        |
| 0x60   | 0x8  | PtrsOffset (ptr to mipmap data ptrs)    |

## Parsing Requirements
- Relocation table must be processed before resolving any internal pointers
- TextureCount is in the NX section, not in the main header

## References
- github.com/KillzXGaming/Switch-Toolbox (BNTX.cs)
