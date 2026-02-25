# NCA (Nintendo Content Archive)

Primary encrypted content container. Multiple NCAs are packaged inside NSP/XCI.

## Encryption
| Offset       | Size        | Description                                                        |
|--------------|------------|---------------------------------------------------------------------|
| 0x000–0x3FF  | 0x400      | NCA header (encrypted, AES-128-XTS)                                 |
| 0x400–0x5FF  | 0x200      | FsHeader for section 0 (encrypted)                                  |
| 0x600–0x7FF  | 0x200      | FsHeader for section 1 (encrypted)                                  |
| 0x800–0x9FF  | 0x200      | FsHeader for section 2 (encrypted)                                  |
| 0xA00–0xBFF  | 0x200      | FsHeader for section 3 (encrypted)                                  |

**Encryption details:**
- Algorithm: AES-128-XTS  
- Sector size: 0x200  
- Encrypted region size: 0xC00 bytes  
- Tweak: byte-reversed sector index (non-standard)  

**Pre-1.0.0 (NCA2):**
Each section header is independently encrypted as sector 0.

## NCA Header (plaintext after decryption, starts at 0x200)
| Offset | Size  | Description                                                                |
|--------|-------|----------------------------------------------------------------------------|
| 0x000  | 0x100 | RSA-2048 sig over [0x200..0x400] using fixed key                           |
| 0x100  | 0x100 | RSA-2048 sig over [0x200..0x400] using NPDM key                            |
| 0x200  | 0x4   | Magic (`NCA3`, `NCA2`, `NCA1`, `NCA0`)                                     |
| 0x204  | 0x1   | DistributionType (0=Download, 1=GameCard)                                  |
| 0x205  | 0x1   | ContentType (0=Program, 1=Meta, 2=Control, 3=Manual, 4=Data, 5=PublicData) |
| 0x206  | 0x1   | KeyGenerationOld (0=1.0.0, 2=3.0.0)                                        |
| 0x207  | 0x1   | KeyAreaEncryptionKeyIndex (0=App, 1=Ocean, 2=System)                       |
| 0x208  | 0x8   | ContentSize                                                                |
| 0x210  | 0x8   | ProgramId                                                                  |
| 0x218  | 0x4   | ContentIndex                                                               |
| 0x21C  | 0x4   | SdkAddonVersion                                                            |
| 0x220  | 0x1   | KeyGeneration (see wiki for version map)                                   |
| 0x221  | 0x1   | [9.0.0+] SignatureKeyGeneration                                            |
| 0x222  | 0xE   | Reserved                                                                   |
| 0x230  | 0x10  | RightsId                                                                   |
| 0x240  | 0x10×4 | FsEntry array (4 entries)                                                 |
| 0x280  | 0x20×4 | SHA-256 hashes of each FsHeader                                           |
| 0x300  | 0x10×4 | EncryptedKeyArea                                                          |

## FsEntry (0x10 bytes each)
| Offset | Size | Description                              |
|--------|------|------------------------------------------|
| 0x0    | 0x4  | StartOffset in 0x200-byte blocks         |
| 0x4    | 0x4  | EndOffset in 0x200-byte blocks           |
| 0x8    | 0x8  | Reserved                                 |

## FsHeader (each at absolute 0x400 + sectionId×0x200)
| Offset | Size  | Description                              |
|--------|-------|------------------------------------------|
| 0x00   | 0x2   | Version (always 2)                       |
| 0x02   | 0x1   | FsType (0=RomFS, 1=PartitionFS)          |
| 0x03   | 0x1   | HashType                                 |
| 0x04   | 0x1   | EncryptionType                           |
| 0x05   | 0x1   | [14.0.0+] MetaDataHashType               |
| 0x06   | 0x2   | Reserved                                 |
| 0x08   | 0xF8  | HashData                                 |
| 0x100  | 0x40  | PatchInfo                                |
| 0x140  | 0x4   | Generation                               |
| 0x144  | 0x4   | SecureValue                              |
| 0x148  | 0x30  | SparseInfo                               |
| 0x178  | 0x28  | [12.0.0+] CompressionInfo                |
| 0x1A0  | 0x30  | [14.0.0+] MetaDataHashDataInfo           |

## References
- switchbrew.org/wiki/NCA
- github.com/SciresM/hactool nca.h, nca.c
- github.com/jakcron/nstool NcaProcess.cpp
