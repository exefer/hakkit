# XCI (NX Card Image)

Physical game card dump format.

## Overall Layout
| Offset   | Size     | Description                           |
|----------|----------|---------------------------------------|
| 0x0      | 0x1000   | CardKeyArea (challenge-response auth) |
| 0x1000   | 0x200    | CardHeader                            |
| 0x1200   | 0x200    | [11.0.0+] CardHeaderT2                |
| 0x1400 	 | 0x400 	  | [11.0.0+] #CardHeaderT2CertArea       |
| 0x1800 	 | 0x100 	  | [11.0.0+] CardHeaderT2CertAreaModulus |
| 0x1900 	 | 0x6700 	| Reserved                              |
| 0x8000   | 0x8000   | CertArea (device certificate)         |
| 0x10000  | Variable | NormalArea → root HFS0                |

## CardHeader (starts at 0x1000)
| Offset | Size  | Description                                         |
|--------|-------|-----------------------------------------------------|
| 0x000  | 0x100 | RSA-2048 signature over [0x100..0x200]              |
| 0x100  | 0x4   | Magic `HEAD`                                        |
| 0x104  | 0x4   | RomAreaStartPageAddress (×0x200 bytes/page)         |
| 0x108  | 0x4   | BackupAreaStartPageAddress (0xFFFFFFFF)             |
| 0x10C  | 0x1   | TitleKeyDecIndex (high nibble) | KekIndex (low)     |
| 0x10D  | 0x1   | RomSize (0xFA=1GB, 0xF8=2GB, 0xF0=4GB, ...)         |
| 0x10E  | 0x1   | Version                                             |
| 0x10F  | 0x1   | Flags                                               |
| 0x110  | 0x8   | PackageId                                           |
| 0x118  | 0x4   | ValidDataEndAddress (page units)                    |
| 0x11C  | 0x4   | Reserved                                            |
| 0x120  | 0x10  | IV (reversed for AES-CBC)                           |
| 0x130  | 0x8   | PartitionFsHeaderAddress (absolute byte offset)     |
| 0x138  | 0x8   | PartitionFsHeaderSize                               |
| 0x140  | 0x20  | PartitionFsHeaderHash (SHA-256 of root HFS0 header) |
| 0x160  | 0x20  | InitialDataHash                                     |
| 0x180  | 0x4   | SelSec (1=T1, 2=T2)                                 |
| 0x184  | 0x4   | SelT1Key (always 2)                                 |
| 0x188  | 0x4   | SelKey (always 0)                                   |
| 0x18C  | 0x4   | LimArea (page units)                                |
| 0x190  | 0x70  | CardHeaderEncryptedData (AES-128-CBC encrypted)     |

## HFS0 Root
The root HFS0 begins at `PartitionFsHeaderAddress` (read from CardHeader at 0x130).
For standard XCI dumps this is always 0x10000.

## References
- switchbrew.org/wiki/XCI
- github.com/SciresM/hactool xci.h
- github.com/jakcron/nstool XciProcess.cpp
