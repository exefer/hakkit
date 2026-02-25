# NPDM (Nintendo Program Descriptor Meta)

Metadata file describing security/access control for a program NCA. Found as
`main.npdm` in the ExeFS partition of a Program NCA.

## File Layout
| Offset | Size  | Description                              |
|--------|-------|------------------------------------------|
| 0x00   | 0x4   | Magic `META`                             |
| 0x04   | 0x4   | Unknown / signature key generation       |
| 0x08   | 0x4   | Reserved                                 |
| 0x0C   | 0x1   | MMUFlags (0x1 = 64-bit)                  |
| 0x0D   | 0x1   | Reserved                                 |
| 0x0E   | 0x1   | MainThreadPriority                       |
| 0x0F   | 0x1   | MainThreadCoreNumber                     |
| 0x10   | 0x4   | Reserved                                 |
| 0x14   | 0x4   | SystemResourceSize                       |
| 0x18   | 0x4   | Version                                  |
| 0x1C   | 0x4   | MainThreadStackSize                      |
| 0x20   | 0x10  | TitleName (null-padded UTF-8)            |
| 0x30   | 0x10  | ProductCode (null-padded)                |
| 0x40   | 0x30  | Reserved                                 |
| 0x70   | 0x4   | AciOffset (relative to start of file)    |
| 0x74   | 0x4   | AciSize                                  |
| 0x78   | 0x4   | AcidOffset                               |
| 0x7C   | 0x4   | AcidSize                                 |

## ACI0 (Access Control Info)
Embedded at AciOffset. Describes the specific title's permissions.

| Offset | Size  | Description                    |
|--------|-------|--------------------------------|
| 0x00   | 0x4   | Magic `ACI0`                   |
| 0x04   | 0xC   | Reserved                       |
| 0x10   | 0x8   | ProgramId                      |
| 0x18   | 0x8   | Reserved                       |
| 0x20   | 0x4   | FsAccessControlOffset          |
| 0x24   | 0x4   | FsAccessControlSize            |
| 0x28   | 0x4   | ServiceAccessControlOffset     |
| 0x2C   | 0x4   | ServiceAccessControlSize       |
| 0x30   | 0x4   | KernelAccessControlOffset      |
| 0x34   | 0x4   | KernelAccessControlSize        |
| 0x38   | 0x8   | Reserved                       |

## ACID (Access Control Info Descriptor)
Embedded at AcidOffset. Signed descriptor used to validate ACI0.

| Offset | Size  | Description                                                |
|--------|-------|------------------------------------------------------------|
| 0x00   | 0x100 | RSA-2048 signature                                         |
| 0x100  | 0x100 | RSA-2048 public key (modulus)                              |
| 0x200  | 0x4   | Magic `ACID`                                               |
| 0x204  | 0x4   | Size (from 0x200 to end of ACID)                           |
| 0x208  | 0x4   | Flags                                                      |
| 0x20C  | 0x4   | Reserved                                                   |
| 0x210  | 0x8   | ProgramIdMin                                               |
| 0x218  | 0x8   | ProgramIdMax                                               |
| ...    | ...   | FsAccessControl, ServiceAccessControl, KernelAccessControl |

## References
- switchbrew.org/wiki/NPDM
- github.com/SciresM/hactool npdm.h
- github.com/jakcron/nstool MetaProcess.cpp
