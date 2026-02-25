# NCZ (Compressed NCA / NSZ)

An NSZ file is not a distinct binary format. It is a convention: an NSP (PFS0)
where individual NCA entries have been compressed using a Nintendo-specific scheme,
with the file renamed from `.nca` to `.ncz` inside the archive.

## Structure
An NSZ is parsed exactly like a PFS0. The difference is in how contained `.ncz`
files are handled.

## NCZ (Compressed NCA)
A `.ncz` file is an NCA whose sections have been compressed with Zstandard after
decryption, prefixed with a custom header that allows streaming decompression.

### File Layout
| Offset       | Size | Description                                        |
|--------------|------|----------------------------------------------------|
| 0x000        | 0x400| Standard NCA header (still AES-XTS encrypted)      |
| 0x400        | 0x8  | Magic `NCZSECTN`                                   |
| 0x408        | 0x8  | SectionCount (u64 LE)                              |
| 0x410        | N×0x38 | Section descriptors                              |
| (after descs)| ...  | Zstandard-compressed data blocks                   |

### Section Descriptor (0x38 bytes each)
| Offset | Size | Description                                          |
|--------|------|------------------------------------------------------|
| 0x00   | 0x8  | Offset within plaintext NCA (u64 LE)                 |
| 0x08   | 0x8  | Decompressed size (u64 LE)                           |
| 0x10   | 0x1  | CryptoType (matches NCA FsHeader EncryptionType)     |
| 0x11   | 0x7  | Reserved                                             |
| 0x18   | 0x10 | CryptoKey (AES-128 key for this section)             |
| 0x28   | 0x10 | CryptoCounter (AES-CTR initial counter)              |

### Compressed Blocks
After all section descriptors, the file contains a sequence of blocks:
```
[u32 LE: compressed_block_size] [compressed_block_size bytes of Zstd data]
```
Repeat until end of file. Each block decompresses independently.

## hakkit Approach
- Parse NSZ as a `Pfs0`
- For `.ncz` entries: seek past the 0x400-byte NCA header, parse `NczHeader`
- Decompress blocks with `compression::zstd::decompress_zstd`
- Reconstruct the full plaintext NCA buffer and parse with `Nca::parse`
- Compression/decompression stays in `compression::zstd`

## References
- github.com/nicoboss/nsz (NSZ spec and reference implementation)
- github.com/julesontheroad/NSC_BUILDER
