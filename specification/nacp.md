# NACP (Nintendo Application Control Property)

Game metadata file. Found as `/control.nacp` in the RomFS of a Control NCA.
The file is always exactly **0x4000 bytes** and requires no magic or version
field - the format is identified by its location inside the NCA.

## File Layout

| Offset   | Size    | Description                                  |
|----------|---------|----------------------------------------------|
| 0x0000   | 0x3000  | TitleEntries - 16 × 0x300 bytes              |
| 0x3000   | 0x25    | Isbn (null-padded)                           |
| 0x3025   | 0x1     | StartupUserAccount (u8)                      |
| 0x3026   | 0xE     | Reserved                                     |
| 0x3034   | 0x4     | AttributeFlag (u32 LE) - bit 0 = Demo        |
| 0x3038   | 0x4     | SupportedLanguageFlag (u32 LE)               |
| 0x303C   | 0x4     | ParentalControlFlag (u32 LE)                 |
| 0x3040   | 0x1     | Screenshot (u8)                              |
| 0x3041   | 0x1     | VideoCapture (u8)                            |
| 0x3042   | 0x2     | Reserved                                     |
| 0x3044   | 0x8     | PresenceGroupId (u64 LE)                     |
| 0x304C   | 0x10    | RatingAge (16 bytes, one per rating org)     |
| 0x305C   | 0x10    | DisplayVersion (null-padded ASCII)           |
| 0x306C   | 0x8     | AddOnContentBaseId (u64 LE)                  |
| 0x3074   | 0x8     | SaveDataOwnerId (u64 LE)                     |
| 0x307C   | 0x8     | UserAccountSaveDataSize (u64 LE)             |
| 0x3084   | 0x8     | UserAccountSaveDataJournalSize (u64 LE)      |
| 0x308C   | 0x8     | DeviceSaveDataSize (u64 LE)                  |
| 0x3094   | 0x8     | DeviceSaveDataJournalSize (u64 LE)           |
| 0x309C   | 0x8     | BcatDeliveryCacheStorageSize (u64 LE)        |
| 0x30A4   | 0x8     | ApplicationErrorCodeCategory                 |
| 0x30AC   | 0x40    | LocalCommunicationId (8 × u64 LE)            |
| 0x30EC   | 0x1     | LogoType (u8)                                |
| 0x30ED   | 0x1     | LogoHandling (u8)                            |
| 0x30EE   | 0x1     | RuntimeAddOnContentInstall (u8)              |
| 0x30EF   | 0x5     | Reserved                                     |
| 0x30F4   | 0x4     | SeedForPseudoDeviceId (u32 LE)               |
| 0x30F8   | 0x41    | BcatPassphrase (null-padded)                 |
| 0x3139   | 0xC7    | Reserved                                     |
| 0x3200   | 0x40    | PlayLogQueryableApplicationId (8 × u64 LE)   |
| 0x3240   | 0x1     | PlayLogQueryCapability (u8)                  |
| 0x3241   | 0x1     | RepairFlag (u8)                              |
| 0x3242   | 0x1     | ProgramIndex (u8)                            |
| 0x3243   | 0x1     | RequiredNetworkServiceLicenseOnLaunchFlag (u8)|
| 0x3244   | 0xDBC   | Reserved (to end of file)                    |

## Title Entry (0x300 bytes each, 16 total)

| Offset | Size   | Description                          |
|--------|--------|--------------------------------------|
| 0x000  | 0x200  | Name (null-padded UTF-8)             |
| 0x200  | 0x100  | DeveloperName (null-padded UTF-8)    |

## Language Index

| Index | Language               |
|-------|------------------------|
| 0     | AmericanEnglish        |
| 1     | BritishEnglish         |
| 2     | Japanese               |
| 3     | French                 |
| 4     | German                 |
| 5     | LatinAmericanSpanish   |
| 6     | Spanish                |
| 7     | Italian                |
| 8     | Dutch                  |
| 9     | CanadianFrench         |
| 10    | Portuguese             |
| 11    | Russian                |
| 12    | Korean                 |
| 13    | TraditionalChinese     |
| 14    | SimplifiedChinese      |
| 15    | BrazilianPortuguese    |

## Field Details

### AttributeFlag (0x3034)

| Bit | Meaning        |
|-----|----------------|
| 0   | IsDemo         |
| 1   | IsRetailInteractiveDisplay |

### SupportedLanguageFlag (0x3038)

Bitmask where bit N corresponds to language index N above. A set bit means
the application has localised content for that language. Note that an entry
in the title table may still be zero-filled even if the bit is set - parsers
should check both.

### Screenshot (0x3040)

| Value | Meaning |
|-------|---------|
| 0     | Allow   |
| 1     | Deny    |

### VideoCapture (0x3041)

| Value | Meaning   |
|-------|-----------|
| 0     | Disabled  |
| 1     | Enabled   |
| 2     | Automatic |

### LogoType (0x30EC)

| Value | Meaning                |
|-------|------------------------|
| 0     | LicensedByNintendo     |
| 1     | DistributedByNintendo  |
| 2     | Nintendo               |

### LogoHandling (0x30ED)

| Value | Meaning |
|-------|---------|
| 0     | Auto    |
| 1     | Manual  |

## Notes

- All multi-byte integers are little-endian.
- String fields are null-padded (not null-terminated): the null byte(s)
  pad the field to its fixed size; there is no trailing length byte.
- NACP has no magic value and no version field. Its identity is established
  by its file path (`/control.nacp`) within the Control NCA RomFS.
- The file is exactly 0x4000 bytes. Parsers should return an error if the
  source is shorter.

## References

- switchbrew.org/wiki/NACP
- github.com/nicoboss/nsz (control.nacp field list)
- github.com/DarkMatterCore/nxdumptool (nacp.h)
