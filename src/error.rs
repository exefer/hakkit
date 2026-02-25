//! Library-wide error and result types.

use std::fmt;
use std::io;

/// Result alias used throughout hakkit.
pub type Result<T> = std::result::Result<T, Error>;

/// All errors the library can produce.
///
/// Error messages are kept intentionally terse; callers that need richer
/// context should wrap `Error` in their own type.
#[derive(Debug)]
pub enum Error {
    /// A magic/signature field did not match the expected value.
    BadMagic,
    /// A format version is present in the data but not supported by this
    /// parser.
    UnsupportedVersion(u8),
    /// The stream ended before all expected bytes could be read.
    UnexpectedEof,
    /// A null-terminated string had no null terminator within the buffer.
    UnterminatedName,
    /// An offset or size field would read outside the valid region.
    InvalidRange,
    /// A structural constraint was violated (message describes which one).
    Parse(&'static str),
    /// An underlying I/O operation failed.
    Io(io::Error),
    /// LZ4 decompression failed.
    #[cfg(feature = "compression")]
    Lz4,
    /// Zstandard decompression failed.
    #[cfg(feature = "compression")]
    Zstd,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::BadMagic => write!(f, "bad magic value"),
            Error::UnsupportedVersion(v) => write!(f, "unsupported version: {v}"),
            Error::UnexpectedEof => write!(f, "unexpected end of file"),
            Error::UnterminatedName => write!(f, "unterminated string"),
            Error::InvalidRange => write!(f, "invalid offset or size"),
            Error::Parse(s) => write!(f, "parse error: {s}"),
            Error::Io(e) => write!(f, "I/O error: {e}"),
            #[cfg(feature = "compression")]
            Error::Lz4 => write!(f, "lz4 decompression failed"),
            #[cfg(feature = "compression")]
            Error::Zstd => write!(f, "zstd decompression failed"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if let Error::Io(e) = self {
            Some(e)
        } else {
            None
        }
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(e)
    }
}
