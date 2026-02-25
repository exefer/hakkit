# hakkit

[![License: MIT OR Apache-2.0](https://img.shields.io/crates/l/hakkit.svg)](#license)
[![crates.io](https://img.shields.io/crates/v/hakkit.svg)](https://crates.io/crates/hakkit)
[![msrv](https://img.shields.io/crates/msrv/hakkit.svg?label=msrv&color=lightgray)](https://blog.rust-lang.org/2025/06/26/Rust-1.88.0/)

Reusable Nintendo binary format parsing library.

```toml
[dependencies]
hakkit = "0.1"
```

## Overview

hakkit provides parsers for Nintendo binary formats used across Switch, Wii U,
and other Nintendo platforms. The library is designed to be composable so that
individual format parsers can be used independently or together in larger tools.

## Usage

See the [examples](examples/) folder.

## Supported Formats

Refer to the [`formats`](https://docs.rs/hakkit/latest/hakkit/formats/) module documentation for the full list of supported Nintendo binary formats.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT) at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this crate by you, as defined in the Apache-2.0 license,
shall be dual licensed as above, without any additional terms or conditions.
