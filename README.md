# hakkit &emsp; [![Latest Version]][crates.io] [![docs.rs]][docs] [![hakkit msrv]][Rust 1.88]

[Latest Version]: https://img.shields.io/crates/v/hakkit.svg
[crates.io]: https://crates.io/crates/hakkit
[docs.rs]: https://img.shields.io/badge/docs.rs-hakkit-66c2a5
[docs]: https://docs.rs/hakkit
[hakkit msrv]: https://img.shields.io/crates/msrv/hakkit.svg?label=hakkit%20msrv&color=lightgray
[Rust 1.88]: https://blog.rust-lang.org/2025/06/26/Rust-1.88.0/

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

<br>

#### License

<sup>
Licensed under either of <a href="LICENSE-APACHE">Apache License, Version
2.0</a> or <a href="LICENSE-MIT">MIT license</a> at your option.
</sup>

<br>

<sub>
Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this crate by you, as defined in the Apache-2.0 license, shall
be dual licensed as above, without any additional terms or conditions.
</sub>
