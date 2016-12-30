# Paillier

[![License: MIT/Apache2](https://img.shields.io/badge/license-MIT%2fApache2-blue.svg)](https://img.shields.io/badge/license-MIT%2fApache2-blue.svg)

Efficient pure-Rust library for the [Paillier](https://en.wikipedia.org/wiki/Paillier_cryptosystem) partially homomorphic encryption scheme, offering both plain and packed variants.
Supports several underlying arbitrary precision libraries, including [RAMP](https://github.com/Aatch/ramp) (default), [GMP](https://github.com/fizyk20/rust-gmp), and [num](https://github.com/rust-num/num).

**Important**: while we have followed recommendations regarding the scheme itself, this library should currently be seen as an experimental implementation. In particular, no particular efforts have so far been made to harden it against non-cryptographic attacks, including side-channel attacks.

The library exposes the scheme operations through two traits and implementations, for respectively a single large value (`plain::Scheme`) and for a vector of smaller values (`packed::Scheme`):
```rust
pub trait AbstractScheme {

    fn encrypt(
      ek: &EncryptionKey<Self::BigInteger>,
       m: &Plaintext<Self::BigInteger>)
       -> Ciphertext<Self::BigInteger>;

    fn decrypt(
      dk: &DecryptionKey<Self::BigInteger>,
       c: &Ciphertext<Self::BigInteger>)
       -> Plaintext<Self::BigInteger>;

    fn add(
      ek: &EncryptionKey<Self::BigInteger>,
      c1: &Ciphertext<Self::BigInteger>,
      c2: &Ciphertext<Self::BigInteger>)
       -> Ciphertext<Self::BigInteger>;

    fn mult(
      ek: &EncryptionKey<Self::BigInteger>,
      c1: &Ciphertext<Self::BigInteger>,
      m2: &Plaintext<Self::BigInteger>)
       -> Ciphertext<Self::BigInteger>;

    fn rerandomise(
      ek: &EncryptionKey<Self::BigInteger>,
       c: &Ciphertext<Self::BigInteger>)
       -> Ciphertext<Self::BigInteger>;

}
```


# Installation

Note that some functionality such as **key generation** is *not* included by default. See the [Building](#building) section for more details.

## GitHub
```bash
git clone https://github.com/snipsco/rust-paillier
cd rust-paillier
cargo build --release
```

## Cargo
```toml
[dependencies]
paillier = { git="https://github.com/snipsco/rust-paillier.git" }
```


## Building

### Key generation

Key generation is optional since it is not always needed yet adds several extra (heavy) dependencies. To include use
```
cargo build --features "keygen"
```

### Arithmetic

The library supports the use of different arithmetic libraries, currently defaulting to [`ramp`](https://github.com/Aatch/ramp) for efficiency.

For [`ramp`](https://github.com/Aatch/ramp)-only compilation use `cargo build` or
```sh
cargo build --features "inclramp"
```
for [`num`](https://github.com/rust-num/num)-only compilation use
```sh
cargo build --no-default-features --features "inclnum"
```
and finally, use
```sh
cargo build --features "inclramp inclnum"
```
to have both available (useful for e.g. performance tests).


# Performance
These numbers were obtained by running
```sh
cargo bench
```
using the nightly toolchain.

# License

Licensed under either of

 * Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall
be dual licensed as above, without any additional terms or conditions.
 
