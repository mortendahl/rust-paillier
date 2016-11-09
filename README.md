# Paillier

Efficient pure-Rust library for the [Paillier](https://en.wikipedia.org/wiki/Paillier_cryptosystem) partially homomorphic encryption scheme, offering both plain and packed variants.

**Important**: while we have followed recommendations regarding the scheme itself, so far no particular efforts have been made to harden the library against non-cryptographic attacks, including side-channel attacks.

The implementation exposes the usual operations through the `PartiallyHomomorphicScheme` interface:
```rust
pub trait PartiallyHomomorphicScheme {
    type Plaintext;
    type Ciphertext;
    type EncryptionKey;
    type DecryptionKey;
    fn encrypt(&Self::EncryptionKey, &Self::Plaintext) -> Self::Ciphertext;
    fn decrypt(&Self::DecryptionKey, &Self::Ciphertext) -> Self::Plaintext;
    fn rerandomise(&Self::EncryptionKey, &Self::Ciphertext) -> Self::Ciphertext;
    fn add(&Self::EncryptionKey, &Self::Ciphertext, &Self::Ciphertext) -> Self::Ciphertext;
    fn mult(&Self::EncryptionKey, &Self::Ciphertext, &Self::Plaintext) -> Self::Ciphertext;
}
```
along with implementations `PlainPaillier` and `PackedPaillier`.



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
paillier = { git="ssh://git@github.com/snipsco/rust-paillier.git" }
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
```
cargo build --features "inclramp"
```
for [`num`](https://github.com/rust-num/num)-only compilation use
```
cargo build --no-default-features --features "inclnum"
```
and finally, use
```
cargo build --features "inclramp inclnum"
```
to have both available (useful for e.g. performance tests).


# Performance
These numbers were obtained by running
```
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
 
