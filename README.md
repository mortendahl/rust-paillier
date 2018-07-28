# Paillier

[![Build Status](https://travis-ci.org/mortendahl/rust-paillier.svg)](https://travis-ci.org/mortendahl/rust-paillier)
[![Latest version](https://img.shields.io/crates/v/paillier.svg)](https://img.shields.io/crates/v/paillier.svg)
[![License: MIT/Apache2](https://img.shields.io/badge/license-MIT%2fApache2-blue.svg)](https://img.shields.io/badge/license-MIT%2fApache2-blue.svg)

Efficient pure-Rust library for the [Paillier](https://en.wikipedia.org/wiki/Paillier_cryptosystem) partially homomorphic encryption scheme, offering also packed encoding for encrypting several values together as well as several zero-knowledge proofs related to typical use-cases.
Supports several underlying arbitrary precision libraries, including [RAMP](https://github.com/Aatch/ramp) and [GMP](https://github.com/fizyk20/rust-gmp).

Several companies have invested resources in the development of this library, including [Snips](https://snips.ai/) who implemented the [original version](https://github.com/snipsco/rust-paillier) for use in their privacy-preserving analytics system, and [KZen networks](https://github.com/KZen-networks) who contributed with implementations of many zero-knowledge proofs. See [contributions](#contributions) below for more details.

**Important**: while we have followed recommendations regarding the scheme itself, some parts of this library have not yet been harden against non-cryptographic attacks such as side-channel attacks.


```rust
extern crate paillier;
use paillier::*;

fn main() {

  // generate a fresh keypair and extract encryption and decryption keys
  let (ek, dk) = Paillier::keypair().keys();

  // encrypt four values
  let c1 = Paillier::encrypt(&ek, 10);
  let c2 = Paillier::encrypt(&ek, 20);
  let c3 = Paillier::encrypt(&ek, 30);
  let c4 = Paillier::encrypt(&ek, 40);

  // add all of them together
  let c = Paillier::add(&ek,
    &Paillier::add(&ek, &c1, &c2),
    &Paillier::add(&ek, &c3, &c4)
  );

  // multiply the sum by 2
  let d = Paillier::mul(&ek, &c, 2);

  // decrypt final result
  let m: u64 = Paillier::decrypt(&dk, &d);
  println!("decrypted total sum is {}", m);

}
```

# Installation

Some features are optional yet currently included by default. See [Features](#features) below for more details. Note that the nightly toolchain is currently needed to build the library.

## Using cargo
```toml
[dependencies]
paillier = { version="0.2" }
```

## From source
```bash
git clone https://github.com/mortendahl/rust-paillier
cd rust-paillier
cargo build --release
```

## Features

The library supports the following features. The default compilation is equivalent to
```
cargo build --release --no-default-features --features "usegmp keygen proofs"
```
using GMP and including both key generation and zero-knowledge proofs.

### Underlying arithmetic

The choice of underlying arithmetic library may be changed using features `usegmp` (default) and `useramp`. GMP generally offers [slightly better performance](https://medium.com/snips-ai/benchmarking-paillier-encryption-15631a0b5ad8) but may be unavailable on some platforms or for some applications. Note that `useramp` does currently *not* support proofs, i.e. features `useramp` and `proofs` cannot be used together.

### Key generation

Key generation feature `keygen` is included by default but if unneeded may safely be excluded to avoid extra dependencies.

```rust
extern crate paillier;
use paillier::*;

fn main() {

  // generate a fresh keypair and extract encryption and decryption keys
  let (ek, dk) = Paillier::keypair().keys();

  ...

}
```

### Zero-knowledge proofs

Feature `proofs` includes various zero-knowledge proofs related to the typical use of Paillier encryption. Turned on by default but may safely be excluded if unneeded.

# Benchmarks

Several benches are included, testing both the underlying arithmetic libraries as well as the operations of the scheme. All may be run using
```
cargo bench
```
and including either several arithmetic libraries and key generation as discussed [above](#building).

# License

Forked from [`snipsco/rust-paillier`](https://github.com/snipsco/rust-paillier) with additional functionality. Licensed under either of

 * Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.


# Contributions

Several people have had a significant impact in the development of this library (in alphabetical order):
- [Gary Benattar](https://github.com/gbenattar) (KZen networks)
- [Mario Cornejo](https://github.com/mcornejo) (while at Snips)
- [Mathieu Poumeyrol](https://github.com/kali) (Snips)
- [Omer Shlomovits](https://github.com/omershlo) (KZen networks)

and several companies have invested resources:
- [Snips](https://github.com/snipsco) sponsored implementation of the original version
- [KZen networks](https://github.com/KZen-networks) sponsored extension of many zero-knowledge proofs

## Reported uses

- [Snips](https://github.com/snipsco): privacy-preserving analytics
- [KZen networks](https://github.com/KZen-networks): multi-party signatures

