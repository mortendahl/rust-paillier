# Paillier

[![License: MIT/Apache2](https://img.shields.io/badge/license-MIT%2fApache2-blue.svg)](https://img.shields.io/badge/license-MIT%2fApache2-blue.svg)

Efficient pure-Rust library for the [Paillier](https://en.wikipedia.org/wiki/Paillier_cryptosystem) partially homomorphic encryption scheme, offering encoding of both scalars and vectors (for encrypting several values together).
Supports several underlying arbitrary precision libraries, including [RAMP](https://github.com/Aatch/ramp) (default), [GMP](https://github.com/fizyk20/rust-gmp), and [num](https://github.com/rust-num/num).

**Important**: while we have followed recommendations regarding the scheme itself, this library should currently be seen as an experimental implementation. In particular, no particular efforts have so far been made to harden it against non-cryptographic attacks, including side-channel attacks.


```rust
extern crate paillier;
use paillier::*;

fn main() {

  // generate a fresh keypair
  let (ek, dk) = Paillier::keypair();

  // select integral coding
  let code = integral::Code::default();

  // pair keys with coding
  let eek = ek.with_code(&code);
  let ddk = dk.with_code(&code);

  // encrypt four values
  let c1 = Paillier::encrypt(&eek, &10);
  let c2 = Paillier::encrypt(&eek, &20);
  let c3 = Paillier::encrypt(&eek, &30);
  let c4 = Paillier::encrypt(&eek, &40);

  // add all of them together
  let c = Paillier::add(&ek,
    &Paillier::add(&ek, &c1, &c2),
    &Paillier::add(&ek, &c3, &c4)
  );

  // multiply the sum by 2
  let d = Paillier::mul(&eek, &c, &2);

  // decrypt final result
  let m: u64 = Paillier::decrypt(&ddk, &d);
  println!("decrypted total sum is {}", m);

}
```


# Installation

Note that some functionality is *not* included by default; see the [Building](#building) section for more details.

## GitHub
```bash
git clone https://github.com/snipsco/rust-paillier
cd rust-paillier
cargo build --release
```

## Cargo
```toml
[dependencies]
paillier = { version="0.1" }
```


## Building

The nightly toolchain is currently needed in order to build the library. For performance reasons we strongly encourage building and testing in release mode.

### Arithmetic

The library supports the use of different arithmetic libraries, currently defaulting to [RAMP](https://github.com/Aatch/ramp) for portability with good performance.

For [RAMP](https://github.com/Aatch/ramp)-only compilation use `cargo` parameters
```
--no-default-features --features "inclramp defaultramp keygen"
```

For [num](https://github.com/rust-num/num)-only compilation use
```
--no-default-features --features "inclnum defaultnum"
```

For [GMP](https://github.com/fizyk20/rust-gmp)-only compilation use
```
--no-default-features --features "inclgmp defaultgmp"
```

Finally, use
```
--no-default-features --features "inclramp inclnum inclgmp defaultramp"
```
to have one or more available, using one of them as the default (useful for e.g. performance tests).

### Key generation

Key generation is optional as it is currently only implemented when using [RAMP](https://github.com/Aatch/ramp) as the underlying arithmetic library.

While included by default it may be excluded using parameter
```
--no-default-features
```
in which case one or more arithmetic libraries must be specified as well as a default one, e.g.
```
--features "inclramp inclgmp defaultramp"
```
as shown in [above](#arithmetic) .




# Performance

Several benches are included, testing both the underlying arithmetic libraries as well as the operations of the scheme. All may be run using
```
cargo bench
```
and including either several arithmetic libraries and key generation as discussed [above](#building).

# License

Licensed under either of

 * Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall
be dual licensed as above, without any additional terms or conditions.
 
