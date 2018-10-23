#![feature(test)]
#![feature(specialization)]

extern crate bit_vec;
extern crate num_traits;
extern crate rand;
extern crate rayon;
#[cfg(feature = "proofs")]
extern crate ring;
extern crate serde;
extern crate test;
#[macro_use]
extern crate serde_derive;

pub mod arithimpl;
pub mod core;
pub mod encoding;
mod serialize;
pub mod traits;

#[cfg(feature = "keygen")]
pub mod keygen;

#[cfg(feature = "proofs")]
pub mod proof;

pub use core::*;
pub use encoding::*;
pub use traits::*;

#[cfg(feature = "keygen")]
pub use keygen::*;

#[cfg(feature = "proofs")]
pub use proof::*;

use serde::de::Deserialize;
use serde::ser::Serialize;
use std::borrow::Cow;

/// Main struct onto which most operations are added.
pub struct Paillier;

#[cfg(feature = "useramp")]
pub use arithimpl::rampimpl::BigInt;

#[cfg(feature = "useframp")]
pub use arithimpl::frampimpl::BigInt;

#[cfg(feature = "usegmp")]
pub use arithimpl::gmpimpl::BigInt;

/// Keypair from which encryption and decryption keys can be derived.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Keypair {
    #[serde(with = "::serialize::bigint")]
    pub p: BigInt, // TODO[Morten] okay to make non-public?

    #[serde(with = "::serialize::bigint")]
    pub q: BigInt, // TODO[Morten] okay to make non-public?
}

/// Public encryption key with no precomputed values.
///
/// Used e.g. for serialization of `EncryptionKey`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MinimalEncryptionKey {
    #[serde(with = "::serialize::bigint")]
    n: BigInt,
}

/// Private decryption key with no precomputed values.
///
/// Used e.g. for serialization of `DecryptionKey`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MinimalDecryptionKey {
    #[serde(with = "::serialize::bigint")]
    p: BigInt,

    #[serde(with = "::serialize::bigint")]
    q: BigInt,
}

/// Public encryption key.
#[derive(Clone, Debug, PartialEq)]
pub struct EncryptionKey {
    n: BigInt,  // the modulus
    nn: BigInt, // the modulus squared
}

/// Private decryption key.
#[derive(Clone, Debug, PartialEq)]
pub struct DecryptionKey {
    p: BigInt, // first prime
    q: BigInt, // second prime
    n: BigInt, // the modulus (also in public key)
    nn: BigInt,
    pp: BigInt,
    pminusone: BigInt,
    qq: BigInt,
    qminusone: BigInt,
    phi: BigInt,
    dp: BigInt,
    dq: BigInt,
    pinv: BigInt,
    ppinv: BigInt,
    hp: BigInt,
    hq: BigInt,
}

/// Unencrypted message without type information.
///
/// Used mostly for internal purposes and advanced use-cases.
#[derive(Clone, Debug, PartialEq)]
pub struct RawPlaintext<'b>(pub Cow<'b, BigInt>);

/// Encrypted message without type information.
///
/// Used mostly for internal purposes and advanced use-cases.
#[derive(Clone, Debug, PartialEq)]
pub struct RawCiphertext<'b>(pub Cow<'b, BigInt>);
