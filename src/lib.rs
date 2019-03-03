extern crate bit_vec;
extern crate curv;
extern crate num_traits;
extern crate rand;
extern crate rayon;
extern crate serde;
//extern crate test;
#[macro_use]
extern crate serde_derive;

pub mod core;
pub mod encoding;
mod serialize;
pub mod traits;

pub mod keygen;

pub use core::*;
pub use encoding::*;
pub use traits::*;

pub use keygen::*;

use std::borrow::Cow;

/// Main struct onto which most operations are added.
pub struct Paillier;

pub use curv::arithmetic::big_gmp::BigInt;

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
    pub n: BigInt,
}

/// Private decryption key with no precomputed values.
///
/// Used e.g. for serialization of `DecryptionKey`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MinimalDecryptionKey {
    #[serde(with = "::serialize::bigint")]
    pub p: BigInt,

    #[serde(with = "::serialize::bigint")]
    pub q: BigInt,
}

/// Public encryption key.
#[derive(Clone, Debug, PartialEq)]
pub struct EncryptionKey {
    pub n: BigInt,  // the modulus
    pub nn: BigInt, // the modulus squared
}

/// Private decryption key.
#[derive(Clone, Debug, PartialEq)]
pub struct DecryptionKey {
    pub p: BigInt, // first prime
    pub q: BigInt, // second prime
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
