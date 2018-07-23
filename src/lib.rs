#![feature(test)]
#![feature(specialization)]

extern crate test;
extern crate rand;
extern crate num_traits;
extern crate rayon;
#[cfg(feature="proofs")]
extern crate ring;
extern crate bit_vec;

pub mod arithimpl;
pub mod core;
pub mod encoding;
pub mod traits;

#[cfg(feature="keygen")]
pub mod keygen;

#[cfg(feature="proofs")]
pub mod proof;

pub use traits::*;
pub use core::*;
pub use encoding::*;
pub use proof::*;

#[cfg(feature="keygen")]
pub use keygen::*;

use std::borrow::Cow;

/// Main struct onto which most operations are added.
pub struct Paillier {}

#[cfg(feature="useramp")]
pub use arithimpl::rampimpl::BigInt as BigInt;

#[cfg(feature="useframp")]
pub use arithimpl::frampimpl::BigInt as BigInt;

#[cfg(feature="usegmp")]
pub use arithimpl::gmpimpl::BigInt as BigInt;

/// Representation of a keypair from which encryption and decryption keys can be derived.
pub struct Keypair {
    pub p: BigInt,
    pub q: BigInt,
}

/// Public encryption key.
#[derive(Debug,Clone)]
pub struct EncryptionKey {
    n: BigInt,  // the modulus
    nn: BigInt, // the modulus squared
}

/// Private decryption key.
#[derive(Debug,Clone)]
pub struct DecryptionKey {
    p: BigInt,  // first prime
    q: BigInt,  // second prime
    n: BigInt,  // the modulus (also in public key)
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

/// Representation of unencrypted message.
#[derive(Clone,Debug,PartialEq)]
pub struct RawPlaintext<'b>( pub Cow<'b, BigInt>);

/// Representation of encrypted message.
#[derive(Clone,Debug,PartialEq)]
pub struct RawCiphertext<'b>(pub Cow<'b, BigInt>);
