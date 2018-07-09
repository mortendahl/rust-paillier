#![feature(test)]
#![feature(specialization)]

extern crate test;
extern crate rand;
extern crate num_traits;
#[macro_use]
extern crate itertools;
extern crate rayon;
#[cfg(feature="proofs")]
extern crate ring;
extern crate bit_vec;

pub mod arithimpl;
pub mod traits;
pub mod core;
pub mod coding;
#[cfg(feature="keygen")]
pub mod keygen;
#[cfg(feature="proofs")]
pub mod proof;

pub use traits::*;
pub use core::*;
pub use coding::*;
#[cfg(feature="keygen")]
pub use keygen::*;


/// Main struct onto which most operations are added.
pub struct Paillier {}

#[cfg(feature="useramp")]
pub use arithimpl::rampimpl::BigInteger as BigInteger;

#[cfg(feature="useframp")]
pub use arithimpl::frampimpl::BigInteger as BigInteger;

#[cfg(feature="usegmp")]
pub use arithimpl::gmpimpl::BigInteger as BigInteger;

#[cfg(feature="usenum")]
pub use arithimpl::numimpl::BigInteger as BigInteger;

/// Public encryption key.
#[derive(Debug,Clone)]
pub struct EncryptionKey {
    n: BigInteger,  // the modulus
    nn: BigInteger, // the modulus squared
}

/// Private decryption key.
#[derive(Debug,Clone)]
pub struct DecryptionKey {
    p: BigInteger,  // first prime
    q: BigInteger,  // second prime
    n: BigInteger,  // the modulus (also in public key)
    nn: BigInteger,
    pp: BigInteger,
    pminusone: BigInteger,
    qq: BigInteger,
    qminusone: BigInteger,
    phi: BigInteger,
    dp: BigInteger,
    dq: BigInteger,
    pinv: BigInteger,
    ppinv: BigInteger,
    hp: BigInteger,
    hq: BigInteger,
}