#![feature(test)]
#![feature(specialization)]

extern crate test;
extern crate rand;
extern crate num_traits;
extern crate ring;
extern crate data_encoding;

pub mod arithimpl;
pub mod traits;
pub mod core;
pub mod coding;
#[cfg(feature="keygen")]
pub mod keygen;
pub mod proof;

pub use traits::*;
pub use coding::*;
pub use core::{Keypair, RawPlaintext, RawCiphertext};
#[cfg(feature="keygen")]
pub use keygen::*;
pub use proof::*;


/// Parameterised type onto which all operations are added (see `Paillier`).
pub struct AbstractPaillier<I> {
    junk: ::std::marker::PhantomData<I>
}


/*************************
  Ramp instance
 *************************/

#[cfg(feature="inclramp")]
mod rampinstance
{
    pub use arithimpl::rampimpl::BigInteger as RampBigInteger;
    pub type RampPaillier = ::AbstractPaillier<RampBigInteger>;

    #[cfg(feature="defaultramp")]
    pub type BigInteger = RampBigInteger;
    #[cfg(feature="defaultramp")]
    pub type Paillier = RampPaillier;
}
#[cfg(feature="inclramp")]
pub use self::rampinstance::*;


/*************************
  Framp instance
 *************************/

#[cfg(feature="inclframp")]
mod frampinstance
{
    pub use arithimpl::frampimpl::BigInteger as FrampBigInteger;
    pub type FrampPaillier = ::AbstractPaillier<FrampBigInteger>;

    #[cfg(feature="defaultframp")]
    pub type BigInteger = FrampBigInteger;
    #[cfg(feature="defaultframp")]
    pub type Paillier = FrampPaillier;
}
#[cfg(feature="inclframp")]
pub use self::frampinstance::*;


/**************
  GMP instance
 **************/

#[cfg(feature="inclgmp")]
mod gmpinstance
{
    pub use arithimpl::gmpimpl::BigInteger as GmpBigInteger;
    pub type GmpPaillier = ::AbstractPaillier<GmpBigInteger>;

    #[cfg(feature="defaultgmp")]
    pub type BigInteger = GmpBigInteger;
    #[cfg(feature="defaultgmp")]
    pub type Paillier = GmpPaillier;
}
#[cfg(feature="inclgmp")]
pub use self::gmpinstance::*;


/**************
  Num instance
 **************/

#[cfg(feature="inclnum")]
mod numinstance
{
    pub use arithimpl::numimpl::BigInteger as NumBigInteger;
    pub type NumPaillier = ::AbstractPaillier<NumBigInteger>;

    #[cfg(feature="defaultnum")]
    pub type BigInteger = NumBigInteger;
    #[cfg(feature="defaultnum")]
    pub type Paillier = NumPaillier;
}
#[cfg(feature="inclnum")]
pub use self::numinstance::*;


/// Encryption key that may be shared publicly.
#[derive(Debug,Clone)]
pub struct EncryptionKey {
    pub n: BigInteger,  // the modulus
    nn: BigInteger, // the modulus squared
}

/// Decryption key that should be kept private.
#[derive(Debug,Clone)]
pub struct DecryptionKey {
    p: BigInteger,  // first prime
    q: BigInteger,  // second prime
    n: BigInteger,  // the modulus (also in public key)
    pp: BigInteger,
    pminusone: BigInteger,
    qq: BigInteger,
    qminusone: BigInteger,
    pinvq: BigInteger,
    hp: BigInteger,
    hq: BigInteger,
}