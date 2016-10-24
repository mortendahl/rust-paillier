#![feature(test)]

extern crate test;
extern crate rand;
extern crate num_traits;

mod arithimpl;
mod phe;
mod plain;
mod packed;

pub use phe::{KeyGeneration, PartiallyHomomorphicScheme};


/*************************
  Ramp instance (default)
 *************************/

#[cfg(feature="inclramp")]
mod rampinstance
{
    use arithimpl::rampimpl::BigInteger as BigInteger;
    pub type RampPlainPaillier = ::plain::AbstractPlainPaillier<BigInteger>;
    pub type RampPackedPaillier = ::packed::AbstractPackedPaillier<u64, RampPlainPaillier>;

    pub type PlainPaillier = RampPlainPaillier;
    pub type PackedPaillier = RampPackedPaillier;
}
#[cfg(feature="inclramp")]
pub use self::rampinstance::*;


/**************
  Num instance
 **************/

#[cfg(feature="inclnum")]
mod numinstance
{
    use arithimpl::numimpl::BigInteger as BigInteger;
    pub type NumPlainPaillier = ::plain::AbstractPlainPaillier<BigInteger>;
    pub type NumPackedPaillier = ::packed::AbstractPackedPaillier<u64, NumPlainPaillier>;

    #[cfg(not(feature="inclramp"))]
    pub type PlainPaillier = NumPlainPaillier;
    #[cfg(not(feature="inclramp"))]
    pub type PackedPaillier = NumPackedPaillier;
}
#[cfg(feature="inclnum")]
pub use self::numinstance::*;
