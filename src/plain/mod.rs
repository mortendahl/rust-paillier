
#[cfg(feature="useramp")]
use arithimpl::rampimpl::BigInteger as BigInteger;

#[cfg(feature="usenum")]
use arithimpl::numimpl::BigInteger as BigInteger;

pub mod abstractimpl;
pub type PlainPaillier = self::abstractimpl::AbstractPlainPaillier<BigInteger>;
