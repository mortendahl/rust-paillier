
#[cfg(not(feature="inclnum"))]
use arithimpl::rampimpl::BigInteger as BigInteger;

#[cfg(feature="inclnum")]
use arithimpl::numimpl::BigInteger as BigInteger;

mod abstractimpl;
pub type PlainPaillier = self::abstractimpl::AbstractPlainPaillier<BigInteger>;
