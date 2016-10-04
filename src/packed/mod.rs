
#[cfg(feature="useramp")]
mod foo
{
    use arithimpl::rampimpl::BigInteger as BigInteger;
    pub type BasePHE = ::plain::abstractimpl::AbstractPlainPaillier<BigInteger>;
    pub type ComponentType = u64;
}

#[cfg(feature="usenum")]
mod foo
{
    use arithimpl::numimpl::BigInteger as BigInteger;
    pub type BasePHE = ::plain::abstractimpl::AbstractPlainPaillier<BigInteger>;
    pub type ComponentType = u64;
}

use self::foo::*;

mod abstractimpl;
use self::abstractimpl::AbstractPackedPaillier;
pub type PackedPaillier = AbstractPackedPaillier<ComponentType, BasePHE>;
