
mod abstractimpl;
use self::abstractimpl::*;

mod rampimpl;
pub use self::rampimpl::RampPlainPaillier;

mod numimpl;
pub use self::numimpl::NumPlainPaillier;

// default PlainPaillier implementation
pub type PlainPaillier = RampPlainPaillier;

mod tests;
