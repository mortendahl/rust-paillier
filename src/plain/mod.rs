
mod abstractimpl;

mod rampimpl;
pub use self::rampimpl::RampPlainPaillier;

mod numimpl;
pub use self::numimpl::NumPlainPaillier;

pub type PlainPaillier = RampPlainPaillier;

mod tests;
