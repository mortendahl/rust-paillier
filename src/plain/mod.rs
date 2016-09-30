
mod abstractimpl;
mod rampimpl;
mod numimpl;

pub use self::rampimpl::RampPlainPaillier as PlainPaillier;

#[cfg(feature="inclnum")]
pub use self::numimpl::NumPlainPaillier;

mod tests;
