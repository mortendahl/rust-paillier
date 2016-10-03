
mod abstractimpl;
mod rampimpl;
mod numimpl;

pub use self::rampimpl::RampPlainPaillier;
pub type PlainPaillier = RampPlainPaillier;

#[cfg(feature="inclnum")]
pub use self::numimpl::NumPlainPaillier;
// pub type PlainPaillier = NumPlainPaillier;
