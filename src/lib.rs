#![feature(test)]

extern crate test;
extern crate rand;
extern crate ramp;

//#[cfg(feature="inclnum")]
// extern crate num;

mod phe;
pub use phe::{KeyGeneration, PartiallyHomomorphicScheme};

pub mod plain;
pub use plain::*;

pub mod packed;
pub use packed::*;
