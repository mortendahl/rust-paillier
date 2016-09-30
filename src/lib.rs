#![feature(test)]

extern crate test;
extern crate rand;

extern crate num;
extern crate ramp;

mod phe;
pub mod plain;
pub use plain::PlainPaillier;

pub mod packed;
pub use packed::PackedPaillier;
