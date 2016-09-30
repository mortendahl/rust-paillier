#![feature(test)]

extern crate test;
extern crate rand;

extern crate num;
extern crate ramp;

mod phe;
pub mod plain;
pub mod packed;

// default implementations
pub type PlainPaillier = plain::RampPlainPaillier;
pub type PackedPaillier = packed::AbstractPackedPaillier<PlainPaillier>;
