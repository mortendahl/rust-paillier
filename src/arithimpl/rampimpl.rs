#![cfg(feature = "useramp")]

extern crate ramp;

use self::ramp::RandomInt;
use super::traits::*;
use rand::prelude::*;

impl Samplable for ramp::Int {
    fn sample_below(upper: &Self) -> Self {
        let mut rng = thread_rng();
        rng.gen_uint_below(upper)
    }

    fn sample(bitsize: usize) -> Self {
        let mut rng = thread_rng();
        rng.gen_uint(bitsize)
    }

    fn sample_range(lower: &Self, upper: &Self) -> Self {
        let mut rng = thread_rng();
        rng.gen_int_range(lower, upper)
    }
}

impl NumberTests for ramp::Int {
    fn is_zero(me: &Self) -> bool {
        me == &0
    }
    fn is_even(me: &Self) -> bool {
        me.is_even()
    }
    fn is_negative(me: &Self) -> bool {
        me < &0
    }
}

impl ModPow for ramp::Int {}

impl ConvertFrom<ramp::Int> for usize {
    fn _from(x: &ramp::Int) -> usize {
        usize::from(x)
    }
}

impl ConvertFrom<ramp::Int> for u8 {
    fn _from(x: &ramp::Int) -> u8 {
        u8::from(x)
    }
}

impl ConvertFrom<ramp::Int> for u16 {
    fn _from(x: &ramp::Int) -> u16 {
        u16::from(x)
    }
}

impl ConvertFrom<ramp::Int> for u32 {
    fn _from(x: &ramp::Int) -> u32 {
        u32::from(x)
    }
}

impl ConvertFrom<ramp::Int> for u64 {
    fn _from(x: &ramp::Int) -> u64 {
        u64::from(x)
    }
}

impl ConvertFrom<ramp::Int> for i8 {
    fn _from(x: &ramp::Int) -> i8 {
        i8::from(x)
    }
}

impl ConvertFrom<ramp::Int> for i16 {
    fn _from(x: &ramp::Int) -> i16 {
        i16::from(x)
    }
}

impl ConvertFrom<ramp::Int> for i32 {
    fn _from(x: &ramp::Int) -> i32 {
        i32::from(x)
    }
}

impl ConvertFrom<ramp::Int> for i64 {
    fn _from(x: &ramp::Int) -> i64 {
        i64::from(x)
    }
}

impl BitManipulation for ramp::Int {
    fn set_bit(self: &mut Self, bit: usize, bit_val: bool) {
        self.set_bit(bit as u32, bit_val);
    }

    fn test_bit(self: &Self, bit: usize) -> bool {
        self.bit(bit as u32)
    }
}

pub type BigInt = ramp::Int;
