#![cfg(feature="inclramp")]

extern crate ramp;
use rand::{OsRng};
use super::traits::*;


impl Samplable for ramp::Int {
    fn sample_below(upper: &Self) -> Self {
        use self::ramp::RandomInt;
        let mut rng = OsRng::new().unwrap();
        rng.gen_uint_below(upper)
    }

     fn sample(bitsize: usize) -> Self {
        use self::ramp::RandomInt;
        let mut rng = OsRng::new().unwrap();
        rng.gen_uint(bitsize)
    }

     fn sample_range(lower: &Self, upper: &Self) -> Self {
        use self::ramp::RandomInt;
        let mut rng = OsRng::new().unwrap();
        rng.gen_int_range(lower, upper)
    }
}

impl NumberTests for ramp::Int {
    fn is_zero(me: &Self) -> bool { me == &0 }
    fn is_even(me: &Self) -> bool { me.is_even() }
    fn is_negative(me: &Self) -> bool { me < &0 }
}

impl ModularArithmetic for ramp::Int {
    fn divmod(dividend: &Self, module: &Self) -> (Self, Self) {
        dividend.divmod(module)
    }
}

impl ConvertFrom<ramp::Int> for u64 {
    fn _from(x: &ramp::Int) -> u64 {
        u64::from(x)
    }
}

impl BitManipulation for ramp::Int {
    fn set_bit(self: &mut Self, bit: usize, bit_val: bool) {
        self.set_bit(bit as u32, bit_val);
    }
}

pub type BigInteger = ramp::Int;
