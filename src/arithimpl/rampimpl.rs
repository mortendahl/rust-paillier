#![cfg(feature="useramp")]

extern crate ramp;

use rand;

use super::traits::*;

impl Samplable for ramp::Int {
    fn sample(upper: &Self) -> Self {
        use self::ramp::RandomInt;
        let mut rng = rand::OsRng::new().unwrap();
        rng.gen_uint_below(upper)
    }
}

impl NumberTests for ramp::Int {
    fn is_zero(me: &Self) -> bool { me == &0 }
    fn is_even(me: &Self) -> bool { me.is_even() }
    fn is_negative(me: &Self) -> bool { me < &0 }
}

impl ModularArithmetic for ramp::Int {}

impl ConvertFrom<ramp::Int> for u64 {
    fn _from(x: &ramp::Int) -> u64 {
        u64::from(x)
    }
}

pub type BigInteger = ramp::Int;
