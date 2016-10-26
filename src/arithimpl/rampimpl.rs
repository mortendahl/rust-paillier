#![cfg(feature="inclramp")]

extern crate ramp;

use rand;

use super::traits::*;

impl Samplable for ramp::Int {
    fn sample_below(upper: &Self) -> Self {
        use self::ramp::RandomInt;
        let mut rng = rand::OsRng::new().unwrap();
        rng.gen_uint_below(upper)
    }

     fn sample(bitsize: usize) -> Self {
        use self::ramp::RandomInt;
        let mut rng = rand::OsRng::new().unwrap();
        rng.gen_uint(bitsize)
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

impl PrimeNumbers for ramp::Int {    

    fn sample_prime(bitsize :usize) -> Self {
        
        loop {
            let mut candidate = Self::sample(bitsize);

            if Self::is_even(&candidate) {
                candidate = candidate + Self::one();
            }

            // TRIAL 
            // FERMAT
            // MILLER_RABIN

            return candidate
        }
    }
}


pub type BigInteger = ramp::Int;