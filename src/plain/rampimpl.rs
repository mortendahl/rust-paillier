
use rand;
use ramp;

use phe::*;
use num_traits as num;

#[derive(Debug,Clone)]
pub struct RampBigInteger(pub ramp::Int);

impl Samplable for ramp::Int {
    fn sample(upper: &Self) -> Self {
        use ramp::RandomInt;
        let mut rng = rand::OsRng::new().unwrap();
        rng.gen_uint_below(upper)
    }
}

impl NumberTests for ramp::Int {
    fn is_zero(me: &Self) -> bool { me == &0_usize }
    fn is_even(me: &Self) -> bool { me.is_even() }
    fn is_negative(me: &Self) -> bool { me < &0_usize }
}

// impl num::Zero for RampBigInteger {
//
// }

impl ModularArithmetic for ramp::Int {

    // TODO much of this code could be moved into trait for re-use

    fn modinv(a: &Self, prime: &Self) -> Self {
        use std::ops::Neg;

        let r = a % prime;
        let d = if r < 0 {
            let r = r.neg();
            -Self::egcd(prime, &r).2
        } else {
            Self::egcd(prime, &r).2
        };
        (prime + d) % prime
    }

}

use super::abstractimpl::AbstractPlainPaillier;
pub type RampPlainPaillier = AbstractPlainPaillier<ramp::Int>;
