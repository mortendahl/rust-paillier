#![cfg(feature="inclgmp")]

extern crate gmp;

use super::traits::*;
use self::gmp::mpz::Mpz;
use self::gmp::rand::RandState;

impl Samplable for Mpz {
    fn sample_below(upper: &Self) -> Self {
        let mut r = RandState::new();
        r.urandom(upper)
    }

    #[allow(unused_variables)]
    fn sample(bitsize: usize) -> Self {
        unimplemented!();
    }

    #[allow(unused_variables)]
    fn sample_range(lower: &Self, upper: &Self) -> Self {
        unimplemented!();
    }
}

impl NumberTests for Mpz {
    fn is_zero(me: &Self) -> bool { me.is_zero() }
    fn is_even(me: &Self) -> bool { me.is_multiple_of(&Mpz::from(2)) }
    fn is_negative(me: &Self) -> bool { me < &Mpz::from(0) }
}

pub use num_traits::{Zero, One};

impl ModularArithmetic for Mpz {

    fn modinv(a: &Self, prime: &Self) -> Self {
        a.invert(prime).unwrap()
    }

    fn modpow(x: &Self, e: &Self, prime: &Self) -> Self {
        x.powm(e, prime)
    }

    fn egcd(a: &Self, b: &Self) -> (Self, Self, Self) {
        a.gcdext(b)
    }

    // TODO: native way of doing divmod (supported by GMP but not currently by Rust wrapper)

}

impl ConvertFrom<Mpz> for u64 {
    fn _from(x: &Mpz) -> u64 {
        let foo: Option<u64> = x.into();
        foo.unwrap()
    }
}

pub type BigInteger = Mpz;
