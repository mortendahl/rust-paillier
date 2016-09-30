
use rand;
use num;

use phe::*;

impl Int for num::bigint::BigInt {}

impl Samplable for num::bigint::BigInt {
    fn sample(upper: &Self) -> Self {
        use num::bigint::{ToBigInt, RandBigInt};
        let mut rng = rand::OsRng::new().unwrap();
        rng.gen_biguint_below(&upper.to_biguint().unwrap()).to_bigint().unwrap()
    }
}

use num::{Zero, One};
impl Identities for num::bigint::BigInt {
    fn _zero() -> Self { Self::zero() }
    fn _one() -> Self { Self::one() }
}

impl ModularArithmetic for num::bigint::BigInt {

    // TODO much of this code could be moved into trait for re-use

    fn modpow(x: &Self, e: &Self, prime: &Self) -> Self {
        use num::{Zero, Integer};

        let mut mx = x.clone();
        let mut me = e.clone();
        let mut acc = Self::one();
        while !me.is_zero() {
            if me.is_even() {
                // even
                // no-op
            }
            else {
                // odd
                acc = (&acc * &mx) % prime;
            }
            mx = (&mx * &mx) % prime;  // waste one of these by having it here but code is simpler (tiny bit)
            me = me >> 1;
        }
        acc
    }

    fn egcd(a: &Self, b: &Self) -> (Self, Self, Self) {
        if b == &Self::zero() {
            (a.clone(), Self::one(), Self::zero())
        } else {
            let q = a / b;
            let r = a % b;
            let (d, s, t) = Self::egcd(b, &r);
            let new_t = s - &t * q;
            (d, t, new_t)
        }
    }

    fn modinv(a: &Self, prime: &Self) -> Self {
        use num::Signed;
        use std::ops::Neg;

        let r = a % prime;
        let d = if r.is_negative() {
            let r = r.neg();
            -Self::egcd(prime, &r).2
        } else {
            Self::egcd(prime, &r).2
        };
        (prime + d) % prime
    }

}

use super::abstractimpl::AbstractPlainPaillier;
pub type NumPlainPaillier = AbstractPlainPaillier<num::bigint::BigInt>;
