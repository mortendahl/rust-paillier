#![cfg(feature="inclnum")]

use rand;
use num;

use phe::*;

// impl Int for num::bigint::BigInt {}

impl Samplable for num::bigint::BigInt {
    fn sample(upper: &Self) -> Self {
        use num::bigint::{ToBigInt, RandBigInt};
        let mut rng = rand::OsRng::new().unwrap();
        rng.gen_biguint_below(&upper.to_biguint().unwrap()).to_bigint().unwrap()
    }
}

use num::{Zero, Integer, Signed};
impl NumberTests for num::bigint::BigInt {
    fn is_zero(me: &Self) -> bool { me.is_zero() }
    fn is_even(me: &Self) -> bool { me.is_even() }
    fn is_negative(me: &Self) -> bool { me.is_negative() }
}

impl ModularArithmetic for num::bigint::BigInt {}

use super::abstractimpl::AbstractPlainPaillier;
pub type NumPlainPaillier = AbstractPlainPaillier<num::bigint::BigInt>;
