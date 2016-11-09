#![cfg(feature="inclnum")]

extern crate num;

use rand;
// use num;
// use self::num;

use super::traits::*;

impl Samplable for num::bigint::BigInt {
    fn sample_below(upper: &Self) -> Self {
        use self::num::bigint::{ToBigInt, RandBigInt};
        let mut rng = rand::OsRng::new().unwrap();
        rng.gen_biguint_below(&upper.to_biguint().unwrap()).to_bigint().unwrap()  // TODO this is really ugly
    }

    fn sample(bitsize: usize) -> Self {
        use self::num::bigint::{ToBigInt, RandBigInt};
        let mut rng = rand::OsRng::new().unwrap();
        rng.gen_biguint(bitsize).to_bigint().unwrap()
    }

    fn sample_range(lower: &Self, upper: &Self) -> Self {
        use self::num::bigint::{ToBigInt, RandBigInt};
        let mut rng = rand::OsRng::new().unwrap();
        rng.gen_biguint_range(&lower.to_biguint().unwrap(), &upper.to_biguint().unwrap()).to_bigint().unwrap()
    }
}

use self::num::{Zero, Integer, Signed};
impl NumberTests for num::bigint::BigInt {
    fn is_zero(me: &Self) -> bool { me.is_zero() }
    fn is_even(me: &Self) -> bool { me.is_even() }
    fn is_negative(me: &Self) -> bool { me.is_negative() }
}

impl ModularArithmetic for num::bigint::BigInt {
    fn divmod(dividend: &Self, module: &Self) -> (Self, Self) {
        dividend.div_rem(module)
    }
}

use self::num::ToPrimitive;
impl ConvertFrom<num::bigint::BigInt> for u64 {
    fn _from(x: &num::bigint::BigInt) -> u64 {
        x.to_u64().unwrap()
    }
}

pub type BigInteger = num::bigint::BigInt;
