#![cfg(feature="inclnum")]

extern crate num;

use rand;
// use num;
// use self::num;

use super::traits::*;

impl Samplable for num::bigint::BigInt {
    fn sample_below(upper: &Self) -> Self {
        use self::num::bigint::{ToBigInt, RandBigInt};
        let mut rng = try!(rand::OsRng::new());
        try!(rng.gen_biguint_below(try!(&upper.to_biguint()).to_bigint()))
    }

    fn sample(bitsize: usize) -> Self {
        use self::num::bigint::{ToBigInt, RandBigInt};
        let mut rng = try!(rand::OsRng::new());
        try!(rng.gen_biguint(bitsize).to_bigint())
    }

}

use self::num::{Zero, Integer, Signed};
impl NumberTests for num::bigint::BigInt {
    fn is_zero(me: &Self) -> bool { me.is_zero() }
    fn is_even(me: &Self) -> bool { me.is_even() }
    fn is_negative(me: &Self) -> bool { me.is_negative() }
}

impl ModularArithmetic for num::bigint::BigInt {}

use self::num::ToPrimitive;
impl ConvertFrom<num::bigint::BigInt> for u64 {
    fn _from(x: &num::bigint::BigInt) -> u64 {
        x.to_u64().unwrap()
    }
}

pub type BigInteger = num::bigint::BigInt;
