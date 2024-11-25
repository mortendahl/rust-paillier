#![cfg(feature = "usegmp")]

extern crate gmp;

use self::gmp::mpz::Mpz;
use super::traits::*;
use rand::prelude::*;

impl Samplable for Mpz {
    fn sample_below(upper: &Self) -> Self {
        let bits = upper.bit_length();
        loop {
            let n = Self::sample(bits);
            if n < *upper {
                return n;
            }
        }
    }

    fn sample(bitsize: usize) -> Self {
        let mut rng = thread_rng();
        let bytes = (bitsize - 1) / 8 + 1;
        let mut buf: Vec<u8> = vec![0; bytes];
        rng.fill_bytes(&mut buf);
        Self::from(&*buf) >> (bytes * 8 - bitsize)
    }

    fn sample_range(lower: &Self, upper: &Self) -> Self {
        lower + Self::sample_below(&(upper - lower))
    }
}

impl NumberTests for Mpz {
    fn is_zero(me: &Self) -> bool {
        me.is_zero()
    }
    fn is_even(me: &Self) -> bool {
        me.is_multiple_of(&Mpz::from(2))
    }
    fn is_negative(me: &Self) -> bool {
        me < &Mpz::from(0)
    }
}

pub use num_traits::{One, Zero};

#[cfg(feature = "gmp_nonsec")]
impl ModPow for Mpz {
    fn modpow(base: &Self, exponent: &Self, modulus: &Self) -> Self {
        base.powm(exponent, modulus)
    }
}

#[cfg(not(feature = "gmp_nonsec"))]
impl ModPow for Mpz {
    fn modpow(base: &Self, exponent: &Self, modulus: &Self) -> Self {
        base.powm_sec(exponent, modulus)
    }
}

impl ModMul for Mpz {
    fn modmul(a: &Self, b: &Self, modulus: &Self) -> Self {
        (a.mod_floor(modulus) * b.mod_floor(modulus)).mod_floor(modulus)
    }
}

impl ModInv for Mpz {
    fn modinv(a: &Self, modulus: &Self) -> Self {
        a.invert(modulus).unwrap()
    }
}

impl EGCD for Mpz {
    fn egcd(a: &Self, b: &Self) -> (Self, Self, Self) {
        a.gcdext(b)
    }
}

impl ConvertFrom<Mpz> for u8 {
    fn _from(x: &Mpz) -> u8 {
        let foo: Option<u64> = x.into();
        foo.unwrap() as u8
    }
}

impl ConvertFrom<Mpz> for u16 {
    fn _from(x: &Mpz) -> u16 {
        let foo: Option<u64> = x.into();
        foo.unwrap() as u16
    }
}

impl ConvertFrom<Mpz> for u32 {
    fn _from(x: &Mpz) -> u32 {
        let foo: Option<u64> = x.into();
        foo.unwrap() as u32
    }
}

impl ConvertFrom<Mpz> for u64 {
    fn _from(x: &Mpz) -> u64 {
        let foo: Option<u64> = x.into();
        foo.unwrap()
    }
}

impl ConvertFrom<Mpz> for i8 {
    fn _from(x: &Mpz) -> i8 {
        let foo: Option<u64> = x.into();
        foo.unwrap() as i8
    }
}

impl ConvertFrom<Mpz> for i16 {
    fn _from(x: &Mpz) -> i16 {
        let foo: Option<u64> = x.into();
        foo.unwrap() as i16
    }
}

impl ConvertFrom<Mpz> for i32 {
    fn _from(x: &Mpz) -> i32 {
        let foo: Option<u64> = x.into();
        foo.unwrap() as i32
    }
}

impl ConvertFrom<Mpz> for i64 {
    fn _from(x: &Mpz) -> i64 {
        let foo: Option<u64> = x.into();
        foo.unwrap() as i64
    }
}

impl BitManipulation for Mpz {
    fn set_bit(self: &mut Self, bit: usize, bit_val: bool) {
        if bit_val {
            self.setbit(bit);
        } else {
            self.clrbit(bit);
        }
    }

    fn test_bit(self: &Self, bit: usize) -> bool {
        self.tstbit(bit)
    }
}

pub type BigInt = Mpz;
