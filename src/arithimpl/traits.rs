
use std::marker::Sized;

pub trait NumberTests {
    fn is_zero(&Self) -> bool;
    fn is_even(&Self) -> bool;
    fn is_negative(me: &Self) -> bool;
}

pub trait ModPow
{
    fn modpow(base: &Self, exponent: &Self, modulus: &Self) -> Self;
}

pub trait EGCD
where
    Self: Sized
{
    fn egcd(a: &Self, b: &Self) -> (Self, Self, Self);
}

pub trait ModInv
{
    fn modinv(a: &Self, prime: &Self) -> Self;
}

pub trait Samplable {
    fn sample_below(upper: &Self) -> Self;
    fn sample_range(lower: &Self, upper: &Self) -> Self;
    fn sample(bitsize: usize) -> Self;
}

pub trait BitManipulation {
    fn set_bit(self: &mut Self, bit: usize, bit_val: bool);
}

pub trait ConvertFrom<T> {
    fn _from(&T) -> Self;
}

use std::ops::{Add, Sub, Mul, Div, Rem, Shr, Neg};
use num_traits::{Zero, One};

impl<I> ModPow for I
where // TODO clean up
    I: Clone + Sized,
    I: Zero + One + Neg<Output=I> + NumberTests,
    for<'a>    &'a I: Mul<I, Output=I>,
    for<'a,'b> &'a I: Mul<&'b I, Output=I>,
    for<'a,'b> &'a I: Div<&'b I, Output=I>,
    for<'a>        I: Rem<&'a I, Output=I>,
    for<'a,'b> &'a I: Rem<&'b I, Output=I>,
    for<'a,'b> &'a I: Add<&'b I, Output=I>,
                   I: Sub<I, Output=I>,
    for<'b>        I: Sub<&'b I, Output=I>,
    for<'a,'b> &'a I: Sub<&'b I, Output=I>,
    I: Shr<usize, Output=I>,
{
    default fn modpow(base: &Self, exponent: &Self, modulus: &Self) -> Self {
        let mut base = base.clone();
        let mut exponent = exponent.clone();
        let mut result = Self::one();

        while !NumberTests::is_zero(&exponent) {
            if !NumberTests::is_even(&exponent) {
                result = (&result * &base) % modulus;
            }
            base = (&base * &base) % modulus;  // waste one of these by having it here but code is simpler (tiny bit)
            exponent = exponent >> 1;
        }
        result
    }
}

impl<I> EGCD for I
where // TODO clean up
    I: Clone,
    I: Sized,
    I: Zero + One,
    I: Neg<Output=I>,
    I: NumberTests,
    for<'a>    &'a I: Mul<I, Output=I>,
    for<'a,'b> &'a I: Mul<&'b I, Output=I>,
    for<'a,'b> &'a I: Div<&'b I, Output=I>,
    for<'a>        I: Rem<&'a I, Output=I>,
    for<'a,'b> &'a I: Rem<&'b I, Output=I>,
    for<'a,'b> &'a I: Add<&'b I, Output=I>,
                   I: Sub<I, Output=I>,
    for<'b>        I: Sub<&'b I, Output=I>,
    for<'a,'b> &'a I: Sub<&'b I, Output=I>,
    I: Shr<usize, Output=I>,
{
    default fn egcd(a: &Self, b: &Self) -> (Self, Self, Self) {
        if NumberTests::is_zero(b) {
            (a.clone(), Self::one(), Self::zero())
        } else {
            let q = a / b;
            let r = a % b;
            let (d, s, t) = Self::egcd(b, &r);
            let new_t = s - &t * q;
            (d, t, new_t)
        }
    }
}

impl<I> ModInv for I
where
    I: EGCD,
    I: Clone + Sized,
    I: Zero + One + Neg<Output=I> + NumberTests,
    for<'a>    &'a I: Mul<I, Output=I>,
    for<'a,'b> &'a I: Mul<&'b I, Output=I>,
    for<'a,'b> &'a I: Div<&'b I, Output=I>,
    for<'a>        I: Rem<&'a I, Output=I>,
    for<'a,'b> &'a I: Rem<&'b I, Output=I>,
    for<'a,'b> &'a I: Add<&'b I, Output=I>,
                   I: Sub<I, Output=I>,
    for<'b>        I: Sub<&'b I, Output=I>,
    for<'a,'b> &'a I: Sub<&'b I, Output=I>,
    I: Shr<usize, Output=I>,
{
    default fn modinv(a: &Self, prime: &Self) -> Self {
        let r = a % prime;
        let ref d = if NumberTests::is_negative(&r) {
            let r = r.neg();
            -Self::egcd(prime, &r).2
        } else {
            Self::egcd(prime, &r).2
        };
        (prime + d) % prime
    }
}
