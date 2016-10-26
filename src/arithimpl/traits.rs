
use std::ops::{Add, Sub, Mul, Div, Rem, Shr, Neg};
use std::marker::Sized;
use num_traits::{Zero, One};

pub trait NumberTests {
    fn is_zero(&Self) -> bool;
    fn is_even(&Self) -> bool;
    fn is_negative(me: &Self) -> bool;
}

pub trait ModularArithmetic
where
    Self: Clone + Sized,
    Self: Zero + One + Neg<Output=Self> + NumberTests,
    for<'a>    &'a Self: Mul<Self, Output=Self>,
    for<'a,'b> &'a Self: Mul<&'b Self, Output=Self>,
    for<'a,'b> &'a Self: Div<&'b Self, Output=Self>,
    for<'a>        Self: Rem<&'a Self, Output=Self>,
    for<'a,'b> &'a Self: Rem<&'b Self, Output=Self>,
    for<'a,'b> &'a Self: Add<&'b Self, Output=Self>,
                   Self: Sub<Self, Output=Self>,
    for<'b>        Self: Sub<&'b Self, Output=Self>,
    for<'a,'b> &'a Self: Sub<&'b Self, Output=Self>,
    Self: Shr<usize, Output=Self>,
{

    fn modinv(a: &Self, prime: &Self) -> Self {
        let r = a % prime;
        let ref d = if NumberTests::is_negative(&r) {
            let r = r.neg();
            -Self::egcd(prime, &r).2
        } else {
            Self::egcd(prime, &r).2
        };
        (prime + d) % prime
    }

    fn modpow(x: &Self, e: &Self, prime: &Self) -> Self {
        let mut mx = x.clone();
        let mut me = e.clone();
        let mut acc = Self::one();
        while !NumberTests::is_zero(&me) {
            if NumberTests::is_even(&me) {
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

pub trait Samplable {
    fn sample_below(upper: &Self) -> Self;
    fn sample(bitsize: usize) -> Self;
}

pub trait PrimeNumbers {
    fn sample_prime(bitsize: usize) -> Self;
}

pub trait ConvertFrom<T> {
    fn _from(&T) -> Self;
}
