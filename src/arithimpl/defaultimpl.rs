use crate::arithimpl::traits::{NumberTests, EGCD};
use num_traits::{One, Zero};
use std::ops::{Add, Div, Mul, Neg, Rem, Shr, Sub};

fn modpow<I>(base: &I, exponent: &I, modulus: &I) -> I
where
    // TODO clean up
    I: Clone + Sized,
    I: Zero + One + Neg<Output = I> + NumberTests,
    for<'a> &'a I: Mul<I, Output = I>,
    for<'a, 'b> &'a I: Mul<&'b I, Output = I>,
    for<'a, 'b> &'a I: Div<&'b I, Output = I>,
    for<'a> I: Rem<&'a I, Output = I>,
    for<'a, 'b> &'a I: Rem<&'b I, Output = I>,
    for<'a, 'b> &'a I: Add<&'b I, Output = I>,
    I: Sub<I, Output = I>,
    for<'b> I: Sub<&'b I, Output = I>,
    for<'a, 'b> &'a I: Sub<&'b I, Output = I>,
    I: Shr<usize, Output = I>,
{
    let mut base = base.clone();
    let mut exponent = exponent.clone();
    let mut result = I::one();

    while !NumberTests::is_zero(&exponent) {
        if !NumberTests::is_even(&exponent) {
            result = (&result * &base) % modulus;
        }
        base = (&base * &base) % modulus; // waste one of these by having it here but code is simpler (tiny bit)
        exponent = exponent >> 1;
    }
    result
}

pub(crate) fn egcd<I>(a: &I, b: &I) -> (I, I, I)
where
    // TODO clean up
    I: EGCD,
    I: Clone,
    I: Sized,
    I: Zero + One,
    I: Neg<Output = I>,
    I: NumberTests,
    for<'a> &'a I: Mul<I, Output = I>,
    for<'a, 'b> &'a I: Mul<&'b I, Output = I>,
    for<'a, 'b> &'a I: Div<&'b I, Output = I>,
    for<'a> I: Rem<&'a I, Output = I>,
    for<'a, 'b> &'a I: Rem<&'b I, Output = I>,
    for<'a, 'b> &'a I: Add<&'b I, Output = I>,
    I: Sub<I, Output = I>,
    for<'b> I: Sub<&'b I, Output = I>,
    for<'a, 'b> &'a I: Sub<&'b I, Output = I>,
    I: Shr<usize, Output = I>,
{
    if NumberTests::is_zero(b) {
        (a.clone(), I::one(), I::zero())
    } else {
        let q = a / b;
        let r = a % b;
        let (d, s, t) = I::egcd(b, &r);
        let new_t = s - &t * q;
        (d, t, new_t)
    }
}

pub(crate) fn default_modinv<I>(a: &I, prime: &I) -> I
where
    I: EGCD,
    I: Clone + Sized,
    I: Zero + One + Neg<Output = I> + NumberTests,
    for<'a> &'a I: Mul<I, Output = I>,
    for<'a, 'b> &'a I: Mul<&'b I, Output = I>,
    for<'a, 'b> &'a I: Div<&'b I, Output = I>,
    for<'a> I: Rem<&'a I, Output = I>,
    for<'a, 'b> &'a I: Rem<&'b I, Output = I>,
    for<'a, 'b> &'a I: Add<&'b I, Output = I>,
    I: Sub<I, Output = I>,
    for<'b> I: Sub<&'b I, Output = I>,
    for<'a, 'b> &'a I: Sub<&'b I, Output = I>,
    I: Shr<usize, Output = I>,
{
    let r = a % prime;
    let ref d = if NumberTests::is_negative(&r) {
        let r = r.neg();
        -I::egcd(prime, &r).2
    } else {
        I::egcd(prime, &r).2
    };
    (prime + d) % prime
}
