use std::marker::Sized;

pub trait NumberTests {
    fn is_zero(&Self) -> bool;
    fn is_even(&Self) -> bool;
    fn is_negative(me: &Self) -> bool;
}

pub trait ModPow {
    fn modpow(base: &Self, exponent: &Self, modulus: &Self) -> Self;
}

pub trait ModMul {
    fn modmul(a: &Self, b: &Self, modulus: &Self) -> Self;
}

pub trait EGCD
where
    Self: Sized,
{
    fn egcd(a: &Self, b: &Self) -> (Self, Self, Self);
}

pub trait ModInv {
    fn modinv(a: &Self, prime: &Self) -> Self;
}

pub trait Samplable {
    fn sample_below(upper: &Self) -> Self;
    fn sample_range(lower: &Self, upper: &Self) -> Self;
    fn sample(bitsize: usize) -> Self;
}

pub trait BitManipulation {
    fn set_bit(self: &mut Self, bit: usize, bit_val: bool);
    fn test_bit(self: &Self, bit: usize) -> bool;
}

pub trait ConvertFrom<T> {
    fn _from(&T) -> Self;
}
