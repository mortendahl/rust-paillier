
pub trait ModularArithmetic {
    fn zero() -> Self;
    fn one() -> Self;

    fn modpow(x: &Self, exponent: &Self, modulus: &Self) -> Self;
    fn modinv(a: &Self, modulus: &Self) -> Self;
    fn egcd(a: &Self, b: &Self) -> (Self, Self, Self) where Self: Sized;
}

use std::ops::{Add, Sub, Mul};
pub trait Int : Add<Output=Self> + Sub<Output=Self> + Mul + Mul<Self, Output=Self> + ModularArithmetic + Clone {}

pub trait Samplable {
    fn sample(upper: &Self) -> Self;
}

pub trait PartiallyHomomorphicScheme {

    type Plaintext;
    type Ciphertext;
    type EncryptionKey;
    type DecryptionKey;

    fn encrypt(&Self::EncryptionKey, &Self::Plaintext) -> Self::Ciphertext;
    fn decrypt(&Self::DecryptionKey, &Self::Ciphertext) -> Self::Plaintext;

    fn rerandomise(&Self::EncryptionKey, &Self::Ciphertext) -> Self::Ciphertext;

    fn add(&Self::EncryptionKey, &Self::Ciphertext, &Self::Ciphertext) -> Self::Ciphertext;
    fn mult(&Self::EncryptionKey, &Self::Ciphertext, &Self::Plaintext) -> Self::Ciphertext;

}
