
pub trait Identities {
    fn _zero() -> Self;
    fn _one() -> Self;
}

pub trait ModularArithmetic {
    fn modpow(x: &Self, exponent: &Self, modulus: &Self) -> Self;
    fn modinv(a: &Self, modulus: &Self) -> Self;
    fn egcd(a: &Self, b: &Self) -> (Self, Self, Self) where Self: Sized;
}

use std::ops::{Add, Sub, Mul, Div, Rem};
pub trait Int where
    Self: Add<Self, Output=Self>,

    Self: Sub<Self, Output=Self>,
    for<'a> Self: Sub<&'a Self, Output=Self>,

    Self: Mul<Output=Self>,
    for<'a> &'a Self: Mul<Self, Output=Self>,
    for<'b> Self: Mul<&'b Self, Output=Self>,
    // for<'a> &'a Self: Mul<Self, Output=Self>,
    // for<'a, 'b> &'a Self: Mul<&'b Self, Output=Self>,

    Self: Div<Output=Self>,

    Self: Rem<Output=Self>,
    for<'a> Self: Rem<&'a Self, Output=Self>,

    Self: ModularArithmetic,
    Self: Clone
{}

pub trait Samplable {
    fn sample(upper: &Self) -> Self;
}

pub trait PartiallyHomomorphicScheme {
    type Plaintext : From<usize>;
    type Ciphertext;
    type EncryptionKey;
    type DecryptionKey;
    fn encrypt(&Self::EncryptionKey, &Self::Plaintext) -> Self::Ciphertext;
    fn decrypt(&Self::DecryptionKey, &Self::Ciphertext) -> Self::Plaintext;
    fn rerandomise(&Self::EncryptionKey, &Self::Ciphertext) -> Self::Ciphertext;
    fn add(&Self::EncryptionKey, &Self::Ciphertext, &Self::Ciphertext) -> Self::Ciphertext;
    fn mult(&Self::EncryptionKey, &Self::Ciphertext, &Self::Plaintext) -> Self::Ciphertext;
}

pub trait KeyGeneration {
    type EncryptionKey;
    type DecryptionKey;
    fn keypair(bit_length: usize) -> (Self::EncryptionKey, Self::DecryptionKey);
}
