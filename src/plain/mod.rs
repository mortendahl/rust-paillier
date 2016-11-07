use std::ops::{Add, Sub, Mul, Div, Rem};
use num_traits::{One};
use arithimpl::traits::*;
use arithimpl::primes::*;
use phe::*;
use rand::OsRng;



#[derive(Debug,Clone)]
pub struct PlainEncryptionKey<I> {
    pub n: I,  // the modulus
    nn: I,     // the modulus squared
    g: I,      // the generator, fixed at g = n + 1
}

impl<I> PlainEncryptionKey<I>
where
    I: Clone,
    I: One,
    for<'a, 'b> &'a I: Mul<&'b I, Output=I>,
    for<'a, 'b> &'a I: Add<&'b I, Output=I>
{
    pub fn from(modulus: &I) -> PlainEncryptionKey<I> {
        PlainEncryptionKey {
            n: modulus.clone(),
            nn: modulus * modulus,
            g: modulus + &I::one()
        }
    }
}

#[derive(Debug,Clone)]
pub struct PlainDecryptionKey<I> {
    pub p: I,  // first prime
    pub q: I,  // second prime
    pub n: I,  // the modulus (also in public key)
    nn: I,     // the modulus squared
    lambda: I, // fixed at lambda = (p-1)*(q-1)
    mu: I,     // fixed at lambda^{-1}
}

impl<I> PlainDecryptionKey<I>
where
    I: Clone,
    I: One + ModularArithmetic + Mul<Output=I>,
    for<'a>    &'a I: Mul<I, Output=I>,
    for<'a,'b> &'a I: Mul<&'b I, Output=I>,
    for<'a,'b> &'a I: Div<&'b I, Output=I>,
    for<'a,'b> &'a I: Add<&'b I, Output=I>,
    for<'a,'b> &'a I: Sub<&'b I, Output=I>,
    for<'a,'b> &'a I: Rem<&'b I, Output=I>
{
    pub fn from(p: &I, q: &I) -> PlainDecryptionKey<I> {
        let ref one = I::one();
        let modulus = p * q;
        let nn = &modulus * &modulus;
        let lambda = (p - one) * (q - one);
        let mu = I::modinv(&lambda, &modulus);
        PlainDecryptionKey {
            p: p.clone(),
            q: q.clone(),
            n: modulus,
            nn: nn,
            lambda: lambda,
            mu: mu,
        }
    }
}

pub struct AbstractPlainPaillier<I> {
    junk: ::std::marker::PhantomData<I>
}

impl <I> PartiallyHomomorphicScheme for AbstractPlainPaillier<I>
where
    // I: From<usize>,
    I: Samplable,
    I: One + ModularArithmetic,
    for<'a,'b> &'a I: Add<&'b I, Output=I>,
    for<'a>    &'a I: Sub<I, Output=I>,
    for<'a,'b> &'a I: Sub<&'b I, Output=I>,
    for<'a>    &'a I: Mul<I, Output=I>,
    for<'b>        I: Mul<&'b I, Output=I>,
    for<'a,'b> &'a I: Mul<&'b I, Output=I>,
    for<'b>        I: Div<&'b I, Output=I>,
    for<'a,'b> &'a I: Div<&'b I, Output=I>,
    for<'a>        I: Rem<&'a I, Output=I>,
    for<'a,'b> &'a I: Rem<&'b I, Output=I>
{

    type Plaintext = I;
    type Ciphertext = I;
    type EncryptionKey = PlainEncryptionKey<I>;
    type DecryptionKey = PlainDecryptionKey<I>;

    fn encrypt(ek: &Self::EncryptionKey, m: &Self::Plaintext) -> Self::Ciphertext {
        let ref gx = I::modpow(&ek.g, &m, &ek.nn);
        Self::rerandomise(ek, gx)
    }

    fn decrypt(dk: &Self::DecryptionKey, c: &Self::Ciphertext) -> Self::Plaintext {
        let ref u = I::modpow(&c, &dk.lambda, &dk.nn);
        ((u - I::one()) / &dk.n * &dk.mu) % &dk.n
    }

    fn add(ek: &Self::EncryptionKey, c1: &Self::Ciphertext, c2: &Self::Ciphertext) -> Self::Ciphertext {
        (c1 * c2) % &ek.nn
    }

    fn mult(ek: &Self::EncryptionKey, c1: &Self::Ciphertext, m2: &Self::Plaintext) -> Self::Ciphertext {
        I::modpow(c1, m2, &ek.nn)
    }

    fn rerandomise(ek: &Self::EncryptionKey, c: &Self::Ciphertext) -> Self::Ciphertext {
        let ref r = I::sample_below(&ek.n);
        (c * I::modpow(r, &ek.n, &ek.nn)) % &ek.nn
    }

}

#[cfg(test)]
mod tests {

    use phe::PartiallyHomomorphicScheme as PHE;
    use PlainPaillier as Plain;
    use phe::KeyGeneration as KeyGen;

    fn test_keypair() -> (<Plain as PHE>::EncryptionKey, <Plain as PHE>::DecryptionKey) {
        <Plain as KeyGen>::keypair(2048)
    }

    fn test_keypair_sized(bitsize: usize) -> (<Plain as PHE>::EncryptionKey, <Plain as PHE>::DecryptionKey) {
        <Plain as KeyGen>::keypair(bitsize)
    }

    fn test_keypair_sized_safe(bitsize: usize) -> (<Plain as PHE>::EncryptionKey, <Plain as PHE>::DecryptionKey) {
        <Plain as KeyGen>::keypair_safe(bitsize)
    }

    #[test]
    fn test_correct_keygen_512() {
        let (ek, dk) = test_keypair_sized(4096);
        println!("p: {:?}", dk.p);
        println!("q: {:?}", dk.q);
        let m = <Plain as PHE>::Plaintext::from(10);
        let c = Plain::encrypt(&ek, &m);

        let recovered_m = Plain::decrypt(&dk, &c);
        assert_eq!(recovered_m, m);
    }

#[test]
    fn test_correct_keygen_512_safe() {
        let (ek, dk) = test_keypair_sized_safe(512);
        
        let m = <Plain as PHE>::Plaintext::from(10);
        let c = Plain::encrypt(&ek, &m);

        let recovered_m = Plain::decrypt(&dk, &c);
        assert_eq!(recovered_m, m);
    }

    #[test]
    fn test_correct_encryption_decryption() {
        let (ek, dk) = test_keypair();

        let m = <Plain as PHE>::Plaintext::from(10);
        let c = Plain::encrypt(&ek, &m);

        let recovered_m = Plain::decrypt(&dk, &c);
        assert_eq!(recovered_m, m);
    }

    #[test]
    fn test_correct_addition() {
        let (ek, dk) = test_keypair();

        let m1 = <Plain as PHE>::Plaintext::from(10);
        let c1 = Plain::encrypt(&ek, &m1);
        let m2 = <Plain as PHE>::Plaintext::from(20);
        let c2 = Plain::encrypt(&ek, &m2);

        let c = Plain::add(&ek, &c1, &c2);
        let m = Plain::decrypt(&dk, &c);
        assert_eq!(m, m1 + m2);
    }

    #[test]
    fn test_correct_multiplication() {
        let (ek, dk) = test_keypair();

        let m1 = <Plain as PHE>::Plaintext::from(10);
        let c1 = Plain::encrypt(&ek, &m1);
        let m2 = <Plain as PHE>::Plaintext::from(20);

        let c = Plain::mult(&ek, &c1, &m2);
        let m = Plain::decrypt(&dk, &c);
        assert_eq!(m, m1 * m2);
    }

}

#[cfg(feature="keygen")]
impl <I> KeyGeneration for AbstractPlainPaillier<I>
where
    I: From<u64>,
    I: ::std::str::FromStr, <I as ::std::str::FromStr>::Err: ::std::fmt::Debug,
    I: Clone,
    I: Samplable,
    I: ModularArithmetic,
    I: PrimeNumbers,
                   I: Mul<Output=I>,
    for<'a>    &'a I: Mul<I, Output=I>,
    for<'b>        I: Mul<&'b I, Output=I>,
    for<'a,'b> &'a I: Mul<&'b I, Output=I>,
    for<'a,'b> &'a I: Add<&'b I, Output=I>,
    for<'a>    &'a I: Sub<I, Output=I>,
    for<'a,'b> &'a I: Sub<&'b I, Output=I>,
    for<'b>        I: Div<&'b I, Output=I>,
    for<'a,'b> &'a I: Div<&'b I, Output=I>,
    for<'a>        I: Rem<&'a I, Output=I>,
    for<'a,'b> &'a I: Rem<&'b I, Output=I>
{

    type EncryptionKey = PlainEncryptionKey<I>;
    type DecryptionKey = PlainDecryptionKey<I>;

    fn keypair(bit_length: usize) -> (Self::EncryptionKey, Self::DecryptionKey) {

        let p = I::sample_prime(bit_length/2);
        let q = I::sample_prime(bit_length/2);
        let n = &p * &q;
        let ek = PlainEncryptionKey::from(&n);
        let dk = PlainDecryptionKey::from(&p, &q);
        (ek, dk)
        
    }


    fn keypair_safe(bit_length: usize) -> (Self::EncryptionKey, Self::DecryptionKey) {
    
        let p = I::sample_safe_prime(bit_length);
        let q = I::sample_safe_prime(bit_length);
        let n = &p * &q;
        let ek = PlainEncryptionKey::from(&n);
        let dk = PlainDecryptionKey::from(&p, &q);
        (ek, dk)
    
    }

}
