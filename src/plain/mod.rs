use std::ops::{Add, Sub, Mul, Div, Rem};
use num_traits::{One};
use arithimpl::traits::*;
use phe::*;
//use rand::OsRng;



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
    I: One,
    I: ModularArithmetic,
                   I: Mul<Output=I>,
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
    I: One,
    I: Samplable,
    I: ModularArithmetic,
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

    #[cfg(feature="keygen")]
    use phe::KeyGeneration as KeyGen;

    fn test_keypair() -> (<Plain as PHE>::EncryptionKey, <Plain as PHE>::DecryptionKey) {
        let p = str::parse("148677972634832330983979593310074301486537017973460461278300587514468301043894574906886127642530475786889672304776052879927627556769456140664043088700743909632312483413393134504352834240399191134336344285483935856491230340093391784574980688823380828143810804684752914935441384845195613674104960646037368551517").unwrap();
        let q = str::parse("158741574437007245654463598139927898730476924736461654463975966787719309357536545869203069369466212089132653564188443272208127277664424448947476335413293018778018615899291704693105620242763173357203898195318179150836424196645745308205164116144020613415407736216097185962171301808761138424668335445923774195463").unwrap();
        let n = &p * &q;
        let ek = <Plain as PHE>::EncryptionKey::from(&n);
        let dk = <Plain as PHE>::DecryptionKey::from(&p, &q);
        (ek, dk)
    }

    #[cfg(feature="keygen")]
    fn test_keypair_sized(bitsize: usize) -> (<Plain as PHE>::EncryptionKey, <Plain as PHE>::DecryptionKey) {
        <Plain as KeyGen>::keypair(bitsize)
    }


    #[cfg(feature="keygen")]
    #[test]
    fn test_correct_keygen() {
        let (ek, dk) = test_keypair_sized(2048);
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
use arithimpl::primes::*;

#[cfg(feature="keygen")]
impl <I> KeyGeneration for AbstractPlainPaillier<I>
where
    I: From<u64>,
    I: ::std::str::FromStr, <I as ::std::str::FromStr>::Err: ::std::fmt::Debug,
    I: Clone,
    I: Samplable,
    I: ModularArithmetic,
    I: PrimeSampable,
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
}
