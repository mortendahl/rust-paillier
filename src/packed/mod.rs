
use plain;
use plain::AbstractScheme as PlainAbstractScheme;

#[cfg(feature="keygen")]
use plain::KeyGeneration as PlainKeyGeneration;

#[derive(Debug,Clone)]
pub struct EncryptionKey<I> {
    underlying_ek: plain::EncryptionKey<I>,
    component_count: usize,
    component_size: usize,  // in bits
}

impl <I> EncryptionKey<I> {
    pub fn from(underlying_ek: plain::EncryptionKey<I>,
                component_count: usize,
                component_size: usize)
                -> EncryptionKey<I> {
        // assert!(component_size * component_count <= plain_ek.n.bits());
        // assert!(component_size * component_count <= underlying_ek.n.bit_length() as usize); // TODO
        assert!(component_size <= 64);
        EncryptionKey {
            underlying_ek: underlying_ek,
            component_size: component_size,
            component_count: component_count,
        }
    }
}


#[derive(Debug,Clone)]
pub struct DecryptionKey<I> {
    underlying_dk: plain::DecryptionKey<I>,
    component_count: usize,
    component_size: usize,  // in bits
}

impl <I> DecryptionKey<I> {
    pub fn from(underlying_dk: plain::DecryptionKey<I>,
                component_count: usize,
                component_size: usize)
                -> DecryptionKey<I> {
        assert!(component_size <= 64);
        DecryptionKey {
            underlying_dk: underlying_dk,
            component_size: component_size,
            component_count: component_count,
        }
    }
}

use std::marker::PhantomData;

#[derive(Debug,Clone,PartialEq)]
pub struct Plaintext<I, T> {
    pub data: Vec<T>,
    _phantom: PhantomData<I>
}

impl <I, T> From<T> for Plaintext<I, T>
where
    I: From<T>,
    T: Clone
{
    fn from(x: T) -> Self {
        Plaintext { data: vec![x.clone()], _phantom: PhantomData }
    }
}

impl <I, T> From<Vec<T>> for Plaintext<I, T>
where
    I : From<T>,
    T : Clone,
{
    fn from(x: Vec<T>) -> Self {
        Plaintext { data: x.clone(), _phantom: PhantomData }
    }
}

// impl <T : Clone> From<[T]> for Plaintext<T> {
//     fn from(x: [T]) -> Self {
//         Plaintext(x.to_vec())
//     }
// }


#[derive(Debug,Clone)]
pub struct Ciphertext<I, T> {
    pub data: plain::Ciphertext<I>,
    _phantom: PhantomData<T>
}


use std::ops::{Sub, Mul, Div};
use std::ops::{Add, Shl, Shr, Rem};
use num_traits::{One};
use arithimpl::traits::*;

#[cfg(feature="keygen")]
use arithimpl::primes::*;

pub struct Scheme<BigInteger, ComponentType> {
    junk: ::std::marker::PhantomData<(BigInteger, ComponentType)>
}

pub trait AbstractScheme
{
    type BigInteger;
    type ComponentType;

    fn encrypt( ek: &EncryptionKey<Self::BigInteger>,
                ms: &Plaintext<Self::BigInteger, Self::ComponentType>)
                -> Ciphertext<Self::BigInteger, Self::ComponentType>;

    fn decrypt( dk: &DecryptionKey<Self::BigInteger>,
                c: &Ciphertext<Self::BigInteger, Self::ComponentType>)
                -> Plaintext<Self::BigInteger, Self::ComponentType>;

    fn add( ek: &EncryptionKey<Self::BigInteger>,
            c1: &Ciphertext<Self::BigInteger, Self::ComponentType>,
            c2: &Ciphertext<Self::BigInteger, Self::ComponentType>)
            -> Ciphertext<Self::BigInteger, Self::ComponentType>;

    fn mult(ek: &EncryptionKey<Self::BigInteger>,
            c1: &Ciphertext<Self::BigInteger, Self::ComponentType>,
            m2: &Self::ComponentType)
            -> Ciphertext<Self::BigInteger, Self::ComponentType>;

    fn rerandomise(ek: &EncryptionKey<Self::BigInteger>,
                    c: &Ciphertext<Self::BigInteger, Self::ComponentType>)
                    -> Ciphertext<Self::BigInteger, Self::ComponentType>;
}

impl <I, T> AbstractScheme for Scheme<I, T>
where
    // regarding ComponentType
            T: Clone,
            T: One,
            T: Shl<usize, Output=T>,
    for<'b> T: ConvertFrom<I>,
    // regarding I
    I: From<T>,
    I: One,
    I: Samplable,
    I: ModularArithmetic,
                    I: Add<Output=I>,
    for<'a,'b> &'a  I: Add<&'b I, Output=I>,
    for<'a>    &'a  I: Sub<I, Output=I>,
    for<'a,'b> &'a  I: Sub<&'b I, Output=I>,
    for<'a>    &'a  I: Mul<I, Output=I>,
    for<'b>         I: Mul<&'b I, Output=I>,
    for<'a,'b> &'a  I: Mul<&'b I, Output=I>,
    for<'b>         I: Div<&'b I, Output=I>,
    for<'a,'b> &'a  I: Div<&'b I, Output=I>,
                    I: Rem<Output=I>,
    for<'a>         I: Rem<&'a I, Output=I>,
    for<'a,'b> &'a  I: Rem<&'b I, Output=I>,
                    I: Shl<usize, Output=I>,
                    I: Shr<usize, Output=I>,
    for<'a> &'a     I: Shr<usize, Output=I>,
{

    type BigInteger = I;
    type ComponentType = T;

    fn encrypt(ek: &EncryptionKey<I>, ms: &Plaintext<I, T>) -> Ciphertext<I, T> {
        let plaintexts: &Vec<T> = &ms.data;
        assert!(plaintexts.len() == ek.component_count);
        let mut packed_plaintexts: I = I::from(plaintexts[0].clone());
        for plaintext in &plaintexts[1..] {
            packed_plaintexts = packed_plaintexts << ek.component_size;
            packed_plaintexts = packed_plaintexts + I::from(plaintext.clone());
        }
        let c: plain::Ciphertext<I> = plain::Scheme::encrypt(
            &ek.underlying_ek,
            &plain::Plaintext(packed_plaintexts));
        Ciphertext { data: c, _phantom: PhantomData }
    }

    fn decrypt(dk: &DecryptionKey<I>, c: &Ciphertext<I, T>) -> Plaintext<I, T> {
        let mut packed_plaintext: I = plain::Scheme::decrypt(&dk.underlying_dk, &c.data).0;
        let raw_mask: T = T::one() << dk.component_size;
        let mask: I = I::from(raw_mask.clone());
        let mut result: Vec<T> = vec![];
        for _ in 0..dk.component_count {
            let slot_value = &packed_plaintext % &mask;
            let foo = T::_from(&slot_value);
            result.push(foo);
            packed_plaintext = &packed_plaintext >> dk.component_size;
        }
        result.reverse();
        Plaintext { data: result, _phantom: PhantomData }
    }

    fn add(ek: &EncryptionKey<I>, c1: &Ciphertext<I, T>, c2: &Ciphertext<I, T>) -> Ciphertext<I, T> {
        let c: plain::Ciphertext<I> = plain::Scheme::add(&ek.underlying_ek, &c1.data, &c2.data);
        Ciphertext { data: c, _phantom: PhantomData }
    }

    fn mult(ek: &EncryptionKey<I>, c1: &Ciphertext<I, T>, m2: &T) -> Ciphertext<I, T> {
        let scalar = plain::Plaintext(I::from(m2.clone()));
        let c: plain::Ciphertext<I> = plain::Scheme::mult(&ek.underlying_ek, &c1.data, &scalar);
        Ciphertext { data: c, _phantom: PhantomData }
    }

    fn rerandomise(ek: &EncryptionKey<I>, c: &Ciphertext<I, T>) -> Ciphertext<I, T> {
        let d: plain::Ciphertext<I> = plain::Scheme::rerandomise(&ek.underlying_ek, &c.data);
        Ciphertext { data: d, _phantom: PhantomData }
    }

}


pub trait Encode<T>
{
    type I;
    fn encode(x: T) -> Plaintext<Self::I, T>;
}

impl <I, T> Encode<T> for Scheme<I, T>
where
    Plaintext<I, T> : From<T>,
{
    type I = I;
    fn encode(x: T) -> Plaintext<I, T> {
        Plaintext::from(x)
    }
}


pub trait KeyGeneration<I>
{
    fn keypair(bit_length: usize, component_count: usize, component_size: usize) -> (EncryptionKey<I>, DecryptionKey<I>);
}

#[cfg(feature="keygen")]
impl <I, T> KeyGeneration<I> for Scheme<I, T>
where
    I: From<u64>,
    I: ::std::str::FromStr, <I as ::std::str::FromStr>::Err: ::std::fmt::Debug,
    I: Clone,
    I: Samplable,
    I: ModularArithmetic,
    I: One,
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
    fn keypair(bit_length: usize, component_count: usize, component_size: usize) -> (EncryptionKey<I>, DecryptionKey<I>) {
        let (plain_ek, plain_dk) = plain::Scheme::keypair(bit_length);
        let ek = EncryptionKey::from(plain_ek, component_count, component_size);
        let dk = DecryptionKey::from(plain_dk, component_count, component_size);
        (ek, dk)
    }
}


bigint!(I,
#[cfg(test)]
mod tests {

    use super::I;
    use ::packed::*;

    fn test_keypair() -> (EncryptionKey<I>, DecryptionKey<I>) {
        //1024 bits prime
        let p = str::parse("148677972634832330983979593310074301486537017973460461278300587514468301043894574906886127642530475786889672304776052879927627556769456140664043088700743909632312483413393134504352834240399191134336344285483935856491230340093391784574980688823380828143810804684752914935441384845195613674104960646037368551517").unwrap();
        let q = str::parse("158741574437007245654463598139927898730476924736461654463975966787719309357536545869203069369466212089132653564188443272208127277664424448947476335413293018778018615899291704693105620242763173357203898195318179150836424196645745308205164116144020613415407736216097185962171301808761138424668335445923774195463").unwrap();

        let n = &p * &q;
        let plain_ek = ::plain::EncryptionKey::from(&n);
        let plain_dk = ::plain::DecryptionKey::from(&p, &q);

        let ek = EncryptionKey::from(plain_ek, 3, 10);
        let dk = DecryptionKey::from(plain_dk, 3, 10);
        (ek, dk)
    }

    #[test]
    fn test_correct_encryption_decryption() {
        let (ek, dk) = test_keypair();

        let m: Plaintext<I, u64> = Plaintext::from(vec![1, 2, 3]);
        let c = Scheme::encrypt(&ek, &m);

        let recovered_m = Scheme::decrypt(&dk, &c);
        assert_eq!(recovered_m, m);
    }

    #[test]
    fn test_correct_addition() {
        let (ek, dk) = test_keypair();

        let m1 = Plaintext::from(vec![1, 2, 3]);
        let c1 = Scheme::encrypt(&ek, &m1);
        let m2 = Plaintext::from(vec![1, 2, 3]);
        let c2 = Scheme::encrypt(&ek, &m2);

        let c = Scheme::add(&ek, &c1, &c2);
        let m: Plaintext<I, u64> = Scheme::decrypt(&dk, &c);
        assert_eq!(m.data, vec![2, 4, 6]);
    }

    #[test]
    fn test_correct_multiplication() {
        let (ek, dk) = test_keypair();

        let m1: Plaintext<I, u64> = Plaintext::from(vec![1, 2, 3]);
        let c1 = Scheme::encrypt(&ek, &m1);
        let m2 = 4;

        let c = Scheme::mult(&ek, &c1, &m2);
        let m = Scheme::decrypt(&dk, &c);
        assert_eq!(m.data, vec![4, 8, 12]);
    }

});
