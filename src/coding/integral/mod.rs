//! Integral code supporting both scalars and vectors.

use ::core::{RawPlaintext, RawCiphertext};
use ::traits::*;
use ::BigInteger as BigInt;
use ::Paillier as Paillier;
use arithimpl::traits::ConvertFrom;

use std::marker::PhantomData;

/// Representation of unencrypted integral scalar.
#[derive(Debug,Clone,PartialEq)]
pub struct ScalarPlaintext<T> {
    pub data: RawPlaintext,
    pub _phantom: PhantomData<T>
}

/// Representation of encrypted integral scalar.
#[derive(Debug,Clone)]
pub struct ScalarCiphertext<T> {
    pub data: RawCiphertext,
    pub _phantom: PhantomData<T>
}

impl From<u8> for ScalarPlaintext<u8> {
    fn from(x: u8) -> ScalarPlaintext<u8> {
        ScalarPlaintext {
            data: RawPlaintext(BigInt::from(x as u32)),
            _phantom: PhantomData,
        }
    }
}

impl From<u16> for ScalarPlaintext<u16> {
    fn from(x: u16) -> ScalarPlaintext<u16> {
        ScalarPlaintext {
            data: RawPlaintext(BigInt::from(x as u32)),
            _phantom: PhantomData,
        }
    }
}

impl From<u32> for ScalarPlaintext<u32> {
    fn from(x: u32) -> ScalarPlaintext<u32> {
        ScalarPlaintext {
            data: RawPlaintext(BigInt::from(x)),
            _phantom: PhantomData,
        }
    }
}

impl From<u64> for ScalarPlaintext<u64> {
    fn from(x: u64) -> ScalarPlaintext<u64> {
        ScalarPlaintext {
            data: RawPlaintext(BigInt::from(x)),
            _phantom: PhantomData,
        }
    }
}

impl Into<u8> for ScalarPlaintext<u8> {
    fn into(self) -> u8 {
        u8::_from(&self.data.0)
    }
}

impl Into<u16> for ScalarPlaintext<u16> {
    fn into(self) -> u16 {
        u16::_from(&self.data.0)
    }
}

impl Into<u32> for ScalarPlaintext<u32> {
    fn into(self) -> u32 {
        u32::_from(&self.data.0)
    }
}

impl Into<u64> for ScalarPlaintext<u64> {
    fn into(self) -> u64 {
        u64::_from(&self.data.0)
    }
}

// TODO[Morten] need to encode signed integers better -- use n/2 as zero?

impl From<i8> for ScalarPlaintext<i8> {
    fn from(x: i8) -> ScalarPlaintext<i8> {
        ScalarPlaintext {
            data: RawPlaintext(BigInt::from(x as i32)),
            _phantom: PhantomData,
        }
    }
}

impl From<i16> for ScalarPlaintext<i16> {
    fn from(x: i16) -> ScalarPlaintext<i16> {
        ScalarPlaintext {
            data: RawPlaintext(BigInt::from(x as i32)),
            _phantom: PhantomData,
        }
    }
}

impl From<i32> for ScalarPlaintext<i32> {
    fn from(x: i32) -> ScalarPlaintext<i32> {
        ScalarPlaintext {
            data: RawPlaintext(BigInt::from(x)),
            _phantom: PhantomData,
        }
    }
}

impl From<i64> for ScalarPlaintext<i64> {
    fn from(x: i64) -> ScalarPlaintext<i64> {
        ScalarPlaintext {
            data: RawPlaintext(BigInt::from(x)),
            _phantom: PhantomData,
        }
    }
}

impl Into<i8> for ScalarPlaintext<i8> {
    fn into(self) -> i8 {
        i8::_from(&self.data.0)
    }
}

impl Into<i16> for ScalarPlaintext<i16> {
    fn into(self) -> i16 {
        i16::_from(&self.data.0)
    }
}

impl Into<i32> for ScalarPlaintext<i32> {
    fn into(self) -> i32 {
        i32::_from(&self.data.0)
    }
}

impl Into<i64> for ScalarPlaintext<i64> {
    fn into(self) -> i64 {
        i64::_from(&self.data.0)
    }
}

 /// Representation of unencrypted integral vector.
#[derive(Clone,Debug,PartialEq)]
pub struct VectorPlaintext<T> {
    pub data: RawPlaintext,
    pub component_count: usize,
    pub _phantom: PhantomData<T>,
}

/// Representation of encrypted integral vector.
#[derive(Clone,Debug)]
pub struct VectorCiphertext<T> {
    pub data: RawCiphertext,
    pub component_count: usize,
    pub _phantom: PhantomData<T>,
}

impl<EK, T> Encrypt<EK, T, ScalarCiphertext<T>> for Paillier
where 
    ScalarPlaintext<T>: From<T>,
    for<'m> Self: Encrypt<EK, &'m RawPlaintext, RawCiphertext>
{
    fn encrypt(ek: &EK, m: T) -> ScalarCiphertext<T> {
        let raw = ScalarPlaintext::from(m).data;
        ScalarCiphertext {
            data: Self::encrypt(ek, &raw),
            _phantom: PhantomData,
        }
    }
}

impl<'c, DK, T> Decrypt<DK, &'c ScalarCiphertext<T>, T> for Paillier
where 
    ScalarPlaintext<T>: Into<T>,
    Self: Decrypt<DK, &'c RawCiphertext, RawPlaintext>,
{
    fn decrypt(dk: &DK, c: &'c ScalarCiphertext<T>) -> T {
        let m: ScalarPlaintext<_> =  ScalarPlaintext {
            data: Self::decrypt(dk, &c.data),
            _phantom: PhantomData
        };
        m.into()
    }
}

impl<'c, EK, T> Rerandomize<EK, &'c ScalarCiphertext<T>, ScalarCiphertext<T>> for Paillier
where Self: Rerandomize<EK, &'c RawCiphertext, RawCiphertext>,
{
    fn rerandomise(ek: &EK, c: &'c ScalarCiphertext<T>) -> ScalarCiphertext<T> {
        let core_ciphertext: RawCiphertext = Self::rerandomise(ek, &c.data);
        ScalarCiphertext {
            data: core_ciphertext,
            _phantom: PhantomData
        }
    }
}

impl<'c1, 'c2, EK, T> Add<EK, &'c1 ScalarCiphertext<T>, &'c2 ScalarCiphertext<T>, ScalarCiphertext<T>> for Paillier
where Self: Add<EK, &'c1 RawCiphertext, &'c2 RawCiphertext, RawCiphertext> 
{
    fn add(ek: &EK, c1: &'c1 ScalarCiphertext<T>, c2: &'c2 ScalarCiphertext<T>) -> ScalarCiphertext<T> {
        ScalarCiphertext {
            data: Self::add(ek, &c1.data, &c2.data),
            _phantom: PhantomData
        }
    }
}

impl<'c1, 'm2, EK, T> Add<EK, &'c1 ScalarCiphertext<T>, &'m2 ScalarPlaintext<T>, ScalarCiphertext<T>> for Paillier
where
    Self: Encrypt<EK, &'m2 ScalarPlaintext<T>, ScalarCiphertext<T>>,
    for<'c2> Self: Add<EK, &'c1 ScalarCiphertext<T>, &'c2 ScalarCiphertext<T>, ScalarCiphertext<T>>,
{
    fn add(ek: &EK, c1: &'c1 ScalarCiphertext<T>, m2: &'m2 ScalarPlaintext<T>) -> ScalarCiphertext<T> {
        Self::add(ek, c1, &Self::encrypt(ek, m2))
    }
}

impl<'m1, 'c2, EK, T> Add<EK, &'m1 ScalarPlaintext<T>, &'c2 ScalarCiphertext<T>, ScalarCiphertext<T>> for Paillier
where 
    Self: Encrypt<EK, &'m1 ScalarPlaintext<T>, ScalarCiphertext<T>>,
    for<'c1> Self: Add<EK, &'c1 ScalarCiphertext<T>, &'c2 ScalarCiphertext<T>, ScalarCiphertext<T>>,
{
    fn add(ek: &EK, m1: &'m1 ScalarPlaintext<T>, c2: &'c2 ScalarCiphertext<T>) -> ScalarCiphertext<T> {
        Self::add(ek, &Self::encrypt(ek, m1), c2)
    }
}

impl<'c1, EK, T> Add<EK, &'c1 ScalarCiphertext<T>, T, ScalarCiphertext<T>> for Paillier
where 
    ScalarPlaintext<T>: From<T>,
    for<'m2> Self: Add<EK, &'c1 ScalarCiphertext<T>, &'m2 ScalarPlaintext<T>, ScalarCiphertext<T>>,
{
    fn add(ek: &EK, c1: &'c1 ScalarCiphertext<T>, m2: T) -> ScalarCiphertext<T> {
        Self::add(ek, c1, &ScalarPlaintext::from(m2))
    }
}

impl<'c2, EK, T> Add<EK, T, &'c2 ScalarCiphertext<T>, ScalarCiphertext<T>> for Paillier
where 
    ScalarPlaintext<T>: From<T>,
    for<'m1> Self: Add<EK, &'m1 ScalarPlaintext<T>, &'c2 ScalarCiphertext<T>, ScalarCiphertext<T>>,
{
    fn add(ek: &EK, m1: T, c2: &'c2 ScalarCiphertext<T>) -> ScalarCiphertext<T> {
        Self::add(ek, &ScalarPlaintext::from(m1), c2)
    }
}

impl<'c1, 'm2, EK, T> Mul<EK, &'c1 ScalarCiphertext<T>, &'m2 ScalarPlaintext<T>, ScalarCiphertext<T>> for Paillier
where Self: Mul<EK, &'c1 RawCiphertext, &'m2 RawPlaintext, RawCiphertext>
{
    fn mul(ek: &EK, c1: &'c1 ScalarCiphertext<T>, m2: &'m2 ScalarPlaintext<T>) -> ScalarCiphertext<T> {
        ScalarCiphertext {
            data: Self::mul(ek, &c1.data, &m2.data),
            _phantom: PhantomData
        }
    }
}

impl<'m1, 'c2, EK, T> Mul<EK, &'m1 ScalarPlaintext<T>, &'c2 ScalarCiphertext<T>, ScalarCiphertext<T>> for Paillier
where Self: Mul<EK, &'m1 RawPlaintext, &'c2 RawCiphertext, RawCiphertext>
{
    fn mul(ek: &EK, m1: &'m1 ScalarPlaintext<T>, c2: &'c2 ScalarCiphertext<T>) -> ScalarCiphertext<T> {
        ScalarCiphertext {
            data: Self::mul(ek, &m1.data, &c2.data),
            _phantom: PhantomData
        }
    }
}

impl<'c1, EK, T> Mul<EK, &'c1 ScalarCiphertext<T>, T, ScalarCiphertext<T>> for Paillier
where 
    ScalarPlaintext<T>: From<T>,
    for<'m2> Self: Mul<EK, &'c1 ScalarCiphertext<T>, &'m2 ScalarPlaintext<T>, ScalarCiphertext<T>>,
{
    fn mul(ek: &EK, c1: &'c1 ScalarCiphertext<T>, m2: T) -> ScalarCiphertext<T> {
        let m2_encoded = ScalarPlaintext::from(m2);
        Self::mul(ek, c1, &m2_encoded)
    }
}

impl<'c2, EK, T> Mul<EK, T, &'c2 ScalarCiphertext<T>, ScalarCiphertext<T>> for Paillier
where 
    ScalarPlaintext<T>: From<T>,
    for<'m1> Paillier: Mul<EK, &'m1 ScalarPlaintext<T>, &'c2 ScalarCiphertext<T>, ScalarCiphertext<T>>,
{
    fn mul(ek: &EK, m1: T, c2: &'c2 ScalarCiphertext<T>) -> ScalarCiphertext<T> {
        Self::mul(ek, &ScalarPlaintext::from(m1), c2)
    }
}


mod tests {

    use super::*;
    use core::Keypair;
    use traits::*;
    use ::Paillier;

    fn test_keypair() -> Keypair {
        let p = str::parse("148677972634832330983979593310074301486537017973460461278300587514468301043894574906886127642530475786889672304776052879927627556769456140664043088700743909632312483413393134504352834240399191134336344285483935856491230340093391784574980688823380828143810804684752914935441384845195613674104960646037368551517").unwrap();
        let q = str::parse("158741574437007245654463598139927898730476924736461654463975966787719309357536545869203069369466212089132653564188443272208127277664424448947476335413293018778018615899291704693105620242763173357203898195318179150836424196645745308205164116144020613415407736216097185962171301808761138424668335445923774195463").unwrap();
        Keypair {
            p: p,
            q: q,
        }
    }

    #[test]
    fn test_correct_encryption_decryption() {
        let (ek, dk) = test_keypair().keys();

        let m = 10;
        let c = Paillier::encrypt(&ek, m);

        let recovered_m = Paillier::decrypt(&dk, &c);
        assert_eq!(recovered_m, m);
    }

    #[test]
    fn test_correct_addition() {
        let (ek, dk) = test_keypair().keys();

        let c1 = Paillier::encrypt(&ek, 10);
        let c2 = Paillier::encrypt(&ek, 20);

        let c = Paillier::add(&ek, &c1, &c2);
        let m = Paillier::decrypt(&dk, &c);
        assert_eq!(m, 30);
    }

    #[test]
    fn correct_multiplication() {
        let (ek, dk) = test_keypair().keys();

        let c1 = Paillier::encrypt(&ek, 10);
        let c = Paillier::mul(&ek, &c1, 20);
        let m = Paillier::decrypt(&dk, &c);
        assert_eq!(m, 200);
    }

}