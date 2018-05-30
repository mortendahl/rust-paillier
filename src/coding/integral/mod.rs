//! Integral code supporting both scalars and vectors.

use ::core;
use ::traits::*;
use ::BigInteger as BigInt;
use ::Paillier as Paillier;
use arithimpl::traits::ConvertFrom;

use std::marker::PhantomData;

/// Representation of unencrypted integral scalar.
#[derive(Debug,Clone,PartialEq)]
pub struct ScalarPlaintext<T> {
    pub data: core::Plaintext,
    pub _phantom: PhantomData<T>
}

/// Representation of encrypted integral scalar.
#[derive(Debug,Clone)]
pub struct ScalarCiphertext<T> {
    pub data: core::Ciphertext,
    pub _phantom: PhantomData<T>
}

impl<'t> From<&'t u32> for ScalarPlaintext<u32>
{
    fn from(x: &'t u32) -> ScalarPlaintext<u32> {
        ScalarPlaintext {
            data: core::Plaintext(BigInt::from(*x)),
            _phantom: PhantomData,
        }
    }
}

impl<'t> From<&'t u64> for ScalarPlaintext<u64>
{
    fn from(x: &'t u64) -> ScalarPlaintext<u64> {
        ScalarPlaintext {
            data: core::Plaintext(BigInt::from(*x)),
            _phantom: PhantomData,
        }
    }
}

impl<'t> From<&'t i32> for ScalarPlaintext<i32>
{
    fn from(x: &'t i32) -> ScalarPlaintext<i32> {
        ScalarPlaintext {
            data: core::Plaintext(BigInt::from(*x)),
            _phantom: PhantomData,
        }
    }
}

impl<'t> From<&'t i64> for ScalarPlaintext<i64>
{
    fn from(x: &'t i64) -> ScalarPlaintext<i64> {
        ScalarPlaintext {
            data: core::Plaintext(BigInt::from(*x)),
            _phantom: PhantomData,
        }
    }
}

impl Into<u8> for ScalarPlaintext<u8>
{
    fn into(self) -> u8 {
        u8::_from(&self.data.0)
    }
}

impl Into<u16> for ScalarPlaintext<u16>
{
    fn into(self) -> u16 {
        u16::_from(&self.data.0)
    }
}

impl Into<u32> for ScalarPlaintext<u32>
{
    fn into(self) -> u32 {
        u32::_from(&self.data.0)
    }
}

impl Into<u64> for ScalarPlaintext<u64>
{
    fn into(self) -> u64 {
        u64::_from(&self.data.0)
    }
}

impl Into<i8> for ScalarPlaintext<i8>
{
    fn into(self) -> i8 {
        i8::_from(&self.data.0)
    }
}

impl Into<i16> for ScalarPlaintext<i16>
{
    fn into(self) -> i16 {
        i16::_from(&self.data.0)
    }
}

impl Into<i32> for ScalarPlaintext<i32>
{
    fn into(self) -> i32 {
        i32::_from(&self.data.0)
    }
}

impl Into<i64> for ScalarPlaintext<i64>
{
    fn into(self) -> i64 {
        i64::_from(&self.data.0)
    }
}

pub mod vector
{
    use super::*;

    /// Representation of unencrypted integral vector.
    #[derive(Clone,Debug,PartialEq)]
    pub struct Plaintext<T> {
        pub data: core::Plaintext,
        pub component_count: usize,
        pub component_size: usize,  // in bits
        pub _phantom: PhantomData<T>,
    }

    /// Representation of encrypted integral vector.
    #[derive(Clone,Debug)]
    pub struct Ciphertext<T> {
        pub data: core::Ciphertext,
        pub component_count: usize,
        pub component_size: usize,  // in bits
        pub _phantom: PhantomData<T>,
    }
}

// NOTE[Morten]
// got rid of these to make API easier to use (no explicit typing needed)
//
// impl<EK, T> Encrypt<EK, ScalarPlaintext<T>, ScalarCiphertext<T>> for Paillier
// where Paillier: Encrypt<EK, core::Plaintext, core::Ciphertext>
// {
//     fn encrypt(ek: &EK, m: &ScalarPlaintext<T>) -> ScalarCiphertext<T> {
//         ScalarCiphertext {
//             data: Self::encrypt(ek, &m.data),
//             _phantom: PhantomData,
//         }
//     }
// }
//
// impl<EK, T> Encrypt<EK, T, ScalarCiphertext<T>> for Paillier
// where 
//     for<'a> ScalarPlaintext<T>: From<&'a T>,
//     Paillier: Encrypt<EK, ScalarPlaintext<T>, ScalarCiphertext<T>>,
// {
//     fn encrypt(ek: &EK, m: &T) -> ScalarCiphertext<T> {
//         let c = ScalarPlaintext::from(m);
//         Self::encrypt(ek, &c)
//     }
// }
//
// impl<DK, T> Decrypt<DK, ScalarCiphertext<T>, ScalarPlaintext<T>> for Paillier
// where Paillier: Decrypt<DK, core::Ciphertext, core::Plaintext>
// {
//     fn decrypt(dk: &DK, c: &ScalarCiphertext<T>) -> ScalarPlaintext<T> {
//         ScalarPlaintext {
//             data: Self::decrypt(dk, &c.data),
//             _phantom: PhantomData
//         }
//     }
// }
//
// impl<DK, T> Decrypt<DK, ScalarCiphertext<T>, T> for Paillier
// where 
//     ScalarPlaintext<T>: Into<T>,
//     Paillier: Decrypt<DK, ScalarCiphertext<T>, ScalarPlaintext<T>>,
// {
//     fn decrypt(dk: &DK, c: &ScalarCiphertext<T>) -> T {
//         let m: ScalarPlaintext<_> = Self::decrypt(dk, c);
//         m.into()
//     }
// }

impl<EK, T> Encrypt<EK, T, ScalarCiphertext<T>> for Paillier
where 
    for<'a> ScalarPlaintext<T>: From<&'a T>,
    Paillier: Encrypt<EK, core::Plaintext, core::Ciphertext>
{
    fn encrypt(ek: &EK, m: &T) -> ScalarCiphertext<T> {
        ScalarCiphertext {
            data: Self::encrypt(ek, &ScalarPlaintext::from(m).data),
            _phantom: PhantomData,
        }
    }
}

impl<DK, T> Decrypt<DK, ScalarCiphertext<T>, T> for Paillier
where 
    ScalarPlaintext<T>: Into<T>,
    Paillier: Decrypt<DK, core::Ciphertext, core::Plaintext>,
{
    fn decrypt(dk: &DK, c: &ScalarCiphertext<T>) -> T {
        let m: ScalarPlaintext<_> =  ScalarPlaintext {
            data: Self::decrypt(dk, &c.data),
            _phantom: PhantomData
        };
        m.into()
    }
}

impl<EK, T> Rerandomize<EK, ScalarCiphertext<T>> for Paillier
where Paillier: Rerandomize<EK, core::Ciphertext>
{
    fn rerandomise(ek: &EK, c: &ScalarCiphertext<T>) -> ScalarCiphertext<T> {
        let core_ciphertext: core::Ciphertext = Self::rerandomise(ek, &c.data);
        ScalarCiphertext {
            data: core_ciphertext,
            _phantom: PhantomData
        }
    }
}

impl<EK, T> Add<EK, ScalarCiphertext<T>, ScalarCiphertext<T>, ScalarCiphertext<T>> for Paillier
where Paillier: Add<EK, core::Ciphertext, core::Ciphertext, core::Ciphertext>
{
    fn add(ek: &EK, c1: &ScalarCiphertext<T>, c2: &ScalarCiphertext<T>) -> ScalarCiphertext<T> {
        ScalarCiphertext {
            data: Self::add(ek, &c1.data, &c2.data),
            _phantom: PhantomData
        }
    }
}

impl<EK, T> Add<EK, ScalarCiphertext<T>, ScalarPlaintext<T>, ScalarCiphertext<T>> for Paillier
where
    Paillier: Encrypt<EK, ScalarPlaintext<T>, ScalarCiphertext<T>>,
    Paillier: Add<EK, ScalarCiphertext<T>, ScalarCiphertext<T>, ScalarCiphertext<T>>,
{
    fn add(ek: &EK, c1: &ScalarCiphertext<T>, m2: &ScalarPlaintext<T>) -> ScalarCiphertext<T> {
        Self::add(ek, c1, &Self::encrypt(ek, m2))
    }
}

impl<EK, T> Add<EK, ScalarPlaintext<T>, ScalarCiphertext<T>, ScalarCiphertext<T>> for Paillier
where 
    Paillier: Encrypt<EK, ScalarPlaintext<T>, ScalarCiphertext<T>>,
    Paillier: Add<EK, ScalarCiphertext<T>, ScalarCiphertext<T>, ScalarCiphertext<T>>,
{
    fn add(ek: &EK, m1: &ScalarPlaintext<T>, c2: &ScalarCiphertext<T>) -> ScalarCiphertext<T> {
        Self::add(ek, &Self::encrypt(ek, m1), c2)
    }
}

impl<EK, T, U> Add<EK, ScalarCiphertext<T>, U, ScalarCiphertext<T>> for Paillier
where 
    for<'a> ScalarPlaintext<T>: From<&'a U>,
    Paillier: Add<EK, ScalarCiphertext<T>, ScalarPlaintext<T>, ScalarCiphertext<T>>,
{
    fn add(ek: &EK, c1: &ScalarCiphertext<T>, m2: &U) -> ScalarCiphertext<T> {
        let m2_encoded = ScalarPlaintext::from(m2);
        Self::add(ek, c1, &m2_encoded)
    }
}

impl<EK, T, U> Add<EK, U, ScalarCiphertext<T>, ScalarCiphertext<T>> for Paillier
where 
    for<'a> ScalarPlaintext<T>: From<&'a U>,
    Paillier: Add<EK, ScalarPlaintext<T>, ScalarCiphertext<T>, ScalarCiphertext<T>>,
{
    fn add(ek: &EK, m1: &U, c2: &ScalarCiphertext<T>) -> ScalarCiphertext<T> {
        let m1_encoded = ScalarPlaintext::from(m1);
        Self::add(ek, &m1_encoded, c2)
    }
}

impl<EK, T> Mul<EK, ScalarCiphertext<T>, ScalarPlaintext<T>, ScalarCiphertext<T>> for Paillier
where Paillier: Mul<EK, core::Ciphertext, core::Plaintext, core::Ciphertext>
{
    fn mul(ek: &EK, c1: &ScalarCiphertext<T>, m2: &ScalarPlaintext<T>) -> ScalarCiphertext<T> {
        ScalarCiphertext {
            data: Self::mul(ek, &c1.data, &m2.data),
            _phantom: PhantomData
        }
    }
}

impl<EK, T> Mul<EK, ScalarPlaintext<T>, ScalarCiphertext<T>, ScalarCiphertext<T>> for Paillier
where Paillier: Mul<EK, core::Plaintext, core::Ciphertext, core::Ciphertext>
{
    fn mul(ek: &EK, m1: &ScalarPlaintext<T>, c2: &ScalarCiphertext<T>) -> ScalarCiphertext<T> {
        ScalarCiphertext {
            data: Self::mul(ek, &m1.data, &c2.data),
            _phantom: PhantomData
        }
    }
}

impl<EK, T, U> Mul<EK, ScalarCiphertext<T>, U, ScalarCiphertext<T>> for Paillier
where 
    for<'a> ScalarPlaintext<T>: From<&'a U>,
    Paillier: Mul<EK, ScalarCiphertext<T>, ScalarPlaintext<T>, ScalarCiphertext<T>>,
{
    fn mul(ek: &EK, c1: &ScalarCiphertext<T>, m2: &U) -> ScalarCiphertext<T> {
        let m2_encoded = ScalarPlaintext::from(m2);
        Self::mul(ek, c1, &m2_encoded)
    }
}

impl<EK, T, U> Mul<EK, U, ScalarCiphertext<T>, ScalarCiphertext<T>> for Paillier
where 
    for<'a> ScalarPlaintext<T>: From<&'a U>,
    Paillier: Mul<EK, ScalarPlaintext<T>, ScalarCiphertext<T>, ScalarCiphertext<T>>,
{
    fn mul(ek: &EK, m1: &U, c2: &ScalarCiphertext<T>) -> ScalarCiphertext<T> {
        let m1_encoded = ScalarPlaintext::from(m1);
        Self::mul(ek, &m1_encoded, c2)
    }
}



// impl<I> Encoder<Vec<u64>> for Code<I>
// where
//     I: One,
//     I: Clone,
//     I: From<u64>,
//     I: Shl<usize, Output=I>,
//     I: Add<I, Output=I>,
//     for<'a,'b> &'a I: Rem<&'b I, Output=I>,
//     for<'a> &'a    I: Shr<usize, Output=I>,
// {
//     type Target=vector::Plaintext<I, u64>;
//     fn encode(&self, x: &Vec<u64>) -> Self::Target {
//         vector::Plaintext {
//             data: core::Plaintext(pack(x, self.component_count, self.component_size)),
//             component_count: self.component_count,
//             component_size: self.component_size,
//             _phantom: PhantomData,
//         }
//     }
// }

// impl<I> Decoder<Vec<u64>> for Code<I>
// where
//     u64: ConvertFrom<I>,
//     I: One,
//     I: Clone,
//     I: From<u64>,
//     I: Shl<usize, Output=I>,
//     I: Add<I, Output=I>,
//     for<'a,'b> &'a I: Rem<&'b I, Output=I>,
//     for<'a> &'a    I: Shr<usize, Output=I>,
// {
//     type Source=vector::Plaintext<I, u64>;

//     fn decode(&self, x: &vector::Plaintext<I, u64>) -> Vec<u64> {
//         unpack(x.data.0.clone(), self.component_count, self.component_size)
//     }
// }

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
        let c = Paillier::encrypt(&ek, &m);

        let recovered_m = Paillier::decrypt(&dk, &c);
        assert_eq!(recovered_m, m);
    }

    #[test]
    fn test_correct_addition() {
        let (ek, dk) = test_keypair().keys();

        let m1 = 10;
        let c1 = Paillier::encrypt(&ek, &m1);
        let m2 = 20;
        let c2 = Paillier::encrypt(&ek, &m2);

        let c = Paillier::add(&ek, &c1, &c2);
        let m = Paillier::decrypt(&dk, &c);
        assert_eq!(m, 30);
    }

    #[test]
    fn correct_multiplication() {
        let (ek, dk) = test_keypair().keys();

        let m1 = 10;
        let c1 = Paillier::encrypt(&ek, &m1);
        let m2 = 20;

        let c = Paillier::mul(&ek, &c1, &m2);
        let m = Paillier::decrypt(&dk, &c);
        assert_eq!(m, 200);
    }

}