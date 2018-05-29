//! Integral code supporting both scalars and vectors.

use ::core;
use ::traits::*;
use ::BigInteger as BigInt;
use arithimpl::traits::ConvertFrom;

use std::marker::PhantomData;

pub mod scalar
{
    use super::*;

    /// Representation of unencrypted integral scalar.
    #[derive(Debug,Clone,PartialEq)]
    pub struct Plaintext<T> {
        pub data: core::Plaintext,
        pub _phantom: PhantomData<T>
    }

    /// Representation of encrypted integral scalar.
    #[derive(Debug,Clone)]
    pub struct Ciphertext<T> {
        pub data: core::Ciphertext,
        pub _phantom: PhantomData<T>
    }

    impl<'t> From<&'t u32> for Plaintext<u32>
    {
        fn from(x: &'t u32) -> Plaintext<u32> {
            Plaintext {
                data: core::Plaintext(BigInt::from(*x)),
                _phantom: PhantomData,
            }
        }
    }

    impl<'t> From<&'t u64> for Plaintext<u64>
    {
        fn from(x: &'t u64) -> Plaintext<u64> {
            Plaintext {
                data: core::Plaintext(BigInt::from(*x)),
                _phantom: PhantomData,
            }
        }
    }

    impl<'t> From<&'t i32> for Plaintext<i32>
    {
        fn from(x: &'t i32) -> Plaintext<i32> {
            Plaintext {
                data: core::Plaintext(BigInt::from(*x)),
                _phantom: PhantomData,
            }
        }
    }

    impl Into<u8> for Plaintext<u64> 
    {
        fn into(self) -> u8 {
            u8::_from(&self.data.0)
        }
    }

    impl Into<u16> for Plaintext<u64> 
    {
        fn into(self) -> u16 {
            u16::_from(&self.data.0)
        }
    }

    impl Into<u32> for Plaintext<u64> 
    {
        fn into(self) -> u32 {
            u32::_from(&self.data.0)
        }
    }

    impl Into<u64> for Plaintext<u64> 
    {
        fn into(self) -> u64 {
            u64::_from(&self.data.0)
        }
    }

    impl Into<i8> for Plaintext<u64> 
    {
        fn into(self) -> i8 {
            i8::_from(&self.data.0)
        }
    }

    impl Into<i16> for Plaintext<u64> 
    {
        fn into(self) -> i16 {
            i16::_from(&self.data.0)
        }
    }

    impl Into<i32> for Plaintext<u64> 
    {
        fn into(self) -> i32 {
            i32::_from(&self.data.0)
        }
    }

    impl Into<i64> for Plaintext<u64> 
    {
        fn into(self) -> i64 {
            i64::_from(&self.data.0)
        }
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

impl<S, T> Encryption<core::EncryptionKey, scalar::Plaintext<T>, scalar::Ciphertext<T>> for S
where
    S: AbstractScheme<BigInteger=BigInt>,
    S: Encryption<core::EncryptionKey, core::Plaintext, core::Ciphertext>,
{
    fn encrypt(ek: &core::EncryptionKey, m: &scalar::Plaintext<T>) -> scalar::Ciphertext<T> {
        scalar::Ciphertext {
            data: S::encrypt(ek, &m.data),
            _phantom: PhantomData,
        }
    }
}

impl<S, T> Encryption<core::EncryptionKey, T, scalar::Ciphertext<T>> for S
where
    S: AbstractScheme<BigInteger=BigInt>,
    S: Encryption<core::EncryptionKey, scalar::Plaintext<T>, scalar::Ciphertext<T>>,
    for<'a> scalar::Plaintext<T>: From<&'a T>,
{
    fn encrypt(ek: &core::EncryptionKey, m: &T) -> scalar::Ciphertext<T> {
        S::encrypt(ek, &scalar::Plaintext::from(m))
    }
}

impl<S, T> Rerandomisation<core::EncryptionKey, scalar::Ciphertext<T>> for S
where
    S: AbstractScheme<BigInteger=BigInt>,
    S: Rerandomisation<core::EncryptionKey, core::Ciphertext>,
{
    fn rerandomise(ek: &core::EncryptionKey, c: &scalar::Ciphertext<T>) -> scalar::Ciphertext<T> {
        scalar::Ciphertext {
            data: S::rerandomise(&ek, &c.data),
            _phantom: PhantomData
        }
    }
}

impl<S, T> Addition<core::EncryptionKey, scalar::Ciphertext<T>, scalar::Ciphertext<T>, scalar::Ciphertext<T>> for S
where
    S: AbstractScheme<BigInteger=BigInt>,
    S: Addition<core::EncryptionKey, core::Ciphertext, core::Ciphertext, core::Ciphertext>,
{
    fn add(ek: &core::EncryptionKey, c1: &scalar::Ciphertext<T>, c2: &scalar::Ciphertext<T>) -> scalar::Ciphertext<T> {
        scalar::Ciphertext {
            data: S::add(&ek, &c1.data, &c2.data),
            _phantom: PhantomData
        }
    }
}

impl<S, T> Addition<core::EncryptionKey, scalar::Ciphertext<T>, scalar::Plaintext<T>, scalar::Ciphertext<T>> for S
where
    S: AbstractScheme<BigInteger=BigInt>,
    S: Addition<core::EncryptionKey, scalar::Ciphertext<T>, scalar::Ciphertext<T>, scalar::Ciphertext<T>>,
    S: Encryption<core::EncryptionKey, scalar::Plaintext<T>, scalar::Ciphertext<T>>,
{
    fn add(ek: &core::EncryptionKey, c1: &scalar::Ciphertext<T>, m2: &scalar::Plaintext<T>) -> scalar::Ciphertext<T> {
        S::add(&ek, &c1, &S::encrypt(&ek, &m2))
    }
}

impl<S, T> Addition<core::EncryptionKey, scalar::Plaintext<T>, scalar::Ciphertext<T>, scalar::Ciphertext<T>> for S
where
    S: AbstractScheme<BigInteger=BigInt>,
    S: Addition<core::EncryptionKey, scalar::Ciphertext<T>, scalar::Ciphertext<T>, scalar::Ciphertext<T>>,
    S: Encryption<core::EncryptionKey, scalar::Plaintext<T>, scalar::Ciphertext<T>>,
{
    fn add(ek: &core::EncryptionKey, m1: &scalar::Plaintext<T>, c2: &scalar::Ciphertext<T>) -> scalar::Ciphertext<T> {
        S::add(&ek, &S::encrypt(&ek, &m1), &c2)
    }
}

impl<S, T> Addition<core::EncryptionKey, scalar::Ciphertext<T>, T, scalar::Ciphertext<T>> for S
where
    S: AbstractScheme<BigInteger=BigInt>,
    S: Addition<core::EncryptionKey, scalar::Ciphertext<T>, scalar::Plaintext<T>, scalar::Ciphertext<T>>,
    for<'a> scalar::Plaintext<T>: From<&'a T>,
{
    fn add(ek: &core::EncryptionKey, c1: &scalar::Ciphertext<T>, m2: &T) -> scalar::Ciphertext<T> {
        S::add(&ek, &c1, &m2.into())
    }
}

impl<S, T> Addition<core::EncryptionKey, T, scalar::Ciphertext<T>, scalar::Ciphertext<T>> for S
where
    S: AbstractScheme<BigInteger=BigInt>,
    S: Addition<core::EncryptionKey, scalar::Plaintext<T>, scalar::Ciphertext<T>, scalar::Ciphertext<T>>,
    for<'a> scalar::Plaintext<T>: From<&'a T>,
{
    fn add(ek: &core::EncryptionKey, m1: &T, c2: &scalar::Ciphertext<T>) -> scalar::Ciphertext<T> {
        S::add(&ek, &m1.into(), &c2)
    }
}

impl<S, T> Multiplication<core::EncryptionKey, scalar::Ciphertext<T>, scalar::Plaintext<T>, scalar::Ciphertext<T>> for S
where
    S: AbstractScheme<BigInteger=BigInt>,
    S: Multiplication<core::EncryptionKey, core::Ciphertext, core::Plaintext, core::Ciphertext>,
{
    fn mul(ek: &core::EncryptionKey, c1: &scalar::Ciphertext<T>, m2: &scalar::Plaintext<T>) -> scalar::Ciphertext<T> {
        scalar::Ciphertext {
            data: S::mul(&ek, &c1.data, &m2.data),
            _phantom: PhantomData
        }
    }
}

impl<S, T> Multiplication<core::EncryptionKey, scalar::Plaintext<T>, scalar::Ciphertext<T>, scalar::Ciphertext<T>> for S
where
    S: AbstractScheme<BigInteger=BigInt>,
    S: Multiplication<core::EncryptionKey, core::Plaintext, core::Ciphertext, core::Ciphertext>,
{
    fn mul(ek: &core::EncryptionKey, m1: &scalar::Plaintext<T>, c2: &scalar::Ciphertext<T>) -> scalar::Ciphertext<T> {
        scalar::Ciphertext {
            data: S::mul(&ek, &m1.data, &c2.data),
            _phantom: PhantomData
        }
    }
}

impl<S, T> Multiplication<core::EncryptionKey, scalar::Ciphertext<T>, T, scalar::Ciphertext<T>> for S
where
    S: AbstractScheme<BigInteger=BigInt>,
    S: Multiplication<core::EncryptionKey, scalar::Ciphertext<T>, scalar::Plaintext<T>, scalar::Ciphertext<T>>,
    for<'a> scalar::Plaintext<T>: From<&'a T>,
{
    fn mul(ek: &core::EncryptionKey, c1: &scalar::Ciphertext<T>, m2: &T) -> scalar::Ciphertext<T> {
        S::mul(&ek, &c1, &m2.into())
    }
}

impl<S, T> Multiplication<core::EncryptionKey, T, scalar::Ciphertext<T>, scalar::Ciphertext<T>> for S
where
    S: AbstractScheme<BigInteger=BigInt>,
    S: Multiplication<core::EncryptionKey, scalar::Plaintext<T>, scalar::Ciphertext<T>, scalar::Ciphertext<T>>,
    for<'a> scalar::Plaintext<T>: From<&'a T>,
{
    fn mul(ek: &core::EncryptionKey, m1: &T, c2: &scalar::Ciphertext<T>) -> scalar::Ciphertext<T> {
        S::mul(&ek, &m1.into(), &c2)
    }
}

impl<S, T> Decryption<core::DecryptionKey, scalar::Ciphertext<T>, scalar::Plaintext<T>> for S
where
    S: AbstractScheme<BigInteger=BigInt>,
    S: Decryption<core::DecryptionKey, core::Ciphertext, core::Plaintext>,
{
    fn decrypt(dk: &core::DecryptionKey, c: &scalar::Ciphertext<T>) -> scalar::Plaintext<T> {
        scalar::Plaintext {
            data: S::decrypt(dk, &c.data),
            _phantom: PhantomData
        }
    }
}

impl<S, T> Decryption<core::DecryptionKey, scalar::Ciphertext<T>, T> for S
where
    S: AbstractScheme<BigInteger=BigInt>,
    S: Decryption<core::DecryptionKey, scalar::Ciphertext<T>, scalar::Plaintext<T>>,
    scalar::Plaintext<T>: Into<T>,
{
    fn decrypt(dk: &core::DecryptionKey, c: &scalar::Ciphertext<T>) -> T {
        S::decrypt(dk, c).into()
    }
}


// use std::marker::PhantomData;

// /// Integral code for scalars and vectors.
// pub struct Code<I> {
//     /// Number of components to expect in vectors.
//     pub component_count: usize,
//     /// Bits to allocate for each component in vectors, including gap space.
//     pub component_size: usize,
//     pub _phantom: PhantomData<I>
// }


// impl<I> Code<I> {
//     pub fn default() -> Code<I> {
//         Self::new(10, 64)
//     }

//     pub fn new(component_count: usize, component_size: usize) -> Code<I> {
//         Code {
//             component_count: component_count,
//             component_size: component_size,
//             _phantom: PhantomData,
//         }
//     }
// }


// impl<I> Encoder<usize> for Code<I>
// where
//     I: From<usize>,
// {
//     type Target=scalar::Plaintext<I, usize>;
//     fn encode(&self, x: &usize) -> Self::Target {
//         scalar::Plaintext {
//             data: basic::Plaintext(I::from(*x)),
//             _phantom: PhantomData,
//         }
//     }
// }
//
//
// impl<I> Encoder<u8> for Code<I>
// where
//     I: From<u8>,
// {
//     type Target=scalar::Plaintext<I, u8>;
//     fn encode(&self, x: &u8) -> Self::Target {
//         scalar::Plaintext {
//             data: basic::Plaintext(I::from(*x)),
//             _phantom: PhantomData,
//         }
//     }
// }
//
//
// impl<I> Encoder<u16> for Code<I>
// where
//     I: From<u16>,
// {
//     type Target=scalar::Plaintext<I, u16>;
//     fn encode(&self, x: &u16) -> Self::Target {
//         scalar::Plaintext {
//             data: basic::Plaintext(I::from(*x)),
//             _phantom: PhantomData,
//         }
//     }
// }
//
//
// impl<I> Encoder<u32> for Code<I>
// where
//     I: From<u32>,
// {
//     type Target=scalar::Plaintext<I, u32>;
//     fn encode(&self, x: &u32) -> Self::Target {
//         scalar::Plaintext {
//             data: basic::Plaintext(I::from(*x)),
//             _phantom: PhantomData,
//         }
//     }
// }


// impl<I> Encoder<u64> for Code<I>
// where
//     I: From<u64>,
// {
//     type Target=scalar::Plaintext<I, u64>;
//     fn encode(&self, x: &u64) -> Self::Target {
//         scalar::Plaintext {
//             data: core::Plaintext(I::from(*x)),
//             _phantom: PhantomData,
//         }
//     }
// }


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


// impl<I> Decoder<usize> for Code<I>
// where
//     usize: ConvertFrom<I>,
// {
//     type Source=scalar::Plaintext<I, usize>;
//     fn decode(&self, x: &scalar::Plaintext<I, usize>) -> usize {
//         usize::_from(&x.data.0)
//     }
// }
//
// impl<I> Decoder<u8> for Code<I>
// where
//     u8: ConvertFrom<I>,
// {
//     type Source=scalar::Plaintext<I, u8>;
//     fn decode(&self, x: &scalar::Plaintext<I, u8>) -> u8 {
//         u8::_from(&x.data.0)
//     }
// }
//
// impl<I> Decoder<u16> for Code<I>
// where
//     u16: ConvertFrom<I>,
// {
//     type Source=scalar::Plaintext<I, u16>;
//     fn decode(&self, x: &scalar::Plaintext<I, u16>) -> u16 {
//         u16::_from(&x.data.0)
//     }
// }
//
// impl<I> Decoder<u32> for Code<I>
// where
//     u32: ConvertFrom<I>,
// {
//     type Source=scalar::Plaintext<I, u32>;
//     fn decode(&self, x: &scalar::Plaintext<I, u32>) -> u32 {
//         u32::_from(&x.data.0)
//     }
// }

// impl<I> Decoder<u64> for Code<I>
// where
//     u64: ConvertFrom<I>,
// {
//     type Source=scalar::Plaintext<I, u64>;
//     fn decode(&self, x: &scalar::Plaintext<I, u64>) -> u64 {
//         u64::_from(&x.data.0)
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
        let c: scalar::Ciphertext<u64> = Paillier::encrypt(&ek, &m);

        let recovered_m: u64 = Paillier::decrypt(&dk, &c);
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