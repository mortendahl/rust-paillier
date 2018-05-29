//! Integral scalars such as `u64`.

use ::core;
use ::traits::*;
use ::BigInteger as BigInt;

use std::marker::PhantomData;

/// Representation of unencrypted integral scalar.
#[derive(Debug,Clone,PartialEq)]
pub struct Plaintext<T> {
    pub data: core::Plaintext,
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

impl Into<i32> for Plaintext<i32> 
{
    fn into(self) -> i32 {
        5 // TODO 
    }
}

/// Representation of encrypted integral scalar.
#[derive(Debug,Clone)]
pub struct Ciphertext<T> {
    pub data: core::Ciphertext,
    pub _phantom: PhantomData<T>
}


impl<S> Encode<u32> for S
where S: AbstractScheme<BigInteger=BigInt>,
{
    type Target = Plaintext<u32>;

    fn encode(x: u32) -> Plaintext<u32> {
        Plaintext {
            data: core::Plaintext(x.into()),
            _phantom: PhantomData,
        }
    }
}

// impl<S> Encode<u64> for S
// where
//     S: AbstractScheme<BigInteger=BigInt>,
// {
//     type Target = scalar::Plaintext<u64>;

//     fn encode(x: u64) -> scalar::Plaintext<u64> {
//         scalar::Plaintext {
//             data: core::Plaintext(x.into()),
//             _phantom: PhantomData,
//         }
//     }
// }

pub trait Foo {}

impl Foo for u64 {}

impl<S, EK, T> Encryption<EK, Plaintext<T>, Ciphertext<T>> for S
where
    S: AbstractScheme<BigInteger=BigInt>,
    S: Encryption<EK, core::Plaintext, core::Ciphertext>,
{
    fn encrypt(ek: &EK, m: &Plaintext<T>) -> Ciphertext<T> {
        Ciphertext {
            data: S::encrypt(ek, &m.data),
            _phantom: PhantomData,
        }
    }
}

// impl<S, EK> Encryption<EK, u64, Ciphertext<u64>> for S
// where
//     S: AbstractScheme<BigInteger=BigInt>,
//     S: Encryption<EK, Plaintext<u64>, Ciphertext<u64>>,
// {
//     fn encrypt(ek: &EK, m: &u64) -> Ciphertext<u64> {
//         S::encrypt(ek, &Plaintext::from(m))
//     }
// }

impl<S, EK, T> Encryption<EK, T, Ciphertext<T>> for S
where
    S: AbstractScheme<BigInteger=BigInt>,
    S: Encryption<EK, Plaintext<T>, Ciphertext<T>>,
    for<'a> Plaintext<T>: From<&'a T>,
{
    fn encrypt(ek: &EK, m: &T) -> Ciphertext<T> {
        S::encrypt(ek, &Plaintext::from(m))
    }
}

// impl<S, EK, T> Encryption<EK, T, scalar::Ciphertext<T>> for S
// where
//     S: AbstractScheme<BigInteger=BigInt>,
//     S: Encode<T>,
//     S: Encryption<EK, <S as Encode<T>>::Target, scalar::Ciphertext<T>>,
// {
//     fn encrypt(ek: &EK, m: &T) -> scalar::Ciphertext<T> {
//         S::encrypt(ek, &S::encode(*m))
//     }
// }


// impl<T, S, EK> Encryption<EK, scalar::Plaintext<T>, scalar::Ciphertext<T>> for S
// where
//     S: AbstractScheme<BigInteger=BigInt>,
//     S: Encryption<EK, core::Plaintext<BigInt>, core::Ciphertext<BigInt>>,
// {
//     fn encrypt(ek: &EK, m: &scalar::Plaintext<T>) -> scalar::Ciphertext<T> {
//         Ciphertext {
//             data: S::encrypt(&ek, &m.data),
//             _phantom: PhantomData
//         }
//     }
// }

impl<S, DK, T> Decryption<DK, Ciphertext<T>, Plaintext<T>> for S
where
    S: AbstractScheme<BigInteger=BigInt>,
    S: Decryption<DK, core::Ciphertext, core::Plaintext>,
{
    fn decrypt(dk: &DK, c: &Ciphertext<T>) -> Plaintext<T> {
        Plaintext {
            data: S::decrypt(dk, &c.data),
            _phantom: PhantomData
        }
    }
}

impl<S, DK, T> Decryption<DK, Ciphertext<T>, T> for S
where
    S: AbstractScheme<BigInteger=BigInt>,
    S: Decryption<DK, Ciphertext<T>, Plaintext<T>>,
    Plaintext<T>: Into<T>,
{
    fn decrypt(dk: &DK, c: &Ciphertext<T>) -> T {
        let m = S::decrypt(dk, c);
        m.into()
    }
}

// impl<DK, T, U> Decryption<DK, Ciphertext<T>, U> for ::Paillier
// {
//     fn decrypt(dk: &DK, c: &Ciphertext<T>) -> U {
//         unimplemented!()
//         // S::decrypt(dk, &c.data) as U
//         // Plaintext {
//         //     data: S::decrypt(dk, &c.data),
//         //     _phantom: PhantomData
//         // }
//     }
// }

impl<S, EK, T> Rerandomisation<EK, Ciphertext<T>> for S
where
    S: AbstractScheme<BigInteger=BigInt>,
    S: Rerandomisation<EK, core::Ciphertext>,
{
    fn rerandomise(ek: &EK, c: &Ciphertext<T>) -> Ciphertext<T> {
        Ciphertext {
            data: S::rerandomise(&ek, &c.data),
            _phantom: PhantomData
        }
    }
}

impl<S, EK, T> Addition<EK, Ciphertext<T>, Ciphertext<T>, Ciphertext<T>> for S
where
    S: AbstractScheme<BigInteger=BigInt>,
    S: Addition<EK, core::Ciphertext, core::Ciphertext, core::Ciphertext>,
{
    fn add(ek: &EK, c1: &Ciphertext<T>, c2: &Ciphertext<T>) -> Ciphertext<T> {
        Ciphertext {
            data: S::add(&ek, &c1.data, &c2.data),
            _phantom: PhantomData
        }
    }
}

impl<S, EK, T> Multiplication<EK, Ciphertext<T>, Plaintext<T>, Ciphertext<T>> for S
where
    S: AbstractScheme<BigInteger=BigInt>,
    S: Multiplication<EK, core::Ciphertext, core::Plaintext, core::Ciphertext>,
{
    fn mul(ek: &EK, c1: &Ciphertext<T>, m2: &Plaintext<T>) -> Ciphertext<T> {
        Ciphertext {
            data: S::mul(&ek, &c1.data, &m2.data),
            _phantom: PhantomData
        }
    }
}

bigint!(I,
#[cfg(test)]
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

        let _recovered_m: i32 = Paillier::decrypt(&dk, &c);
        // assert_eq!(recovered_m, m);
    }

    // #[test]
    // fn test_correct_addition() {
    //     let (ek, dk) = test_keypair().keys();
    //     let code = Code::default();

    //     let m1 = code.encode(&10_u64);
    //     let c1 = AbstractPaillier::encrypt(&ek, &m1);
    //     let m2 = code.encode(&20_u64);
    //     let c2 = AbstractPaillier::encrypt(&ek, &m2);

    //     let c = AbstractPaillier::add(&ek, &c1, &c2);
    //     let m = AbstractPaillier::decrypt(&dk, &c);
    //     assert_eq!(m, code.encode(&30_u64));
    // }

    // #[test]
    // fn correct_multiplication() {
    //     let (ek, dk) = test_keypair().keys();
    //     let code = Code::default();

    //     let m1 = code.encode(&10_u64);
    //     let c1 = AbstractPaillier::encrypt(&ek, &m1);
    //     let m2 = code.encode(&20_u64);

    //     let c = AbstractPaillier::mul(&ek, &c1, &m2);
    //     let m = AbstractPaillier::decrypt(&dk, &c);
    //     assert_eq!(m, code.encode(&200_u64));
    // }

});
