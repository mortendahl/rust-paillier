//! Integral vectors such as `Vec<u64>`.
//!
//! Allows several (small) values to be encrypted together while preserving homomorphic properties.

use std::marker::PhantomData;

use ::core;
use ::traits::*;
use ::BigInteger as BigInt;


/// Representation of unencrypted integral vector.
#[derive(Debug,Clone,PartialEq)]
pub struct Plaintext<T> {
    pub data: core::Plaintext,
    pub component_count: usize,
    pub component_size: usize,  // in bits
    pub _phantom: PhantomData<T>,
}

/// Representation of encrypted integral vector.
#[derive(Debug,Clone)]
pub struct Ciphertext<T> {
    pub data: core::Ciphertext,
    pub component_count: usize,
    pub component_size: usize,  // in bits
    pub _phantom: PhantomData<T>,
}

impl<S, EK, T> Encryption<EK, Plaintext<T>, Ciphertext<T>> for S
where
    S: AbstractScheme<BigInteger=BigInt>,
    S: Encryption<EK, core::Plaintext, core::Ciphertext>,
{
    fn encrypt(ek: &EK, m: &Plaintext<T>) -> Ciphertext<T> {
        Ciphertext {
            data: S::encrypt(&ek, &m.data),
            component_count: m.component_count,
            component_size: m.component_size,
            _phantom: PhantomData
        }
    }
}

impl<S, DK, T> Decryption<DK, Ciphertext<T>, Plaintext<T>> for S
where
    S: AbstractScheme<BigInteger=BigInt>,
    S: Decryption<DK, core::Ciphertext, core::Plaintext>,
{
    fn decrypt(dk: &DK, c: &Ciphertext<T>) -> Plaintext<T> {
        Plaintext {
            data: S::decrypt(dk, &c.data),
            component_count: c.component_count,
            component_size: c.component_size,
            _phantom: PhantomData
        }
    }
}

// impl<DK, T> Decryption<DK, Ciphertext<T>, Plaintext<T>> for ::Paillier
// {
//     fn decrypt(dk: &DK, c: &Ciphertext<T>) -> Plaintext<T> {
//         Plaintext {
//             data: ::Paillier::decrypt(dk, &c.data),
//             component_count: c.component_count,
//             component_size: c.component_size,
//             _phantom: PhantomData
//         }
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
            component_count: c.component_count,
            component_size: c.component_size,
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
            component_count: c1.component_count,
            component_size: c1.component_size, // TODO equality
            _phantom: PhantomData
        }
    }
}

impl<S, EK, T> Multiplication<EK, Ciphertext<T>, ::coding::integral::scalar::Plaintext<T>, Ciphertext<T>> for S
where
    S: AbstractScheme<BigInteger=BigInt>,
    S: Multiplication<EK, core::Ciphertext, core::Plaintext, core::Ciphertext>,
{
    fn mul(ek: &EK, c1: &Ciphertext<T>, m2: &::coding::integral::scalar::Plaintext<T>) -> Ciphertext<T> {
        Ciphertext {
            data: S::mul(&ek, &c1.data, &m2.data),
            component_count: c1.component_count, // TODO equality
            component_size: c1.component_size,
            _phantom: PhantomData
        }
    }
}

bigint!(I,
#[cfg(test)]
mod tests {

    use ::core::*;
    use ::AbstractPaillier;
    use ::integral::vector::*;

    fn test_keypair() -> Keypair {
        //1024 bits prime
        let p = str::parse("148677972634832330983979593310074301486537017973460461278300587514468301043894574906886127642530475786889672304776052879927627556769456140664043088700743909632312483413393134504352834240399191134336344285483935856491230340093391784574980688823380828143810804684752914935441384845195613674104960646037368551517").unwrap();
        let q = str::parse("158741574437007245654463598139927898730476924736461654463975966787719309357536545869203069369466212089132653564188443272208127277664424448947476335413293018778018615899291704693105620242763173357203898195318179150836424196645745308205164116144020613415407736216097185962171301808761138424668335445923774195463").unwrap();
        Keypair {
            p: p,
            q: q,
        }
    }

    // #[test]
    // fn test_correct_encryption_decryption() {
    //     let (ek, dk) = test_keypair().keys();

    //     let code = Code::new(3, 64);
    //     let m = vec![1, 2, 3];

    //     let p = code.encode(&m);
    //     let c = AbstractPaillier::encrypt(&ek, &p);
    //     let recovered_p = AbstractPaillier::decrypt(&dk, &c);
    //     let recovered_m: Vec<u64> = code.decode(&recovered_p);

    //     assert_eq!(recovered_p, p);
    //     assert_eq!(recovered_m, m);
    // }

    // #[test]
    // fn test_correct_addition() {
    //     let (ek, dk) = test_keypair().keys();

    //     let code = Code::new(3, 16);

    //     let m1 = code.encode(&vec![1, 2, 3]);
    //     let c1 = AbstractPaillier::encrypt(&ek, &m1);
    //     let m2 = code.encode(&vec![1, 2, 3]);
    //     let c2 = AbstractPaillier::encrypt(&ek, &m2);

    //     let c = AbstractPaillier::add(&ek, &c1, &c2);
    //     let m: Vec<_> = code.decode(&AbstractPaillier::decrypt(&dk, &c));
    //     assert_eq!(m, vec![2, 4, 6]);
    // }

    // #[test]
    // fn test_correct_multiplication() {
    //     let (ek, dk) = test_keypair().keys();

    //     let code = Code::new(3, 16);

    //     let m1 = code.encode(&vec![1, 2, 3]);
    //     let c1 = AbstractPaillier::encrypt(&ek, &m1);
    //     let m2 = scalar::Plaintext::from(4);

    //     let c = AbstractPaillier::mul(&ek, &c1, &m2);
    //     let m: Vec<_> = code.decode(&AbstractPaillier::decrypt(&dk, &c));
    //     assert_eq!(m, vec![4, 8, 12]);
    // }

});
