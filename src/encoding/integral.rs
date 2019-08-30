//! Integral code supporting both scalars and vectors.

use std::borrow::Borrow;
use std::marker::PhantomData;

use curv::arithmetic::traits::*;

use super::{pack, unpack, EncodedCiphertext};
use crate::traits::{Add, Decrypt, Encrypt, Mul, Rerandomize};
use crate::{BigInt, Paillier, RawCiphertext, RawPlaintext};

impl<EK> Encrypt<EK, u64, EncodedCiphertext<u64>> for Paillier
where
    for<'p, 'c> Self: Encrypt<EK, RawPlaintext<'p>, RawCiphertext<'c>>,
{
    fn encrypt(ek: &EK, m: u64) -> EncodedCiphertext<u64> {
        let c = Self::encrypt(ek, RawPlaintext::from(BigInt::from(m)));
        EncodedCiphertext {
            raw: c.into(),
            components: 1,
            _phantom: PhantomData,
        }
    }
}

impl<'m, EK> Encrypt<EK, &'m [u64], EncodedCiphertext<Vec<u64>>> for Paillier
where
    for<'p, 'c> Self: Encrypt<EK, RawPlaintext<'p>, RawCiphertext<'c>>,
{
    fn encrypt(ek: &EK, m: &'m [u64]) -> EncodedCiphertext<Vec<u64>> {
        let m_packed = pack(m, 64);
        let c = Self::encrypt(ek, RawPlaintext::from(m_packed));
        EncodedCiphertext {
            raw: c.into(),
            components: m.len(),
            _phantom: PhantomData,
        }
    }
}

impl<EK, C> Rerandomize<EK, C, EncodedCiphertext<u64>> for Paillier
where
    for<'c, 'd> Self: Rerandomize<EK, RawCiphertext<'c>, RawCiphertext<'d>>,
    C: Borrow<EncodedCiphertext<u64>>,
{
    fn rerandomize(ek: &EK, c: C) -> EncodedCiphertext<u64> {
        let d = Self::rerandomize(ek, RawCiphertext::from(&c.borrow().raw));
        EncodedCiphertext {
            raw: d.into(),
            components: c.borrow().components,
            _phantom: PhantomData,
        }
    }
}

impl<EK, C> Rerandomize<EK, C, EncodedCiphertext<Vec<u64>>> for Paillier
where
    for<'c, 'd> Self: Rerandomize<EK, RawCiphertext<'c>, RawCiphertext<'d>>,
    C: Borrow<EncodedCiphertext<Vec<u64>>>,
{
    fn rerandomize(ek: &EK, c: C) -> EncodedCiphertext<Vec<u64>> {
        let d = Self::rerandomize(ek, RawCiphertext::from(&c.borrow().raw));
        EncodedCiphertext {
            raw: d.into(),
            components: c.borrow().components,
            _phantom: PhantomData,
        }
    }
}

impl<DK, C> Decrypt<DK, C, u64> for Paillier
where
    for<'c, 'p> Self: Decrypt<DK, RawCiphertext<'c>, RawPlaintext<'p>>,
    C: Borrow<EncodedCiphertext<u64>>,
{
    fn decrypt(dk: &DK, c: C) -> u64 {
        let m = Self::decrypt(dk, RawCiphertext::from(&c.borrow().raw));
        u64::_from(&m.into())
    }
}

impl<DK, C> Decrypt<DK, C, Vec<u64>> for Paillier
where
    for<'c, 'p> Self: Decrypt<DK, RawCiphertext<'c>, RawPlaintext<'p>>,
    C: Borrow<EncodedCiphertext<Vec<u64>>>,
{
    fn decrypt(dk: &DK, c: C) -> Vec<u64> {
        let m = Self::decrypt(dk, RawCiphertext::from(&c.borrow().raw));
        unpack(m.into(), 64, c.borrow().components)
    }
}

impl<EK, C1, C2> Add<EK, C1, C2, EncodedCiphertext<u64>> for Paillier
where
    for<'c1, 'c2, 'd> Self: Add<EK, RawCiphertext<'c1>, RawCiphertext<'c2>, RawCiphertext<'d>>,
    C1: Borrow<EncodedCiphertext<u64>>,
    C2: Borrow<EncodedCiphertext<u64>>,
{
    fn add(ek: &EK, c1: C1, c2: C2) -> EncodedCiphertext<u64> {
        let d = Self::add(
            ek,
            RawCiphertext::from(&c1.borrow().raw),
            RawCiphertext::from(&c2.borrow().raw),
        );
        EncodedCiphertext {
            raw: d.into(),
            components: 1,
            _phantom: PhantomData,
        }
    }
}

impl<EK, C1, C2> Add<EK, C1, C2, EncodedCiphertext<Vec<u64>>> for Paillier
where
    for<'c1, 'c2, 'd> Self: Add<EK, RawCiphertext<'c1>, RawCiphertext<'c2>, RawCiphertext<'d>>,
    C1: Borrow<EncodedCiphertext<Vec<u64>>>,
    C2: Borrow<EncodedCiphertext<Vec<u64>>>,
{
    fn add(ek: &EK, c1: C1, c2: C2) -> EncodedCiphertext<Vec<u64>> {
        let c1 = c1.borrow();
        let c2 = c2.borrow();
        assert_eq!(c1.components, c2.components); // TODO[Morten] expand one if needed

        let d = Self::add(
            ek,
            RawCiphertext::from(&c1.raw),
            RawCiphertext::from(&c2.raw),
        );
        EncodedCiphertext {
            raw: d.into(),
            components: c1.components,
            _phantom: PhantomData,
        }
    }
}

// impl<'c1, 'c2, EK> Add<EK, &'c1 Ciphertext<Vec<u64>>, &'c2 Ciphertext<u64>, Ciphertext<Vec<u64>>> for Paillier
// where Self: Add<EK, &'c1 BigInt, &'c2 BigInt, BigInt>
// {
//     fn add(ek: &EK, c1: &'c1 Ciphertext<Vec<u64>>, c2: &'c2 Ciphertext<u64>) -> Ciphertext<Vec<u64>> {
//         unimplemented!()
//     }
// }

// impl<'c1, 'c2, EK> Add<EK, &'c1 Ciphertext<u64>, &'c2 Ciphertext<Vec<u64>>, Ciphertext<Vec<u64>>> for Paillier
// where Self: Add<EK, &'c1 BigInt, &'c2 BigInt, BigInt>
// {
//     fn add(ek: &EK, c1: &'c1 Ciphertext<u64>, c2: &'c2 Ciphertext<Vec<u64>>) -> Ciphertext<Vec<u64>> {
//         unimplemented!()
//     }
// }

impl<EK, C> Add<EK, C, u64, EncodedCiphertext<u64>> for Paillier
where
    for<'c, 'p, 'd> Self: Add<EK, RawCiphertext<'c>, RawPlaintext<'p>, RawCiphertext<'d>>,
    C: Borrow<EncodedCiphertext<u64>>,
{
    fn add(ek: &EK, c: C, p: u64) -> EncodedCiphertext<u64> {
        let d = Self::add(
            ek,
            RawCiphertext::from(&c.borrow().raw),
            RawPlaintext::from(BigInt::from(p)),
        );
        EncodedCiphertext {
            raw: d.into(),
            components: 1,
            _phantom: PhantomData,
        }
    }
}

impl<EK, C> Add<EK, C, u64, EncodedCiphertext<Vec<u64>>> for Paillier
where
    for<'c, 'p, 'd> Self: Add<EK, RawCiphertext<'c>, RawPlaintext<'p>, RawCiphertext<'d>>,
    C: Borrow<EncodedCiphertext<Vec<u64>>>,
{
    fn add(ek: &EK, c: C, p: u64) -> EncodedCiphertext<Vec<u64>> {
        let c = c.borrow();

        let m2_expanded = vec![p; c.components];
        let d = Self::add(
            ek,
            RawCiphertext::from(&c.raw),
            RawPlaintext::from(pack(&m2_expanded, 64)),
        );
        EncodedCiphertext {
            raw: d.into(),
            components: c.components,
            _phantom: PhantomData,
        }
    }
}

// impl<'m2, EK, C1> Add<EK, C1, &'m2 [u64], Ciphertext<Vec<u64>>> for Paillier
// where
//     for<'c1> Self: Add<EK, &'c1 BigInt, BigInt, BigInt>,
//     C1: Borrow<Ciphertext<Vec<u64>>>,
// {
//     fn add(ek: &EK, c1: C1, m2: &'m2 [u64]) -> Ciphertext<Vec<u64>> {
//         unimplemented!()
//     }
// }

impl<EK, C2> Add<EK, u64, C2, EncodedCiphertext<u64>> for Paillier
where
    for<'m, 'c, 'd> Self: Add<EK, RawPlaintext<'m>, RawCiphertext<'c>, RawCiphertext<'d>>,
    C2: Borrow<EncodedCiphertext<u64>>,
{
    fn add(ek: &EK, m1: u64, c2: C2) -> EncodedCiphertext<u64> {
        let d = Self::add(
            ek,
            RawPlaintext::from(BigInt::from(m1)),
            RawCiphertext::from(&c2.borrow().raw),
        );
        EncodedCiphertext {
            raw: d.into(),
            components: 1,
            _phantom: PhantomData,
        }
    }
}

// impl<EK, C2> Add<EK, u64, C2, Ciphertext<Vec<u64>>> for Paillier
// where
//     for<'c2> Self: Add<EK, BigInt, &'c2 BigInt, BigInt>,
//     C2: Borrow<Ciphertext<Vec<u64>>>,
// {
//     fn add(ek: &EK, m1: u64, c2: C2) -> Ciphertext<Vec<u64>> {
//         unimplemented!()
//     }
// }

// impl<'m1, EK, C2> Add<EK, &'m1 [u64], C2, Ciphertext<Vec<u64>>> for Paillier
// where
//     for<'c2> Self: Add<EK, BigInt, &'c2 BigInt, BigInt>,
//     C2: Borrow<Ciphertext<Vec<u64>>>,
// {
//     fn add(ek: &EK, m1: &'m1 [u64], c2: C2) -> Ciphertext<Vec<u64>> {
//         unimplemented!()
//     }
// }

impl<EK, C> Mul<EK, C, u64, EncodedCiphertext<u64>> for Paillier
where
    for<'c, 'm, 'd> Self: Mul<EK, RawCiphertext<'c>, RawPlaintext<'m>, RawCiphertext<'d>>,
    C: Borrow<EncodedCiphertext<u64>>,
{
    fn mul(ek: &EK, c: C, m: u64) -> EncodedCiphertext<u64> {
        let d = Self::mul(
            ek,
            RawCiphertext::from(&c.borrow().raw),
            RawPlaintext::from(BigInt::from(m)),
        );
        EncodedCiphertext {
            raw: d.into(),
            components: 1,
            _phantom: PhantomData,
        }
    }
}

impl<EK, C> Mul<EK, C, u64, EncodedCiphertext<Vec<u64>>> for Paillier
where
    for<'c, 'm, 'd> Self: Mul<EK, RawCiphertext<'c>, RawPlaintext<'m>, RawCiphertext<'d>>,
    C: Borrow<EncodedCiphertext<Vec<u64>>>,
{
    fn mul(ek: &EK, c: C, m: u64) -> EncodedCiphertext<Vec<u64>> {
        let d = Self::mul(
            ek,
            RawCiphertext::from(&c.borrow().raw),
            RawPlaintext::from(BigInt::from(m)),
        );
        EncodedCiphertext {
            raw: d.into(),
            components: c.borrow().components,
            _phantom: PhantomData,
        }
    }
}

impl<EK, C> Mul<EK, u64, C, EncodedCiphertext<u64>> for Paillier
where
    for<'m, 'c, 'd> Self: Mul<EK, RawPlaintext<'m>, RawCiphertext<'c>, RawCiphertext<'d>>,
    C: Borrow<EncodedCiphertext<u64>>,
{
    fn mul(ek: &EK, m: u64, c: C) -> EncodedCiphertext<u64> {
        let d = Self::mul(
            ek,
            RawPlaintext::from(BigInt::from(m)),
            RawCiphertext::from(&c.borrow().raw),
        );
        EncodedCiphertext {
            raw: d.into(),
            components: 1,
            _phantom: PhantomData,
        }
    }
}

impl<EK, C> Mul<EK, u64, C, EncodedCiphertext<Vec<u64>>> for Paillier
where
    for<'m, 'c, 'd> Self: Mul<EK, RawPlaintext<'m>, RawCiphertext<'c>, RawCiphertext<'d>>,
    C: Borrow<EncodedCiphertext<Vec<u64>>>,
{
    fn mul(ek: &EK, m: u64, c: C) -> EncodedCiphertext<Vec<u64>> {
        let d = Self::mul(
            ek,
            RawPlaintext::from(BigInt::from(m)),
            RawCiphertext::from(&c.borrow().raw),
        );
        EncodedCiphertext {
            raw: d.into(),
            components: c.borrow().components,
            _phantom: PhantomData,
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::Keypair;

    fn test_keypair() -> Keypair {
        let p = str::parse("148677972634832330983979593310074301486537017973460461278300587514468301043894574906886127642530475786889672304776052879927627556769456140664043088700743909632312483413393134504352834240399191134336344285483935856491230340093391784574980688823380828143810804684752914935441384845195613674104960646037368551517").unwrap();
        let q = str::parse("158741574437007245654463598139927898730476924736461654463975966787719309357536545869203069369466212089132653564188443272208127277664424448947476335413293018778018615899291704693105620242763173357203898195318179150836424196645745308205164116144020613415407736216097185962171301808761138424668335445923774195463").unwrap();
        Keypair { p, q }
    }

    #[test]
    fn test_scalar_encrypt_decrypt() {
        let (ek, dk) = test_keypair().keys();

        let m = 10;
        let c = Paillier::encrypt(&ek, m);

        let recovered_m = Paillier::decrypt(&dk, &c);
        assert_eq!(recovered_m, m);
    }

    #[test]
    fn test_vector_encrypt_decrypt() {
        let (ek, dk) = test_keypair().keys();

        let m = vec![1, 2, 3];
        let c = Paillier::encrypt(&ek, &*m);
        let recovered_m = Paillier::decrypt(&dk, &c);

        assert_eq!(recovered_m, m);
    }

    #[test]
    fn test_scalar_add_plaintext_scalar() {
        let (ek, dk) = test_keypair().keys();

        let c1 = Paillier::encrypt(&ek, 10);
        let m2 = 20;

        let c = Paillier::add(&ek, &c1, m2);
        let m = Paillier::decrypt(&dk, &c);
        assert_eq!(m, 30);
    }

    #[test]
    fn test_scalar_add_ciphertext_scalar() {
        let (ek, dk) = test_keypair().keys();

        let c1 = Paillier::encrypt(&ek, 10);
        let c2 = Paillier::encrypt(&ek, 20);

        let c = Paillier::add(&ek, &c1, &c2);
        let m = Paillier::decrypt(&dk, &c);
        assert_eq!(m, 30);
    }

    #[test]
    fn test_vector_add_plaintext_vector() {
        let (ek, dk) = test_keypair().keys();

        let m1 = vec![1, 2, 3];
        let c1 = Paillier::encrypt(&ek, &*m1);
        let m2 = vec![3, 2, 1];
        let c2 = Paillier::encrypt(&ek, &*m2);

        let c = Paillier::add(&ek, &c1, &c2);
        let m: Vec<_> = Paillier::decrypt(&dk, &c);
        assert_eq!(m, vec![4, 4, 4]);
    }

    // #[test]
    // fn test_add_vector_scalar() {
    //     let (ek, dk) = test_keypair().keys();

    //     let m1 = vec![1, 2, 3];
    //     let c1 = Paillier::encrypt(&ek, &*m1);
    //     let m2 = 3;
    //     let c2 = Paillier::encrypt(&ek, m2);

    //     let c = Paillier::add(&ek, &c1, &c2);
    //     let m: Vec<_> = Paillier::decrypt(&dk, &c);
    //     assert_eq!(m, vec![2, 4, 6]);
    // }

    // #[test]
    // fn test_add_scalar_vector() {
    //     let (ek, dk) = test_keypair().keys();

    //     let m1 = vec![1, 2, 3];
    //     let c1 = Paillier::encrypt(&ek, &*m1);
    //     let m2 = 3;
    //     let c2 = Paillier::encrypt(&ek, m2);

    //     let c = Paillier::add(&ek, &c1, &c2);
    //     let m: Vec<_> = Paillier::decrypt(&dk, &c);
    //     assert_eq!(m, vec![2, 4, 6]);
    // }

    #[test]
    fn test_scalar_mul_plaintext_scalar() {
        let (ek, dk) = test_keypair().keys();

        let c = Paillier::encrypt(&ek, 10);
        let d = Paillier::mul(&ek, &c, 20);
        let m = Paillier::decrypt(&dk, &d);
        assert_eq!(m, 200);
    }

    #[test]
    fn test_vector_mul_plaintext_scalar() {
        let (ek, dk) = test_keypair().keys();

        let m1 = vec![1, 2, 3];
        let c1 = Paillier::encrypt(&ek, &*m1);
        let m2 = 4;

        let c = Paillier::mul(&ek, &c1, m2);
        let m: Vec<_> = Paillier::decrypt(&dk, &c);
        assert_eq!(m, vec![4, 8, 12]);
    }
}
