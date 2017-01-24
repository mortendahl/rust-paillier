
//! Integral scalars such as `u64`.

use super::*;

use std::marker::PhantomData;

/// Representation of unencrypted integral scalar.
#[derive(Debug,Clone,PartialEq)]
pub struct Plaintext<I, T> {
    pub data: core::Plaintext<I>,
    pub _phantom: PhantomData<T>
}


/// Representation of encrypted integral scalar.
#[derive(Debug,Clone)]
pub struct Ciphertext<I, T> {
    pub data: core::Ciphertext<I>,
    pub _phantom: PhantomData<T>
}


impl<I, T, S, EK> Encryption<EK, Plaintext<I, T>, Ciphertext<I, T>> for S
where
    S: AbstractScheme<BigInteger=I>,
    S: Encryption<EK, core::Plaintext<I>, core::Ciphertext<I>>,
{
    fn encrypt(ek: &EK, m: &Plaintext<I, T>) -> Ciphertext<I, T> {
        Ciphertext {
            data: S::encrypt(&ek, &m.data),
            _phantom: PhantomData
        }
    }
}


impl<I, T, S, DK> Decryption<DK, Ciphertext<I, T>, Plaintext<I, T>> for S
where
    S: AbstractScheme<BigInteger=I>,
    S: Decryption<DK, core::Ciphertext<I>, core::Plaintext<I>>,
{
    fn decrypt(dk: &DK, c: &Ciphertext<I, T>) -> Plaintext<I, T> {
        Plaintext {
            data: S::decrypt(dk, &c.data),
            _phantom: PhantomData
        }
    }
}


impl<I, T, S, EK> Rerandomisation<EK, Ciphertext<I, T>> for S
where
    S: AbstractScheme<BigInteger=I>,
    S: Rerandomisation<EK, core::Ciphertext<I>>,
{
    fn rerandomise(ek: &EK, c: &Ciphertext<I, T>) -> Ciphertext<I, T> {
        Ciphertext {
            data: S::rerandomise(&ek, &c.data),
            _phantom: PhantomData
        }
    }
}


impl<I, T, S, EK> Addition<EK, Ciphertext<I, T>, Ciphertext<I, T>, Ciphertext<I, T>> for S
where
    S: AbstractScheme<BigInteger=I>,
    S: Addition<EK, core::Ciphertext<I>, core::Ciphertext<I>, core::Ciphertext<I>>,
{
    fn add(ek: &EK, c1: &Ciphertext<I, T>, c2: &Ciphertext<I, T>) -> Ciphertext<I, T> {
        Ciphertext {
            data: S::add(&ek, &c1.data, &c2.data),
            _phantom: PhantomData
        }
    }
}


impl<I, T, S, EK> Multiplication<EK, Ciphertext<I, T>, Plaintext<I, T>, Ciphertext<I, T>> for S
where
    S: AbstractScheme<BigInteger=I>,
    S: Multiplication<EK, core::Ciphertext<I>, core::Plaintext<I>, core::Ciphertext<I>>,
{
    fn mul(ek: &EK, c1: &Ciphertext<I, T>, m2: &Plaintext<I, T>) -> Ciphertext<I, T> {
        Ciphertext {
            data: S::mul(&ek, &c1.data, &m2.data),
            _phantom: PhantomData
        }
    }
}


impl<I, T> From<T> for Plaintext<I, T>
where
    T: Copy,  // marker to avoid infinite loop by excluding Plaintext
    I: From<T>,
{
    fn from(x: T) -> Plaintext<I, T> {
        Plaintext{
            data: core::Plaintext(I::from(x)),
            _phantom: PhantomData
        }
    }
}


bigint!(I,
#[cfg(test)]
mod tests {

    use super::I;
    use ::AbstractPaillier;
    use ::integral::scalar::*;

    fn test_keypair() -> Keypair<I> {
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
        let code = Code::default();

        let m = code.encode(&10_u64);
        let c = AbstractPaillier::encrypt(&ek, &m);

        let recovered_m = AbstractPaillier::decrypt(&dk, &c);
        assert_eq!(recovered_m, m);
    }

    #[test]
    fn test_correct_addition() {
        let (ek, dk) = test_keypair().keys();
        let code = Code::default();

        let m1 = code.encode(&10_u64);
        let c1 = AbstractPaillier::encrypt(&ek, &m1);
        let m2 = code.encode(&20_u64);
        let c2 = AbstractPaillier::encrypt(&ek, &m2);

        let c = AbstractPaillier::add(&ek, &c1, &c2);
        let m = AbstractPaillier::decrypt(&dk, &c);
        assert_eq!(m, code.encode(&30_u64));
    }

    #[test]
    fn correct_multiplication() {
        let (ek, dk) = test_keypair().keys();
        let code = Code::default();

        let m1 = code.encode(&10_u64);
        let c1 = AbstractPaillier::encrypt(&ek, &m1);
        let m2 = code.encode(&20_u64);

        let c = AbstractPaillier::mul(&ek, &c1, &m2);
        let m = AbstractPaillier::decrypt(&dk, &c);
        assert_eq!(m, code.encode(&200_u64));
    }

});
