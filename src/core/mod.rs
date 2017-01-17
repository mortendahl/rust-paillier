
//! Core Paillier encryption scheme supporting ciphertext addition and plaintext multiplication.

use traits::*;

use std::ops::{Add, Sub, Mul, Div, Rem};
use num_traits::{One};
use arithimpl::traits::*;


/// Representation of unencrypted message.
#[derive(Debug,Clone,PartialEq)]
pub struct Plaintext<I>(pub I);


/// Representation of encrypted message.
#[derive(Debug,Clone)]
pub struct Ciphertext<I>(pub I);


impl<I, T> From<T> for Plaintext<I>
where
    T: Copy,  // marker to avoid infinite loop by excluding Plaintext
    I: From<T>,
{
    fn from(x: T) -> Plaintext<I> {
        Plaintext(I::from(x))
    }
}

use std::fmt;
impl<I> fmt::Display for Plaintext<I>
where
    I: fmt::Display
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.0.fmt(f)
    }
}


// impl<I, T> Encoding<T, Plaintext<I>> for Scheme<I>
// where
//     T: Copy,
//     Plaintext<I> : From<T>,
// {
//     fn encode(x: &T) -> Plaintext<I> {
//         Plaintext::from(*x)
//     }
// }
//
// impl<I, T> Decoding<Plaintext<I>, T> for Scheme<I>
// where
//     Plaintext<I>: Copy,
//     T: From<Plaintext<I>>,
// {
//     fn decode(x: &Plaintext<I>) -> T {
//         T::from(*x)
//     }
// }


fn l<I>(u: &I, n: &I) -> I
where
    I: One,
    for<'a>    &'a I: Sub<I, Output=I>,
    for<'b>        I: Div<&'b I, Output=I>,
{
    (u - I::one()) / n
}

pub mod standard;
pub mod crt;

#[cfg(feature="keygen")]
pub mod keygen;
#[cfg(feature="keygen")]
pub use self::keygen::*;




bigint!(I,
#[cfg(test)]
mod tests {

    use ::AbstractPaillier;
    use super::I;
    use ::core::*;

    fn test_keypair() -> (standard::EncryptionKey<I>, crt::DecryptionKey<I>) {
        let p = str::parse("148677972634832330983979593310074301486537017973460461278300587514468301043894574906886127642530475786889672304776052879927627556769456140664043088700743909632312483413393134504352834240399191134336344285483935856491230340093391784574980688823380828143810804684752914935441384845195613674104960646037368551517").unwrap();
        let q = str::parse("158741574437007245654463598139927898730476924736461654463975966787719309357536545869203069369466212089132653564188443272208127277664424448947476335413293018778018615899291704693105620242763173357203898195318179150836424196645745308205164116144020613415407736216097185962171301808761138424668335445923774195463").unwrap();
        let n = &p * &q;
        let ek = standard::EncryptionKey::from(&n);
        let dk = crt::DecryptionKey::from((&p, &q));
        (ek, dk)
    }

    #[test]
    fn test_correct_encryption_decryption() {
        let (ek, dk) = test_keypair();

        let m = Plaintext::from(10);
        let c = AbstractPaillier::encrypt(&ek, &m);

        let recovered_m = AbstractPaillier::decrypt(&dk, &c);
        assert_eq!(recovered_m, m);
    }

    #[test]
    fn test_correct_addition() {
        let (ek, dk) = test_keypair();

        let m1 = Plaintext::from(10);
        let c1 = AbstractPaillier::encrypt(&ek, &m1);
        let m2 = Plaintext::from(20);
        let c2 = AbstractPaillier::encrypt(&ek, &m2);

        let c = AbstractPaillier::add(&ek, &c1, &c2);
        let m = AbstractPaillier::decrypt(&dk, &c);
        assert_eq!(m, Plaintext::from(30));
    }

    #[test]
    fn correct_multiplication() {
        let (ek, dk) = test_keypair();

        let m1 = Plaintext::from(10);
        let c1 = AbstractPaillier::encrypt(&ek, &m1);
        let m2 = Plaintext::from(20);

        let c = AbstractPaillier::mul(&ek, &c1, &m2);
        let m = AbstractPaillier::decrypt(&dk, &c);
        assert_eq!(m, Plaintext::from(200));
    }

    #[cfg(feature="keygen")]
    #[test]
    fn test_correct_keygen() {
        let (ek, dk): (standard::EncryptionKey<I>, _) = AbstractPaillier::keypair_with_modulus_size(2048);

        let m = Plaintext::from(10);
        let c = AbstractPaillier::encrypt(&ek, &m);

        let recovered_m = AbstractPaillier::decrypt(&dk, &c);
        assert_eq!(recovered_m, m);
    }

});
