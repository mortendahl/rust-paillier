
//! Key generation following standard recommendations.

use super::*;
use arithimpl::primes::*;

impl<I, S> KeyGeneration<standard::EncryptionKey<I>, crt::DecryptionKey<I>> for S
where
    S: AbstractScheme<BigInteger=I>,
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
    for<'b>        I: Sub<&'b I, Output=I>,
    for<'a,'b> &'a I: Sub<&'b I, Output=I>,
    for<'b>        I: Div<&'b I, Output=I>,
    for<'a,'b> &'a I: Div<&'b I, Output=I>,
    for<'a>        I: Rem<&'a I, Output=I>,
    for<'a,'b> &'a I: Rem<&'b I, Output=I>
{
    fn keypair_with_modulus_size(bit_length: usize) -> (standard::EncryptionKey<I>, crt::DecryptionKey<I>) {
        let p = I::sample_prime(bit_length/2);
        let q = I::sample_prime(bit_length/2);
        let n = &p * &q;
        let ek = standard::EncryptionKey::from(&n);
        let dk = crt::DecryptionKey::from((&p, &q));
        (ek, dk)
    }
}
