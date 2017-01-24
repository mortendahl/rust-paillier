
//! Key generation following standard recommendations.

use super::*;
use arithimpl::primes::*;

impl<I, S> KeyGeneration<Keypair<I>> for S
where // TODO clean up bounds
    S: AbstractScheme<BigInteger=I>,
    I: From<u64>,
    I: ::std::str::FromStr, <I as ::std::str::FromStr>::Err: ::std::fmt::Debug,
    I: Clone,
    I: Samplable,
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
    fn keypair_with_modulus_size(bit_length: usize) -> Keypair<I> {
        let p = I::sample_prime(bit_length/2);
        let q = I::sample_prime(bit_length/2);
        Keypair {
            p: p,
            q: q,
        }
    }
}
