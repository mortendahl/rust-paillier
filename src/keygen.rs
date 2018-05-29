
//! Key generation following standard recommendations.

use super::*;
use arithimpl::primes::*;

impl<S> KeyGeneration<Keypair> for S
where S: AbstractScheme<BigInteger=::BigInteger>
{
    fn keypair_with_modulus_size(bit_length: usize) -> Keypair {
        let p = ::BigInteger::sample_prime(bit_length/2);
        let q = ::BigInteger::sample_prime(bit_length/2);
        Keypair {
            p: p,
            q: q,
        }
    }
}
