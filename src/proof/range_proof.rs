use std::fmt;
use std::iter;
use std::str;
use std::error::Error;
use std::borrow::Borrow;

use ring::digest::{Context, SHA256};

use ::arithimpl::traits::*;
use ::BigInteger as BigInt;
use ::Paillier as Paillier;
use ::{EncryptionKey, DecryptionKey};

use ::correct_key::ProofError;
const STATISTICAL_ERROR_FACTOR: usize = 40;

pub struct encrypted_pairs {
    c1: Vec<BigInt>,
    c2: Vec<BigInt>,
}

/// zero-knowledge range proof that a value x<q/3 lies in interval [0,q].
/// The verifier is given only c = ENC(ek,x).
/// The prover has input x, dk, r (randomness used for calculating c)
/// It is assumed that q is known to both.

/// References:
/// - Appendix A in [Lindell'17](https://eprint.iacr.org/2017/552)
/// - section 1.2.2 in [Boudot '00](https://www.iacr.org/archive/eurocrypt2000/1807/18070437-new.pdf)

pub trait RangeProof<EK, DK> {
    /// Verifier commit to a t-bits vector e where e is STATISTICAL_ERROR_FACTOR.
    fn verifier_commit() -> (&BigInt, &BigInt, Vec<bool>); // (commitment, randomness, e), commitment is public
    // TODO: decide on commitment scheme to use. Assuming ROM we can use correct_key::compute_digest
    // but need to restrict it for two inputs and make sure randomness is greater or equal the size of the message

    /// Prover generates t random pairs, each pair encrypts a number in {q/3, 2q/3} and a number in {0, q/3}
    fn prover_generate_encrypted_pairs(ek: &DK) -> encrypted_pairs;

    /// Verifier decommits to vector e.
    fn verifier_decommit(com: BigInt) -> (BigInt, Vec<bool>); // (randomness, e)

    /// prover calcuate z_i according to bit e_i and return a vector z
    fn proof(e:  Vec<bool>) -> (Vec<BigInt>);

    /// Verifier verifies the proof
    fn verifier_output(z: &Vec<BigInt>) -> Result<(), ProofError>; // (randomness, e)
}

//TODO: compute digest is being used by other proofs, consider changing it to public or move it to some utility file.
fn compute_digest<IT>(values: IT) -> BigInt
    where  IT: Iterator, IT::Item: Borrow<BigInt>
{
    let mut digest = Context::new(&SHA256);
    for value in values {
        let bytes: Vec<u8> = value.borrow().into();
        digest.update(&bytes);
    }
    BigInt::from(digest.finish().as_ref())
}

