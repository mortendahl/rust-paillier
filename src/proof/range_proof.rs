use std::fmt;
use std::iter;
use std::str;
use std::mem;
use std::error::Error;
use std::borrow::Borrow;
use ring::digest::{Context, SHA256};
use rand::random;
use ::arithimpl::traits::*;
use ::BigInteger as BigInt;
use ::Paillier as Paillier;
use ::core::*;
use ::traits::*;
use ::{EncryptionKey, DecryptionKey};

use proof::correct_key::ProofError;
const STATISTICAL_ERROR_FACTOR: usize = 40;
const STATISTICAL_ERROR_FACTOR_IN_BYTES: usize = 5;
const SECURITY_PARAM : usize  = 256;

pub struct encrypted_pairs {
    c1: Vec<RawCiphertext>,
    c2: Vec<RawCiphertext>,
}

/// zero-knowledge range proof that a value x<q/3 lies in interval [0,q].
/// The verifier is given only c = ENC(ek,x).
/// The prover has input x, dk, r (randomness used for calculating c)
/// It is assumed that q is known to both.

/// References:
/// - Appendix A in [Lindell'17](https://eprint.iacr.org/2017/552)
/// - section 1.2.2 in [Boudot '00](https://www.iacr.org/archive/eurocrypt2000/1807/18070437-new.pdf)

pub trait RangeProof<EK, DK,PT, R, CT> {

    /// Verifier commit to a t-bits vector e where e is STATISTICAL_ERROR_FACTOR.
    fn verifier_commit() -> (BigInt, BigInt, Vec<u8>); // (commitment, randomness, e), commitment is public
    // TODO: decide on commitment scheme to use. Assuming ROM we can use correct_key::compute_digest
    // but need to restrict it for two inputs and make sure randomness is greater or equal the size of the message

    /// Prover generates t random pairs, each pair encrypts a number in {q/3, 2q/3} and a number in {0, q/3}
    fn prover_generate_encrypted_pairs(ek: &EK, range: &BigInt) -> encrypted_pairs;
/*
    /// Verifier decommits to vector e.
 //   fn verifier_decommit(com: BigInt) -> (BigInt, Vec<bool>); // (randomness, e)

    /// prover calcuate z_i according to bit e_i and return a vector z
  //  fn proof(e:  Vec<bool>,range: &BigInt) -> Vec<BigInt>;

    /// Verifier verifies the proof
 //   fn verifier_output(z: &Vec<BigInt>,range: &BigInt) -> Result<(), ProofError>; // (randomness, e)
*/
}
/// hash based commitment scheme : digest = H(m||r), works under random oracle model. |r| is of length security parameter
pub fn get_hash_commitment(x: &BigInt, r: &BigInt) -> BigInt {
    let mut digest = Context::new(&SHA256);
    let bytes_x: Vec<u8> = x.into();
    digest.update(&bytes_x);

    let bytes_r: Vec<u8> = r.into();
    digest.update(&bytes_r);
    BigInt::from(digest.finish().as_ref())
}



impl RangeProof<EncryptionKey, DecryptionKey,RawPlaintext,Randomness,RawCiphertext> for Paillier {

    fn verifier_commit() -> (BigInt, BigInt, Vec<u8>)
    {

        let e: Vec<_> = (0..STATISTICAL_ERROR_FACTOR_IN_BYTES)
            .map(|_| random::<u8>())
            .collect();
        let m = <Paillier as Trait>::correct_key::compute_digest(&BigInt::from_bytes_be(BigInt::Sign::Plus, e)) ;
        let r =  BigInt::sample_below(&2.pow(SECURITY_PARAM));
        let com = get_hash_commitment(&m, &r);
        (com,r,e)

    }
    fn prover_generate_encrypted_pairs(ek: &EncryptionKey, range: &BigInt) -> encrypted_pairs

    {

        let r1: Vec<_> = (0..STATISTICAL_ERROR_FACTOR)
            .map(|_| BigInt::sample_below(&ek.n))
            .collect();
        let r2: Vec<_> = (0..STATISTICAL_ERROR_FACTOR)
            .map(|_| BigInt::sample_below(&ek.n))
            .collect();
        let range_scaled_third: BigInt = range.div_floor(&BigInt::from(3i32));
        let range_scaled_two_thirds: BigInt = BigInt::from(2i32) * &range_scaled_third;
        let mut w1: Vec<_> = (0..STATISTICAL_ERROR_FACTOR)
            .map(|_| BigInt::sample_range(&range_scaled_third, &range_scaled_two_thirds))
            .collect();
        let mut w2: Vec<BigInt> = Vec::new();
        let mut w2: Vec<BigInt> = w1.clone();
        let mut w2 = w2.iter().map(|x| x - &range_scaled_third).collect::<Vec<_>>();
        let mut encrypted_pairs = encrypted_pairs{
            c1: Vec::new(),
            c2: Vec::new(),
        };
        println!("w1_before = {:?}", w1);
        println!("w2_before = {:?}", w2);
        for i in 0..STATISTICAL_ERROR_FACTOR {
            // with probability 1/2 switch between w1i and w2i
            if random() {
                mem::swap(&mut w2[i],&mut w1[i]);
            }

            encrypted_pairs.c1.push( Paillier::encrypt_with_chosen_randomness(ek, &RawPlaintext::from(w1[i].clone()), &Randomness(r1[i].clone())));
            encrypted_pairs.c2.push( Paillier::encrypt_with_chosen_randomness(ek, &RawPlaintext::from(w2[i].clone()), &Randomness(r2[i].clone())));
        }

        encrypted_pairs
    }
}


    // Verifier decommits to vector e.
  //  fn verifier_decommit(com: BigInt) -> (BigInt, Vec<bool>)
   // {

  //  }

    // prover calcuate z_i according to bit e_i and return a vector z
  //  fn proof(e:  Vec<bool>,range: &BigInt) -> Vec<BigInt>
 //   {

 //   }

    // Verifier verifies the proof
  //  fn verifier_output(z: &Vec<BigInt>,range: &BigInt) -> Result<(), ProofError>
  //  {

  //  }

#[cfg(test)]
mod tests {
    use super::*;
    use core::Keypair;
    use traits::*;

    fn test_keypair() -> Keypair {
        let p = str::parse("148677972634832330983979593310074301486537017973460461278300587514468301043894574906886127642530475786889672304776052879927627556769456140664043088700743909632312483413393134504352834240399191134336344285483935856491230340093391784574980688823380828143810804684752914935441384845195613674104960646037368551517").unwrap();
        let q = str::parse("158741574437007245654463598139927898730476924736461654463975966787719309357536545869203069369466212089132653564188443272208127277664424448947476335413293018778018615899291704693105620242763173357203898195318179150836424196645745308205164116144020613415407736216097185962171301808761138424668335445923774195463").unwrap();
        Keypair {
            p: p,
            q: q,
        }
    }


    #[test]
    fn test_prover_generate_encrypted_pairs() {
        let (ek, dk) = test_keypair().keys();
        let range = BigInt::from(0xFFFFFFFFFFFFFi64);
        Paillier::prover_generate_encrypted_pairs(&ek,&range);
    }
}