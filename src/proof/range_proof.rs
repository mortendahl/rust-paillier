use std::mem;

use rand::{random, Rng, OsRng};
use rayon::prelude::*;
use ring::digest::{Context, SHA256};
use bit_vec::BitVec;

use ::arithimpl::traits::*;
use ::BigInteger as BigInt;
use ::Paillier as Paillier;
use ::core::*;
use proof::correct_key::*;
use ::traits::*;
use ::EncryptionKey;
use proof::correct_key::ProofError;

const STATISTICAL_ERROR_FACTOR : usize = 40;
const RANGE_BITS : usize = 256; //for elliptic curves with 256bits for example

#[derive(Default)]
pub struct EncryptedPairs {
    c1: Vec<RawCiphertext>,
    c2: Vec<RawCiphertext>,
}

#[derive(Default)]
pub struct DataRandomnessPairs {
    w1: Vec<BigInt>,
    w2: Vec<BigInt>,
    r1: Vec<BigInt>,
    r2: Vec<BigInt>,
}

// TODO[Morten] find better name
pub enum Response {
    Open { w1: BigInt, r1: BigInt, w2: BigInt, r2: BigInt },
    Mask { j: u8, masked_x: BigInt, masked_r: BigInt },
}

pub struct Proof(Vec<Response>);

pub struct Commitment(BigInt);

pub struct Challenge(Vec<u8>);

impl Challenge {
    fn sample(big_length: usize) -> Challenge {
        let mut rng = OsRng::new().unwrap();
        let mut bytes: Vec<u8> = vec![0; big_length/8];
        rng.fill_bytes(&mut bytes);
        Challenge(bytes)
    }
}

pub struct ChallengeRandomness(BigInt);

/// Zero-knowledge range proof that a value x<q/3 lies in interval [0,q].
/// 
/// The verifier is given only c = ENC(ek,x).
/// The prover has input x, dk, r (randomness used for calculating c)
/// It is assumed that q is known to both.
///
/// References:
/// - Appendix A in [Lindell'17](https://eprint.iacr.org/2017/552)
/// - Section 1.2.2 in [Boudot '00](https://www.iacr.org/archive/eurocrypt2000/1807/18070437-new.pdf)
///
/// /// This is an interactive version of the proof, assuming only DCRA which is alreasy assumed for Paillier cryptosystem security
pub trait RangeProof<PT, R, CT> {

    /// Verifier commits to a t-bit vector e where e is STATISTICAL_ERROR_FACTOR.
    fn verifier_commit(ek: &EncryptionKey) -> (Commitment, ChallengeRandomness, Challenge); // commitment is public

    /// Prover generates t random pairs, each pair encrypts a number in {q/3, 2q/3} and a number in {0, q/3}
    fn generate_encrypted_pairs(ek: &EncryptionKey, range: &BigInt) -> (EncryptedPairs, DataRandomnessPairs);

    /// Verifier decommits to vector e.

    /// Prover check correctness using:
    fn verify_commit(ek: &EncryptionKey, com: &Commitment, r: &ChallengeRandomness, e: &Challenge) -> Result<(), ProofError>;

    /// Prover calcuate z_i according to bit e_i and returns a vector z
    fn generate_proof(ek: &EncryptionKey, secret_x: &BigInt, secret_r: &BigInt, e: &Challenge, range: &BigInt, data: &DataRandomnessPairs) -> Proof;

    /// Verifier verifies the proof
    fn verifier_output(ek: &EncryptionKey, e: &Challenge, encrypted_pairs: &EncryptedPairs, z: &Proof, range: &BigInt, cipher_x: &RawCiphertext) -> Result<(), ProofError>;

}

impl RangeProof<RawPlaintext, ChallengeRandomness, RawCiphertext> for Paillier {

    fn verifier_commit(ek: &EncryptionKey) -> (Commitment, ChallengeRandomness, Challenge) {
        let e = Challenge::sample(STATISTICAL_ERROR_FACTOR);
        // commit to challenge
        let m = compute_digest(&e.0);
        let r = BigInt::sample_below(&ek.n);
        let com = get_paillier_commitment(&ek,&m, &r);

        (Commitment(com), ChallengeRandomness(r), e)
    }

    fn generate_encrypted_pairs(ek: &EncryptionKey, range: &BigInt) -> (EncryptedPairs, DataRandomnessPairs) {
        let range_scaled_third = range.div_floor(&BigInt::from(3));
        let range_scaled_two_thirds = BigInt::from(2) * &range_scaled_third;

        let mut w1: Vec<_> = (0..STATISTICAL_ERROR_FACTOR).into_par_iter()
            .map(|_| BigInt::sample_range(&range_scaled_third, &range_scaled_two_thirds))
            .collect();

        let mut w2: Vec<_> = w1.par_iter()
            .map(|x| x - &range_scaled_third)
            .collect();

        // with probability 1/2 switch between w1i and w2i
        for i in 0..STATISTICAL_ERROR_FACTOR {
            // TODO[Morten] need secure randomness?
            if random() {
                mem::swap(&mut w2[i], &mut w1[i]);
            }
        }

        let r1: Vec<_> = (0..STATISTICAL_ERROR_FACTOR).into_par_iter()
            .map(|_| BigInt::sample_below(&ek.n))
            .collect();

        let r2: Vec<_> = (0..STATISTICAL_ERROR_FACTOR).into_par_iter()
            .map(|_| BigInt::sample_below(&ek.n))
            .collect();

        let c1: Vec<_> = w1.par_iter().zip(&r1)
            .map(|(wi, ri)| {
                Paillier::encrypt_with_chosen_randomness(
                    ek,
                    &RawPlaintext::from(wi.clone()), 
                    &Randomness::from(ri)
                )
            })
            .collect();

        let c2: Vec<_> = w2.par_iter().zip(&r2)
            .map(|(wi, ri)| {
                Paillier::encrypt_with_chosen_randomness(
                    ek,
                    &RawPlaintext::from(wi.clone()), 
                    &Randomness::from(ri)
                )
            })
            .collect();

        (EncryptedPairs { c1, c2 }, DataRandomnessPairs { w1, w2, r1, r2 })
    }

    fn verify_commit(ek: &EncryptionKey, com: &Commitment, r: &ChallengeRandomness, e: &Challenge) -> Result<(), ProofError> {
        let m = compute_digest(&e.0);
        let com_tag = get_paillier_commitment(&ek, &m, &r.0);
        if com.0 == com_tag {
            Ok(())
        } else {
            Err(ProofError)
        }
    }

    fn generate_proof(ek: &EncryptionKey, secret_x: &BigInt, secret_r: &BigInt, e: &Challenge, range: &BigInt, data: &DataRandomnessPairs) -> Proof {
        let range_scaled_third: BigInt = range.div_floor(&BigInt::from(3));
        let range_scaled_two_thirds = BigInt::from(2) * &range_scaled_third;
        let bits_of_e = BitVec::from_bytes(&e.0);
        let reponses: Vec<_> = (0..STATISTICAL_ERROR_FACTOR).into_par_iter()
            .map(|i| {
                let ei = bits_of_e[i];
                if !ei {
                    Response::Open { 
                        w1: data.w1[i].clone(),
                        r1: data.r1[i].clone(),
                        w2: data.w2[i].clone(),
                        r2: data.r2[i].clone(),
                    }
                } else {
                    if secret_x + &data.w1[i] > range_scaled_third  && secret_x + &data.w1[i] < range_scaled_two_thirds {
                        Response::Mask {
                            j: 1,
                            masked_x: secret_x + &data.w1[i],
                            masked_r: secret_r * &data.r1[i] % &ek.n,
                        }
                    } else {
                        Response::Mask {
                            j: 2,
                            masked_x: secret_x + &data.w2[i],
                            masked_r: secret_r * &data.r2[i] % &ek.n,
                        }
                    }
                }
            })
            .collect();

        Proof(reponses)
    }

    fn verifier_output(ek: &EncryptionKey, e: &Challenge, encrypted_pairs: &EncryptedPairs, proof: &Proof, range: &BigInt, cipher_x: &RawCiphertext) -> Result<(), ProofError> {
        let range_scaled_third: BigInt = range.div_floor(&BigInt::from(3i32));
        let range_scaled_two_thirds: BigInt = BigInt::from(2i32) * &range_scaled_third;

        let bits_of_e = BitVec::from_bytes(&e.0);
        let responses = &proof.0;

        let verifications: Vec<bool> = (0..STATISTICAL_ERROR_FACTOR).into_par_iter()
            .map(|i| {
                let ei = bits_of_e[i];
                let response = &responses[i];

                match (ei, response) {

                    (false, Response::Open { w1, r1, w2, r2 }) => {
                        let mut res = true;

                        if Paillier::encrypt_with_chosen_randomness(ek, &RawPlaintext::from(w1.clone()), &Randomness::from(r1)) != encrypted_pairs.c1[i] { res = false; }
                        if Paillier::encrypt_with_chosen_randomness(ek, &RawPlaintext::from(w2.clone()), &Randomness::from(r2)) != encrypted_pairs.c2[i] { res = false; }

                        let mut flag = false;
                        if w1 < &range_scaled_third {
                            if w2 > &range_scaled_third && w2 < &range_scaled_two_thirds { flag = true; }
                        }
                        if w2 < &range_scaled_third {
                            if w1 > &range_scaled_third && w1 < &range_scaled_two_thirds { flag = true; }
                        }
                        if !flag { res = false; }

                        res
                    }

                    (true, Response::Mask { j, masked_x, masked_r }) => {
                        let mut res = true;

                        let enc_zi = Paillier::encrypt_with_chosen_randomness(ek, &RawPlaintext::from(masked_x.clone()), &Randomness::from(masked_r.clone()));

                        let c = if *j == 1 {
                            &encrypted_pairs.c1[i].0 * &cipher_x.0 % &ek.nn
                        } else {
                            &encrypted_pairs.c2[i].0 * &cipher_x.0 % &ek.nn
                        };
                        if c != enc_zi.0 { res = false; }
                        if masked_x < &range_scaled_third || masked_x > &range_scaled_two_thirds { res = false; }

                        res
                    }

                    _ => false
                }
            })
            .collect();

        if verifications.iter().all(|b| *b) {
            Ok(())
        } else {
            Err(ProofError)
        }
    }

}

/// hash based commitment scheme : digest = H(m||r), works under random oracle model. |r| is of length security parameter
fn get_paillier_commitment(ek: &EncryptionKey, x: &BigInt, r: &BigInt) -> BigInt {

    let com_pi = Paillier::encrypt_with_chosen_randomness(ek, &RawPlaintext::from(x.clone()), &Randomness::from(r));
    com_pi.0

}

fn compute_digest(bytes: &[u8]) -> BigInt {
    let mut digest = Context::new(&SHA256);
    digest.update(&bytes);
    BigInt::from(digest.finish().as_ref())
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::Keypair;
    use traits::*;
    use Paillier;
    use test::Bencher;


    fn test_keypair() -> Keypair {
        let p = str::parse("148677972634832330983979593310074301486537017973460461278300587514468301043894574906886127642530475786889672304776052879927627556769456140664043088700743909632312483413393134504352834240399191134336344285483935856491230340093391784574980688823380828143810804684752914935441384845195613674104960646037368551517").unwrap();
        let q = str::parse("158741574437007245654463598139927898730476924736461654463975966787719309357536545869203069369466212089132653564188443272208127277664424448947476335413293018778018615899291704693105620242763173357203898195318179150836424196645745308205164116144020613415407736216097185962171301808761138424668335445923774195463").unwrap();
        Keypair {
            p: p,
            q: q,
        }
    }

    #[test]
    fn test_generate_encrypted_pairs() {
        let (ek, dk) = test_keypair().keys();
        let range = BigInt::from(0xFFFFFFFFFFFFFi64);
        Paillier::generate_encrypted_pairs(&ek, &range);
        //Paillier::verifier_commit();
    }

    #[test]
    fn test_commit_decommit() {
        let (verifier_ek, verifier_dk) = test_keypair().keys();
        let (com, r, e) = Paillier::verifier_commit(&verifier_ek);
        /// 1. verifier sends the prover (com,r,e,verifier_ek)
        /// 2. prover is playing verifier for zk correct_key protocol to make sure verifier_ek was generated correctly:
        let (challenge, verification_aid) = Paillier::challenge(&verifier_ek);
        /// 3. verifier is proving correct_key
        let proof_results = Paillier::prove(&verifier_dk, &challenge);
        assert!(proof_results.is_ok());
        /// 4. prover verifies correct key proof:
        let result = Paillier::verify(&proof_results.unwrap(), &verification_aid);
        assert!(result.is_ok());
        assert!(Paillier::verify_commit(&verifier_ek,&com, &r, &e).is_ok())
    }

    #[test]
    fn test_generate_proof() {
        let (ek, dk) = test_keypair().keys();
        let (verifier_ek, verifier_dk) = test_keypair().keys();
        let range = BigInt::from(0xFFFFFFFFFFFFFi64);
        let (com,r,e) = Paillier::verifier_commit(&verifier_ek);
        let (encrypted_pairs, data_and_randmoness_pairs) = Paillier::generate_encrypted_pairs(&ek, &range);
        let secret_r = BigInt::sample_below(&ek.n);
        let secret_x = BigInt::from(0xFFFFFFFi64);
        let z_vector= Paillier::generate_proof(&ek, &secret_x, &secret_r, &e, &range, &data_and_randmoness_pairs);
    }

    #[test]
    fn test_range_proof_correct_proof() {
        // common:
        let range = BigInt::sample(RANGE_BITS);
        // prover:
        let (ek, dk) = test_keypair().keys();
        let (verifier_ek, verifier_dk) = test_keypair().keys();
        // verifier:
        let (com, r, e) = Paillier::verifier_commit(&verifier_ek);
        let (challenge, verification_aid) = Paillier::challenge(&verifier_ek);
        let proof_results = Paillier::prove(&verifier_dk, &challenge);
        let result = Paillier::verify(&proof_results.unwrap(), &verification_aid);
        Paillier::verify_commit(&verifier_ek,&com, &r, &e);
        // prover:
        let (encrypted_pairs, data_and_randmoness_pairs) = Paillier::generate_encrypted_pairs(&ek, &range);
        // prover:
        let secret_r = BigInt::sample_below(&ek.n);
        let secret_x = BigInt::sample_below(&range.div_floor(&BigInt::from(3)));
        // common:
        let cipher_x = Paillier::encrypt_with_chosen_randomness(&ek, &RawPlaintext::from(secret_x.clone()), &Randomness(secret_r.clone()));
        // verifer decommits (tested in test_commit_decommit)
        // prover:
        let z_vector = Paillier::generate_proof(&ek, &secret_x, &secret_r, &e, &range,&data_and_randmoness_pairs);
        // verifier:
        let result = Paillier::verifier_output(&ek, &e, &encrypted_pairs,&z_vector, &range, &cipher_x);
        assert!(result.is_ok());
    }

    #[test]
    fn test_range_proof_incorrect_proof() {
        // common:
        let range = BigInt::sample(RANGE_BITS);
        // prover:
        let (ek, dk) = test_keypair().keys();
        let (verifier_ek, verifier_dk) = test_keypair().keys();
        // verifier:
        let (com, r, e) = Paillier::verifier_commit(&verifier_ek);
        // prover:
        let (encrypted_pairs, data_and_randmoness_pairs) = Paillier::generate_encrypted_pairs(&ek, &range);
        // prover:
        let secret_r = BigInt::sample_below(&ek.n);
        let secret_x =  BigInt::sample_range(&(BigInt::from(100i32) * &range), &(BigInt::from(10000i32) * &range));
        // common:
        let cipher_x = Paillier::encrypt_with_chosen_randomness(&ek, &RawPlaintext::from(secret_x.clone()), &Randomness(secret_r.clone()));
        // verifer decommits (tested in test_commit_decommit)
        // prover:
        let z_vector = Paillier::generate_proof(&ek, &secret_x, &secret_r, &e, &range,&data_and_randmoness_pairs);
        // verifier:
        let result = Paillier::verifier_output(&ek, &e, &encrypted_pairs,&z_vector, &range, &cipher_x);
        assert!(result.is_err());
    }

    #[bench]
    fn bench_range_proof(b: &mut Bencher){
        // TODO: bench range for 256bit range.
        b.iter(|| {
            // common:
            let range = BigInt::sample(RANGE_BITS);
            // prover:
            let (ek, dk) = test_keypair().keys();
            let (verifier_ek, verifier_dk) = test_keypair().keys();
            // verifier:
            let (com,r,e) = Paillier::verifier_commit(&verifier_ek);
            // prover:
            let (encrypted_pairs, data_and_randmoness_pairs) = Paillier::generate_encrypted_pairs(&ek, &range);
            // prover:
            let secret_r = BigInt::sample_below(&ek.n);
            let secret_x = BigInt::sample_below(&range.div_floor(&BigInt::from(3)));
            //let secret_x = BigInt::from(0xFFFFFFFi64);
            // common:
            let cipher_x = Paillier::encrypt_with_chosen_randomness(&ek, &RawPlaintext::from(secret_x.clone()), &Randomness(secret_r.clone()));
            // verifer decommits (tested in test_commit_decommit)
            // prover:
            let z_vector = Paillier::generate_proof(&ek, &secret_x, &secret_r, &e, &range,&data_and_randmoness_pairs);
            // verifier:
            let result = Paillier::verifier_output(&ek, &e, &encrypted_pairs,&z_vector, &range, &cipher_x);
        });
    }

}