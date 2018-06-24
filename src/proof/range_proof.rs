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
use proof::correct_key::*;
use ::traits::*;
use ::{EncryptionKey, DecryptionKey};

use proof::correct_key::ProofError;
const STATISTICAL_ERROR_FACTOR: usize = 40;
const STATISTICAL_ERROR_FACTOR_IN_BYTES: usize = 5;
const SECURITY_PARAM : usize  = 256;
const BITS_IN_BYTE: usize = 8;
pub struct encrypted_pairs {
    c1: Vec<RawCiphertext>,
    c2: Vec<RawCiphertext>,
}
pub struct data_and_randmoness_pairs {
    w1: Vec<BigInt>,
    w2: Vec<BigInt>,
    r1: Vec<BigInt>,
    r2: Vec<BigInt>,
}
// z_i = (j, x+wi, r*ri modN)
pub struct masked_witness{
    j: Vec<u8>,
    masked_x: Vec<BigInt>,
    masked_r: Vec<BigInt>,
}
pub struct z_vector{
    map: Vec<bool>,
    z1: data_and_randmoness_pairs,
    z2: masked_witness,
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
    fn generate_encrypted_pairs(ek: &EK, range: &BigInt) -> (encrypted_pairs, data_and_randmoness_pairs);

    /// Verifier decommits to vector e. Prover check correctness using:
    fn verify_commit(com: &BigInt, r: &BigInt, e: &Vec<u8>) -> bool; // (randomness, e)

    /// prover calcuate z_i according to bit e_i and return a vector z
    fn generate_proof(ek: &EncryptionKey, secret_x: &BigInt ,secret_r: &BigInt ,e:  &Vec<u8>,range: &BigInt, data: &data_and_randmoness_pairs) -> z_vector;

    /// Verifier verifies the proof
    fn verifier_output(ek: &EncryptionKey, e:  &Vec<u8>, encrypted_pairs: &encrypted_pairs,  z: &z_vector,range: &BigInt, cipher_x: &RawCiphertext) -> Result<(), ProofError>; // (randomness, e)

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

        let mut e: Vec<_> = (0..STATISTICAL_ERROR_FACTOR_IN_BYTES)
            .map(|_| random::<u8>())
            .collect();
        let mut digest = Context::new(&SHA256);
        digest.update(&e);
        let m =  BigInt::from(digest.finish().as_ref());
        let two = BigInt::from(2u32);
        let r =  BigInt::sample_below(&two.pow(SECURITY_PARAM as u32));
        let com = get_hash_commitment(&m, &r);
        (com,r,e)

    }
    fn generate_encrypted_pairs(ek: &EncryptionKey, range: &BigInt) -> (encrypted_pairs, data_and_randmoness_pairs)

    {
        let mut encrypted_pairs = encrypted_pairs{
            c1: Vec::new(),
            c2: Vec::new(),
        };
        let mut data_and_randmoness_pairs = data_and_randmoness_pairs{
            w1: Vec::new(),
            w2: Vec::new(),
            r1: Vec::new(),
            r2: Vec::new(),
        };

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


        for i in 0..STATISTICAL_ERROR_FACTOR {
            // with probability 1/2 switch between w1i and w2i
            if random() {
                mem::swap(&mut w2[i],&mut w1[i]);
            }

            encrypted_pairs.c1.push( Paillier::encrypt_with_chosen_randomness(ek, &RawPlaintext::from(w1[i].clone()), &Randomness(r1[i].clone())));
            encrypted_pairs.c2.push( Paillier::encrypt_with_chosen_randomness(ek, &RawPlaintext::from(w2[i].clone()), &Randomness(r2[i].clone())));
        }
        data_and_randmoness_pairs.w1.extend(w1.iter().cloned());
        data_and_randmoness_pairs.w2.extend(w2.iter().cloned());
        data_and_randmoness_pairs.r1.extend(r1.iter().cloned());
        data_and_randmoness_pairs.r2.extend(r2.iter().cloned());
        (encrypted_pairs,data_and_randmoness_pairs)
    }

    fn verify_commit(com: &BigInt, r: &BigInt, e: &Vec<u8>) -> bool
    {

        let mut digest = Context::new(&SHA256);
        digest.update(e);
        let m =  BigInt::from(digest.finish().as_ref());
        let com_tag = get_hash_commitment(&m, r);
        com == &com_tag

    }

    fn generate_proof(ek: &EncryptionKey, secret_x: &BigInt, secret_r: &BigInt ,e:  &Vec<u8>,range: &BigInt, data: &data_and_randmoness_pairs) -> z_vector
    {

        let bit: u8 = 1;
        let range_scaled_third: BigInt = range.div_floor(&BigInt::from(3i32));
        let mut masked_witness = masked_witness{
            j: Vec::new(),
            masked_x: Vec::new(),
            masked_r: Vec::new(),
        };
        let mut data_and_randmoness_pairs = data_and_randmoness_pairs{
            w1: Vec::new(),
            w2: Vec::new(),
            r1: Vec::new(),
            r2: Vec::new(),
        };
        let mut z_vector =  z_vector{
            map: Vec::new(),
            z1: data_and_randmoness_pairs,
            z2: masked_witness,
        };

        for i in 0..STATISTICAL_ERROR_FACTOR_IN_BYTES
            {
                let mut ei = &e[i];
                for j in 0..BITS_IN_BYTE
                    {
                        let ei = &(ei >> j);
                        let mut eij = ei & &bit;
                        let index = i*BITS_IN_BYTE + j;
                        if eij == 0{
                            z_vector.map.push(true);
                            z_vector.z1.w1.push(data.w1[index].clone());
                            z_vector.z1.w2.push(data.w2[index].clone());
                            z_vector.z1.r1.push(data.r1[index].clone());
                            z_vector.z1.r2.push(data.r2[index].clone());
                        }
                        else{
                            z_vector.map.push(false);
                            if &(secret_x + data.w1[index].clone()) > &range_scaled_third{
                                z_vector.z2.j.push(1);
                                z_vector.z2.masked_x.push(secret_x + data.w1[index].clone());
                                z_vector.z2.masked_r.push(secret_r * data.r1[index].clone() % &ek.n);

                            }
                            else{
                                z_vector.z2.j.push(2);
                                z_vector.z2.masked_x.push(secret_x + data.w2[index].clone());
                                z_vector.z2.masked_r.push(secret_r * data.r2[index].clone() % &ek.n);
                            }
                        }
                    }

            }
        z_vector

    }

    fn verifier_output(ek: &EncryptionKey, e:  &Vec<u8>, encrypted_pairs: &encrypted_pairs, z: &z_vector,range: &BigInt, cipher_x: &RawCiphertext) -> Result<(), ProofError>
    {

        let bit: u8 = 1;
        let mut res = true;
        let range_scaled_third: BigInt = range.div_floor(&BigInt::from(3i32));
        let range_scaled_two_thirds: BigInt = BigInt::from(2i32) * &range_scaled_third;
        let mut index0 = 0;
        let mut index1 = 0;
        for i in 0..STATISTICAL_ERROR_FACTOR_IN_BYTES
            {
                let mut ei = &e[i];
                for j in 0..BITS_IN_BYTE
                    {
                        let index = i*BITS_IN_BYTE + j;
                        let ei = &(ei >> j);
                        let mut eij = ei & &bit;

                        if eij == 0 {
                            if Paillier::encrypt_with_chosen_randomness(ek, &RawPlaintext::from( z.z1.w1[index0].clone()), &Randomness(z.z1.r1[index0].clone())) != encrypted_pairs.c1[index]{res = false;}
                            if Paillier::encrypt_with_chosen_randomness(ek, &RawPlaintext::from( z.z1.w2[index0].clone()), &Randomness(z.z1.r2[index0].clone())) != encrypted_pairs.c2[index]{res = false;}
                            let mut flag = false;
                            if z.z1.w1[index0] < range_scaled_third {
                                if z.z1.w2[index0] > range_scaled_third && z.z1.w2[index0] < range_scaled_two_thirds {flag = true; }
                            }
                            if z.z1.w2[index0] < range_scaled_third {
                                if z.z1.w1[index0] > range_scaled_third && z.z1.w1[index0] < range_scaled_two_thirds {flag = true; }
                            }
                            if flag==false {res = false;}
                            index0 = index0 + 1;
                        }
                            else{

                                let enc_zi =  Paillier::encrypt_with_chosen_randomness(ek, &RawPlaintext::from( z.z2.masked_x[index1].clone()), &Randomness(z.z2.masked_r[index1].clone()));
                                if z.z2.j[index1] == bit{
                                    let c = (&encrypted_pairs.c1[index].0 * &cipher_x.0) % &ek.nn;
                                    if c != enc_zi.0 {res = false;}
                                }
                                else{
                                    let c = (&encrypted_pairs.c2[index].0 * &cipher_x.0) % &ek.nn;
                                    if c != enc_zi.0 {res = false;}
                                }
                                if z.z2.masked_x[index1] < range_scaled_third && z.z2.masked_x[index1] > range_scaled_two_thirds {res = false;}
                                index1 = index1 + 1;

                            }



                    }

            }
        if res {
            Ok(())
        } else {
            Err(ProofError)
        }

    }
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
        let (com,r,e) = Paillier::verifier_commit();
        assert!(Paillier::verify_commit(&com, &r, &e))
    }

    #[test]
    fn test_generate_proof() {
        let (ek, dk) = test_keypair().keys();
        let range = BigInt::from(0xFFFFFFFFFFFFFi64);
        let (com,r,e) = Paillier::verifier_commit();
        let (encrypted_pairs, data_and_randmoness_pairs) = Paillier::generate_encrypted_pairs(&ek, &range);
        let secret_r = BigInt::sample_below(&ek.n);
        let secret_x = BigInt::from(0xFFFFFFFi64);
        let z_vector= Paillier::generate_proof(&ek,&secret_x,&secret_r,&e,&range,&data_and_randmoness_pairs);
    }

    #[test]
    fn test_range_proof() {
        /// common:
        let range = BigInt::from(0xFFFFFFFFFFFFFi64);
        /// prover:
        let (ek, dk) = test_keypair().keys();
        /// verifier:
        let (com,r,e) = Paillier::verifier_commit();
        /// prover:
        let (encrypted_pairs, data_and_randmoness_pairs) = Paillier::generate_encrypted_pairs(&ek, &range);
        /// prover:
        let secret_r = BigInt::sample_below(&ek.n);
        let secret_x = BigInt::from(0xFFFFFFFi64);
        /// common:
        let cipher_x = Paillier::encrypt_with_chosen_randomness(&ek, &RawPlaintext::from( secret_x.clone()), &Randomness(secret_r.clone()));
        // verifer decommits (tested in test_commit_decommit)
        /// prover:
        let z_vector= Paillier::generate_proof(&ek,&secret_x,&secret_r,&e,&range,&data_and_randmoness_pairs);
        /// verifier:
        let result = Paillier::verifier_output(&ek,&e,&encrypted_pairs,&z_vector,&range,&cipher_x );
        assert!(result.is_ok());
    }

    #[bench]
    fn bench_range_proof(b: &mut Bencher){
        // TODO: bench range for 256bit range.
        b.iter(|| {
            /// common:
            let range = BigInt::from(0xFFFFFFFFFFFFFi64);
            /// prover:
            let (ek, dk) = test_keypair().keys();
            /// verifier:
            let (com,r,e) = Paillier::verifier_commit();
            /// prover:
            let (encrypted_pairs, data_and_randmoness_pairs) = Paillier::generate_encrypted_pairs(&ek, &range);
            /// prover:
            let secret_r = BigInt::sample_below(&ek.n);
            let secret_x = BigInt::from(0xFFFFFFFi64);
            /// common:
            let cipher_x = Paillier::encrypt_with_chosen_randomness(&ek, &RawPlaintext::from( secret_x.clone()), &Randomness(secret_r.clone()));
            // verifer decommits (tested in test_commit_decommit)
            /// prover:
            let z_vector= Paillier::generate_proof(&ek,&secret_x,&secret_r,&e,&range,&data_and_randmoness_pairs);
            /// verifier:
            let result = Paillier::verifier_output(&ek,&e,&encrypted_pairs,&z_vector,&range,&cipher_x );
        });
    }

}