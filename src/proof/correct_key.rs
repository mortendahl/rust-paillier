use std::fmt;
use std::iter;
use std::error::Error;
use std::borrow::Borrow;

use ring::digest::{Context, SHA256};

use ::arithimpl::traits::*;
use ::BigInteger as BigInt;
use core::extract_nroot;
use ::Paillier as Paillier;
use ::{EncryptionKey, DecryptionKey};

use rayon::prelude::*;

const STATISTICAL_ERROR_FACTOR: usize = 40;


#[derive(Debug)]
pub struct ProofError;

impl fmt::Display for ProofError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "ProofError")
    }
}

impl Error for ProofError {
    fn description(&self) -> &str {
        "Error while verifying"
    }
}

pub struct Challenge {
    x: Vec<BigInt>,
    e: BigInt,
    z: Vec<BigInt>,
}

pub struct VerificationAid {
    y_digest: BigInt
}

pub struct CorrectKeyProof {
    y_digest: BigInt
}

/// Zero-knowledge proof of co-primality between the encryption modulus and its order.
///
/// The sub-protocol for proving knowledge of challenge plaintexts is made non-interactive
/// using the [Fiat-Shamir heuristic](https://en.wikipedia.org/wiki/Fiat%E2%80%93Shamir_heuristic).
///
/// References:
/// - section 3.1 in [Lindell'17](https://eprint.iacr.org/2017/552)
/// - section 3.3 in [HMRTN'12](https://eprint.iacr.org/2011/494)
/// - section 4.2 in [DJ'01](http://www.brics.dk/RS/00/45/BRICS-RS-00-45.pdf)
pub trait CorrectKey<EK, DK> {
    /// Generate challenge for given encryption key.
    fn challenge(ek: &EK) -> (Challenge, VerificationAid);

    /// Generate proof given decryption key.
    fn prove(dk: &DK, challenge: &Challenge) -> Result<CorrectKeyProof, ProofError>;

    /// Verify proof.
    fn verify(proof: &CorrectKeyProof, aid: &VerificationAid) -> Result<(), ProofError>;
}

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

impl CorrectKey<EncryptionKey, DecryptionKey> for Paillier
{
    fn challenge(ek: &EncryptionKey) -> (Challenge, VerificationAid) {

        // FIXME[Morten]
        // settle the question of whether using n instead of n^2 is okay

        // TODO[Morten] 
        // most of these could probably be run in parallel with Rayon
        // after simplification (using `into_par_iter` in some cases)

        // Compute challenges in the form of n-powers

        let y: Vec<_> = (0..STATISTICAL_ERROR_FACTOR)
            .map(|_| BigInt::sample_below(&ek.n))
            .collect();

        let x: Vec<_> = y.par_iter()
            .map(|yi| BigInt::modpow(yi, &ek.n, &ek.n))
            .collect();

        // Compute non-interactive proof of knowledge of the n-roots in the above
        // TODO[Morten] introduce new proof type for this that can be used independently?

        let r: Vec<_> = (0..STATISTICAL_ERROR_FACTOR)
            .map(|_| BigInt::sample_below(&ek.n))
            .collect();

        let a : Vec<_> = r.par_iter()
            .map(|ri| BigInt::modpow(ri, &ek.n, &ek.n))
            .collect();

        let e = compute_digest(
            iter::once(&ek.n)
                .chain(&x)
                .chain(&a)
        );

        let z: Vec<_> = r.par_iter()
            .zip(y.par_iter())
            .map(|(ri, yi)| (ri * BigInt::modpow(yi, &e, &ek.n)) % &ek.n)
            .collect();

        // Compute expected result for equality test in verification
        let y_digest: BigInt = compute_digest(y.iter());

        (Challenge { x, e, z }, VerificationAid { y_digest })
    }

    fn prove(dk: &DecryptionKey, challenge: &Challenge) -> Result<CorrectKeyProof, ProofError>
    {
        // check x co-prime with n
        if challenge.x.par_iter().any(|xi| BigInt::egcd(&dk.n, xi).0 != BigInt::one()) {
            return Err(ProofError)
        }

        // check z co-prime with n
        if challenge.z.par_iter().any(|zi| BigInt::egcd(&dk.n, zi).0 != BigInt::one()) {
            return Err(ProofError)
        }

        // reconstruct a
        let phimine = &dk.phi - (&challenge.e % &dk.phi);
        let a: Vec<_> = challenge.z.par_iter().zip(challenge.x.par_iter())
            .map(|(zi, xi)| {
                let zn = BigInt::modpow(zi, &dk.n, &dk.n);
                let xphi = BigInt::modpow(xi, &phimine, &dk.n);
                (zn * xphi) % &dk.n
            })
            .collect();

        // check a co-prime with n
        if a.par_iter().any(|ai| BigInt::egcd(&dk.n, ai).0 != BigInt::one()) {
            return Err(ProofError)
        }

        // check that e was computed correctly
        let e = compute_digest(
            iter::once(&dk.n)
                .chain(&challenge.x)
                .chain(&a)
        );
        if challenge.e != e {
            return Err(ProofError)
        }

        // compute proof in the form of a hash of the recovered roots
        let y_digest = compute_digest(
            challenge.x.iter()
                .map(|xi| extract_nroot(dk, xi)));

        Ok(CorrectKeyProof { y_digest })
    }

    fn verify(proof: &CorrectKeyProof, va: &VerificationAid) -> Result<(), ProofError> {
        // compare actual with expected
        if proof.y_digest == va.y_digest {
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

    fn test_keypair() -> Keypair {
        let p = str::parse("148677972634832330983979593310074301486537017973460461278300587514468301043894574906886127642530475786889672304776052879927627556769456140664043088700743909632312483413393134504352834240399191134336344285483935856491230340093391784574980688823380828143810804684752914935441384845195613674104960646037368551517").unwrap();
        let q = str::parse("158741574437007245654463598139927898730476924736461654463975966787719309357536545869203069369466212089132653564188443272208127277664424448947476335413293018778018615899291704693105620242763173357203898195318179150836424196645745308205164116144020613415407736216097185962171301808761138424668335445923774195463").unwrap();
        Keypair {
            p: p,
            q: q,
        }
    }

    #[test]
    fn test_correct_zk_proof() {
        let (ek, dk) = test_keypair().keys();

        let (challenge, verification_aid) = Paillier::challenge(&ek);
        let proof_results = Paillier::prove(&dk, &challenge);
        assert!(proof_results.is_ok());

        let result = Paillier::verify(&proof_results.unwrap(), &verification_aid);
        assert!(result.is_ok());
    }

    #[test]
    fn test_incorrect_zk_proof() {
        let (ek, dk) = test_keypair().keys();

        let (mut challenge, _verification_aid) = Paillier::challenge(&ek);
        challenge.e += 1;
        let proof_results = Paillier::prove(&dk, &challenge);

        assert!(proof_results.is_err()); // ERROR expected because of manipulated challenge
    }

    #[test]
    fn test_incorrect_zk_proof_2() {
        let (ek, dk) = test_keypair().keys();

        let (challenge, mut verification_aid) = Paillier::challenge(&ek);
        let proof_results = Paillier::prove(&dk, &challenge);
        assert!(proof_results.is_ok());

        verification_aid.y_digest += 1;
        let result = Paillier::verify(&proof_results.unwrap(), &verification_aid);
        assert!(result.is_err()); // ERROR expected because of manipulated aid
    }

}