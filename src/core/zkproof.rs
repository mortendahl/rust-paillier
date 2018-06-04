use super::*;

use num_traits::{Zero, One};
use std::ops::{Sub, Mul, Rem};
use std::iter;

use ring::digest::{Context, SHA256};

use std::error::Error;
use std::fmt;
use core::{ EncryptionKey, DecryptionKey };

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

pub struct Challenge<I> {
    x: Vec<I>,
    e: I,
    z: Vec<I>,
}

pub struct VerificationAid<I> {
    y_digest: I
}

pub struct CorrectKeyProof<I> {
    y_digest : I
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
pub trait ProveCorrectKey<I, EK, DK> {
    /// Generate challenge for given encryption key.
    fn challenge(ek: &EK) -> (Challenge<I>, VerificationAid<I>);

    /// Generate proof given decryption key.
    fn prove(dk: &DK, challenge: &Challenge<I>) -> Result<CorrectKeyProof<I>, ProofError>;

    /// Verify proof.
    fn verify(proof: &CorrectKeyProof<I>, aid: &VerificationAid<I>) -> Result<(), ProofError>;
}

fn compute_digest<'i, IT, I: 'i>(values: IT) -> I
where
    IT: Iterator<Item=&'i I>,
    I: ToString + FromString<I>,
{
    // TODO[Morten] use https://github.com/fizyk20/rust-gmp/pull/4/files instead of convertion to hex?
    let mut digest = Context::new(&SHA256);
    for value in values {
        digest.update(ToString::to_hex_str(value).as_bytes());
    }
    I::get_from_digest(digest.finish())
}

impl<I, S> ProveCorrectKey<I, EncryptionKey<I>, DecryptionKey<I>> for S
    where
        S : AbstractScheme<BigInteger=I>,
        I : Samplable,
        I : Eq,
        I : One,
        I : Zero,
        I : ModInv,
        I : ModPow,
        I : ModMul,
        I : Sub<I, Output=I>,
        I : EGCD,
        I : ToString,
        I : FromString<I>,
        for<'a>    &'a I: Add<I, Output=I>,
        for<'b>        I: Add<&'b I, Output=I>,
        for<'a,'b> &'a I: Sub<&'b I, Output=I>,
        for<'a>        I: Rem<&'a I, Output=I>,
        for<'a,'b> &'a I: Rem<&'b I, Output=I>,
        for<'a>    &'a I: Mul<I, Output=I>,
{
    fn challenge(ek: &EncryptionKey<I>) -> (Challenge<I>, VerificationAid<I>) {

        // TODO[Morten] 
        // most of these could probably be run in parallel with Rayon
        // after simplification (using `into_par_iter` in some cases)

        // Compute challenges in the form of n-powers

        let y: Vec<_> = (0..STATISTICAL_ERROR_FACTOR)
            .map(|_| I::sample_below(&ek.n))
            .collect();

        let x: Vec<_> = y.iter()
            .map(|yi| I::modpow(yi, &ek.n, &ek.n))
            .collect();

        // Compute non-interactive proof of knowledge of the n-roots in the above
        // TODO[Morten] introduce new proof type for this that can be used independently?

        let r: Vec<_> = (0..STATISTICAL_ERROR_FACTOR)
            .map(|_| I::sample_below(&ek.n))
            .collect();

        let a : Vec<_> = r.iter()
            .map(|ri| I::modpow(ri, &ek.n, &ek.n))
            .collect();

        let e = compute_digest(
            iter::once(&ek.n)
                .chain(&x)
                .chain(&a)
        );

        let z: Vec<_> = r.iter()
            .zip(y.iter())
            .map(|(ri, yi)| (ri * I::modpow(yi, &e, &ek.n)) % &ek.n)
            .collect();

        // Compute expected result for equality test in verification
        let y_digest: I = compute_digest(y.iter());

        (Challenge { x, e, z }, VerificationAid { y_digest })
    }

    fn prove(dk: &DecryptionKey<I>, challenge: &Challenge<I>) -> Result<CorrectKeyProof<I>, ProofError>
    {
        // check x co-prime with n
        if challenge.x.iter().any(|xi| I::egcd(&dk.n, xi).0 != I::one()) {
            return Err(ProofError)
        }

        // check z co-prime with n
        if challenge.z.iter().any(|zi| I::egcd(&dk.n, zi).0 != I::one()) {
            return Err(ProofError)
        }

        // reconstruct a
        let phi = (&dk.p - &I::one()) * (&dk.q - &I::one());
        let phimine = &phi - &(&challenge.e % &phi);
        let a: Vec<_> = challenge.z.iter().zip(challenge.x.iter())
            .map(|(zi, xi)| {
                let zn = I::modpow(zi, &dk.n, &dk.n);
                let xphi = I::modpow(xi, &phimine, &dk.n);
                (zn * xphi) % &dk.n
            })
            .collect();

        // check a co-prime with n
        if a.iter().any(|ai| I::egcd(&dk.n, ai).0 != I::one()) {
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

        // TODO[Morten]
        // some of these are already stored in the key
        let dn = I::modinv(&dk.n, &phi);
        let dp = &dn % &(&dk.p - &I::one());
        let dq = &dn % &(&dk.q - &I::one());
        let qinvp = I::modinv(&dk.q, &dk.p);

        // TODO[Morten]
        // move to public method for etracting randomness

        // TODO[Morten]
        // there should be no need to `collect` first, simply
        // pass iterator directly to `compute_digest`; need to
        // convert that iterator into one that returns references
        // first though

        let foo: Vec<_> = challenge.x.iter()
            .map(|xi| {
                let xp = xi % &dk.p;
                let mp = I::modpow(&xp, &dp, &dk.p);

                let xq = xi % &dk.q;
                let mq = I::modpow(&xq, &dq, &dk.q);

                let yi = &mq + (&dk.q * I::modmul(&qinvp, &(&mp - &mq), &dk.p));
                yi
            })
            .collect();
        let y_digest: I = compute_digest(foo.iter());

        Ok(CorrectKeyProof { y_digest })
    }

    fn verify(proof: &CorrectKeyProof<I>, va: &VerificationAid<I>) -> Result<(), ProofError> {
        let expected_y_digest = &va.y_digest;
        let actual_y_digest = &proof.y_digest;

        if actual_y_digest == expected_y_digest {
            Ok(())
        } else {
            Err(ProofError)
        }
    }
}

bigint!(I,
#[cfg(test)]
mod tests {
    use super::*;
    use traits::*;
    use ::AbstractPaillier;
    use core::*;
    use core::zkproof::ProveCorrectKey;

    fn test_keypair() -> Keypair<I> {
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

        let (challenge, verification_aid) = AbstractPaillier::challenge(&ek);
        let proof_results = AbstractPaillier::prove(&dk, &challenge);
        assert!(proof_results.is_ok());

        let result = AbstractPaillier::verify(&proof_results.unwrap(), &verification_aid);
        assert!(result.is_ok());
    }

    #[test]
    fn test_incorrect_zk_proof() {
        let (ek, dk) = test_keypair().keys();

        let (mut challenge, _verification_aid) = AbstractPaillier::challenge(&ek);
        challenge.e += 1;
        let proof_results = AbstractPaillier::prove(&dk, &challenge);

        assert!(proof_results.is_err()); // ERROR expected because of manipulated challenge
    }

    #[test]
    fn test_incorrect_zk_proof_2() {
        let (ek, dk) = test_keypair().keys();

        let (challenge, mut verification_aid) = AbstractPaillier::challenge(&ek);
        let proof_results = AbstractPaillier::prove(&dk, &challenge);
        assert!(proof_results.is_ok());

        verification_aid.y_digest += 1;
        let result = AbstractPaillier::verify(&proof_results.unwrap(), &verification_aid);
        assert!(result.is_err()); // ERROR expected because of manipulated aid
    }

});