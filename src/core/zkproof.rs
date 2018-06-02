use super::*;

use num_traits::{Zero, One};
use std::ops::{Sub, Mul, Rem};

use crypto::sha2::Sha256;
use crypto::digest::Digest;

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

pub struct CorrectInputProof<I> {
    pub e : I,
    pub z : Vec<I>,
}

pub struct CorrectKeyProof<I> {
    pub proof : I,
}

pub trait ProveCorrectKey<I, EK, DK> {
    fn generate_challenge(ek: &EK) -> (Vec<I>, CorrectInputProof<I>, Vec<I>);
    fn prove(dk: &DK, challenge: &Vec<I>, correct_input_proof: &CorrectInputProof<I>)
        -> Result<CorrectKeyProof<I>, ProofError>;
    fn verify(correct_key_proof: &CorrectKeyProof<I>, y: &Vec<I>) -> Result<(), ProofError>;
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
    fn generate_challenge(ek: &EncryptionKey<I>) -> (Vec<I>, CorrectInputProof<I>, Vec<I>) {
        let (mut y, mut challenge) : (Vec<I>, Vec<I>) = (Vec::new(), Vec::new());

        for i in 0..STATISTICAL_ERROR_FACTOR {
            let candidate = I::sample_below(&ek.n);

            y.push(candidate);
            challenge.push(I::modpow(&y[i], &ek.n, &ek.n));
        }

        let (mut random, mut a) : (Vec<I>, Vec<I>) = (Vec::new(), Vec::new());

        let mut a_x_hash = Sha256::new();
        a_x_hash.input_str(&I::to_hex_str(&ek.n));

        for i in 0..STATISTICAL_ERROR_FACTOR {
            let candidate = I::sample_below(&ek.n);
            if I::egcd(&ek.n, &candidate).0 != I::one() { continue; }

            random.push(candidate);
            a.push(I::modpow(&random[i], &ek.n, &ek.n));

            a_x_hash.input_str(&I::to_hex_str(&challenge[i]));
            a_x_hash.input_str(&I::to_hex_str(&a[i]));
        }

        let e : I = I::from_hex_str(&a_x_hash.result_str());

        let mut z : Vec<I> = Vec::new();

        for i in 0..STATISTICAL_ERROR_FACTOR {
            z.push(((&random[i] % &ek.n) * I::modpow(&y[i], &e, &ek.n)) % &ek.n);
        }

        (challenge, CorrectInputProof { e, z }, y)
    }

    fn prove(dk: &DecryptionKey<I>, challenge: &Vec<I>, correct_input_proof: &CorrectInputProof<I>)
        -> Result<CorrectKeyProof<I>, ProofError>
    {
        let phi = (&dk.p - &I::one()) * (&dk.q - &I::one());

        let mut a : Vec<I> = Vec::new();
        for i in 0..STATISTICAL_ERROR_FACTOR {
            if I::egcd(&dk.n, &correct_input_proof.z[i]).0 != I::one() ||
                I::egcd(&dk.n, &challenge[i]).0 != I::one() {
                return Err(ProofError);
            }

            let zn = I::modpow(&correct_input_proof.z[i], &dk.n, &dk.n);
            let cphi = I::modpow(&challenge[i], &phi, &dk.n);
            let cminphi = I::modinv(
                &I::modpow(&challenge[i], &correct_input_proof.e, &dk.n), &dk.n);

            a.push((zn * cphi * cminphi) %& dk.n);

            if I::egcd(&dk.n, &correct_input_proof.z[i]).0 != I::one(){
                return Err(ProofError);
            }
        }

        let mut a_x_hash = Sha256::new();
        a_x_hash.input_str(&I::to_hex_str(&dk.n));

        for i in 0..STATISTICAL_ERROR_FACTOR {
            a_x_hash.input_str(&I::to_hex_str(&challenge[i]));
            a_x_hash.input_str(&I::to_hex_str(&a[i]));
        }

        if &I::from_hex_str(&a_x_hash.result_str()) != &correct_input_proof.e {
            return Err(ProofError);
        }

        let dn = I::modinv(&dk.n, &phi);
        let dp = &dn % &(&dk.p - &I::one());
        let dq = &dn % &(&dk.q - &I::one());

        let mut y_tag_hash = Sha256::new();

        for i in 0..STATISTICAL_ERROR_FACTOR {
            let cp = &challenge[i] % &dk.p;
            let mp = I::modpow(&cp, &dp, &dk.p);

            let cq = &challenge[i] % &dk.q;
            let mq = I::modpow(&cq, &dq, &dk.q);

            let qinvp = I::modinv(&dk.q, &dk.p);
            let mtag = &mq + (&dk.q * I::modmul(&qinvp, &(&mp - &mq), &dk.p));

            y_tag_hash.input_str(&I::to_hex_str(&mtag));
        }

        Ok(CorrectKeyProof { proof: I::from_hex_str(&y_tag_hash.result_str()) })
    }

    fn verify(correct_key_proof: &CorrectKeyProof<I>, y: &Vec<I>) -> Result<(), ProofError> {
        let mut y_hash = Sha256::new();

        let mut v : usize = 0;
        while v < STATISTICAL_ERROR_FACTOR {
            y_hash.input_str(&I::to_hex_str(&y[v]));
            v += 1;
        }

        if &I::from_hex_str(&y_hash.result_str()) != &correct_key_proof.proof {
            Err(ProofError)
        } else {
            Ok(())
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

        let (challenge, correct_input_proof, y) = AbstractPaillier::generate_challenge(&ek);
        let proof_results = AbstractPaillier::prove(&dk, &challenge, &correct_input_proof);
        assert!(proof_results.is_ok());

        let result = AbstractPaillier::verify(&proof_results.unwrap(), &y);
        assert!(result.is_ok());
    }

    #[test]
    fn test_incorrect_zk_proof() {
        let (ek, dk) = test_keypair().keys();

        let (_challenge, correct_input_proof, y) = AbstractPaillier::generate_challenge(&ek);
        let proof_results = AbstractPaillier::prove(&dk, &y, &correct_input_proof);

        assert!(proof_results.is_err()); // ERROR expected because of the use of y instead of challenge
    }

    #[test]
    fn test_incorrect_zk_proof_2() {
        let (ek, dk) = test_keypair().keys();

        let (challenge, correct_input_proof, _y) = AbstractPaillier::generate_challenge(&ek);
        let proof_results = AbstractPaillier::prove(&dk, &challenge, &correct_input_proof);
        assert!(proof_results.is_ok());

        let result = AbstractPaillier::verify(&proof_results.unwrap(), &challenge);
        assert!(result.is_err()); // ERROR expected becasue use of challenge instead of y
    }

});