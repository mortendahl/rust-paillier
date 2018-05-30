use super::*;
use arithimpl::traits::*;

use num_traits::{Zero, One};
use std::ops::{Sub, Mul, Rem};

use crypto::sha2::Sha256;
use crypto::digest::Digest;

use std::error::Error;
use std::fmt;

impl fmt::Display for ZKVerifierError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "ZKVerifierError")
    }
}

impl Error for ZKVerifierError {
    fn description(&self) -> &str {
        "Error while verifying"
    }
}

impl<I> ZKVerifier<I> for EncryptionKey<I>
    where
        I : Samplable,
        I : Eq,
        I : One,
        I : Zero,
        I : ModPow,
        I : Sub<I, Output=I>,
        I : EGCD,
        I : ToString,
        I : FromString<I>,
        for<'a>        I: Rem<&'a I, Output=I>,
        for<'a,'b> &'a I: Rem<&'b I, Output=I>,
        for<'a>    &'a I: Mul<I, Output=I>,
{
    fn generate_challenge(&self) -> (Vec<I>, I, Vec<I>, Vec<I>) {
        let (mut y, mut challenge) : (Vec<I>, Vec<I>) = (Vec::new(), Vec::new());

        let mut i : usize = 0;
        while i < ZK_SECURITY_FACTOR {
            let candidate = I::sample_below(&self.n);
            if I::egcd(&self.n, &candidate).0 != I::one() { continue; }

            y.push(candidate);
            challenge.push(I::modpow(&y[i], &self.n, &self.n));

            i += 1;
        }

        let (mut random, mut a) : (Vec<I>, Vec<I>) = (Vec::new(), Vec::new());

        let mut a_x_hash = Sha256::new();
        a_x_hash.input_str(&I::to_hex_str(&self.n));

        let mut j : usize = 0;
        while j < ZK_SECURITY_FACTOR {
            let candidate = I::sample_below(&self.n);
            if I::egcd(&self.n, &candidate).0 != I::one() { continue; }

            random.push(candidate);
            a.push(I::modpow(&random[j], &self.n, &self.n));

            a_x_hash.input_str(&I::to_hex_str(&challenge[j]));
            a_x_hash.input_str(&I::to_hex_str(&a[j]));

            j += 1;
        }

        let e : I = I::from_hex_str(a_x_hash.result_str());

        let mut z : Vec<I> = Vec::new();

        let mut k : usize = 0;
        while k < ZK_SECURITY_FACTOR {
            z.push(((&random[k] % &self.n) * I::modpow(&y[k], &e, &self.n)) % &self.n);
            k+= 1;
        }

        (challenge, e, z, y )
    }

    fn verify(&self, proof: &I, y:  &Vec<I>) -> Result<(), ZKVerifierError> {
        let mut y_hash = Sha256::new();

        let mut v : usize = 0;
        while v < ZK_SECURITY_FACTOR {
            y_hash.input_str(&I::to_hex_str(&y[v]));
            v += 1;
        }

        if &I::from_hex_str(y_hash.result_str()) != proof {
            Err(ZKVerifierError)
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
    use zkproof::*;

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
        let mut attempt : usize = 10;

        while attempt > 0 {
            let (ek, dk) = test_keypair().keys();

            let (challenge, e, z, y) = ek.generate_challenge();

            let proof = dk.generate_proof(&challenge, &e, &z);
            assert!(proof.is_ok());

            let result = ek.verify(&proof.unwrap(), &y);
            assert!(result.is_ok());

            attempt -= 1;
        }
    }

    #[test]
    fn test_incorrect_zk_proof() {
        let (ek, dk) = test_keypair().keys();

        let (challenge, e, _z, y) = ek.generate_challenge();

        let proof = dk.generate_proof(&challenge, &e, &y);
        assert!(proof.is_err()); // ERROR expected because of the use of y instead of z
    }

    #[test]
    fn test_incorrect_zk_proof_2() {
        let (ek, dk) = test_keypair().keys();

        let (challenge, e, z, y) = ek.generate_challenge();
        let proof = dk.generate_proof(&challenge, &e, &z);
        assert!(proof.is_ok());

        let result = ek.verify(&e, &y);
        assert!(result.is_err()); // ERROR expected becasue use of e instead of proof
    }
});