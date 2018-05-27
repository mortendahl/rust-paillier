use super::*;
use arithimpl::traits::*;
use num_traits::{Zero, One};
use std::ops::{Sub, Mul, Rem};
use crypto::sha2::Sha256;
use crypto::digest::Digest;

const SECURITY_FACTOR : usize = 40;

pub trait ZKVerifier<'ek, I>
{
    fn generate_challenge(&'ek self) -> (Vec<I>, I, Vec<I>);
    fn verify(&'ek self, challenge: &Vec<I>, proof: &I) -> Result<(), String>;
}

#[allow(dead_code)] // TODO: to remove once implementation is done
impl<'ek, I> ZKVerifier<'ek, I> for EncryptionKey<I>
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
    #[allow(unused)] // TODO: to remove once implementation is done
    fn generate_challenge(&'ek self) -> (Vec<I>, I, Vec<I>) {
        let (mut y, mut challenge) : (Vec<I>, Vec<I>) = (Vec::new(), Vec::new());

        let mut i : usize = 0;
        while i < SECURITY_FACTOR {
            let candidate = I::sample_below(&self.n);
            let (g, s, t) = I::egcd(&self.n, &candidate);
            if g != I::one() { continue; }

            y.push(candidate);
            challenge.push(I::modpow(
                &y.get(i).unwrap(), &self.n, &self.n));

            i += 1;
        }

        let (mut random, mut a) : (Vec<I>, Vec<I>) = (Vec::new(), Vec::new());
        let mut a_x_hash = Sha256::new();
        a_x_hash.input_str(&I::to_hex_str(&self.n));

        let mut j : usize = 0;
        while j < SECURITY_FACTOR {
            let candidate = I::sample_below(&self.n);
            let (g, s, t) = I::egcd(&self.n, &candidate);
            if g != I::one() { continue; }

            random.push(candidate);
            a.push(I::modpow(
                &random.get(i).unwrap(), &self.n, &self.n));

            a_x_hash.input_str(&I::to_hex_str(&challenge.get(j).unwrap()));
            a_x_hash.input_str(&I::to_hex_str(&a.get(j).unwrap()));

            j += 1;
        }

        let e : I = I::from_hex_str(a_x_hash.result_str());

        let mut z : Vec<I> = Vec::new();

        let mut k : usize = 0;
        while k < SECURITY_FACTOR {
            let mod_k_n = random.get(k).unwrap() % &self.n;
            let mod_pow_y_e_n = I::modpow(
                &y.get(k).unwrap(), &e, &self.n);

            z.push((mod_k_n * mod_pow_y_e_n) % &self.n);
            k+= 1;
        }

        (challenge, e, z)
    }

    #[allow(unused)] // TODO: to remove once implementation is done
    fn verify(&'ek self, challenge: &Vec<I>, proof: &I) -> Result<(), String> {
        unimplemented!();
    }
}

pub trait ZKProver<'dk, I>
{
    fn generate_proof(&'dk self, challenge: &Vec<I>, e: &I, z: &Vec<I>) -> I;
}

#[allow(dead_code)] // TODO: to remove once implementation is done
impl<'a, I> ZKProver<'a, I> for DecryptionKey<I>
{
    #[allow(unused)] // TODO: to remove once implementation is done
    fn generate_proof(&'a self, challenge: &Vec<I>, e: &I, z: &Vec<I>) -> I {
        unimplemented!();
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
    #[should_panic] // TODO: to remove once the implementation is done. This is just here to not break the build.
    fn test_correct_zk_proof() {
        let (ek, dk) = test_keypair().keys();

        let (challenge, e, z) = ek.generate_challenge();
        let proof = dk.generate_proof(&challenge, &e, &z);
        let result = ek.verify(&challenge, &proof);

        assert!(result.is_ok())
    }
});