use super::*;

pub trait ZKVerifier<'ek, T>
{
    fn generate_challenge(&'ek self) -> Vec<T>;
    fn verify(&'ek self, challenge: &Vec<T>, proof: &T) -> Result<(), String>;
}

#[allow(dead_code)] // TODO: to remove once implementation is done
impl<'a, I> ZKVerifier<'a, I> for EncryptionKey<I>
{
    #[allow(unused)] // TODO: to remove once implementation is done
    fn generate_challenge(&'a self) -> Vec<I> {
        unimplemented!();
    }

    #[allow(unused)] // TODO: to remove once implementation is done
    fn verify(&'a self, challenge: &Vec<I>, proof: &I) -> Result<(), String> {
        unimplemented!();
    }
}

pub trait ZKProver<'dk, T>
{
    fn generate_proof(&'dk self, challenge: &Vec<T>) -> T;
}

#[allow(dead_code)] // TODO: to remove once implementation is done
impl<'a, I> ZKProver<'a, I> for DecryptionKey<I>
{
    #[allow(unused)] // TODO: to remove once implementation is done
    fn generate_proof(&'a self, challenge: &Vec<I>) -> I {
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

        let challenge = ek.generate_challenge();
        let proof = dk.generate_proof(&challenge);
        let result = ek.verify(&challenge, &proof);

        assert!(result.is_ok())
    }
});