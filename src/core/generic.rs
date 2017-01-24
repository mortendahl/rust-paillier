
//! Slower generic encryption supporting an arbitrary generator.

use super::*;


/// Encryption key that may be shared publicly.
#[derive(Debug,Clone)]
pub struct EncryptionKey<I> {
    pub n: I,  // the modulus
    pub nn: I, // the modulus squared
    pub g: I,  // the generator
}


impl<I> ::traits::EncryptionKey for EncryptionKey<I> {}


impl<'kp, 'g, I> From<(&'kp Keypair<I>, &'g I)> for EncryptionKey<I>
where
    I: Clone,
    for<'a, 'b> &'a I: Mul<&'b I, Output=I>,
{
    fn from((keypair, generator) : (&'kp Keypair<I>, &'g I)) -> EncryptionKey<I> {
        let ref modulus = &keypair.p * &keypair.q;
        EncryptionKey {
            n: modulus.clone(),
            nn: modulus * modulus,
            g: generator.clone(),
        }
    }
}


impl<'kp, I> From<&'kp Keypair<I>> for EncryptionKey<I>
where
    I: One,
    I: Clone,
    for<'a, 'b> &'a I: Add<I, Output=I>,
    for<'a, 'b> &'a I: Mul<&'b I, Output=I>,
{
    fn from(keypair: &'kp Keypair<I>) -> EncryptionKey<I> {
        let ref n = &keypair.p * &keypair.q;
        let ref g = n + I::one(); // default; would be more efficient to use another key for this case
        EncryptionKey::from((keypair, g))
    }
}


impl<I, S> Rerandomisation<EncryptionKey<I>, Ciphertext<I>> for S
where
    S: AbstractScheme<BigInteger=I>,
    I: Samplable,
    I: ModPow,
    for<'a>    &'a I: Mul<I, Output=I>,
    for<'b>        I: Rem<&'b I, Output=I>,
{
    fn rerandomise(ek: &EncryptionKey<I>, c: &Ciphertext<I>) -> Ciphertext<I> {
        let r = I::sample_below(&ek.n);
        let d = (&c.0 * I::modpow(&r, &ek.n, &ek.nn)) % &ek.nn;
        Ciphertext(d)
    }
}


impl<I, S> Encryption<EncryptionKey<I>, Plaintext<I>, Ciphertext<I>> for S
where
    S: AbstractScheme<BigInteger=I>,
    S: Rerandomisation<EncryptionKey<I>, Ciphertext<I>>,
    I: ModPow,
{
    fn encrypt(ek: &EncryptionKey<I>, m: &Plaintext<I>) -> Ciphertext<I> {
        let gm = I::modpow(&ek.g, &m.0, &ek.nn);
        Self::rerandomise(ek, &Ciphertext(gm))
    }
}



bigint!(I,
#[cfg(test)]
mod tests {

    use super::I;
    use ::AbstractPaillier;
    use ::core::*;
    use ::coding::*;

    fn test_keypair() -> Keypair<I> {
        let p = str::parse("148677972634832330983979593310074301486537017973460461278300587514468301043894574906886127642530475786889672304776052879927627556769456140664043088700743909632312483413393134504352834240399191134336344285483935856491230340093391784574980688823380828143810804684752914935441384845195613674104960646037368551517").unwrap();
        let q = str::parse("158741574437007245654463598139927898730476924736461654463975966787719309357536545869203069369466212089132653564188443272208127277664424448947476335413293018778018615899291704693105620242763173357203898195318179150836424196645745308205164116144020613415407736216097185962171301808761138424668335445923774195463").unwrap();
        Keypair {
            p: p,
            q: q,
        }
    }

    #[test]
    fn test_correct_encryption_decryption() {
        let ref keypair = test_keypair();
        let ek: generic::EncryptionKey<_> = generic::EncryptionKey::from(keypair);
        let dk: crt::DecryptionKey<_> = crt::DecryptionKey::from(keypair);
        let code = integral::Code::default();

        let m = code.encode(&10_u64);
        let c = AbstractPaillier::encrypt(&ek, &m);

        let recovered_m = AbstractPaillier::decrypt(&dk, &c);
        assert_eq!(recovered_m, m);
    }

});
