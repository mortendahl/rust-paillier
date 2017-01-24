
//! Standard encryption and decryption.

use super::*;


/// Encryption key that may be shared publicly.
#[derive(Debug,Clone)]
pub struct EncryptionKey<I> {
    pub n: I,  // the modulus
    nn: I, // the modulus squared
}


impl<I> ::traits::EncryptionKey for EncryptionKey<I> {}


impl<'kp, I> From<&'kp Keypair<I>> for EncryptionKey<I>
where
    I: Clone,
    for<'a, 'b> &'a I: Mul<&'b I, Output=I>,
{
    fn from(keypair: &'kp Keypair<I>) -> EncryptionKey<I> {
        let ref modulus = &keypair.p * &keypair.q;
        EncryptionKey {
            n: modulus.clone(),
            nn: modulus * modulus,
        }
    }
}


/// Decryption key that should be kept private.
#[derive(Debug,Clone)]
pub struct DecryptionKey<I> {
    p: I,  // first prime
    q: I,  // second prime
    n: I,  // the modulus (also in public key)
    nn: I,     // the modulus squared
    lambda: I, // fixed at lambda = (p-1)*(q-1)
    mu: I,     // fixed at lambda^{-1}
}

impl<I> ::traits::DecryptionKey for DecryptionKey<I> {}

impl<'kp, I> From<&'kp Keypair<I>> for DecryptionKey<I>
where
    I: One,
    I: Clone,
    I: ModInv,
    for<'a,'b> &'a I: Mul<&'b I, Output=I>,
    for<'a,'b> &'a I: Sub<&'b I, Output=I>,
{
    fn from(keypair: &'kp Keypair<I>) -> DecryptionKey<I> {
        let ref one = I::one();
        let modulus = &keypair.p * &keypair.q;
        let nn = &modulus * &modulus;
        let lambda = (&keypair.p - one) * (&keypair.q - one);
        let mu = I::modinv(&lambda, &modulus);
        DecryptionKey {
            p: keypair.p.clone(), // TODO store reference instead
            q: keypair.q.clone(),
            n: modulus,
            nn: nn,
            lambda: lambda,
            mu: mu,
        }
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
    I: One,
    for<'a,'b> &'a I: Add<&'b I, Output=I>,
    for<'a>    &'a I: Mul<I, Output=I>,
    for<'a,'b> &'a I: Mul<&'b I, Output=I>,
    for<'b>        I: Rem<&'b I, Output=I>,
{
    fn encrypt(ek: &EncryptionKey<I>, m: &Plaintext<I>) -> Ciphertext<I> {
        // here we assume that g = n+1
        let nm = &m.0 * &ek.n;
        let gx = (&nm + &I::one()) % &ek.nn;
        Self::rerandomise(ek, &Ciphertext(gx))
    }
}


impl<I, S> Addition<EncryptionKey<I>, Ciphertext<I>, Ciphertext<I>, Ciphertext<I>> for S
where
    S: AbstractScheme<BigInteger=I>,
    for<'a,'b> &'a I: Mul<&'b I, Output=I>,
    for<'b>        I: Rem<&'b I, Output=I>,
{
    fn add(ek: &EncryptionKey<I>, c1: &Ciphertext<I>, c2: &Ciphertext<I>) -> Ciphertext<I> {
        let c = (&c1.0 * &c2.0) % &ek.nn;
        Ciphertext(c)
    }
}


impl<I, S> Multiplication<EncryptionKey<I>, Ciphertext<I>, Plaintext<I>, Ciphertext<I>> for S
where
    S: AbstractScheme<BigInteger=I>,
    I: ModPow,
{
    fn mul(ek: &EncryptionKey<I>, c1: &Ciphertext<I>, m2: &Plaintext<I>) -> Ciphertext<I> {
        let c = I::modpow(&c1.0, &m2.0, &ek.nn);
        Ciphertext(c)
    }
}


impl<I, S> Decryption<DecryptionKey<I>, Ciphertext<I>, Plaintext<I>> for S
where
    S: AbstractScheme<BigInteger=I>,
    I: One,
    I: ModPow,
    for<'a>    &'a I: Sub<I, Output=I>,
    for<'b>        I: Mul<&'b I, Output=I>,
    for<'b>        I: Div<&'b I, Output=I>,
    for<'a>        I: Rem<&'a I, Output=I>,
{
    fn decrypt(dk: &DecryptionKey<I>, c: &Ciphertext<I>) -> Plaintext<I> {
        let u = I::modpow(&c.0, &dk.lambda, &dk.nn);
        let m = (l(&u, &dk.n) * &dk.mu) % &dk.n;
        Plaintext(m)
    }
}
