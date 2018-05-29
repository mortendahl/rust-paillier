
//! Core Paillier encryption scheme supporting ciphertext addition and plaintext multiplication.

use std::fmt;

use ::traits::*;
use ::arithimpl::traits::*;
use ::BigInteger as BigInt;


/// Representation of a keypair from which encryption and decryption keys can be derived.
pub struct Keypair {
    pub p: BigInt,
    pub q: BigInt,
}

impl DefaultKeys for Keypair
{
    type EK = EncryptionKey;
    type DK = DecryptionKey;

    fn encryption_key(&self) -> Self::EK {
        EncryptionKey::from(self)
    }

    fn decryption_key(&self) -> Self::DK {
        DecryptionKey::from(self)
    }
}

impl<'p, 'q> From<(&'p BigInt, &'q BigInt)> for Keypair
{
    fn from((p, q) : (&'p BigInt, &'q BigInt)) -> Keypair {
        Keypair {
            p: p.clone(),
            q: q.clone(),
        }
    }
}

/// Representation of unencrypted message.
#[derive(Clone,Debug,PartialEq)]
pub struct Plaintext(pub BigInt);

/// Representation of encrypted message.
#[derive(Clone,Debug,PartialEq)]
pub struct Ciphertext(pub BigInt);

impl From<BigInt> for Plaintext
{
    fn from(x: BigInt) -> Plaintext {
        Plaintext(x)
    }
}

impl fmt::Display for Plaintext
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// Encryption key that may be shared publicly.
#[derive(Debug,Clone)]
pub struct EncryptionKey {
    pub n: BigInt,  // the modulus
    nn: BigInt, // the modulus squared
}

impl<'kp> From<&'kp Keypair> for EncryptionKey
{
    fn from(keypair: &'kp Keypair) -> EncryptionKey {
        let ref modulus = &keypair.p * &keypair.q;
        EncryptionKey {
            n: modulus.clone(),
            nn: modulus * modulus,
        }
    }
}

/// Decryption key that should be kept private.
#[derive(Debug,Clone)]
pub struct DecryptionKey {
    p: BigInt,  // first prime
    q: BigInt,  // second prime
    n: BigInt,  // the modulus (also in public key)
    pp: BigInt,
    pminusone: BigInt,
    qq: BigInt,
    qminusone: BigInt,
    pinvq: BigInt,
    hp: BigInt,
    hq: BigInt,
}

impl<'kp> From<&'kp Keypair> for DecryptionKey 
{
    fn from(keypair: &'kp Keypair) -> DecryptionKey {
        let ref p = keypair.p;
        let ref q = keypair.q;
        let ref pp = p * p;
        let ref qq = q * q;
        let ref n = p * q;
        DecryptionKey {
            p: p.clone(), // TODO store ref to keypair instead
            q: q.clone(),

            pp: pp.clone(),
            pminusone: p - 1,

            qq: qq.clone(),
            qminusone: q - 1,

            pinvq: BigInt::modinv(p, q),
            hp: h(p, pp, n),
            hq: h(q, qq, n),

            n: n.clone()
        }
    }
}

fn h(p: &BigInt, pp: &BigInt, n: &BigInt) -> BigInt
{
    // here we assume:
    //  - p \in {P, Q}
    //  - n = P * Q
    //  - g = 1 + n

    // compute g^{p-1} mod p^2
    let gp = (1 - n) % pp;
    // compute L_p(.)
    let lp = l(&gp, p);
    // compute L_p(.)^{-1}
    let hp = BigInt::modinv(&lp, p);
    hp
}

fn l(u: &BigInt, n: &BigInt) -> BigInt {
    (u - 1) / n
}

impl<S> Decryption<DecryptionKey, Ciphertext, Plaintext> for S
where S: AbstractScheme<BigInteger=BigInt>
{
    fn decrypt(dk: &DecryptionKey, c: &Ciphertext) -> Plaintext {
        // process using p
        let cp = BigInt::modpow(&c.0, &dk.pminusone, &dk.pp);
        let lp = l(&cp, &dk.p);
        let mp = (&lp * &dk.hp) % &dk.p;
        // process using q
        let cq = BigInt::modpow(&c.0, &dk.qminusone, &dk.qq);
        let lq = l(&cq, &dk.q);
        let mq = (&lq * &dk.hq) % &dk.q;
        // perform CRT
        let m = crt(&mp, &mq, &dk);
        Plaintext(m)
    }
}

fn crt(mp: &BigInt, mq: &BigInt, dk: &DecryptionKey) -> BigInt
{
    let mut mq_minus_mp = (mq-mp) % &dk.q;
    if NumberTests::is_negative(&mq_minus_mp) {
        mq_minus_mp = mq_minus_mp + &dk.q;
    }
    let u = (mq_minus_mp * &dk.pinvq) % &dk.q;
    let m = mp + (&u * &dk.p);
    m % &dk.n
}

impl<S> Rerandomisation<EncryptionKey, Ciphertext> for S
where S: AbstractScheme<BigInteger=BigInt>
{
    fn rerandomise(ek: &EncryptionKey, c: &Ciphertext) -> Ciphertext {
        let r = BigInt::sample_below(&ek.n);
        let d = (&c.0 * BigInt::modpow(&r, &ek.n, &ek.nn)) % &ek.nn;
        Ciphertext(d)
    }
}

impl<S> Encryption<EncryptionKey, Plaintext, Ciphertext> for S
where S: AbstractScheme<BigInteger=BigInt> + Rerandomisation<EncryptionKey, Ciphertext>
{
    fn encrypt(ek: &EncryptionKey, m: &Plaintext) -> Ciphertext {
        // here we assume that g = n+1
        let nm = &m.0 * &ek.n;
        let gx = (&nm + 1) % &ek.nn;
        Self::rerandomise(ek, &Ciphertext(gx))
    }
}

impl<S> Addition<EncryptionKey, Ciphertext, Ciphertext, Ciphertext> for S
where S: AbstractScheme<BigInteger=BigInt>
{
    fn add(ek: &EncryptionKey, c1: &Ciphertext, c2: &Ciphertext) -> Ciphertext {
        let c = (&c1.0 * &c2.0) % &ek.nn;
        Ciphertext(c)
    }
}

impl<S> Multiplication<EncryptionKey, Ciphertext, Plaintext, Ciphertext> for S
where S: AbstractScheme<BigInteger=BigInt>
{
    fn mul(ek: &EncryptionKey, c1: &Ciphertext, m2: &Plaintext) -> Ciphertext {
        let c = BigInt::modpow(&c1.0, &m2.0, &ek.nn);
        Ciphertext(c)
    }
}




#[cfg(test)]
mod tests {

    use ::AbstractPaillier;
    use super::*;

    fn test_keypair() -> Keypair {
        let p = str::parse("148677972634832330983979593310074301486537017973460461278300587514468301043894574906886127642530475786889672304776052879927627556769456140664043088700743909632312483413393134504352834240399191134336344285483935856491230340093391784574980688823380828143810804684752914935441384845195613674104960646037368551517").unwrap();
        let q = str::parse("158741574437007245654463598139927898730476924736461654463975966787719309357536545869203069369466212089132653564188443272208127277664424448947476335413293018778018615899291704693105620242763173357203898195318179150836424196645745308205164116144020613415407736216097185962171301808761138424668335445923774195463").unwrap();
        Keypair {
            p: p,
            q: q,
        }
    }

    #[test]
    fn test_correct_encryption_decryption() {
        let (ek, dk) = test_keypair().keys();

        let m = Plaintext::from(BigInt::from(10));
        let c = AbstractPaillier::encrypt(&ek, &m);

        let recovered_m = AbstractPaillier::decrypt(&dk, &c);
        assert_eq!(recovered_m, m);
    }

    #[test]
    fn test_correct_addition() {
        let (ek, dk) = test_keypair().keys();

        let m1 = Plaintext::from(BigInt::from(10));
        let c1 = AbstractPaillier::encrypt(&ek, &m1);
        let m2 = Plaintext::from(BigInt::from(20));
        let c2 = AbstractPaillier::encrypt(&ek, &m2);

        let c = AbstractPaillier::add(&ek, &c1, &c2);
        let m = AbstractPaillier::decrypt(&dk, &c);
        assert_eq!(m, Plaintext::from(BigInt::from(30)));
    }

    #[test]
    fn correct_multiplication() {
        let (ek, dk) = test_keypair().keys();

        let m1 = Plaintext::from(BigInt::from(10));
        let c1 = AbstractPaillier::encrypt(&ek, &m1);
        let m2 = Plaintext::from(BigInt::from(20));

        let c = AbstractPaillier::mul(&ek, &c1, &m2);
        let m = AbstractPaillier::decrypt(&dk, &c);
        assert_eq!(m, Plaintext::from(BigInt::from(200)));
    }

    #[cfg(feature="keygen")]
    #[test]
    fn test_correct_keygen() {
        let (ek, dk): (EncryptionKey, _) = AbstractPaillier::keypair_with_modulus_size(2048).keys();

        let m = Plaintext::from(BigInt::from(10));
        let c = AbstractPaillier::encrypt(&ek, &m);

        let recovered_m = AbstractPaillier::decrypt(&dk, &c);
        assert_eq!(recovered_m, m);
    }

}
