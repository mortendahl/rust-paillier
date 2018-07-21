//! Core Paillier encryption scheme supporting ciphertext addition and plaintext multiplication.

use std::borrow::{Borrow, Cow};
use std::fmt;

use rayon::join;

use ::traits::*;
use ::arithimpl::traits::*;
use ::BigInteger as BigInt;
use ::Paillier as Paillier;
use ::{Keypair, EncryptionKey, DecryptionKey, RawPlaintext, RawCiphertext};

impl DefaultKeys for Keypair {
    type EK = EncryptionKey;
    type DK = DecryptionKey;

    fn encryption_key(&self) -> Self::EK {
        EncryptionKey::from(self)
    }

    fn decryption_key(&self) -> Self::DK {
        DecryptionKey::from(self)
    }
}

impl<'p, 'q> From<(&'p BigInt, &'q BigInt)> for Keypair {
    fn from((p, q) : (&'p BigInt, &'q BigInt)) -> Keypair {
        Keypair {
            p: p.clone(),
            q: q.clone(),
        }
    }
}

impl<'kp> From<&'kp Keypair> for DecryptionKey {
    fn from(keypair: &'kp Keypair) -> DecryptionKey {
        let p = keypair.p.clone();
        let q = keypair.q.clone();
        let pp = &p * &p;
        let qq = &q * &q;
        let n = &p * &q;
        let nn = &n * &n;

        let pminusone = &p - 1;
        let qminusone = &q - 1;
        let phi = &pminusone * &qminusone;

        let dn = BigInt::modinv(&n, &phi);
        let (dp, dq) = crt_decompose(dn, &pminusone, &qminusone);

        let pinv = BigInt::modinv(&p, &q);
        let ppinv = BigInt::modinv(&pp, &qq);

        let hp = h(&p, &pp, &n);
        let hq = h(&q, &qq, &n);

        DecryptionKey {
            p, pp, pminusone, pinv, ppinv,
            q, qq, qminusone,
            n, nn,
            phi,
            dp, dq,
            hp, hq,
        }
    }
}

impl<'kp> From<&'kp Keypair> for EncryptionKey {
    fn from(keypair: &'kp Keypair) -> EncryptionKey {
        let ref modulus = &keypair.p * &keypair.q;
        EncryptionKey {
            n: modulus.clone(),
            nn: modulus * modulus,
        }
    }
}

#[derive(Debug,PartialEq)]
pub struct Randomness(pub BigInt);

#[derive(Debug,PartialEq)]
pub struct PrecomputedRandomness(BigInt);

impl Randomness {
    pub fn sample(ek: &EncryptionKey) -> Randomness {
        Randomness(BigInt::sample_below(&ek.n))
    }
}

impl From<BigInt> for Randomness {
    fn from(x: BigInt) -> Randomness {
        Randomness(x)
    }
}

impl<'b> From<&'b BigInt> for Randomness {
    fn from(x: &'b BigInt) -> Randomness {
        Randomness(x.clone())
    }
}

impl<'b> From<BigInt> for RawPlaintext<'b> {
    fn from(x: BigInt) -> Self {
        RawPlaintext(Cow::Owned(x))
    }
}

impl<'b> From<&'b BigInt> for RawPlaintext<'b> {
    fn from(x: &'b BigInt) -> Self {
        RawPlaintext(Cow::Borrowed(x))
    }
}

impl<'b> From<RawPlaintext<'b>> for BigInt {
    fn from(x: RawPlaintext<'b>) -> Self {
        x.0.into_owned()
    }
}

impl<'b> From<BigInt> for RawCiphertext<'b> {
    fn from(x: BigInt) -> Self {
        RawCiphertext(Cow::Owned(x))
    }
}

impl<'b> From<&'b BigInt> for RawCiphertext<'b> {
    fn from(x: &'b BigInt) -> Self {
        RawCiphertext(Cow::Borrowed(x))
    }
}

impl<'b> From<RawCiphertext<'b>> for BigInt {
    fn from(x: RawCiphertext<'b>) -> Self {
        x.0.into_owned()
    }
}

impl<'m, 'd> Encrypt<EncryptionKey, RawPlaintext<'m>, RawCiphertext<'d>> for Paillier {
    fn encrypt(ek: &EncryptionKey, m: RawPlaintext<'m>) -> RawCiphertext<'d> {
        let r = Randomness::sample(&ek);
        let rn = BigInt::modpow(&r.0, &ek.n, &ek.nn);
        let gm = (1 + m.0.borrow() * &ek.n) % &ek.nn;
        let c = (gm * rn) % &ek.nn;
        RawCiphertext(Cow::Owned(c))
    }
}

impl<'m, 'r, 'd> EncryptWithChosenRandomness<EncryptionKey, RawPlaintext<'m>, &'r Randomness, RawCiphertext<'d>> for Paillier {
    fn encrypt_with_chosen_randomness(ek: &EncryptionKey, m: RawPlaintext<'m>, r: &'r Randomness) -> RawCiphertext<'d> {
        let rn = BigInt::modpow(&r.0, &ek.n, &ek.nn);
        let gm = (1 + m.0.borrow() * &ek.n) % &ek.nn;
        let c = (gm * rn) % &ek.nn;
        RawCiphertext(Cow::Owned(c))
    }
}

impl<'m, 'r, 'd> EncryptWithChosenRandomness<EncryptionKey, RawPlaintext<'m>, &'r PrecomputedRandomness, RawCiphertext<'d>> for Paillier {
    fn encrypt_with_chosen_randomness(ek: &EncryptionKey, m: RawPlaintext<'m>, rn: &'r PrecomputedRandomness) -> RawCiphertext<'d> {
        let gm = (1 + m.0.borrow() * &ek.n) % &ek.nn;
        let c = (gm * &rn.0) % &ek.nn;
        RawCiphertext(Cow::Owned(c))
    }
}

impl<'m, 'd> Encrypt<DecryptionKey, RawPlaintext<'m>, RawCiphertext<'d>> for Paillier {
    fn encrypt(dk: &DecryptionKey, m: RawPlaintext<'m>) -> RawCiphertext<'d> {
        let (mp, mq) = crt_decompose(m.0.borrow(), &dk.pp, &dk.qq);
        
        let (cp, cq) = join(
            || {
                let rp = BigInt::sample_below(&dk.p);
                let rnp = BigInt::modpow(&rp, &dk.n, &dk.pp);
                let gmp = (1 + mp * &dk.n) % &dk.pp; // TODO[Morten] maybe there's more to get here
                let cp = (gmp * rnp) % &dk.pp;
                cp
            },
            || {
                let rq = BigInt::sample_below(&dk.q);
                let rnq = BigInt::modpow(&rq, &dk.n, &dk.qq);
                let gmq = (1 + mq * &dk.n) % &dk.qq; // TODO[Morten] maybe there's more to get here
                let cq = (gmq * rnq) % &dk.qq;
                cq
            }
        );

        // let rp = BigInt::sample_below(&dk.p);
        // let rnp = BigInt::modpow(&rp, &dk.n, &dk.pp);
        // let gmp = (1 + mp * &dk.n) % &dk.pp; // TODO[Morten] maybe there's more to get here
        // let cp = (gmp * rnp) % &dk.pp;
        
        // let rq = BigInt::sample_below(&dk.q);
        // let rnq = BigInt::modpow(&rq, &dk.n, &dk.qq);
        // let gmq = (1 + mq * &dk.n) % &dk.qq; // TODO[Morten] maybe there's more to get here
        // let cq = (gmq * rnq) % &dk.qq;

        let c = crt_recombine(cp, cq, &dk.pp, &dk.qq, &dk.ppinv);
        RawCiphertext(Cow::Owned(c))
    }
}

impl<'m, 'r, 'd> EncryptWithChosenRandomness<DecryptionKey, RawPlaintext<'m>, &'r Randomness, RawCiphertext<'d>> for Paillier {
    fn encrypt_with_chosen_randomness(dk: &DecryptionKey, m: RawPlaintext<'m>, r: &'r Randomness) -> RawCiphertext<'d> {
        let (mp, mq) = crt_decompose(m.0.borrow(), &dk.pp, &dk.qq);
        let (rp, rq) = crt_decompose(&r.0, &dk.pp, &dk.qq);
        let (cp, cq) = join(
            || {
                let rnp = BigInt::modpow(&rp, &dk.n, &dk.pp);
                let gmp = (1 + mp * &dk.n) % &dk.pp; // TODO[Morten] maybe there's more to get here
                let cp = (gmp * rnp) % &dk.pp;
                cp
            },
            || {
                let rnq = BigInt::modpow(&rq, &dk.n, &dk.qq);
                let gmq = (1 + mq * &dk.n) % &dk.qq; // TODO[Morten] maybe there's more to get here
                let cq = (gmq * rnq) % &dk.qq;
                cq
            }
        );
        let c = crt_recombine(cp, cq, &dk.pp, &dk.qq, &dk.ppinv);
        RawCiphertext(Cow::Owned(c))
    }
}

impl<'m, 'r, 'd> EncryptWithChosenRandomness<DecryptionKey, RawPlaintext<'m>, &'r PrecomputedRandomness, RawCiphertext<'d>> for Paillier {
    fn encrypt_with_chosen_randomness(dk: &DecryptionKey, m: RawPlaintext<'m>, rn: &'r PrecomputedRandomness) -> RawCiphertext<'d> {
        let gm = (1 + m.0.borrow() * &dk.n) % &dk.nn;
        let c = (gm * &rn.0) % &dk.nn;
        RawCiphertext(Cow::Owned(c))
    }
}

impl<'ek, 'r> PrecomputeRandomness<&'ek EncryptionKey, &'r BigInt, PrecomputedRandomness> for Paillier {
    fn precompute(ek: &'ek EncryptionKey, r: &'r BigInt) -> PrecomputedRandomness {
        let rn = BigInt::modpow(r, &ek.n, &ek.nn);
        PrecomputedRandomness(rn)
    }
}

impl<'c, 'd> Rerandomize<EncryptionKey, RawCiphertext<'c>, RawCiphertext<'d>> for Paillier {
    fn rerandomize(ek: &EncryptionKey, c: RawCiphertext<'c>) -> RawCiphertext<'d> {
        let r = BigInt::sample_below(&ek.n);
        let rn = BigInt::modpow(&r, &ek.n, &ek.nn);
        let d = (c.0.borrow() * rn) % &ek.nn;
        RawCiphertext(Cow::Owned(d))
    }
}

/// TODO
///
/// Efficient decryption using CRT based on [Paillier99, section 7](http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.112.4035&rep=rep1&type=pdf)
impl<'c, 'm> Decrypt<DecryptionKey, RawCiphertext<'c>, RawPlaintext<'m>> for Paillier {
    fn decrypt(dk: &DecryptionKey, c: RawCiphertext<'c>) -> RawPlaintext<'m> {
        Self::decrypt(dk, &c)
    }
}

/// TODO
///
/// Efficient decryption using CRT based on [Paillier99, section 7](http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.112.4035&rep=rep1&type=pdf)
impl<'c, 'm> Decrypt<DecryptionKey, &'c RawCiphertext<'c>, RawPlaintext<'m>> for Paillier {
    fn decrypt(dk: &DecryptionKey, c: &'c RawCiphertext<'c>) -> RawPlaintext<'m> {
        let (cp, cq) = crt_decompose(c.0.borrow(), &dk.pp, &dk.qq);
        // decrypt in parallel with respectively p and q
        let (mp, mq) = join(
            || {
                // process using p
                let dp = BigInt::modpow(&cp, &dk.pminusone, &dk.pp);
                let lp = l(&dp, &dk.p);
                let mp = (&lp * &dk.hp) % &dk.p;
                mp
            },
            || {
                // process using q
                let dq = BigInt::modpow(&cq, &dk.qminusone, &dk.qq);
                let lq = l(&dq, &dk.q);
                let mq = (&lq * &dk.hq) % &dk.q;
                mq
            }
        );
        // perform CRT
        let m = crt_recombine(mp, mq, &dk.p, &dk.q, &dk.pinv);
        RawPlaintext(Cow::Owned(m))
    }
}

// impl<'c, 'r, 'm> Open<DecryptionKey, &'c RawCiphertext<'r>, RawPlaintext<'m>, Randomness> for Paillier {
//     fn open(dk: &DecryptionKey, c: &'c RawCiphertext<'r>) -> (RawPlaintext<'m>, Randomness) {
//         let m = Self::decrypt(dk, c.clone()); // TODO[Morten] avoid clone
//         let gminv = (1 - m.0.borrow() * &dk.n) % &dk.nn;
//         let rn = (c.0.borrow() * gminv) % &dk.nn;
//         let r = extract_nroot(dk, &rn);
//         (m, Randomness(r))
//     }
// }

impl<'c, 'm> Open<DecryptionKey, RawCiphertext<'c>, RawPlaintext<'m>, Randomness> for Paillier {
    fn open(dk: &DecryptionKey, c: RawCiphertext<'c>) -> (RawPlaintext<'m>, Randomness) {
        Self::open(dk, &c)
    }
}

impl<'c, 'm> Open<DecryptionKey, &'c RawCiphertext<'c>, RawPlaintext<'m>, Randomness> for Paillier {
    fn open(dk: &DecryptionKey, c: &'c RawCiphertext<'c>) -> (RawPlaintext<'m>, Randomness) {
        let m = Self::decrypt(dk, c);
        let gminv = (1 - m.0.borrow() * &dk.n) % &dk.nn;
        let rn = (c.0.borrow() * gminv) % &dk.nn;
        let r = extract_nroot(dk, &rn);
        (m, Randomness(r))
    }
}

impl<'c1, 'c2, 'd> Add<EncryptionKey, RawCiphertext<'c1>, RawCiphertext<'c2>, RawCiphertext<'d>> for Paillier {
    fn add(ek: &EncryptionKey, c1: RawCiphertext<'c1>, c2: RawCiphertext<'c2>) -> RawCiphertext<'d> {
        let c1: &BigInt = c1.0.borrow();
        let d: BigInt = c1 * c2.0.borrow() % &ek.nn;
        RawCiphertext(Cow::Owned(d))
    }
}

impl<'c, 'm, 'd> Add<EncryptionKey, RawCiphertext<'c>, RawPlaintext<'m>, RawCiphertext<'d>> for Paillier {
    fn add(ek: &EncryptionKey, c: RawCiphertext<'c>, m: RawPlaintext<'m>) -> RawCiphertext<'d> {
        let c1 = c.0.borrow();
        let c2 = (m.0.borrow() * &ek.n + 1) % &ek.nn;
        let d: BigInt = (c1 * c2) % &ek.nn;
        RawCiphertext(Cow::Owned(d))
    }
}

impl<'c, 'm, 'd> Add<EncryptionKey, RawPlaintext<'m>, RawCiphertext<'c>, RawCiphertext<'d>> for Paillier {
    fn add(ek: &EncryptionKey, m: RawPlaintext<'m>, c: RawCiphertext<'c>) -> RawCiphertext<'d> {
        let c1 = (m.0.borrow() * &ek.n + 1) % &ek.nn;
        let c2 = c.0.borrow();
        let d: BigInt = (c1 * c2) % &ek.nn;
        RawCiphertext(Cow::Owned(d))
    }
}

impl<'c, 'm, 'd> Mul<EncryptionKey, RawCiphertext<'c>, RawPlaintext<'m>, RawCiphertext<'d>> for Paillier {
    fn mul(ek: &EncryptionKey, c: RawCiphertext<'c>, m: RawPlaintext<'m>) -> RawCiphertext<'d> {
        RawCiphertext(Cow::Owned(BigInt::modpow(c.0.borrow(), m.0.borrow(), &ek.nn)))
    }
}

impl<'c, 'm, 'd> Mul<EncryptionKey, RawPlaintext<'m>, RawCiphertext<'c>, RawCiphertext<'d>> for Paillier {
    fn mul(ek: &EncryptionKey, m: RawPlaintext<'m>, c: RawCiphertext<'c>) -> RawCiphertext<'d> {
        RawCiphertext(Cow::Owned(BigInt::modpow(c.0.borrow(), m.0.borrow(), &ek.nn)))
    }
}

fn h(p: &BigInt, pp: &BigInt, n: &BigInt) -> BigInt {
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

fn crt_decompose<X, M1, M2>(x: X, m1: M1, m2: M2) -> (BigInt, BigInt)
where X: Borrow<BigInt>, M1: Borrow<BigInt>, M2: Borrow<BigInt>
{
    (x.borrow() % m1.borrow(), x.borrow() % m2.borrow())
}

fn crt_recombine<X1, X2, M1, M2, I>(x1: X1, x2: X2, m1: M1, m2: M2, m1inv: I) -> BigInt 
where X1: Borrow<BigInt>, X2: Borrow<BigInt>, M1: Borrow<BigInt>, M2: Borrow<BigInt>, I: Borrow<BigInt>
{
    let mut diff = (x2.borrow() - x1.borrow()) % m2.borrow();
    if NumberTests::is_negative(&diff) {
        diff += m2.borrow();
    }
    let u = (diff * m1inv.borrow()) % m2.borrow();
    let x = x1.borrow() + (u * m1.borrow());
    x
}

/// Extract randomness component of a zero ciphertext.
pub fn extract_nroot(dk: &DecryptionKey, z: &BigInt) -> BigInt {
    let (zp, zq) = crt_decompose(z, &dk.p, &dk.q);

    let rp = BigInt::modpow(&zp, &dk.dp, &dk.p);
    let rq = BigInt::modpow(&zq, &dk.dq, &dk.q);

    let r = crt_recombine(rp, rq, &dk.p, &dk.q, &dk.pinv);
    r
}

#[cfg(test)]
mod tests {

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

        let p = RawPlaintext::from(BigInt::from(10));
        let c = Paillier::encrypt(&ek, p.clone());

        let recovered_p = Paillier::decrypt(&dk, c);
        assert_eq!(recovered_p, p);
    }

    #[test]
    fn test_correct_opening() {
        let (ek, dk) = test_keypair().keys();

        let c = Paillier::encrypt(&ek, RawPlaintext::from(BigInt::from(10)));
        let (m, r) = Paillier::open(&dk, &c);
        let d = Paillier::encrypt_with_chosen_randomness(&ek, m, &r);
        assert_eq!(c, d);
    }

    #[test]
    fn test_correct_addition() {
        let (ek, dk) = test_keypair().keys();

        let m1 = RawPlaintext::from(BigInt::from(10));
        let c1 = Paillier::encrypt(&ek, m1);
        let m2 = RawPlaintext::from(BigInt::from(20));
        let c2 = Paillier::encrypt(&ek, m2);

        let c = Paillier::add(&ek, c1, c2);
        let m = Paillier::decrypt(&dk, c);
        assert_eq!(m, BigInt::from(30).into());
    }

    #[test]
    fn correct_multiplication() {
        let (ek, dk) = test_keypair().keys();

        let m1 = RawPlaintext::from(BigInt::from(10));
        let c1 = Paillier::encrypt(&ek, m1);
        let m2 = RawPlaintext::from(BigInt::from(20));

        let c = Paillier::mul(&ek, c1, m2);
        let m = Paillier::decrypt(&dk, c);
        assert_eq!(m, BigInt::from(200).into());
    }

    #[cfg(feature="keygen")]
    #[test]
    fn test_correct_keygen() {
        let (ek, dk): (EncryptionKey, _) = Paillier::keypair_with_modulus_size(2048).keys();

        let m = RawPlaintext::from(BigInt::from(10));
        let c = Paillier::encrypt(&ek, m.clone()); // TODO avoid

        let recovered_m = Paillier::decrypt(&dk, c);
        assert_eq!(recovered_m, m);
    }

}
