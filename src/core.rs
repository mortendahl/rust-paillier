//! Core Paillier encryption scheme supporting ciphertext addition and plaintext multiplication.

use std::borrow::{Borrow, Cow};

use rayon::join;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::traits::*;
use crate::{
    BigInt, DecryptionKey, EncryptionKey, Keypair, MinimalDecryptionKey, MinimalEncryptionKey,
    Paillier, RawCiphertext, RawPlaintext,
};
use curv::arithmetic::traits::*;

impl Keypair {
    /// Generate default encryption and decryption keys.
    pub fn keys(&self) -> (EncryptionKey, DecryptionKey) {
        (EncryptionKey::from(self), DecryptionKey::from(self))
    }
}

impl<'p, 'q> From<(&'p BigInt, &'q BigInt)> for Keypair {
    fn from((p, q): (&'p BigInt, &'q BigInt)) -> Keypair {
        Keypair {
            p: p.clone(),
            q: q.clone(),
        }
    }
}

impl<'kp> From<&'kp Keypair> for MinimalEncryptionKey {
    fn from(keypair: &'kp Keypair) -> Self {
        MinimalEncryptionKey {
            n: &keypair.p * &keypair.q,
        }
    }
}

impl<'e> From<&'e EncryptionKey> for MinimalEncryptionKey {
    fn from(ek: &'e EncryptionKey) -> Self {
        MinimalEncryptionKey { n: ek.n.clone() }
    }
}

impl<'e> From<MinimalEncryptionKey> for EncryptionKey {
    fn from(ek: MinimalEncryptionKey) -> Self {
        let nn = &ek.n * &ek.n;
        let n = ek.n;
        EncryptionKey { n, nn }
    }
}

impl<'kp> From<&'kp Keypair> for EncryptionKey {
    fn from(keypair: &'kp Keypair) -> Self {
        let minimal = MinimalEncryptionKey::from(keypair);
        EncryptionKey::from(minimal)
    }
}

// TODO[Morten] where is this needed?
impl<'n> From<&'n BigInt> for EncryptionKey {
    fn from(n: &'n BigInt) -> Self {
        let minimal = MinimalEncryptionKey { n: n.clone() };
        EncryptionKey::from(minimal)
    }
}

impl Serialize for EncryptionKey {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let minimal = MinimalEncryptionKey::from(self);
        minimal.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for EncryptionKey {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let minimal = MinimalEncryptionKey::deserialize(deserializer)?;
        Ok(EncryptionKey::from(minimal))
    }
}

impl<'kp> From<&'kp Keypair> for MinimalDecryptionKey {
    fn from(keypair: &'kp Keypair) -> Self {
        MinimalDecryptionKey {
            p: keypair.p.clone(),
            q: keypair.q.clone(),
        }
    }
}

impl<'e> From<&'e DecryptionKey> for MinimalDecryptionKey {
    fn from(dk: &'e DecryptionKey) -> Self {
        MinimalDecryptionKey {
            p: dk.p.clone(),
            q: dk.q.clone(),
        }
    }
}

impl<'e> From<MinimalDecryptionKey> for DecryptionKey {
    fn from(dk: MinimalDecryptionKey) -> Self {
        let p = dk.p;
        let q = dk.q;

        DecryptionKey { p, q }
    }
}

impl<'kp> From<&'kp Keypair> for DecryptionKey {
    fn from(keypair: &'kp Keypair) -> DecryptionKey {
        let minimal = MinimalDecryptionKey::from(keypair);
        DecryptionKey::from(minimal)
    }
}

impl Serialize for DecryptionKey {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let minimal = MinimalDecryptionKey::from(self);
        minimal.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for DecryptionKey {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let minimal = MinimalDecryptionKey::deserialize(deserializer)?;
        Ok(DecryptionKey::from(minimal))
    }
}

#[derive(Debug, PartialEq)]
pub struct Randomness(pub BigInt);

#[derive(Debug, PartialEq)]
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
        let rn = BigInt::mod_pow(&r.0, &ek.n, &ek.nn);
        let gm: BigInt = (m.0.borrow() as &BigInt * &ek.n + 1) % &ek.nn;
        let c = (gm * rn) % &ek.nn;
        RawCiphertext(Cow::Owned(c))
    }
}

impl<'m, 'r, 'd>
    EncryptWithChosenRandomness<EncryptionKey, RawPlaintext<'m>, &'r Randomness, RawCiphertext<'d>>
    for Paillier
{
    fn encrypt_with_chosen_randomness(
        ek: &EncryptionKey,
        m: RawPlaintext<'m>,
        r: &'r Randomness,
    ) -> RawCiphertext<'d> {
        let rn = BigInt::mod_pow(&r.0, &ek.n, &ek.nn);
        let gm: BigInt = (m.0.borrow() as &BigInt * &ek.n + 1) % &ek.nn;
        let c = (gm * rn) % &ek.nn;
        RawCiphertext(Cow::Owned(c))
    }
}

impl<'m, 'r, 'd>
    EncryptWithChosenRandomness<
        EncryptionKey,
        RawPlaintext<'m>,
        &'r PrecomputedRandomness,
        RawCiphertext<'d>,
    > for Paillier
{
    fn encrypt_with_chosen_randomness(
        ek: &EncryptionKey,
        m: RawPlaintext<'m>,
        rn: &'r PrecomputedRandomness,
    ) -> RawCiphertext<'d> {
        let gm: BigInt = (m.0.borrow() as &BigInt * &ek.n + 1) % &ek.nn;
        let c = (gm * &rn.0) % &ek.nn;
        RawCiphertext(Cow::Owned(c))
    }
}

impl<'m, 'd> Encrypt<DecryptionKey, RawPlaintext<'m>, RawCiphertext<'d>> for Paillier {
    fn encrypt(dk: &DecryptionKey, m: RawPlaintext<'m>) -> RawCiphertext<'d> {
        let dk_pp = &dk.p * &dk.p;
        let dk_qq = &dk.q * &dk.q;
        let dk_n = &dk.q * &dk.p;
        let dk_ppinv = BigInt::mod_inv(&dk_pp, &dk_qq);
        let (mp, mq) = crt_decompose(m.0.borrow(), &dk_pp, &dk_qq);
        let (cp, cq) = join(
            || {
                let rp = BigInt::sample_below(&dk.p);
                let rnp = BigInt::mod_pow(&rp, &dk_n, &dk_pp);
                let gmp = (1 + mp * &dk_n) % &dk_pp; // TODO[Morten] maybe there's more to get here
                (gmp * rnp) % &dk_pp
            },
            || {
                let rq = BigInt::sample_below(&dk.q);
                let rnq = BigInt::mod_pow(&rq, &dk_n, &dk_qq);
                let gmq = (1 + mq * &dk_n) % &dk_qq; // TODO[Morten] maybe there's more to get here
                (gmq * rnq) % &dk_qq
            },
        );
        let c = crt_recombine(cp, cq, &dk_pp, &dk_qq, &dk_ppinv);
        RawCiphertext(Cow::Owned(c))
    }
}

impl<'m, 'r, 'd>
    EncryptWithChosenRandomness<DecryptionKey, RawPlaintext<'m>, &'r Randomness, RawCiphertext<'d>>
    for Paillier
{
    fn encrypt_with_chosen_randomness(
        dk: &DecryptionKey,
        m: RawPlaintext<'m>,
        r: &'r Randomness,
    ) -> RawCiphertext<'d> {
        let dk_pp = &dk.p * &dk.p;
        let dk_qq = &dk.q * &dk.q;
        let dk_n = &dk.q * &dk.p;
        let dk_ppinv = BigInt::mod_inv(&dk_pp, &dk_qq);
        let (mp, mq) = crt_decompose(m.0.borrow(), &dk_pp, &dk_qq);
        let (rp, rq) = crt_decompose(&r.0, &dk_pp, &dk_qq);
        let (cp, cq) = join(
            || {
                let rnp = BigInt::mod_pow(&rp, &dk_n, &dk_pp);
                let gmp = (1 + mp * &dk_n) % &dk_pp; // TODO[Morten] maybe there's more to get here
                (gmp * rnp) % &dk_pp
            },
            || {
                let rnq = BigInt::mod_pow(&rq, &dk_n, &dk_qq);
                let gmq = (1 + mq * &dk_n) % &dk_qq; // TODO[Morten] maybe there's more to get here
                (gmq * rnq) % &dk_qq
            },
        );
        let c = crt_recombine(cp, cq, &dk_pp, &dk_qq, &dk_ppinv);
        RawCiphertext(Cow::Owned(c))
    }
}

impl<'m, 'r, 'd>
    EncryptWithChosenRandomness<
        DecryptionKey,
        RawPlaintext<'m>,
        &'r PrecomputedRandomness,
        RawCiphertext<'d>,
    > for Paillier
{
    fn encrypt_with_chosen_randomness(
        dk: &DecryptionKey,
        m: RawPlaintext<'m>,
        rn: &'r PrecomputedRandomness,
    ) -> RawCiphertext<'d> {
        let dk_n = &dk.q * &dk.p;
        let dk_nn = &dk_n * &dk_n;
        let gm = (1 + m.0.borrow() as &BigInt * &dk_n) % &dk_nn;
        let c = (gm * &rn.0) % &dk_nn;
        RawCiphertext(Cow::Owned(c))
    }
}

impl<'ek, 'r> PrecomputeRandomness<&'ek EncryptionKey, &'r BigInt, PrecomputedRandomness>
    for Paillier
{
    fn precompute(ek: &'ek EncryptionKey, r: &'r BigInt) -> PrecomputedRandomness {
        let rn = BigInt::mod_pow(r, &ek.n, &ek.nn);
        PrecomputedRandomness(rn)
    }
}

impl<'c, 'd> Rerandomize<EncryptionKey, RawCiphertext<'c>, RawCiphertext<'d>> for Paillier {
    fn rerandomize(ek: &EncryptionKey, c: RawCiphertext<'c>) -> RawCiphertext<'d> {
        let r = BigInt::sample_below(&ek.n);
        let rn = BigInt::mod_pow(&r, &ek.n, &ek.nn);
        let d = (c.0.borrow() as &BigInt * rn) % &ek.nn;
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
        let dk_qq = &dk.q * &dk.q;
        let dk_pp = &dk.p * &dk.p;
        let dk_n = &dk.p * &dk.q;
        let dk_pinv = BigInt::mod_inv(&dk.p, &dk.q);
        let dk_qminusone = &dk.q - BigInt::one();
        let dk_pminusone = &dk.p - BigInt::one();
        let dk_hp = h(&dk.p, &dk_pp, &dk_n);
        let dk_hq = h(&dk.q, &dk_qq, &dk_n);
        let (cp, cq) = crt_decompose(c.0.borrow(), &dk_pp, &dk_qq);
        // decrypt in parallel with respectively p and q
        let (mp, mq) = join(
            || {
                // process using p
                let dp = BigInt::mod_pow(&cp, &dk_pminusone, &dk_pp);
                let lp = l(&dp, &dk.p);
                (&lp * &dk_hp) % &dk.p
            },
            || {
                // process using q
                let dq = BigInt::mod_pow(&cq, &dk_qminusone, &dk_qq);
                let lq = l(&dq, &dk.q);
                (&lq * &dk_hq) % &dk.q
            },
        );
        // perform CRT
        let m = crt_recombine(mp, mq, &dk.p, &dk.q, &dk_pinv);
        RawPlaintext(Cow::Owned(m))
    }
}

impl<'c, 'm> Open<DecryptionKey, RawCiphertext<'c>, RawPlaintext<'m>, Randomness> for Paillier {
    fn open(dk: &DecryptionKey, c: RawCiphertext<'c>) -> (RawPlaintext<'m>, Randomness) {
        Self::open(dk, &c)
    }
}

impl<'c, 'm> Open<DecryptionKey, &'c RawCiphertext<'c>, RawPlaintext<'m>, Randomness> for Paillier {
    fn open(dk: &DecryptionKey, c: &'c RawCiphertext<'c>) -> (RawPlaintext<'m>, Randomness) {
        let dk_n = &dk.p * &dk.q;
        let dk_nn = &dk_n * &dk_n;

        let m = Self::decrypt(dk, c);
        let gminv = (BigInt::one() - (m.0.borrow() as &BigInt) * &dk_n) % &dk_nn;
        let rn = (c.0.borrow() as &BigInt * gminv) % &dk_nn;
        let r = extract_nroot(dk, &rn);
        (m, Randomness(r))
    }
}

impl<'c1, 'c2, 'd> Add<EncryptionKey, RawCiphertext<'c1>, RawCiphertext<'c2>, RawCiphertext<'d>>
    for Paillier
{
    fn add(
        ek: &EncryptionKey,
        c1: RawCiphertext<'c1>,
        c2: RawCiphertext<'c2>,
    ) -> RawCiphertext<'d> {
        let d = (c1.0.borrow() as &BigInt * c2.0.borrow() as &BigInt) % &ek.nn;
        RawCiphertext(Cow::Owned(d))
    }
}

impl<'c, 'm, 'd> Add<EncryptionKey, RawCiphertext<'c>, RawPlaintext<'m>, RawCiphertext<'d>>
    for Paillier
{
    fn add(ek: &EncryptionKey, c: RawCiphertext<'c>, m: RawPlaintext<'m>) -> RawCiphertext<'d> {
        let c1 = c.0.borrow() as &BigInt;
        let c2 = (m.0.borrow() as &BigInt * &ek.n + 1) % &ek.nn;
        let d = (c1 * c2) % &ek.nn;
        RawCiphertext(Cow::Owned(d))
    }
}

impl<'c, 'm, 'd> Add<EncryptionKey, RawPlaintext<'m>, RawCiphertext<'c>, RawCiphertext<'d>>
    for Paillier
{
    fn add(ek: &EncryptionKey, m: RawPlaintext<'m>, c: RawCiphertext<'c>) -> RawCiphertext<'d> {
        let c1 = (m.0.borrow() as &BigInt * &ek.n + 1) % &ek.nn;
        let c2 = c.0.borrow() as &BigInt;
        let d = (c1 * c2) % &ek.nn;
        RawCiphertext(Cow::Owned(d))
    }
}

impl<'c, 'm, 'd> Mul<EncryptionKey, RawCiphertext<'c>, RawPlaintext<'m>, RawCiphertext<'d>>
    for Paillier
{
    fn mul(ek: &EncryptionKey, c: RawCiphertext<'c>, m: RawPlaintext<'m>) -> RawCiphertext<'d> {
        RawCiphertext(Cow::Owned(BigInt::mod_pow(
            c.0.borrow(),
            m.0.borrow(),
            &ek.nn,
        )))
    }
}

impl<'c, 'm, 'd> Mul<EncryptionKey, RawPlaintext<'m>, RawCiphertext<'c>, RawCiphertext<'d>>
    for Paillier
{
    fn mul(ek: &EncryptionKey, m: RawPlaintext<'m>, c: RawCiphertext<'c>) -> RawCiphertext<'d> {
        RawCiphertext(Cow::Owned(BigInt::mod_pow(
            c.0.borrow(),
            m.0.borrow(),
            &ek.nn,
        )))
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
    BigInt::mod_inv(&lp, p)
}

fn l(u: &BigInt, n: &BigInt) -> BigInt {
    (u - 1) / n
}

fn crt_decompose<X, M1, M2>(x: X, m1: M1, m2: M2) -> (BigInt, BigInt)
where
    X: Borrow<BigInt>,
    M1: Borrow<BigInt>,
    M2: Borrow<BigInt>,
{
    (x.borrow() % m1.borrow(), x.borrow() % m2.borrow())
}

fn crt_recombine<X1, X2, M1, M2, I>(x1: X1, x2: X2, m1: M1, m2: M2, m1inv: I) -> BigInt
where
    X1: Borrow<BigInt>,
    X2: Borrow<BigInt>,
    M1: Borrow<BigInt>,
    M2: Borrow<BigInt>,
    I: Borrow<BigInt>,
{
    let diff = BigInt::mod_sub(x2.borrow(), x1.borrow(), m2.borrow());
    //  let mut diff = (x2.borrow() - x1.borrow()) % m2.borrow();
    //  if NumberTests::is_negative(&diff) {
    //      diff += m2.borrow();
    //  }
    let u = (diff * m1inv.borrow()) % m2.borrow();
    x1.borrow() + (u * m1.borrow())
}

/// Extract randomness component of a zero ciphertext.
pub fn extract_nroot(dk: &DecryptionKey, z: &BigInt) -> BigInt {
    let dk_n = &dk.p * &dk.q;

    let dk_pinv = BigInt::mod_inv(&dk.p, &dk.q);
    let dk_qminusone = &dk.q - BigInt::one();
    let dk_pminusone = &dk.p - BigInt::one();

    let dk_phi = &dk_pminusone * &dk_qminusone;
    let dk_dn = BigInt::mod_inv(&dk_n, &dk_phi);
    let (dk_dp, dk_dq) = crt_decompose(dk_dn, &dk_pminusone, &dk_qminusone);
    let (zp, zq) = crt_decompose(z, &dk.p, &dk.q);

    let rp = BigInt::mod_pow(&zp, &dk_dp, &dk.p);
    let rq = BigInt::mod_pow(&zq, &dk_dq, &dk.q);

    crt_recombine(rp, rq, &dk.p, &dk.q, &dk_pinv)
}

#[cfg(test)]
mod tests {

    use super::*;

    extern crate serde_json;

    fn test_keypair() -> Keypair {
        let p = str::parse("148677972634832330983979593310074301486537017973460461278300587514468301043894574906886127642530475786889672304776052879927627556769456140664043088700743909632312483413393134504352834240399191134336344285483935856491230340093391784574980688823380828143810804684752914935441384845195613674104960646037368551517").unwrap();
        let q = str::parse("158741574437007245654463598139927898730476924736461654463975966787719309357536545869203069369466212089132653564188443272208127277664424448947476335413293018778018615899291704693105620242763173357203898195318179150836424196645745308205164116144020613415407736216097185962171301808761138424668335445923774195463").unwrap();
        Keypair { p, q }
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

    #[cfg(feature = "keygen")]
    #[test]
    fn test_correct_keygen() {
        let (ek, dk): (EncryptionKey, _) = Paillier::keypair_with_modulus_size(2048).keys();

        let m = RawPlaintext::from(BigInt::from(10));
        let c = Paillier::encrypt(&ek, m.clone()); // TODO avoid clone

        let recovered_m = Paillier::decrypt(&dk, c);
        assert_eq!(recovered_m, m);
    }

    #[test]
    fn test_key_serialization() {
        let (ek, dk) = test_keypair().keys();

        let ek_serialized = serde_json::to_string(&ek).unwrap();
        let ek_recovered: EncryptionKey = serde_json::from_str(&ek_serialized).unwrap();
        assert_eq!(ek, ek_recovered);

        let dk_serialized = serde_json::to_string(&dk).unwrap();
        let dk_recovered: DecryptionKey = serde_json::from_str(&dk_serialized).unwrap();
        assert_eq!(dk, dk_recovered);
    }

    #[test]
    fn test_failing_deserialize() {
        let illformatted = "{\"n\":\"12345abcdef\"}";

        let result: Result<EncryptionKey, _> = serde_json::from_str(&illformatted);
        assert!(result.is_err())
    }
}
