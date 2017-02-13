
//! Faster decryption using the Chinese Remainder Theorem.

use super::*;


/// Decryption key that should be kept private.
#[derive(Debug,Clone)]
pub struct DecryptionKey<I> {
    p: I,  // first prime
    q: I,  // second prime
    n: I,  // the modulus (also in public key)
    pp: I,
    pminusone: I,
    qq: I,
    qminusone: I,
    pinvq: I,
    hp: I,
    hq: I,
}


impl<I> ::traits::DecryptionKey for DecryptionKey<I> {}


impl<'kp, I> From<&'kp Keypair<I>> for DecryptionKey<I>
where
    I: Clone,
    I: One,
    I: ModInv,
    for<'a>     &'a I: Sub<I, Output=I>,
    for<'a,'b>  &'a I: Mul<&'b I, Output=I>,
    for<'b>         I: Sub<&'b I, Output=I>,
    for<'b>         I: Rem<&'b I, Output=I>,
    for<'b>         I: Div<&'b I, Output=I>,
{
    fn from(keypair: &'kp Keypair<I>) -> DecryptionKey<I> {
        let ref p = keypair.p;
        let ref q = keypair.q;
        let ref pp = p * p;
        let ref qq = q * q;
        let ref n = p * q;
        DecryptionKey {
            p: p.clone(), // TODO store ref to keypair instead
            q: q.clone(),

            pp: pp.clone(),
            pminusone: p - I::one(),

            qq: qq.clone(),
            qminusone: q - I::one(),

            pinvq: I::modinv(p, q),
            hp: h(p, pp, n),
            hq: h(q, qq, n),

            n: n.clone()
        }
    }
}


impl<I, S> Decryption<DecryptionKey<I>, Ciphertext<I>, Plaintext<I>> for S
where
    S: AbstractScheme<BigInteger=I>,
    I: One,
    I: ModPow,
    I: NumberTests,
    for<'a>    &'a I: Add<I, Output=I>,
    for<'b>        I: Add<&'b I, Output=I>,
    for<'a>    &'a I: Sub<I, Output=I>,
    for<'a,'b> &'a I: Sub<&'b I, Output=I>,
    for<'b>        I: Mul<&'b I, Output=I>,
    for<'a,'b> &'a I: Mul<&'b I, Output=I>,
    for<'b>        I: Div<&'b I, Output=I>,
    for<'a>        I: Rem<&'a I, Output=I>,
{
    fn decrypt(dk: &DecryptionKey<I>, c: &Ciphertext<I>) -> Plaintext<I> {
        // process using p
        let cp = I::modpow(&c.0, &dk.pminusone, &dk.pp);
        let lp = l(&cp, &dk.p);
        let mp = (&lp * &dk.hp) % &dk.p;
        // process using q
        let cq = I::modpow(&c.0, &dk.qminusone, &dk.qq);
        let lq = l(&cq, &dk.q);
        let mq = (&lq * &dk.hq) % &dk.q;
        // perform CRT
        Plaintext(crt(&mp, &mq, &dk))
    }
}


fn h<I>(p: &I, pp: &I, n: &I) -> I
where
    I: One,
    I: ModInv,
    for<'a> &'a I: Sub<I, Output=I>,
    for<'b>     I: Sub<&'b I, Output=I>,
    for<'b>     I: Rem<&'b I, Output=I>,
    for<'b>     I: Div<&'b I, Output=I>,
{
    // here we assume:
    //  - p \in {P, Q}
    //  - n = P * Q
    //  - g = 1 + n

    // compute g^{p-1} mod p^2
    let gp = (I::one() - n) % pp;
    // compute L_p(.)
    let lp = l(&gp, p);
    // compute L_p(.)^{-1}
    let hp = I::modinv(&lp, p);
    hp
}


fn crt<I>(mp: &I, mq: &I, dk: &DecryptionKey<I>) -> I
where
    I: NumberTests,
    for<'a>    &'a I: Add<I, Output=I>,
    for<'b>        I: Add<&'b I, Output=I>,
    for<'a,'b> &'a I: Sub<&'b I, Output=I>,
    for<'a,'b> &'a I: Mul<&'b I, Output=I>,
    for<'b>        I: Mul<&'b I, Output=I>,
    for<'b>        I: Rem<&'b I, Output=I>,
{
    let mut mq_minus_mp = (mq-mp) % &dk.q;
    if NumberTests::is_negative(&mq_minus_mp) {
        mq_minus_mp = mq_minus_mp + &dk.q;
    }
    let u = (mq_minus_mp * &dk.pinvq) % &dk.q;
    let m = mp + (&u * &dk.p);
    m % &dk.n
}
