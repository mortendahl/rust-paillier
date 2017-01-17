#[macro_use]
extern crate bencher;
extern crate paillier;
extern crate num_traits;

use bencher::Bencher;
use paillier::*;
use paillier::core::*;
// use paillier::core::standard::*;

pub fn bench_encryption<S>(b: &mut Bencher)
where
    S : AbstractScheme,
    S : Encryption<
            EncryptionKey<<S as AbstractScheme>::BigInteger>,
            Plaintext<<S as AbstractScheme>::BigInteger>,
            Ciphertext<<S as AbstractScheme>::BigInteger>>,
    S : TestKeyGeneration<<S as AbstractScheme>::BigInteger>,
    <S as AbstractScheme>::BigInteger : From<u32>,
{
    let (ek, _) = S::test_keypair();
    let m = Plaintext::from(10);
    b.iter(|| {
        let _ = S::encrypt(&ek, &m);
    });
}

pub fn bench_decryption<S>(b: &mut Bencher)
where
    S : AbstractScheme,
    S : Encryption<
            EncryptionKey<<S as AbstractScheme>::BigInteger>,
            Plaintext<<S as AbstractScheme>::BigInteger>,
            Ciphertext<<S as AbstractScheme>::BigInteger>>,
    S : Decryption<
            DecryptionKey<<S as AbstractScheme>::BigInteger>,
            Ciphertext<<S as AbstractScheme>::BigInteger>,
            Plaintext<<S as AbstractScheme>::BigInteger>>,
    S : TestKeyGeneration<<S as AbstractScheme>::BigInteger>,
    <S as AbstractScheme>::BigInteger : From<u32>,
{
    let (ek, dk) = S::test_keypair();
    let m = Plaintext::from(10);
    let c = S::encrypt(&ek, &m);
    b.iter(|| {
        let _ = S::decrypt(&dk, &c);
    });
}

pub fn bench_rerandomisation<S>(b: &mut Bencher)
where
    S : AbstractScheme,
    S : Encryption<
            EncryptionKey<<S as AbstractScheme>::BigInteger>,
            Plaintext<<S as AbstractScheme>::BigInteger>,
            Ciphertext<<S as AbstractScheme>::BigInteger>>,
    S : Rerandomisation<
            EncryptionKey<<S as AbstractScheme>::BigInteger>,
            Ciphertext<<S as AbstractScheme>::BigInteger>>,
    S : TestKeyGeneration<<S as AbstractScheme>::BigInteger>,
    <S as AbstractScheme>::BigInteger : From<u32>,
{
    let (ek, _) = S::test_keypair();
    let m = Plaintext::from(10);
    let c = S::encrypt(&ek, &m);
    b.iter(|| {
        let _ = S::rerandomise(&ek, &c);
    });
}

pub fn bench_addition<S>(b: &mut Bencher)
where
    S : AbstractScheme,
    S : Encryption<
            EncryptionKey<<S as AbstractScheme>::BigInteger>,
            Plaintext<<S as AbstractScheme>::BigInteger>,
            Ciphertext<<S as AbstractScheme>::BigInteger>>,
    S : Addition<
            EncryptionKey<<S as AbstractScheme>::BigInteger>,
            Ciphertext<<S as AbstractScheme>::BigInteger>,
            Ciphertext<<S as AbstractScheme>::BigInteger>,
            Ciphertext<<S as AbstractScheme>::BigInteger>>,
    S : TestKeyGeneration<<S as AbstractScheme>::BigInteger>,
    <S as AbstractScheme>::BigInteger : From<u32>,
{
    let (ek, _) = S::test_keypair();

    let m1 = Plaintext::from(10);
    let c1 = S::encrypt(&ek, &m1);

    let m2 = Plaintext::from(20);
    let c2 = S::encrypt(&ek, &m2);

    b.iter(|| {
        let _ = S::add(&ek, &c1, &c2);
    });
}

pub fn bench_multiplication<S>(b: &mut Bencher)
where
    S : AbstractScheme,
    S : Encryption<
            EncryptionKey<<S as AbstractScheme>::BigInteger>,
            Plaintext<<S as AbstractScheme>::BigInteger>,
            Ciphertext<<S as AbstractScheme>::BigInteger>>,
    S : Multiplication<
            EncryptionKey<<S as AbstractScheme>::BigInteger>,
            Ciphertext<<S as AbstractScheme>::BigInteger>,
            Plaintext<<S as AbstractScheme>::BigInteger>,
            Ciphertext<<S as AbstractScheme>::BigInteger>>,
    S : TestKeyGeneration<<S as AbstractScheme>::BigInteger>,
    <S as AbstractScheme>::BigInteger : From<u32>,
{
    let (ek, _) = S::test_keypair();

    let m1 = Plaintext::from(10);
    let c1 = S::encrypt(&ek, &m1);

    let m2 = Plaintext::from(20);

    b.iter(|| {
        let _ = S::mul(&ek, &c1, &m2);
    });
}

// 1024 bit primes
static P: &'static str = "148677972634832330983979593310074301486537017973460461278300587514468301043894574906886127642530475786889672304776052879927627556769456140664043088700743909632312483413393134504352834240399191134336344285483935856491230340093391784574980688823380828143810804684752914935441384845195613674104960646037368551517";
static Q: &'static str = "158741574437007245654463598139927898730476924736461654463975966787719309357536545869203069369466212089132653564188443272208127277664424448947476335413293018778018615899291704693105620242763173357203898195318179150836424196645745308205164116144020613415407736216097185962171301808761138424668335445923774195463";

// 2048 bit primes
// static P: &'static str = "54012895487015803837782421918841304863093162502146915827099238255626761389465957752056702693431430972436786355954646022466841435632094385265559627938436498972714352765471698566168945062965812056432412175521672036039582393637684261505269548649599691053041645072024278713283987472744964393377089048380212183701013564638897218456903964669359622810875460724326972855594957135344351009076932272355015777958742805494234839710255927334289902051693131165245513596331706022111667560809760947628509288759753593140967096047486612859680010875340619186313770693509235798857494768621913543203586903819461926872265770592622637080247";
// static Q: &'static str = "60110804761482905184172241999095064083721568391310132372880785562823040626081548259976195239057024762128798436684644401019565227508680839629752481384744855648596664223620474562582585419094571730852126918991494749938349375651158144545334949768160783962056913632707282062013023732986998195594940491859337992015569093391582644730733764652146222141495874869085082992832080902317418308778550853362446428222413647016439326663338175383509775221151568910938769471308411320393345489705012051577672571014388700476797545130036524629098427518061068575727892423981365405385986469525296662636940291427883820330312960173766723887143";

pub trait TestKeyGeneration<I>
{
    fn test_keypair() -> (EncryptionKey<I>, DecryptionKey<I>);
}

use std::ops::{Sub, Mul, Div, Rem};
use num_traits::{One};
use paillier::arithimpl::traits::ModularArithmetic;

// #[cfg(feature="inclramp")]
impl <I> TestKeyGeneration<I> for AbstractPaillier<I>
where
    I: Clone,
    I: One,
    I: ModularArithmetic,
    I: ::std::str::FromStr, <I as ::std::str::FromStr>::Err: ::std::fmt::Debug,
    for<'a, 'b> &'a I: Mul<&'b I, Output=I>,
    for<'b>         I: Div<&'b I, Output=I>,
    for<'a>     &'a I: Sub<I, Output=I>,
    for<'b>         I: Sub<&'b I, Output=I>,
    for<'b>         I: Rem<&'b I, Output=I>,
 {
    fn test_keypair() -> (EncryptionKey<I>, DecryptionKey<I>) {
        let ref p = str::parse(P).unwrap();
        let ref q = str::parse(Q).unwrap();
        let ref n = p * q;
        let ek = EncryptionKey::from(n);
        let dk = DecryptionKey::from((p, q));
        (ek, dk)
    }
}

#[cfg(feature="inclramp")]
benchmark_group!(ramp,
    self::bench_encryption<RampPaillier>,
    self::bench_decryption<RampPaillier>,
    self::bench_rerandomisation<RampPaillier>,
    self::bench_addition<RampPaillier>,
    self::bench_multiplication<RampPaillier>
);

#[cfg(feature="inclnum")]
benchmark_group!(num,
    self::bench_encryption<NumPaillier>,
    self::bench_decryption<NumPaillier>,
    self::bench_rerandomisation<NumPaillier>,
    self::bench_addition<NumPaillier>,
    self::bench_multiplication<NumPaillier>
);

#[cfg(feature="inclgmp")]
benchmark_group!(gmp,
    self::bench_encryption<GmpPaillier>,
    self::bench_decryption<GmpPaillier>,
    self::bench_rerandomisation<GmpPaillier>,
    self::bench_addition<GmpPaillier>,
    self::bench_multiplication<GmpPaillier>
);

pub fn dummy(_: &mut Bencher) {}

#[cfg(not(feature="inclramp"))]
benchmark_group!(ramp, dummy);

#[cfg(not(feature="inclnum"))]
benchmark_group!(num, dummy);

#[cfg(not(feature="inclgmp"))]
benchmark_group!(gmp, dummy);

benchmark_main!(ramp, num, gmp);
