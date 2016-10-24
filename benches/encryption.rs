
#[macro_use]
extern crate bencher;
extern crate paillier;

use bencher::Bencher;
use paillier::*;


pub trait TestKeyGeneration
where
    Self : PartiallyHomomorphicScheme
{
    fn test_keypair() -> (Self::EncryptionKey, Self::DecryptionKey);
}

pub fn bench_encryption<PHE>(b: &mut Bencher)
where
    PHE : PartiallyHomomorphicScheme,
    PHE : TestKeyGeneration,
    PHE::Plaintext : From<usize>
{
    let (ek, _) = PHE::test_keypair();
    let m = PHE::Plaintext::from(10);
    b.iter(|| {
        let _ = PHE::encrypt(&ek, &m);
    });
}

pub fn bench_decryption<PHE>(b: &mut Bencher)
where
    PHE : PartiallyHomomorphicScheme,
    PHE : TestKeyGeneration,
    PHE::Plaintext : From<usize>
{
    let (ek, dk) = PHE::test_keypair();
    let m = PHE::Plaintext::from(10);
    let c = PHE::encrypt(&ek, &m);
    b.iter(|| {
        let _ = PHE::decrypt(&dk, &c);
    });
}

pub fn bench_rerandomisation<PHE>(b: &mut Bencher)
where
    PHE : PartiallyHomomorphicScheme,
    PHE : TestKeyGeneration,
    PHE::Plaintext : From<usize>
{
    let (ek, _) = PHE::test_keypair();
    let m = PHE::Plaintext::from(10);
    let c = PHE::encrypt(&ek, &m);
    b.iter(|| {
        let _ = PHE::rerandomise(&ek, &c);
    });
}

pub fn bench_addition<PHE>(b: &mut Bencher)
where
    PHE : PartiallyHomomorphicScheme,
    PHE : TestKeyGeneration,
    PHE::Plaintext : From<usize>
{
    let (ek, _) = PHE::test_keypair();

    let m1 = PHE::Plaintext::from(10);
    let c1 = PHE::encrypt(&ek, &m1);

    let m2 = PHE::Plaintext::from(20);
    let c2 = PHE::encrypt(&ek, &m2);

    b.iter(|| {
        let _ = PHE::add(&ek, &c1, &c2);
    });
}

pub fn bench_multiplication<PHE>(b: &mut Bencher)
where
    PHE : PartiallyHomomorphicScheme,
    PHE : TestKeyGeneration,
    PHE::Plaintext : From<usize>
{
    let (ek, _) = PHE::test_keypair();

    let m1 = PHE::Plaintext::from(10);
    let c1 = PHE::encrypt(&ek, &m1);

    let m2 = PHE::Plaintext::from(20);

    b.iter(|| {
        let _ = PHE::mult(&ek, &c1, &m2);
    });
}

static P: &'static str = "148677972634832330983979593310074301486537017973460461278300587514468301043894574906886127642530475786889672304776052879927627556769456140664043088700743909632312483413393134504352834240399191134336344285483935856491230340093391784574980688823380828143810804684752914935441384845195613674104960646037368551517";
static Q: &'static str = "158741574437007245654463598139927898730476924736461654463975966787719309357536545869203069369466212089132653564188443272208127277664424448947476335413293018778018615899291704693105620242763173357203898195318179150836424196645745308205164116144020613415407736216097185962171301808761138424668335445923774195463";

#[cfg(feature="inclramp")]
impl TestKeyGeneration for RampPlainPaillier {
    fn test_keypair() -> (<Self as PartiallyHomomorphicScheme>::EncryptionKey, <Self as PartiallyHomomorphicScheme>::DecryptionKey) {
        let ref p = str::parse(P).unwrap();
        let ref q = str::parse(Q).unwrap();
        let ref n = p * q;
        let ek = <Self as PartiallyHomomorphicScheme>::EncryptionKey::from(n);
        let dk = <Self as PartiallyHomomorphicScheme>::DecryptionKey::from(p, q);
        (ek, dk)
    }
}

#[cfg(feature="inclnum")]
impl TestKeyGeneration for NumPlainPaillier {
    fn test_keypair() -> (<Self as PartiallyHomomorphicScheme>::EncryptionKey, <Self as PartiallyHomomorphicScheme>::DecryptionKey) {
        let ref p = str::parse(P).unwrap();
        let ref q = str::parse(Q).unwrap();
        let ref n = p * q;
        let ek = <Self as PartiallyHomomorphicScheme>::EncryptionKey::from(n);
        let dk = <Self as PartiallyHomomorphicScheme>::DecryptionKey::from(p, q);
        (ek, dk)
    }
}

#[cfg(feature="inclramp")]
benchmark_group!(ramp,
    self::bench_encryption<RampPlainPaillier>,
    self::bench_decryption<RampPlainPaillier>,
    self::bench_rerandomisation<RampPlainPaillier>,
    self::bench_addition<RampPlainPaillier>,
    self::bench_multiplication<RampPlainPaillier>
);

#[cfg(feature="inclnum")]
benchmark_group!(num,
    self::bench_encryption<NumPlainPaillier>,
    self::bench_decryption<NumPlainPaillier>,
    self::bench_rerandomisation<NumPlainPaillier>,
    self::bench_addition<NumPlainPaillier>,
    self::bench_multiplication<NumPlainPaillier>
);

pub fn dummy(_: &mut Bencher) {}

#[cfg(not(feature="inclramp"))]
benchmark_group!(ramp, dummy);

#[cfg(not(feature="inclnum"))]
benchmark_group!(num, dummy);

benchmark_main!(ramp, num);
