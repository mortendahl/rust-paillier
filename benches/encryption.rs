
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
    fn test_keypair_sized(usize) -> (Self::EncryptionKey, Self::DecryptionKey);
}
 



pub fn bench_key_generation_512<PHE>(b: &mut Bencher)
where
    PHE : PartiallyHomomorphicScheme,
    PHE : TestKeyGeneration,
    PHE::Plaintext : From<usize>
{
    b.iter(|| {
        PHE::test_keypair_sized(512);
    });
}

pub fn bench_key_generation_1024<PHE>(b: &mut Bencher)
where
    PHE : PartiallyHomomorphicScheme,
    PHE : TestKeyGeneration,
    PHE::Plaintext : From<usize>
{
    b.iter(|| {
        PHE::test_keypair_sized(1024);
    });
}

pub fn bench_key_generation_2048<PHE>(b: &mut Bencher)
where
    PHE : PartiallyHomomorphicScheme,
    PHE : TestKeyGeneration,
    PHE::Plaintext : From<usize>
{
    b.iter(|| {
        PHE::test_keypair_sized(2048);
    });
}

pub fn bench_key_generation_3072<PHE>(b: &mut Bencher)
where
    PHE : PartiallyHomomorphicScheme,
    PHE : TestKeyGeneration,
    PHE::Plaintext : From<usize>
{
    b.iter(|| {
        PHE::test_keypair_sized(3072);
    });    
}


////////////// END GENERATION  ////////////// 

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

#[cfg(feature="keygen")]
impl TestKeyGeneration for PlainPaillier {
    fn test_keypair() -> (<Self as PartiallyHomomorphicScheme>::EncryptionKey, <Self as PartiallyHomomorphicScheme>::DecryptionKey) {
        <Self as KeyGeneration>::keypair(2048)
    }

     fn test_keypair_sized(bitsize: usize) -> (<Self as PartiallyHomomorphicScheme>::EncryptionKey, <Self as PartiallyHomomorphicScheme>::DecryptionKey) {
        <Self as KeyGeneration>::keypair(bitsize)
    }
}

#[cfg(not(feature="keygen"))]
impl TestKeyGeneration for PlainPaillier {
    fn test_keypair() -> (<Self as PartiallyHomomorphicScheme>::EncryptionKey, <Self as PartiallyHomomorphicScheme>::DecryptionKey) {
        let p = str::parse("148677972634832330983979593310074301486537017973460461278300587514468301043894574906886127642530475786889672304776052879927627556769456140664043088700743909632312483413393134504352834240399191134336344285483935856491230340093391784574980688823380828143810804684752914935441384845195613674104960646037368551517").unwrap();
        let q = str::parse("158741574437007245654463598139927898730476924736461654463975966787719309357536545869203069369466212089132653564188443272208127277664424448947476335413293018778018615899291704693105620242763173357203898195318179150836424196645745308205164116144020613415407736216097185962171301808761138424668335445923774195463").unwrap();
        let n = &p * &q;
        let ek = <Self as PartiallyHomomorphicScheme>::EncryptionKey::from(&n);
        let dk = <Self as PartiallyHomomorphicScheme>::DecryptionKey::from(&p, &q);
        (ek, dk)
    }

    fn test_keypair_sized(bitsize: usize) -> (<Self as PartiallyHomomorphicScheme>::EncryptionKey, <Self as PartiallyHomomorphicScheme>::DecryptionKey) {
        let p = str::parse("148677972634832330983979593310074301486537017973460461278300587514468301043894574906886127642530475786889672304776052879927627556769456140664043088700743909632312483413393134504352834240399191134336344285483935856491230340093391784574980688823380828143810804684752914935441384845195613674104960646037368551517").unwrap();
        let q = str::parse("158741574437007245654463598139927898730476924736461654463975966787719309357536545869203069369466212089132653564188443272208127277664424448947476335413293018778018615899291704693105620242763173357203898195318179150836424196645745308205164116144020613415407736216097185962171301808761138424668335445923774195463").unwrap();
        let n = &p * &q;
        let ek = <Self as PartiallyHomomorphicScheme>::EncryptionKey::from(&n);
        let dk = <Self as PartiallyHomomorphicScheme>::DecryptionKey::from(&p, &q);
        (ek, dk)
    }
}

benchmark_group!(all,
    self::bench_encryption<PlainPaillier>,
    self::bench_decryption<PlainPaillier>,
    self::bench_rerandomisation<PlainPaillier>,
    self::bench_addition<PlainPaillier>,
    self::bench_multiplication<PlainPaillier>
);

#[cfg(feature="keygen")]
benchmark_group!(keygen,
    self::bench_key_generation_512<PlainPaillier>,
    self::bench_key_generation_1024<PlainPaillier>,
    self::bench_key_generation_2048<PlainPaillier>,
    self::bench_key_generation_3072<PlainPaillier>
); 


#[cfg(feature="keygen")]
benchmark_main!(keygen, all);

#[cfg(not(feature="keygen"))]
benchmark_main!(all);