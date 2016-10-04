
#[macro_use]
extern crate bencher;
extern crate paillier;

use bencher::Bencher;
use paillier::PartiallyHomomorphicScheme as PHE;
use paillier::PlainPaillier;

fn test_keypair() -> (<PlainPaillier as PHE>::EncryptionKey, <PlainPaillier as PHE>::DecryptionKey) {
    let ref p = str::parse("148677972634832330983979593310074301486537017973460461278300587514468301043894574906886127642530475786889672304776052879927627556769456140664043088700743909632312483413393134504352834240399191134336344285483935856491230340093391784574980688823380828143810804684752914935441384845195613674104960646037368551517").unwrap();
    let ref q = str::parse("158741574437007245654463598139927898730476924736461654463975966787719309357536545869203069369466212089132653564188443272208127277664424448947476335413293018778018615899291704693105620242763173357203898195318179150836424196645745308205164116144020613415407736216097185962171301808761138424668335445923774195463").unwrap();
    let ref n = p * q;
    let ek = <PlainPaillier as PHE>::EncryptionKey::from(n);
    let dk = <PlainPaillier as PHE>::DecryptionKey::from(p, q);
    (ek, dk)
}

pub fn bench_encryption(b: &mut Bencher) {
    let (ek, _) = test_keypair();
    let m = <PlainPaillier as PHE>::Plaintext::from(10);
    b.iter(|| {
        let _ = PlainPaillier::encrypt(&ek, &m);
    });
}

pub fn bench_decryption(b: &mut Bencher) {
    let (ek, dk) = test_keypair();
    let m = <PlainPaillier as PHE>::Plaintext::from(10);
    let c = PlainPaillier::encrypt(&ek, &m);
    b.iter(|| {
        let _ = PlainPaillier::decrypt(&dk, &c);
    });
}

pub fn bench_rerandomisation(b: &mut Bencher) {
    let (ek, _) = test_keypair();
    let m = <PlainPaillier as PHE>::Plaintext::from(10);
    let c = PlainPaillier::encrypt(&ek, &m);
    b.iter(|| {
        let _ = PlainPaillier::rerandomise(&ek, &c);
    });
}

pub fn bench_addition(b: &mut Bencher) {
    let (ek, _) = test_keypair();

    let m1 = <PlainPaillier as PHE>::Plaintext::from(10);
    let c1 = PlainPaillier::encrypt(&ek, &m1);

    let m2 = <PlainPaillier as PHE>::Plaintext::from(20);
    let c2 = PlainPaillier::encrypt(&ek, &m2);

    b.iter(|| {
        let _ = PlainPaillier::add(&ek, &c1, &c2);
    });
}

pub fn bench_multiplication(b: &mut Bencher) {
    let (ek, _) = test_keypair();

    let m1 = <PlainPaillier as PHE>::Plaintext::from(10);
    let c1 = PlainPaillier::encrypt(&ek, &m1);

    let m2 = <PlainPaillier as PHE>::Plaintext::from(20);

    b.iter(|| {
        let _ = PlainPaillier::mult(&ek, &c1, &m2);
    });
}

benchmark_group!(group,
    self::bench_encryption,
    self::bench_decryption,
    self::bench_rerandomisation,
    self::bench_addition,
    self::bench_multiplication);

benchmark_main!(group);
