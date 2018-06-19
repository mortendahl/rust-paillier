#[macro_use]
extern crate bencher;
extern crate paillier;
extern crate num_traits;

use bencher::Bencher;
use paillier::*;

mod helpers;
use helpers::*;

pub fn bench_encryption<KS: KeySize>(b: &mut Bencher) {
    let ref keypair = KS::keypair();
    let ek = EncryptionKey::from(keypair);
    let m = RawPlaintext::from(10);
    b.iter(|| {
        let _ = Paillier::encrypt(&ek, &m);
    });
}

pub fn bench_decryption<KS: KeySize>(b: &mut Bencher) {
    let ref keypair = KS::keypair();
    let ek = EncryptionKey::from(keypair);
    let dk = DecryptionKey::from(keypair);
    let m = RawPlaintext::from(10);
    let c = Paillier::encrypt(&ek, &m);
    b.iter(|| {
        let _ = Paillier::decrypt(&dk, &c);
    });
}

pub fn bench_rerandomisation<KS: KeySize>(b: &mut Bencher) {
    let ref keypair = KS::keypair();
    let ek = EncryptionKey::from(keypair);
    let m = RawPlaintext::from(10);
    let c = Paillier::encrypt(&ek, &m);
    b.iter(|| {
        let _ = Paillier::rerandomise(&ek, &c);
    });
}

pub fn bench_addition<KS: KeySize>(b: &mut Bencher) {
    let ref keypair = KS::keypair();
    let ek = EncryptionKey::from(keypair);

    let m1 = RawPlaintext::from(10);
    let c1 = Paillier::encrypt(&ek, &m1);

    let m2 = RawPlaintext::from(20);
    let c2 = Paillier::encrypt(&ek, &m2);

    b.iter(|| {
        let _ = Paillier::add(&ek, &c1, &c2);
    });
}

pub fn bench_multiplication<KS: KeySize>(b: &mut Bencher) {
    let ref keypair = KS::keypair();
    let ek = EncryptionKey::from(keypair);

    let m1 = RawPlaintext::from(10);
    let c1 = Paillier::encrypt(&ek, &m1);

    let m2 = RawPlaintext::from(20);

    b.iter(|| {
        let _ = Paillier::mul(&ek, &c1, &m2);
    });
}

benchmark_group!(ks_2048,
    self::bench_encryption<KeySize2048>,
    self::bench_decryption<KeySize2048>,
    self::bench_rerandomisation<KeySize2048>,
    self::bench_addition<KeySize2048>,
    self::bench_multiplication<KeySize2048>
);

benchmark_group!(ks_4096,
    self::bench_encryption<KeySize4096>,
    self::bench_decryption<KeySize4096>,
    self::bench_rerandomisation<KeySize4096>,
    self::bench_addition<KeySize4096>,
    self::bench_multiplication<KeySize4096>
);

benchmark_main!(ks_2048, ks_4096);
