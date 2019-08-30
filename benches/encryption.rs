use bencher::{benchmark_group, benchmark_main, Bencher};

use paillier::*;

mod helpers;
use helpers::*;

pub fn bench_encryption_ek<KS: KeySize>(b: &mut Bencher) {
    let keypair = KS::keypair();
    let ek = EncryptionKey::from(&keypair);

    b.iter(|| {
        let _ = Paillier::encrypt(&ek, 10);
    });
}

pub fn bench_encryption_dk<KS: KeySize>(b: &mut Bencher) {
    let keypair = KS::keypair();
    let dk = DecryptionKey::from(&keypair);

    b.iter(|| {
        let _ = Paillier::encrypt(&dk, 10);
    });
}

pub fn bench_decryption<KS: KeySize>(b: &mut Bencher) {
    let keypair = KS::keypair();
    let (ek, dk) = keypair.keys();

    let c = Paillier::encrypt(&ek, 10);

    b.iter(|| {
        let _ = Paillier::decrypt(&dk, &c);
    });
}

pub fn bench_rerandomisation<KS: KeySize>(b: &mut Bencher) {
    let keypair = KS::keypair();
    let ek = EncryptionKey::from(&keypair);

    let c = Paillier::encrypt(&ek, 10);

    b.iter(|| {
        let _ = Paillier::rerandomize(&ek, &c);
    });
}

pub fn bench_addition<KS: KeySize>(b: &mut Bencher) {
    let keypair = KS::keypair();
    let ek = EncryptionKey::from(&keypair);

    let c1 = Paillier::encrypt(&ek, 10);
    let c2 = Paillier::encrypt(&ek, 20);

    b.iter(|| {
        let _ = Paillier::add(&ek, &c1, &c2);
    });
}

pub fn bench_multiplication<KS: KeySize>(b: &mut Bencher) {
    let keypair = KS::keypair();
    let ek = EncryptionKey::from(&keypair);

    let c = Paillier::encrypt(&ek, 10);

    b.iter(|| {
        let _ = Paillier::mul(&ek, &c, 20);
    });
}

benchmark_group!(
    ks_2048,
    self::bench_encryption_ek<KeySize2048>,
    self::bench_encryption_dk<KeySize2048>,
    self::bench_decryption<KeySize2048>,
    self::bench_rerandomisation<KeySize2048>,
    self::bench_addition<KeySize2048>,
    self::bench_multiplication<KeySize2048>
);

benchmark_group!(
    ks_4096,
    self::bench_encryption_ek<KeySize4096>,
    self::bench_encryption_dk<KeySize4096>,
    self::bench_decryption<KeySize4096>,
    self::bench_rerandomisation<KeySize4096>,
    self::bench_addition<KeySize4096>,
    self::bench_multiplication<KeySize4096>
);

benchmark_main!(ks_2048, ks_4096);
