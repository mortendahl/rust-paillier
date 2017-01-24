#[macro_use]
extern crate bencher;
extern crate paillier;
extern crate num_traits;

use bencher::Bencher;
use paillier::*;
use paillier::core::*;

#[macro_use]
mod macros;
mod helpers;
use helpers::*;

pub fn bench_encryption<S, EK>(b: &mut Bencher)
where
    S : AbstractScheme,
    S : TestKeyGeneration<<S as AbstractScheme>::BigInteger>,
    for<'kp> EK : From<&'kp Keypair<<S as AbstractScheme>::BigInteger>>,
    S : Encryption<
            EK,
            Plaintext<<S as AbstractScheme>::BigInteger>,
            Ciphertext<<S as AbstractScheme>::BigInteger>>,
    <S as AbstractScheme>::BigInteger : From<u32>,
{
    let ref keypair = S::test_keypair();
    let ek = EK::from(keypair);
    let m = Plaintext::from(10);
    b.iter(|| {
        let _ = S::encrypt(&ek, &m);
    });
}

pub fn bench_decryption<S, EK, DK>(b: &mut Bencher)
where
    S : AbstractScheme,
    for<'kp> EK : From<&'kp Keypair<<S as AbstractScheme>::BigInteger>>,
    for<'kp> DK : From<&'kp Keypair<<S as AbstractScheme>::BigInteger>>,
    S : Encryption<
            EK,
            Plaintext<<S as AbstractScheme>::BigInteger>,
            Ciphertext<<S as AbstractScheme>::BigInteger>>,
    S : Decryption<
            DK,
            Ciphertext<<S as AbstractScheme>::BigInteger>,
            Plaintext<<S as AbstractScheme>::BigInteger>>,
    S : TestKeyGeneration<<S as AbstractScheme>::BigInteger>,
    <S as AbstractScheme>::BigInteger : From<u32>,
{
    let ref keypair = S::test_keypair();
    let ek = EK::from(keypair);
    let dk = DK::from(keypair);
    let m = Plaintext::from(10);
    let c = S::encrypt(&ek, &m);
    b.iter(|| {
        let _ = S::decrypt(&dk, &c);
    });
}

pub fn bench_rerandomisation<S, EK>(b: &mut Bencher)
where
    S : AbstractScheme,
    S : Encryption<
            EK,
            Plaintext<<S as AbstractScheme>::BigInteger>,
            Ciphertext<<S as AbstractScheme>::BigInteger>>,
    S : Rerandomisation<
            EK,
            Ciphertext<<S as AbstractScheme>::BigInteger>>,
    S : TestKeyGeneration<<S as AbstractScheme>::BigInteger>,
    for<'kp> EK : From<&'kp Keypair<<S as AbstractScheme>::BigInteger>>,
    <S as AbstractScheme>::BigInteger : From<u32>,
{
    let ref keypair = S::test_keypair();
    let ek = EK::from(keypair);
    let m = Plaintext::from(10);
    let c = S::encrypt(&ek, &m);
    b.iter(|| {
        let _ = S::rerandomise(&ek, &c);
    });
}

pub fn bench_addition<S, EK>(b: &mut Bencher)
where
    S : AbstractScheme,
    S : Encryption<
            EK,
            Plaintext<<S as AbstractScheme>::BigInteger>,
            Ciphertext<<S as AbstractScheme>::BigInteger>>,
    S : Addition<
            EK,
            Ciphertext<<S as AbstractScheme>::BigInteger>,
            Ciphertext<<S as AbstractScheme>::BigInteger>,
            Ciphertext<<S as AbstractScheme>::BigInteger>>,
    S : TestKeyGeneration<<S as AbstractScheme>::BigInteger>,
    for<'kp> EK : From<&'kp Keypair<<S as AbstractScheme>::BigInteger>>,
    <S as AbstractScheme>::BigInteger : From<u32>,
{
    let ref keypair = S::test_keypair();
    let ek = EK::from(keypair);

    let m1 = Plaintext::from(10);
    let c1 = S::encrypt(&ek, &m1);

    let m2 = Plaintext::from(20);
    let c2 = S::encrypt(&ek, &m2);

    b.iter(|| {
        let _ = S::add(&ek, &c1, &c2);
    });
}

pub fn bench_multiplication<S, EK>(b: &mut Bencher)
where
    S : AbstractScheme,
    S : Encryption<
            EK,
            Plaintext<<S as AbstractScheme>::BigInteger>,
            Ciphertext<<S as AbstractScheme>::BigInteger>>,
    S : Multiplication<
            EK,
            Ciphertext<<S as AbstractScheme>::BigInteger>,
            Plaintext<<S as AbstractScheme>::BigInteger>,
            Ciphertext<<S as AbstractScheme>::BigInteger>>,
    S : TestKeyGeneration<<S as AbstractScheme>::BigInteger>,
    for<'kp> EK : From<&'kp Keypair<<S as AbstractScheme>::BigInteger>>,
    <S as AbstractScheme>::BigInteger : From<u32>,
{
    let ref keypair = S::test_keypair();
    let ek = EK::from(keypair);

    let m1 = Plaintext::from(10);
    let c1 = S::encrypt(&ek, &m1);

    let m2 = Plaintext::from(20);

    b.iter(|| {
        let _ = S::mul(&ek, &c1, &m2);
    });
}

type RampStandardEK = standard::EncryptionKey<RampBigInteger>;
type RampGenericEK = generic::EncryptionKey<RampBigInteger>;
type RampCrtDK = crt::DecryptionKey<RampBigInteger>;

#[cfg(feature="inclramp")]
benchmark_group!(ramp,
    self::bench_encryption<RampPaillier, RampStandardEK>,
    self::bench_encryption<RampPaillier, RampGenericEK>,
    self::bench_decryption<RampPaillier, RampStandardEK, RampCrtDK>,
    self::bench_rerandomisation<RampPaillier, RampStandardEK>,
    self::bench_addition<RampPaillier, RampStandardEK>,
    self::bench_multiplication<RampPaillier, RampStandardEK>
);

#[cfg(feature="inclnum")]
benchmark_group!(num,
    self::bench_encryption<NumPaillier, standard::EncryptionKey<NumBigInteger>>,
    self::bench_decryption<NumPaillier, standard::EncryptionKey<NumBigInteger>, crt::DecryptionKey<NumBigInteger>>,
    self::bench_rerandomisation<NumPaillier, standard::EncryptionKey<NumBigInteger>>,
    self::bench_addition<NumPaillier, standard::EncryptionKey<NumBigInteger>>,
    self::bench_multiplication<NumPaillier, standard::EncryptionKey<NumBigInteger>>
);

#[cfg(feature="inclgmp")]
benchmark_group!(gmp,
    self::bench_encryption<GmpPaillier, standard::EncryptionKey<GmpBigInteger>>,
    self::bench_decryption<GmpPaillier, standard::EncryptionKey<GmpBigInteger>, crt::DecryptionKey<GmpBigInteger>>,
    self::bench_rerandomisation<GmpPaillier, standard::EncryptionKey<GmpBigInteger>>,
    self::bench_addition<GmpPaillier, standard::EncryptionKey<GmpBigInteger>>,
    self::bench_multiplication<GmpPaillier, standard::EncryptionKey<GmpBigInteger>>
);

pub fn dummy(_: &mut Bencher) {}

#[cfg(not(feature="inclramp"))]
benchmark_group!(ramp, dummy);

#[cfg(not(feature="inclnum"))]
benchmark_group!(num, dummy);

#[cfg(not(feature="inclgmp"))]
benchmark_group!(gmp, dummy);

benchmark_main!(ramp, num, gmp);
