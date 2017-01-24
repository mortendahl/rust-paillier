#[macro_use]
extern crate bencher;
extern crate paillier;
extern crate num_traits;

#[macro_use]
mod macros;
mod helpers;
use helpers::*;

scheme!(S, bench, group,
pub mod bench
{

    use super::*;
    use bencher::Bencher;
    use paillier::*;

    use TestKeyGeneration;

    pub fn bench_decryption_crt_small(b: &mut Bencher) {
        let keypair = S::test_keypair();
        let ek = core::standard::EncryptionKey::from(&keypair);
        let dk = core::crt::DecryptionKey::from(&keypair);

        let m = core::Plaintext::from(10);
        let c = S::encrypt(&ek, &m);
        b.iter(|| {
            let _ = S::decrypt(&dk, &c);
        });
    }

    pub fn bench_decryption_crt_random(b: &mut Bencher) {
        let keypair = S::test_keypair();
        let ek = core::standard::EncryptionKey::from(&keypair);
        let dk = core::crt::DecryptionKey::from(&keypair);

        use arithimpl::traits::Samplable;
        let m = core::Plaintext(<S as AbstractScheme>::BigInteger::sample_below(&ek.n));
        let c = S::encrypt(&ek, &m);
        b.iter(|| {
            let _ = S::decrypt(&dk, &c);
        });
    }

    pub fn bench_decryption_standard_small(b: &mut Bencher) {
        let keypair = S::test_keypair();
        let ek = core::standard::EncryptionKey::from(&keypair);
        let dk = core::standard::DecryptionKey::from(&keypair);

        let m = core::Plaintext::from(10);
        let c = S::encrypt(&ek, &m);
        b.iter(|| {
            let _ = S::decrypt(&dk, &c);
        });
    }

    pub fn bench_decryption_standard_random(b: &mut Bencher) {
        let keypair = S::test_keypair();
        let ek = core::standard::EncryptionKey::from(&keypair);
        let dk = core::standard::DecryptionKey::from(&keypair);

        use arithimpl::traits::Samplable;
        let m = core::Plaintext(<S as AbstractScheme>::BigInteger::sample_below(&ek.n));
        let c = S::encrypt(&ek, &m);
        b.iter(|| {
            let _ = S::decrypt(&dk, &c);
        });
    }

    benchmark_group!(group,
        self::bench_decryption_crt_small,
        self::bench_decryption_crt_random,
        self::bench_decryption_standard_small,
        self::bench_decryption_standard_random
    );

});

benchmark_main!(::ramp::bench::group, ::num::bench::group, ::gmp::bench::group);
