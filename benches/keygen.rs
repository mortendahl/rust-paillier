#[macro_use]
extern crate bencher;
extern crate paillier;

#[cfg(feature="keygen")]
mod bench {

    use bencher::Bencher;
    use paillier::RampPaillier;
    use paillier::*;

    pub fn bench_key_generation<S, KS>(b: &mut Bencher)
    where
        S : AbstractScheme,
        S : KeyGeneration<
                EncryptionKey<<S as AbstractScheme>::BigInteger>,
                DecryptionKey<<S as AbstractScheme>::BigInteger>>,
        KS : KeySize,
    {
        b.iter(|| {
            S::keypair_with_modulus_size(KS::get());
        });
    }

    pub trait KeySize { fn get() -> usize; }
    struct KeySize512;  impl KeySize for KeySize512  { fn get() -> usize {  512 } }
    struct KeySize1024; impl KeySize for KeySize1024 { fn get() -> usize { 1024 } }
    struct KeySize2048; impl KeySize for KeySize2048 { fn get() -> usize { 2048 } }
    struct KeySize3072; impl KeySize for KeySize3072 { fn get() -> usize { 3072 } }
    struct KeySize4096; impl KeySize for KeySize4096 { fn get() -> usize { 4096 } }

    benchmark_group!(ramp,
        self::bench_key_generation<RampPaillier, KeySize512>,
        self::bench_key_generation<RampPaillier, KeySize1024>,
        self::bench_key_generation<RampPaillier, KeySize2048>,
        self::bench_key_generation<RampPaillier, KeySize3072>,
        self::bench_key_generation<RampPaillier, KeySize4096>
    );

}

#[cfg(feature="keygen")]
benchmark_main!(bench::ramp);

#[cfg(not(feature="keygen"))]
fn main() {}
