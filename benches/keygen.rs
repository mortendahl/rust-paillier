#[macro_use]
extern crate bencher;
extern crate paillier;

mod helpers;

#[cfg(feature="keygen")]
mod bench {

    use bencher::Bencher;
    use paillier::RampPaillier;
    use paillier::*;
    use helpers::*;

    pub fn bench_key_generation<S, KS>(b: &mut Bencher)
    where
        S : AbstractScheme,
        S : KeyGeneration<Keypair<<S as AbstractScheme>::BigInteger>>,
        KS : KeySize,
    {
        b.iter(|| {
            S::keypair_with_modulus_size(KS::get());
        });
    }

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
