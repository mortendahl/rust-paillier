#[macro_use]
extern crate bencher;
extern crate paillier;

#[cfg(feature="keygen")]
mod bench {

    use bencher::Bencher;
    use paillier::RampPlainPaillier;
    use paillier::plain::{self, KeyGeneration};

    pub fn bench_key_generation_512<Scheme>(b: &mut Bencher)
    where
        Scheme : plain::AbstractScheme,
        Scheme : plain::Encode<usize, BigInteger=<Scheme as plain::AbstractScheme>::BigInteger>,
        Scheme : KeyGeneration<<Scheme as plain::AbstractScheme>::BigInteger>
    {
        b.iter(|| {
            Scheme::keypair(512);
        });
    }

    pub fn bench_key_generation_1024<Scheme>(b: &mut Bencher)
    where
        Scheme : plain::AbstractScheme,
        Scheme : plain::Encode<usize, BigInteger=<Scheme as plain::AbstractScheme>::BigInteger>,
        Scheme : KeyGeneration<<Scheme as plain::AbstractScheme>::BigInteger>
    {
        b.iter(|| {
            Scheme::keypair(1024);
        });
    }

    pub fn bench_key_generation_2048<Scheme>(b: &mut Bencher)
    where
        Scheme : plain::AbstractScheme,
        Scheme : plain::Encode<usize, BigInteger=<Scheme as plain::AbstractScheme>::BigInteger>,
        Scheme : KeyGeneration<<Scheme as plain::AbstractScheme>::BigInteger>
    {
        b.iter(|| {
            Scheme::keypair(2048);
        });
    }

    pub fn bench_key_generation_3072<Scheme>(b: &mut Bencher)
    where
        Scheme : plain::AbstractScheme,
        Scheme : plain::Encode<usize, BigInteger=<Scheme as plain::AbstractScheme>::BigInteger>,
        Scheme : KeyGeneration<<Scheme as plain::AbstractScheme>::BigInteger>
    {
        b.iter(|| {
            Scheme::keypair(3072);
        });
    }

    /*
    impl TestKeyGeneration for PlainPaillier {
        fn test_keypair(bitsize: usize) -> (<Self as PartiallyHomomorphicScheme>::EncryptionKey, <Self as PartiallyHomomorphicScheme>::DecryptionKey) {
            <Self as KeyGeneration>::keypair(bitsize)
        }
    }
    */

    benchmark_group!(ramp,
        self::bench_key_generation_512<RampPlainPaillier>,
        self::bench_key_generation_1024<RampPlainPaillier>,
        self::bench_key_generation_2048<RampPlainPaillier>,
        self::bench_key_generation_3072<RampPlainPaillier>
    );

}

#[cfg(feature="keygen")]
benchmark_main!(bench::ramp);

#[cfg(not(feature="keygen"))]
fn main() {}
