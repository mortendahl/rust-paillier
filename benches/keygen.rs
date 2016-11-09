#[macro_use]
extern crate bencher;
extern crate paillier;

#[cfg(feature="keygen")]
mod bench {

use bencher::Bencher;
use paillier::*;

pub fn bench_key_generation_512<PHE>(b: &mut Bencher)
where
    PHE : PartiallyHomomorphicScheme,
    PHE : KeyGeneration,
    PHE::Plaintext : From<usize>
{
    b.iter(|| {
        PHE::keypair(512);
    });
}

pub fn bench_key_generation_1024<PHE>(b: &mut Bencher)
where
    PHE : PartiallyHomomorphicScheme,
    PHE : KeyGeneration,
    PHE::Plaintext : From<usize>
{
    b.iter(|| {
        PHE::keypair(1024);
    });
}

pub fn bench_key_generation_2048<PHE>(b: &mut Bencher)
where
    PHE : PartiallyHomomorphicScheme,
    PHE : KeyGeneration,
    PHE::Plaintext : From<usize>
{
    b.iter(|| {
        PHE::keypair(2048);
    });
}

pub fn bench_key_generation_3072<PHE>(b: &mut Bencher)
where
    PHE : PartiallyHomomorphicScheme,
    PHE : KeyGeneration,
    PHE::Plaintext : From<usize>
{
    b.iter(|| {
        PHE::keypair(3072);
    });    
}

/*
impl TestKeyGeneration for PlainPaillier {
    fn test_keypair(bitsize: usize) -> (<Self as PartiallyHomomorphicScheme>::EncryptionKey, <Self as PartiallyHomomorphicScheme>::DecryptionKey) {
        <Self as KeyGeneration>::keypair(bitsize)
    }
}
*/

benchmark_group!(keygen,
    self::bench_key_generation_512<PlainPaillier>,
    self::bench_key_generation_1024<PlainPaillier>,
    self::bench_key_generation_2048<PlainPaillier>,
    self::bench_key_generation_3072<PlainPaillier>
); 

}

#[cfg(feature="keygen")]
benchmark_main!(bench::keygen);

#[cfg(not(feature="keygen"))]
fn main() {}