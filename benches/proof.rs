#[macro_use]
extern crate bencher;
extern crate paillier;

mod helpers;

#[cfg(feature="proofs")]
mod bench {

    use bencher::*;
    use paillier::*;
    use paillier::proof::ProveCorrectKey;

    use helpers::*;

    pub fn bench_zk_proof_challenge<KS: KeySize>(b: &mut Bencher) {
        let (ek, _dk) = KS::keypair().keys();

        b.iter(|| {
            let (_challenge, _verification_aid) = Paillier::challenge(&ek);
        });
    }

    pub fn bench_zk_proof_prove<KS: KeySize>(b: &mut Bencher) {
        let (ek, dk) = KS::keypair().keys();
        let (challenge, _verification_aid) = Paillier::challenge(&ek);

        b.iter(|| {
            let _proof_results = Paillier::prove(&dk, &challenge);
        });
    }

    pub fn bench_zk_proof_prove_and_verify<KS: KeySize>(b: &mut Bencher) {
        let (ek, dk) = KS::keypair().keys();
        let (challenge, verification_aid) = Paillier::challenge(&ek);

        b.iter(|| {
            let proof_results = Paillier::prove(&dk, &challenge);
            let _result = Paillier::verify(&proof_results.unwrap(), &verification_aid);
        });
    }

    pub fn bench_zk_proof_prove_all<KS: KeySize>(b: &mut Bencher) {
        let (ek, dk) = KS::keypair().keys();
        b.iter(|| {
            let (challenge, verification_aid) = Paillier::challenge(&ek);
            let proof_results = Paillier::prove(&dk, &challenge);
            let _result = Paillier::verify(&proof_results.unwrap(), &verification_aid);
        });
    }

    benchmark_group!(zk_1024,
        self::bench_zk_proof_challenge<KeySize1024>,
        self::bench_zk_proof_prove<KeySize1024>,
        self::bench_zk_proof_prove_and_verify<KeySize1024>,
        self::bench_zk_proof_prove_all<KeySize1024>
    );

    benchmark_group!(zk_2048,
        self::bench_zk_proof_challenge<KeySize2048>,
        self::bench_zk_proof_prove<KeySize2048>,
        self::bench_zk_proof_prove_and_verify<KeySize2048>,
        self::bench_zk_proof_prove_all<KeySize2048>
    );

}

#[cfg(feature="proofs")]
benchmark_main!(bench::zk_1024, bench::zk_2048);

#[cfg(not(feature="proofs"))]
fn main() {}
