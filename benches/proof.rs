mod helpers;

#[cfg(feature = "proofs")]
mod bench {

    use bencher::*;
    use paillier::proof::CorrectKey;
    use paillier::*;

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

    benchmark_group!(
        zk_2048,
        self::bench_zk_proof_challenge<KeySize2048>,
        self::bench_zk_proof_prove<KeySize2048>,
        self::bench_zk_proof_prove_and_verify<KeySize2048>,
        self::bench_zk_proof_prove_all<KeySize2048>
    );

    benchmark_group!(
        zk_4096,
        self::bench_zk_proof_challenge<KeySize4096>,
        self::bench_zk_proof_prove<KeySize4096>,
        self::bench_zk_proof_prove_and_verify<KeySize4096>,
        self::bench_zk_proof_prove_all<KeySize4096>
    );
}

#[cfg(feature = "proofs")]
benchmark_main!(bench::zk_2048, bench::zk_4096);

#[cfg(not(feature = "proofs"))]
fn main() {}
