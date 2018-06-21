extern crate bencher;
extern crate paillier;

use bencher::*;
use paillier::*;

mod helpers;
use helpers::KeySize;

pub fn bench_zk_proof_challenge_1024(b: &mut Bencher) {
    let (ek, _dk) =  helpers::get_key_pair(KeySize::S1024).keys();

    b.iter(|| {
        let (_challenge, _verification_aid) = Paillier::challenge(&ek);
    });
}


pub fn bench_zk_proof_prove_1024(b: &mut Bencher) {
    let (ek, dk) =  helpers::get_key_pair(KeySize::S1024).keys();
    let (challenge, _verification_aid) = Paillier::challenge(&ek);

    b.iter(|| {
        let _proof_results = Paillier::prove(&dk, &challenge);
    });
}


pub fn bench_zk_proof_prove_and_verify_1024(b: &mut Bencher) {
    let (ek, dk) =  helpers::get_key_pair(KeySize::S1024).keys();
    let (challenge, verification_aid) = Paillier::challenge(&ek);

    b.iter(|| {
        let proof_results = Paillier::prove(&dk, &challenge);
        let _result = Paillier::verify_correctKey(&proof_results.unwrap(), &verification_aid);
    });
}

pub fn bench_zk_proof_prove_all_1024(b: &mut Bencher) {
    let (ek, dk) =  helpers::get_key_pair(KeySize::S1024).keys();
    b.iter(|| {
        let (challenge, verification_aid) = Paillier::challenge(&ek);
        let proof_results = Paillier::prove(&dk, &challenge);
        let _result = Paillier::verify_correctKey(&proof_results.unwrap(), &verification_aid);
    });
}

pub fn bench_zk_proof_prove_all_2048(b: &mut Bencher) {
    let (ek, dk) =  helpers::get_key_pair(KeySize::S2048).keys();
    b.iter(|| {
        let (challenge, verification_aid) = Paillier::challenge(&ek);
        let proof_results = Paillier::prove(&dk, &challenge);
        let _result = Paillier::verify_correctKey(&proof_results.unwrap(), &verification_aid);

    });
}

benchmark_group!(zk_gmp,
    self::bench_zk_proof_challenge_1024,
    self::bench_zk_proof_prove_1024,
    self::bench_zk_proof_prove_and_verify_1024,
    self::bench_zk_proof_prove_all_1024,
    self::bench_zk_proof_prove_all_2048
);

benchmark_main!(zk_gmp);

