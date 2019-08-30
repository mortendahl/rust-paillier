use bencher::{benchmark_group, benchmark_main, Bencher};
use curv::arithmetic::traits::*;

use paillier::*;

mod helpers;
use helpers::*;

pub fn bench_mul(b: &mut Bencher) {
    let p: &BigInt = &str::parse(P2048).unwrap();
    let q: &BigInt = &str::parse(Q2048).unwrap();

    b.iter(|| {
        let _ = p * q;
    });
}

pub fn bench_mulrem(b: &mut Bencher) {
    let p: &BigInt = &str::parse(P2048).unwrap();
    let q: &BigInt = &str::parse(Q2048).unwrap();
    let n: &BigInt = &str::parse(N2048).unwrap();

    b.iter(|| {
        let _ = (p * q) % n;
    });
}

pub fn bench_modarith(b: &mut Bencher) {
    let p: &BigInt = &str::parse(P2048).unwrap();
    let q: &BigInt = &str::parse(Q2048).unwrap();
    let n: &BigInt = &str::parse(N2048).unwrap();

    b.iter(|| {
        let _ = BigInt::mod_pow(p, q, n);
    });
}

benchmark_group!(
    group,
    self::bench_mul,
    self::bench_mulrem,
    self::bench_modarith
);

benchmark_main!(group);
