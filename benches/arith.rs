#[macro_use]
extern crate bencher;
extern crate curv;
extern crate paillier;

use bencher::Bencher;
use curv::arithmetic::traits::*;
use paillier::*;

mod helpers;
use helpers::*;

pub fn bench_mul(b: &mut Bencher) {
    let ref p: BigInt = str::parse(P2048).unwrap();
    let ref q: BigInt = str::parse(Q2048).unwrap();

    b.iter(|| {
        let _ = p * q;
    });
}

pub fn bench_mulrem(b: &mut Bencher) {
    let ref p: BigInt = str::parse(P2048).unwrap();
    let ref q: BigInt = str::parse(Q2048).unwrap();
    let ref n: BigInt = str::parse(N2048).unwrap();

    b.iter(|| {
        let _ = (p * q) % n;
    });
}

pub fn bench_modarith(b: &mut Bencher) {
    let ref p: BigInt = str::parse(P2048).unwrap();
    let ref q: BigInt = str::parse(Q2048).unwrap();
    let ref n: BigInt = str::parse(N2048).unwrap();

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
