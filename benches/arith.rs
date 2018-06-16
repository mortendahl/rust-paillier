
#[macro_use]
extern crate bencher;
extern crate paillier;

use bencher::Bencher;
use paillier::*;
use paillier::arithimpl::traits::*;

mod helpers;
use helpers::*;

pub fn bench_mul(b: &mut Bencher) {
    let ref p: BigInteger = str::parse(P1024).unwrap();
    let ref q: BigInteger = str::parse(Q1024).unwrap();

    b.iter(|| {
        let _ = p * q;
    });
}

pub fn bench_mulrem(b: &mut Bencher) {
    let ref p: BigInteger = str::parse(P1024).unwrap();
    let ref q: BigInteger = str::parse(Q1024).unwrap();
    let ref n: BigInteger = str::parse(N1024).unwrap();

    b.iter(|| {
        let _ = (p * q) % n;
    });
}

pub fn bench_modarith(b: &mut Bencher) {
    let ref p: BigInteger = str::parse(P1024).unwrap();
    let ref q: BigInteger = str::parse(Q1024).unwrap();
    let ref n: BigInteger = str::parse(N1024).unwrap();

    b.iter(|| {
        let _ = BigInteger::modpow(p, q, n);
    });
}

benchmark_group!(group,
    self::bench_mul,
    self::bench_mulrem,
    self::bench_modarith
);

benchmark_main!(group);
