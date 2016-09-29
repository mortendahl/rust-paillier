use rand;
// use numtheory::*;

mod tests;

// use num::One;
// pub use num::bigint::BigInt;
// use num::bigint::{ToBigInt, RandBigInt};

use ramp::{Int, RandomInt};
use std::str::FromStr;
type Ring = Int;

pub trait ModularArithmetic {
    fn modpow(x: &Self, exponent: &Self, modulus: &Self) -> Self;
    fn modinv(a: &Self, modulus: &Self) -> Self;
    fn egcd(a: &Self, b: &Self) -> (Self, Self, Self) where Self: Sized;
}

impl ModularArithmetic for Int {

    fn modpow(x: &Int, e: &Int, prime: &Int) -> Int {
        let mut mx = x.clone();
        let mut me = e.clone();
        let mut acc = Int::one();
        while me != 0 {
            if me.is_even() {
                // even
                // no-op
            }
            else {
                // odd
                acc = (&acc * &mx) % prime;
            }
            mx = (&mx * &mx) % prime;  // waste one of these by having it here but code is simpler (tiny bit)
            me = me >> 1;
        }
        acc
    }

    fn egcd(a: &Int, b: &Int) -> (Int, Int, Int) {
        if b == &Int::zero() {
            (a.clone(), Int::one(), Int::zero())
        } else {
            let q = a / b;
            let r = a % b;
            let (d, s, t) = Self::egcd(b, &r);
            let new_t = s - &t * q;
            (d, t, new_t)
        }
    }

    fn modinv(a: &Int, prime: &Int) -> Int {
        // use num::Signed;
        use std::ops::Neg;

        let r = a % prime;
        let d = if r < 0 {
            let r = r.neg();
            -Self::egcd(prime, &r).2
        } else {
            Self::egcd(prime, &r).2
        };
        (prime + d) % prime
    }

}








pub type Plaintext = Ring;
pub type Ciphertext = Ring;

#[derive(Debug,Clone)]
pub struct PublicKey {
    pub n: Ring,  // the modulus
    nn: Ring,     // the modulus squared
    g: Ring,      // the generator, fixed at g = n + 1
}

#[derive(Debug,Clone)]
pub struct PrivateKey {
    pub p: Ring,  // first prime
    pub q: Ring,  // second prime
    pub n: Ring,  // the modulus (also in public key)
    nn: Ring,     // the modulus squared
    lambda: Ring, // fixed at lambda = (p-1)*(q-1)
    mu: Ring,     // fixed at lambda^{-1}
}




impl PublicKey {
    pub fn from(modulus: &Ring) -> PublicKey {
        PublicKey {
            n: modulus.clone(),
            nn: modulus * modulus,
            g: modulus + Ring::one()
        }
    }
}

impl PrivateKey {
    pub fn from(p: &Ring, q: &Ring) -> PrivateKey {
        let ref one = Ring::one();
        let modulus = p * q;
        let nn = &modulus * &modulus;
        let lambda = (p - one) * (q - one);
        let mu = Ring::modinv(&lambda, &modulus);
        PrivateKey {
            p: p.clone(),
            q: q.clone(),
            n: modulus,
            nn: nn,
            lambda: lambda,
            mu: mu,
        }
    }
}

// fn find_strong_prime(bit_length: usize) -> BigUint {
//     let mut rng = rand::OsRng::new().unwrap();
//     loop {
//         let p = rng.gen_biguint(bit_length);
//         if p.bits() == bit_length && is_prime(&p) {
//             return p
//         }
//     }
// }
//
// fn find_primes(modulus_bit_length: usize) -> (BigUint, BigUint) {
//     let prime_bit_length = modulus_bit_length / 2;
//     loop {
//         let p = find_prime(prime_bit_length);
//         let q = find_prime(prime_bit_length);
//         if p == q { continue } // TODO we may be able to keep using p instead of throwing both away
//
//         let modulus = &p * &q;
//         if modulus.bits() == modulus_bit_length {
//             return (p, q)
//         }
//     }
// }
//
// #[test]
// fn test_find_primes() {
    // let (p, q) = find_primes(128);
    // println!("{:?}, {:?}", p.bits(), q.bits());
    // println!("{:?}, {:?}", p, q);
    // assert_eq!(p.bits(), 128/2);
    // assert_eq!(q.bits(), 128/2);
// }
//
// pub fn generate_keypair(modulus_bit_length: usize) -> (PublicKey, PrivateKey) {
//     let (ref p, ref q) = find_primes(modulus_bit_length);
//     let ref n = p * q;
//     let dk = PrivateKey::from(p, q);
//     let ek = PublicKey::from(n);
//     (ek, dk)
// }
//
// pub fn generate_keypair(modulus_bit_length: usize) -> (PublicKey, PrivateKey) {
//     let (ref p, ref q) = (BigUint::from(1061u32), BigUint::from(1063u32));
//     let ref n = p * q;
//     let dk = PrivateKey::from(p, q);
//     let ek = PublicKey::from(n);
//     (ek, dk)
// }


pub fn fake_key_pair() -> (PublicKey, PrivateKey) {
    let p = Ring::from(1061u32);
    let q = Ring::from(1063u32);
    let n = &p * &q;
    let ek = PublicKey::from(&n);
    let dk = PrivateKey::from(&p, &q);
    (ek, dk)
}

pub fn large_fake_key_pair() -> (PublicKey, PrivateKey) {
    // let p = BigInt::parse_bytes(b"148677972634832330983979593310074301486537017973460461278300587514468301043894574906886127642530475786889672304776052879927627556769456140664043088700743909632312483413393134504352834240399191134336344285483935856491230340093391784574980688823380828143810804684752914935441384845195613674104960646037368551517", 10).unwrap();
    // let q = BigInt::parse_bytes(b"158741574437007245654463598139927898730476924736461654463975966787719309357536545869203069369466212089132653564188443272208127277664424448947476335413293018778018615899291704693105620242763173357203898195318179150836424196645745308205164116144020613415407736216097185962171301808761138424668335445923774195463", 10).unwrap();
    let p = Int::from_str("148677972634832330983979593310074301486537017973460461278300587514468301043894574906886127642530475786889672304776052879927627556769456140664043088700743909632312483413393134504352834240399191134336344285483935856491230340093391784574980688823380828143810804684752914935441384845195613674104960646037368551517").unwrap();
    let q = Int::from_str("158741574437007245654463598139927898730476924736461654463975966787719309357536545869203069369466212089132653564188443272208127277664424448947476335413293018778018615899291704693105620242763173357203898195318179150836424196645745308205164116144020613415407736216097185962171301808761138424668335445923774195463").unwrap();
    let n = &p * &q;
    let ek = PublicKey::from(&n);
    let dk = PrivateKey::from(&p, &q);
    (ek, dk)
}


pub fn encrypt(ek: &PublicKey, m: &Plaintext) -> Ciphertext {
    let ref gx = Ring::modpow(&ek.g, &m, &ek.nn);
    rerandomise(ek, gx)
}

pub fn decrypt(dk: &PrivateKey, c: &Ciphertext) -> Plaintext {
    let ref u = Ring::modpow(&c, &dk.lambda, &dk.nn);
    ((u - &Ring::one()) / &dk.n * &dk.mu) % &dk.n
}

pub fn add(ek: &PublicKey, c1: &Ciphertext, c2: &Ciphertext) -> Ciphertext {
    (c1 * c2) % &ek.nn
}

pub fn mult(ek: &PublicKey, c1: &Ciphertext, m2: &Plaintext) -> Ciphertext {
    Ring::modpow(c1, m2, &ek.nn)
}

pub fn rerandomise(ek: &PublicKey, c: &Ciphertext) -> Ciphertext {
    let mut rng = rand::OsRng::new().unwrap();
    // let ref r = rng.gen_biguint_below(&ek.n.to_biguint().unwrap()).to_bigint().unwrap();
    let ref r = rng.gen_uint_below(&ek.n);
    // { use num::Integer; debug_assert_eq!(r.gcd(&ek.n), BigInt::one()); }
    (c * Ring::modpow(r, &ek.n, &ek.nn)) % &ek.nn
}
