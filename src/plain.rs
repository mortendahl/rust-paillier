use rand;
use num::One;
use num::bigint::{BigUint, ToBigInt, RandBigInt};

use numtheory::*;

pub type Plaintext = BigUint;

pub type Ciphertext = BigUint;

#[derive(Debug,Clone)]
pub struct PublicKey {
    pub n: BigUint,  // the modulus
    nn: BigUint,     // the modulus squared
    g: BigUint,      // the generator, fixed at g = n + 1
}

#[derive(Debug,Clone)]
pub struct PrivateKey {
    pub p: BigUint,  // first prime
    pub q: BigUint,  // second prime
    pub n: BigUint,      // the modulus (also in public key)
    nn: BigUint,     // the modulus squared
    lambda: BigUint, // fixed at lambda = (p-1)*(q-1)
    mu: BigUint,     // fixed at lambda^{-1}
}

impl PublicKey {
    pub fn from(modulus: &BigUint) -> PublicKey {
        PublicKey {
            n: modulus.clone(),
            nn: modulus * modulus,
            g: modulus + BigUint::one()
        }
    }
}

impl PrivateKey {
    pub fn from(p: &BigUint, q: &BigUint) -> PrivateKey {
        let ref one = BigUint::one();
        let modulus = p * q;
        let nn = &modulus * &modulus;
        let lambda = (p - one) * (q - one);
        let mu = modinv(&lambda.to_bigint().unwrap(), &modulus.to_bigint().unwrap()).to_biguint().unwrap(); // TODO ugly
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
    let p = BigUint::from(1061u32);
    let q = BigUint::from(1063u32);
    let n = &p * &q;
    let ek = PublicKey::from(&n);
    let dk = PrivateKey::from(&p, &q);
    (ek, dk)
}

pub fn large_fake_key_pair() -> (PublicKey, PrivateKey) {
    let p = BigUint::parse_bytes(b"148677972634832330983979593310074301486537017973460461278300587514468301043894574906886127642530475786889672304776052879927627556769456140664043088700743909632312483413393134504352834240399191134336344285483935856491230340093391784574980688823380828143810804684752914935441384845195613674104960646037368551517", 10).unwrap();
    let q = BigUint::parse_bytes(b"158741574437007245654463598139927898730476924736461654463975966787719309357536545869203069369466212089132653564188443272208127277664424448947476335413293018778018615899291704693105620242763173357203898195318179150836424196645745308205164116144020613415407736216097185962171301808761138424668335445923774195463", 10).unwrap();
    let n = &p * &q;
    let ek = PublicKey::from(&n);
    let dk = PrivateKey::from(&p, &q);
    (ek, dk)
}

pub fn encrypt(ek: &PublicKey, m: &Plaintext) -> Ciphertext {
    let ref gx = modpow(&ek.g, &m, &ek.nn);
    rerandomise(ek, gx)
}

pub fn decrypt(dk: &PrivateKey, c: &Ciphertext) -> Plaintext {
    let ref u = modpow(&c, &dk.lambda, &dk.nn);
    ((u - &BigUint::one()) / &dk.n * &dk.mu) % &dk.n
}

pub fn add(ek: &PublicKey, c1: &Ciphertext, c2: &Ciphertext) -> Ciphertext {
    (c1 * c2) % &ek.nn
}

pub fn mult(ek: &PublicKey, c1: &Ciphertext, m2: &Plaintext) -> Ciphertext {
    modpow(c1, m2, &ek.nn)
}

pub fn rerandomise(ek: &PublicKey, c: &Ciphertext) -> Ciphertext {
    let mut rng = rand::OsRng::new().unwrap();
    let ref r = rng.gen_biguint_below(&ek.n);
    { use num::Integer; debug_assert_eq!(r.gcd(&ek.n), BigUint::one()); }
    (c * modpow(r, &ek.n, &ek.nn)) % &ek.nn
}


#[cfg(test)]
mod tests {

    use super::*;
    use num::bigint::BigUint;

    fn key_pair() -> (PublicKey, PrivateKey) {
        fake_key_pair()
    }

    #[test]
    fn correct_encryption_decryption() {
        let (ek, dk) = key_pair();

        let m = BigUint::from(10 as usize);
        let c = encrypt(&ek, &m);

        let recovered_m = decrypt(&dk, &c);
        assert_eq!(recovered_m, m);
    }

    #[test]
    fn correct_addition() {
        let (ek, dk) = key_pair();

        let m1 = BigUint::from(10 as u32);
        let c1 = encrypt(&ek, &m1);
        let m2 = BigUint::from(20 as u32);
        let c2 = encrypt(&ek, &m2);

        let c = add(&ek, &c1, &c2);
        let m = decrypt(&dk, &c);
        assert_eq!(m, m1 + m2);
    }

    #[test]
    fn correct_multiplication() {
        let (ek, dk) = key_pair();

        let m1 = BigUint::from(10 as u32);
        let c1 = encrypt(&ek, &m1);
        let m2 = BigUint::from(20 as u32);

        let c = mult(&ek, &c1, &m2);
        let m = decrypt(&dk, &c);
        assert_eq!(m, m1 * m2);
    }

}
