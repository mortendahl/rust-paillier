
use rand;
use num::One;
use num::bigint::{BigUint, ToBigInt, RandBigInt};

use numtheory::*;

pub type Plaintext = BigUint;
pub type Ciphertext = BigUint;

#[derive(Debug)]
pub struct PublicKey {
    pub n: BigUint,  // the modulus
    nn: BigUint,     // the modulus squared
    g: BigUint,      // the generator, fixed at g = n + 1
}

#[derive(Debug)]
pub struct PrivateKey {
    pub p: BigUint,  // first prime
    pub q: BigUint,  // second prime
    n: BigUint,      // the modulus (also in public key)
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

// fn find_prime(bit_length: usize) -> BigUint {
//     let mut rng = rand::thread_rng(); // TODO OsRng
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

// #[test]
// fn test_find_primes() {
    // let (p, q) = find_primes(128);
    // println!("{:?}, {:?}", p.bits(), q.bits());
    // println!("{:?}, {:?}", p, q);
    // assert_eq!(p.bits(), 128/2);
    // assert_eq!(q.bits(), 128/2);
// }

// pub fn generate_keypair(modulus_bit_length: usize) -> (PublicKey, PrivateKey) {
//     let (ref p, ref q) = find_primes(modulus_bit_length);
//     let ref n = p * q;
//     let dk = PrivateKey::from(p, q);
//     let ek = PublicKey::from(n);
//     (ek, dk)
// }

pub fn encrypt(ek: &PublicKey, m: &BigUint) -> Ciphertext {
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
    let mut rng = rand::thread_rng(); // TODO OsRng
    let ref r = rng.gen_biguint_below(&ek.n);
    {
        use num::Integer;
        debug_assert_eq!(r.gcd(&ek.n), BigUint::one());
    }
    (c * modpow(r, &ek.n, &ek.nn)) % &ek.nn
}


#[cfg(test)]
mod tests {

    use super::*;
    use num::bigint::BigUint;

    fn key_pair() -> (PublicKey, PrivateKey) {
        let p = BigUint::from(1061u32);
        let q = BigUint::from(1063u32);
        let n = &p * &q;
        let dk = PrivateKey::from(&p, &q);
        let ek = PublicKey::from(&n);
        (ek, dk)
    }

    // fn key_pair() -> (PublicKey, PrivateKey) {
    //     let p = BigUint::from(23u32);
    //     let q = BigUint::from(31u32);
    //     let n = &p * &q;
    //     let dk = PrivateKey::from(&p, &q);
    //     let ek = PublicKey::from(&n);
    //     (ek, dk)
    // }

    // #[test]
    // fn key_generation() {
    //     let (ek, dk) = generate_keypair(1024);
    //     assert_eq!(ek.n, dk.p * dk.q);
    // }

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
