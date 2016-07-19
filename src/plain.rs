
use rand;
use num::bigint::{BigUint, RandBigInt};

#[derive(Debug)]
pub struct PublicKey {
    pub modulus: BigUint,
    modulus_squared: BigUint
}

impl PublicKey {
    fn new(modulus: BigUint) -> PublicKey {
        PublicKey {
            modulus: modulus.clone(),
            modulus_squared: modulus.clone() * modulus.clone()
        }
    }
}

#[derive(Debug)]
pub struct PrivateKey {
    pub p: BigUint,
    pub q: BigUint
}

pub type Plaintext = BigUint;

pub type Ciphertext = BigUint;

pub fn generate_keypair(modulus_bit_length: usize) -> (PublicKey, PrivateKey) {
    let mut rng = rand::thread_rng();

    let p = rng.gen_biguint(modulus_bit_length);
    let q = rng.gen_biguint(modulus_bit_length);
    let dk = PrivateKey { p: p.clone(), q: q.clone() };

    let n = p * q;
    let ek = PublicKey::new(n);

    (ek, dk)
}

pub fn encrypt(ek: &PublicKey, m: &Plaintext) -> Ciphertext {
    m.clone()
}

// pub fn encrypt(ek: &PublicKey, m: usize) -> Ciphertext {
//     encrypt(ek, BigUint::from(m))
// }

pub fn decrypt(dk: &PrivateKey, c: &Ciphertext) -> Plaintext {
    c.clone()
}

pub fn add(ek: &PublicKey, c1: &Ciphertext, c2: &Ciphertext) -> Ciphertext {
    c1.clone() + c2.clone()
}

pub fn mult(ek: &PublicKey, c1: &Ciphertext, m2: &Plaintext) -> Ciphertext {
    c1.clone() * m2.clone()
}


#[cfg(test)]
mod tests {

    use super::*;
    use num::bigint::BigUint;

    #[test]
    fn key_generation() {
        let (ek, dk) = generate_keypair(1024);
        assert_eq!(ek.modulus, dk.p * dk.q);
    }

    #[test]
    fn correct_encryption_decryption() {
        let (ek, dk) = generate_keypair(1024);
        let m = BigUint::from(10 as usize);
        let c = encrypt(&ek, &m);
        let m_prime = decrypt(&dk, &c);
        assert_eq!(m, m_prime);
    }

    #[test]
    fn correct_addition() {
        let (ek, dk) = generate_keypair(1024);

        let m1 = BigUint::from(10 as u32);
        let c1 = encrypt(&ek, &m1);
        let m2 = BigUint::from(20 as u32);
        let c2 = encrypt(&ek, &m2);

        let c = add(&ek, &c1, &c2);
        let m = decrypt(&dk, &c);
        assert_eq!(m, BigUint::from(30 as u32));
    }

    #[test]
    fn correct_multiplication() {
        let (ek, dk) = generate_keypair(1024);

        let m1 = BigUint::from(10 as u32);
        let c1 = encrypt(&ek, &m1);
        let m2 = BigUint::from(20 as u32);

        let c = mult(&ek, &c1, &m2);
        let m = decrypt(&dk, &c);
        assert_eq!(m, BigUint::from(200 as u32));
    }

}
