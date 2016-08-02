use num::bigint::{BigUint};
use num::{ToPrimitive};

use plain;

pub type Plaintext = u64;

pub type Ciphertext = plain::Ciphertext;

#[derive(Debug,Clone)]
pub struct PublicKey {
    plain_ek: plain::PublicKey,
    component_count: usize,
    component_size: usize,  // in bits
}

#[derive(Debug,Clone)]
pub struct PrivateKey {
    plain_dk: plain::PrivateKey,
    component_count: usize,
    component_size: usize,  // in bits
}

impl PublicKey {
    pub fn from(modulus: &BigUint, component_count: usize, component_size: usize) -> PublicKey {
        PublicKey::from_plain(plain::PublicKey::from(modulus), component_count, component_size)
    }

    pub fn from_plain(plain_ek: plain::PublicKey, component_count: usize, component_size: usize) -> PublicKey {
        assert!(component_size * component_count <= plain_ek.n.bits());
        assert!(component_size <= 64);
        PublicKey {
            plain_ek: plain_ek,
            component_size: component_size,
            component_count: component_count,
        }
    }
}

impl PrivateKey {
    pub fn from(p: &BigUint, q: &BigUint, component_count: usize, component_size: usize) -> PrivateKey {
        PrivateKey::from_plain(plain::PrivateKey::from(p, q), component_count, component_size)
    }

    pub fn from_plain(plain_dk: plain::PrivateKey, component_count: usize, component_size: usize) -> PrivateKey {
        assert!(component_size <= 64);
        PrivateKey {
            plain_dk: plain_dk,
            component_size: component_size,
            component_count: component_count,
        }
    }
}

pub fn encrypt(ek: &PublicKey, ms: &[Plaintext]) -> Ciphertext {
    assert!(ms.len() == ek.component_count);
    let mut packed_plaintext = BigUint::from(ms[0]);
    for &m in &ms[1..] {
        packed_plaintext = packed_plaintext << ek.component_size;
        packed_plaintext = packed_plaintext + BigUint::from(m);
    }
    plain::encrypt(&ek.plain_ek, &packed_plaintext)
}

pub fn decrypt(dk: &PrivateKey, c: &Ciphertext) -> Vec<Plaintext> {
    let mut packed_plaintext = plain::decrypt(&dk.plain_dk, c);
    let mask = BigUint::from(1u64 << dk.component_size);
    let mut result = vec![];
    for _ in 0..dk.component_count {
        let slot_value = &packed_plaintext % &mask;
        packed_plaintext = &packed_plaintext >> dk.component_size;
        result.push(slot_value.to_u64().unwrap());
    }
    result.reverse();
    result
}

pub fn add(ek: &PublicKey, c1: &Ciphertext, c2: &Ciphertext) -> Ciphertext {
    plain::add(&ek.plain_ek, c1, c2)
}

pub fn mult(ek: &PublicKey, c1: &Ciphertext, m2: Plaintext) -> Ciphertext {
    let expanded_m2 = BigUint::from(m2);
    plain::mult(&ek.plain_ek, c1, &expanded_m2)
}

pub fn rerandomise(ek: &PublicKey, c: &Ciphertext) -> Ciphertext {
    plain::rerandomise(&ek.plain_ek, c)
}


#[cfg(test)]
mod tests {

    use super::*;

    fn key_pair() -> (PublicKey, PrivateKey) {
        use plain;
        let (plain_ek, plain_dk) = plain::fake_key_pair();
        let ek = PublicKey::from_plain(plain_ek, 3, 6);
        let dk = PrivateKey::from_plain(plain_dk, 3, 6);
        (ek, dk)
    }

    #[test]
    fn correct_encryption_decryption() {
        let (ek, dk) = key_pair();

        let m = &[1, 2, 3];
        let c = encrypt(&ek, m);

        let recovered_m = decrypt(&dk, &c);
        assert_eq!(recovered_m, m);
    }

    #[test]
    fn correct_addition() {
        let (ek, dk) = key_pair();

        let m1 = &[1, 2, 3];
        let c1 = encrypt(&ek, m1);

        let m2 = &[1, 2, 3];
        let c2 = encrypt(&ek, m2);

        let c = add(&ek, &c1, &c2);
        let m = decrypt(&dk, &c);
        assert_eq!(m, [2, 4, 6]);
    }

    #[test]
    fn correct_multiplication() {
        let (ek, dk) = key_pair();

        let m1 = &[1, 2, 3];
        let c1 = encrypt(&ek, m1);

        let m2 = 11;

        let c = mult(&ek, &c1, m2);
        let m = decrypt(&dk, &c);
        assert_eq!(m, [11, 22, 33]);
    }

}
