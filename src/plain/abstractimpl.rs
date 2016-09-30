
use phe::*;

#[derive(Debug,Clone)]
pub struct PlainEncryptionKey<I: Int> {
    pub n: I,  // the modulus
    nn: I,     // the modulus squared
    g: I,      // the generator, fixed at g = n + 1
}

impl<I: Int> PlainEncryptionKey<I> {
    pub fn from(modulus: I) -> PlainEncryptionKey<I> {
        PlainEncryptionKey {
            n: modulus.clone(),
            nn: modulus * &modulus,
            g: modulus + I::one()
        }
    }
}

#[derive(Debug,Clone)]
pub struct PlainDecryptionKey<I: Int>  {
    pub p: I,  // first prime
    pub q: I,  // second prime
    pub n: I,  // the modulus (also in public key)
    nn: I,     // the modulus squared
    lambda: I, // fixed at lambda = (p-1)*(q-1)
    mu: I,     // fixed at lambda^{-1}
}

impl<I: Int> PlainDecryptionKey<I> {
    pub fn from(p: I, q: I) -> PlainDecryptionKey<I> {
        let one = I::one();
        let modulus = p * &q;
        let nn = modulus * &modulus;
        let lambda = (p - one) * (q - one);
        let mu = I::modinv(&lambda, &modulus);
        PlainDecryptionKey {
            p: p.clone(),
            q: q.clone(),
            n: modulus,
            nn: nn,
            lambda: lambda,
            mu: mu,
        }
    }
}

pub struct AbstractPlainPaillier<I : Int> {
    junk: ::std::marker::PhantomData<I>
}

impl <I : Int + Samplable> PartiallyHomomorphicScheme for AbstractPlainPaillier<I> {

    type Plaintext = I;
    type Ciphertext = I;
    type EncryptionKey = PlainEncryptionKey<I>;
    type DecryptionKey = PlainDecryptionKey<I>;

    fn encrypt(ek: &Self::EncryptionKey, m: &Self::Plaintext) -> Self::Ciphertext {
        let ref gx = I::modpow(&ek.g, &m, &ek.nn);
        Self::rerandomise(ek, gx)
    }

    fn decrypt(dk: &Self::DecryptionKey, c: &Self::Ciphertext) -> Self::Plaintext {
        let ref u = I::modpow(&c, &dk.lambda, &dk.nn);
        ((u - I::one()) / &dk.n * &dk.mu) % &dk.n
    }

    fn add(ek: &Self::EncryptionKey, c1: &Self::Ciphertext, c2: &Self::Ciphertext) -> Self::Ciphertext {
        (c1 * c2) % &ek.nn
    }

    fn mult(ek: &Self::EncryptionKey, c1: &Self::Ciphertext, m2: &Self::Plaintext) -> Self::Ciphertext {
        I::modpow(c1, m2, &ek.nn)
    }

    fn rerandomise(ek: &Self::EncryptionKey, c: &Self::Ciphertext) -> Self::Ciphertext {
        let ref r = I::sample(&ek.n);
        (c * I::modpow(r, &ek.n, &ek.nn)) % &ek.nn
    }

}

#[cfg(feature="keygen")]
impl <I : Int + From<u64>> KeyGeneration for AbstractPlainPaillier<I> {

    type EncryptionKey = PlainEncryptionKey<I>;
    type DecryptionKey = PlainDecryptionKey<I>;

    fn keypair(bit_length: usize) -> (Self::EncryptionKey, Self::DecryptionKey) {
        let p = I::from(1061u64);
        let q = I::from(1063u64);
        let n = &p * &q;
        let ek = PlainEncryptionKey::from(n);
        let dk = PlainDecryptionKey::from(p, q);
        (ek, dk)
    }

    // fn keypair(bit_length: usize) -> (Self::EncryptionKey, Self::DecryptionKey) {
    //     let p = str::parse("148677972634832330983979593310074301486537017973460461278300587514468301043894574906886127642530475786889672304776052879927627556769456140664043088700743909632312483413393134504352834240399191134336344285483935856491230340093391784574980688823380828143810804684752914935441384845195613674104960646037368551517").unwrap();
    //     let q = str::parse("158741574437007245654463598139927898730476924736461654463975966787719309357536545869203069369466212089132653564188443272208127277664424448947476335413293018778018615899291704693105620242763173357203898195318179150836424196645745308205164116144020613415407736216097185962171301808761138424668335445923774195463").unwrap();
    //     let n = &p * &q;
    //     let ek = PlainEncryptionKey::from(&n);
    //     let dk = PlainDecryptionKey::from(&p, &q);
    //     (ek, dk)
    // }


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

}
