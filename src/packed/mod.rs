
use phe::PartiallyHomomorphicScheme as PHE;

#[derive(Debug,Clone)]
pub struct PackedEncryptionKey<UnderlyingScheme : PHE> {
    underlying_ek: UnderlyingScheme::EncryptionKey,
    component_count: usize,
    component_size: usize,  // in bits
}

impl<UnderlyingScheme: PHE> PackedEncryptionKey<UnderlyingScheme> {
    pub fn from(underlying_ek: UnderlyingScheme::EncryptionKey, component_count: usize, component_size: usize) -> PackedEncryptionKey<UnderlyingScheme> {
        // assert!(component_size * component_count <= plain_ek.n.bits());
        // assert!(component_size * component_count <= underlying_ek.n.bit_length() as usize); // TODO
        assert!(component_size <= 64);
        PackedEncryptionKey {
            underlying_ek: underlying_ek,
            component_size: component_size,
            component_count: component_count,
        }
    }
}

#[derive(Debug,Clone)]
pub struct PackedDecryptionKey<UnderlyingScheme : PHE> {
    underlying_dk: UnderlyingScheme::DecryptionKey,
    component_count: usize,
    component_size: usize,  // in bits
}

impl<UnderlyingScheme: PHE> PackedDecryptionKey<UnderlyingScheme> {
    pub fn from(underlying_dk: UnderlyingScheme::DecryptionKey, component_count: usize, component_size: usize) -> PackedDecryptionKey<UnderlyingScheme> {
        assert!(component_size <= 64);
        PackedDecryptionKey {
            underlying_dk: underlying_dk,
            component_size: component_size,
            component_count: component_count,
        }
    }
}

pub struct AbstractPackedPaillier<T, BasePHE : PHE> {
    junk: ::std::marker::PhantomData<(T, BasePHE)>
}

#[derive(Debug,Clone,PartialEq)]
pub struct PackedPlaintext<ComponentType>(Vec<ComponentType>);

impl <T : Clone> From<T> for PackedPlaintext<T> {
    fn from(x: T) -> Self {
        PackedPlaintext(vec![x.clone()])
    }
}

impl <T : Clone> From<Vec<T>> for PackedPlaintext<T> {
    fn from(x: Vec<T>) -> Self {
        PackedPlaintext(x.clone())
    }
}

use std::ops::{Add, Shl, Shr, Rem};
use num_traits::{One};
use arithimpl::traits::*;
impl <ComponentType, BasePHE> PHE for AbstractPackedPaillier<ComponentType, BasePHE>
where
    // regarding ComponentType
    ComponentType: Clone,
    ComponentType: One,
    ComponentType: Shl<usize, Output=ComponentType>,
    for<'b> ComponentType: ConvertFrom<BasePHE::Plaintext>,
    // regarding BasePHE
    BasePHE: PHE,
    BasePHE::Plaintext: From<ComponentType>,
    BasePHE::Plaintext: Shl<usize, Output=BasePHE::Plaintext>,
    // BasePHE::Plaintext: ShlAssign<usize>,
    BasePHE::Plaintext: Shr<usize, Output=BasePHE::Plaintext>,
    for<'a> &'a BasePHE::Plaintext: Shr<usize, Output=BasePHE::Plaintext>,
    BasePHE::Plaintext: Add<Output=BasePHE::Plaintext>,
    BasePHE::Plaintext: Rem<Output=BasePHE::Plaintext>,
    for<'a,'b> &'a BasePHE::Plaintext: Rem<&'b BasePHE::Plaintext, Output=BasePHE::Plaintext>
{

    type Plaintext = PackedPlaintext<ComponentType>;
    type Ciphertext = BasePHE::Ciphertext;
    type EncryptionKey = PackedEncryptionKey<BasePHE>;
    type DecryptionKey = PackedDecryptionKey<BasePHE>;

    fn encrypt(ek: &Self::EncryptionKey, ms: &Self::Plaintext) -> Self::Ciphertext {
        assert!(ms.0.len() == ek.component_count);
        let mut packed_plaintext = BasePHE::Plaintext::from(ms.0[0].clone());
        for m in &ms.0[1..] {
            packed_plaintext = packed_plaintext << ek.component_size;
            packed_plaintext = packed_plaintext + BasePHE::Plaintext::from(m.clone());
        }
        BasePHE::encrypt(&ek.underlying_ek, &packed_plaintext)
    }

    fn decrypt(dk: &Self::DecryptionKey, c: &Self::Ciphertext) -> Self::Plaintext {
        let mut packed_plaintext = BasePHE::decrypt(&dk.underlying_dk, c);
        let raw_mask = ComponentType::one() << dk.component_size;
        let mask = BasePHE::Plaintext::from(raw_mask);
        let mut result = vec![];
        for _ in 0..dk.component_count {
            let slot_value = &packed_plaintext % &mask;
            let foo = ComponentType::_from(&slot_value);
            result.push(foo);
            packed_plaintext = &packed_plaintext >> dk.component_size;
        }
        result.reverse();
        PackedPlaintext(result)
    }

    fn add(ek: &Self::EncryptionKey, c1: &Self::Ciphertext, c2: &Self::Ciphertext) -> Self::Ciphertext {
        BasePHE::add(&ek.underlying_ek, c1, c2)
    }

    fn mult(ek: &Self::EncryptionKey, c1: &Self::Ciphertext, m2: &Self::Plaintext) -> Self::Ciphertext {
        let ref expanded_m2 = BasePHE::Plaintext::from(m2.0[0].clone()); // TODO have separate type for scalar?
        BasePHE::mult(&ek.underlying_ek, c1, expanded_m2)
    }

    fn rerandomise(ek: &Self::EncryptionKey, c: &Self::Ciphertext) -> Self::Ciphertext {
        BasePHE::rerandomise(&ek.underlying_ek, c)
    }

}

#[cfg(test)]
mod tests {

    use PlainPaillier;
    use PackedPaillier;
    use phe::PartiallyHomomorphicScheme as PHE;

    fn test_keypair() -> (<PackedPaillier as PHE>::EncryptionKey, <PackedPaillier as PHE>::DecryptionKey) {
        //1024 bits prime
        let p = str::parse("148677972634832330983979593310074301486537017973460461278300587514468301043894574906886127642530475786889672304776052879927627556769456140664043088700743909632312483413393134504352834240399191134336344285483935856491230340093391784574980688823380828143810804684752914935441384845195613674104960646037368551517").unwrap();
        let q = str::parse("158741574437007245654463598139927898730476924736461654463975966787719309357536545869203069369466212089132653564188443272208127277664424448947476335413293018778018615899291704693105620242763173357203898195318179150836424196645745308205164116144020613415407736216097185962171301808761138424668335445923774195463").unwrap();
        
        let n = &p * &q;
        let plain_ek = <PlainPaillier as PHE>::EncryptionKey::from(&n);
        let plain_dk = <PlainPaillier as PHE>::DecryptionKey::from(&p, &q);

        let ek = <PackedPaillier as PHE>::EncryptionKey::from(plain_ek, 3, 10);
        let dk = <PackedPaillier as PHE>::DecryptionKey::from(plain_dk, 3, 10);
        (ek, dk)
    }

    #[test]
    fn test_correct_encryption_decryption() {
        let (ek, dk) = test_keypair();

        let m = <PackedPaillier as PHE>::Plaintext::from(vec![1, 2, 3]);
        let c = PackedPaillier::encrypt(&ek, &m);

        let recovered_m = PackedPaillier::decrypt(&dk, &c);
        assert_eq!(recovered_m, m);
    }

    #[test]
    fn test_correct_addition() {
        let (ek, dk) = test_keypair();

        let m1 = <PackedPaillier as PHE>::Plaintext::from(vec![1, 2, 3]);
        let c1 = PackedPaillier::encrypt(&ek, &m1);
        let m2 = <PackedPaillier as PHE>::Plaintext::from(vec![1, 2, 3]);
        let c2 = PackedPaillier::encrypt(&ek, &m2);

        let c = PackedPaillier::add(&ek, &c1, &c2);
        let m = PackedPaillier::decrypt(&dk, &c);
        assert_eq!(m.0, vec![2, 4, 6]);
    }

    #[test]
    fn test_correct_multiplication() {
        let (ek, dk) = test_keypair();

        let m1 = <PackedPaillier as PHE>::Plaintext::from(vec![1, 2, 3]);
        let c1 = PackedPaillier::encrypt(&ek, &m1);
        let m2 = <PackedPaillier as PHE>::Plaintext::from(vec![4]);

        let c = PackedPaillier::mult(&ek, &c1, &m2);
        let m = PackedPaillier::decrypt(&dk, &c);
        assert_eq!(m.0, vec![4, 8, 12]);
    }

}
