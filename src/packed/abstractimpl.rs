
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

pub struct AbstractPackedPaillier<BasePHE : PHE> {
    junk: ::std::marker::PhantomData<BasePHE>
}

pub struct PackedPlaintext(Vec<usize>);

impl From<usize> for PackedPlaintext {
    fn from(x: usize) -> Self {
        PackedPlaintext(vec![x])
    }
}

use std::ops::{Add, Shl, Shr, Rem};
impl <BasePHE : PHE> PHE for AbstractPackedPaillier<BasePHE>
where
    BasePHE::Plaintext: From<usize> + Into<usize>,
    BasePHE::Plaintext: Shl<usize, Output=BasePHE::Plaintext>,
    BasePHE::Plaintext: Shr<usize, Output=BasePHE::Plaintext>,
    for<'a> &'a BasePHE::Plaintext: Shr<usize, Output=BasePHE::Plaintext>,
    BasePHE::Plaintext: Add<Output=BasePHE::Plaintext>,
    BasePHE::Plaintext: Rem<Output=BasePHE::Plaintext>,
    for<'a, 'b> &'a BasePHE::Plaintext: Rem<&'b BasePHE::Plaintext, Output=BasePHE::Plaintext>
{

    type Plaintext = PackedPlaintext;
    type Ciphertext = BasePHE::Ciphertext;
    type EncryptionKey = PackedEncryptionKey<BasePHE>;
    type DecryptionKey = PackedDecryptionKey<BasePHE>;

    fn encrypt(ek: &Self::EncryptionKey, ms: &Self::Plaintext) -> Self::Ciphertext {
        assert!(ms.0.len() == ek.component_count);
        let mut packed_plaintext = BasePHE::Plaintext::from(ms.0[0]);
        for &m in &ms.0[1..] {
            packed_plaintext = packed_plaintext << ek.component_size;
            packed_plaintext = packed_plaintext + BasePHE::Plaintext::from(m);
        }
        BasePHE::encrypt(&ek.underlying_ek, &packed_plaintext)
    }

    fn decrypt(dk: &Self::DecryptionKey, c: &Self::Ciphertext) -> Self::Plaintext {
        let mut packed_plaintext = BasePHE::decrypt(&dk.underlying_dk, c);
        let mask = BasePHE::Plaintext::from(1usize << dk.component_size);
        let mut result = vec![];
        for _ in 0..dk.component_count {
            let slot_value = &packed_plaintext % &mask;
            packed_plaintext = &packed_plaintext >> dk.component_size;
            result.push(slot_value.into());
        }
        result.reverse();
        PackedPlaintext(result)
    }

    fn add(ek: &Self::EncryptionKey, c1: &Self::Ciphertext, c2: &Self::Ciphertext) -> Self::Ciphertext {
        BasePHE::add(&ek.underlying_ek, c1, c2)
    }

    fn mult(ek: &Self::EncryptionKey, c1: &Self::Ciphertext, m2: &Self::Plaintext) -> Self::Ciphertext {
        let ref expanded_m2 = BasePHE::Plaintext::from(m2.0[0]); // TODO have separate type for scalar?
        BasePHE::mult(&ek.underlying_ek, c1, expanded_m2)
    }

    fn rerandomise(ek: &Self::EncryptionKey, c: &Self::Ciphertext) -> Self::Ciphertext {
        BasePHE::rerandomise(&ek.underlying_ek, c)
    }

}
