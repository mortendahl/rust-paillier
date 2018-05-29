//! Various coding schemes to be used in conjunction with the core Paillier encryption scheme.

pub mod integral;
use ::BigInteger as BigInt;
use arithimpl::traits::ConvertFrom;

use super::*;

pub fn pack<T>(components: &Vec<T>, component_count: usize, component_size: usize) -> BigInt
where T: Clone, BigInt: From<T>
{
    assert!(components.len() == component_count);
    let mut packed = BigInt::from(components[0].clone());
    for component in &components[1..] {
        packed = packed << component_size;
        packed = packed + BigInt::from(component.clone());
    }
    packed
}

pub fn unpack<T>(mut packed_components: BigInt, component_count: usize, component_size: usize) -> Vec<T>
where T: ConvertFrom<BigInt>
{
    let mask = BigInt::one() << component_size;
    let mut components: Vec<T> = vec![];
    for _ in 0..component_count {
        let raw_component = &packed_components % &mask;  // TODO replace with bitwise AND
        let component = T::_from(&raw_component);
        components.push(component);
        packed_components = &packed_components >> component_size;
    }
    components.reverse();
    components
}

// /// Associating a key with a code.
// pub trait WithCode<'k, 'c, K, C> {
//     /// Return key combined with code.
//     fn with_code(&'k self, code: &'c C) -> K;
// }

// /// Encryption key with associated encoder.
// pub struct EncodingEncryptionKey<'ek, 'e, EK: 'ek, E: 'e> {
//     key: &'ek EK,
//     encoder: &'e E,
// }

// // impl<'ek, 'e, EK: 'ek, E: 'e> ::traits::EncryptionKey for EncodingEncryptionKey<'ek, 'e, EK, E> {}

// /// Decryption key with associated decoder.
// pub struct DecodingDecryptionKey<'dk, 'd, DK: 'dk, D: 'd> {
//     key: &'dk DK,
//     decoder: &'d D,
// }

// // impl<'dk, 'd, DK: 'dk, D: 'd> ::traits::DecryptionKey for DecodingDecryptionKey<'dk, 'd, DK, D> {}

// impl<'a, 'b, EK, E> WithCode<'a, 'b, EncodingEncryptionKey<'a, 'b, EK, E>, E> for EK
// where
//     EK: ::traits::EncryptionKey
// {
//     fn with_code(&'a self, code: &'b E) -> EncodingEncryptionKey<'a, 'b, EK, E> {
//         EncodingEncryptionKey {
//             key: self,
//             encoder: code
//         }
//     }
// }

// impl<'a, 'b, DK, D> WithCode<'a, 'b, DecodingDecryptionKey<'a, 'b, DK, D>, D> for DK
// where
//     DK: ::traits::DecryptionKey
// {
//     fn with_code(&'a self, code: &'b D) -> DecodingDecryptionKey<'a, 'b, DK, D> {
//         DecodingDecryptionKey {
//             key: self,
//             decoder: code
//         }
//     }
// }


// impl<'a, 'b, E: 'b, M, CT, S, EK: 'a> Encryption<EncodingEncryptionKey<'a, 'b, EK, E>, M, CT> for S
// where
//     M : EncodableType,
//     E : Encoder<M>,
//     S : Encryption<EK, E::Target, CT>,
// {
//     fn encrypt(ek: &EncodingEncryptionKey<EK, E>, m: &M) -> CT {
//         S::encrypt(ek.key, &ek.encoder.encode(m))
//     }
// }


// impl<'a, 'b, D: 'b, M, CT, S, DK: 'a> Decryption<DecodingDecryptionKey<'a, 'b, DK, D>, CT, M> for S
// where
//     M : EncodableType,
//     D : Decoder<M>,
//     S : Decryption<DK, CT, D::Source>,
// {
//     fn decrypt(dk: &DecodingDecryptionKey<DK, D>, c: &CT) -> M {
//         dk.decoder.decode(&S::decrypt(dk.key, c))
//     }
// }


// impl<'a, 'b, E, EK: 'a, S> Addition<EncodingEncryptionKey<'a, 'b, EK, E>, core::Ciphertext, core::Ciphertext, core::Ciphertext> for S
// where
//     S : Addition<EK, core::Ciphertext, core::Ciphertext, core::Ciphertext>,
// {
//     fn add(ek: &EncodingEncryptionKey<EK, E>, c1: &core::Ciphertext, c2: &core::Ciphertext) -> core::Ciphertext {
//         S::add(ek.key, c1, c2)
//     }
// }


// impl<'a, 'b, E, M, EK: 'a, CT, S> Addition<EncodingEncryptionKey<'a, 'b, EK, E>, CT, M, CT> for S
// where
//     M : EncodableType,
//     E : Encoder<M>,
//     S : Encryption<EK, E::Target, CT>,
//     S : Addition<EK, CT, CT, CT>,
// {
//     fn add(ek: &EncodingEncryptionKey<'a, 'b, EK, E>, c1: &CT, m2: &M) -> CT {
//         let ref p2 = ek.encoder.encode(m2);
//         let ref c2 = S::encrypt(&ek.key, p2);
//         S::add(ek.key, c1, c2)
//     }
// }


// maybe this could work if we didn't parameterise over S but stuck to a concrete type instead
// impl<'a, 'b, E, M, EK: 'a, CT, S> Addition<EncodingEncryptionKey<'a, 'b, EK, E>, M, CT, CT> for S
// where
//     M : EncodableType,
//     E : Encoder<M>,
//     S : Encryption<EK, E::Target, CT>,
//     S : Addition<EK, CT, CT, CT>,
// {
//     fn add(ek: &EncodingEncryptionKey<'a, 'b, EK, E>, c1: &CT, m2: &M) -> CT {
//         let ref p2 = ek.encoder.encode(m2);
//         let ref c2 = S::encrypt(&ek.key, p2);
//         S::add(ek.key, c1, c2)
//     }
// }


// impl<'a, 'b, E, M: 'b, CT, S, EK: 'a> Multiplication<EncodingEncryptionKey<'a, 'b, EK, E>, CT, M, CT> for S
// where
//     M : EncodableType,
//     E : Encoder<M>,
//     S : Multiplication<EK, CT, E::Target, CT>,
// {
//     fn mul(ek: &EncodingEncryptionKey<EK, E>, c1: &CT, m2: &M) -> CT {
//         let ref p2 = ek.encoder.encode(m2);
//         S::mul(ek.key, c1, p2)
//     }
// }
