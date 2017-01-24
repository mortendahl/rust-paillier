
//! Variout coding schemes to be used in conjuction with the core Paillier encryption scheme.

mod packing;
pub mod integral;

use super::*;
use self::packing::*;

/// Associating a key with a code.
pub trait WithCode<'k, 'c, K, C> {
    /// Return key combined with code.
    fn with_code(&'k self, code: &'c C) -> K;
}

/// Encryption key with associated encoder.
pub struct EncodingEncryptionKey<'ek, 'e, EK: 'ek, E: 'e> {
    key: &'ek EK,
    encoder: &'e E,
}

impl<'ek, 'e, EK: 'ek, E: 'e> ::traits::EncryptionKey for EncodingEncryptionKey<'ek, 'e, EK, E> {}

/// Decryption key with associated decoder.
pub struct DecodingDecryptionKey<'dk, 'd, DK: 'dk, D: 'd> {
    key: &'dk DK,
    decoder: &'d D,
}

impl<'dk, 'd, DK: 'dk, D: 'd> ::traits::DecryptionKey for DecodingDecryptionKey<'dk, 'd, DK, D> {}

impl<'a, 'b, EK, E> WithCode<'a, 'b, EncodingEncryptionKey<'a, 'b, EK, E>, E> for EK
where
    EK: ::traits::EncryptionKey
{
    fn with_code(&'a self, code: &'b E) -> EncodingEncryptionKey<'a, 'b, EK, E> {
        EncodingEncryptionKey {
            key: self,
            encoder: code
        }
    }
}

impl<'a, 'b, DK, D> WithCode<'a, 'b, DecodingDecryptionKey<'a, 'b, DK, D>, D> for DK
where
    DK: ::traits::DecryptionKey
{
    fn with_code(&'a self, code: &'b D) -> DecodingDecryptionKey<'a, 'b, DK, D> {
        DecodingDecryptionKey {
            key: self,
            decoder: code
        }
    }
}


impl<'a, 'b, E: 'b, M, CT, S, EK: 'a> Encryption<EncodingEncryptionKey<'a, 'b, EK, E>, M, CT> for S
where
    M : EncodableType,
    E : Encoder<M>,
    S : Encryption<EK, E::Target, CT>,
{
    fn encrypt(ek: &EncodingEncryptionKey<EK, E>, m: &M) -> CT {
        S::encrypt(ek.key, &ek.encoder.encode(m))
    }
}


impl<'a, 'b, D: 'b, M, CT, S, DK: 'a> Decryption<DecodingDecryptionKey<'a, 'b, DK, D>, CT, M> for S
where
    M : EncodableType,
    D : Decoder<M>,
    S : Decryption<DK, CT, D::Source>,
{
    fn decrypt(dk: &DecodingDecryptionKey<DK, D>, c: &CT) -> M {
        dk.decoder.decode(&S::decrypt(dk.key, c))
    }
}


impl<'a, 'b, E, EK: 'a, I, S> Addition<EncodingEncryptionKey<'a, 'b, EK, E>, core::Ciphertext<I>, core::Ciphertext<I>, core::Ciphertext<I>> for S
where
    S : Addition<EK, core::Ciphertext<I>, core::Ciphertext<I>, core::Ciphertext<I>>,
{
    fn add(ek: &EncodingEncryptionKey<EK, E>, c1: &core::Ciphertext<I>, c2: &core::Ciphertext<I>) -> core::Ciphertext<I> {
        S::add(ek.key, c1, c2)
    }
}


impl<'a, 'b, E, M, EK: 'a, CT, S> Addition<EncodingEncryptionKey<'a, 'b, EK, E>, CT, M, CT> for S
where
    M : EncodableType,
    E : Encoder<M>,
    S : Encryption<EK, E::Target, CT>,
    S : Addition<EK, CT, CT, CT>,
{
    fn add(ek: &EncodingEncryptionKey<'a, 'b, EK, E>, c1: &CT, m2: &M) -> CT {
        let ref p2 = ek.encoder.encode(m2);
        let ref c2 = S::encrypt(&ek.key, p2);
        S::add(ek.key, c1, c2)
    }
}


impl<'a, 'b, E, M: 'b, CT, S, EK: 'a> Multiplication<EncodingEncryptionKey<'a, 'b, EK, E>, CT, M, CT> for S
where
    M : EncodableType,
    E : Encoder<M>,
    S : Multiplication<EK, CT, E::Target, CT>,
{
    fn mul(ek: &EncodingEncryptionKey<EK, E>, c1: &CT, m2: &M) -> CT {
        let ref p2 = ek.encoder.encode(m2);
        S::mul(ek.key, c1, p2)
    }
}
