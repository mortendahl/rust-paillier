
//! Abstract operations exposed by the library.

/// Marker trait for the Paillier scheme.
pub trait AbstractScheme
{
    /// Underlying arbitrary precision arithmetic type.
    type BigInteger;
}

/// Secure generation of fresh key pairs.
pub trait KeyGeneration<EK, DK>
{
    /// Generate fresh key pair with currently recommended security level (2048 bit modulus).
    fn keypair() -> (EK, DK) {
        Self::keypair_with_modulus_size(2048)
    }

    /// Generate fresh key pair with security level specified as the `bit_length` of the modulus.
    ///
    /// Currently recommended security level is a minimum of 2048 bits.
    fn keypair_with_modulus_size(big_length: usize) -> (EK, DK);
}

/// Marker trait for encryption keys.
pub trait EncryptionKey {}

/// Marker trait for decryption keys.
pub trait DecryptionKey {}

/// Encryption of plaintext.
pub trait Encryption<EK, PT, CT> {
    /// Encrypt plaintext `m` under key `ek` into a ciphertext.
    fn encrypt(ek: &EK, m: &PT) -> CT;
}

/// Decryption of ciphertext.
pub trait Decryption<DK, CT, PT> {
    /// Decrypt ciphertext `c` using key `dk` into a plaintext.
    fn decrypt(ek: &DK, c: &CT) -> PT;
}

/// Addition of two ciphertexts.
pub trait Addition<EK, CT1, CT2, CT> {
    /// Homomorphically combine ciphertexts `c1` and `c2` to obtain a ciphertext containing
    /// the sum of the two underlying plaintexts, reduced modulus `n` from `ek`.
    fn add(ek: &EK, c1: &CT1, c2: &CT2) -> CT;
}

/// Multiplication of ciphertext with plaintext.
pub trait Multiplication<EK, CT1, PT2, CT> {
    /// Homomorphically combine ciphertext `c1` and plaintext `m2` to obtain a ciphertext
    /// containing the multiplication of the (underlying) plaintexts, reduced modulus `n` from `ek`.
    fn mul(ek: &EK, c1: &CT1, m2: &PT2) -> CT;
}

/// Rerandomisation of ciphertext.
pub trait Rerandomisation<EK, CT> {
    /// Rerandomise ciphertext `c` to hide any history of which homomorphic operations were
    /// used to compute it, making it look exactly like a fresh encryption of the same plaintext.
    fn rerandomise(ek: &EK, c: &CT) -> CT;
}

/// Marker trait to avoid conflicting implementations.
// Future support for negative traits could void this.
pub trait EncodableType {}
// Heuristics for what constitutes an encodable type:
// impl<T: Into<u64>> EncodableType for T {}
impl<T: Into<u64>> EncodableType for Vec<T> {}
// impl EncodableType for usize {}
// impl EncodableType for u8 {}
// impl EncodableType for u16 {}
// impl EncodableType for u32 {}
impl EncodableType for u64 {}

/// Encoding into plaintexts.
pub trait Encoder<T>
{
    type Target;

    /// Encode `T` types into `Target` types.
    fn encode(&self, x: &T) -> Self::Target;
}

/// Decoding from plaintexts.
pub trait Decoder<T>
{
    type Source;

    /// Decode `Source` types into `T` types.
    fn decode(&self, y: &Self::Source) -> T;
}
