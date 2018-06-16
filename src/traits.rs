//! Abstract operations exposed by the library.

/// Secure generation of fresh key pairs.
pub trait KeyGeneration<KP>
{
    /// Generate fresh key pair with currently recommended security level (2048 bit modulus).
    fn keypair() -> KP {
        Self::keypair_with_modulus_size(2048)
    }

    /// Generate fresh key pair with security level specified as the `bit_length` of the modulus.
    ///
    /// Currently recommended security level is a minimum of 2048 bits.
    fn keypair_with_modulus_size(big_length: usize) -> KP;
}

/// Generate default encryption and decryption keys.
pub trait DefaultKeys {

    /// Type of encryption key generated.
    type EK;

    /// Type of decryption key generated.
    type DK;

    /// Generate default encryption key.
    fn encryption_key(&self) -> Self::EK;

    /// Generate default decryption key.
    fn decryption_key(&self) -> Self::DK;

    /// Generate default encryption and decryption keys.
    fn keys(&self) -> (Self::EK, Self::DK) {
        (self.encryption_key(), self.decryption_key())
    }
}

pub trait PrecomputeRandomness<EK, R, PR> {
    fn precompute(ek: EK, r: R) -> PR;
}

/// Encryption of plaintext.
pub trait Encrypt<EK, PT, CT> {
    /// Encrypt plaintext `m` under key `ek` into a ciphertext.
    fn encrypt(ek: &EK, m: PT) -> CT;
}

pub trait EncryptWithChosenRandomness<EK, PT, R, CT> {
    fn encrypt_with_chosen_randomness(ek: &EK, m: PT, r: R) -> CT;
}

/// Decryption of ciphertext.
pub trait Decrypt<DK, CT, PT> {
    /// Decrypt ciphertext `c` using key `dk` into a plaintext.
    fn decrypt(ek: &DK, c: CT) -> PT;
}

/// Opening of ciphertext.
///
/// Unlike decryption this also returns the randomness used.
pub trait Open<DK, CT, PT, R> {
    /// Open ciphertext `c` using key `dk` into a plaintext and a randomness.
    fn open(dk: &DK, c: CT) -> (PT, R);
}

/// Addition of two ciphertexts.
pub trait Add<EK, CT1, CT2, CT> {
    /// Homomorphically combine ciphertexts `c1` and `c2` to obtain a ciphertext containing
    /// the sum of the two underlying plaintexts, reduced modulus `n` from `ek`.
    fn add(ek: &EK, c1: CT1, c2: CT2) -> CT;
}

/// Multiplication of ciphertext with plaintext.
pub trait Mul<EK, CT1, PT2, CT> {
    /// Homomorphically combine ciphertext `c1` and plaintext `m2` to obtain a ciphertext
    /// containing the multiplication of the (underlying) plaintexts, reduced modulus `n` from `ek`.
    fn mul(ek: &EK, c1: CT1, m2: PT2) -> CT;
}

/// Rerandomisation of ciphertext.
pub trait Rerandomize<EK, CT1, CT> {
    /// Rerandomise ciphertext `c` to hide any history of which homomorphic operations were
    /// used to compute it, making it look exactly like a fresh encryption of the same plaintext.
    fn rerandomise(ek: &EK, c: CT1) -> CT;
}
