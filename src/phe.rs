
pub trait PartiallyHomomorphicScheme {
    type Plaintext;
    type Ciphertext;
    type EncryptionKey;
    type DecryptionKey;
    fn encrypt(&Self::EncryptionKey, &Self::Plaintext) -> Self::Ciphertext;
    fn decrypt(&Self::DecryptionKey, &Self::Ciphertext) -> Self::Plaintext;
    fn rerandomise(&Self::EncryptionKey, &Self::Ciphertext) -> Self::Ciphertext;
    fn add(&Self::EncryptionKey, &Self::Ciphertext, &Self::Ciphertext) -> Self::Ciphertext;
    fn mult(&Self::EncryptionKey, &Self::Ciphertext, &Self::Plaintext) -> Self::Ciphertext;
}

pub trait KeyGeneration {
    type EncryptionKey;
    type DecryptionKey;
    fn keypair(bit_length: usize) -> (Self::EncryptionKey, Self::DecryptionKey);
}
