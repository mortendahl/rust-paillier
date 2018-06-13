
use ::BigInteger as BigInt;
use ::Paillier as Paillier;

pub struct CorrectOpeningProof {
    m: BigInt,
    r: BigInt,
}

/// Correct opening of ciphertext.
pub trait CorrectOpening<EK, DK, CT, PT, R> {
    fn prove(dk: &DK, c: CT) -> CorrectOpeningProof;
    fn verify(ek: &EK, c: CT, m: PT, r: R) -> bool;
}

// impl<C> ProveCorrectDecrypt for Paillier {
//     fn verify(ek: &EK, c: &C, proof: &CorrectDecryptProof) -> bool {
//         Self::encrypt(ek, &proof.m, &proof.r) 
//     }
// }
