
use ::BigInteger as BigInt;
use ::Paillier as Paillier;

/// Correct opening of ciphertext.
pub trait CorrectOpening<EK, DK, CT, PT, R> {
    fn prove(dk: &DK, c: CT) -> (PT, R);
    fn verify(ek: &EK, c: CT, m: PT, r: R) -> bool;
}

pub struct CorrectDecryptProof {
    m: BigInt,
    r: BigInt,
}

// pub trait ProveCorrectDecrypt<EK, C> {
//     fn verify(ek: &EK, c: &C, proof: &CorrectDecryptProof) -> bool;
// }

// impl<C> ProveCorrectDecrypt for Paillier {
//     fn verify(ek: &EK, c: &C, proof: &CorrectDecryptProof) -> bool {
//         Self::encrypt(ek, &proof.m, &proof.r) 
//     }
// }
