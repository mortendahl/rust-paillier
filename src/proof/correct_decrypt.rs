
use ::BigInteger as BigInt;
use ::Paillier as Paillier;

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