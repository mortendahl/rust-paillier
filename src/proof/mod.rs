mod correct_opening;
pub use self::correct_opening::CorrectOpening;

pub use self::correct_key::Challenge;
pub use self::correct_key::CorrectKeyProof;
pub use self::correct_key::CorrectKeyProofError;
pub use self::correct_key::VerificationAid;
mod correct_key;
pub use self::correct_key::CorrectKey;

mod range_proof;
pub use self::range_proof::RangeProof;

pub use self::range_proof::ChallengeBits;
pub use self::range_proof::EncryptedPairs;
pub use self::range_proof::Proof;
mod range_proof_ni;
pub use self::range_proof_ni::RangeProofNI;

use crypto::digest::Digest;
use crypto::sha2::Sha256;
use hex::decode;

use std::borrow::Borrow;
use BigInt;

pub fn compute_digest<IT>(it: IT) -> BigInt
where
    IT: Iterator,
    IT::Item: Borrow<BigInt>,
{
    let mut hasher = Sha256::new();
    for value in it {
        let bytes: Vec<u8> = value.borrow().into();
        hasher.input(&bytes);
    }

    let result_string = hasher.result_str();

    let result_bytes = decode(result_string).unwrap();

    BigInt::from(&result_bytes[..])
}
