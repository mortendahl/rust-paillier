
mod abstractimpl;
use self::abstractimpl::AbstractPackedPaillier;

use super::PlainPaillier;
pub type PackedPaillier = AbstractPackedPaillier<u64, PlainPaillier>;
