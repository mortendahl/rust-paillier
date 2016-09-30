
// mod tests;

mod abstractimpl;
pub use self::abstractimpl::AbstractPackedPaillier;

use super::PlainPaillier;
pub type PackedPaillier = AbstractPackedPaillier<PlainPaillier>;
