use traits::*;
use Paillier;
use {EncryptionKey, RawPlaintext};

/// Verify correct opening of ciphertext.
pub trait CorrectOpening<EK, PT, R, CT> {
    fn verify_opening(ek: &EK, m: PT, r: R, c: CT) -> bool;
}

impl<'m, 'r, 'c, R, CT> CorrectOpening<EncryptionKey, RawPlaintext<'m>, &'r R, &'c CT> for Paillier
where
    Self: EncryptWithChosenRandomness<EncryptionKey, RawPlaintext<'m>, &'r R, CT>,
    CT: PartialEq,
{
    fn verify_opening(ek: &EncryptionKey, m: RawPlaintext<'m>, r: &'r R, c: &'c CT) -> bool {
        let d = Self::encrypt_with_chosen_randomness(ek, m, r);
        c == &d
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use {BigInt, Keypair};

    fn test_keypair() -> Keypair {
        let p = str::parse("148677972634832330983979593310074301486537017973460461278300587514468301043894574906886127642530475786889672304776052879927627556769456140664043088700743909632312483413393134504352834240399191134336344285483935856491230340093391784574980688823380828143810804684752914935441384845195613674104960646037368551517").unwrap();
        let q = str::parse("158741574437007245654463598139927898730476924736461654463975966787719309357536545869203069369466212089132653564188443272208127277664424448947476335413293018778018615899291704693105620242763173357203898195318179150836424196645745308205164116144020613415407736216097185962171301808761138424668335445923774195463").unwrap();
        Keypair { p, q }
    }

    #[test]
    fn test_verify() {
        let (ek, dk) = test_keypair().keys();

        let c = Paillier::encrypt(&ek, RawPlaintext::from(BigInt::from(10)));
        let (m, r) = Paillier::open(&dk, &c);

        assert!(Paillier::verify_opening(&ek, m, &r, &c));
    }
}
