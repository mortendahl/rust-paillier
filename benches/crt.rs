#[macro_use]
extern crate bencher;
extern crate paillier;
extern crate num_traits;

macro_rules! scheme {
    ( $s:ident, $m:ident, $g:ident, $body:item ) => {

        use bencher::Bencher;
        use paillier::*;

        #[cfg(feature="inclramp")]
        pub mod ramp {
            #[allow(dead_code)]
            type $s = ::RampPaillier;
            $body
        }

        #[cfg(feature="inclgmp")]
        pub mod gmp {
            #[allow(dead_code)]
            type $s = ::GmpPaillier;
            $body
        }

        #[cfg(feature="inclnum")]
        pub mod num {
            #[allow(dead_code)]
            type $s = ::NumPaillier;
            $body
        }

        pub fn dummy(_: &mut Bencher) {}

        #[cfg(not(feature="inclramp"))]
        mod ramp {
            pub mod $m {
                benchmark_group!($g, super::super::dummy);
            }
        }

        #[cfg(not(feature="inclgmp"))]
        mod gmp {
            pub mod $m {
                benchmark_group!($g, super::super::dummy);
            }
        }

        #[cfg(not(feature="inclnum"))]
        mod num {
            pub mod $m {
                benchmark_group!($g, super::super::dummy);
            }
        }

        benchmark_main!(ramp::$m::$g, num::$m::$g, gmp::$m::$g);

    };
}


// 1024 bit primes
static P: &'static str = "148677972634832330983979593310074301486537017973460461278300587514468301043894574906886127642530475786889672304776052879927627556769456140664043088700743909632312483413393134504352834240399191134336344285483935856491230340093391784574980688823380828143810804684752914935441384845195613674104960646037368551517";
static Q: &'static str = "158741574437007245654463598139927898730476924736461654463975966787719309357536545869203069369466212089132653564188443272208127277664424448947476335413293018778018615899291704693105620242763173357203898195318179150836424196645745308205164116144020613415407736216097185962171301808761138424668335445923774195463";

// 2048 bit primes
// static P: &'static str = "54012895487015803837782421918841304863093162502146915827099238255626761389465957752056702693431430972436786355954646022466841435632094385265559627938436498972714352765471698566168945062965812056432412175521672036039582393637684261505269548649599691053041645072024278713283987472744964393377089048380212183701013564638897218456903964669359622810875460724326972855594957135344351009076932272355015777958742805494234839710255927334289902051693131165245513596331706022111667560809760947628509288759753593140967096047486612859680010875340619186313770693509235798857494768621913543203586903819461926872265770592622637080247";
// static Q: &'static str = "60110804761482905184172241999095064083721568391310132372880785562823040626081548259976195239057024762128798436684644401019565227508680839629752481384744855648596664223620474562582585419094571730852126918991494749938349375651158144545334949768160783962056913632707282062013023732986998195594940491859337992015569093391582644730733764652146222141495874869085082992832080902317418308778550853362446428222413647016439326663338175383509775221151568910938769471308411320393345489705012051577672571014388700476797545130036524629098427518061068575727892423981365405385986469525296662636940291427883820330312960173766723887143";

use std::ops::Mul;

pub trait TestKeyGeneration<I>
{
    fn test_keypair() -> (I, I, I);
}

impl<I, S> TestKeyGeneration<I> for S
where
    S: AbstractScheme<BigInteger=I>,
    I: ::std::str::FromStr, <I as ::std::str::FromStr>::Err: ::std::fmt::Debug,
    for<'a,'b> &'a I: Mul<&'b I, Output=I>,
 {
    fn test_keypair() -> (I, I, I) {
        let p = str::parse(P).unwrap();
        let q = str::parse(Q).unwrap();
        let n = &p * &q;
        (p, q, n)
    }
}

scheme!(S, bench, group,
pub mod bench
{
    use paillier::*;
    use super::*;
    use bencher::Bencher;

    use TestKeyGeneration;
    // use plain::{Encode, Encryption, Decryption};

    pub fn bench_decryption_crt_small(b: &mut Bencher) {
        let (p, q, n) = S::test_keypair();
        let ek = core::standard::EncryptionKey::from(&n);
        let dk = core::crt::DecryptionKey::from((&p, &q));

        let m = core::Plaintext::from(10);
        let c = S::encrypt(&ek, &m);
        b.iter(|| {
            let _ = S::decrypt(&dk, &c);
        });
    }

    pub fn bench_decryption_crt_random(b: &mut Bencher) {
        let (p, q, n) = S::test_keypair();
        let ek = core::standard::EncryptionKey::from(&n);
        let dk = core::crt::DecryptionKey::from((&p, &q));

        use arithimpl::traits::Samplable;
        let m = core::Plaintext(<S as AbstractScheme>::BigInteger::sample_below(&n));
        let c = S::encrypt(&ek, &m);
        b.iter(|| {
            let _ = S::decrypt(&dk, &c);
        });
    }

    pub fn bench_decryption_standard_small(b: &mut Bencher) {
        let (p, q, n) = S::test_keypair();
        let ek = core::standard::EncryptionKey::from(&n);
        let dk = core::standard::DecryptionKey::from((&p, &q));

        let m = core::Plaintext::from(10);
        let c = S::encrypt(&ek, &m);
        b.iter(|| {
            let _ = S::decrypt(&dk, &c);
        });
    }

    pub fn bench_decryption_standard_random(b: &mut Bencher) {
        let (p, q, n) = S::test_keypair();
        let ek = core::standard::EncryptionKey::from(&n);
        let dk = core::standard::DecryptionKey::from((&p, &q));

        use arithimpl::traits::Samplable;
        let m = core::Plaintext(<S as AbstractScheme>::BigInteger::sample_below(&n));
        let c = S::encrypt(&ek, &m);
        b.iter(|| {
            let _ = S::decrypt(&dk, &c);
        });
    }

    benchmark_group!(group,
        self::bench_decryption_crt_small,
        self::bench_decryption_crt_random,
        self::bench_decryption_standard_small,
        self::bench_decryption_standard_random
    );

});
