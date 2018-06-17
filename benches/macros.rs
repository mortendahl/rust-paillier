
macro_rules! scheme {
    ( $s:ident, $m:ident, $g:ident, $body:item ) => {

        use bencher::Bencher;
        use paillier::*;

        #[cfg(feature="usegmp")]
        pub mod gmp {
            #[allow(dead_code)]
            type $s = ::GmpPaillier;
            $body
        }

        pub fn dummy(_: &mut Bencher) {}

        #[cfg(not(feature="usegmp"))]
        mod gmp {
            pub mod $m {
                benchmark_group!($g, super::super::dummy);
            }
        }

    };
}
