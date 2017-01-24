
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

    };

}
