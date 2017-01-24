
macro_rules! bigint {
    ( $t:ident, $body:item ) => {

        #[cfg(feature="inclramp")]
        mod ramp {
            #[allow(dead_code)]
            type $t = ::RampBigInteger;
            $body
        }

        #[cfg(feature="inclgmp")]
        mod gmp {
            #[allow(dead_code)]
            type $t = ::GmpBigInteger;
            $body
        }

        #[cfg(feature="inclnum")]
        mod num {
            #[allow(dead_code)]
            type $t = ::NumBigInteger;
            $body
        }

    };
}
