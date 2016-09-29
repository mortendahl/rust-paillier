
// pub trait ModArith {
//     // fn one() -> Self;
//
//     fn modpow(x: &Self, e: &Self, m: &Self) -> Self;
//     fn modinv(a: &Self, p: &Self) -> Self;
//     fn egcd(a: &Self, b: &Self) -> (Self, Self, Self);
//     // fn gcd(a: &Self, b: &Self) -> Self;
// }

pub use self::ramp::*;
// pub use self::num::*;

mod ramp {

    // use super::ModArith;
    use ramp::{Int, RandomInt};

    // impl ModArith for Int {
    //
    //     // fn one() -> BigInt {
    //     //     BigInt::one()
    //     // }
    //
    //     fn modpow(x: &Int, e: &Int, m: &Int) -> Int {
    //         modpow(x, e, m)
    //     }
    //
    //     fn modinv(a: &Int, prime: &Int) -> Int {
    //         modinv(a, prime)
    //     }
    //
    //     fn egcd(a: &Int, b: &Int) -> (Int, Int, Int) {
    //         egcd(a, b)
    //     }
    //
    // }

    pub fn modpow(x: &Int, e: &Int, prime: &Int) -> Int {
        let mut mx = x.clone();
        let mut me = e.clone();
        let mut acc = Int::one();
        while me != 0 {
            if me.is_even() {
                // even
                // no-op
            }
            else {
                // odd
                acc = (&acc * &mx) % prime;
            }
            mx = (&mx * &mx) % prime;  // waste one of these by having it here but code is simpler (tiny bit)
            me = me >> 1;
        }
        acc
    }

    pub fn egcd(a: &Int, b: &Int) -> (Int, Int, Int) {
        if b == &Int::zero() {
            (a.clone(), Int::one(), Int::zero())
        } else {
            let q = a / b;
            let r = a % b;
            let (d, s, t) = egcd(b, &r);
            let new_t = s - &t * q;
            (d, t, new_t)
        }
    }

    pub fn modinv(a: &Int, prime: &Int) -> Int {
        use num::Signed;
        use std::ops::Neg;

        let r = a % prime;
        let d = if r < 0 {
            let r = r.neg();
            -egcd(prime, &r).2
        } else {
            egcd(prime, &r).2
        };
        (prime + d) % prime
    }


    // #[cfg(test)]
    // mod tests {
    //
    //     use super::*;
    //     use num::bigint::BigInt;
    //
    //     #[test]
    //     fn test_modinv() {
    //         assert_eq!(
    //             modinv(&BigInt::from(3), &BigInt::from(7)),
    //             BigInt::from(5)
    //         );
    //     }
    //
    //     #[test]
    //     fn test_egcd() {
    //         assert_eq!(
    //             egcd(&BigInt::from(12), &BigInt::from(16)),
    //             (BigInt::from(4), BigInt::from(-1), BigInt::from(1))
    //         );
    //     }
    //
    // }

}


mod num {

    // use super::ModArith;
    //
    // impl ModArith for BigInt {
    //
    //     // fn one() -> BigInt {
    //     //     BigInt::one()
    //     // }
    //
    //     fn modpow(x: &BigInt, e: &BigInt, m: &BigInt) -> BigInt {
    //         modpow(x, e, m)
    //     }
    //
    //     fn modinv(a: &BigInt, prime: &BigInt) -> BigInt {
    //         modinv(a, prime)
    //     }
    //
    //     fn egcd(a: &BigInt, b: &BigInt) -> (BigInt, BigInt, BigInt) {
    //         egcd(a, b)
    //     }
    //
    // }

    use num::{Zero, One, Integer};
    use num::bigint::BigInt;

    pub fn modpow(x: &BigInt, e: &BigInt, prime: &BigInt) -> BigInt {
        let mut mx = x.clone();
        let mut me = e.clone();
        let mut acc = BigInt::one();
        while !me.is_zero() {
            if me.is_even() {
                // even
                // no-op
            }
            else {
                // odd
                acc = (&acc * &mx) % prime;
            }
            mx = (&mx * &mx) % prime;  // waste one of these by having it here but code is simpler (tiny bit)
            me = me >> 1;
        }
        acc
    }

    pub fn egcd(a: &BigInt, b: &BigInt) -> (BigInt, BigInt, BigInt) {
        if b.is_zero() {
            (a.clone(), BigInt::one(), BigInt::zero())
        } else {
            let q = a / b;
            let r = a % b;
            let (d, s, t) = egcd(b, &r);
            let new_t = s - &t * q;
            (d, t, new_t)
        }
    }

    pub fn modinv(a: &BigInt, prime: &BigInt) -> BigInt {
        use num::Signed;
        use std::ops::Neg;

        let r = a % prime;
        let d = if r.is_negative() {
            let r = r.neg();
            -egcd(prime, &r).2
        } else {
            egcd(prime, &r).2
        };
        (prime + d) % prime
    }


    #[cfg(test)]
    mod tests {

        use super::*;
        use num::bigint::BigInt;

        #[test]
        fn test_modinv() {
            assert_eq!(
                modinv(&BigInt::from(3), &BigInt::from(7)),
                BigInt::from(5)
            );
        }

        #[test]
        fn test_egcd() {
            assert_eq!(
                egcd(&BigInt::from(12), &BigInt::from(16)),
                (BigInt::from(4), BigInt::from(-1), BigInt::from(1))
            );
        }

    }

}
