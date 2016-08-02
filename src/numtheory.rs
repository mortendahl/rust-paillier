use num::{Zero, One, Integer};
use num::bigint::{BigInt, BigUint};

pub fn modpow(x: &BigUint, e: &BigUint, prime: &BigUint) -> BigUint {
    let mut mx = x.clone();
    let mut me = e.clone();
    let mut acc = BigUint::one();
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
