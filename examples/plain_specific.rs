
extern crate paillier;

use paillier::BigInteger;  // could be a specific type such as RampBigInteger as well
use paillier::plain::*;

type MyScheme = Scheme<BigInteger>;

#[cfg(not(feature="keygen"))]
fn main() {
    println!("*** please run with 'keygen' feature ***")
}

#[cfg(feature="keygen")]
fn main() {

    let (ek, dk) = MyScheme::keypair(100);

    let m1 = MyScheme::encode(10);
    let c1 = MyScheme::encrypt(&ek, &m1);

    let m2 = MyScheme::encode(20);;
    let c2 = MyScheme::encrypt(&ek, &m2);

    let m3 = MyScheme::encode(30);
    let c3 = MyScheme::encrypt(&ek, &m3);

    let m4 = MyScheme::encode(40);
    let c4 = MyScheme::encrypt(&ek, &m4);

    // add up all four encryptions
    let c = MyScheme::add(&ek,
        &MyScheme::add(&ek, &c1, &c2),
        &MyScheme::add(&ek, &c3, &c4)
    );

    // divide by 4 (only correct when result is integer)
    //  - note that this could just as well be done after decrypting!
    // let d = plain::div(&ek, &c, &BigUint::from(4u32));

    let m = MyScheme::decrypt(&dk, &c).0;
    // let n = plain::decrypt(&dk, &d);
    println!("decrypted total sum is {}", m);
    // println!("... and after dividing {}", n);
}
