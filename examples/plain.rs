
extern crate paillier;

use paillier::PartiallyHomomorphicScheme as PHE;
use paillier::KeyGeneration;
use paillier::PlainPaillier;

#[cfg(not(feature="keygen"))]
fn main() {
    println!("*** please run with 'keygen' feature ***")
}

#[cfg(feature="keygen")]
fn main() {
    // let (ek, dk) = plain::generate_keypair(1024);
    let (ek, dk) = PlainPaillier::keypair(10); // TODO

    let m1 = <PlainPaillier as PHE>::Plaintext::from(10);
    // let m1 = PlainPaillier::Plaintext::from(10);
    let c1 = PlainPaillier::encrypt(&ek, &m1);

    // let m2 = BigUint::from(20u32);
    // let c2 = plain::encrypt(&ek, &m2);
    //
    // let m3 = BigUint::from(30u32);
    // let c3 = plain::encrypt(&ek, &m3);
    //
    // let m4 = BigUint::from(40u32);
    // let c4 = plain::encrypt(&ek, &m4);
    //
    // // add up all four encryptions
    // let c = plain::add(&ek,
    //     &plain::add(&ek, &c1, &c2),
    //     &plain::add(&ek, &c3, &c4)
    // );

    // divide by 4 (only correct when result is integer)
    //  - note that this could just as well be done after decrypting!
    // let d = plain::div(&ek, &c, &BigUint::from(4u32));

    let m = PlainPaillier::decrypt(&dk, &c1);
    // let n = plain::decrypt(&dk, &d);
    println!("decrypted total sum is {}", m);
    // println!("... and after dividing {}", n);
}
