
extern crate paillier;

use paillier::PackedPaillier;
use paillier::packed::*;

#[cfg(not(feature="keygen"))]
fn main() {
    println!("*** please run with 'keygen' feature ***")
}

#[cfg(feature="keygen")]
fn main() {
    let (ek, dk) = PackedPaillier::keypair(100, 3, 10);

    let m1 = Plaintext::from(vec![1, 2, 3]);
    let c1 = PackedPaillier::encrypt(&ek, &m1);
    let m2 = Plaintext::from(vec![1, 2, 3]);
    let c2 = PackedPaillier::encrypt(&ek, &m2);

    let c = PackedPaillier::add(&ek, &c1, &c2);
    let m = PackedPaillier::decrypt(&dk, &c);
    assert_eq!(m.data, vec![2, 4, 6]);

    let m1 = Plaintext::from(vec![1, 5, 10]);
    let c1 = PackedPaillier::encrypt(&ek, &m1);

    let m2 = Plaintext::from(vec![2, 10, 20]);;
    let c2 = PackedPaillier::encrypt(&ek, &m2);

    let m3 = Plaintext::from(vec![3, 15, 30]);
    let c3 = PackedPaillier::encrypt(&ek, &m3);

    let m4 = Plaintext::from(vec![4, 20, 40]);
    let c4 = PackedPaillier::encrypt(&ek, &m4);

    // add up all four encryptions
    let c = PackedPaillier::add(&ek,
        &PackedPaillier::add(&ek, &c1, &c2),
        &PackedPaillier::add(&ek, &c3, &c4)
    );

    let d = PackedPaillier::mult(&ek, &c, &2);

    // divide by 4 (only correct when result is integer)
    //  - note that this could just as well be done after decrypting!
    // let d = plain::div(&ek, &c, &BigUint::from(4u32));

    let m = PackedPaillier::decrypt(&dk, &c).data;
    let n = PackedPaillier::decrypt(&dk, &d).data;
    println!("decrypted total sum is {:?}", m);
    println!("... and after multiplying {:?}", n);
}
