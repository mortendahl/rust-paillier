
extern crate paillier;
use paillier::*;

#[cfg(not(feature="keygen"))]
fn main() {
    println!("*** please run with 'keygen' feature ***")
}

#[cfg(feature="keygen")]
fn main() {

    // generate a fresh keypair and extract encryption and decryption keys
    let (ek, dk) = Paillier::keypair().keys();

    // encrypt four values
    let c1 = Paillier::encrypt(&ek, 10);
    let c2 = Paillier::encrypt(&ek, 20);
    let c3 = Paillier::encrypt(&ek, 30);
    let c4 = Paillier::encrypt(&ek, 40);

    // add all of them together
    let c = Paillier::add(&ek,
        &Paillier::add(&ek, &c1, &c2),
        &Paillier::add(&ek, &c3, &c4)
    );

    // multiply the sum by 2
    let d = Paillier::mul(&ek, &c, 2);

    // decrypt final result
    let m = Paillier::decrypt(&dk, &d);
    println!("decrypted total sum is {}", m);

}
