
extern crate paillier;

#[cfg(not(feature="keygen"))]
fn main() {
    println!("*** please run with 'keygen' feature ***")
}

#[cfg(feature="keygen")]
fn main() {

    use paillier::*;

    // generate a fresh keypair
    let (ek, dk) = Paillier::keypair();

    // encrypt two values
    let c1 = Paillier::encrypt(&ek, &core::Plaintext::from(20));
    let c2 = Paillier::encrypt(&ek, &core::Plaintext::from(30));

    // add all of them together
    let c = Paillier::add(&ek, &c1, &c2);

    // multiply the sum by 2
    let d = Paillier::mul(&ek, &c, &core::Plaintext::from(2));

    // decrypt final result
    let m = Paillier::decrypt(&dk, &d);
    println!("decrypted total sum is {}", m);

}
