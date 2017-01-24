
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

    // select integral coding
    let code = integral::Code::default();

    // pair keys with coding
    let eek = ek.with_code(&code);
    let ddk = dk.with_code(&code);

    // encrypt four values
    let c1 = Paillier::encrypt(&eek, &10);
    let c2 = Paillier::encrypt(&eek, &20);
    let c3 = Paillier::encrypt(&eek, &30);
    let c4 = Paillier::encrypt(&eek, &40);

    // add all of them together
    let c = Paillier::add(&eek,
        &Paillier::add(&eek, &c1, &c2),
        &Paillier::add(&eek, &c3, &c4)
    );

    // multiply the sum by 2
    let d = Paillier::mul(&eek, &c, &2);

    // decrypt final result
    let m: u64 = Paillier::decrypt(&ddk, &d);
    println!("decrypted total sum is {}", m);

}
