
extern crate paillier;

#[cfg(not(feature="keygen"))]
fn main() {
    println!("*** please run with 'keygen' feature ***")
}

#[cfg(feature="keygen")]
fn main() {

    use paillier::{AbstractPaillier, BigInteger, integral};  // could be a specific type such as RampBigInteger as well
    use paillier::coding::*;
    use paillier::traits::*;
    type MyScheme = AbstractPaillier<BigInteger>;

    let (ek, dk) = MyScheme::keypair().keys();
    let code = integral::Code::default();

    let eek = ek.with_code(&code);

    let c1 = MyScheme::encrypt(&eek, &10);
    let c2 = MyScheme::encrypt(&eek, &20);
    let c3 = MyScheme::encrypt(&eek, &30);
    let c4 = MyScheme::encrypt(&eek, &40);
    // add up all four encryptions
    let c = MyScheme::add(&ek,
        &MyScheme::add(&ek, &c1, &c2),
        &MyScheme::add(&ek, &c3, &c4)
    );

    let m: u64 = code.decode(&MyScheme::decrypt(&dk, &c));
    println!("decrypted total sum is {}", m);

}
