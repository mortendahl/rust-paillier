use paillier::*;

fn main() {
    // generate a fresh keypair
    let (ek, dk) = Paillier::keypair().keys();

    // encrypt two values
    let c1 = Paillier::encrypt(&ek, RawPlaintext::from(BigInt::from(20)));
    let c2 = Paillier::encrypt(&ek, RawPlaintext::from(BigInt::from(30)));

    // add all of them together
    let c = Paillier::add(&ek, c1, c2);

    // multiply the sum by 2
    let d = Paillier::mul(&ek, c, RawPlaintext::from(BigInt::from(2)));

    // decrypt final result
    let m: BigInt = Paillier::decrypt(&dk, d).into();
    println!("decrypted total sum is {}", m);
}
