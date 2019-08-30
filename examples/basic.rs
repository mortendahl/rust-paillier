use paillier::*;

fn main() {
    // first generate a fresh keypair, where
    // the encryption key can be made public
    // while the decryption key should remain private
    let (ek, dk) = Paillier::keypair().keys();

    // after sharing the encryption key anyone can encrypt values
    let c1 = Paillier::encrypt(&ek, 10);
    let c2 = Paillier::encrypt(&ek, 20);
    let c3 = Paillier::encrypt(&ek, 30);
    let c4 = Paillier::encrypt(&ek, 40);

    // and anyone can perform homomorphic operations on encrypted values,
    // e.g. multiplication with unencrypted values
    let d1 = Paillier::mul(&ek, c1, 4);
    let d2 = Paillier::mul(&ek, c2, 3);
    let d3 = Paillier::mul(&ek, c3, 2);
    let d4 = Paillier::mul(&ek, c4, 1);
    // ... or addition with encrypted values
    let d = Paillier::add(&ek, Paillier::add(&ek, d1, d2), Paillier::add(&ek, d3, d4));

    // after all homomorphic operations are done the result
    // should be re-randomized to hide all traces of the inputs
    let d = Paillier::rerandomize(&ek, d);

    // finally, only the one with the private decryption key
    // can retrieve the result
    let m = Paillier::decrypt(&dk, &d);
    println!("Decrypted value is {}", m);
}
