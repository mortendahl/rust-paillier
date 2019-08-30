use paillier::*;

fn main() {
    let (ek, dk) = Paillier::keypair().keys();

    //
    // Encryption
    //

    let c1 = Paillier::encrypt(&ek, &*vec![1, 5, 10]);
    let c2 = Paillier::encrypt(&ek, &*vec![2, 10, 20]);
    let c3 = Paillier::encrypt(&ek, &*vec![3, 15, 30]);
    let c4 = Paillier::encrypt(&ek, &*vec![4, 20, 40]);

    // add up all four encryptions
    let c = Paillier::add(
        &ek,
        &Paillier::add(&ek, &c1, &c2),
        &Paillier::add(&ek, &c3, &c4),
    );

    let d = Paillier::mul(&ek, &c, 2);

    //
    // Decryption
    //

    let m = Paillier::decrypt(&dk, &c);
    let n = Paillier::decrypt(&dk, &d);
    println!("decrypted total sum is {:?}", m);
    println!("... and after multiplying {:?}", n);
    assert_eq!(m, vec![10, 50, 100]);
}
