use plain;
use packed::*;

fn key_pair() -> (PublicKey, PrivateKey) {
    use plain;
    let (plain_ek, plain_dk) = plain::fake_key_pair();
    let ek = PublicKey::from_plain(plain_ek, 3, 6);
    let dk = PrivateKey::from_plain(plain_dk, 3, 6);
    (ek, dk)
}

#[test]
fn correct_encryption_decryption() {
    let (ek, dk) = key_pair();

    let m = &[1, 2, 3];
    let c = encrypt(&ek, m);

    let recovered_m = decrypt(&dk, &c);
    assert_eq!(recovered_m, m);
}

#[test]
fn correct_addition() {
    let (ek, dk) = key_pair();

    let m1 = &[1, 2, 3];
    let c1 = encrypt(&ek, m1);

    let m2 = &[1, 2, 3];
    let c2 = encrypt(&ek, m2);

    let c = add(&ek, &c1, &c2);
    let m = decrypt(&dk, &c);
    assert_eq!(m, [2, 4, 6]);
}

#[test]
fn correct_multiplication() {
    let (ek, dk) = key_pair();

    let m1 = &[1, 2, 3];
    let c1 = encrypt(&ek, m1);

    let m2 = 11;

    let c = mult(&ek, &c1, m2);
    let m = decrypt(&dk, &c);
    assert_eq!(m, [11, 22, 33]);
}
