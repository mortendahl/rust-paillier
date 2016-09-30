#[cfg(test)]

use plain::*;
use test::Bencher;

use phe::PartiallyHomomorphicScheme as PHE;
use phe::KeyGeneration;
use PlainPaillier as Plain;

#[test]
fn test_correct_encryption_decryption() {
    let (ek, dk) = Plain::keypair(10);

    let m = <Plain as PHE>::Plaintext::from(10usize);
    let c = Plain::encrypt(&ek, &m);

    let recovered_m = Plain::decrypt(&dk, &c);
    assert_eq!(recovered_m, m);
}

#[bench]
#[cfg(test)]
fn bench_encryption(b: &mut Bencher) {
    let (ek, _) = Plain::keypair(10);

    let m = <Plain as PHE>::Plaintext::from(10 as usize);

    b.iter(|| {
        let _ = Plain::encrypt(&ek, &m);
    });
}

// #[bench]
// fn bench_decryption(b: &mut Bencher) {
//     let (ek, dk) = large_fake_key_pair();
//     let m = BigInt::from(10 as usize);
//     let c = encrypt(&ek, &m);
//
//     b.iter(|| {
//         let recovered_m = decrypt(&dk, &c);
//     });
// }
//
// #[bench]
// fn bench_rerandomisation(b: &mut Bencher) {
//     let (ek, dk) = large_fake_key_pair();
//     let m = BigInt::from(10 as usize);
//     let c = encrypt(&ek, &m);
//
//     b.iter(|| {
//         rerandomise(&ek, &c);
//     });
// }
//
// #[test]
// fn test_correct_addition() {
//     let (ek, dk) = key_pair();
//
//     let m1 = BigInt::from(10 as u32);
//     let c1 = encrypt(&ek, &m1);
//     let m2 = BigInt::from(20 as u32);
//     let c2 = encrypt(&ek, &m2);
//
//     let c = add(&ek, &c1, &c2);
//     let m = decrypt(&dk, &c);
//     assert_eq!(m, m1 + m2);
// }
//
// #[bench]
// fn bench_addition(b: &mut Bencher) {
//     let (ek, dk) = large_fake_key_pair();
//
//     let m1 = BigInt::from(10 as u32);
//     let c1 = encrypt(&ek, &m1);
//     let m2 = BigInt::from(20 as u32);
//     let c2 = encrypt(&ek, &m2);
//
//     b.iter(|| {
//         let c = add(&ek, &c1, &c2);
//     });
// }
//
// #[test]
// fn test_correct_multiplication() {
//     let (ek, dk) = key_pair();
//
//     let m1 = BigInt::from(10 as u32);
//     let c1 = encrypt(&ek, &m1);
//     let m2 = BigInt::from(20 as u32);
//
//     let c = mult(&ek, &c1, &m2);
//     let m = decrypt(&dk, &c);
//     assert_eq!(m, m1 * m2);
// }
//
// #[bench]
// fn bench_multiplication(b: &mut Bencher) {
//     let (ek, dk) = large_fake_key_pair();
//
//     let m1 = BigInt::from(10 as u32);
//     let c1 = encrypt(&ek, &m1);
//     let m2 = BigInt::from(20 as u32);
//
//     b.iter(|| {
//         let c = mult(&ek, &c1, &m2);
//     });
// }
