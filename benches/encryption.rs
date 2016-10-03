
use test::Bencher;

use phe::PartiallyHomomorphicScheme as PHE;
use PlainPaillier as Plain;

fn test_keypair() -> (<Plain as PHE>::EncryptionKey, <Plain as PHE>::DecryptionKey) {
    let ref p = str::parse("148677972634832330983979593310074301486537017973460461278300587514468301043894574906886127642530475786889672304776052879927627556769456140664043088700743909632312483413393134504352834240399191134336344285483935856491230340093391784574980688823380828143810804684752914935441384845195613674104960646037368551517").unwrap();
    let ref q = str::parse("158741574437007245654463598139927898730476924736461654463975966787719309357536545869203069369466212089132653564188443272208127277664424448947476335413293018778018615899291704693105620242763173357203898195318179150836424196645745308205164116144020613415407736216097185962171301808761138424668335445923774195463").unwrap();
    let ref n = p * q;
    let ek = <Plain as PHE>::EncryptionKey::from(n);
    let dk = <Plain as PHE>::DecryptionKey::from(p, q);
    (ek, dk)
}

#[test]
fn bench_encryption(b: &mut Bencher) {
    let (ek, _) = test_keypair();

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
