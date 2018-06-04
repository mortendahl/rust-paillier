
extern crate paillier;

// #[cfg(not(feature="keygen"))]
fn main() {
    println!("*** please run with 'keygen' feature ***")
}

// #[cfg(feature="keygen")]
// fn main() {

//     use paillier::*;

//     // generate a fresh keypair
//     let keypair = Paillier::keypair();

//     // choose type of encryption
//     let ek = core::EncryptionKey::from(&keypair);

//     // choose type of decryption
//     let dk = core::DecryptionKey::from(&keypair);
//     // let dk = crt::DecryptionKey::from(&keypair);

//     // pair keys with integral coding
//     let code = integral::Code::default();
//     let eek = ek.with_code(&code);
//     let ddk = dk.with_code(&code);

//     // encrypt and decrypt
//     let c = Paillier::encrypt(&eek, &10);
//     let m: u64 = Paillier::decrypt(&ddk, &c);
//     println!("decrypted value is {}", m);

// }
