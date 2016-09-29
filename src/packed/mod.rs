//
// mod tests;
//
// use plain;
//
// pub type Plaintext = u64;
// pub type Ciphertext = plain::Ciphertext;
//
// #[derive(Debug,Clone)]
// pub struct PublicKey {
//     plain_ek: plain::PublicKey,
//     component_count: usize,
//     component_size: usize,  // in bits
// }
//
// #[derive(Debug,Clone)]
// pub struct PrivateKey {
//     plain_dk: plain::PrivateKey,
//     component_count: usize,
//     component_size: usize,  // in bits
// }
//
// impl PublicKey {
//     pub fn from_plain(plain_ek: plain::PublicKey, component_count: usize, component_size: usize) -> PublicKey {
//         // assert!(component_size * component_count <= plain_ek.n.bits());
//         assert!(component_size * component_count <= plain_ek.n.bit_length() as usize);
//         assert!(component_size <= 64);
//         PublicKey {
//             plain_ek: plain_ek,
//             component_size: component_size,
//             component_count: component_count,
//         }
//     }
// }
//
// impl PrivateKey {
//     pub fn from_plain(plain_dk: plain::PrivateKey, component_count: usize, component_size: usize) -> PrivateKey {
//         assert!(component_size <= 64);
//         PrivateKey {
//             plain_dk: plain_dk,
//             component_size: component_size,
//             component_count: component_count,
//         }
//     }
// }
//
// pub fn encrypt(ek: &PublicKey, ms: &[Plaintext]) -> Ciphertext {
//     assert!(ms.len() == ek.component_count);
//     let mut packed_plaintext = plain::Plaintext::from(ms[0]);
//     for &m in &ms[1..] {
//         packed_plaintext = packed_plaintext << ek.component_size;
//         packed_plaintext = packed_plaintext + plain::Plaintext::from(m);
//     }
//     plain::encrypt(&ek.plain_ek, &packed_plaintext)
// }
//
// pub fn decrypt(dk: &PrivateKey, c: &Ciphertext) -> Vec<Plaintext> {
//     let mut packed_plaintext = plain::decrypt(&dk.plain_dk, c);
//     let mask = plain::Plaintext::from(1u64 << dk.component_size);
//     let mut result = vec![];
//     for _ in 0..dk.component_count {
//         let slot_value = &packed_plaintext % &mask;
//         packed_plaintext = &packed_plaintext >> dk.component_size;
//         // result.push(slot_value.to_u64().unwrap());
//         result.push(u64::from(&slot_value));
//     }
//     result.reverse();
//     result
// }
//
// pub fn add(ek: &PublicKey, c1: &Ciphertext, c2: &Ciphertext) -> Ciphertext {
//     plain::add(&ek.plain_ek, c1, c2)
// }
//
// pub fn mult(ek: &PublicKey, c1: &Ciphertext, m2: Plaintext) -> Ciphertext {
//     let expanded_m2 = plain::Plaintext::from(m2);
//     plain::mult(&ek.plain_ek, c1, &expanded_m2)
// }
//
// pub fn rerandomise(ek: &PublicKey, c: &Ciphertext) -> Ciphertext {
//     plain::rerandomise(&ek.plain_ek, c)
// }
