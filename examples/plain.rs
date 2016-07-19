extern crate paillier;
extern crate num;

use paillier::plain::*;
use num::bigint::BigUint;

fn main() {
    let (ek, dk) = generate_keypair(1024);
    let c = encrypt(&ek, &BigUint::from(10 as u32));
    let m = decrypt(&dk, &c);
    println!("decrypted to {}", m);
}
