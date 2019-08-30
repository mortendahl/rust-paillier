use paillier::{
    Add, Decrypt, DecryptionKey, EncodedCiphertext, Encrypt, EncryptionKey, KeyGeneration,
    Paillier, Rerandomize,
};

fn main() {
    // first we initialize the clerk by asking it to generate a fresh keypair
    let clerk = Clerk::new();

    // then we create a set of voters using the corresponding encryption key of the clerk
    let ek = clerk.encryption_key();
    let voters = (0..10).map(|_| Voter::new(&ek)).collect::<Vec<_>>();

    // the clerk launched a new vote by sharing an encryption of zero
    let mut tally = clerk.new_voting();

    // each voter in turn
    voters.iter().for_each(|voter| {
        tally = voter.vote(&tally);
    });

    // let clerk reveal final tally
    let nb_voters_for = clerk.reveal(&tally);
    let nb_voters_against = voters.len() as u64 - nb_voters_for;
    println!(
        "The result is {} for and {} against",
        nb_voters_for, nb_voters_against
    );

    // check tally correctness for fun
    // - normally this wouldn't be possible of course
    assert_eq!(
        nb_voters_for,
        voters.iter().filter(|voter| voter.vote).count() as u64
    );
    assert_eq!(
        nb_voters_against,
        voters.iter().filter(|voter| !voter.vote).count() as u64
    );
}

struct Clerk {
    ek: EncryptionKey,
    dk: DecryptionKey,
}

impl Clerk {
    fn new() -> Self {
        // generate fresh keypair
        let keypair = Paillier::keypair();
        // extract encryption key from keypair
        let (ek, dk) = keypair.keys();
        Clerk { ek, dk }
    }

    fn encryption_key(&self) -> String {
        // serialize key for sending
        serde_json::to_string(&self.ek).unwrap()
    }

    fn new_voting(&self) -> String {
        // encrypt zero
        let c = Paillier::encrypt(&self.ek, 0);
        // serialize the ciphertext
        serde_json::to_string(&c).unwrap()
    }

    fn reveal(&self, tally: &str) -> u64 {
        // deserialize ciphertext
        let c: EncodedCiphertext<u64> = serde_json::from_str(tally).unwrap();
        // decrypt tally
        Paillier::decrypt(&self.dk, c)
    }
}

struct Voter {
    ek: EncryptionKey,
    vote: bool,
}

impl Voter {
    fn new(ek: &str) -> Voter {
        // deserialize encryption key
        let ek: EncryptionKey = serde_json::from_str(&ek).unwrap();
        // generate random vote
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let vote = rng.gen();

        Voter { ek, vote }
    }

    fn vote(&self, tally: &str) -> String {
        // deserialize current tally ciphertext
        let c: EncodedCiphertext<u64> = serde_json::from_str(tally).unwrap();
        // add own vote
        let d = Paillier::add(&self.ek, c, if self.vote { 1 } else { 0 });
        // re-randomize once all homomorphic operations have been performed
        let d = Paillier::rerandomize(&self.ek, d);
        // re-serialize ciphertext
        serde_json::to_string(&d).unwrap()
    }
}
