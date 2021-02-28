use std::convert::TryInto;

use rand_hc::Hc128Rng;
use rand::{SeedableRng, RngCore};
use sha2::{Sha256, Digest};

use crate::SignatureScheme;
use crate::u256::U256;
use bitvec::prelude::{BitView, Lsb0};


pub struct Key(Box<[(U256, U256)]>);

impl Key {
    fn gen_private(msg_len: usize) -> Self {
        // Get message length in bits
        let msg_len = msg_len * 8;

        let mut rng = Hc128Rng::from_entropy();

        let result = (0..msg_len).map(|_| {
            let mut key1 = [0; 32];
            let mut key2 = [0; 32];
            rng.fill_bytes(&mut key1);
            rng.fill_bytes(&mut key2);
            (U256::from(key1), U256::from(key2))
        })
            .collect();

        Self(result)
    }

    fn gen_public(private: &Self) -> Self {
        let result = private.0.iter()
            .map(|(k1, k2)| (hash(k1.as_bytes()), hash(k2.as_bytes())))
            .collect();

        Self(result)
    }
}


pub struct Signature(Box<[U256]>);


pub struct Lamport;

impl Lamport {
    fn gen_keys(msg_len: usize) -> (Key, Key) {
        let private = Key::gen_private(msg_len);
        let public = Key::gen_public(&private);

        (private, public)
    }
}

impl SignatureScheme for Lamport {
    type Private = Key;
    type Public = Key;
    type Signature = Signature;

    fn sign(msg: &[u8], private: &Self::Private) -> Self::Signature {
        let msg_bits = msg.view_bits::<Lsb0>();

        let sig = msg_bits.iter().by_val()
            .enumerate()
            .map(|(i, bit)| if bit {
                private.0[i].1
            } else {
                private.0[i].0
            })
            .collect();

        Signature(sig)
    }

    fn verify(msg: &[u8], public: &Self::Public, sig: &Self::Signature) -> bool {
        let msg_bits = msg.view_bits::<Lsb0>();

        msg_bits.iter().by_val()
            .enumerate()
            .map(|(i, bit)| if bit {
                (sig.0[i], public.0[i].1)
            } else {
                (sig.0[i], public.0[i].0)
            })
            .all(|(s, k)| hash(s.as_bytes()) == k)
    }
}

fn hash(data: &[u8]) -> U256 {
    Sha256::digest(data).as_slice()
        .try_into()
        .unwrap()
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let msg = b"My OS update";

        let (private, public) = Lamport::gen_keys(msg.len());

        let sig = Lamport::sign(msg, &private);

        assert!(Lamport::verify(msg, &public, &sig))
    }
}