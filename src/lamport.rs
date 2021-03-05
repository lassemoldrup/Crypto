use std::convert::TryFrom;

use sha2::{Sha256, Digest};
use rand_hc::Hc128Rng;
use rand::{SeedableRng, RngCore};
use bitvec::prelude::{BitView, Lsb0};

use crate::SignatureScheme;
use crate::u256::{U256, hash};

#[derive(Clone, PartialEq)]
pub struct Key(Box<[u8]>);

impl Key {
    fn gen_private(msg_len: usize, seed: Option<U256>) -> Self {
        // Get message length in bits
        let msg_len = msg_len * 8;

        let mut rng = match seed {
            None => Hc128Rng::from_entropy(),
            Some(seed) => Hc128Rng::from_seed(*seed.as_ref())
        };

        let mut result = vec![0; msg_len * 64];
        rng.fill_bytes(&mut result[..]);

        Self(result.into_boxed_slice())
    }

    fn gen_public(private: &Self) -> Self {
        let mut result = private.0.clone();

        result.chunks_exact_mut(32)
            .for_each(|k| k.copy_from_slice(Sha256::digest(k).as_slice()));

        Self(result)
    }

    fn get(&self, idx: usize) -> (U256, U256) {
        let byte_idx = idx * 64;
        (U256::try_from(&self.0[byte_idx..byte_idx + 32]).unwrap(),
         U256::try_from(&self.0[byte_idx + 32..byte_idx + 64]).unwrap())
    }

    fn len(&self) -> usize {
        self.0.len() / (64 * 8)
    }
}

impl AsRef<[u8]> for Key {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}


pub struct Signature(Box<[U256]>);

impl Signature {
    fn len(&self) -> usize {
        self.0.len() / 8
    }
}


pub struct Lamport {
    msg_len: usize,
}

impl Lamport {
    pub fn new(msg_len: usize) -> Self {
        Self { msg_len }
    }
}

impl SignatureScheme for Lamport {
    type Private = Key;
    type Public = Key;
    type Signature = Signature;

    fn gen_keys(&self, seed: Option<U256>) -> (Key, Key) {
        let private = Key::gen_private(self.msg_len, seed);
        let public = Key::gen_public(&private);

        (private, public)
    }

    fn sign(&self, msg: &[u8], private: &Self::Private) -> Self::Signature {
        assert_eq!(self.msg_len, private.len());

        let msg_bits = msg.view_bits::<Lsb0>();

        let sig = msg_bits.iter().by_val()
            .enumerate()
            .map(|(i, bit)| if bit {
                private.get(i).1
            } else {
                private.get(i).0
            })
            .collect();

        Signature(sig)
    }

    fn verify(&self, msg: &[u8], public: &Self::Public, sig: &Self::Signature) -> bool {
        assert_eq!(self.msg_len, public.len());

        if msg.len() != sig.len() {
            return false;
        }

        let msg_bits = msg.view_bits::<Lsb0>();

        msg_bits.iter().by_val()
            .enumerate()
            .map(|(i, bit)| (sig.0[i], if bit {
                public.get(i).1
            } else {
                public.get(i).0
            }))
            .all(|(s, k)| hash(s.as_ref()) == k)
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let msg = b"My OS update";

        let lamport = Lamport::new(64);
        let (private, public) = lamport.gen_keys(None);

        let sig = lamport.sign(msg, &private);

        assert!(lamport.verify(msg, &public, &sig));
        assert!(!lamport.verify(b"My OS apdate", &public, &sig));
    }
}