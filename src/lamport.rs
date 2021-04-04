use std::ops::Index;

use bitvec::prelude::{BitView, Lsb0};
use bytemuck::{cast_slice, cast_slice_mut};
use rand::{RngCore, SeedableRng};
use rand_hc::Hc128Rng;

use crate::hash::hash;
use crate::SignatureScheme;
use crate::U256;

#[derive(Clone, PartialEq)]
pub struct Key(Box<[[U256; 2]]>);

impl Key {
    fn gen_private(msg_len: usize, seed: Option<U256>) -> Self {
        // Get message length in bits
        let msg_len = msg_len * 8;

        let mut rng = match seed {
            None => Hc128Rng::from_entropy(),
            Some(seed) => Hc128Rng::from_seed(seed)
        };

        let mut result = vec![[[0u8; 32]; 2]; msg_len];
        rng.fill_bytes(cast_slice_mut(&mut result[..]));

        Self(result.into_boxed_slice())
    }

    fn gen_public(private: &Self) -> Self {
        let mut result = private.clone();

        for keys in result.0.iter_mut() {
            keys[0] = hash(keys[0]);
            keys[1] = hash(keys[1]);
        }

        result
    }

    /// Length in signable bytes
    fn len(&self) -> usize {
        self.0.len() / 8
    }
}

impl AsRef<[u8]> for Key {
    fn as_ref(&self) -> &[u8] {
        cast_slice(&*self.0)
    }
}

impl Index<usize> for Key {
    type Output = [U256; 2];

    fn index(&self, index: usize) -> &Self::Output {
        &self.0[index]
    }
}


pub struct Signature(Box<[U256]>);

impl Signature {
    /// Length in signed bytes
    fn len(&self) -> usize {
        self.0.len() / 8
    }
}

impl Index<usize> for Signature {
    type Output = U256;

    fn index(&self, index: usize) -> &Self::Output {
        &self.0[index]
    }
}


#[derive(Copy, Clone)]
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
        assert!(msg.len() <= self.msg_len);

        let msg_bits = msg.view_bits::<Lsb0>();

        let sig = msg_bits.iter().by_val()
            .enumerate()
            .map(|(i, bit)| private[i][bit as usize])
            .collect();

        Signature(sig)
    }

    fn verify(&self, msg: &[u8], public: &Self::Public, sig: &Self::Signature) -> bool {
        assert_eq!(self.msg_len, public.len());
        assert!(msg.len() <= self.msg_len);

        if msg.len() != sig.len() {
            return false;
        }

        let msg_bits = msg.view_bits::<Lsb0>();

        msg_bits.iter().by_val()
            .enumerate()
            .map(|(i, bit)| (sig[i], public[i][bit as usize]))
            .all(|(s, k)| hash(s) == k)
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