use bytemuck::bytes_of;
use rand::prelude::{SeedableRng, StdRng};
use rand::RngCore;

use crate::{SignatureScheme, U256};
use crate::hash::{hash, hash_n};

pub struct Key([U256; 32]);

impl AsRef<[u8]> for Key {
    fn as_ref(&self) -> &[u8] {
        bytes_of(&self.0)
    }
}


#[derive(Clone, Copy)]
pub struct Winternitz;

impl Winternitz {
    pub fn new() -> Self {
        Self
    }
}

impl SignatureScheme for Winternitz {
    type Private = Key;
    type Public = Key;
    type Signature = Key;

    fn gen_keys(&self, seed: Option<U256>) -> (Self::Private, Self::Public) {
        let mut rng = match seed {
            None => StdRng::from_entropy(),
            Some(seed) => StdRng::from_seed(seed),
        };

        let mut private = [[0; 32]; 32];
        for sk in private.iter_mut() {
            rng.fill_bytes(sk);
        }

        let mut public = [[0; 32]; 32];
        for (i, pk) in public.iter_mut().enumerate() {
            *pk = hash_n(private[i], 256);
        }

        (Key(private), Key(public))
    }

    fn sign(&self, msg: &[u8], private: &Self::Private) -> Self::Signature {
        let mut sig = [[0; 32]; 32];
        for (i, &byte) in hash(msg).iter().enumerate() {
            let num_hashes = 256 - byte as usize;
            sig[i] = hash_n(private.0[i], num_hashes);
        }

        Key(sig)
    }

    fn verify(&self, msg: &[u8], public: &Self::Public, sig: &Self::Signature) -> bool {
        hash(msg).iter().enumerate()
            .all(|(i, &byte)| public.0[i] == hash_n(sig.0[i], byte as usize))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let msg1 = b"My OS update";
        let msg2 = b"My important message";

        let winternitz = Winternitz::new();

        let (private, public) = winternitz.gen_keys(None);

        let sig = winternitz.sign(msg1, &private);
        assert!(winternitz.verify(msg1, &public, &sig));

        let sig = winternitz.sign(msg2, &private);
        assert!(winternitz.verify(msg2, &public, &sig));

        assert!(!winternitz.verify(msg1, &public, &sig));
    }
}