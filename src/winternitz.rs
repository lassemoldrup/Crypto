use crate::{SignatureScheme, U256};
use rand::prelude::{StdRng, SeedableRng};
use crate::hash::{hash, hash_n};
use rand::RngCore;

pub struct Winternitz;

impl Winternitz {
    pub fn new() -> Self {
        Self
    }
}

impl SignatureScheme for Winternitz {
    type Private = [U256; 32];
    type Public = [U256; 32];
    type Signature = [U256; 32];

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

        (private, public)
    }

    fn sign(&self, msg: &[u8], private: &Self::Private) -> Self::Signature {
        let mut sig = [[0; 32]; 32];
        for (i, &byte) in hash(msg).iter().enumerate() {
            let num_hashes = 256 - byte as usize;
            sig[i] = hash_n(private[i], num_hashes);
        }
        sig
    }

    fn verify(&self, msg: &[u8], public: &Self::Public, sig: &Self::Signature) -> bool {
        hash(msg).iter().enumerate()
            .all(|(i, &byte)| public[i] == hash_n(sig[i], byte as usize))
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