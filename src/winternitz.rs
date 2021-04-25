use bytemuck::{bytes_of, cast_slice};
use rand::prelude::{SeedableRng, StdRng};
use rand::{RngCore, Rng};
use rug::Integer;

use crate::{SignatureScheme, U256};
use crate::util::{hash, hash_n, div_up, floored_log};
use rug::integer::Order;

pub struct Key(Box<[U256]>);

impl AsRef<[u8]> for Key {
    fn as_ref(&self) -> &[u8] {
        cast_slice(&*self.0)
    }
}


#[derive(Clone, Copy)]
pub struct Winternitz {
    w: usize,
    len1: usize,
    len2: usize,
    len: usize,
}

impl Winternitz {
    pub fn new(w: usize) -> Self {
        assert!(w.is_power_of_two());

        let log_w = w.trailing_zeros() as usize;
        let len1 = div_up(256, log_w);
        let len2 = floored_log(len1 * (w - 1)) / log_w + 1;
        let len = len1 + len2;

        Self {
            w, len1, len2, len
        }
    }

    fn gen_private(&self, seed: U256) -> Key {
        let mut rng = StdRng::from_seed(seed);

        let mut private = vec![[0; 32]; self.len];
        for sk in private.iter_mut() {
            rng.fill_bytes(sk);
        }

        Key(private.into_boxed_slice())
    }

    fn push_base_w(&self, val: &[u8], digits: &mut Vec<usize>) {
        let mut i = Integer::from_digits(val, Order::Lsf);
        while i > 0 {
            digits.push(i.mod_u(self.w as u32) as usize);
            i /= self.w as u32;
        }
    }

    fn hash_counts(&self, msg: &[u8]) -> Vec<usize> {
        let mut counts = Vec::with_capacity(self.len);

        // Is this fine? (not necessarily self.len1 long)
        self.push_base_w(&hash(msg), &mut counts);

        // same
        let checksum: usize = counts.iter()
            .map(|&m| self.w - 1 - m as usize)
            .sum();
        self.push_base_w(bytes_of(&checksum), &mut counts);

        counts
    }
}

impl SignatureScheme for Winternitz {
    type Private = U256;
    type Public = Key;
    type Signature = Key;

    fn gen_keys(&self, seed: Option<U256>) -> (Self::Private, Self::Public) {
        let seed = match seed {
            None => StdRng::from_entropy().gen(),
            Some(s) => s,
        };

        let private = self.gen_private(seed);

        let mut public = vec![[0; 32]; self.len];
        for (i, pk) in public.iter_mut().enumerate() {
            *pk = hash_n(private.0[i], self.w - 1);
        }

        (seed, Key(public.into_boxed_slice()))
    }

    fn sign(&self, msg: &[u8], private: &Self::Private) -> Self::Signature {
        let counts = self.hash_counts(msg);
        let private = self.gen_private(*private);

        let mut sig = Vec::with_capacity(self.len);
        for (&sk, count) in private.0.iter().zip(counts) {
            sig.push(hash_n(sk, count));
        }

        Key(sig.into_boxed_slice())
    }

    fn verify(&self, msg: &[u8], public: &Self::Public, sig: &Self::Signature) -> bool {
        self.hash_counts(msg).iter().enumerate()
            .all(|(i, &count)| public.0[i] == hash_n(sig.0[i], self.w - 1 - count))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let msg1 = b"My OS update";
        let msg2 = b"My important message";

        let winternitz = Winternitz::new(16);

        let (private, public) = winternitz.gen_keys(None);

        let sig = winternitz.sign(msg1, &private);
        assert!(winternitz.verify(msg1, &public, &sig));

        let sig = winternitz.sign(msg2, &private);
        assert!(winternitz.verify(msg2, &public, &sig));

        assert!(!winternitz.verify(msg1, &public, &sig));
    }
}