use bytemuck::bytes_of;
use rand::prelude::{Rng, SeedableRng, StdRng};
use rug::Integer;
use rug::integer::Order;
use rug::ops::Pow;
use rug::rand::RandState;
use sha2::{Digest, Sha256, Sha512};

use crate::{SignatureScheme, U256};
use crate::util::{hash_pair, div_up};
use crate::merkle::Merkle;
use std::convert::TryInto;

type MerklePublic<O> = <Merkle<O> as SignatureScheme>::Public;
type MerkleSignature<O> = <Merkle<O> as SignatureScheme>::Signature;
pub struct Signature<O: SignatureScheme, F: SignatureScheme>
    where <O as SignatureScheme>::Public: AsRef<[u8]> {
    fts_public: F::Public,
    fts_sig: F::Signature,
    path: Box<[(MerklePublic<O>, MerkleSignature<O>)]>,
    random: U256,
}


pub struct Sphincs<O, F> {
    depth: usize,
    sub_tree_height: usize,
    idx_len: usize,
    merkle: Merkle<O>,
    fts_scheme: F,
}

impl<O: SignatureScheme + Clone, F: SignatureScheme> Sphincs<O, F>
    where <O as SignatureScheme>::Public: AsRef<[u8]>, <F as SignatureScheme>::Public: AsRef<[u8]> {
    fn new(depth: usize, sub_tree_height: usize, ots_scheme: O, fts_scheme: F) -> Self {
        let idx_len = div_up(depth * sub_tree_height + 1, 8);
        let merkle = Merkle::new(sub_tree_height, ots_scheme.clone());

        Self {
            depth, sub_tree_height, idx_len, merkle, fts_scheme
        }
    }

    fn get_sub_tree_keys(&self, private: U256, depth: usize, idx: &Integer) -> (U256, U256) {
        let mut hasher = Sha256::new();

        let padding = self.idx_len - idx.significant_digits::<u8>();
        hasher.update(&private);
        hasher.update(&idx.to_digits(Order::Lsf));
        hasher.update(&vec![0u8; padding]);
        hasher.update(bytes_of(&depth));
        let tree_seed = hasher.finalize().into();

        let (private, public) = self.merkle.gen_keys(Some(tree_seed));
        (private.0, public)
    }

    fn get_fts_keys(&self, private: U256, idx: &Integer) -> (F::Private, F::Public) {
        let seed = hash_pair(&private, &idx.to_digits(Order::Lsf));
        self.fts_scheme.gen_keys(Some(seed))
    }

    // TODO: don't hard code this
    fn transform_msg(msg: &[u8], random: U256) -> Box<[u8]> {
        let mut hasher = Sha512::new();
        hasher.update(random);
        hasher.update(msg);
        hasher.finalize().as_slice().into()
    }
}

impl<O: SignatureScheme + Clone, F: SignatureScheme> SignatureScheme for Sphincs<O, F>
    where <O as SignatureScheme>::Public: AsRef<[u8]>, <F as SignatureScheme>::Public: AsRef<[u8]> {
    type Private = (U256, U256);
    type Public = U256;
    type Signature = Signature<O, F>;

    fn gen_keys(&self, seed: Option<U256>) -> (Self::Private, Self::Public) {
        let mut rng = match seed {
            None => StdRng::from_entropy(),
            Some(seed) => StdRng::from_seed(seed),
        };

        let private = (rng.gen(), rng.gen());

        let public = self.get_sub_tree_keys(private.0, self.depth - 1, &Integer::new()).1;

        (private, public)
    }

    fn sign(&self, msg: &[u8], private: &Self::Private) -> Self::Signature {
        let (sk1, sk2) = *private;

        let num_sub_tree_leaves = 1 << self.sub_tree_height;
        let num_leaves = Integer::from(num_sub_tree_leaves).pow(self.depth as u32);
        let mut rand = RandState::new(); // Is this safe?
        rand.seed(&Integer::from_digits(&[msg, &sk2].concat(), Order::Lsf));
        let fts_idx = Integer::random_below(num_leaves.clone(), &mut rand);

        let (fts_private, fts_public) = self.get_fts_keys(sk1, &fts_idx);

        let random = Integer::from(Integer::random_bits(256, &mut rand)).to_digits(Order::Lsf)
            .try_into().unwrap();
        let msg = Self::transform_msg(msg, random);

        let fts_sig = self.fts_scheme.sign(&msg, &fts_private);

        let mut node: Box<[u8]> = fts_public.as_ref().into();
        let mut path = Vec::with_capacity(self.depth);
        let mut idx = fts_idx;
        for depth in 0..self.depth{
            let sub_tree_idx = idx.mod_u(num_sub_tree_leaves) as usize;
            idx /= num_sub_tree_leaves;

            let (private, public) = self.get_sub_tree_keys(sk1, depth, &idx);
            let sig = self.merkle.sign(&node, &(private, sub_tree_idx));
            path.push((public, sig));

            node = public.into();
        }

        Signature {
            fts_public,
            fts_sig,
            path: path.into_boxed_slice(),
            random,
        }
    }

    fn verify(&self, msg: &[u8], public: &Self::Public, sig: &Self::Signature) -> bool {
        let msg = Self::transform_msg(msg, sig.random);
        if !self.fts_scheme.verify(&msg, &sig.fts_public, &sig.fts_sig) {
            return false;
        }

        let mut node: Box<[u8]> = sig.fts_public.as_ref().into();
        for (public, sig) in sig.path.iter() {
            if !self.merkle.verify(&node, public, sig) {
                return false;
            }
            node = public.as_ref().into();
        }

        public.as_ref() == &*node
    }
}


#[cfg(test)]
mod tests {
    use crate::winternitz::Winternitz;

    use super::*;
    use crate::horst::Horst;

    #[test]
    fn it_works() {
        let msg1 = b"My OS update";
        let msg2 = b"My important message";

        let ots = Winternitz::new(16);
        let fts = Horst::new(16, 32);
        let sphincs = Sphincs::new(12, 5, ots, fts);

        let (private, public) = sphincs.gen_keys(None);

        let sig = sphincs.sign(msg1, &private);
        assert!(sphincs.verify(msg1, &public, &sig));

        let sig = sphincs.sign(msg2, &private);
        assert!(sphincs.verify(msg2, &public, &sig));

        assert!(!sphincs.verify(msg1, &public, &sig));
    }
}