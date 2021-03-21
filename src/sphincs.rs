use crate::{SignatureScheme, U256};
use rand::prelude::{SeedableRng, Rng, StdRng};
use crate::merkle::Merkle;
use crate::hash::hash_pair;
use rug::Integer;
use rug::integer::Order;
use rug::rand::RandState;
use rug::ops::Pow;

pub struct Signature<F: SignatureScheme> {
    fts_sig: F::Signature,
}


pub struct Sphincs<O, F> {
    depth: usize,
    sub_tree_height: usize,
    ots_scheme: O,
    fts_scheme: F,
}

impl<O: SignatureScheme + Clone, F: SignatureScheme> Sphincs<O, F>
    where <O as SignatureScheme>::Public: AsRef<[u8]> {
    fn get_sub_tree_keys(&self, private: U256, idx: &Integer) -> (U256, U256) {
        let tree_seed = hash_pair(&private, &idx.to_digits(Order::Lsf));
        let merkle = Merkle::new(self.sub_tree_height, self.ots_scheme.clone());
        let (private, public) = merkle.gen_keys(Some(tree_seed));
        (private.0, public)
    }

    fn get_fts_keys(&self, private: U256, idx: &Integer) -> (F::Private, F::Public) {
        let seed = hash_pair(&private, &idx.to_digits(Order::Lsf));
        self.fts_scheme.gen_keys(Some(seed))
    }
}

impl<O: SignatureScheme + Clone, F: SignatureScheme> SignatureScheme for Sphincs<O, F>
    where <O as SignatureScheme>::Public: AsRef<[u8]> {
    type Private = U256;
    type Public = U256;
    type Signature = ();

    fn gen_keys(&self, seed: Option<U256>) -> (Self::Private, Self::Public) {
        let private = match seed {
            None => StdRng::from_entropy().gen(),
            Some(seed) => StdRng::from_seed(seed).gen(),
        };

        let public = self.get_sub_tree_keys(private, &Integer::new()).1;

        (private, public)
    }

    fn sign(&self, msg: &[u8], private: &Self::Private) -> Self::Signature {
        let num_sub_tree_leaves = Integer::from(1) << self.sub_tree_height as u32;
        let num_leaf_trees = num_sub_tree_leaves.clone().pow(self.depth as u32);
        let mut rand = RandState::new(); // Is this safe?
        let mut leaf_tree_idx = Integer::random_below(num_leaf_trees.clone(), &mut rand);
        leaf_tree_idx = leaf_tree_idx + (num_leaf_trees - 1) / (num_sub_tree_leaves - 1);

        let (fts_private, fts_public) = self.get_fts_keys(*private, &leaf_tree_idx);
        let fts_sig = self.fts_scheme.sign(msg, &fts_private);
    }

    fn verify(&self, msg: &[u8], public: &Self::Public, sig: &Self::Signature) -> bool {
        unimplemented!()
    }
}