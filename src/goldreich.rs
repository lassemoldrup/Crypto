use getrandom::getrandom;

use crate::SignatureScheme;
use crate::u256::{U256, hash_pair};
use rand_hc::Hc128Rng;
use rand::{SeedableRng, Rng};

pub struct Signature<O: SignatureScheme> {
    leaf_idx: usize,
    path: Box<[(O::Public, O::Public, O::Signature)]>,
}


pub struct Goldreich<O> {
    tree_height: usize,
    ots_scheme: O,
}

impl<O: SignatureScheme> Goldreich<O> {
    fn new(tree_height: usize, ots_scheme: O) -> Self {
        assert!(tree_height >= 1);

        Self {
            tree_height, ots_scheme
        }
    }
}

impl<'a, O: SignatureScheme> SignatureScheme for Goldreich<O>
    where <O as SignatureScheme>::Public: AsRef<[u8]> + Clone + PartialEq {
    type Private = U256;
    type Public = (O::Public, O::Signature);
    type Signature = Signature<O>;

    fn gen_keys(&self, seed: Option<U256>) -> (Self::Private, Self::Public) {
        let mut private = U256::new();
        match seed {
            None => getrandom(private.as_mut_bytes()).unwrap(),
            Some(seed) => private = seed,
        }

        let mut rng = Hc128Rng::from_seed(*private.as_ref());
        let root_seed = U256::from(rng.gen::<[u8; 32]>());
        let left_child_seed = U256::from(rng.gen::<[u8; 32]>());
        let right_child_seed = U256::from(rng.gen::<[u8; 32]>());
        let root = self.ots_scheme.gen_keys(Some(root_seed));
        let left_public = self.ots_scheme.gen_keys(Some(left_child_seed)).1;
        let right_public = self.ots_scheme.gen_keys(Some(right_child_seed)).1;

        let hash = hash_pair(left_public.as_ref(), right_public.as_ref());
        let sig = self.ots_scheme.sign(hash.as_ref(), &root.0);

        let public = (root.1, sig);

        (private, public)
    }

    fn sign(&self, msg: &[u8], private: &Self::Private) -> Self::Signature {
        let num_leaves = 1 << self.tree_height;
        let tree_size = num_leaves * 2 - 1;

        let mut rng = Hc128Rng::from_seed(*private.as_ref());

        let tree: Vec<_> = (0..tree_size)
            .map(|_| {
                let seed = U256::from(rng.gen::<[u8; 32]>());
                self.ots_scheme.gen_keys(Some(seed))
            })
            .collect();

        rng = Hc128Rng::from_entropy();
        let leaf_idx = rng.gen_range(num_leaves-1..tree_size);
        let leaf = &tree[leaf_idx];
        let leaf_sig = self.ots_scheme.sign(msg, &leaf.0);

        let parent_idx = (leaf_idx - 1) / 2;
        let left_sibling = &tree[parent_idx * 2 + 1];
        let right_sibling = &tree[parent_idx * 2 + 2];

        let mut path = Vec::new();
        path.push((left_sibling.1.clone(), right_sibling.1.clone(), leaf_sig));

        let mut idx = (leaf_idx - 1) / 2;
        let mut hash = hash_pair(left_sibling.1.as_ref(), right_sibling.1.as_ref());
        while idx != 0 {
            let node = &tree[idx];

            let parent_idx = (idx - 1) / 2;
            let left_sibling = &tree[parent_idx * 2 + 1];
            let right_sibling = &tree[parent_idx * 2 + 2];

            let sig = self.ots_scheme.sign(hash.as_ref(), &node.0);
            path.push((left_sibling.1.clone(), right_sibling.1.clone(), sig));

            idx = parent_idx;
            hash = hash_pair(left_sibling.1.as_ref(), right_sibling.1.as_ref());
        }

        Signature {
            leaf_idx,
            path: path.into_boxed_slice(),
        }
    }

    fn verify(&self, msg: &[u8], public: &Self::Public, sig: &Self::Signature) -> bool {
        let mut idx = sig.leaf_idx;
        let mut hash: Box<[u8]> = msg.into();
        for (left_sibling, right_sibling, sig) in sig.path.iter() {
            let node = if idx % 2 == 0 {
                // node is a right child
                right_sibling
            } else {
                // node is a left child
                left_sibling
            };

            if !self.ots_scheme.verify(&hash, node, sig) {
                return false;
            }

            hash = hash_pair(left_sibling.as_ref(), right_sibling.as_ref()).as_ref()[..].into();
            idx = (idx - 1) / 2;
        }

        self.ots_scheme.verify(&hash, &public.0, &public.1)
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::lamport::Lamport;

    #[test]
    fn it_works() {
        let msg1 = b"My OS update";
        let msg2 = b"My important message";

        let lamport = Lamport::new(64);
        let goldreich = Goldreich::new(5, lamport);

        let (private, public) = goldreich.gen_keys(None);

        let sig = goldreich.sign(msg1, &private);
        assert!(goldreich.verify(msg1, &public, &sig));

        let sig = goldreich.sign(msg2, &private);
        assert!(goldreich.verify(msg2, &public, &sig));

        assert!(!goldreich.verify(msg1, &public, &sig));
    }
}