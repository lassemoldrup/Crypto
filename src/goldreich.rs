use getrandom::getrandom;

use rug::Integer;
use rug::integer::Order;
use rug::rand::RandState;

use crate::{SignatureScheme, U256};
use crate::hash::hash_pair;

pub struct Signature<O: SignatureScheme> {
    leaf_idx: Integer,
    path: Box<[(O::Public, O::Public, O::Signature)]>,
}


pub struct Goldreich<O> {
    tree_height: usize,
    ots_scheme: O,
}

impl<O: SignatureScheme> Goldreich<O>
    where <O as SignatureScheme>::Public: AsRef<[u8]> + Clone + PartialEq {
    fn get_node(&self, private: <Self as SignatureScheme>::Private, idx: &Integer) -> (O::Private, O::Public) {
        let node_seed = hash_pair(&private, &idx.to_digits(Order::Lsf));
        self.ots_scheme.gen_keys(Some(node_seed))
    }
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
        let mut private = [0; 32];
        match seed {
            None => getrandom(&mut private).unwrap(),
            Some(seed) => private = seed,
        }

        let root = self.get_node(private, &Integer::from(0));
        let left_public = self.get_node(private, &Integer::from(1)).1;
        let right_public = self.get_node(private, &Integer::from(2)).1;

        let hash = hash_pair(left_public, right_public);
        let sig = self.ots_scheme.sign(&hash, &root.0);
        let public = (root.1, sig);

        (private, public)
    }

    fn sign(&self, msg: &[u8], private: &Self::Private) -> Self::Signature {
        let num_leaves = Integer::from(1) << self.tree_height as u32;
        let mut rand = RandState::new(); // Is this safe?
        let mut leaf_idx = Integer::random_below(num_leaves.clone(), &mut rand);
        leaf_idx = leaf_idx + num_leaves - 1;

        let mut path = Vec::new();
        let mut idx = leaf_idx.clone();
        let mut hash: Box<[u8]> = msg.into();
        while idx != 0 {
            let node = self.get_node(*private, &idx);

            let parent_idx = (idx - 1) / 2;
            let tmp = Integer::from(&parent_idx * 2);
            let left_sibling = self.get_node(*private, &Integer::from(&tmp + 1));
            let right_sibling = self.get_node(*private, &(tmp + 2));

            let sig = self.ots_scheme.sign(&hash, &node.0);
            path.push((left_sibling.1.clone(), right_sibling.1.clone(), sig));

            idx = parent_idx;
            hash = hash_pair(left_sibling.1, right_sibling.1).into();
        }

        Signature {
            leaf_idx,
            path: path.into_boxed_slice(),
        }
    }

    fn verify(&self, msg: &[u8], public: &Self::Public, sig: &Self::Signature) -> bool {
        let mut idx = sig.leaf_idx.clone();
        let mut hash: Box<[u8]> = msg.into();
        for (left_sibling, right_sibling, sig) in sig.path.iter() {
            let node = if idx.is_even() {
                // node is a right child
                right_sibling
            } else {
                // node is a left child
                left_sibling
            };

            if !self.ots_scheme.verify(&hash, node, sig) {
                return false;
            }

            hash = hash_pair(left_sibling, right_sibling).into();
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
        let goldreich = Goldreich::new(100, lamport);

        let (private, public) = goldreich.gen_keys(None);

        let sig = goldreich.sign(msg1, &private);
        assert!(goldreich.verify(msg1, &public, &sig));

        let sig = goldreich.sign(msg2, &private);
        assert!(goldreich.verify(msg2, &public, &sig));

        assert!(!goldreich.verify(msg1, &public, &sig));
    }
}