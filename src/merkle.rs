use crate::{SignatureScheme, U256};
use crate::hash::{hash_pair, hash};
use bytemuck::bytes_of;
use rand::prelude::{Rng, SeedableRng, StdRng};

pub struct Signature<O: SignatureScheme> {
    leaf_idx: usize,
    leaf_public: O::Public,
    leaf_sig: O::Signature,
    path: Box<[U256]>,
}


pub struct Merkle<O> {
    tree_height: usize,
    ots_scheme: O,
}

impl<O: SignatureScheme> Merkle<O>
    where <O as SignatureScheme>::Public: AsRef<[u8]> {
    pub fn new(tree_height: usize, ots_scheme: O) -> Self {
        Self {
            tree_height,
            ots_scheme,
        }
    }

    fn get_ots_pair(&self, private: U256, idx: usize) -> (O::Private, O::Public) {
        let node_seed = hash_pair(&private, bytes_of(&idx));
        self.ots_scheme.gen_keys(Some(node_seed))
    }

    fn get_node(&self, private: U256, height: usize, idx: usize) -> U256 {
        if height == self.tree_height {
            return hash(self.get_ots_pair(private, idx).1);
        }

        let left = self.get_node(private, height + 1, idx * 2);
        let right = self.get_node(private, height + 1, idx * 2 + 1);
        hash_pair(left, right)
    }

    pub fn next_key(&self, mut private: <Self as SignatureScheme>::Private) -> Option<<Self as SignatureScheme>::Private> {
        private.1 += 1;
        (private.1 < 1 << self.tree_height).then(|| private)
    }
}

impl<O: SignatureScheme> SignatureScheme for Merkle<O>
    where <O as SignatureScheme>::Public: AsRef<[u8]> {
    type Private = (U256, usize);
    type Public = U256;
    type Signature = Signature<O>;

    fn gen_keys(&self, seed: Option<U256>) -> (Self::Private, Self::Public) {
        let private = match seed {
            None => StdRng::from_entropy().gen(),
            Some(seed) => StdRng::from_seed(seed).gen(),
        };

        ((private, 0), self.get_node(private, 0, 0))
    }

    fn sign(&self, msg: &[u8], private: &Self::Private) -> Self::Signature {
        let ots_pair = self.get_ots_pair(private.0, private.1);

        let leaf_sig = self.ots_scheme.sign(msg, &ots_pair.0);

        let path = (0..self.tree_height)
            .map(|h| {
                let idx = private.1 / (1 << h);
                if idx % 2 == 0 {
                    self.get_node(private.0, self.tree_height - h, idx + 1)
                } else {
                    self.get_node(private.0, self.tree_height - h, idx - 1)
                }
            })
            .collect();

        Signature {
            leaf_idx: private.1,
            leaf_public: ots_pair.1,
            leaf_sig,
            path,
        }
    }

    fn verify(&self, msg: &[u8], public: &Self::Public, sig: &Self::Signature) -> bool {
        if !self.ots_scheme.verify(msg, &sig.leaf_public, &sig.leaf_sig) {
            return false;
        }

        let root = sig.path.iter()
            .enumerate()
            .fold(hash(&sig.leaf_public), |acc, (h, sibling)| {
                let idx = sig.leaf_idx / (1 << h);
                if idx % 2 == 0 {
                    hash_pair(&acc, sibling)
                } else {
                    hash_pair(sibling, &acc)
                }
            });

        root == *public
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
        let merkle = Merkle::new(6, lamport);

        let (mut private, public) = merkle.gen_keys(None);

        let sig = merkle.sign(msg1, &private);
        assert!(merkle.verify(msg1, &public, &sig));

        private = merkle.next_key(private).unwrap();

        let sig = merkle.sign(msg2, &private);
        assert!(merkle.verify(msg2, &public, &sig));

        assert!(!merkle.verify(msg1, &public, &sig));
    }
}