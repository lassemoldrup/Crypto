use crate::{SignatureScheme, U256};
use crate::hash::{hash_pair, hash};
use rug::integer::Order;
use getrandom::getrandom;


pub struct Signature<O: SignatureScheme> {
    leaf_idx: usize,
    leaf_public: O::Public,
    leaf_sig: O::Signature,
    path: Box<[U256]>,
}


pub struct Merkle<O> {
    leaf_idx: usize,
    tree_height: usize,
    ots_scheme: O,
}

impl<O: SignatureScheme> Merkle<O>
    where <O as SignatureScheme>::Public: AsRef<[u8]> {
    fn get_ots_pair(&self, private: <Self as SignatureScheme>::Private, idx: usize) -> (O::Private, O::Public) {
        let node_seed = hash_pair(&private, &idx.to_digits(Order::Lsf));
        self.ots_scheme.gen_keys(Some(node_seed))
    }

    fn get_node(&self, private: <Self as SignatureScheme>::Private, height: usize, idx: usize) -> U256 {
        if height == self.tree_height {
            return hash(self.get_ots_pair(private, idx).1);
        }

        let left = self.get_node(private, height + 1, idx * 2);
        let right = self.get_node(private, height + 1, idx * 2 + 1);
        hash_pair(left, right)
    }
}

impl<O: SignatureScheme> SignatureScheme for Merkle<O>
    where <O as SignatureScheme>::Public: AsRef<[u8]> {
    type Private = U256;
    type Public = U256;
    type Signature = Signature<O>;

    fn gen_keys(&self, seed: Option<[u8; 32]>) -> (Self::Private, Self::Public) {
        let mut private = [0; 32];
        match seed {
            None => getrandom(&mut private).unwrap(),
            Some(seed) => private = seed,
        }

        (private, self.get_node(private, 0, 0))
    }

    fn sign(&self, msg: &[u8], private: &Self::Private) -> Self::Signature {
        let ots_pair = self.get_ots_pair(*private, self.leaf_idx);

        let leaf_sig = self.ots_scheme.sign(msg, &ots_pair.0);

        let path = (1..=self.tree_height).rev()
            .map(|h| )
    }

    fn verify(&self, msg: &[u8], public: &Self::Public, sig: &Self::Signature) -> bool {
        unimplemented!()
    }
}