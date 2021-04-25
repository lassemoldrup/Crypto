use crate::{SignatureScheme, U256};
use rand::prelude::{StdRng, SeedableRng, RngCore};
use crate::hash::{hash, hash_pair};
use rug::Integer;
use rug::integer::Order;

pub struct Signature {
    leaf_idx: usize,
    sk: U256,
    path: Box<[U256]>,
}


pub struct Horst {
    height: usize,      // tau
    num_leaves: usize,  // t
    k: usize,           // k
}

impl Horst {
    pub fn new(height: usize, k: usize) -> Self {
        let num_leaves = 1 << height;
        Self {
            height, num_leaves, k
        }
    }

    fn get_node(private: &Self::Private, height: usize, idx: usize) -> U256 {
        if height == 0 {
            return hash(private[idx]);
        }

        let left = Self::get_node(private, height + 1, idx * 2);
        let right = Self::get_node(private, height + 1, idx * 2 + 1);

        hash_pair(left, right)
    }

    // TODO: Is it OK to just return zeros, if msg too short?
    fn transform_msg(&self, msg: &[u8]) -> Box<[u32]> {
        let mut transformed = vec![0; self.k].into_boxed_slice();
        let mut msg = Integer::from_digits(msg, Order::Lsf);
        for m in transformed.iter_mut() {
            *m = msg.mod_u(self.height as u32);
            msg /= self.height;
        }

        transformed
    }
}

impl SignatureScheme for Horst {
    type Private = Box<[U256]>;
    type Public = U256;
    type Signature = Signature;

    fn gen_keys(&self, seed: Option<U256>) -> (Self::Private, Self::Public) {
        let mut rng = match seed {
            None => StdRng::from_entropy(),
            Some(seed) => StdRng::from_seed(seed),
        };

        let mut private = vec![[0; 32]; self.t].into_boxed_slice();
        for sk in private.iter_mut() {
            rng.fill_bytes(sk);
        }

        let public = Self::get_node(&private, self.height, 0);

        (private, public)
    }

    fn sign(&self, msg: &[u8], private: &Self::Private) -> Self::Signature {
        assert!(msg.len() * 8 <= self.k * self.height);

        todo!()
    }

    fn verify(&self, msg: &[u8], public: &Self::Public, sig: &Self::Signature) -> bool {
        todo!()
    }
}