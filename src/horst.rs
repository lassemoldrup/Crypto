use crate::{SignatureScheme, U256};
use rand::prelude::{StdRng, SeedableRng, RngCore};
use crate::util::{hash, hash_pair, floored_log};
use rug::Integer;
use rug::integer::Order;

pub struct Signature {
    sk: U256,
    path: Box<[U256]>,
}


pub struct Horst {
    height: usize,      // tau
    num_leaves: usize,  // t
    x: usize,           // x
    k: usize,           // k
}

impl Horst {
    pub fn new(height: usize, k: usize) -> Self {
        let num_leaves = 1 << height;
        let x = floored_log(k) + 1; // close enough
        Self {
            height, num_leaves, k, x
        }
    }

    fn get_node(private: &<Self as SignatureScheme>::Private, height: usize, idx: usize) -> U256 {
        if height == 0 {
            return hash(private[idx]);
        }

        let left = Self::get_node(private, height - 1, idx * 2);
        let right = Self::get_node(private, height - 1, idx * 2 + 1);

        hash_pair(left, right)
    }

    fn get_path(&self, private: &<Self as SignatureScheme>::Private, leaf_idx: usize) -> Box<[U256]> {
        let path_len = self.height - self.x;

        let mut path = Vec::with_capacity(path_len);
        let mut idx = leaf_idx;
        for height in 0..path_len {
            let sibling_idx = if idx % 2 == 0 {
                idx + 1
            } else {
                idx - 1
            };
            path.push(Self::get_node(private, height, sibling_idx));

            idx /= 2;
        }

        path.into_boxed_slice()
    }

    // TODO: Is it OK to just return zeros, if msg too short?
    fn transform_msg(&self, msg: &[u8]) -> Box<[usize]> {
        let mut transformed = vec![0; self.k].into_boxed_slice();
        let mut msg = Integer::from_digits(msg, Order::Lsf);
        for m in transformed.iter_mut() {
            *m = msg.mod_u(self.height as u32) as usize;
            msg /= self.height as u32;
        }

        transformed
    }

    fn get_root_from_top_nodes(&self, top_nodes: &[U256]) -> U256 {
        fn inner(top_nodes_height: usize, top_nodes: &[U256], height: usize, idx: usize) -> U256 {
            if height == top_nodes_height {
                return top_nodes[idx];
            }

            let left = inner(top_nodes_height, top_nodes, height - 1, idx * 2);
            let right = inner(top_nodes_height, top_nodes, height - 1, idx * 2 + 1);

            hash_pair(left, right)
        }

        inner(self.height - self.x, top_nodes, self.height, 0)
    }
}

impl SignatureScheme for Horst {
    type Private = Box<[U256]>;
    type Public = U256;
    type Signature = (Box<[Signature]>, Box<[U256]>);

    fn gen_keys(&self, seed: Option<U256>) -> (Self::Private, Self::Public) {
        let mut rng = match seed {
            None => StdRng::from_entropy(),
            Some(seed) => StdRng::from_seed(seed),
        };

        let mut private = vec![[0; 32]; self.num_leaves].into_boxed_slice();
        for sk in private.iter_mut() {
            rng.fill_bytes(sk);
        }

        let public = Self::get_node(&private, self.height, 0);

        (private, public)
    }

    fn sign(&self, msg: &[u8], private: &Self::Private) -> Self::Signature {
        assert!(msg.len() * 8 <= self.k * self.height);

        let msg = self.transform_msg(msg);

        let mut signature = Vec::with_capacity(self.k);
        for &m in msg.iter() {
            let sk = private[m];
            let path = self.get_path(private, m);
            let sig = Signature {
                sk,
                path
            };
            signature.push(sig);
        }

        let top_nodes_len = 1 << self.x;
        let top_nodes_height = self.height - self.x;
        let top_nodes = (0..top_nodes_len)
            .map(|i| Self::get_node(private, top_nodes_height, i))
            .collect();

        (signature.into_boxed_slice(), top_nodes)
    }

    fn verify(&self, msg: &[u8], public: &Self::Public, sig: &Self::Signature) -> bool {
        let msg = self.transform_msg(msg);
        let (signature, top_nodes) = sig;

        for (&m, sig) in msg.iter().zip(signature.iter()) {
            let mut idx = m;
            let mut node = hash(sig.sk);
            for &sibling in sig.path.iter() {
                node = if idx % 2 == 0 {
                    hash_pair(node, sibling)
                } else {
                    hash_pair(sibling, node)
                };

                idx /= 2;
            }

            if node != top_nodes[idx] {
                return false;
            }
        }

        self.get_root_from_top_nodes(top_nodes) == *public
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let msg1 = b"My OS update";
        let msg2 = b"My important message";

        let horst = Horst::new(16, 32);

        let (private, public) = horst.gen_keys(None);

        let sig = horst.sign(msg1, &private);
        assert!(horst.verify(msg1, &public, &sig));

        let sig = horst.sign(msg2, &private);
        assert!(horst.verify(msg2, &public, &sig));

        assert!(!horst.verify(msg1, &public, &sig));
    }
}