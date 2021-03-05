use crate::u256::U256;

pub mod lamport;
pub mod goldreich;
pub mod u256;

pub trait SignatureScheme {
    type Private;
    type Public;
    type Signature;

    fn gen_keys(&self, seed: Option<U256>) -> (Self::Private, Self::Public);

    fn sign(&self, msg: &[u8], private: &Self::Private) -> Self::Signature;

    fn verify(&self, msg: &[u8], public: &Self::Public, sig: &Self::Signature) -> bool;
}