pub mod util;
pub mod lamport;
pub mod goldreich;
pub mod merkle;
pub mod sphincs;
pub mod winternitz;
pub mod horst;

pub type U256 = [u8; 32];

pub trait SignatureScheme {
    type Private;
    type Public;
    type Signature;

    fn gen_keys(&self, seed: Option<U256>) -> (Self::Private, Self::Public);

    fn sign(&self, msg: &[u8], private: &Self::Private) -> Self::Signature;

    fn verify(&self, msg: &[u8], public: &Self::Public, sig: &Self::Signature) -> bool;
}