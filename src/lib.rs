pub mod lamport;
pub mod goldreich;
pub mod u256;

pub trait SignatureScheme {
    type Private;
    type Public;
    type Signature;

    fn sign(msg: &[u8], private: &Self::Private) -> Self::Signature;

    fn verify(msg: &[u8], public: &Self::Public, sig: &Self::Signature) -> bool;
}