use std::convert::{TryFrom, TryInto};
use std::array::TryFromSliceError;
use sha2::{Sha256, Digest};
use sha2::digest::FixedOutput;

#[derive(Copy, Clone, PartialEq)]
pub struct U256([u8; 32]);

impl U256 {
    pub fn new() -> Self {
        Self([0; 32])
    }

    pub fn as_mut_bytes(&mut self) -> &mut [u8; 32] {
        &mut self.0
    }

    pub fn into_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl AsRef<[u8; 32]> for U256 {
    fn as_ref(&self) -> &[u8; 32] {
        &self.0
    }
}

impl TryFrom<&[u8]> for U256 {
    type Error = TryFromSliceError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        value.try_into()
            .map(|data: [u8; 32]| Self::from(data))
    }
}

impl From<[u8; 32]> for U256 {
    fn from(data: [u8; 32]) -> Self {
        Self(data)
    }
}


pub fn hash(data: &[u8]) -> U256 {
    Sha256::digest(data).as_slice()
        .try_into()
        .unwrap()
}

pub fn hash_pair(left: &[u8], right: &[u8]) -> U256 {
    let mut sha = Sha256::new();
    sha.update(left);
    sha.update(right);
    let bytes: [u8; 32] = sha.finalize().into();
    bytes.into()
}