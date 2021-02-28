use std::convert::{TryFrom, TryInto};
use std::array::TryFromSliceError;

#[derive(Copy, Clone, PartialEq)]
pub struct U256([u8; 32]);

impl U256 {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn into_bytes(self) -> [u8; 32] {
        self.0
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