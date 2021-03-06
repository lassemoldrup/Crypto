use sha2::{Sha256, Digest};

use crate::U256;
/*pub fn hash(data: &[u8]) -> U256 {
    Sha256::digest(data).into()
}*/

pub fn hash(data: impl AsRef<[u8]>) -> U256 {
    Sha256::digest(data.as_ref()).into()
}

pub fn hash_pair(left: impl AsRef<[u8]>, right: impl AsRef<[u8]>) -> U256 {
    let mut hasher = Sha256::new();
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}