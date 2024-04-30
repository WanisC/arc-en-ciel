use sha3::{Digest, Sha3_256};

/// Hash a password with SHA-3
pub fn hash_password(password: &str) -> Vec<u8> {
    let mut hasher = Sha3_256::new();
    hasher.update(password);
    hasher.finalize().to_vec()
}