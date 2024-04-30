//! Implements traits and methods for a hash type.

use core::fmt;

/// The hash type.
/// # Fields
/// * `hash` - The hash
/// # Note
/// The hash is stored as a vector of u8.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Hash {
    pub hash: Vec<u8>,
}

/// Implement the hash type.
impl Hash {
    /// Create a new hash instance.
    pub fn new(hash: Vec<u8>) -> Hash {
        Hash { hash }
    }

    /// Convert the hash to a string.
    pub fn to_string(&self) -> String {
        let mut hash_str = String::new();
        for byte in &self.hash {
            hash_str.push_str(&format!("{:02x}", byte));
        }
        hash_str
    }
}

/// Implement the From trait for the hash type.
impl From<String> for Hash {
    fn from(hash_str: String) -> Self {
        let mut hash_str = hash_str;
        let mut hash = Vec::new();
        for _ in 0..32 {
            let byte = u8::from_str_radix(&hash_str[0..2], 16).unwrap();
            hash.push(byte);
            hash_str = hash_str[2..].to_string();
        }
        Hash::new(hash)
    }
}

/// Implement the Into trait for the hash type.
impl Into<String> for Hash {
    fn into(self) -> String {
        let mut hash_str = String::new();
        for byte in self.hash {
            hash_str.push_str(&format!("{:02x}", byte));
        }
        hash_str
    }
}

/// Implement the Display trait for the hash type.
impl fmt::Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_string())
    }
}

/// Implement the Debug trait for the hash type.
impl fmt::Debug for Hash {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_string())
    }
}