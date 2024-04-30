//! Hashing module

use std::collections::HashMap;
use crate::{hash::Hash, keccak::Keccak};

/// SHA-3 struct.  
/// # Arguments
/// * `password` - The password to hash
/// * `password_bytes` - The password in bytes
/// * `b` - The block size (b = r + c)
/// * `c` - Extra block size for more security/operations (SHA-3 norm: c = 2*fingerprint)
/// * `r` - Rate of bits absorbed by the sponge (r = b - c)
/// * `fingerprint` - Size of the fingerprint (224, 256, 384, 512)
#[derive(Debug)]
pub struct Sha3 {
    pub password: String,
    pub password_bytes: String,
    pub b: i32,
    pub c: i32,
    pub r: i32,
    pub fingerprint: i32,
}

/// Implementation of the SHA-3 struct.  
impl Sha3 {
    /// Create a new SHA-3 instance.
    /// # Arguments
    /// * `password` - The password to hash
    /// * `fingerprint` - The size of the fingerprint (224, 256, 384, 512)
    /// # Returns
    /// A new SHA-3 instance
    /// # Example
    /// ```
    /// let sha_3 = Sha3::new("password", 256);
    /// ```
    pub fn new(password: &str, fingerprint: i32) -> Sha3 {

        // Fingerprint values for each block size
        let mut fingerprint_values = HashMap::new();
        fingerprint_values.insert(224, 1152);
        fingerprint_values.insert(256, 1088);
        fingerprint_values.insert(384, 832);
        fingerprint_values.insert(512, 576);

        match fingerprint_values.get(&fingerprint) {
            // If a correct fingerprint is given, we use it
            Some(b) => Sha3 {
                password: password.to_string(),
                password_bytes: String::new(),
                b: b + 2*fingerprint,
                c: 2*fingerprint,
                r: *b,
                fingerprint,
            },
            // If not, we use the default fingerprint size (256 bits)
            None => {
                let b = fingerprint_values.get(&256).unwrap();
                Sha3 {
                    password: password.to_string(),
                    password_bytes: String::new(),
                    b: b + 2*fingerprint,
                    c: 2*fingerprint,
                    r: *b,
                    fingerprint,
                }
            }
        }
    }

    /// Pre-processing function for the SHA-3 algorithm.  
    /// It converts the password to bytes and adds padding.   
    /// Passwords are less than r bits long so there is a padding of 0s until the length of the password is a multiple of r.
    /// # Arguments
    /// * `self` - The SHA-3 instance
    /// # Example
    /// ```
    /// let mut sha_3 = Sha3::new("password", 256);
    /// sha_3.preprocessing();
    /// ```
    pub fn preprocessing(&mut self) {
        // Conversion to bytes
        self.password_bytes = self.string_to_lsb(self.password.as_str());
        // Adding the delimiter
        self.password_bytes.push_str("0000011");
        // Padding
        let mut padding = String::new();
        let padding_len = self.r - (self.password_bytes.len() % self.r as usize) as i32 - 8;
        for _ in 0..padding_len {
            padding.push('0');
        }
        // Adding the last delimiter
        padding.push_str("10000000");
        self.password_bytes.push_str(&padding);
    }

    /// Convert a string to a string of bits (LSB).
    /// # Arguments
    /// * `self` - The SHA-3 instance
    /// * `s` - The string to convert
    /// # Returns
    /// A string of bits.
    pub fn string_to_lsb(&self, s: &str) -> String {
        let mut result = String::new(); // Resulting string (initially empty)
        // For each character in the string, we convert it to binary and add it to the result
        for c in s.chars() {
            result.push_str(&format!("{:08b}", c as u8));
        }
        result
    }

    /// Hashing function using the SHA-3 algorithm.  
    /// It calls the preprocessing function and then the sponge function from the Keccak module.  
    /// The state is then converted to a string of bits.
    /// # Arguments
    /// * `self` - The SHA-3 instance
    /// # Returns
    /// The hashed password.
    pub fn sha_3(&mut self) -> String {
        // Message pre-processing (conversion to binary -> adding padding if necessary -> return password in binary)
        self.preprocessing();

        // Sponge call (from the Keccak module)
        let mut keccak: Keccak = Keccak::new(self);
        keccak.sponge();
        keccak.state_to_strings()
    }
}

/// Hash a password using the SHA-3 algorithm.
/// # Arguments
/// * `password` - The password to hash
/// * `fingerprint` - The size of the fingerprint (224, 256, 384, 512)
/// # Returns
/// The hashed password.
pub fn sha3_hash(password: &str, fingerprint: Option<i32>) -> Hash {
    let mut sha_3 = match fingerprint {
        Some(f) => Sha3::new(password, f),
        None => Sha3::new(password, 256),
    };
    Hash::from(sha_3.sha_3())

}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    // Test the creation of a new SHA-3 with 224 bits
    fn test_sha_3_new_224() {
        let sha_3 = Sha3::new("password", 224);
        assert_eq!(sha_3.b, 1152 + 2*224);
        assert_eq!(sha_3.c, 2*224);
        assert_eq!(sha_3.r, 1152);
        assert_eq!(sha_3.fingerprint, 224);
    }

    #[test]
    // Test the creation of a new SHA-3 with 256 bits
    fn test_sha_3_new_256() {
        let mut sha_3 = Sha3::new("password", 256);
        let res = sha_3.sha_3();
        println!("{:?}", res);
    }

    #[test]
    fn test_sha3() {
        let res = sha3_hash("password", None);
        println!("{:?}", res);
    }

    #[test]
    // Test the creation of a new SHA-3 with 384 bits
    fn test_sha_3_new_384() {
        let sha_3 = Sha3::new("password", 384);
        assert_eq!(sha_3.b, 832 + 2*384);
        assert_eq!(sha_3.c, 2*384);
        assert_eq!(sha_3.r, 832);
        assert_eq!(sha_3.fingerprint, 384);
    }

    #[test]
    // Test the creation of a new SHA-3 with 512 bits
    fn test_sha_3_new_512() {
        let sha_3 = Sha3::new("password", 512);
        assert_eq!(sha_3.b, 576 + 2*512);
        assert_eq!(sha_3.c, 2*512);
        assert_eq!(sha_3.r, 576);
        assert_eq!(sha_3.fingerprint, 512);
    }

    // Test the creation of a new SHA-3 instance with a block size
    #[test]
    fn test_sha_3_new_with_block() {
        let sha_3 = Sha3::new("password", 256);
        assert_eq!(sha_3.b, 1088 + 2*256);
        assert_eq!(sha_3.c, 2*256);
        assert_eq!(sha_3.r, 1088);
        assert_eq!(sha_3.fingerprint, 256);
    }

    // Test the creation of a new SHA-3 instance without a block size
    #[test]
    fn test_sha_3_new_without_block() {
        let sha_3 = Sha3::new("password", 256);
        assert_eq!(sha_3.b, 1088 + 2*256);
        assert_eq!(sha_3.c, 2*256);
        assert_eq!(sha_3.r, 1088);
        assert_eq!(sha_3.fingerprint, 256);
    }
}