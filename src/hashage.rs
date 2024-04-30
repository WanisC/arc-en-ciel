//! Hashing module

use std::collections::HashMap;
use crate::keccak::Keccak;
use byteorder::{ByteOrder, LittleEndian};
use clap::builder::Str;

/// SHA-3 struct
#[derive(Debug)]
pub struct Sha3 {
    pub password: String,
    pub password_bytes: String,   // password in binary
    pub b: i32,                 // block size (b = r + c)
    pub c: i32,                 // extra block size for more security/operations (SHA-3 norm: c = 2*fingerprint) 
    pub r: i32,                 // rate of bits absorbed by the sponge (r = b - c)
    pub fingerprint: i32,       // size of the fingerprint
}

impl Sha3 {
    /// Create a new SHA-3 instance
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

    /// Will check if the binary password need a padding
    /// If so, it will add the padding to the binary password
    pub fn preprocessing(&mut self) -> String { //TODO enlever le pub plus tard
        // Conversion to bytes
        self.password_bytes = self.string_to_lsb(self.password.as_str());
        self.password_bytes.push_str("0000011");
        // Padding
        let mut padding = String::new();
        let padding_len = self.r - (self.password_bytes.len() % self.r as usize) as i32 - 8;
        for _ in 0..padding_len {
            padding.push('0');
        }
        padding.push_str("10000000");
        self.password_bytes.push_str(&padding);
        self.password_bytes.clone()
    }
    
    pub fn string_to_lsb(&self, s: &str) -> String {
        let mut result = String::new();
        for c in s.chars() {
            result.push_str(&format!("{:08b}", c as u8));
        }
        result
    }
    /// Hashing function using the SHA-3 algorithm
    #[allow(dead_code)]
    pub fn sha_3(&mut self) {
        
        // Message pre-processing (conversion to binary -> adding padding if necessary -> return password in binary)
        self.password_bytes = self.preprocessing();

        // Sponge call (from the Keccak module)
        let mut keccak = Keccak::new(self);
        keccak.sponge();
        
    }
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
        sha_3.sha_3();
        println!("{:?}", sha_3);
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