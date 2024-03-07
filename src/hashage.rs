//! Hashing module

use std::collections::HashMap;

/// SHA-3 struct
#[derive(Debug)]
pub struct Sha3 {
    pub password: String,
    l: usize, // will be 6 for Keccak (à supprimer ?)
    pub b: i32, // block size (b = r + c)
    pub c: i32, // extra block size for more security/operations (SHA-3 norm: c = 2*fingerprint) 
    pub r: i32, // rate of bits absorbed by the sponge (r = b - c)
    pub fingerprint: i32,
}

impl Sha3 {
    /// Create a new SHA-3 instance
    pub fn new(password: &str, block: Option<i32>, fingerprint: i32) -> Sha3 {

        // Fingerprint values for each block size
        let mut fingerprint_values = HashMap::new();
        fingerprint_values.insert(224, 1152);
        fingerprint_values.insert(256, 1088);
        fingerprint_values.insert(384, 832);
        fingerprint_values.insert(512, 576);

        // If the block size is provided, we use it
        match block {
            Some(b) => Sha3 {
                password: password.to_string(),
                l: 6,
                b: b + 2*fingerprint,
                c: 2*fingerprint,
                r: b,
                fingerprint,
            },
            // If not, we use the default block size for the fingerprint
            None => {
                if let Some(&r) = fingerprint_values.get(&fingerprint) { // If we are able to recover the block size for the fingerprint
                    Sha3 {
                        password: password.to_string(),
                        l: 6,
                        b: r + 2*fingerprint,
                        c: 2*fingerprint,
                        r,
                        fingerprint,
                    }
                } else { // If not, we panic
                    panic!("Invalid fingerprint size");
                }
            }
        }
    }

    /// Will check if the binary password need a padding
    /// If so, it will add the padding to the binary password
    #[allow(dead_code)]
    fn preprocessing(&self, password_bin: &mut String) -> String {
        // Recover the original length of the binary password in bits
        let original_length_bits = password_bin.len() as i32;
        // Recover the padding length
        let padding_length = self.r - (original_length_bits % self.r);
        password_bin.push('1'); // Add the padding start bit "1"
        // Add the minimum number of "0" bits to make the length of the message a multiple of r
        for _ in 0..padding_length-2 { // -2 because we already added the "1" bit and we will also add the last "1" bit after the loop
            password_bin.push('0');
        }
        password_bin.push('1'); // Add the padding end bit "1"

        println!("Binary length with padding: {}", password_bin.len());
        println!("Binary password: {}", password_bin);

        password_bin.to_string()
    }

    #[allow(dead_code)]
    fn sponge(&self, password: &String) {
        println!("Songe paramters: {}", password);
    }

    /// Hashing function using the SHA-3 algorithm
    #[allow(dead_code)]
    pub fn sha_3(&self) {
        // Message pre-processing (conversion to binary)
        let mut password_bin = String::new();
        for c in self.password.chars() {
            password_bin.push_str(&format!("{:08b}", c as u8));
        }

        // Message pre-processing (conversion to binary -> adding padding if necessary -> return password in binary)
        self.preprocessing(&mut password_bin);

        self.sponge(&password_bin);

    }


}

#[cfg(test)]
mod tests {
    use super::*;

    // Test the creation of a new SHA-3 instance with a block size
    #[test]
    fn test_sha_3_new_with_block() {
        let sha_3: Sha3 = Sha3::new("password", Some(1088), 256);
        assert_eq!(sha_3.l, 6);
        assert_eq!(sha_3.b, 1088 + 2*256);
        assert_eq!(sha_3.c, 2*256);
        assert_eq!(sha_3.r, 1088);
        assert_eq!(sha_3.fingerprint, 256);
    }

    // Test the creation of a new SHA-3 instance without a block size
    #[test]
    fn test_sha_3_new_without_block() {
        let sha_3: Sha3 = Sha3::new("password", None, 256);
        assert_eq!(sha_3.l, 6);
        assert_eq!(sha_3.b, 1088 + 2*256);
        assert_eq!(sha_3.c, 2*256);
        assert_eq!(sha_3.r, 1088);
        assert_eq!(sha_3.fingerprint, 256);
    }

    // Test the pre-processing of the binary password (with padding)
    #[test]
    fn test_sha_3_prepocessing() {
        let sha_3 = Sha3::new("password", None, 256);
        let password = String::from("password123");
        let mut password_bin = String::new();
        for c in password.chars() {
            password_bin.push_str(&format!("{:08b}", c as u8));
        }
        let result = sha_3.preprocessing(&mut password_bin);
        assert_eq!(result.len(), 1088);
    }

    // Test the pre-processing of the binary password (without padding)
    #[test]
    #[should_panic]
    fn test_sha_3_prepocessing_no_padding() {
        unimplemented!("Not implemented yet")
    }
}