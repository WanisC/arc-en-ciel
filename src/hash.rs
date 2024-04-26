use core::fmt;

#[derive(Clone, PartialEq)]
pub struct Hash {
    pub hash: Vec<u8>,
}

impl Hash {
    pub fn new(hash: Vec<u8>) -> Hash {
        Hash { hash }
    }

    pub fn to_string(&self) -> String {
        let mut hash_str = String::new();
        for byte in &self.hash {
            hash_str.push_str(&format!("{:02x}", byte));
        }
        hash_str
    }
}

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

impl Into<String> for Hash {
    fn into(self) -> String {
        let mut hash_str = String::new();
        for byte in self.hash {
            hash_str.push_str(&format!("{:02x}", byte));
        }
        hash_str
    }
}

impl fmt::Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_string())
    }
}

impl fmt::Debug for Hash {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_string())
    }
}