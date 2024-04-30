//! Module dedicated to the reduction function used in the algorithm.

/// Function that reduces a hash to a password.
/// # Arguments
/// * `hash` - A reference to a vector of bytes representing the hash to reduce.
/// * `offset` - The offset to apply to the hash.
/// * `password_length` - The length of the password to generate.
/// # Returns
/// A string representing the password generated from the hash.
pub fn reduction(hash: &Vec<u8>, offset: u16, password_length: usize) -> String {
    let mut password: Vec<u8> = Vec::new(); // The password to generate

    let j = offset / 64;
    let offset = offset % 64;
    // 0 <= i < password_length
    for i in 0..(password_length as u16) {
        password.push(((hash[((i + j) % 32) as usize] as u16 + offset) % 64) as u8);
    }

    // For each character in the password, convert it to the corresponding character
    password.iter_mut().for_each(|x| {
        match x {
            0..=25 => *x += 65,     // A-Z
            26..=51 => *x += 71,    // a-z
            52..=61 => *x -= 4,     // 0-9
            62 => *x = 33,          // !
            63 => *x = 42,          // *
            _ => panic!("Invalid character"), // should never happen
        }
    });
    return password.iter().map(|x| *x as char).collect();
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha3::{Digest, Sha3_256};

    #[test]
    fn test_reduction() {
        let mut hasher = Sha3_256::new();
        hasher.update("m0000Qa");
        let hash = hasher.finalize().to_vec();
        
        println!("{:?}", reduction(&hash, 0, 7));
    }
}