pub fn reduction(hash: &Vec<u8>, offset: u16) -> String {
    let mut password: Vec<u8> = Vec::new();

    let j = offset / 64;
    let offset = offset % 64;
    for i in 0..7 {
        password.push(((hash[((i + j) % 32) as usize] as u16 + offset) % 64) as u8);
    }

    password.iter_mut().for_each(|x| {
        match x {
            0..=25 => *x += 65, // A-Z
            26..=51 => *x += 71, // a-z
            52..=61 => *x -= 4, // 0-9
            62 => *x = 33, // !
            63 => *x = 42, // *
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
        hasher.update("0000000");
        let hash = hasher.finalize().to_vec();

        assert_eq!(reduction(&hash, 0), "ZnjbHCA");
    }
}