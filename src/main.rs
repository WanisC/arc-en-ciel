mod reduction;
use sha3::{Digest, Sha3_256};
use std::{hash, io::Write, ops::{Add, Sub}};
use rayon::prelude::*;

struct Password {
    password: String,
}

impl Add<u64> for Password {
    type Output = Password;

    fn add(self, offset: u64) -> Password {
        let mut password = self.to_b64();

        let mut carry = offset;
        for i in (0..7).rev() {
            let sum = password[i] + carry;
            password[i] = sum % 64;
            carry = sum / 64;
            if carry == 0 {
                break;
            }
        }

        Password::from_b64(password)
    }
}

impl Sub<u64> for Password {
    type Output = Password;

    fn sub(self, offset: u64) -> Password {
        let mut password = self.to_b64();

        let mut carry = offset;
        for i in (0..7).rev() {
            let sum: i64 = password[i] as i64 - carry as i64;
            if sum < 0 {
                password[i] = (64 as i64 + sum) as u64;
                carry = 1;
            } else {
                password[i] = sum as u64;
                carry = 0;
                break;
            }
        }

        Password::from_b64(password)
    }
}

impl Password {
    fn to_b64(&self) -> Vec<u64> {
        self.password.clone().into_bytes().into_par_iter().map(|c| 
            match c {
                48..=57 => c - 48,
                65..=90 => c - 29,
                97..=122 => c - 87,
                33 => 62,
                42 => 63,
                _ => c,
            } as u64
        ).collect::<Vec<u64>>()
    }

    fn from_b64(b64: Vec<u64>) -> Password {
        let password = b64.into_par_iter().map(|c| 
            match c {
                0..=9 => c + 48,
                10..=35 => c + 87,
                36..=61 => c + 29,
                62 => 33,
                63 => 42,
                _ => c,
            } as u8
        ).map(|c| c as char).collect::<String>();
        Password { password }
    }
}

fn main() {
    // let mut hasher = Sha3_256::new();
    (0..8).into_par_iter().for_each(|i| {
        // Open a file
        let path = format!("./output/{}.txt", i);
        let mut file = std::fs::File::create(path).unwrap(); 

        let mut hasher = Sha3_256::new();
        let mut password = Password { password: "0000000".to_string() } + (64_u64.pow(6) * 8 * i);
        for _ in 0..64_u64.pow(6) * 8 / 100 {
            let mut password_tmp = password.password.clone();
            for offset in 0..100 {
                hasher.update(password_tmp.clone());
                let hash = hasher.finalize_reset().to_vec();
                password_tmp = reduction::reduction(&hash, offset);
            }
            let buf = format!("{}-{}\n", password.password, password_tmp);
            file.write_all(buf.as_bytes()).unwrap();
            password = password + 100;
        }
    });
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reduction() {
        let hash: Vec<u8> = vec![0; 32];
        let password = reduction::reduction(&hash, 0);
        assert_eq!(password, "AAAAAAA");
    }

    #[test]
    fn test_add() {
        let password = Password { password: "8000000".to_string() };
        let password = password + 1;
        assert_eq!(password.password, "8000001");
    }

    #[test]
    fn test_add_with_carry() {
        let password = Password { password: "8000009".to_string() };
        let password = password + 2;
        assert_eq!(password.password, "800000b");
    }

    #[test]
    fn test_sub() {
        let password = Password { password: "8000001".to_string() };
        let password = password - 1;
        assert_eq!(password.password, "8000000");
    }

    #[test]
    fn test_sub_with_carry() {
        let password = Password { password: "800000b".to_string() };
        let password = password - 2;
        assert_eq!(password.password, "8000009");
    }
}

