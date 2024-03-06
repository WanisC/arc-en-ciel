use rayon::prelude::*;
use std::ops::{Add, Sub};

#[derive(Clone, Debug)]
pub struct Password {
    pub password: String,
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
        let mut offset = offset as i128;
        for i in (0..7).rev() {
            let sum: i128 = password[i] as i128 - offset;
            if sum < 0 {
                password[i] = ((64 - (sum.abs() & 63)) & 63) as u64;
                offset = (sum.abs() - 1) / 64 + 1;
            } else {
                password[i] = sum as u64;
                break;
            }
        }

        Password::from_b64(password)
    }
}

impl PartialEq for Password {
    fn eq(&self, other: &Password) -> bool {
        self.password == other.password
    }
}

impl PartialOrd for Password {
    fn partial_cmp(&self, other: &Password) -> Option<std::cmp::Ordering> {
        let password = self.to_b64().iter().fold(0, |acc, x| acc * 64 + x);
        password.partial_cmp(&other.to_b64().iter().fold(0, |acc, x| acc * 64 + x))
    }
}

impl Password {
    fn to_b64(&self) -> Vec<u64> {
        self.password.clone().into_bytes().into_par_iter().map(|c| 
            match c {
                48..=57 => c - 48,
                65..=90 => c - 55,
                97..=122 => c - 61,
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
                10..=35 => c + 55,
                36..=61 => c + 61,
                62 => 33,
                63 => 42,
                _ => c,
            } as u8
        ).map(|c| c as char).collect::<String>();
        Password { password }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let password = Password { password: "80000a0".to_string() };
        let password = password - 64;
        assert_eq!(password.password, "8000090");
    }

    #[test]
    fn test_sub_complex() {
        for i in 0..1000 {
            let password = Password { password: "800000!".to_string() };
            let password = password + i;
            println!("{:?}", password.password);
            let password = password - i;
            assert_eq!(password.password, "800000!");
        }
    }

    #[test]
    fn test_eq() {
        let password = Password { password: "8000000".to_string() };
        let password2 = Password { password: "8000000".to_string() };
        assert_eq!(password == password2, true);
    }

    #[test]
    fn test_gt() {
        let password = Password { password: "8020000".to_string() };
        let password2 = Password { password: "800!000".to_string() };
        assert_eq!(password > password2, true);
    }

    #[test]
    fn test_lt() {
        let password = Password { password: "802000z".to_string() };
        let password2 = Password { password: "802000!".to_string() };
        assert_eq!(password < password2, true);
    }
}