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