//! Contains the implementation of the Keccak sponge function.

use crate::hashage::Sha3;

const STATE_INDEX: [usize; 5] = [3 as usize, 4 as usize, 0 as usize, 1 as usize, 2 as usize];

/// Keccak sponge function
/// 224 -> r = 1152
/// 256 -> r = 1088
/// 384 -> r = 832
/// 512 -> r = 576
#[derive(Debug)]
pub struct Keccak {
    password: String,
    f: i32,     // fingerprint
    b: i32,     // block size (b = r + c)
    r: i32,     // bitrate
    l: i32,     // log2(w) so since w = 64, l = 6
    w: usize,   // word size (by default 64)
    nr: i32,    // number of rounds (by default 24)
}

impl Keccak {

    /// Create a new Keccak instance
    pub fn new(obj: &Sha3) -> Keccak {
        Keccak {
            password: obj.password_bin.clone().to_string(),
            f: obj.fingerprint,
            b: obj.b,
            r: obj.r,
            l: 6,
            w: 64,
            nr: 24,
        }
    }

    /// Convert the password into a state array
    fn strings_to_state(&self, st : String) -> Vec<Vec<Vec<i32>>> {
        let mut statearray: Vec<Vec<Vec<i32>>> = vec![vec![vec![0; self.w]; 5]; 5];
        // Convert the password into a binary array
        let password_bin  = st
            .chars()
            .map(|c| c.to_digit(10).unwrap() as i32)
            .collect::<Vec<i32>>();

        // 0 <= x < 5
        for x in 0..5 {
            let x_state = STATE_INDEX[x];
            // 0 <= y < 5
            for y in 0..5 {
                let y_state = STATE_INDEX[y];
                // 0 <= z < w
                for z in 0..self.w {
                    if password_bin.len() <= self.w * (5 * y_state + x_state) + z { // case where we read all the bits of the password
                        break;
                    }
                    // A[x, y, z] = password_bin[w * (5 * y + x) + z
                    statearray[x_state][y_state][z] = password_bin[self.w * (5 * y_state + x_state) + z];
                }
            }
        }

        statearray
    }

    /// Convert the state array into a string
    fn state_to_strings(&self, statearray: &Vec<Vec<Vec<i32>>>) -> String {
        let mut password_bin = String::new();

        // 0 <= y < 5
        for y in 0..5 {
            let y_state = STATE_INDEX[y];
            // 0 <= x < 5
            for x in 0..5 {
                let x_state = STATE_INDEX[x];
                // 0 <= z < w
                for z in 0..self.w {
                    // S = A[0, 0, 0] || A[0, 0, 1] || ... || A[1, 0, 0] || A[1, 0, 1] || ... || A[4, 4, 63]
                    password_bin.push_str(&statearray[x_state][y_state][z].to_string());
                }
            }
        }

        password_bin
    }

    /// θ routine
    fn routine_theta(&self, statearray: &mut Vec<Vec<Vec<i32>>>) -> Vec<Vec<Vec<i32>>> {
        let mut c = vec![vec![0; self.w]; 5];
        let mut d = vec![vec![0; self.w]; 5];

        // 0 <= x < 5
        for x in 0..5 {
            let x_state: usize = STATE_INDEX[x];
            // 0 <= z < w
            for z in 0..self.w {
                c[x_state][z] = statearray[x_state][0][z] ^ statearray[x_state][1][z] ^ statearray[x_state][2][z] ^ statearray[x_state][3][z] ^ statearray[x_state][4][z];
            }
        }

        // 0 <= x < 5
        for x in 0..5 {
            let x_state = STATE_INDEX[x];
            // 0 <= z < w
            for z in 0..self.w {
                d[x_state][z] = c[((x_state as i32 - 1).rem_euclid(5)) as usize][z] ^ c[(x_state + 1).rem_euclid(5)][((z as i32 - 1).rem_euclid(self.w as i32)) as usize];
            }
        }

        // 0 <= x < 5
        for x in 0..5 {
            let x_state = STATE_INDEX[x];
            // 0 <= y < 5
            for y in 0..5 {
                let y_state = STATE_INDEX[y];
                // 0 <= z < w
                for z in 0..self.w {
                    statearray[x_state][y_state][z] = statearray[x_state][y_state][z] ^ d[x_state][z];
                }
            }
        }

        statearray.to_vec()
    }
    
    /// ρ routine
    fn routine_rho(&self, statearray: &mut Vec<Vec<Vec<i32>>>) -> Vec<Vec<Vec<i32>>> {
        let (mut x, mut y) = (1, 0);

        // 0 <= t <= 23
        for t in 0..=23 {
            // 0 <= z < w
            for z in 0..self.w {
                // A[x, y, z] = A[x, y, (z - (t + 1) * (t + 2) / 2) % w]
                let index = (z as i64 - (t + 1) * (t + 2) / 2) as usize;
                let positive_index = index.rem_euclid(self.w);
                statearray[x][y][z] = statearray[x][y][positive_index];
            }
            (x, y) = (y, (2 * x + 3 * y).rem_euclid(5));
        }

        statearray.to_vec()
    }

    /// π routine 
    fn routine_pi(&self, statearray: &mut Vec<Vec<Vec<i32>>>) -> Vec<Vec<Vec<i32>>> {
        // 0 <= x < 5
        for x in 0..5 {
            let x_state = STATE_INDEX[x];
            // 0 <= y < 5
            for y in 0..5 {
                let y_state = STATE_INDEX[y];
                // 0 <= z < w
                for z in 0..self.w {
                    statearray[x_state][y_state][z] = statearray[(x_state + 3 * y_state).rem_euclid(5)][x_state][z];
                }
            }
        }
        
        statearray.to_vec()
    }

    /// χ routine
    fn routine_chi(&self, statearray: &mut Vec<Vec<Vec<i32>>>) -> Vec<Vec<Vec<i32>>> {
        // 0 <= x < 5
        for x in 0..5 {
            let x_state = STATE_INDEX[x];
            // 0 <= y < 5
            for y in 0..5 {
                let y_state = STATE_INDEX[y];
                // 0 <= z < w
                for z in 0..self.w {
                    statearray[x_state][y_state][z] = statearray[x_state][y_state][z] ^ ((!statearray[(x_state + 1).rem_euclid(5)][y_state][z]) & statearray[(x_state + 2).rem_euclid(5)][y_state][z]);
                }
            }
        }
        
        statearray.to_vec()
    }
    
    /// ι routine
    fn routine_iota(&self, statearray: &mut Vec<Vec<Vec<i32>>>, round_index: i32) -> Vec<Vec<Vec<i32>>> {
        let mut rc = vec![0; self.w];

        // 0 <= j <= l
        for j in 0..=self.l {
            // RC[2^j - 1] = rc(j + 7 * round_index)
            rc[(2i32.pow(j as u32) - 1) as usize] = self.round_constant(j as i32 + 7 * round_index);
        }

        // 0 <= z < w
        for z in 0..self.w {
            statearray[0][0][z] = statearray[0][0][z] ^ rc[z];
        }

        statearray.to_vec()
    }

    /// Round constant function
    fn round_constant(&self, t: i32) -> i32 {
        if t.rem_euclid(255) == 0 {
            1
        } else {
            let mut r_vec = vec![1, 0, 0, 0, 0, 0, 0, 0];
            for _ in 1..=t.rem_euclid(255) {
                // a. R = 0 || R
                r_vec.insert(0, 0);

                // b. R[0] = R[0] ^ R[8]
                r_vec[0] ^= r_vec[7];

                // c. R[4] = R[4] ^ R[8]
                r_vec[4] ^= r_vec[7];

                // d. R[5] = R[5] ^ R[8]
                r_vec[5] ^= r_vec[7];

                // e. R[6] = R[6] ^ R[8]
                r_vec[6] ^= r_vec[7];

                // f. R = R[1..8]
                r_vec = r_vec[0..=7].to_vec();
            }

            r_vec[0]
        }      
    }
    
    fn round_index(&self, st_ar: &Vec<Vec<Vec<i32>>>, i_round : i32) -> Vec<Vec<Vec<i32>>> {
        let mut statearray = st_ar.to_vec();
        statearray = self.routine_theta(&mut statearray);
        statearray = self.routine_rho(&mut statearray);
        statearray = self.routine_pi(&mut statearray);
        statearray = self.routine_chi(&mut statearray);
        statearray = self.routine_iota(&mut statearray, i_round);
        statearray.to_vec()
    }

    fn keccak_p(&self, st : String) -> String {
        let mut statearray = self.strings_to_state(st);
        for i in 0..self.nr {
            statearray = self.round_index(&mut statearray, i);
        }
        self.state_to_strings(&statearray)
    }
    
    /// Sponge function
    pub fn sponge(&self) -> String {
        let r_usize = self.r as usize;
        let n = self.password.len() / r_usize;
        let c = self.b - self.r;
        let mut password_tab = vec![];
        let mut s = vec![];
        for _ in 0..self.b {
            s.push(0);
        }
        for i in 0..n {
            password_tab.push(self.password[i * r_usize..(i + 1) * r_usize].to_string() + &"0".repeat(c as usize));
        }
        for i in 0..n {
            for j in 0..r_usize {
                s[j] = s[j] ^ password_tab[i].chars().nth(j).unwrap().to_digit(10).unwrap() as i32;
            }
            let mut s_str = s.into_iter().map(|i| i.to_string()).collect::<String>();
            s_str = self.keccak_p(s_str);
            s = s_str.chars().map(|c| c.to_digit(10).unwrap() as i32).collect::<Vec<i32>>();
        }
        let mut z = "".to_string();
        z.push_str(&s[0..r_usize].iter().map(|i| i.to_string()).collect::<String>());  
        while z.len() <= self.f as usize {
            let mut s_str = s.into_iter().map(|i| i.to_string()).collect::<String>();
            s_str = self.keccak_p(s_str);
            s = s_str.chars().map(|c| c.to_digit(10).unwrap() as i32).collect::<Vec<i32>>();
            z.push_str(&s[0..r_usize].iter().map(|i| i.to_string()).collect::<String>());   
        }
        z[0..(self.f-1) as usize].to_string()
        
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    fn convert_to_hex_from_binary(binary: &str) -> String {
        let padding_count = 4 - binary.len() % 4;
    
        let padded_binary = if padding_count > 0 {
            ["0".repeat(padding_count), binary.to_string()].concat()
        } else {
            binary.to_string()
        };
    
        let mut counter = 0;
        let mut hex_string = String::new();
        while counter < padded_binary.len() {
            let converted = to_hex(&padded_binary[counter..counter + 4]);
            hex_string.push_str(converted);
            counter += 4;
        }
    
        hex_string
    }

    fn to_hex(b: &str) -> &str {
        match b {
            "0000" => "0",
            "0001" => "1",
            "0010" => "2",
            "0011" => "3",
            "0100" => "4",
            "0101" => "5",
            "0110" => "6",
            "0111" => "7",
            "1000" => "8",
            "1001" => "9",
            "1010" => "a",
            "1011" => "b",
            "1100" => "c",
            "1101" => "d",
            "1110" => "e",
            "1111" => "f",
            _ => "",
        }
    }

    #[test]
    // Test the creation of a new Keccak instance
    fn test_keccak_new() {
        let mut sha3 = Sha3::new("password", 256);
        sha3.password_bin = sha3.preprocessing();
        let keccak = Keccak::new(&sha3);
        println!("keccak: {:?}", keccak);
        assert_eq!(keccak.password, sha3.password_bin);
        assert_eq!(keccak.b, 1088 + 2*256);
        assert_eq!(keccak.nr, 24);
    }

    #[test]
    // Test the creation of a new Keccak instance with a block size
    fn test_keccak_new_with_block() {
        let mut sha3 = Sha3::new("password", 256);
        sha3.password_bin = sha3.preprocessing();
        let keccak = Keccak::new(&sha3);
        assert_eq!(keccak.password, sha3.password_bin);
        assert_eq!(keccak.b, 1088 + 2*256);
        assert_eq!(keccak.nr, 24);
    }

    #[test]
    // Test the creation of a new Keccak instance without a block size
    fn test_keccak_new_without_block() {
        let mut sha3 = Sha3::new("password", 256);
        sha3.password_bin = sha3.preprocessing();
        let keccak = Keccak::new(&sha3);
        assert_eq!(keccak.password, sha3.password_bin);
        assert_eq!(keccak.b, 1088 + 2*256);
        assert_eq!(keccak.nr, 24);
    }

    #[test]
    // Test the conversion of a string to a state array
    fn test_keccak_strings_to_state() {
        let mut sha3 = Sha3::new("password", 256);
        sha3.password_bin = sha3.preprocessing();
        let keccak = Keccak::new(&sha3);
        let statearray = keccak.strings_to_state(keccak.password.clone());
        assert_eq!(statearray.len(), 5);
        assert_eq!(statearray[0].len(), 5);
        assert_eq!(statearray[0][0].len(), 64);
    }

    #[test]
    // Test the conversion of a state array to a string
    fn test_keccak_state_to_strings() {
        let mut sha3 = Sha3::new("password", 256);
        sha3.password_bin = sha3.preprocessing();
        let keccak = Keccak::new(&sha3);
        let statearray = keccak.strings_to_state(keccak.password.clone());
        let password_bin = keccak.state_to_strings(&statearray);
        assert_eq!(password_bin.len(), 1600);
    }

    #[test]
    // Test the θ routine
    fn test_keccak_routine_theta() {
        let mut sha3 = Sha3::new("password", 256);
        sha3.password_bin = sha3.preprocessing();
        let keccak = Keccak::new(&sha3);
        let mut statearray = keccak.strings_to_state(keccak.password.clone());
        statearray = keccak.routine_theta(&mut statearray);
        println!("statearray.len(): {}", statearray.len());
        println!("statearray[0].len(): {}", statearray[0].len());
        println!("statearray[0][0].len(): {}", statearray[0][0].len());
        assert_eq!(statearray.len(), 5);
        assert_eq!(statearray[0].len(), 5);
        assert_eq!(statearray[0][0].len(), 64);
    }

    #[test]
    // Test the ρ routine
    fn test_keccak_routine_rho() {
        let mut sha3 = Sha3::new("password", 256);
        sha3.password_bin = sha3.preprocessing();
        let keccak = Keccak::new(&sha3);
        let mut statearray = keccak.strings_to_state(keccak.password.clone());
        statearray = keccak.routine_theta(&mut statearray);
        statearray = keccak.routine_rho(&mut statearray);
        assert_eq!(statearray.len(), 5);
        assert_eq!(statearray[0].len(), 5);
        assert_eq!(statearray[0][0].len(), 64);
    }

    #[test]
    // Test the π routine
    fn test_keccak_routine_pi() {
        let mut sha3 = Sha3::new("password", 256);
        sha3.password_bin = sha3.preprocessing();
        let keccak = Keccak::new(&sha3);
        let mut statearray = keccak.strings_to_state(keccak.password.clone());
        statearray = keccak.routine_theta(&mut statearray);
        statearray = keccak.routine_rho(&mut statearray);
        statearray = keccak.routine_pi(&mut statearray);
        assert_eq!(statearray.len(), 5);
        assert_eq!(statearray[0].len(), 5);
        assert_eq!(statearray[0][0].len(), 64);
    }

    #[test]
    // Test the χ routine
    fn test_keccak_routine_chi() {
        let mut sha3 = Sha3::new("password", 256);
        sha3.password_bin = sha3.preprocessing();
        let keccak = Keccak::new(&sha3);
        let mut statearray = keccak.strings_to_state(keccak.password.clone());
        statearray = keccak.routine_theta(&mut statearray);
        statearray = keccak.routine_rho(&mut statearray);
        statearray = keccak.routine_pi(&mut statearray);
        statearray = keccak.routine_chi(&mut statearray);
        assert_eq!(statearray.len(), 5);
        assert_eq!(statearray[0].len(), 5);
        assert_eq!(statearray[0][0].len(), 64);
    }
    
    #[test]
    // Test the χ routine (this test should return the same result as the following test)
    fn test_keccak_routine_iota() {
        let mut sha3 = Sha3::new("password", 256);
        sha3.password_bin = sha3.preprocessing();
        let keccak = Keccak::new(&sha3);
        let mut statearray = keccak.strings_to_state(keccak.password.clone());
        statearray = keccak.routine_theta(&mut statearray);
        statearray = keccak.routine_rho(&mut statearray);
        statearray = keccak.routine_pi(&mut statearray);
        statearray = keccak.routine_chi(&mut statearray);
        statearray = keccak.routine_iota(&mut statearray, 0);
        assert_eq!(statearray.len(), 5);
        assert_eq!(statearray[0].len(), 5);
        assert_eq!(statearray[0][0].len(), 64);
    }

    #[test]
    // Test of all the routines together we assume that n = 24
    fn test_sha_3_keccak() {
        let mut sha3 = Sha3::new("password", 256);
        sha3.password_bin = sha3.preprocessing();
        let keccak = Keccak::new(&sha3);
        let res = keccak.sponge();
        let res_hex = convert_to_hex_from_binary(&res);
        assert_eq!("c0067d4af4e87f00dbac63b6156828237059172d1bbeac67427345d6a9fda484", res_hex);

    }
    
    #[test]
    // Test the sponge function
    fn test_keccak_sponge() {
        let mut sha3 = Sha3::new("password", 256);
        sha3.password_bin = sha3.preprocessing();
        let keccak = Keccak::new(&sha3);
        keccak.sponge();
    }

    #[test]
    // Test the round constant function
    fn test_keccak_round_constant() {
        let mut sha3 = Sha3::new("password", 256);
        sha3.password_bin = sha3.preprocessing();
        let keccak = Keccak::new(&sha3);
        let rc = keccak.round_constant(2);
        println!("rc: {}", rc);
        assert_eq!(rc, 0);
    }
}