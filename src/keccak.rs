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
            l: 6,
            w: 64,
            nr: 24,
        }
    }

    /// Convert the password into a state array
    fn strings_to_state(&self) -> Vec<Vec<Vec<i32>>> {
        let mut statearray: Vec<Vec<Vec<i32>>> = vec![vec![vec![0; self.w]; 5]; 5];

        // Convert the password into a binary array
        let password_bin  = self.password
            .chars()
            .map(|c| c.to_digit(10).unwrap() as i32)
            .collect::<Vec<i32>>();

        // 0 <= x < 5
        for x in 0..5 {
            let x = STATE_INDEX[x];
            // 0 <= y < 5
            for y in 0..5 {
                let y = STATE_INDEX[y];
                // 0 <= z < w
                for z in 0..self.w {
                    if password_bin.len() <= self.w * (5 * y + x) + z { // case where we read all the bits of the password
                        break;
                    }
                    // A[x, y, z] = password_bin[w * (5 * y + x) + z
                    statearray[x][y][z] = password_bin[self.w * (5 * y + x) + z];
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
            let y = STATE_INDEX[y];
            // 0 <= x < 5
            for x in 0..5 {
                let x = STATE_INDEX[x];
                // 0 <= z < w
                for z in 0..self.w {
                    // S = A[0, 0, 0] || A[0, 0, 1] || ... || A[1, 0, 0] || A[1, 0, 1] || ... || A[4, 4, 63]
                    password_bin.push_str(&statearray[x][y][z].to_string());
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
            let x = STATE_INDEX[x];
            // 0 <= z < w
            for z in 0..self.w {
                c[x][z] = statearray[x][0][z] ^ statearray[x][1][z] ^ statearray[x][2][z] ^ statearray[x][3][z] ^ statearray[x][4][z];
            }
        }

        // TODO vérifier par rapport au document NIST si (x + 4) % 5 et (z + 63) % w sont corrects
        // TODO changer peut-être les ranges des boucles
        // 0 <= x < 5
        for x in 0..5 {
            let x = STATE_INDEX[x];
            // 0 <= z < w
            for z in 0..self.w {
                d[x][z] = c[((x as i32 - 1).rem_euclid(5)) as usize][z] ^ c[(x + 1).rem_euclid(5)][((z as i32 - 1).rem_euclid(self.w as i32)) as usize];
            }
        }

        // 0 <= x < 5
        for x in 0..5 {
            let x = STATE_INDEX[x];
            // 0 <= y < 5
            for y in 0..5 {
                let y = STATE_INDEX[y];
                // 0 <= z < w
                for z in 0..self.w {
                    statearray[x][y][z] = statearray[x][y][z] ^ d[x][z];
                }
            }
        }

        statearray.to_vec()
    }
    
    /// ρ routine
    fn routine_rho(&self, statearray: &mut Vec<Vec<Vec<i32>>>) -> Vec<Vec<Vec<i32>>> {
        let (mut x, mut y) = (1, 0);

        // TODO vérifier par rapport au document NIST si (z - (t + 1) * (t + 2) / 2) % w est correct
        // TODO changer peut-être les ranges des boucles
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
            let x = STATE_INDEX[x];
            // 0 <= y < 5
            for y in 0..5 {
                let y = STATE_INDEX[y];
                // 0 <= z < w
                for z in 0..self.w {
                    statearray[x][y][z] = statearray[(x + 3 * y).rem_euclid(5)][x][z];
                }
            }
        }
        
        statearray.to_vec()
    }

    /// χ routine
    fn routine_chi(&self, statearray: &mut Vec<Vec<Vec<i32>>>) -> Vec<Vec<Vec<i32>>> {
        // 0 <= x < 5
        for x in 0..5 {
            let x = STATE_INDEX[x];
            // 0 <= y < 5
            for y in 0..5 {
                let y = STATE_INDEX[y];
                // 0 <= z < w
                for z in 0..self.w {
                    statearray[x][y][z] = statearray[x][y][z] ^ ((!statearray[(x + 1).rem_euclid(5)][y][z]) & statearray[(x + 2).rem_euclid(5)][y][z]);
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
    
    /// Sponge function
    pub fn sponge(&self) -> String {

        // Convert the string into a state array
        let mut statearray = self.strings_to_state();

        // 12 + 2 * l - nr <= i <= 12 + 2 * l - 1
        for i in 12 + 2 * self.l - self.nr..12 + 2 * self.l - 1 {
            // Executing the θ routine on the state array
            statearray = self.routine_theta(&mut statearray);

            // Executing the ρ routine on the state array
            statearray = self.routine_rho(&mut statearray);

            // Executing the π routine on the state array
            statearray = self.routine_pi(&mut statearray);

            // Executing the χ routine on the state array
            statearray = self.routine_chi(&mut statearray);

            // Executing the ι routine on the state array
            statearray = self.routine_iota(&mut statearray, i); // TODO: round_index needs to be implemented
        }

        // Convert the state array into a string
        let password_bin = self.state_to_strings(&statearray);

        password_bin
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    // Test the creation of a new Keccak instance
    fn test_keccak_new() {
        let mut sha3 = Sha3::new("password", 256);
        sha3.password_bin = sha3.preprocessing();
        let keccak = Keccak::new(&sha3);
        println!("keccak: {:?}", keccak);
        assert_eq!(keccak.password, sha3.password_bin);
        assert_eq!(keccak.f, 256);
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
        assert_eq!(keccak.f, 256);
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
        assert_eq!(keccak.f, 256);
        assert_eq!(keccak.b, 1088 + 2*256);
        assert_eq!(keccak.nr, 24);
    }

    #[test]
    // Test the conversion of a string to a state array
    fn test_keccak_strings_to_state() {
        let mut sha3 = Sha3::new("password", 256);
        sha3.password_bin = sha3.preprocessing();
        let keccak = Keccak::new(&sha3);
        let statearray = keccak.strings_to_state();
        assert_eq!(statearray.len(), 5);
        assert_eq!(statearray[0].len(), 5);
        assert_eq!(statearray[0][0].len(), keccak.w);
    }

    #[test]
    // Test the conversion of a state array to a string
    fn test_keccak_state_to_strings() {
        let mut sha3 = Sha3::new("password", 256);
        sha3.password_bin = sha3.preprocessing();
        let keccak = Keccak::new(&sha3);
        let statearray = keccak.strings_to_state();
        let password_bin = keccak.state_to_strings(&statearray);
        assert_eq!(password_bin.len(), 1600);
    }

    #[test]
    // Test the θ routine
    fn test_keccak_routine_theta() {
        let mut sha3 = Sha3::new("password", 256);
        sha3.password_bin = sha3.preprocessing();
        let keccak = Keccak::new(&sha3);
        let mut statearray = keccak.strings_to_state();
        statearray = keccak.routine_theta(&mut statearray);
        assert_eq!(statearray.len(), 5);
        assert_eq!(statearray[0].len(), 5);
        assert_eq!(statearray[0][0].len(), keccak.w);
    }

    #[test]
    // Test the ρ routine
    fn test_keccak_routine_rho() {
        let mut sha3 = Sha3::new("password", 256);
        sha3.password_bin = sha3.preprocessing();
        let keccak = Keccak::new(&sha3);
        let mut statearray = keccak.strings_to_state();
        statearray = keccak.routine_theta(&mut statearray);
        statearray = keccak.routine_rho(&mut statearray);
        assert_eq!(statearray.len(), 5);
        assert_eq!(statearray[0].len(), 5);
        assert_eq!(statearray[0][0].len(), keccak.w);
    }

    #[test]
    // Test the π routine
    fn test_keccak_routine_pi() {
        let mut sha3 = Sha3::new("password", 256);
        sha3.password_bin = sha3.preprocessing();
        let keccak = Keccak::new(&sha3);
        let mut statearray = keccak.strings_to_state();
        statearray = keccak.routine_theta(&mut statearray);
        statearray = keccak.routine_rho(&mut statearray);
        statearray = keccak.routine_pi(&mut statearray);
        assert_eq!(statearray.len(), 5);
        assert_eq!(statearray[0].len(), 5);
        assert_eq!(statearray[0][0].len(), keccak.w);
    }

    #[test]
    // Test the χ routine
    fn test_keccak_routine_chi() {
        let mut sha3 = Sha3::new("password", 256);
        sha3.password_bin = sha3.preprocessing();
        let keccak = Keccak::new(&sha3);
        let mut statearray = keccak.strings_to_state();
        statearray = keccak.routine_theta(&mut statearray);
        statearray = keccak.routine_rho(&mut statearray);
        statearray = keccak.routine_pi(&mut statearray);
        statearray = keccak.routine_chi(&mut statearray);
        assert_eq!(statearray.len(), 5);
        assert_eq!(statearray[0].len(), 5);
        assert_eq!(statearray[0][0].len(), keccak.w);
    }
    
    #[test]
    // Test the χ routine (this test should return the same result as the following test)
    fn test_keccak_routine_iota() {
        let mut sha3 = Sha3::new("password", 256);
        sha3.password_bin = sha3.preprocessing();
        let keccak = Keccak::new(&sha3);
        let mut statearray = keccak.strings_to_state();
        statearray = keccak.routine_theta(&mut statearray);
        statearray = keccak.routine_rho(&mut statearray);
        statearray = keccak.routine_pi(&mut statearray);
        statearray = keccak.routine_chi(&mut statearray);
        statearray = keccak.routine_iota(&mut statearray, 0);
        assert_eq!(statearray.len(), 5);
        assert_eq!(statearray[0].len(), 5);
        assert_eq!(statearray[0][0].len(), keccak.w);
    }
    
    
    #[test]
    // Test the round constant function
    fn test_keccak_round_constant() {
        let mut sha3 = Sha3::new("password", 256);
        sha3.password_bin = sha3.preprocessing();
        let keccak = Keccak::new(&sha3);
        let rc = keccak.round_constant(2);
        assert_eq!(rc, 0);
    }

    #[test]
    #[ignore]
    // Test the sponge function for 224 bits
    fn test_keccak_sponge_224() {
        let mut sha3 = Sha3::new("password", 224);
        sha3.password_bin = sha3.preprocessing();
        let keccak = Keccak::new(&sha3);
        let hash = keccak.sponge();
        println!("hash: {}", hash);
        assert_eq!(hash, "c3f847612c3780385a859a1993dfd9fe7c4e6d7f477148e527e9374c");
    }
    
    #[test]
    #[ignore]
    // Test the sponge function for 256 bits
    fn test_keccak_sponge_256() {
        let mut sha3 = Sha3::new("password", 256);
        sha3.password_bin = sha3.preprocessing();
        let keccak = Keccak::new(&sha3);
        let hash = keccak.sponge();
        println!("hash: {}", hash);
        assert_eq!(hash, "c0067d4af4e87f00dbac63b6156828237059172d1bbeac67427345d6a9fda484");
    }

    #[test]
    #[ignore]
    // Test the sponge function for 384 bits
    fn test_keccak_sponge_384() {
        let mut sha3 = Sha3::new("password", 384);
        sha3.password_bin = sha3.preprocessing();
        let keccak = Keccak::new(&sha3);
        let hash = keccak.sponge();
        println!("hash: {}", hash);
        assert_eq!(hash, "9c1565e99afa2ce7800e96a73c125363c06697c5674d59f227b3368fd00b85ead506eefa90702673d873cb2c9357eafc");
    }

    #[test]
    #[ignore]
    // Test the sponge function for 512 bits
    fn test_keccak_sponge_512() {
        let mut sha3 = Sha3::new("password", 512);
        sha3.password_bin = sha3.preprocessing();
        let keccak = Keccak::new(&sha3);
        let hash = keccak.sponge();
        println!("hash: {}", hash);
        assert_eq!(hash, "e9a75486736a550af4fea861e2378305c4a555a05094dee1dca2f68afea49cc3a50e8de6ea131ea521311f4d6fb054a146e8282f8e35ff2e6368c1a62e909716");
    }
}