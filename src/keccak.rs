//! Contains the implementation of the Keccak sponge function.

use crate::hashage::Sha3;

/// Keccak sponge function
/// 224 -> r = 1152
/// 256 -> r = 1088
/// 384 -> r = 832
/// 512 -> r = 576
#[derive(Debug)]
#[allow(dead_code)]
pub struct Keccak {
    password: String,
    b: i32,     // block size (b = r + c)
    nr: i32,    // number of rounds (by default 24)
}

impl Keccak {

    /// Create a new Keccak instance
    pub fn new(obj: &Sha3) -> Keccak {
        Keccak {
            password: obj.password_bin.clone().to_string(),
            b: obj.b,
            nr: 24,
        }
    }

    fn strings_to_state(&self) -> Vec<Vec<Vec<i32>>> {
        let mut statearray: Vec<Vec<Vec<i32>>> = vec![vec![vec![0; 64]; 5]; 5];

        // Convert the password to binary
        // TODO: fingerprint doit être différente en fonction de l'input (à régler dans le futur)
        let password_bin  = Sha3::new(&self.password, 256)
            .preprocessing()
            .chars()
            .map(|c| c.to_digit(10).unwrap() as i32)
            .collect::<Vec<i32>>();

        // Convert the binary password to a state array
        for x in 0..5 {
            for y in 0..5 {
                for z in 0..64 {
                    if password_bin.len() <= 64 * (5 * y + x) + z {
                        break;
                    }
                    statearray[x][y][z] = password_bin[64 * (5 * y + x) + z];
                }
            }
        }

        statearray
    }

    fn state_to_strings(&self, statearray: &Vec<Vec<Vec<i32>>>) -> String {
        let mut password_bin = String::new();

        for y in 0..5 {
            for x in 0..5 {
                for z in 0..64 {
                    password_bin.push_str(&statearray[x][y][z].to_string());
                }
            }
        }
        password_bin
    }

    fn routine_theta(&self, statearray: &mut Vec<Vec<Vec<i32>>>) -> Vec<Vec<Vec<i32>>> {
        let mut c = vec![vec![0; 64]; 5];
        let mut d = vec![vec![0; 64]; 5];

        for x in 0..5 {
            for z in 0..64 {
                c[x][z] = statearray[x][0][z] ^ statearray[x][1][z] ^ statearray[x][2][z] ^ statearray[x][3][z] ^ statearray[x][4][z];
            }
        }

        // TODO vérifier par rapport au document NIST si (x + 4) % 5 et (z + 63) % 64 sont corrects
        // TODO changer peut-être les ranges des boucles
        for x in 0..5 {
            for z in 0..64 {
                d[x][z] = c[(x + 4) % 5][z] ^ c[(x + 1) % 5][(z + 63) % 64];
            }
        }

        for x in 0..5 {
            for y in 0..5 {
                for z in 0..64 {
                    statearray[x][y][z] = statearray[x][y][z] ^ d[x][z];
                }
            }
        }

        statearray.to_vec()
    }
    
    fn routine_rho(&self, statearray: &mut Vec<Vec<Vec<i32>>>) -> Vec<Vec<Vec<i32>>> {
        let (mut x, mut y) = (1, 0);

        // TODO vérifier par rapport au document NIST si (z - (t + 1) * (t + 2) / 2) % 64 est correct
        // TODO changer peut-être les ranges des boucles
        for t in 0..=23 {
            for z in 0..64 {
                let index = (z as i64 - (t + 1) * (t + 2) / 2) as usize;
                let positive_index = index.rem_euclid(64);
                statearray[x][y][z] = statearray[x][y][positive_index];
            }
            (x, y) = (y, (2 * x + 3 * y) % 5);
        }

        statearray.to_vec()
    }
    
    fn routine_pi(&self, statearray: &mut Vec<Vec<Vec<i32>>>) -> Vec<Vec<Vec<i32>>> {
        for x in 0..5 {
            for y in 0..5 {
                for z in 0..64 {
                    statearray[x][y][z] = statearray[(x + 3 * y) % 5][x][z];
                }
            }
        }
        
        statearray.to_vec()
    }

    fn routine_chi(&self, statearray: &mut Vec<Vec<Vec<i32>>>) -> Vec<Vec<Vec<i32>>> {
        for x in 0..5 {
            for y in 0..5 {
                for z in 0..64 {
                    statearray[x][y][z] = statearray[x][y][z] ^ ((!statearray[(x + 1) % 5][y][z]) & statearray[(x + 2) % 5][y][z]);
                }
            }
        }
        statearray.to_vec()
    }
    
    fn routine_iota(&self, statearray: &mut Vec<Vec<Vec<i32>>>, round_index: i32) -> Vec<Vec<Vec<i32>>> {
        let mut rc = vec![0; 64];
        for j in 0..=6 {
            rc[(2i32.pow(j) - 1) as usize] = self.round_constant(j as i32 + 7 * round_index);
        }

        for z in 0..64 {
            statearray[0][0][z] = statearray[0][0][z] ^ rc[z];
        }

        statearray.to_vec()
    }

    fn round_constant(&self, t: i32) -> i32 {
        if t % 255 == 0 {
            1
        } else {
            let mut r_vec: Vec<u8> = vec![1, 0, 0, 0, 0, 0, 0, 0];
            for _ in 1..=t % 255 {
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
            r_vec[0] as i32
            //(r & 1) as i32
        }

        
    }
    
    pub fn sponge(&self) -> String {

        // Convert the string into a state array
        let mut statearray = self.strings_to_state();

        // Executing the θ routine on the state array
        statearray = self.routine_theta(&mut statearray);

        // Executing the ρ routine on the state array
        statearray = self.routine_rho(&mut statearray);

        // Executing the π routine on the state array
        statearray = self.routine_pi(&mut statearray);

        // Executing the χ routine on the state array
        statearray = self.routine_chi(&mut statearray);

        // Executing the ι routine on the state array
        statearray = self.routine_iota(&mut statearray, 0); // TODO: round_index needs to be implemented

        // Convert the final state array into a string
        self.state_to_strings(&mut statearray)
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
        let statearray = keccak.strings_to_state();
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
        let mut statearray = keccak.strings_to_state();
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
        let mut statearray = keccak.strings_to_state();
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
        let mut statearray = keccak.strings_to_state();
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
        let mut statearray = keccak.strings_to_state();
        statearray = keccak.routine_theta(&mut statearray);
        statearray = keccak.routine_rho(&mut statearray);
        statearray = keccak.routine_pi(&mut statearray);
        statearray = keccak.routine_chi(&mut statearray);
        statearray = keccak.routine_iota(&mut statearray, 0); // TODO: round_index
        assert_eq!(statearray.len(), 5);
        assert_eq!(statearray[0].len(), 5);
        assert_eq!(statearray[0][0].len(), 64);
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