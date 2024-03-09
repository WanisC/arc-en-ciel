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
    #[allow(dead_code)]
    pub fn new(obj: Sha3) -> Keccak {
        Keccak {
            password: obj.password,
            b: obj.b,
            nr: 24,
        }
    }

    #[allow(dead_code)]
    fn strings_to_state(&self) -> Vec<Vec<Vec<i32>>> {
        let mut statearray: Vec<Vec<Vec<i32>>> = vec![vec![vec![0; 64]; 5]; 5];

        // Convert the password to binary
        // TODO: fingerprint doit être différente en fonction de l'input (à régler dans le futur)
        let password_bin  = Sha3::new(&self.password, None, 256)
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

    #[allow(dead_code)]
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

        //TODO vérifier par rapport au document NIST si (x + 4) % 5 et (z + 63) % 64 sont corrects
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
    
    #[allow(dead_code)]
    fn routine_rho(&self, statearray: &mut Vec<Vec<Vec<i32>>>) -> Vec<Vec<Vec<i32>>> {
        statearray.to_vec()
    }
    
    #[allow(dead_code)]
    fn routine_pi(&self, statearray: &mut Vec<Vec<Vec<i32>>>) -> Vec<Vec<Vec<i32>>> {
        statearray.to_vec()
    }

    #[allow(dead_code)]
    fn routine_chi(&self, statearray: &mut Vec<Vec<Vec<i32>>>) -> Vec<Vec<Vec<i32>>> {
        statearray.to_vec()
    }
    
    #[allow(dead_code)]
    fn routine_iota(&self, statearray: &mut Vec<Vec<Vec<i32>>>) -> Vec<Vec<Vec<i32>>> {
        statearray.to_vec()
    }
    
    #[allow(dead_code)]
    fn sponge(&self, statearray: &mut Vec<Vec<Vec<i32>>>) -> Vec<Vec<Vec<i32>>> {
        // θ routine
        *statearray = self.routine_theta(statearray);

        // ρ routine
        *statearray = self.routine_rho(statearray);

        // π routine
        *statearray = self.routine_pi(statearray);

        // χ routine
        *statearray = self.routine_chi(statearray);

        // ι routine
        *statearray = self.routine_iota(statearray);

        statearray.to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    // Test the creation of a new Keccak instance
    fn test_keccak_new() {
        let sha3 = Sha3::new("password", None, 256);
        let keccak = Keccak::new(sha3);
        assert_eq!(keccak.password, "password");
        assert_eq!(keccak.b, 1088 + 2*256);
        assert_eq!(keccak.nr, 24);
    }

    #[test]
    // Test the creation of a new Keccak instance with a block size
    fn test_keccak_new_with_block() {
        let sha3 = Sha3::new("password", Some(1088), 256);
        let keccak = Keccak::new(sha3);
        assert_eq!(keccak.password, "password");
        assert_eq!(keccak.b, 1088 + 2*256);
        assert_eq!(keccak.nr, 24);
    }

    #[test]
    // Test the creation of a new Keccak instance without a block size
    fn test_keccak_new_without_block() {
        let sha3 = Sha3::new("password", None, 256);
        let keccak = Keccak::new(sha3);
        assert_eq!(keccak.password, "password");
        assert_eq!(keccak.b, 1088 + 2*256);
        assert_eq!(keccak.nr, 24);
    }

    #[test]
    // Test the conversion of a string to a state array
    fn test_keccak_strings_to_state() {
        let sha3 = Sha3::new("password", None, 256);
        let keccak = Keccak::new(sha3);
        let statearray = keccak.strings_to_state();
        assert_eq!(statearray.len(), 5);
        assert_eq!(statearray[0].len(), 5);
        assert_eq!(statearray[0][0].len(), 64);
    }

    #[test]
    // Test the conversion of a state array to a string
    fn test_keccak_state_to_strings() {
        let sha3 = Sha3::new("password", None, 256);
        let keccak = Keccak::new(sha3);
        let statearray = keccak.strings_to_state();
        let password_bin = keccak.state_to_strings(&statearray);
        assert_eq!(password_bin.len(), 1600);
    }

    #[test]
    // Test the θ routine
    fn test_keccak_routine_theta() {
        let sha3 = Sha3::new("password", None, 256);
        let keccak = Keccak::new(sha3);
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
    #[ignore]
    // Test the ρ routine
    fn test_keccak_routine_rho() {
        let sha3 = Sha3::new("password", None, 256);
        let keccak = Keccak::new(sha3);
        let mut statearray = keccak.strings_to_state();
        statearray = keccak.routine_theta(&mut statearray);
        statearray = keccak.routine_rho(&mut statearray);
        assert_eq!(statearray.len(), 5);
        assert_eq!(statearray[0].len(), 5);
        assert_eq!(statearray[0][0].len(), 64);
    }

    #[test]
    #[ignore]
    // Test the π routine
    fn test_keccak_routine_pi() {
        let sha3 = Sha3::new("password", None, 256);
        let keccak = Keccak::new(sha3);
        let mut statearray = keccak.strings_to_state();
        statearray = keccak.routine_theta(&mut statearray);
        statearray = keccak.routine_rho(&mut statearray);
        statearray = keccak.routine_pi(&mut statearray);
        assert_eq!(statearray.len(), 5);
        assert_eq!(statearray[0].len(), 5);
        assert_eq!(statearray[0][0].len(), 64);
    }

    #[test]
    #[ignore]
    // Test the χ routine
    fn test_keccak_routine_chi() {
        let sha3 = Sha3::new("password", None, 256);
        let keccak = Keccak::new(sha3);
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
    #[ignore]
    // Test the χ routine (this test should return the same result as the following test)
    fn test_keccak_routine_iota() {
        let sha3 = Sha3::new("password", None, 256);
        let keccak = Keccak::new(sha3);
        let mut statearray = keccak.strings_to_state();
        statearray = keccak.routine_theta(&mut statearray);
        statearray = keccak.routine_rho(&mut statearray);
        statearray = keccak.routine_pi(&mut statearray);
        statearray = keccak.routine_chi(&mut statearray);
        statearray = keccak.routine_iota(&mut statearray);
        assert_eq!(statearray.len(), 5);
        assert_eq!(statearray[0].len(), 5);
        assert_eq!(statearray[0][0].len(), 64);
    }
    
    #[test]
    #[ignore]
    // Test the sponge function
    fn test_keccak_sponge() {
        let sha3 = Sha3::new("password", None, 256);
        let keccak = Keccak::new(sha3);
        let mut statearray = keccak.strings_to_state();
        keccak.sponge(&mut statearray);
    }
}