//! Contains the implementation of the Keccak sponge function.

use std::ops::BitAnd;

use crate::hashage::Sha3;

/// Keccak sponge function
/// 224 -> r = 1152
/// 256 -> r = 1088
/// 384 -> r = 832
/// 512 -> r = 576
#[derive(Debug)]
#[allow(arithmetic_overflow)]
pub struct Keccak {
    password: String,
    state: Vec<Vec<u64>>,
    f: i32,     // fingerprint
    b: i32,     // block size (b = r + c)
    r: i32,     // bitrate
    l: i32,     // log2(w) so since w = 64, l = 6
    w: usize,   // word size (by default 64)
    nr: i32,    // number of rounds (by default 24)
    r_iota: u32, // round index
}

impl Keccak {

    /// Create a new Keccak instance
    pub fn new(obj: &Sha3) -> Keccak {
        Keccak {
            password: obj.password_bytes.clone().to_string(),
            state: vec![vec![0; 5]; 5],
            f: obj.fingerprint,
            b: obj.b,
            r: obj.r,
            l: 6,
            w: 64,
            nr: 24,
            r_iota: 1,
        }
    }

    fn rol_64(a: u64, n: i32) -> u64 {
        (a >> (64 - (n % 64))) + (a << (n % 64)) 
    }
    
    fn zfill(s: &str, width: usize) -> String {
        if width <= s.len() {
            return s.to_string();
        }
        let padding = width - s.len();
        let zeros: String = std::iter::repeat('0').take(padding).collect();
        format!("{}{}", zeros, s)
    }

    /// Convert the state array into a string
    fn state_to_strings(&self) -> String {
        let nlanes = self.r / 256;
        let mut output = String::new();
        for i in 0..nlanes {
            let y = (i / 5) as usize;
            let x = (i - 5 * y as i32) as usize;
            output += Keccak::zfill(format!("{:08x}", self.state[x][y].swap_bytes()).as_str(), 16).as_str();
            
        }
        output
    }

    /// θ routine
    fn routine_theta(&mut self) {
        let mut c = vec![0; 5];
        let mut d = vec![0; 5];

        // 0 <= x < 5
        for x in 0..5 {
            // 0 <= z < w
            c[x] = self.state[x][0] ^ self.state[x][1] ^ self.state[x][2] ^ self.state[x][3] ^ self.state[x][4];
        }

        // TODO vérifier par rapport au document NIST si (x + 4) % 5 et (z + 63) % w sont corrects
        // TODO changer peut-être les ranges des boucles
        // 0 <= x < 5
        for x in 0..5 {
            // 0 <= z < w
            d[x] = c[(x + 4).rem_euclid(5)] ^ Keccak::rol_64(c[(x + 1).rem_euclid(5)], 1);
        }

        for x in 0..5 {
            for y in 0..5 {
                self.state[x][y] ^= d[x];
            }
        }

    }
    
    /// ρ routine
    fn routine_rho_pi(&mut self) {
        let (mut x, mut y) = (1, 0);
        let mut curent = self.state[x][y];
        // TODO vérifier par rapport au document NIST si (z - (t + 1) * (t + 2) / 2) % w est correct
        // TODO changer peut-être les ranges des boucles
        // 0 <= t <= 23
        for t in 0..=23 {
            // 0 <= z < w
            (x, y) = (y, (2 * x + 3 * y).rem_euclid(5));
            (curent, self.state[x][y]) = (self.state[x][y], Keccak::rol_64(curent, ((t + 1) * (t + 2) / 2) as i32));
        }
    }

    /// χ routine
    fn routine_chi(&mut self) {
        // 0 <= x < 5
        for y in 0..5 {
            // 0 <= z < w
            let mut s = vec![0; 5];
            for x in 0..5 {
                s[x] = self.state[x][y];
            }
            for x in 0..5 {
                self.state[x][y] = s[x] ^ ((!s[(x + 1).rem_euclid(5)]) & s[(x + 2).rem_euclid(5)]);
            }
        }
    }
    
    /// ι routine
    fn routine_iota(&mut self) {
        for j in 0..7 {
            self.r_iota = ((self.r_iota << 1) ^ ((self.r_iota >> 7) * 0x71)).rem_euclid(256);
            if self.r_iota.bitand(2) == 2 {
                self.state[0][0] ^= 1 << ((1 << j) - 1);
            }
        }

    }
    
    fn round_index(&mut self) {
        self.routine_theta();
        self.routine_rho_pi();
        self.routine_chi();
        self.routine_iota();
    }

    fn keccak_p(&mut self) {
        for _ in 0..self.nr {
            self.round_index();
        }
    }
    
    /// Sponge function
    pub fn sponge(&mut self) {
        let r_octet = self.r as usize / 8;
        let n_lanes = r_octet / 8;
        for i in 0..n_lanes {
            let mut lane = String::new();
            for j in 0..8 {
                lane = format!("{}{}",&self.password[(i * 64 + j * 8)..(i * 64 + j * 8 + 8)], lane);
            }
            let y = i / 5;
            let x = i - 5 * y;
            self.state[x][y] ^= u64::from_str_radix(&lane, 2).unwrap() as u64;
        }
        self.keccak_p();
    }
}


#[cfg(test)]
mod tests {
    use super::*;
   
    #[test]
    // Test of all the routines together we assume that n = 24
    fn test_sha_3_keccak() {
        let mut sha3 = Sha3::new("****", 256);
        sha3.password_bytes = sha3.preprocessing();
        let mut keccak = Keccak::new(&sha3);
        keccak.sponge();
        let res = keccak.state_to_strings();
        assert_eq!("9c75caf0e14b30ac6b50c5d2f464d3690a6c72890228dd4994b6dabaf261a2ad", res);
    }
}