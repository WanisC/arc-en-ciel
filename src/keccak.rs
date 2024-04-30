//! Contains the implementation of the Keccak sponge function.

use std::ops::BitAnd;

use crate::hashage::Sha3;

/// Keccak sponge function.  
/// Here the default bit rate based on the fingerprint size:  
/// 224 -> r = 1152  
/// 256 -> r = 1088  
/// 384 -> r = 832  
/// 512 -> r = 576 
/// 
/// # Arguments
/// * `password` - The password to hash
/// * `state` - The state array
/// * `f` - The fingerprint
/// * `r` - The bit rate
/// * `nr` - The number of rounds
/// * `r_iota` - The round index 
#[derive(Debug)]
pub struct Keccak {
    password: String,       // password
    state: Vec<Vec<u64>>,   // state array
    f: i32,                 // fingerprint
    r: i32,                 // bit rate
    nr: i32,                // number of rounds (by default 24)
    r_iota: u32,            // round index
}

/// Implementation of the Keccak sponge function.  
/// The Keccak sponge function is the main function of the Keccak algorithm.  
/// It is composed of two main steps:
/// 1. Absorbing phase: The password is divided into 64-bit blocks, and each block is XORed with a lane of the state array.
/// 2. Squeezing phase: The state array is updated after each block, and the state array is converted into a string.
/// # Example
/// ```rust
/// let mut sha3 = Sha3::new("****", 256);
/// sha3.preprocessing();
/// let mut keccak = Keccak::new(&sha3);
/// keccak.sponge();
/// let res = keccak.state_to_strings();
/// assert_eq!("9c75caf0e14b30ac6b50c5d2f464d3690a6c72890228dd4994b6dabaf261a2ad", res);
/// ```
/// # Note
/// The sponge function is the main function of the Keccak algorithm.
impl Keccak {

    /// Create a new Keccak instance.
    /// # Arguments
    /// * `obj` - A reference to a Sha3 instance
    /// # Returns
    /// A new Keccak instance.
    pub fn new(obj: &Sha3) -> Keccak {
        Keccak {
            password: obj.password_bytes.clone().to_string(),
            state: vec![vec![0; 5]; 5],
            f: obj.fingerprint,
            r: obj.r,
            nr: 24,
            r_iota: 1,
        }
    }

    /// Rotate left function.
    /// # Arguments
    /// * `a` - The number to rotate
    /// * `n` - The number of bits to rotate
    /// # Returns
    /// The rotated number.
    fn rol_64(a: u64, n: i32) -> u64 {
        (a >> (64 - (n % 64))) + (a << (n % 64)) 
    }

    /// Fill the string with zeros if the length is less than the width.
    /// # Example
    /// ```
    /// let num = "42";
    /// let res = Keccak::zfill(num, 8);
    /// assert_eq!(res, "00000042");
    /// ```
    /// # Arguments
    /// * `s` - The string to fill
    /// * `width` - The width of the string
    /// # Returns
    /// A string with zeros added.
    fn zfill(s: &str, width: usize) -> String {
        // If the length of the string is greater or equal than the width, we return the string
        if width <= s.len() {
            return s.to_string();
        }
        // Calculate the number of zeros to add
        let padding = width - s.len();
        let zeros: String = std::iter::repeat('0').take(padding).collect();
        // Return the string with the zeros added
        format!("{}{}", zeros, s)
    }

    /// Convert the state array into a string.
    /// # Arguments
    /// * `self` - The Keccak instance
    /// # Returns
    /// A string representing the state array, truncated to the fingerprint size divided by 4.
    pub fn state_to_strings(&self) -> String {
        // Number of lanes
        let nlanes = self.r / self.f;
        let mut output = String::new();
        // 0 <= i < nlanes
        for i in 0..nlanes {
            let y = (i / 5) as usize;
            let x = (i - 5 * y as i32) as usize;
            // For each "lane" in the state, converts the value into a hexadecimal string, 
            // inverts the byte order, adds leading zeros until the string is 16 characters wide,
            // then adds this string to the output
            output += Keccak::zfill(format!("{:08x}", self.state[x][y].swap_bytes()).as_str(), 16).as_str();
            
        }
        // Truncate the output to the fingerprint size divided by 4, and return it
        output.truncate(self.f as usize / 4);
        output
    }

    /// The θ routine performs a series of XOR operations and left rotations on the internal state of the Keccak algorithm.
    /// # Arguments
    /// * `self` - The Keccak instance
    fn routine_theta(&mut self) {
        // Initialize two null vectors c and d of size 5
        let mut c = vec![0; 5];
        let mut d = vec![0; 5];

        // 0 <= x < 5
        for x in 0..5 {
            // c[x] = state[x][0] XOR state[x][1] XOR state[x][2] XOR state[x][3] XOR state[x][4]
            c[x] = self.state[x][0] ^ self.state[x][1] ^ self.state[x][2] ^ self.state[x][3] ^ self.state[x][4];
        }

        // 0 <= x < 5
        for x in 0..5 {
            // d[x] = c[x-1] XOR rot(c[x+1], 1)
            d[x] = c[(x + 4).rem_euclid(5)] ^ Keccak::rol_64(c[(x + 1).rem_euclid(5)], 1);
        }

        // 0 <= x < 5
        for x in 0..5 {
            // 0 <= y < 5
            for y in 0..5 {
                // state[x][y] = state[x][y] XOR d[x]
                self.state[x][y] ^= d[x];
            }
        }
    }
    
    /// The ρ and π routines perform a series of permutations and rotations to the left on the internal state of the Keccak algorithm.
    /// # Arguments
    /// * `self` - The Keccak instance
    fn routine_rho_pi(&mut self) {
        // Initialize the position (x, y) to (1, 0) and the current value to state[1][0]
        let (mut x, mut y) = (1, 0);
        let mut current = self.state[x][y];
        // 0 <= t <= 23
        for t in 0..=23 {
            // (x, y) = (y, (2 * x + 3 * y) mod 5)
            (x, y) = (y, (2 * x + 3 * y).rem_euclid(5));
            // (current, state[x][y]) = (state[x][y], rot(current, (t + 1) * (t + 2) / 2))
            (current, self.state[x][y]) = (self.state[x][y], Keccak::rol_64(current, ((t + 1) * (t + 2) / 2) as i32));
        }
    }

    /// The χ routines perform a series of XOR, AND and NOT operations on the internal state of the Keccak algorithm.
    /// # Arguments
    /// * `self` - The Keccak instance
    fn routine_chi(&mut self) {
        // 0 <= y < 5
        for y in 0..5 {
            let mut s = vec![0; 5]; // Initialize a null vector s of size 5
            // 0 <= x < 5
            for x in 0..5 {
                s[x] = self.state[x][y];
            }

            // 0 <= x < 5
            for x in 0..5 {
                // state[x][y] = s[x] XOR (NOT s[(x + 1) mod 5] AND s[(x + 2) mod 5])
                self.state[x][y] = s[x] ^ ((!s[(x + 1).rem_euclid(5)]) & s[(x + 2).rem_euclid(5)]);
            }
        }
    }
    
    /// The ι routines perform a series of rotation, XOR and shift operations on the internal state of the Keccak algorithm.
    /// # Arguments
    /// * `self` - The Keccak instance
    fn routine_iota(&mut self) {
        // 0 <= j < 7
        for j in 0..7 {
            // r_iota = ((r_iota << 1) XOR ((r_iota >> 7) * 0x71)) mod 256
            self.r_iota = ((self.r_iota << 1) ^ ((self.r_iota >> 7) * 0x71)).rem_euclid(256);
            // If the second bit (from the right) of self.r_iota is 1
            if self.r_iota.bitand(2) == 2 {
                self.state[0][0] ^= 1 << ((1 << j) - 1);
            }
        }

    }
    
    /// The round index method applies the θ, ρ, π, χ and ι routines to the internal state of the Keccak algorithm.
    /// # Arguments
    /// * `self` - The Keccak instance
    fn round_index(&mut self) {
        // Apply the θ, ρ, π, χ and ι routines
        self.routine_theta();
        self.routine_rho_pi();
        self.routine_chi();
        self.routine_iota();
    }

    /// The Keccak-p permutation loops over the round index method for a number of rounds (24 by default).
    /// # Arguments
    /// * `self` - The Keccak instance
    /// # Note
    /// It is composed of 24 rounds.  
    /// Each round consists of the θ, ρ, π, χ and ι routines (round_index method).  
    /// The permutation is applied to the state array.  
    /// The state array is updated after each round.
    fn keccak_p(&mut self) {
        // 0 <= i < nr (24 by default)
        for _ in 0..self.nr {
            self.round_index(); // Apply the θ, ρ, π, χ and ι routines
        }
    }
    
    /// The sponge function absorbs the input data into the internal state of the Keccak algorithm, performs a series of operations on this state, then applies the Keccak-p permutation.
    /// # Arguments
    /// * `self` - The Keccak instance
    /// # Note
    /// The sponge function is the main function of the Keccak algorithm.
    pub fn sponge(&mut self) {
        let r_octet = self.r as usize / 8;  // Transform the bit rate into a byte rate
        let n_lanes = r_octet / 8;          // Number of lanes
        // 0 <= i < n_lanes
        for i in 0..n_lanes {
            let mut lane = String::new(); // Initialize a mutable string lane
            // 0 <= j < 8
            for j in 0..8 {
                // Extracts a substring from self.password based on the values of i and j
                // Concatenates it with the current value of lane, and assigns the result to lane
                lane = format!("{}{}",&self.password[(i * 64 + j * 8)..(i * 64 + j * 8 + 8)], lane);
            }

            // Initializes y based on the value of i, and x based on the value of i and y
            let y = i / 5;
            let x = i - 5 * y;
            self.state[x][y] ^= u64::from_str_radix(&lane, 2).unwrap() as u64;
        }

        // Apply the Keccak-p permutation
        self.keccak_p();
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    /// Test the `zfill` method
    fn test_zfill() {
        let num = "42";
        let res = Keccak::zfill(num, 8);
        assert_eq!(res, "00000042");
    }
    
    #[test]
    /// Test the creation of a new Keccak instance
    fn test_sha_3_keccak() {
        let mut sha3 = Sha3::new("****", 256);
        sha3.preprocessing();
        let mut keccak = Keccak::new(&sha3);
        keccak.sponge();
        let res = keccak.state_to_strings();
        assert_eq!("9c75caf0e14b30ac6b50c5d2f464d3690a6c72890228dd4994b6dabaf261a2ad", res);
    }
}