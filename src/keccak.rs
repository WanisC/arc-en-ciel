//! Contains the implementation of the Keccak sponge function.

/// Keccak sponge function
/// 224 -> r = 1152
/// 256 -> r = 1088
/// 384 -> r = 832
/// 512 -> r = 576
#[derive(Debug)]
struct Keccak {
    password: String,
    l: usize, // will be 6 for Keccak
    b: usize, // block size (b = r + c)
    c: usize, // extra block size for more security/operations (SHA-3 norm: c = 2*fingerprint) 
    r: usize, // rate of bits absorbed by the sponge (r = b - c)
    fingerprint: usize,
}

impl Keccak {

    /// Create a new Keccak instance (224 bits)
    fn new224(password: &str, block: usize) -> Keccak {
        Keccak {
            password: password.to_string(),
            6,
            1152 + 2*224,
            2*224,
            1152,
            224,
        }
    }

    /// Create a new Keccak instance (256 bits)
    fn new256(password: &str, block: usize) -> Keccak {
        Keccak {
            password: password.to_string(),
            6,
            1088 + 2*256,
            2*256,
            1088,
            256,
        }
    }

    /// Create a new Keccak instance (384 bits)
    fn new384(password: &str, block: usize) -> Keccak {
        Keccak {
            password: password.to_string(),
            6,
            832 + 2*384,
            2*384,
            832,
            384,
        }
    }

    /// Create a new Keccak instance (512 bits)
    fn new512(password: &str, block: usize) -> Keccak {
        Keccak {
            password: password.to_string(),
            6,
            576 + 2*512,
            2*512,
            576,
            512,
        }
    }

    #[allow(dead_code)]
    fn sponge(&self, _word: &str) {
        // routine θ
        // routine ρ
        // routine π
        // routine χ
        // routine ι
    }

    #[allow(dead_code)]
    fn routine_θ(&self) {
        unimplemented!("Not implemented yet")
    }

    #[allow(dead_code)]
    fn routine_ρ(&self) {
        unimplemented!("Not implemented yet")
    }

    #[allow(dead_code)]
    fn routine_π(&self) {
        unimplemented!("Not implemented yet")
    }

    #[allow(dead_code)]
    fn routine_χ(&self) {
        unimplemented!("Not implemented yet")
    }

    #[allow(dead_code)]
    fn routine_ι(&self) {
        unimplemented!("Not implemented yet")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keccak_new224() {
        let keccak = Keccak::new224("password", 1152, 224);
        assert_eq!(keccak.l, 6);
        assert_eq!(keccak.b, 1152 + 2^224);
        assert_eq!(keccak.c, 2^224);
        assert_eq!(keccak.r, 1152);
        assert_eq!(keccak.fingerprint, Some(224));
    }

    #[test]
    fn test_keccak_new256() {
        let keccak = Keccak::new256("password", 1088);
        assert_eq!(keccak.l, 6);
        assert_eq!(keccak.b, 1088 + 2^256);
        assert_eq!(keccak.c, 2^256);
        assert_eq!(keccak.r, 1088);
        assert_eq!(keccak.fingerprint, Some(256));
    }

    #[test]
    fn test_keccak_new384() {
        let keccak = Keccak::new384("password", 832);
        assert_eq!(keccak.l, 6);
        assert_eq!(keccak.b, 832 + 2^384);
        assert_eq!(keccak.c, 2^384);
        assert_eq!(keccak.r, 832);
        assert_eq!(keccak.fingerprint, Some(384));
    }

    #[test]
    fn test_keccak_new512() {
        let keccak = Keccak::new512("password", 576);
        assert_eq!(keccak.l, 6);
        assert_eq!(keccak.b, 576 + 2^512);
        assert_eq!(keccak.c, 2^512);
        assert_eq!(keccak.r, 576);
        assert_eq!(keccak.fingerprint, Some(512));
    }
}