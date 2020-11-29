#![allow(non_snake_case)]

use num_bigint::BigUint;
use std::clone::Clone;
use std::ops::*;

pub struct MPVSS {
    pub q: BigUint,
    pub g: BigUint,
    pub G: BigUint,

    pub length: u32,
}

impl MPVSS {
    /// `q` is a safe prime of length 2048 bit (RFC3526).
    /// `2` and the corresponding sophie germain prime are generators.
    /// sophie germain prime is p if 2*p + 1 is also prime, let 2*p + 1 = q
    pub fn new() -> Self {
        let q: BigUint = BigUint::parse_bytes(b"ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3be39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf6955817183995497cea956ae515d2261898fa051015728e5a8aacaa68ffffffffffffffff", 16).unwrap();
        let g: BigUint = q.clone().sub(BigUint::from(1u32)).div(BigUint::from(2u32));
        return MPVSS {
            q: q,
            g: g,
            G: BigUint::from(2u32),
            length: 2048,
        };
    }

    //pub fn init(length: u32) -> Self {}
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_new() {
        use super::MPVSS;
        use num_bigint::BigUint;
        use num_primes::Verification;

        let mpvss = MPVSS::new();
        assert!(Verification::is_safe_prime(&mpvss.q));
        assert!(Verification::is_prime(&mpvss.g));
        assert!(!Verification::is_safe_prime(&mpvss.g));
    }
}
