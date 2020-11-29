#![allow(non_snake_case)]

use num_bigint::{BigUint, RandBigInt, ToBigUint};
use num_integer::Integer;
use num_primes::Generator;
use std::clone::Clone;
use std::ops::*;

pub struct MPVSS {
    pub q: BigUint,
    pub g: BigUint,
    pub G: BigUint,

    pub length: u32,
}

impl MPVSS {
    /// `q` is a safe prime of length 2048 bit RFC3526 https://tools.ietf.org/html/rfc3526.
    /// `2` and the corresponding sophie germain prime are generators.
    /// sophie germain prime is p if 2*p + 1 is also prime, let 2*p + 1 = q
    pub fn new() -> Self {
        let q: BigUint = BigUint::parse_bytes(b"ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3be39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf6955817183995497cea956ae515d2261898fa051015728e5a8aacaa68ffffffffffffffff", 16).unwrap();
        let g: BigUint = q
            .clone()
            .sub(1.to_biguint().unwrap())
            .div(2.to_biguint().unwrap());
        return MPVSS {
            q: q,
            g: g,
            G: 2.to_biguint().unwrap(),
            length: 2048,
        };
    }

    /// Initializes a MPVSS by generating a safe prime of `length` bit length.
    ///
    /// - Parameter length: Number of bits used for choosing numbers and doing calculations.
    pub fn init(length: u32) -> Self {
        let q: BigUint = Generator::safe_prime(length as usize);
        let g: BigUint = q
            .clone()
            .sub(1.to_biguint().unwrap())
            .div(2.to_biguint().unwrap());
        return MPVSS {
            q: q,
            g: g,
            G: 2.to_biguint().unwrap(),
            length: length,
        };
    }

    pub fn generate_private_key(&self) -> BigUint {
        let mut rng = rand::thread_rng();
        let mut priv_key: BigUint = rng.gen_biguint_below(&self.q);
        // We need the private key and q-1 to be coprime so that we can calculate 1/key mod (q-1) during secret reconstruction.
        while priv_key.gcd(&self.q.clone().sub(BigUint::from(1u32))) != BigUint::from(1u32) {
            priv_key = rng.gen_biguint_below(&self.q);
        }
        priv_key
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_new() {
        use super::MPVSS;
        use num_primes::Verification;

        let mpvss = MPVSS::new();
        assert!(Verification::is_safe_prime(&mpvss.q));
        assert!(Verification::is_prime(&mpvss.g));
        assert!(!Verification::is_safe_prime(&mpvss.g));
    }

    #[test]
    fn test_init() {
        use super::MPVSS;
        use num_primes::Verification;
        let mpvss = MPVSS::init(64);
        assert!(Verification::is_safe_prime(&mpvss.q));
        assert!(Verification::is_prime(&mpvss.g));
        assert!(!Verification::is_safe_prime(&mpvss.g));
    }

    #[test]
    fn test_gen_priv_key() {
        use super::MPVSS;
        use super::*;
        use num_bigint::BigUint;
        use num_integer::Integer;
        use num_primes::Verification;
        let mut mpvss = MPVSS::new();
        mpvss.q = BigUint::from(49999u32);
        assert!(Verification::is_prime(&mpvss.q));
        let priv_key = mpvss.generate_private_key();
        assert_eq!(
            priv_key.gcd(&mpvss.q.clone().sub(BigUint::from(1u32))),
            BigUint::from(1u32)
        );
    }
}
