// Copyright 2020 The MPVSS Authors.
//
// Code is licensed under AGPL License, Version 3.0.

#![allow(non_snake_case)]

use num_bigint::{BigUint, RandBigInt};
use num_integer::Integer;
use num_primes::Generator;
use num_traits::identities::One;
use std::clone::Clone;

/// 2048-bit MODP Group
/// New Modular Exponential (MODP) Diffie-Hellman groups
///
/// This group is assigned id 14.
///
/// This prime is: 2^2048 - 2^1984 - 1 + 2^64 * { [2^1918 pi] + 124476 }
///
/// Its hexadecimal value is:
///
///    FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
///    29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
///    EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
///    E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
///    EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D
///    C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F
///    83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
///    670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B
///    E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9
///    DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510
///    15728E5A 8AACAA68 FFFFFFFF FFFFFFFF
///
/// The generator is: 2.

#[derive(Debug, Clone)]
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
        let g: BigUint = (q.clone() - BigUint::one()) / BigUint::from(2_u64);
        return MPVSS {
            q: q,
            g: g,
            G: BigUint::from(2_u64),
            length: 2048,
        };
    }

    /// Initializes a MPVSS by generating a safe prime of `length` bit length.
    ///
    /// - Parameter length: Number of bits used for choosing numbers and doing calculations.
    pub fn init(length: u32) -> Self {
        let q: BigUint = Generator::safe_prime(length as usize);
        let g: BigUint = (q.clone() - BigUint::one()) / BigUint::from(2_u64);
        return MPVSS {
            q: q,
            g: g,
            G: BigUint::from(2_u64),
            length: length,
        };
    }

    pub fn generate_private_key(&self) -> BigUint {
        let mut rng = rand::thread_rng();
        let mut privkey: BigUint = rng.gen_biguint_below(&self.q);
        // We need the private key and q-1 to be coprime so that we can calculate 1/key mod (q-1) during secret reconstruction.
        while privkey.gcd(&(self.q.clone() - BigUint::one())) != BigUint::one() {
            privkey = rng.gen_biguint_below(&self.q);
        }
        privkey
    }

    /// generate public key from private key
    /// P = G^k over the Group of the order q
    pub fn generate_public_key(&self, privkey: &BigUint) -> BigUint {
        // publicKey = G^privKey mod q
        self.G.modpow(privkey, &self.q)
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
        mpvss.q = BigUint::from(49999_u32);
        assert!(Verification::is_prime(&mpvss.q));
        let priv_key = mpvss.generate_private_key();
        assert_eq!(
            priv_key.gcd(&mpvss.q.clone().sub(BigUint::one())),
            BigUint::one()
        );
    }
}
