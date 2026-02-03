// Copyright 2020-2024 MathxH Chen.
//
// Code is licensed under GPLv3.0 License.

//! MODP group implementation using RFC 3526 2048-bit safe prime.
//!
//! This is the original implementation from the MPVSS library, refactored
//! to implement the `Group` trait.

use num_bigint::{BigInt, BigUint, RandBigInt, ToBigInt};
use num_integer::Integer;
use num_primes::Generator;
use num_traits::identities::{One, Zero};
use sha2::{Digest, Sha256};
use std::sync::Arc;

use crate::group::Group;

/// 2048-bit MODP Group from RFC 3526 (Group ID 14)
///
/// # Group Parameters
/// - `q`: Safe prime (2048-bit)
/// - `g`: Sophie Germain prime = (q-1)/2 (subgroup order)
/// - `G`: Generator = 2
///
/// The prime is: 2^2048 - 2^1984 - 1 + 2^64 * { [2^1918 pi] + 124476 }
#[derive(Debug, Clone)]
pub struct ModpGroup {
    /// Safe prime (group modulus)
    q: BigInt,
    /// Sophie Germain prime (subgroup order)
    g: BigInt,
    /// Main generator (value 2)
    G: BigInt,
    /// Cached q - 1 (group order)
    q_minus_1: BigInt,
}

impl ModpGroup {
    /// Create a new MODP group using RFC 3526 2048-bit prime
    pub fn new() -> Arc<Self> {
        // RFC 3526 2048-bit MODP group (ID 14)
        // Prime: 2^2048 - 2^1984 - 1 + 2^64 * { [2^1918 pi] + 124476 }
        let q: BigUint = BigUint::parse_bytes(
            b"ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74\
              020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1\
              356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb\
              5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d\
              39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d67\
              0c354e4abc9804f1746c08ca18217c32905e462e36ce3be39e772c180e86039b2783a\
              2ec07a28fb5c55df06f4c52c9de2bcbf6955817183995497cea956ae515d2261898fa0\
              51015728e5a8aacaa68ffffffffffffffff",
            16,
        )
        .unwrap();
        let g: BigUint = (q.clone() - BigUint::one()) / BigUint::from(2_u64);

        Arc::new(ModpGroup {
            q: q.to_bigint().unwrap(),
            g: g.to_bigint().unwrap(),
            G: BigInt::from(2),
            q_minus_1: q.to_bigint().unwrap() - BigInt::one(),
        })
    }

    /// Initialize a MODP group by generating a safe prime of `length` bits
    pub fn init(length: u32) -> Arc<Self> {
        let q: BigUint = Generator::safe_prime(length as usize);
        let g: BigUint = (q.clone() - BigUint::one()) / BigUint::from(2_u64);

        Arc::new(ModpGroup {
            q: q.to_bigint().unwrap(),
            g: g.to_bigint().unwrap(),
            G: BigInt::from(2),
            q_minus_1: q.to_bigint().unwrap() - BigInt::one(),
        })
    }

    /// Get the safe prime modulus q
    pub fn modulus(&self) -> &BigInt {
        &self.q
    }

    /// Get the subgroup order g (Sophie Germain prime)
    pub fn subgroup_order_value(&self) -> &BigInt {
        &self.g
    }
}

impl Group for ModpGroup {
    type Scalar = BigInt;
    type Element = BigInt;

    fn order(&self) -> &Self::Scalar {
        &self.q_minus_1
    }

    fn subgroup_order(&self) -> &Self::Scalar {
        &self.g
    }

    fn generator(&self) -> Self::Element {
        self.G.clone()
    }

    fn subgroup_generator(&self) -> Self::Element {
        self.g.clone()
    }

    fn identity(&self) -> Self::Element {
        BigInt::one()
    }

    fn exp(
        &self,
        base: &Self::Element,
        scalar: &Self::Scalar,
    ) -> Self::Element {
        base.modpow(scalar, &self.q)
    }

    fn mul(&self, a: &Self::Element, b: &Self::Element) -> Self::Element {
        (a * b) % &self.q
    }

    fn scalar_inverse(&self, x: &Self::Scalar) -> Option<Self::Scalar> {
        crate::util::Util::mod_inverse(x, &self.q_minus_1)
    }

    fn element_inverse(&self, x: &Self::Element) -> Option<Self::Element> {
        crate::util::Util::mod_inverse(x, &self.q)
    }

    fn hash_to_scalar(&self, data: &[u8]) -> Self::Scalar {
        let hash = Sha256::digest(data);
        BigUint::from_bytes_be(&hash[..])
            .mod_floor(&self.g.to_biguint().unwrap())
            .to_bigint()
            .unwrap()
    }

    fn element_to_bytes(&self, elem: &Self::Element) -> Vec<u8> {
        elem.to_biguint().unwrap().to_bytes_be()
    }

    fn bytes_to_element(&self, bytes: &[u8]) -> Option<Self::Element> {
        Some(BigUint::from_bytes_be(bytes).to_bigint().unwrap())
    }

    fn scalar_to_bytes(&self, scalar: &Self::Scalar) -> Vec<u8> {
        scalar.to_biguint().unwrap().to_bytes_be()
    }

    fn generate_private_key(&self) -> Self::Scalar {
        let mut rng = rand::thread_rng();
        loop {
            let privkey: BigInt = rng
                .gen_biguint_below(&self.q.to_biguint().unwrap())
                .to_bigint()
                .unwrap();
            // Private key must be coprime to (q-1) for modular inverse during reconstruction
            if privkey.gcd(&self.q_minus_1) == BigInt::one() {
                return privkey;
            }
        }
    }

    fn generate_public_key(&self, private_key: &Self::Scalar) -> Self::Element {
        self.exp(&self.G, private_key)
    }

    fn scalar_mul(&self, a: &Self::Scalar, b: &Self::Scalar) -> Self::Scalar {
        (a * b) % self.order()
    }

    fn scalar_sub(&self, a: &Self::Scalar, b: &Self::Scalar) -> Self::Scalar {
        let order = self.order();
        let diff = a - b;
        if diff < BigInt::zero() {
            diff + order
        } else {
            diff % order
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_primes::Verification;

    #[test]
    fn test_modp_group_new() {
        let group = ModpGroup::new();
        assert!(Verification::is_safe_prime(&group.q.to_biguint().unwrap()));
        assert!(Verification::is_prime(&group.g.to_biguint().unwrap()));
        assert!(!Verification::is_safe_prime(&group.g.to_biguint().unwrap()));
    }

    #[test]
    fn test_modp_group_init() {
        let group = ModpGroup::init(64);
        assert!(Verification::is_prime(&group.q.to_biguint().unwrap()));
        assert!(Verification::is_prime(&group.g.to_biguint().unwrap()));
        assert_eq!(
            group.g,
            ((group.q.clone() - BigInt::one()).to_biguint().unwrap()
                / BigUint::from(2_u32))
            .to_bigint()
            .unwrap()
        );
    }

    #[test]
    fn test_generate_private_key() {
        let group = ModpGroup::init(64);
        let privkey = group.generate_private_key();
        assert_eq!(privkey.gcd(&group.q_minus_1), BigInt::one());
    }

    #[test]
    fn test_generate_public_key() {
        let group = ModpGroup::new();
        let privkey = group.generate_private_key();
        let pubkey = group.generate_public_key(&privkey);
        // Public key should be G^privkey mod q
        assert_eq!(pubkey, group.G.modpow(&privkey, &group.q));
    }

    #[test]
    fn test_exp() {
        let group = ModpGroup::new();
        let g = group.generator();
        // G^1 = G
        assert_eq!(group.exp(&g, &BigInt::one()), g);
        // G^0 = 1
        assert_eq!(group.exp(&g, &BigInt::zero()), group.identity());
    }

    #[test]
    fn test_mul() {
        let group = ModpGroup::new();
        let a = BigInt::from(5);
        let b = BigInt::from(3);
        let result = group.mul(&a, &b);
        assert_eq!(result, (a * b) % &group.q);
    }

    #[test]
    fn test_hash_to_scalar() {
        let group = ModpGroup::new();
        let data = b"test data";
        let scalar = group.hash_to_scalar(data);
        // Scalar should be less than subgroup order
        assert!(scalar < group.g);
    }
}
