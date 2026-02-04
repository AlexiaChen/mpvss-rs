// Copyright 2020-2026 MathxH Chen.
//
// Code is licensed under MIT Apache Dual License

//! Cryptographic group abstraction for PVSS scheme.
//!
//! This trait provides a unified interface for both MODP groups (modular exponentiation)
//! and elliptic curve groups (scalar multiplication), enabling the PVSS scheme to work
//! with different cryptographic backends.

use num_bigint::BigInt;
use sha2::{Digest, Sha256};

/// Cryptographic group abstraction for PVSS operations.
///
/// This trait abstracts the group operations needed for the Publicly Verifiable Secret Sharing scheme.
/// It supports both:
/// - **MODP multiplicative groups**: where `exp(G, k) = G^k mod q` and `mul(A, B) = A * B mod q`
/// - **Elliptic curve additive groups**: where `exp(G, k) = k * G` (scalar multiplication) and `mul(A, B) = A + B` (point addition)
///
/// # Type Parameters
/// - `Scalar`: The scalar type (exponent for MODP, private key for EC)
/// - `Element`: The group element type (BigInt for MODP, Point for EC)
pub trait Group: Clone + Send + Sync {
    /// Scalar type (exponent in MODP, private key in EC)
    type Scalar: Clone + Eq + std::fmt::Debug + Send + Sync;

    /// Group element type (BigInt for MODP, Point for EC)
    type Element: Clone + Eq + std::fmt::Debug + Send + Sync;

    /// Group order (q-1 for MODP, curve order n for EC)
    fn order(&self) -> &Self::Scalar;

    /// Subgroup order (g=(q-1)/2 for MODP, n for EC with cofactor 1)
    fn subgroup_order(&self) -> &Self::Scalar;

    /// Main generator G (used for commitments and public key generation)
    ///
    /// - MODP: G = 2
    /// - secp256k1: AffinePoint::GENERATOR
    fn generator(&self) -> Self::Element;

    /// Subgroup generator g (used for computing commitments C_j = g^a_j)
    ///
    /// - MODP: Sophie Germain prime (q-1)/2
    /// - secp256k1: Same as generator (cofactor is 1)
    fn subgroup_generator(&self) -> Self::Element;

    /// Identity element (1 for MODP, point at infinity for EC)
    fn identity(&self) -> Self::Element;

    /// Group exponentiation/scalar multiplication: base^exp (MODP) or exp*base (EC)
    ///
    /// This is the fundamental group operation used throughout the PVSS scheme:
    /// - Public key generation: P = G^k or k*G
    /// - Commitment computation: C_j = g^a_j or a_j*g
    /// - Share encryption: Y_i = y_i^P(i) or P(i)*y_i
    fn exp(&self, base: &Self::Element, scalar: &Self::Scalar)
    -> Self::Element;

    /// Group multiplication: A * B (MODP) or A + B (EC)
    ///
    /// Used for:
    /// - DLEQ verification: a1 = g^r * h^c or r*g + c*h
    /// - Secret reconstruction: G^s = ∏ S_i^λ_i or Σ λ_i*S_i
    fn mul(&self, a: &Self::Element, b: &Self::Element) -> Self::Element;

    /// Scalar modular inverse (for decryption and Lagrange interpolation)
    ///
    /// Returns None if the inverse doesn't exist (e.g., not coprime to group order)
    fn scalar_inverse(&self, x: &Self::Scalar) -> Option<Self::Scalar>;

    /// Element inverse (for handling negative Lagrange coefficients)
    ///
    /// - MODP: computes x^(-1) mod q
    /// - EC: computes the additive inverse (-point)
    fn element_inverse(&self, x: &Self::Element) -> Option<Self::Element>;

    /// Hash bytes to scalar (for DLEQ challenges)
    ///
    /// The hash is reduced modulo the subgroup order to ensure it's a valid scalar
    fn hash_to_scalar(&self, data: &[u8]) -> Self::Scalar;

    /// Serialize element to bytes (for hashing and storage)
    fn element_to_bytes(&self, elem: &Self::Element) -> Vec<u8>;

    /// Deserialize bytes to element
    ///
    /// Returns None if the bytes don't represent a valid element
    fn bytes_to_element(&self, bytes: &[u8]) -> Option<Self::Element>;

    /// Serialize scalar to bytes
    fn scalar_to_bytes(&self, scalar: &Self::Scalar) -> Vec<u8>;

    /// Generate a random private key (scalar coprime to group order)
    ///
    /// For MODP groups, the private key must be coprime to (q-1) to enable
    /// modular inverse computation during reconstruction.
    /// For elliptic curves with prime order, any non-zero scalar works.
    fn generate_private_key(&self) -> Self::Scalar;

    /// Derive public key from private key: P = G^k (MODP) or P = k*G (EC)
    fn generate_public_key(&self, private_key: &Self::Scalar) -> Self::Element;

    /// Scalar multiplication: (a * b) mod order
    ///
    /// Used for DLEQ response computation: r = w - alpha*c
    fn scalar_mul(&self, a: &Self::Scalar, b: &Self::Scalar) -> Self::Scalar;

    /// Scalar subtraction: (a - b) mod order
    ///
    /// Used for DLEQ response computation: r = w - alpha*c
    fn scalar_sub(&self, a: &Self::Scalar, b: &Self::Scalar) -> Self::Scalar;

    /// Get the group modulus (for MODP groups) or None for groups without a modulus
    ///
    /// - MODP: Returns the safe prime q
    /// - EC: Returns None (no modulus concept)
    ///
    /// This is used for U encoding in the PVSS scheme (secret XOR H(G^s))
    fn modulus(&self) -> Option<&BigInt> {
        None
    }
}

/// Helper function to compute SHA-256 hash of multiple byte sequences
pub fn hash_multiple(inputs: &[&[u8]]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    for input in inputs {
        hasher.update(input);
    }
    hasher.finalize().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_multiple() {
        let result = hash_multiple(&[b"hello", b" ", b"world"]);
        let expected = Sha256::digest(b"hello world").to_vec();
        assert_eq!(result, expected);
    }
}
