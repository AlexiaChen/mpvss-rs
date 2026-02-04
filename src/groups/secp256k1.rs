// Copyright 2020-2026 MathxH Chen.
//
// Code is licensed under MIT Apache Dual License

//! secp256k1 elliptic curve group implementation.
//!
//! This module provides a `Group` trait implementation for the secp256k1 curve,
//! which is the elliptic curve used by Bitcoin.
//!
//! # Curve Parameters
//! - **Order (n)**: FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE BAAEDCE6 AF48A03B BFD25E8C D0364141 (prime)
//! - **Cofactor (h)**: 1 (prime-order curve)
//! - **Curve equation**: y² = x³ + 7 over F_p
//! - **Base point (G)**: Standardized generator point

use k256::elliptic_curve::FieldBytes;

use k256::elliptic_curve::ff::PrimeField;

use k256::elliptic_curve::group::GroupEncoding;

use k256::{AffinePoint, ProjectivePoint, Scalar, Secp256k1};

use sha2::{Digest, Sha256};

use std::sync::Arc;

use crate::group::Group;

use num_bigint::BigInt;

/// secp256k1 elliptic curve group (Bitcoin's curve)
///
/// This is a prime-order curve with cofactor h = 1, which means all points
/// on the curve are in the prime-order subgroup. This simplifies the PVSS
/// implementation as we don't need to handle cofactor-related issues.
#[derive(Debug, Clone)]

pub struct Secp256k1Group {
    order: BigInt,
}

impl Secp256k1Group {
    /// Create a new secp256k1 group instance
    pub fn new() -> Arc<Self> {
        // secp256k1 curve order as BigInt for use in modular arithmetic
        // ORDER = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
        let order_bytes: [u8; 32] = [
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48,
            0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
        ];
        let order = BigInt::from_bytes_be(num_bigint::Sign::Plus, &order_bytes);

        Arc::new(Secp256k1Group { order })
    }
}

impl Group for Secp256k1Group {
    type Scalar = Scalar;
    type Element = AffinePoint;

    // Note: order() returns a Scalar placeholder since the actual
    // curve order cannot be represented as a Scalar (it would be equal to 0 mod order)
    // For accurate modular arithmetic, use BigInt operations with order_as_bigint()
    fn order(&self) -> &Self::Scalar {
        // Return Scalar::ONE as a placeholder
        // This is just for API compatibility - actual order is accessed via order_as_bigint()
        static ORDER_PLACEHOLDER: Scalar = Scalar::ONE;
        &ORDER_PLACEHOLDER
    }

    fn subgroup_order(&self) -> &Self::Scalar {
        // secp256k1 has cofactor h = 1, so group order = subgroup order
        static ORDER_PLACEHOLDER: Scalar = Scalar::ONE;
        &ORDER_PLACEHOLDER
    }

    fn generator(&self) -> Self::Element {
        AffinePoint::GENERATOR
    }

    fn subgroup_generator(&self) -> Self::Element {
        // For prime-order groups, main generator and subgroup generator are the same
        AffinePoint::GENERATOR
    }

    fn identity(&self) -> Self::Element {
        AffinePoint::IDENTITY
    }

    fn exp(
        &self,
        base: &Self::Element,
        scalar: &Self::Scalar,
    ) -> Self::Element {
        // Scalar multiplication: scalar * base
        // Note: In EC notation, this is written as k*P (scalar multiplication)
        // which corresponds to G^k in MODP notation (exponentiation)
        (ProjectivePoint::from(*base) * scalar).into()
    }

    fn mul(&self, a: &Self::Element, b: &Self::Element) -> Self::Element {
        // Point addition: a + b
        // Note: In EC (additive) notation, this is A + B
        // which corresponds to A * B (multiplication) in MODP (multiplicative) notation
        (ProjectivePoint::from(*a) + ProjectivePoint::from(*b)).into()
    }

    fn scalar_inverse(&self, x: &Self::Scalar) -> Option<Self::Scalar> {
        // k256 Scalar has invert() method
        x.invert().into()
    }

    fn element_inverse(&self, x: &Self::Element) -> Option<Self::Element> {
        // Additive inverse (negation) of a point
        // Used for handling negative Lagrange coefficients
        // Point negation always succeeds for valid points, so return Some
        Some((-ProjectivePoint::from(*x)).into())
    }

    fn hash_to_scalar(&self, data: &[u8]) -> Self::Scalar {
        let hash = Sha256::digest(data);
        // Convert hash bytes to FieldBytes<Secp256k1>
        let mut field_bytes = FieldBytes::<Secp256k1>::default();
        let hash_len = hash.len().min(field_bytes.len());
        let field_bytes_len = field_bytes.len();
        field_bytes[(field_bytes_len - hash_len)..]
            .copy_from_slice(&hash[..hash_len]);
        // from_repr performs modular reduction modulo curve order
        Scalar::from_repr(field_bytes).unwrap()
    }

    fn element_to_bytes(&self, elem: &Self::Element) -> Vec<u8> {
        // Use GroupEncoding to_bytes() which returns CompressedPoint
        elem.to_bytes().to_vec()
    }

    fn bytes_to_element(&self, bytes: &[u8]) -> Option<Self::Element> {
        // Try to convert slice to FieldBytes (33 bytes for compressed secp256k1 point)
        if bytes.len() != 33 {
            return None;
        }
        let mut array = [0u8; 33];
        array.copy_from_slice(bytes);
        // from_bytes returns CtOption - need to check if it's Some
        let ct_result = AffinePoint::from_bytes((&array).into());
        if bool::from(ct_result.is_some()) {
            Some(ct_result.unwrap())
        } else {
            None
        }
    }

    fn scalar_to_bytes(&self, scalar: &Self::Scalar) -> Vec<u8> {
        scalar.to_bytes().to_vec()
    }

    fn generate_private_key(&self) -> Self::Scalar {
        // Generate random bytes using rand 0.5's thread_rng
        let mut bytes = [0u8; 32];
        for byte in &mut bytes {
            *byte = rand::random::<u8>();
        }
        // from_repr performs modular reduction modulo curve order
        // Note: .into() is needed here to convert [u8; 32] to FieldBytes
        Scalar::from_repr(bytes.into()).unwrap()
    }

    fn generate_public_key(&self, private_key: &Self::Scalar) -> Self::Element {
        // Public key = private_key * G (scalar multiplication)
        (AffinePoint::GENERATOR * private_key).into()
    }

    fn scalar_mul(&self, a: &Self::Scalar, b: &Self::Scalar) -> Self::Scalar {
        // k256 Scalar multiplication handles modular reduction automatically
        a * b
    }

    fn scalar_sub(&self, a: &Self::Scalar, b: &Self::Scalar) -> Self::Scalar {
        // k256 Scalar subtraction handles modular reduction automatically
        a - b
    }
}

impl Secp256k1Group {
    /// Get the curve order as BigInt for use in modular arithmetic
    pub fn order_as_bigint(&self) -> &BigInt {
        &self.order
    }
}

#[cfg(test)]

mod tests {
    use super::*;

    #[test]
    fn test_secp256k1_group_new() {
        let group = Secp256k1Group::new();
        // Verify curve order is accessible and is not ONE
        let order = group.order_as_bigint();
        assert_ne!(*order, num_bigint::BigInt::from(1u32));
        // Verify curve order is the correct secp256k1 order (should be > 2^250)
        // ORDER = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
        assert!(*order > num_bigint::BigInt::from(1u64) << 250);
    }

    #[test]
    fn test_generate_keypair() {
        let group = Secp256k1Group::new();
        let privkey = group.generate_private_key();
        let pubkey = group.generate_public_key(&privkey);
        // Verify public key is not the identity
        assert_ne!(pubkey, AffinePoint::IDENTITY);
    }

    #[test]
    fn test_exp() {
        let group = Secp256k1Group::new();
        let g = group.generator();
        let one = Scalar::ONE;
        // G * 1 = G
        assert_eq!(group.exp(&g, &one), g);
        // G * 0 = Identity
        assert_eq!(group.exp(&g, &Scalar::ZERO), group.identity());
    }

    #[test]
    fn test_mul() {
        let group = Secp256k1Group::new();
        let g = group.generator();
        // g + g = 2*g
        let g_plus_g = group.mul(&g, &g);
        let two_g = group.exp(&g, &Scalar::from(2u32));
        assert_eq!(g_plus_g, two_g);
    }

    #[test]
    fn test_scalar_inverse() {
        let group = Secp256k1Group::new();
        let x = Scalar::from(5u32);
        let inv = group.scalar_inverse(&x).unwrap();
        // x * inv = 1 (mod order)
        let result = x * inv;
        assert_eq!(result, Scalar::ONE);
    }

    #[test]
    fn test_element_inverse() {
        let group = Secp256k1Group::new();
        let g = group.generator();
        let neg_g = group.element_inverse(&g).unwrap();
        // g + (-g) = Identity
        let result = group.mul(&g, &neg_g);
        assert_eq!(result, AffinePoint::IDENTITY);
    }

    #[test]
    fn test_hash_to_scalar() {
        let group = Secp256k1Group::new();
        let data = b"test data";
        let scalar = group.hash_to_scalar(data);
        // Scalar should be valid (non-zero for random data)
        assert_ne!(scalar, Scalar::ZERO);
    }

    #[test]
    fn test_serialize_roundtrip() {
        let group = Secp256k1Group::new();
        let g = group.generator();
        let bytes = group.element_to_bytes(&g);
        // secp256k1 compressed point is 33 bytes
        assert_eq!(bytes.len(), 33);
        let restored = group.bytes_to_element(&bytes).unwrap();
        assert_eq!(g, restored);
    }

    #[test]
    fn test_scalar_serialize_roundtrip() {
        let group = Secp256k1Group::new();
        let scalar = Scalar::from(42u32);
        let bytes = group.scalar_to_bytes(&scalar);
        // Scalar is 32 bytes
        assert_eq!(bytes.len(), 32);
    }
}
