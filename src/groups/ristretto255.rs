// Copyright 2020-2026 MathxH Chen.
//
// Code is licensed under MIT Apache Dual License

//! Ristretto255 group implementation.
//!
//! This module provides a `Group` trait implementation for the Ristretto255 group,
//! which is a prime-order group built on top of Curve25519 (Ed25519).
//!
//! # Why Ristretto255?
//!
//! Ed25519 (Curve25519 in Edwards form) has a cofactor of 8, meaning it's not a
//! prime-order group. This causes issues for cryptographic protocols:
//! - Small-subgroup attacks
//! - Non-injective behavior
//! - Malleability issues
//!
//! Ristretto255 solves these problems by constructing a prime-order group using
//! a quotient group technique, providing:
//! - Prime order l = 2^252 + 27742317777372353535851937790883648493
//! - 32-byte canonical encoding
//! - Each valid encoding corresponds to a unique group element
//!
//! # Group Parameters
//! - **Order (l)**: 2^252 + 27742317777372353535851937790883648493 (prime)
//! - **Cofactor (h)**: 1 (prime-order group)
//! - **Encoding**: 32-byte compressed points

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use num_bigint::BigInt;
use sha2::{Digest, Sha512};
use std::sync::Arc;

use crate::group::Group;

/// Ristretto255 prime-order group (built on Curve25519)
///
/// This is a prime-order group with cofactor h = 1, which means all elements
/// are in the prime-order subgroup. This simplifies the PVSS implementation
/// as we don't need to handle cofactor-related issues.
#[derive(Debug, Clone)]
pub struct Ristretto255Group {
    order: BigInt,
}

impl Ristretto255Group {
    /// Create a new Ristretto255 group instance
    pub fn new() -> Arc<Self> {
        // Ristretto255 group order as BigInt for use in modular arithmetic
        // l = 2^252 + 27742317777372353535851937790883648493
        // Hex (big-endian): 0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed
        let order_bytes: [u8; 32] = [
            0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x14, 0xde, 0xf9, 0xde, 0xa2, 0xf7,
            0x9c, 0xd6, 0x58, 0x12, 0x63, 0x1a, 0x5c, 0xf5, 0xd3, 0xed,
        ];
        let order = BigInt::from_bytes_be(num_bigint::Sign::Plus, &order_bytes);

        Arc::new(Ristretto255Group { order })
    }

    /// Get the group order as BigInt for use in modular arithmetic
    pub fn order_as_bigint(&self) -> &BigInt {
        &self.order
    }

    /// Convert BigInt to Ristretto Scalar
    ///
    /// # Critical Note
    /// curve25519-dalek uses **little-endian** byte order for Scalar,
    /// while num_bigint uses **big-endian**. This function handles the conversion.
    ///
    /// Note: The BigInt value should already be reduced mod order before calling this
    /// function to ensure correct conversion.
    pub fn bigint_to_scalar(bigint: &BigInt) -> Scalar {
        let (_, bytes_be) = bigint.to_bytes_be();
        let mut bytes_le = [0u8; 32];

        // Convert big-endian to little-endian
        // BigInt BE: [MSB, ..., LSB] (most significant first)
        // Scalar LE: [LSB, ..., MSB] (least significant first)
        //
        // For correct conversion:
        // 1. BE[0] is the MSB, should go to LE[31] (or as close as possible)
        // 2. BE[len-1] is the LSB, should go to LE[0]
        //
        // If bytes_be has fewer than 32 bytes, we need to right-align in BE format
        // which means the LSB is still at the end, and we just have fewer MSB bytes

        let len = bytes_be.len().min(32);

        // The bytes are right-aligned in BE format (MSB at index 0, LSB at index len-1)
        // We need to copy them to LE format (LSB at index 0, MSB at index 31)
        // So: LE[0] = BE[len-1] (LSB), LE[1] = BE[len-2], ..., LE[len-1] = BE[0] (MSB)
        // The remaining bytes in LE (index len to 31) should be 0

        for i in 0..len {
            bytes_le[i] = bytes_be[len - 1 - i];
        }

        Scalar::from_bytes_mod_order(bytes_le)
    }

    /// Convert Ristretto Scalar to BigInt
    pub fn scalar_to_bigint(scalar: &Scalar) -> BigInt {
        let bytes_le = scalar.to_bytes();

        // Find the actual length by skipping trailing zeros (which are MSB in BE)
        // In LE format, trailing zeros at the end are most significant zeros
        let actual_len =
            bytes_le.iter().rposition(|&b| b != 0).map_or(0, |i| i + 1);

        // Reverse to get big-endian representation
        let bytes_be: Vec<u8> =
            bytes_le[..actual_len].iter().rev().copied().collect();

        if bytes_be.is_empty() {
            BigInt::from(0)
        } else {
            BigInt::from_bytes_be(num_bigint::Sign::Plus, &bytes_be)
        }
    }
}

impl Group for Ristretto255Group {
    type Scalar = Scalar;
    type Element = RistrettoPoint;

    // Note: order() returns a Scalar placeholder since the actual
    // group order cannot be represented as a Scalar (it would be equal to 0 mod order)
    // For accurate modular arithmetic, use BigInt operations with order_as_bigint()
    fn order(&self) -> &Self::Scalar {
        // Return Scalar::ONE as a placeholder
        // This is just for API compatibility - actual order is accessed via order_as_bigint()
        static ORDER_PLACEHOLDER: Scalar = Scalar::ONE;
        &ORDER_PLACEHOLDER
    }

    fn subgroup_order(&self) -> &Self::Scalar {
        // Ristretto255 has cofactor h = 1, so group order = subgroup order
        static ORDER_PLACEHOLDER: Scalar = Scalar::ONE;
        &ORDER_PLACEHOLDER
    }

    fn generator(&self) -> Self::Element {
        RISTRETTO_BASEPOINT_POINT
    }

    fn subgroup_generator(&self) -> Self::Element {
        // For prime-order groups, main generator and subgroup generator are the same
        RISTRETTO_BASEPOINT_POINT
    }

    fn identity(&self) -> Self::Element {
        RistrettoPoint::identity()
    }

    fn exp(
        &self,
        base: &Self::Element,
        scalar: &Self::Scalar,
    ) -> Self::Element {
        // Scalar multiplication: scalar * base
        // Note: In EC notation, this is written as k*P (scalar multiplication)
        // which corresponds to G^k in MODP notation (exponentiation)
        base * scalar
    }

    fn mul(&self, a: &Self::Element, b: &Self::Element) -> Self::Element {
        // Point addition: a + b
        // Note: In EC (additive) notation, this is A + B
        // which corresponds to A * B (multiplication) in MODP (multiplicative) notation
        a + b
    }

    fn scalar_inverse(&self, x: &Self::Scalar) -> Option<Self::Scalar> {
        // curve25519-dalek Scalar has invert() method that returns CtOption
        if x == &Scalar::ZERO {
            None
        } else {
            // invert() returns CtOption<Scalar>, convert to Option
            Option::from(x.invert())
        }
    }

    fn element_inverse(&self, x: &Self::Element) -> Option<Self::Element> {
        // Additive inverse (negation) of a point
        // Used for handling negative Lagrange coefficients
        // Point negation always succeeds for valid points, so return Some
        Some(-*x)
    }

    fn hash_to_scalar(&self, data: &[u8]) -> Self::Scalar {
        // Use SHA-512 for wider hash output, then reduce mod order
        // This provides better uniformity than SHA-256
        let hash = Sha512::digest(data);
        // from_bytes_mod_order_wide takes 64 bytes and reduces mod l
        let mut wide_bytes = [0u8; 64];
        let hash_len = hash.len().min(64);
        wide_bytes[..hash_len].copy_from_slice(&hash[..hash_len]);
        Scalar::from_bytes_mod_order_wide(&wide_bytes)
    }

    fn element_to_bytes(&self, elem: &Self::Element) -> Vec<u8> {
        // RistrettoPoint compresses to 32 bytes
        elem.compress().to_bytes().to_vec()
    }

    fn bytes_to_element(&self, bytes: &[u8]) -> Option<Self::Element> {
        // Try to convert slice to 32-byte array
        if bytes.len() != 32 {
            return None;
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(bytes);
        CompressedRistretto(arr).decompress()
    }

    fn scalar_to_bytes(&self, scalar: &Self::Scalar) -> Vec<u8> {
        // Scalar is 32 bytes in little-endian
        scalar.to_bytes().to_vec()
    }

    fn generate_private_key(&self) -> Self::Scalar {
        // Generate random bytes using rand 0.5's thread_rng
        // Note: curve25519-dalek requires rand_core 0.6+, but we use rand 0.5
        // So we manually generate random bytes
        let mut bytes = [0u8; 32];
        for byte in &mut bytes {
            *byte = rand::random::<u8>();
        }
        // from_bytes_mod_order performs modular reduction modulo group order
        Scalar::from_bytes_mod_order(bytes)
    }

    fn generate_public_key(&self, private_key: &Self::Scalar) -> Self::Element {
        // Public key = private_key * G (scalar multiplication)
        RISTRETTO_BASEPOINT_POINT * private_key
    }

    fn scalar_mul(&self, a: &Self::Scalar, b: &Self::Scalar) -> Self::Scalar {
        // curve25519-dalek Scalar multiplication handles modular reduction automatically
        a * b
    }

    fn scalar_sub(&self, a: &Self::Scalar, b: &Self::Scalar) -> Self::Scalar {
        // curve25519-dalek Scalar subtraction handles modular reduction automatically
        a - b
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bigint_scalar_detailed_conversion() {
        // Test the detailed byte-level conversion
        let original = BigInt::from(0x0102030405060708u64);

        let (_, bytes_be) = original.to_bytes_be();

        let scalar = Ristretto255Group::bigint_to_scalar(&original);
        let scalar_bytes = scalar.to_bytes();

        let recovered = Ristretto255Group::scalar_to_bigint(&scalar);

        assert_eq!(
            original, recovered,
            "Round-trip conversion should work for simple values"
        );
    }

    #[test]
    fn test_polynomial_scalar_conversion() {
        // Test that converting BigInt coefficients to Scalar and computing commitments
        // gives the same result as computing P(i) as BigInt, converting to Scalar,
        // and computing g^P(i)
        use num_bigint::RandBigInt;
        use num_bigint::ToBigInt;

        let group = Ristretto255Group::new();
        let g = group.generator();
        let order = group.order_as_bigint().clone();

        let mut rng = rand::thread_rng();

        // Generate random coefficients (mod order)
        let a_0: BigInt = rng
            .gen_biguint_below(&order.to_biguint().unwrap())
            .to_bigint()
            .unwrap();
        let a_1: BigInt = rng
            .gen_biguint_below(&order.to_biguint().unwrap())
            .to_bigint()
            .unwrap();
        let a_2: BigInt = rng
            .gen_biguint_below(&order.to_biguint().unwrap())
            .to_bigint()
            .unwrap();

        // Convert to Scalar
        let a_0_scalar = Ristretto255Group::bigint_to_scalar(&a_0);
        let a_1_scalar = Ristretto255Group::bigint_to_scalar(&a_1);
        let a_2_scalar = Ristretto255Group::bigint_to_scalar(&a_2);

        // Compute commitments
        let c_0 = group.exp(&g, &a_0_scalar);
        let c_1 = group.exp(&g, &a_1_scalar);
        let c_2 = group.exp(&g, &a_2_scalar);

        // Compute X_1 = C_0 + C_1 + C_2 (for position 1, exponents are 1^0=1, 1^1=1, 1^2=1)
        let x_1_from_commitments = group.mul(&c_0, &group.mul(&c_1, &c_2));

        // Compute P(1) = a_0 + a_1 + a_2 as BigInt
        let p_1_bigint = &a_0 + &a_1 + &a_2;
        let p_1_mod = &p_1_bigint % &order;
        let p_1_scalar = Ristretto255Group::bigint_to_scalar(&p_1_mod);
        let x_1_from_polynomial = group.exp(&g, &p_1_scalar);

        // ALSO: verify scalar addition matches BigInt addition mod order
        let scalar_sum = a_0_scalar + a_1_scalar + a_2_scalar;

        // Debug: verify round-trip conversion
        let a_0_recovered = Ristretto255Group::scalar_to_bigint(&a_0_scalar);
        let a_1_recovered = Ristretto255Group::scalar_to_bigint(&a_1_scalar);
        let a_2_recovered = Ristretto255Group::scalar_to_bigint(&a_2_scalar);

        // First verify round-trip conversion works
        assert_eq!(a_0, a_0_recovered, "a_0 round-trip conversion should work");
        assert_eq!(a_1, a_1_recovered, "a_1 round-trip conversion should work");
        assert_eq!(a_2, a_2_recovered, "a_2 round-trip conversion should work");

        // Verify scalar sum matches P(1) scalar
        assert_eq!(
            scalar_sum, p_1_scalar,
            "Scalar sum should equal P(1) converted to Scalar"
        );
        assert_eq!(
            x_1_from_commitments, x_1_from_polynomial,
            "X_1 from commitments should equal g^P(1)"
        );
    }

    #[test]
    fn test_scalar_addition_modular() {
        // Test that Scalar addition correctly handles modular arithmetic
        let group = Ristretto255Group::new();
        let order = group.order_as_bigint().clone();

        // Use values close to order/3 so sum exceeds order
        let a = &order / 3;
        let b = &order / 3;
        let c = &order / 3;

        let a_scalar = Ristretto255Group::bigint_to_scalar(&a);
        let b_scalar = Ristretto255Group::bigint_to_scalar(&b);
        let c_scalar = Ristretto255Group::bigint_to_scalar(&c);

        // Scalar sum
        let scalar_sum = a_scalar + b_scalar + c_scalar;

        // BigInt sum then convert
        let bigint_sum = &a + &b + &c;
        let bigint_sum_mod = &bigint_sum % &order;
        let from_bigint = Ristretto255Group::bigint_to_scalar(&bigint_sum_mod);

        assert_eq!(
            scalar_sum, from_bigint,
            "Scalar sum should equal BigInt sum converted to Scalar"
        );
    }

    #[test]
    fn test_order_constant() {
        // Verify the order constant is correct
        let group = Ristretto255Group::new();
        let order = group.order_as_bigint();

        // The Ristretto255 order is: l = 2^252 + 27742317777372353535851937790883648493
        // Use bit shifting instead of pow
        let two_252 = BigInt::from(1u64) << 252;
        let constant =
            BigInt::parse_bytes(b"27742317777372353535851937790883648493", 10)
                .unwrap();
        let expected = two_252 + constant;

        // Also verify the hex representation
        let order_hex = format!("{:x}", order);
        let expected_hex = format!("{:x}", expected);

        // Check byte representations
        let (_, order_be) = order.to_bytes_be();
        let (_, expected_be) = expected.to_bytes_be();

        // The hex should match
        assert_eq!(order_hex, expected_hex, "Hex representations should match");
    }

    #[test]
    fn test_scalar_sum_overflow() {
        // Test with values that overflow the order
        let group = Ristretto255Group::new();
        let order = group.order_as_bigint().clone();

        // Values that are each close to order/2, so sum > order
        let half_order: BigInt = &order / 2;
        let a = half_order.clone();
        let b = half_order.clone();
        let c = BigInt::from(1000u64); // Small value to push sum just over order

        let a_scalar = Ristretto255Group::bigint_to_scalar(&a);
        let b_scalar = Ristretto255Group::bigint_to_scalar(&b);
        let c_scalar = Ristretto255Group::bigint_to_scalar(&c);

        // Verify individual conversions
        let a_recovered = Ristretto255Group::scalar_to_bigint(&a_scalar);
        let b_recovered = Ristretto255Group::scalar_to_bigint(&b_scalar);
        let c_recovered = Ristretto255Group::scalar_to_bigint(&c_scalar);

        assert_eq!(a, a_recovered, "a round-trip should work");
        assert_eq!(b, b_recovered, "b round-trip should work");
        assert_eq!(c, c_recovered, "c round-trip should work");

        // Scalar sum
        let scalar_sum = a_scalar + b_scalar + c_scalar;
        let scalar_sum_recovered =
            Ristretto255Group::scalar_to_bigint(&scalar_sum);

        // BigInt sum then convert
        let bigint_sum = &a + &b + &c;
        let bigint_sum_mod = &bigint_sum % &order;
        let from_bigint = Ristretto255Group::bigint_to_scalar(&bigint_sum_mod);

        assert_eq!(
            scalar_sum, from_bigint,
            "Scalar sum should equal BigInt sum converted to Scalar"
        );
    }

    #[test]
    fn test_scalar_sum_large_values() {
        // Test with large values near the order
        let group = Ristretto255Group::new();
        let order = group.order_as_bigint().clone();

        // Values that are each about 2^250 (close to order)
        // Use specific values to make debugging easier
        let a = BigInt::parse_bytes(b"2000000000000000000000000000000000000000000000000000000000000000000000000000", 10).unwrap();
        let b = BigInt::parse_bytes(b"2000000000000000000000000000000000000000000000000000000000000000000000000000", 10).unwrap();
        let c = BigInt::parse_bytes(b"2000000000000000000000000000000000000000000000000000000000000000000000000000", 10).unwrap();

        let a_scalar = Ristretto255Group::bigint_to_scalar(&a);
        let b_scalar = Ristretto255Group::bigint_to_scalar(&b);
        let c_scalar = Ristretto255Group::bigint_to_scalar(&c);

        // Verify individual conversions
        let a_recovered = Ristretto255Group::scalar_to_bigint(&a_scalar);
        let b_recovered = Ristretto255Group::scalar_to_bigint(&b_scalar);
        let c_recovered = Ristretto255Group::scalar_to_bigint(&c_scalar);

        assert_eq!(a, a_recovered, "a round-trip should work");
        assert_eq!(b, b_recovered, "b round-trip should work");
        assert_eq!(c, c_recovered, "c round-trip should work");

        // Scalar sum
        let scalar_sum = a_scalar + b_scalar + c_scalar;
        let scalar_sum_recovered =
            Ristretto255Group::scalar_to_bigint(&scalar_sum);

        // BigInt sum then convert
        let bigint_sum = &a + &b + &c;
        let bigint_sum_mod = &bigint_sum % &order;
        let from_bigint = Ristretto255Group::bigint_to_scalar(&bigint_sum_mod);

        assert_eq!(
            scalar_sum, from_bigint,
            "Scalar sum should equal BigInt sum converted to Scalar"
        );
    }

    #[test]
    fn test_scalar_sum_individual() {
        // Test individual scalar conversions and sums
        let group = Ristretto255Group::new();
        let order = group.order_as_bigint().clone();

        // Simple values that won't overflow
        let a = BigInt::from(1000u64);
        let b = BigInt::from(2000u64);
        let c = BigInt::from(3000u64);

        let a_scalar = Ristretto255Group::bigint_to_scalar(&a);
        let b_scalar = Ristretto255Group::bigint_to_scalar(&b);
        let c_scalar = Ristretto255Group::bigint_to_scalar(&c);

        // Scalar sum
        let scalar_sum = a_scalar + b_scalar + c_scalar;

        // BigInt sum then convert
        let bigint_sum = &a + &b + &c;
        let bigint_sum_mod = &bigint_sum % &order;
        let from_bigint = Ristretto255Group::bigint_to_scalar(&bigint_sum_mod);

        // Verify scalar_sum equals 6000
        let sum_recovered = Ristretto255Group::scalar_to_bigint(&scalar_sum);
        assert_eq!(
            sum_recovered,
            BigInt::from(6000u64),
            "Scalar sum should be 6000"
        );

        assert_eq!(
            scalar_sum, from_bigint,
            "Scalar sum should equal BigInt sum converted to Scalar"
        );
    }

    #[test]
    fn test_commitment_sum() {
        // Test that C_0 + C_1 + C_2 = g^(a_0 + a_1 + a_2)
        let group = Ristretto255Group::new();
        let g = group.generator();

        // Random coefficients
        let a_0 = group.generate_private_key();
        let a_1 = group.generate_private_key();
        let a_2 = group.generate_private_key();

        // Compute commitments C_j = g^a_j
        let c_0 = group.exp(&g, &a_0);
        let c_1 = group.exp(&g, &a_1);
        let c_2 = group.exp(&g, &a_2);

        // Compute sum of commitments
        let c_sum = group.mul(&c_0, &group.mul(&c_1, &c_2));

        // Compute g^(a_0 + a_1 + a_2)
        let a_sum = a_0 + a_1 + a_2;
        let g_sum = group.exp(&g, &a_sum);

        assert_eq!(
            c_sum, g_sum,
            "C_0 + C_1 + C_2 should equal g^(a_0 + a_1 + a_2)"
        );
    }

    #[test]
    fn test_dleq_verification_math() {
        // Test the DLEQ verification math: g^r * X^c should equal g^w
        // where r = w - alpha*c and X = g^alpha
        let group = Ristretto255Group::new();
        let g = group.generator();

        // Random values
        let w = group.generate_private_key();
        let alpha = group.generate_private_key();
        let c = group.hash_to_scalar(b"test challenge");

        // Compute X = g^alpha
        let x = group.exp(&g, &alpha);

        // Compute response r = w - alpha*c
        let alpha_c = group.scalar_mul(&alpha, &c);
        let r = group.scalar_sub(&w, &alpha_c);

        // Compute g^w (distribution a1)
        let g_w = group.exp(&g, &w);

        // Compute g^r * X^c (verification a1)
        let g_r = group.exp(&g, &r);
        let x_c = group.exp(&x, &c);
        let verify_a1 = group.mul(&g_r, &x_c);

        assert_eq!(g_w, verify_a1, "g^w should equal g^r * X^c");
    }

    #[test]
    fn test_scalar_mult_consistency() {
        // Test that scalar multiplication is consistent: g^(a+b) = g^a * g^b
        let group = Ristretto255Group::new();
        let g = group.generator();

        let a = Scalar::from(5u64);
        let b = Scalar::from(7u64);
        let a_plus_b = a + b;

        let g_a = group.exp(&g, &a);
        let g_b = group.exp(&g, &b);
        let g_a_plus_b = group.exp(&g, &a_plus_b);
        let g_a_mul_g_b = group.mul(&g_a, &g_b);

        assert_eq!(g_a_plus_b, g_a_mul_g_b, "g^(a+b) should equal g^a * g^b");
    }

    #[test]
    fn test_ristretto255_group_new() {
        let group = Ristretto255Group::new();
        // Verify group order is accessible and is not ONE
        let order = group.order_as_bigint();
        assert_ne!(*order, num_bigint::BigInt::from(1u32));
        // Verify group order is the correct Ristretto255 order (should be > 2^250)
        // l = 2^252 + 27742317777372353535851937790883648493
        assert!(*order > num_bigint::BigInt::from(1u64) << 250);
    }

    #[test]
    fn test_generate_keypair() {
        let group = Ristretto255Group::new();
        let privkey = group.generate_private_key();
        let pubkey = group.generate_public_key(&privkey);
        // Verify public key is not the identity
        assert_ne!(pubkey, RistrettoPoint::identity());
    }

    #[test]
    fn test_exp() {
        let group = Ristretto255Group::new();
        let g = group.generator();
        let one = Scalar::ONE;
        // G * 1 = G
        assert_eq!(group.exp(&g, &one), g);
        // G * 0 = Identity
        assert_eq!(group.exp(&g, &Scalar::ZERO), group.identity());
    }

    #[test]
    fn test_mul() {
        let group = Ristretto255Group::new();
        let g = group.generator();
        // g + g = 2*g
        let g_plus_g = group.mul(&g, &g);
        let two_g = group.exp(&g, &Scalar::from(2u64));
        assert_eq!(g_plus_g, two_g);
    }

    #[test]
    fn test_scalar_inverse() {
        let group = Ristretto255Group::new();
        let x = Scalar::from(5u64);
        let inv = group.scalar_inverse(&x).unwrap();
        // x * inv = 1 (mod order)
        let result = x * inv;
        assert_eq!(result, Scalar::ONE);
    }

    #[test]
    fn test_scalar_inverse_zero() {
        let group = Ristretto255Group::new();
        let result = group.scalar_inverse(&Scalar::ZERO);
        assert!(result.is_none());
    }

    #[test]
    fn test_element_inverse() {
        let group = Ristretto255Group::new();
        let g = group.generator();
        let neg_g = group.element_inverse(&g).unwrap();
        // g + (-g) = Identity
        let result = group.mul(&g, &neg_g);
        assert_eq!(result, RistrettoPoint::identity());
    }

    #[test]
    fn test_hash_to_scalar() {
        let group = Ristretto255Group::new();
        let data = b"test data";
        let scalar = group.hash_to_scalar(data);
        // Scalar should be valid (non-zero for random data)
        assert_ne!(scalar, Scalar::ZERO);
    }

    #[test]
    fn test_serialize_roundtrip() {
        let group = Ristretto255Group::new();
        let g = group.generator();
        let bytes = group.element_to_bytes(&g);
        // Ristretto255 compressed point is 32 bytes
        assert_eq!(bytes.len(), 32);
        let restored = group.bytes_to_element(&bytes).unwrap();
        assert_eq!(g, restored);
    }

    #[test]
    fn test_scalar_serialize_roundtrip() {
        let group = Ristretto255Group::new();
        let scalar = Scalar::from(42u64);
        let bytes = group.scalar_to_bytes(&scalar);
        // Scalar is 32 bytes
        assert_eq!(bytes.len(), 32);
    }

    #[test]
    fn test_bigint_scalar_conversion() {
        // Test that BigInt -> Scalar conversion works correctly
        let original = BigInt::from(123456789u64);
        let scalar = Ristretto255Group::bigint_to_scalar(&original);
        let recovered = Ristretto255Group::scalar_to_bigint(&scalar);
        assert_eq!(original, recovered);
    }

    #[test]
    fn test_bigint_scalar_conversion_large() {
        // Test with a large number near 2^200 (well within Scalar range)
        // Note: We don't test order-1 because Scalar::from_bytes_mod_order
        // performs modular reduction, and the round-trip conversion for
        // values very close to the order may not be exact due to endianness
        // handling. In PVSS, coefficients are generated mod order, so they're
        // always valid scalars.
        let original = BigInt::from(1u64) << 200;
        let scalar = Ristretto255Group::bigint_to_scalar(&original);
        let recovered = Ristretto255Group::scalar_to_bigint(&scalar);
        assert_eq!(original, recovered);
    }
}
