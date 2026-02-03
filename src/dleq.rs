// Copyright 2020-2024 MathxH Chen.
//
// Code is licensed under GPLv3.0 License.

//! Generic DLEQ (Discrete Logarithm Equality) proof for multiple cryptographic groups.
//!
//! This module implements the Chaum-Pedersen protocol for proving that log_g1(h1) = log_g2(h2).
//! The generic implementation works with any group implementing the `Group` trait.
//!
//! # Chaum and Pedersen Scheme
//!
//! To prove that log_g1(h1) = log_g2(h2) for generators g1, h1, g2, h2 ∈ Gq,
//! where Gq is a group of order q and q is prime.
//!
//! We denote this protocol by DLEQ(g1, h1, g2, h2), and it consists of the following steps,
//! where the prover knows α such that h1 = g1^α and h2 = g2^α:
//!
//! - The prover sends a1 = g1^w and a2 = g2^w to the verifier, with w ∈ R Zq
//! - The verifier sends a random challenge c ∈ R Zq to the prover
//! - The prover responds with r = w - αc (mod q)
//! - The verifier checks that a1 = (g1^r) * (h1^c) and a2 = (g2^r) * (h2^c)

use sha2::{Digest, Sha256};
use std::sync::Arc;

use crate::group::Group;

// ============================================================================
// Internal Prover/Verifier Structures
// ============================================================================

/// Internal prover structure for DLEQ proof generation
struct Prover {}

impl Prover {
    /// Send a1 = g1^w (MODP) or w*g1 (EC)
    fn send<G: Group>(group: &G, g: &G::Element, w: &G::Scalar) -> G::Element {
        group.exp(g, w)
    }

    /// Compute response r = w - alpha*c (mod order)
    fn response<G: Group>(
        group: &G,
        w: &G::Scalar,
        alpha: &G::Scalar,
        c: &G::Scalar,
    ) -> G::Scalar {
        let alpha_c = group.scalar_mul(alpha, c);
        group.scalar_sub(w, &alpha_c)
    }
}

/// Internal verifier structure for DLEQ proof verification
struct Verifier {}

impl Verifier {
    /// Update challenge hasher with DLEQ data
    ///
    /// Computes a1 = g1^r * h1^c and a2 = g2^r * h2^c for verification
    #[allow(dead_code)]
    #[allow(clippy::too_many_arguments)]
    fn update<G: Group>(
        group: &G,
        g1: &G::Element,
        h1: &G::Element,
        g2: &G::Element,
        h2: &G::Element,
        response: &G::Scalar,
        c: &G::Scalar,
        hasher: &mut Sha256,
    ) where
        G::Scalar: Clone,
        G::Element: Clone,
    {
        // Calc a1, a2
        let g1_r = group.exp(g1, response);
        let h1_c = group.exp(h1, c);
        let a1 = group.mul(&g1_r, &h1_c);

        let g2_r = group.exp(g2, response);
        let h2_c = group.exp(h2, c);
        let a2 = group.mul(&g2_r, &h2_c);

        // Update hash
        hasher.update(group.element_to_bytes(h1));
        hasher.update(group.element_to_bytes(h2));
        hasher.update(group.element_to_bytes(&a1));
        hasher.update(group.element_to_bytes(&a2));
    }

    /// Check that the challenge matches the computed hash
    fn check<G: Group>(group: &G, c: &G::Scalar, hasher: &Sha256) -> bool
    where
        G::Scalar: Clone + Eq,
    {
        let challenge_hash = hasher.clone().finalize();
        let computed = group.hash_to_scalar(&challenge_hash);
        computed == *c
    }
}

// ============================================================================
// Generic DLEQ Proof Structure
// ============================================================================

/// Generic DLEQ (Discrete Logarithm Equality) proof.
///
/// Proves that log_g1(h1) = log_g2(h2) for given generators.
/// This is the Chaum-Pedersen protocol adapted for generic groups.
///
/// # Type Parameters
/// - `G`: A type implementing the `Group` trait
///
/// # Example
///
/// ```rust
/// use mpvss_rs::groups::ModpGroup;
/// use mpvss_rs::dleq::DLEQ;
///
/// let group = ModpGroup::new();
/// let mut dleq = DLEQ::new(group);
/// // ... set up g1, h1, g2, h2, alpha, w
/// // dleq.init(g1, h1, g2, h2, alpha, w);
/// ```
#[derive(Debug, Clone)]
pub struct DLEQ<G: Group> {
    pub g1: G::Element,
    pub h1: G::Element,
    pub g2: G::Element,
    pub h2: G::Element,
    pub w: G::Scalar,
    pub alpha: G::Scalar,
    pub c: Option<G::Scalar>,
    pub r: Option<G::Scalar>,
    pub group: Arc<G>,
}

impl<G: Group> DLEQ<G> {
    /// Create a new DLEQ proof structure.
    pub fn new(group: Arc<G>) -> Self
    where
        G::Scalar: Default,
        G::Element: Default,
    {
        DLEQ {
            g1: Default::default(),
            h1: Default::default(),
            g2: Default::default(),
            h2: Default::default(),
            w: Default::default(),
            alpha: Default::default(),
            c: None,
            r: None,
            group,
        }
    }

    /// Initialize DLEQ with all parameters.
    #[allow(clippy::too_many_arguments)]
    pub fn init(
        &mut self,
        g1: G::Element,
        h1: G::Element,
        g2: G::Element,
        h2: G::Element,
        alpha: G::Scalar,
        w: G::Scalar,
    ) {
        self.g1 = g1;
        self.h1 = h1;
        self.g2 = g2;
        self.h2 = h2;
        self.alpha = alpha;
        self.w = w;
    }

    /// Compute a1 = g1^w (MODP) or w*g1 (EC)
    ///
    /// This is the first commitment sent by the prover.
    pub fn get_a1(&self) -> G::Element {
        Prover::send(self.group.as_ref(), &self.g1, &self.w)
    }

    /// Compute a2 = g2^w (MODP) or w*g2 (EC)
    ///
    /// This is the second commitment sent by the prover.
    pub fn get_a2(&self) -> G::Element {
        Prover::send(self.group.as_ref(), &self.g2, &self.w)
    }

    /// Compute response r = w - alpha*c (mod order)
    ///
    /// The response is computed after receiving the challenge c.
    pub fn get_r(&self) -> Option<G::Scalar>
    where
        G::Scalar: Clone,
    {
        self.c.as_ref().map(|c| {
            Prover::response(self.group.as_ref(), &self.w, &self.alpha, c)
        })
    }

    /// Verify the DLEQ proof.
    ///
    /// Returns `true` if the proof is valid, `false` otherwise.
    pub fn verify(&self) -> bool
    where
        G::Scalar: Clone,
        G::Element: Clone + Eq,
    {
        let c = match &self.c {
            Some(c) => c,
            None => return false,
        };
        let r = match &self.r {
            Some(r) => r,
            None => return false,
        };

        // Compute a1' = g1^r * h1^c (MODP) or r*g1 + c*h1 (EC)
        let g1_r = self.group.exp(&self.g1, r);
        let h1_c = self.group.exp(&self.h1, c);
        let a1_prime = self.group.mul(&g1_r, &h1_c);

        // Compute a2' = g2^r * h2^c (MODP) or r*g2 + c*h2 (EC)
        let g2_r = self.group.exp(&self.g2, r);
        let h2_c = self.group.exp(&self.h2, c);
        let a2_prime = self.group.mul(&g2_r, &h2_c);

        // Check against computed a1, a2
        let a1 = self.get_a1();
        let a2 = self.get_a2();

        a1 == a1_prime && a2 == a2_prime
    }

    /// Update the challenge hasher with DLEQ data.
    ///
    /// This is used to compute the common challenge c from the commitments.
    pub fn update_hash(&self, hasher: &mut Sha256)
    where
        G::Element: Clone,
    {
        hasher.update(self.group.element_to_bytes(&self.h1));
        hasher.update(self.group.element_to_bytes(&self.h2));
        hasher.update(self.group.element_to_bytes(&self.get_a1()));
        hasher.update(self.group.element_to_bytes(&self.get_a2()));
    }

    /// Check that the challenge matches the computed hash.
    ///
    /// This is the final verification step.
    pub fn check(&self, hasher: &Sha256) -> bool
    where
        G::Scalar: Clone + Eq,
    {
        Verifier::check(self.group.as_ref(), self.c.as_ref().unwrap(), hasher)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::groups::ModpGroup;
    use num_bigint::{BigInt, RandBigInt, ToBigInt};
    use num_integer::Integer;
    use num_traits::One;

    #[test]
    fn test_generic_dleq_new() {
        let group = ModpGroup::new();
        let dleq = DLEQ::new(group);
        assert_eq!(dleq.c, None);
        assert_eq!(dleq.r, None);
    }

    #[test]
    fn test_generic_dleq_init() {
        let group = ModpGroup::new();
        let mut dleq = DLEQ::new(group.clone());

        let g1 = BigInt::from(8443);
        let h1 = BigInt::from(531216);
        let g2 = BigInt::from(1299721);
        let h2 = BigInt::from(14767239);
        let w = BigInt::from(81647);
        let alpha = BigInt::from(163027);

        dleq.init(g1.clone(), h1, g2.clone(), h2, alpha, w.clone());

        // Compute expected a1 and a2 values
        let q = group.modulus();
        let a1_expected = g1.modpow(&w, q);
        let a2_expected = g2.modpow(&w, q);

        assert_eq!(dleq.get_a1(), a1_expected);
        assert_eq!(dleq.get_a2(), a2_expected);
    }

    #[test]
    fn test_generic_dleq_get_r() {
        let group = ModpGroup::new();
        let mut dleq = DLEQ::new(group.clone());

        let g1 = BigInt::from(8443);
        let h1 = BigInt::from(531216);
        let g2 = BigInt::from(1299721);
        let h2 = BigInt::from(14767239);
        let w = BigInt::from(81647);
        let alpha = BigInt::from(163027);
        let q = BigInt::from(15487469);

        dleq.init(g1, h1, g2, h2, alpha, w);
        dleq.c = Some(BigInt::from(127997));

        let r = dleq.get_r().unwrap();
        // The response is computed as (w - alpha*c) mod order
        // where order is q-1 for the MODP group
        let order = group.order();
        let expected_r = (BigInt::from(81647)
            - BigInt::from(163027) * BigInt::from(127997))
        .mod_floor(order);

        assert_eq!(r, expected_r);
    }

    #[test]
    fn test_generic_dleq_verify() {
        let group = ModpGroup::new();
        let mut rng = rand::thread_rng();
        let q = group.modulus().clone();

        // Generate random values
        let alpha: BigInt = rng
            .gen_biguint_below(&q.to_biguint().unwrap())
            .to_bigint()
            .unwrap();
        let w: BigInt = rng
            .gen_biguint_below(&q.to_biguint().unwrap())
            .to_bigint()
            .unwrap();

        let g1 = BigInt::from(8443);
        let h1 = g1.modpow(&alpha, &q);
        let g2 = BigInt::from(1299721);
        let h2 = g2.modpow(&alpha, &q);

        let mut dleq = DLEQ::new(group.clone());
        dleq.init(g1, h1, g2, h2, alpha, w);

        // Compute challenge
        let mut hasher = Sha256::new();
        dleq.update_hash(&mut hasher);
        let c = group.hash_to_scalar(&hasher.finalize());
        dleq.c = Some(c.clone());

        // Compute response
        let r = dleq.get_r().unwrap();
        dleq.r = Some(r);

        // Verify should succeed
        assert!(dleq.verify());
    }
}
