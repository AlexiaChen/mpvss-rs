// Copyright 2020-2024 MathxH Chen.
//
// Code is licensed under GPLv3.0 License.

//! MPVSS (Publicly Verifiable Secret Sharing) implementation for multiple cryptographic groups.
//!
//! This module implements the PVSS scheme using the Group trait abstraction, enabling
//! the scheme to work with different cryptographic backends (MODP, secp256k1, etc.).

#![allow(non_snake_case)]

use num_bigint::BigInt;
use num_traits::identities::One;
use sha2::{Digest, Sha256};
use std::sync::Arc;

use crate::group::Group;
use crate::sharebox::{DistributionSharesBox, ShareBox};

// ============================================================================
// PVSS Structure
// ============================================================================

/// PVSS (Publicly Verifiable Secret Sharing) for multiple cryptographic groups.
///
/// This structure provides PVSS operations using the Group trait abstraction.
/// It handles verification of distribution shares and secret reconstruction.
///
/// # Type Parameters
/// - `G`: A type implementing the `Group` trait
///
/// # Example
///
/// ```rust
/// use mpvss_rs::groups::ModpGroup;
/// use mpvss_rs::mpvss::PVSS;
///
/// let group = ModpGroup::new();
/// let pvss = PVSS::new(group);
/// ```
#[derive(Debug, Clone)]
pub struct PVSS<G: Group> {
    group: Arc<G>,
}

impl<G: Group> PVSS<G> {
    /// Create a new generic PVSS instance.
    pub fn new(group: Arc<G>) -> Self {
        PVSS { group }
    }

    /// Get a reference to the underlying group.
    pub fn group(&self) -> &G {
        &self.group
    }

    /// Get the Arc reference to the group.
    pub fn group_arc(&self) -> Arc<G> {
        self.group.clone()
    }
}

// ============================================================================
// Distribution Shares Verification
// ============================================================================

impl<G: Group> PVSS<G>
where
    G::Scalar: Clone + One,
    G::Element: Clone + Eq + Ord,
{
    /// Verify that the shares in the distribution shares box are consistent.
    ///
    /// This is the public verifiability part of PVSS - anyone can verify the dealer
    /// didn't cheat. The verification checks that all encrypted shares are consistent
    /// with the commitments.
    ///
    /// # Parameters
    /// - `distribute_sharesbox`: The distribution shares box to verify
    ///
    /// # Returns
    /// `true` if the distribution is valid, `false` otherwise
    ///
    /// # Verification Process
    ///
    /// The verifier computes X_i = ∏(j = 0 -> t - 1): (C_j)^(i^j) from the C_j values.
    /// Using y_i, X_i, Y_i, r_i, 1 ≤ i ≤ n and c as input, the verifier computes a_1i, a_2i as:
    /// a_1i = g^(r_i) * X_i^c,   a_2i = y_i^(r_i) * Y_i^c
    /// and checks that the hash of X_i, Y_i, a_1i, a_2i, 1 ≤ i ≤ n, matches c.
    pub fn verify_distribution_shares(
        &self,
        distribute_sharesbox: &DistributionSharesBox<G>,
    ) -> bool {
        let subgroup_gen = self.group.subgroup_generator();
        let mut challenge_hasher = Sha256::new();

        // Verify each participant's encrypted share and accumulate hash
        for publickey in &distribute_sharesbox.publickeys {
            let position = distribute_sharesbox.positions.get(publickey);
            let response = distribute_sharesbox.responses.get(publickey);
            let encrypted_share = distribute_sharesbox.shares.get(publickey);

            if position.is_none()
                || response.is_none()
                || encrypted_share.is_none()
            {
                return false;
            }

            // Calculate X_i = ∏_{j=0}^{t-1} C_j^{i^j} using group operations
            let mut x_val = self.group.identity();
            let mut exponent = G::Scalar::one();
            for j in 0..distribute_sharesbox.commitments.len() {
                let c_j_pow = self
                    .group
                    .exp(&distribute_sharesbox.commitments[j], &exponent);
                x_val = self.group.mul(&x_val, &c_j_pow);
                // Note: This assumes we can create a scalar from position
                // For generic groups, this would need to be handled differently
                let pos_scalar = Self::position_to_scalar(*position.unwrap());
                exponent = self.group.scalar_mul(&exponent, &pos_scalar);
                if j < distribute_sharesbox.commitments.len() - 1 {
                    // Only mod if not the last iteration (avoid unnecessary ops)
                    let _ = &exponent;
                }
            }

            // Verify DLEQ proof for this participant
            // DLEQ(g, X_i, y_i, Y_i): proves log_g(X_i) = log_{y_i}(Y_i)
            // a_1 = g^r * X_i^c, a_2 = y_i^r * Y_i^c
            let g_r = self.group.exp(&subgroup_gen, response.unwrap());
            let x_c = self.group.exp(&x_val, &distribute_sharesbox.challenge);
            let a1 = self.group.mul(&g_r, &x_c);

            let y_r = self.group.exp(publickey, response.unwrap());
            let y_c = self
                .group
                .exp(encrypted_share.unwrap(), &distribute_sharesbox.challenge);
            let a2 = self.group.mul(&y_r, &y_c);

            // Update hash with X_i, Y_i, a_1, a_2
            challenge_hasher.update(self.group.element_to_bytes(&x_val));
            challenge_hasher
                .update(self.group.element_to_bytes(encrypted_share.unwrap()));
            challenge_hasher.update(self.group.element_to_bytes(&a1));
            challenge_hasher.update(self.group.element_to_bytes(&a2));
        }

        // Calculate final challenge and check if it matches c
        let challenge_hash = challenge_hasher.finalize();
        let computed_challenge = self.group.hash_to_scalar(&challenge_hash);

        computed_challenge == distribute_sharesbox.challenge
    }

    /// Helper: Convert position (i64) to Scalar
    ///
    /// This is a placeholder - proper implementation would need to be trait-based
    fn position_to_scalar(pos: i64) -> G::Scalar {
        // This is a simplified version - proper implementation would need
        // the Group trait to provide this conversion
        // For now, this is only used in the ModpGroup case where Scalar = BigInt
        // and we can use the From trait
        let _ = pos;
        panic!(
            "position_to_scalar needs to be implemented for the specific group type"
        );
    }
}

// ============================================================================
// ModpGroup-Specific Implementation
// ============================================================================

impl PVSS<crate::groups::ModpGroup> {
    /// Verify distribution shares (ModpGroup-specific implementation).
    ///
    /// This delegates to the existing ModpGroup implementation in generic_participant.
    pub fn verify_distribution_shares_modp(
        &self,
        distribute_sharesbox: &DistributionSharesBox<crate::groups::ModpGroup>,
    ) -> bool {
        // Delegate to the existing implementation
        // This avoids code duplication while we work on full generic support
        use crate::participant::Participant;

        let temp_participant = Participant::with_arc(self.group.clone());
        temp_participant.verify_distribution_shares_modp(distribute_sharesbox)
    }

    /// Verify share (ModpGroup-specific implementation).
    pub fn verify_share_modp(
        &self,
        sharebox: &ShareBox<crate::groups::ModpGroup>,
        distribution_sharebox: &DistributionSharesBox<crate::groups::ModpGroup>,
        publickey: &BigInt,
    ) -> bool {
        use crate::participant::Participant;

        let temp_participant = Participant::with_arc(self.group.clone());
        temp_participant.verify_share_modp(
            sharebox,
            distribution_sharebox,
            publickey,
        )
    }

    /// Reconstruct secret (ModpGroup-specific implementation).
    pub fn reconstruct_modp(
        &self,
        share_boxes: &[ShareBox<crate::groups::ModpGroup>],
        distribute_share_box: &DistributionSharesBox<crate::groups::ModpGroup>,
    ) -> Option<BigInt> {
        use crate::participant::Participant;

        let temp_participant = Participant::with_arc(self.group.clone());
        temp_participant.reconstruct_modp(share_boxes, distribute_share_box)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::groups::ModpGroup;
    use crate::participant::Participant;
    use num_bigint::{BigInt, BigUint, RandBigInt, ToBigInt};
    use rand::Rng;

    #[test]
    fn test_generic_mpvss_new() {
        let group = ModpGroup::new();
        let pvss = PVSS::new(group);
        let modulus = pvss.group().modulus();
        let expected = modulus - BigInt::one();
        assert_eq!(pvss.group().order(), &expected);
    }

    #[test]
    fn test_generic_mpvss_verify_distribution_shares_modp() {
        let group = ModpGroup::new();
        let mut dealer = Participant::with_arc(group.clone());

        let secret = BigUint::from(123456u32);
        let mut p1 = Participant::with_arc(group.clone());
        let mut p2 = Participant::with_arc(group.clone());
        let mut p3 = Participant::with_arc(group.clone());
        p1.initialize();
        p2.initialize();
        p3.initialize();

        let publickeys = vec![
            p1.publickey.clone(),
            p2.publickey.clone(),
            p3.publickey.clone(),
        ];

        let dist_box = dealer.distribute_secret_modp(
            &secret.to_bigint().unwrap(),
            &publickeys,
            3,
        );

        let pvss = PVSS::new(group);
        assert!(pvss.verify_distribution_shares_modp(&dist_box));
    }

    #[test]
    fn test_generic_mpvss_verify_share_modp() {
        let group = ModpGroup::new();
        let mut rng = rand::thread_rng();

        let mut dealer = Participant::with_arc(group.clone());
        dealer.initialize();

        let mut p1 = Participant::with_arc(group.clone());
        let mut p2 = Participant::with_arc(group.clone());
        let mut p3 = Participant::with_arc(group.clone());
        p1.initialize();
        p2.initialize();
        p3.initialize();

        let secret = BigUint::from(123456u32);
        let publickeys = vec![
            p1.publickey.clone(),
            p2.publickey.clone(),
            p3.publickey.clone(),
        ];

        let dist_box = dealer.distribute_secret_modp(
            &secret.to_bigint().unwrap(),
            &publickeys,
            3,
        );

        let w: BigInt = rng
            .gen_biguint_below(&group.modulus().to_biguint().unwrap())
            .to_bigint()
            .unwrap();

        let s1 = p1
            .extract_secret_share_modp(&dist_box, &p1.privatekey, &w)
            .unwrap();

        let pvss = PVSS::new(group);
        assert!(pvss.verify_share_modp(&s1, &dist_box, &p1.publickey));
    }

    #[test]
    fn test_generic_mpvss_reconstruct_modp() {
        let group = ModpGroup::new();
        let mut rng = rand::thread_rng();

        let mut dealer = Participant::with_arc(group.clone());
        dealer.initialize();

        let mut p1 = Participant::with_arc(group.clone());
        let mut p2 = Participant::with_arc(group.clone());
        let mut p3 = Participant::with_arc(group.clone());
        p1.initialize();
        p2.initialize();
        p3.initialize();

        let secret = BigUint::from(123456u32);
        let publickeys = vec![
            p1.publickey.clone(),
            p2.publickey.clone(),
            p3.publickey.clone(),
        ];

        let dist_box = dealer.distribute_secret_modp(
            &secret.to_bigint().unwrap(),
            &publickeys,
            3,
        );

        let w: BigInt = rng
            .gen_biguint_below(&group.modulus().to_biguint().unwrap())
            .to_bigint()
            .unwrap();

        let s1 = p1
            .extract_secret_share_modp(&dist_box, &p1.privatekey, &w)
            .unwrap();
        let s2 = p2
            .extract_secret_share_modp(&dist_box, &p2.privatekey, &w)
            .unwrap();
        let s3 = p3
            .extract_secret_share_modp(&dist_box, &p3.privatekey, &w)
            .unwrap();

        let pvss = PVSS::new(group);
        let reconstructed =
            pvss.reconstruct_modp(&[s1, s2, s3], &dist_box).unwrap();

        assert_eq!(reconstructed.to_biguint().unwrap(), secret);
    }
}
