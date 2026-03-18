// Copyright 2020-2026 MathxH Chen.
//
// Code is licensed under MIT Apache Dual License

//! MPVSS (Publicly Verifiable Secret Sharing) implementation for multiple cryptographic groups.
//!
//! This module implements the PVSS scheme using the Group trait abstraction, enabling
//! the scheme to work with different cryptographic backends (MODP, secp256k1, etc.).

#![allow(non_snake_case)]

use num_traits::identities::One;
use sha2::{Digest, Sha256};
use std::sync::Arc;

use crate::dleq::DLEQ;
use crate::group::Group;
use crate::sharebox::DistributionSharesBox;

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
    G::Scalar: Clone + One + From<i64>,
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
            // Serialize the element to use as HashMap key
            let pubkey_bytes = self.group.element_to_bytes(publickey);
            let position = distribute_sharesbox.positions.get(&pubkey_bytes);
            let response = distribute_sharesbox.responses.get(&pubkey_bytes);
            let encrypted_share =
                distribute_sharesbox.shares.get(&pubkey_bytes);

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
                let pos_scalar = G::Scalar::from(*position.unwrap());
                exponent = self.group.scalar_mul(&exponent, &pos_scalar);
            }

            // Verify DLEQ proof for this participant via shared helper and
            // append transcript.
            let _ = DLEQ::<G>::verifier_update_hash(
                self.group.as_ref(),
                &subgroup_gen,
                &x_val,
                publickey,
                encrypted_share.unwrap(),
                response.unwrap(),
                &distribute_sharesbox.challenge,
                &mut challenge_hasher,
            );
        }

        // Calculate final challenge and check if it matches c
        let challenge_hash = challenge_hasher.finalize();
        let computed_challenge = self.group.hash_to_scalar(&challenge_hash);

        computed_challenge == distribute_sharesbox.challenge
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

    #[test]
    fn test_generic_mpvss_new() {
        let group = ModpGroup::new();
        let pvss = PVSS::new(group);
        let modulus = pvss.group().modulus();
        let expected = modulus - BigInt::one();
        assert_eq!(pvss.group().order(), &expected);
    }

    #[test]
    fn test_generic_mpvss_verify_distribution_shares() {
        let group = ModpGroup::new();
        let pvss = PVSS::new(group.clone());
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

        let dist_box = dealer.distribute_secret(
            &secret.to_bigint().unwrap(),
            &publickeys,
            3,
        );

        // Verify distribution shares using PVSS generic API.
        assert!(pvss.verify_distribution_shares(&dist_box));
    }

    #[test]
    fn test_generic_mpvss_verify_share() {
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

        let dist_box = dealer.distribute_secret(
            &secret.to_bigint().unwrap(),
            &publickeys,
            3,
        );

        let w: BigInt = rng
            .gen_biguint_below(&group.modulus().to_biguint().unwrap())
            .to_bigint()
            .unwrap();

        let s1 = p1
            .extract_secret_share(&dist_box, &p1.privatekey, &w)
            .unwrap();

        // Verify share using Participant directly
        assert!(dealer.verify_share(&s1, &dist_box, &p1.publickey));
    }

    #[test]
    fn test_generic_mpvss_reconstruct() {
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

        let dist_box = dealer.distribute_secret(
            &secret.to_bigint().unwrap(),
            &publickeys,
            3,
        );

        let w: BigInt = rng
            .gen_biguint_below(&group.modulus().to_biguint().unwrap())
            .to_bigint()
            .unwrap();

        let s1 = p1
            .extract_secret_share(&dist_box, &p1.privatekey, &w)
            .unwrap();
        let s2 = p2
            .extract_secret_share(&dist_box, &p2.privatekey, &w)
            .unwrap();
        let s3 = p3
            .extract_secret_share(&dist_box, &p3.privatekey, &w)
            .unwrap();

        // Reconstruct using Participant directly
        let reconstructed =
            dealer.reconstruct(&[s1, s2, s3], &dist_box).unwrap();

        assert_eq!(reconstructed.to_biguint().unwrap(), secret);
    }
}
