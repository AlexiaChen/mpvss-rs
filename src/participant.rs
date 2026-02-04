// Copyright 2020-2026 MathxH Chen.
//
// Code is licensed under MIT Apache Dual License

//! Participant implementation supporting multiple cryptographic groups.
//!
//! This module provides `Participant<G: Group>` which works with any group
//! implementation (MODP, secp256k1, etc.), enabling the PVSS scheme to use different
//! cryptographic backends.

use num_bigint::{BigInt, BigUint, ToBigInt};
use num_integer::Integer;
use num_traits::identities::{One, Zero};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use crate::dleq::DLEQ;
use crate::group::Group;
use crate::groups::ModpGroup;
use crate::polynomial::Polynomial;
use crate::sharebox::{DistributionSharesBox, ShareBox};

// secp256k1-specific imports (only available when feature is enabled)

use crate::groups::Secp256k1Group;

use k256::elliptic_curve::FieldBytes;

use k256::elliptic_curve::ff::PrimeField;

use k256::{AffinePoint, Scalar};

// Type aliases for convenience
// Note: These are already defined in sharebox.rs but re-exported here for convenience

// ============================================================================
// Participant
// ============================================================================

/// Participant that works with any cryptographic group.
///
/// # Type Parameters
/// - `G`: A type implementing the `Group` trait (e.g., `ModpGroup`, `Secp256k1Group`)
///
/// # Example
///
/// ```rust
/// use mpvss_rs::groups::ModpGroup;
/// use mpvss_rs::participant::Participant;
///
/// let group = ModpGroup::new();
/// let mut dealer = Participant::with_arc(group);
/// dealer.initialize();
/// ```
#[derive(Debug)]
pub struct Participant<G: Group> {
    group: Arc<G>,
    pub privatekey: G::Scalar,
    pub publickey: G::Element,
}

// Manual Clone implementation that doesn't require G: Clone
// Only requires G::Scalar and G::Element to be Clone
impl<G: Group> Clone for Participant<G>
where
    G::Scalar: Clone,
    G::Element: Clone,
{
    fn clone(&self) -> Self {
        Participant {
            group: Arc::clone(&self.group),
            privatekey: self.privatekey.clone(),
            publickey: self.publickey.clone(),
        }
    }
}

impl<G: Group> Participant<G> {
    /// Create a new generic participant with an Arc-wrapped group.
    ///
    /// # Example
    ///
    /// ```rust
    /// use mpvss_rs::groups::ModpGroup;
    /// use mpvss_rs::Participant;
    ///
    /// let group = ModpGroup::new();
    /// let participant = Participant::with_arc(group);
    /// ```
    pub fn with_arc(group: Arc<G>) -> Self
    where
        G::Scalar: Default,
        G::Element: Default,
    {
        Participant {
            group,
            privatekey: Default::default(),
            publickey: Default::default(),
        }
    }

    /// Create a new generic participant, wrapping the group in Arc internally.
    ///
    /// This method takes a group by value and wraps it in an Arc internally.
    /// For ModpGroup, since `ModpGroup::new()` already returns `Arc<ModpGroup>`,
    /// use `with_arc()` instead.
    ///
    /// # Example
    ///
    /// ```rust
    /// use mpvss_rs::groups::ModpGroup;
    /// use mpvss_rs::Participant;
    ///
    /// // For ModpGroup, use with_arc since ModpGroup::new() returns Arc<ModpGroup>
    /// let group = ModpGroup::new();
    /// let participant = Participant::with_arc(group);
    /// ```
    pub fn new(group: G) -> Self
    where
        G::Scalar: Default,
        G::Element: Default,
    {
        Participant {
            group: Arc::new(group),
            privatekey: Default::default(),
            publickey: Default::default(),
        }
    }

    /// Initialize the participant by generating a key pair.
    pub fn initialize(&mut self)
    where
        G::Scalar: Default,
        G::Element: Default,
    {
        self.privatekey = self.group.generate_private_key();
        self.publickey = self.group.generate_public_key(&self.privatekey);
    }
}

// ============================================================================
// ModpGroup-Specific Implementation
// ============================================================================

/// Full PVSS distribute_secret implementation for ModpGroup.
///
/// Note: This implementation uses Group trait abstraction where possible,
/// but some BigInt operations remain for non-group computations (Lagrange coefficients,
/// polynomial arithmetic, etc.).
impl Participant<ModpGroup> {
    /// Distribute a secret among participants (full implementation for ModpGroup).
    pub fn distribute_secret(
        &mut self,
        secret: &BigInt,
        publickeys: &[BigInt],
        threshold: u32,
    ) -> DistributionSharesBox<ModpGroup> {
        assert!(threshold <= publickeys.len() as u32);

        // Group generators
        let subgroup_gen = self.group.subgroup_generator();
        let main_gen = self.group.generator();
        let group_order = self.group.order();

        // Generate random polynomial (coefficients are scalars in Z_q)
        let mut polynomial = Polynomial::new();
        polynomial.init((threshold - 1) as i32, group_order);

        // Generate random witness w (scalar)
        let w = self.group.generate_private_key();

        // Data structures
        let mut commitments: Vec<BigInt> = Vec::new();
        let mut positions: HashMap<Vec<u8>, i64> = HashMap::new();
        let mut x: HashMap<Vec<u8>, BigInt> = HashMap::new();
        let mut shares: HashMap<Vec<u8>, BigInt> = HashMap::new();
        let mut challenge_hasher = Sha256::new();

        let mut sampling_points: HashMap<Vec<u8>, BigInt> = HashMap::new();
        let mut dleq_w: HashMap<Vec<u8>, BigInt> = HashMap::new();
        let mut position: i64 = 1;

        // Calculate commitments C_j = g^a_j using group.exp()
        for j in 0..threshold {
            let coeff = &polynomial.coefficients[j as usize];
            let commitment = self.group.exp(&subgroup_gen, coeff);
            commitments.push(commitment);
        }

        // Calculate encrypted shares for each participant
        for pubkey in publickeys {
            let pubkey_bytes = self.group.element_to_bytes(pubkey);
            positions.insert(pubkey_bytes.clone(), position);

            // P(position) mod order (scalar arithmetic)
            let pos_scalar = &BigInt::from(position);
            let secret_share = polynomial.get_value(pos_scalar) % group_order;
            sampling_points.insert(pubkey_bytes.clone(), secret_share.clone());

            // Calculate X_i = g^P(i) using commitments and group operations
            // X_i = ∏_{j=0}^{t-1} C_j^{i^j} where C_j are commitments
            let mut x_val = self.group.identity();
            let mut exponent = BigInt::one();
            for j in 0..threshold {
                let c_j_pow =
                    self.group.exp(&commitments[j as usize], &exponent);
                x_val = self.group.mul(&x_val, &c_j_pow);
                exponent =
                    self.group.scalar_mul(&exponent, pos_scalar) % group_order;
            }
            x.insert(pubkey_bytes.clone(), x_val.clone());

            // Calculate Y_i = y_i^P(i) (encrypted share) using group.exp()
            let encrypted_secret_share = self.group.exp(pubkey, &secret_share);
            shares.insert(pubkey_bytes.clone(), encrypted_secret_share.clone());

            // Generate DLEQ proof: DLEQ(g, X_i, y_i, Y_i)
            let mut dleq = DLEQ::new(self.group.clone());
            dleq.init(
                subgroup_gen.clone(),
                x_val.clone(),
                pubkey.clone(),
                encrypted_secret_share.clone(),
                secret_share.clone(),
                w.clone(),
            );
            dleq_w.insert(pubkey_bytes.clone(), w.clone());

            // Update challenge hash - use same format as legacy implementation
            let a1 = dleq.get_a1();
            let a2 = dleq.get_a2();
            challenge_hasher.update(
                x_val.to_biguint().unwrap().to_str_radix(10).as_bytes(),
            );
            challenge_hasher.update(
                encrypted_secret_share
                    .to_biguint()
                    .unwrap()
                    .to_str_radix(10)
                    .as_bytes(),
            );
            challenge_hasher
                .update(a1.to_biguint().unwrap().to_str_radix(10).as_bytes());
            challenge_hasher
                .update(a2.to_biguint().unwrap().to_str_radix(10).as_bytes());

            position += 1;
        }

        // Compute common challenge using group operations
        let challenge_hash = challenge_hasher.finalize();
        let challenge = self.group.hash_to_scalar(&challenge_hash);

        // Compute responses using scalar arithmetic
        let mut responses: HashMap<Vec<u8>, BigInt> = HashMap::new();
        for pubkey in publickeys {
            let pubkey_bytes = self.group.element_to_bytes(pubkey);
            let alpha = sampling_points.get(&pubkey_bytes).unwrap();
            let w_i = dleq_w.get(&pubkey_bytes).unwrap();
            let alpha_c =
                self.group.scalar_mul(alpha, &challenge) % group_order;
            let response = self.group.scalar_sub(w_i, &alpha_c) % group_order;
            responses.insert(pubkey_bytes, response);
        }

        // Compute U = secret XOR H(G^s) using group.exp()
        let s = polynomial.get_value(&BigInt::zero()) % group_order;
        let g_s = self.group.exp(&main_gen, &s);
        let sha256_hash = Sha256::digest(
            g_s.to_biguint().unwrap().to_str_radix(10).as_bytes(),
        );
        let hash_biguint = BigUint::from_bytes_be(&sha256_hash[..])
            .mod_floor(&self.group.modulus().to_biguint().unwrap());
        let u = secret.to_biguint().unwrap() ^ hash_biguint;

        // Build shares box
        let mut shares_box = DistributionSharesBox::new();
        shares_box.init(
            &commitments,
            positions,
            shares,
            publickeys,
            &challenge,
            responses,
            &u.to_bigint().unwrap(),
        );
        shares_box
    }

    /// Extract a secret share from the distribution box (ModpGroup implementation).
    ///
    /// # Parameters
    /// - `shares_box`: The distribution shares box from the dealer
    /// - `private_key`: The participant's private key
    /// - `w`: Random witness for DLEQ proof
    pub fn extract_secret_share(
        &self,
        shares_box: &DistributionSharesBox<ModpGroup>,
        private_key: &BigInt,
        w: &BigInt,
    ) -> Option<ShareBox<ModpGroup>> {
        use crate::util::Util;

        let main_gen = self.group.generator();
        let group_order = self.group.order();

        // Generate public key from private key using group method
        let public_key = self.group.generate_public_key(private_key);

        // Get encrypted share from distribution box
        let pubkey_bytes = self.group.element_to_bytes(&public_key);
        let encrypted_secret_share = shares_box.shares.get(&pubkey_bytes)?;

        // Decryption: S_i = Y_i^(1/x_i)
        // Note: This requires modular inverse which is not a group operation
        let privkey_inverse = Util::mod_inverse(private_key, group_order)?;
        let decrypted_share =
            self.group.exp(encrypted_secret_share, &privkey_inverse);

        // Generate DLEQ proof: DLEQ(G, publickey, decrypted_share, encrypted_secret_share)
        let mut dleq = DLEQ::new(self.group.clone());
        dleq.init(
            main_gen.clone(),
            public_key.clone(),
            decrypted_share.clone(),
            encrypted_secret_share.clone(),
            private_key.clone(),
            w.clone(),
        );

        // Compute challenge using group operations
        let mut challenge_hasher = Sha256::new();
        challenge_hasher.update(
            public_key.to_biguint().unwrap().to_str_radix(10).as_bytes(),
        );
        challenge_hasher.update(
            encrypted_secret_share
                .to_biguint()
                .unwrap()
                .to_str_radix(10)
                .as_bytes(),
        );

        let a1 = dleq.get_a1();
        let a2 = dleq.get_a2();
        challenge_hasher
            .update(a1.to_biguint().unwrap().to_str_radix(10).as_bytes());
        challenge_hasher
            .update(a2.to_biguint().unwrap().to_str_radix(10).as_bytes());

        let challenge_hash = challenge_hasher.finalize();
        let challenge = self.group.hash_to_scalar(&challenge_hash);
        dleq.c = Some(challenge.clone());

        // Compute response using scalar arithmetic
        let response = dleq.get_r()?;

        // Build share box
        let mut share_box = ShareBox::new();
        share_box.init(public_key, decrypted_share, challenge, response);
        Some(share_box)
    }

    /// Verify a decrypted share (ModpGroup implementation).
    ///
    /// # Parameters
    /// - `sharebox`: The share box containing the decrypted share
    /// - `distribution_sharebox`: The distribution shares box from the dealer
    /// - `publickey`: The public key of the participant who created the share
    pub fn verify_share(
        &self,
        sharebox: &ShareBox<ModpGroup>,
        distribution_sharebox: &DistributionSharesBox<ModpGroup>,
        publickey: &BigInt,
    ) -> bool {
        let main_gen = self.group.generator();

        // Get encrypted share from distribution box
        let pubkey_bytes = self.group.element_to_bytes(publickey);
        let encrypted_share =
            match distribution_sharebox.shares.get(&pubkey_bytes) {
                Some(s) => s,
                None => return false,
            };

        // Verify DLEQ proof using group operations
        // a_1 = G^r * publickey^c, a_2 = decrypted_share^r * encrypted_share^c
        let g1_r = self.group.exp(&main_gen, &sharebox.response);
        let h1_c = self.group.exp(publickey, &sharebox.challenge);
        let a1_verify = self.group.mul(&g1_r, &h1_c);

        let g2_r = self.group.exp(&sharebox.share, &sharebox.response);
        let h2_c = self.group.exp(encrypted_share, &sharebox.challenge);
        let a2_verify = self.group.mul(&g2_r, &h2_c);

        // Compute challenge hash and verify
        let mut challenge_hasher = Sha256::new();
        challenge_hasher.update(
            publickey.to_biguint().unwrap().to_str_radix(10).as_bytes(),
        );
        challenge_hasher.update(
            encrypted_share
                .to_biguint()
                .unwrap()
                .to_str_radix(10)
                .as_bytes(),
        );
        challenge_hasher.update(
            a1_verify.to_biguint().unwrap().to_str_radix(10).as_bytes(),
        );
        challenge_hasher.update(
            a2_verify.to_biguint().unwrap().to_str_radix(10).as_bytes(),
        );

        let challenge_hash = challenge_hasher.finalize();
        let challenge_computed = self.group.hash_to_scalar(&challenge_hash);

        challenge_computed == sharebox.challenge
    }

    /// Verify distribution shares box (ModpGroup implementation).
    ///
    /// Verifies that all encrypted shares are consistent with the commitments.
    /// This is the public verifiability part of PVSS - anyone can verify the dealer
    /// didn't cheat.
    ///
    /// # Parameters
    /// - `distribute_sharesbox`: The distribution shares box to verify
    ///
    /// # Returns
    /// `true` if the distribution is valid, `false` otherwise
    pub fn verify_distribution_shares(
        &self,
        distribute_sharesbox: &DistributionSharesBox<ModpGroup>,
    ) -> bool {
        let subgroup_gen = self.group.subgroup_generator();
        let group_order = self.group.order();
        let mut challenge_hasher = Sha256::new();

        // Verify each participant's encrypted share and accumulate hash
        for publickey in &distribute_sharesbox.publickeys {
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
            let mut exponent = BigInt::one();
            for j in 0..distribute_sharesbox.commitments.len() {
                let c_j_pow = self
                    .group
                    .exp(&distribute_sharesbox.commitments[j], &exponent);
                x_val = self.group.mul(&x_val, &c_j_pow);
                exponent = self
                    .group
                    .scalar_mul(&exponent, &BigInt::from(*position.unwrap()))
                    % group_order;
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
            challenge_hasher.update(
                x_val.to_biguint().unwrap().to_str_radix(10).as_bytes(),
            );
            challenge_hasher.update(
                encrypted_share
                    .unwrap()
                    .to_biguint()
                    .unwrap()
                    .to_str_radix(10)
                    .as_bytes(),
            );
            challenge_hasher
                .update(a1.to_biguint().unwrap().to_str_radix(10).as_bytes());
            challenge_hasher
                .update(a2.to_biguint().unwrap().to_str_radix(10).as_bytes());
        }

        // Calculate final challenge and check if it matches c
        let challenge_hash = challenge_hasher.finalize();
        let computed_challenge = self.group.hash_to_scalar(&challenge_hash);

        computed_challenge == distribute_sharesbox.challenge
    }

    /// Reconstruct secret from shares (ModpGroup implementation).
    ///
    /// # Parameters
    /// - `share_boxes`: Array of share boxes from participants
    /// - `distribute_share_box`: The distribution shares box from the dealer
    pub fn reconstruct(
        &self,
        share_boxes: &[ShareBox<ModpGroup>],
        distribute_share_box: &DistributionSharesBox<ModpGroup>,
    ) -> Option<BigInt> {
        use rayon::prelude::*;

        if share_boxes.len() < distribute_share_box.commitments.len() {
            return None;
        }

        let group_modulus = self.group.modulus();

        // Build position -> share map
        let mut shares: BTreeMap<i64, BigInt> = BTreeMap::new();
        for share_box in share_boxes.iter() {
            let pubkey_bytes =
                self.group.element_to_bytes(&share_box.publickey);
            let position = distribute_share_box.positions.get(&pubkey_bytes)?;
            shares.insert(*position, share_box.share.clone());
        }

        // Compute Lagrange factors and G^s = ∏ S_i^λ_i
        let mut secret = self.group.identity();
        let values: Vec<i64> = shares.keys().copied().collect();
        let shares_vec: Vec<(i64, BigInt)> = shares.into_iter().collect();
        let shares_slice = shares_vec.as_slice();

        let factors: Vec<BigInt> = shares_slice
            .par_iter()
            .map(|(position, share)| {
                self.compute_lagrange_factor(
                    *position,
                    share,
                    &values,
                    group_modulus,
                )
            })
            .collect();

        // Multiply all factors using group.mul()
        secret = factors
            .into_iter()
            .fold(secret, |acc, factor| self.group.mul(&acc, &factor));

        // Reconstruct secret = H(G^s) XOR U
        let secret_hash = Sha256::digest(
            secret.to_biguint().unwrap().to_str_radix(10).as_bytes(),
        );
        let hash_biguint = BigUint::from_bytes_be(&secret_hash[..])
            .mod_floor(&self.group.modulus().to_biguint().unwrap());
        let decrypted_secret =
            hash_biguint ^ distribute_share_box.U.to_biguint().unwrap();

        Some(decrypted_secret.to_bigint().unwrap())
    }

    /// Compute Lagrange factor for secret reconstruction.
    /// Compute Lagrange factor for secret reconstruction.
    ///
    /// Note: Lagrange coefficient computation is pure scalar arithmetic (not group operation),
    /// but the final exponentiation uses group.exp().
    fn compute_lagrange_factor(
        &self,
        position: i64,
        share: &BigInt,
        values: &[i64],
        group_modulus: &BigInt,
    ) -> BigInt {
        use crate::util::Util;

        let lagrange_coefficient =
            Util::lagrange_coefficient(&position, values);

        // Compute exponent: λ_i (may be fractional, needs modular inverse)
        let exponent = if lagrange_coefficient.1 == BigInt::from(1) {
            // Lagrange coefficient is an integer
            lagrange_coefficient.0.clone() / Util::abs(&lagrange_coefficient.1)
        } else {
            // Lagrange coefficient is a proper fraction
            let mut numerator = lagrange_coefficient.0.to_biguint().unwrap();
            let mut denominator =
                Util::abs(&lagrange_coefficient.1).to_biguint().unwrap();
            let gcd = numerator.gcd(&denominator);
            numerator /= &gcd;
            denominator /= &gcd;

            let group_order_minus_1 = group_modulus - BigInt::one();
            let inverse_denominator = Util::mod_inverse(
                &denominator.to_bigint().unwrap(),
                &group_order_minus_1,
            );

            match inverse_denominator {
                Some(inv) => {
                    (numerator.to_bigint().unwrap() * inv) % group_order_minus_1
                }
                None => {
                    eprintln!("ERROR: Denominator has no inverse");
                    BigInt::one()
                }
            }
        };

        // Compute S_i^λ_i using group.exp()
        let mut factor = self.group.exp(share, &exponent);

        // Handle negative Lagrange coefficient using element_inverse
        if lagrange_coefficient.0.clone() * lagrange_coefficient.1
            < BigInt::zero()
            && let Some(inverse_factor) = self.group.element_inverse(&factor)
        {
            factor = inverse_factor;
        }

        factor
    }
}

// Type aliases for convenience
/// Type alias for MODP group participant (backward compatible)
pub type ModpParticipant = Participant<ModpGroup>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::groups::ModpGroup;
    use crate::participant::Participant;
    use num_bigint::RandBigInt;

    #[test]
    fn test_generic_modp_participant_new() {
        let group = ModpGroup::new();
        let participant = Participant::with_arc(group);
        assert_eq!(participant.publickey, Default::default());
    }

    #[test]
    fn test_generic_modp_participant_initialize() {
        let group = ModpGroup::new();
        let mut participant = Participant::with_arc(group);
        participant.initialize();
        let _ = &participant.privatekey;
        let _ = &participant.publickey;
    }

    /// End-to-end test for distribute, extract, and reconstruct.
    #[test]
    fn test_end_to_end_modp() {
        use num_bigint::{BigUint, ToBigInt};

        // Setup participants
        let group = ModpGroup::new();
        let mut dealer = Participant::with_arc(group.clone());
        dealer.initialize();

        let mut p1 = Participant::with_arc(group.clone());
        let mut p2 = Participant::with_arc(group.clone());
        let mut p3 = Participant::with_arc(group.clone());
        p1.initialize();
        p2.initialize();
        p3.initialize();

        let secret_message = String::from("Hello MPVSS End-to-End Test!");
        let secret = BigUint::from_bytes_be(secret_message.as_bytes());

        let publickeys = vec![
            p1.publickey.clone(),
            p2.publickey.clone(),
            p3.publickey.clone(),
        ];
        let threshold = 3;

        // Distribute secret
        let dist_box = dealer.distribute_secret(
            &secret.to_bigint().unwrap(),
            &publickeys,
            threshold,
        );

        // ===== Step 1: Verify distribution =====
        // Each participant should verify the distribution is valid
        let verified_by_p1 = dealer.verify_distribution_shares(&dist_box);
        let verified_by_p2 = dealer.verify_distribution_shares(&dist_box);
        let verified_by_p3 = dealer.verify_distribution_shares(&dist_box);
        assert!(verified_by_p1, "P1 should verify distribution as valid");
        assert!(verified_by_p2, "P2 should verify distribution as valid");
        assert!(verified_by_p3, "P3 should verify distribution as valid");

        // Verify distribution box structure
        assert_eq!(dist_box.publickeys.len(), 3, "Should have 3 public keys");
        assert_eq!(dist_box.commitments.len(), 3, "Should have 3 commitments");
        assert_eq!(dist_box.shares.len(), 3, "Should have 3 shares");
        assert_ne!(dist_box.U, BigInt::zero(), "U should not be zero");

        // Generate random witness for share extraction
        let mut rng = rand::thread_rng();
        let w: BigInt = rng
            .gen_biguint_below(&group.modulus().to_biguint().unwrap())
            .to_bigint()
            .unwrap();

        // ===== Step 2: Extract shares =====
        let s1 = p1
            .extract_secret_share(&dist_box, &p1.privatekey, &w)
            .unwrap();
        let s2 = p2
            .extract_secret_share(&dist_box, &p2.privatekey, &w)
            .unwrap();
        let s3 = p3
            .extract_secret_share(&dist_box, &p3.privatekey, &w)
            .unwrap();

        // Verify extracted shares structure
        assert_eq!(s1.publickey, p1.publickey, "P1 publickey should match");
        assert_ne!(s1.share, BigInt::zero(), "P1 share should not be zero");

        assert_eq!(s2.publickey, p2.publickey, "P2 publickey should match");
        assert_ne!(s2.share, BigInt::zero(), "P2 share should not be zero");

        assert_eq!(s3.publickey, p3.publickey, "P3 publickey should match");
        assert_ne!(s3.share, BigInt::zero(), "P3 share should not be zero");

        // ===== Step 3: Verify each extracted share =====
        // Each participant can verify other participants' shares
        let p1_verifies_s2 = dealer.verify_share(&s2, &dist_box, &p2.publickey);
        let p1_verifies_s3 = dealer.verify_share(&s3, &dist_box, &p3.publickey);
        assert!(p1_verifies_s2, "P1 should verify P2's share as valid");
        assert!(p1_verifies_s3, "P1 should verify P3's share as valid");

        let p2_verifies_s1 = dealer.verify_share(&s1, &dist_box, &p1.publickey);
        let p2_verifies_s3 = dealer.verify_share(&s3, &dist_box, &p3.publickey);
        assert!(p2_verifies_s1, "P2 should verify P1's share as valid");
        assert!(p2_verifies_s3, "P2 should verify P3's share as valid");

        let p3_verifies_s1 = dealer.verify_share(&s1, &dist_box, &p1.publickey);
        let p3_verifies_s2 = dealer.verify_share(&s2, &dist_box, &p2.publickey);
        assert!(p3_verifies_s1, "P3 should verify P1's share as valid");
        assert!(p3_verifies_s2, "P3 should verify P2's share as valid");

        // ===== Step 4: Reconstruct secret from verified shares =====
        let shares = vec![s1, s2, s3];
        let reconstructed = dealer.reconstruct(&shares, &dist_box).unwrap();

        // Verify reconstructed secret matches original
        let reconstructed_message = String::from_utf8(
            reconstructed.to_biguint().unwrap().to_bytes_be(),
        )
        .unwrap();
        assert_eq!(
            reconstructed_message, secret_message,
            "Reconstructed message should match original"
        );

        println!(
            "End-to-end test passed: distribute, extract, and reconstruct all work correctly"
        );
    }

    // ========================================================================
    // secp256k1 Tests
    // ========================================================================

    /// End-to-end test for secp256k1: distribute, extract, and reconstruct.

    #[test]
    fn test_end_to_end_secp256k1() {
        use num_bigint::{BigUint, ToBigInt};

        // Setup participants
        let group = Secp256k1Group::new();
        let mut dealer = Participant::with_arc(group.clone());
        dealer.initialize();

        let mut p1 = Participant::with_arc(group.clone());
        let mut p2 = Participant::with_arc(group.clone());
        let mut p3 = Participant::with_arc(group.clone());
        p1.initialize();
        p2.initialize();
        p3.initialize();

        let secret_message = String::from("Hello secp256k1 PVSS!");
        let secret = BigUint::from_bytes_be(secret_message.as_bytes());

        let publickeys: Vec<k256::AffinePoint> = vec![
            p1.publickey.clone(),
            p2.publickey.clone(),
            p3.publickey.clone(),
        ];
        let threshold = 3;

        // Distribute secret
        let dist_box = dealer.distribute_secret(
            &secret.to_bigint().unwrap(),
            &publickeys,
            threshold,
        );

        // Verify distribution
        assert!(
            dealer.verify_distribution_shares(&dist_box),
            "Distribution should be valid"
        );

        // Generate random witness
        let w = group.generate_private_key();

        // Extract shares
        let s1 = p1
            .extract_secret_share(&dist_box, &p1.privatekey, &w)
            .unwrap();
        let s2 = p2
            .extract_secret_share(&dist_box, &p2.privatekey, &w)
            .unwrap();
        let s3 = p3
            .extract_secret_share(&dist_box, &p3.privatekey, &w)
            .unwrap();

        // Verify shares
        assert!(
            dealer.verify_share(&s1, &dist_box, &p1.publickey),
            "P1's share should be valid"
        );
        assert!(
            dealer.verify_share(&s3, &dist_box, &p3.publickey),
            "P3's share should be valid"
        );

        // Reconstruct from all 3 shares
        let shares = vec![s1, s2, s3];
        let reconstructed = dealer.reconstruct(&shares, &dist_box).unwrap();

        // Verify reconstructed secret matches original
        let reconstructed_message = String::from_utf8(
            reconstructed.to_biguint().unwrap().to_bytes_be(),
        )
        .unwrap();
        assert_eq!(
            reconstructed_message, secret_message,
            "Reconstructed message should match original"
        );

        println!("secp256k1 end-to-end test passed");
    }

    /// Threshold test for secp256k1: 3-of-5 reconstruction.

    #[test]
    fn test_threshold_secp256k1() {
        use num_bigint::{BigUint, ToBigInt};

        // Setup 5 participants with threshold 3
        let group = Secp256k1Group::new();
        let mut dealer = Participant::with_arc(group.clone());
        dealer.initialize();

        let mut p1 = Participant::with_arc(group.clone());
        let mut p2 = Participant::with_arc(group.clone());
        let mut p3 = Participant::with_arc(group.clone());
        let mut p4 = Participant::with_arc(group.clone());
        let mut p5 = Participant::with_arc(group.clone());
        p1.initialize();
        p2.initialize();
        p3.initialize();
        p4.initialize();
        p5.initialize();

        let secret_message = String::from("Threshold test secp256k1!");
        let secret = BigUint::from_bytes_be(secret_message.as_bytes());

        let publickeys: Vec<k256::AffinePoint> = vec![
            p1.publickey.clone(),
            p2.publickey.clone(),
            p3.publickey.clone(),
            p4.publickey.clone(),
            p5.publickey.clone(),
        ];
        let threshold = 3;

        // Distribute secret
        let dist_box = dealer.distribute_secret(
            &secret.to_bigint().unwrap(),
            &publickeys,
            threshold,
        );

        // Verify distribution
        assert!(
            dealer.verify_distribution_shares(&dist_box),
            "Distribution should be valid"
        );

        // Generate random witness
        let w = group.generate_private_key();

        // Extract only 3 shares (threshold)
        let s1 = p1
            .extract_secret_share(&dist_box, &p1.privatekey, &w)
            .unwrap();
        let s3 = p3
            .extract_secret_share(&dist_box, &p3.privatekey, &w)
            .unwrap();
        let s5 = p5
            .extract_secret_share(&dist_box, &p5.privatekey, &w)
            .unwrap();

        // Reconstruct from 3 shares
        let shares = vec![s1, s3, s5];
        let reconstructed = dealer.reconstruct(&shares, &dist_box).unwrap();

        // Verify reconstructed secret matches original
        let reconstructed_message = String::from_utf8(
            reconstructed.to_biguint().unwrap().to_bytes_be(),
        )
        .unwrap();
        assert_eq!(
            reconstructed_message, secret_message,
            "Reconstructed message should match original"
        );

        println!("secp256k1 threshold test passed");
    }

    /// Basic DLEQ test for secp256k1 to verify scalar conversions.

    #[test]
    fn test_scalar_arithmetic_secp256k1() {
        use num_bigint::BigInt;

        let group = Secp256k1Group::new();

        // Test: If s1 = a + b, then s1 * g should equal a*g + b*g
        let a_bigint = BigInt::from(5u32);
        let b_bigint = BigInt::from(7u32);
        let s_bigint = &a_bigint + &b_bigint; // 12

        // Convert to Scalars
        let a = Scalar::from_repr({
            let mut fb = FieldBytes::<k256::Secp256k1>::default();
            let b = a_bigint.to_bytes_be().1;
            if b.len() < 32 {
                fb[32 - b.len()..].copy_from_slice(&b);
            } else {
                fb.copy_from_slice(&b[..32]);
            }
            fb.into()
        })
        .unwrap();

        let b = Scalar::from_repr({
            let mut fb = FieldBytes::<k256::Secp256k1>::default();
            let b = b_bigint.to_bytes_be().1;
            if b.len() < 32 {
                fb[32 - b.len()..].copy_from_slice(&b);
            } else {
                fb.copy_from_slice(&b[..32]);
            }
            fb.into()
        })
        .unwrap();

        let s = Scalar::from_repr({
            let mut fb = FieldBytes::<k256::Secp256k1>::default();
            let b = s_bigint.to_bytes_be().1;
            if b.len() < 32 {
                fb[32 - b.len()..].copy_from_slice(&b);
            } else {
                fb.copy_from_slice(&b[..32]);
            }
            fb.into()
        })
        .unwrap();

        // Test: s * g == a*g + b*g == (a+b)*g
        let g = group.generator();

        let a_times_g = group.exp(&g, &a);
        let b_times_g = group.exp(&g, &b);
        let s_times_g = group.exp(&g, &s);

        let sum_ab_g = group.mul(&a_times_g, &b_times_g);

        assert_eq!(
            sum_ab_g, s_times_g,
            "Scalar arithmetic: (a+b)*g should equal a*g + b*g"
        );
        eprintln!("Scalar arithmetic test passed!");
    }

    /// Basic DLEQ test for secp256k1 to verify scalar conversions.

    #[test]
    fn test_dleq_basic_secp256k1() {
        let group = Secp256k1Group::new();
        let mut dealer = Participant::with_arc(group.clone());
        dealer.initialize();

        // Create a simple DLEQ proof
        let alpha = group.generate_private_key();
        let w = group.generate_private_key();

        // g1 = g, h1 = g^alpha
        let g1 = group.generator();
        let h1 = group.exp(&g1, &alpha);

        // g2 = some public key, h2 = g2^alpha
        let mut p2 = Participant::with_arc(group.clone());
        p2.initialize();
        let g2 = p2.publickey;
        let h2 = group.exp(&g2, &alpha);

        // Create DLEQ
        let mut dleq = DLEQ::new(group.clone());
        dleq.init(g1, h1, g2, h2, alpha, w);

        // Compute a1, a2
        let a1 = dleq.get_a1();
        let a2 = dleq.get_a2();

        // Compute challenge
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(group.element_to_bytes(&h1));
        hasher.update(group.element_to_bytes(&h2));
        hasher.update(group.element_to_bytes(&a1));
        hasher.update(group.element_to_bytes(&a2));
        let hash = hasher.finalize();
        let challenge = group.hash_to_scalar(&hash);

        dleq.c = Some(challenge.clone());
        let response = dleq.get_r().unwrap();
        dleq.r = Some(response);

        // Verify should succeed
        assert!(dleq.verify(), "Basic DLEQ proof should verify");
        eprintln!("Basic DLEQ test passed!");
    }

    /// DLEQ proof verification test for secp256k1.

    #[test]
    fn test_dleq_proofs_secp256k1() {
        use num_bigint::{BigUint, ToBigInt};

        let group = Secp256k1Group::new();
        let mut dealer = Participant::with_arc(group.clone());
        dealer.initialize();

        let mut p1 = Participant::with_arc(group.clone());
        let mut p2 = Participant::with_arc(group.clone());
        p1.initialize();
        p2.initialize();

        let secret = BigUint::from_bytes_be(b"DLEQ test secp256k1");

        let publickeys: Vec<k256::AffinePoint> =
            vec![p1.publickey.clone(), p2.publickey.clone()];
        let threshold = 2;

        // Distribute secret
        let dist_box = dealer.distribute_secret(
            &secret.to_bigint().unwrap(),
            &publickeys,
            threshold,
        );

        // Verify DLEQ proofs
        let verification_result = dealer.verify_distribution_shares(&dist_box);
        if !verification_result {
            // Debug: print challenge and responses
            eprintln!("DEBUG: Distribution verification failed!");
            eprintln!(
                "Challenge bytes: {:?}",
                dealer.group.scalar_to_bytes(&dist_box.challenge)
            );
            for (i, pubkey) in dist_box.publickeys.iter().enumerate() {
                let pubkey_bytes = dealer.group.element_to_bytes(pubkey);
                if let Some(pos) = dist_box.positions.get(&pubkey_bytes) {
                    eprintln!("Participant {}: position={}", i + 1, pos);
                }
                if let Some(resp) = dist_box.responses.get(&pubkey_bytes) {
                    eprintln!(
                        "Participant {}: response bytes: {:?}",
                        i + 1,
                        dealer.group.scalar_to_bytes(resp)
                    );
                }
            }
        }
        assert!(
            verification_result,
            "Distribution DLEQ proofs should be valid"
        );

        // Generate random witness
        let w = group.generate_private_key();

        // Extract and verify shares
        let s1 = p1
            .extract_secret_share(&dist_box, &p1.privatekey, &w)
            .unwrap();
        let s2 = p2
            .extract_secret_share(&dist_box, &p2.privatekey, &w)
            .unwrap();

        // Verify share DLEQ proofs
        assert!(
            dealer.verify_share(&s1, &dist_box, &p1.publickey),
            "P1's DLEQ proof should be valid"
        );
        assert!(
            dealer.verify_share(&s2, &dist_box, &p2.publickey),
            "P2's DLEQ proof should be valid"
        );

        println!("secp256k1 DLEQ proofs test passed");
    }
}

// ============================================================================
// Secp256k1Group-Specific Implementation
// ============================================================================

/// Full PVSS implementation for Secp256k1Group (elliptic curve group).
///
/// This implementation adapts the PVSS scheme for elliptic curve cryptography,
/// using the k256 library's Scalar and AffinePoint types.
///
/// Key differences from ModpGroup:
/// - Elements are EC points (AffinePoint) instead of BigInt
/// - Scalars are k256::Scalar (32 bytes) instead of BigInt
/// - Hashing uses compressed point encoding (33 bytes SEC1 format)
/// - No modulus concept (EC groups are prime-order)
///
/// Note: Uses Vec<u8> (serialized points) as HashMap keys since AffinePoint
/// doesn't implement Hash.
impl Participant<Secp256k1Group> {
    /// Distribute a secret among participants (full implementation for Secp256k1Group).
    ///
    /// # Parameters
    /// - `secret`: The value to be shared (as BigInt for cross-group compatibility)
    /// - `publickeys`: Array of public keys (EC points) of each participant
    /// - `threshold`: Number of shares needed for reconstruction
    ///
    /// Returns a `DistributionSharesBox` containing encrypted shares and DLEQ proofs
    pub fn distribute_secret(
        &mut self,
        secret: &BigInt,
        publickeys: &[AffinePoint],
        threshold: u32,
    ) -> DistributionSharesBox<Secp256k1Group> {
        assert!(threshold <= publickeys.len() as u32);

        // Group generators
        let subgroup_gen = self.group.subgroup_generator();
        let main_gen = self.group.generator();
        let _group_order = self.group.order(); // Stored for API compatibility, actual order from order_as_bigint()

        // Generate random polynomial (coefficients are BigInt, converted to Scalar later)
        let mut polynomial = Polynomial::new();
        // Use BigInt for polynomial arithmetic (compatible with Polynomial module)
        // For secp256k1, use order_as_bigint() to get the actual curve order as BigInt

        let group_order_bigint = self.group.order_as_bigint().clone();
        polynomial.init((threshold - 1) as i32, &group_order_bigint);

        // Generate random witness w (scalar)
        let w = self.group.generate_private_key();

        // Data structures - use Vec<u8> keys (serialized points) since AffinePoint doesn't implement Hash
        let mut commitments: Vec<AffinePoint> = Vec::new();
        let mut positions: std::collections::HashMap<Vec<u8>, i64> =
            std::collections::HashMap::new();
        let mut shares: std::collections::HashMap<Vec<u8>, AffinePoint> =
            std::collections::HashMap::new();
        let mut challenge_hasher = Sha256::new();

        let mut sampling_points: std::collections::HashMap<Vec<u8>, Scalar> =
            std::collections::HashMap::new();
        let mut dleq_w: std::collections::HashMap<Vec<u8>, Scalar> =
            std::collections::HashMap::new();
        let mut position: i64 = 1;

        // Calculate commitments C_j = a_j * g (scalar multiplication)
        for j in 0..threshold {
            let coeff_bigint = &polynomial.coefficients[j as usize];
            // Convert BigInt coefficient to bytes (big-endian) and ensure exactly 32 bytes
            // k256 Scalar::from_repr expects big-endian representation
            let coeff_bytes = coeff_bigint.to_bytes_be().1;
            let mut field_bytes = FieldBytes::<k256::Secp256k1>::default();
            if coeff_bytes.len() < 32 {
                // Right-align for big-endian (copy to the end of the array)
                field_bytes[32 - coeff_bytes.len()..]
                    .copy_from_slice(&coeff_bytes);
            } else {
                field_bytes.copy_from_slice(&coeff_bytes[..32]);
            }
            let coeff = Scalar::from_repr(field_bytes).unwrap();
            let commitment = self.group.exp(&subgroup_gen, &coeff);
            commitments.push(commitment);
        }

        // Calculate encrypted shares for each participant
        for (idx, pubkey) in publickeys.iter().enumerate() {
            let pubkey_bytes = self.group.element_to_bytes(pubkey);
            positions.insert(pubkey_bytes.clone(), position);

            // P(position) as Scalar
            let pos_scalar = BigInt::from(position);
            let secret_share_bigint = polynomial.get_value(&pos_scalar);
            // CRITICAL: Must take mod order BEFORE converting to Scalar
            let secret_share_mod = &secret_share_bigint % &group_order_bigint;
            // Use big-endian representation for k256 Scalar
            let secret_share_bytes = secret_share_mod.to_bytes_be().1;
            let mut field_bytes = FieldBytes::<k256::Secp256k1>::default();
            if secret_share_bytes.len() < 32 {
                // Right-align for big-endian
                field_bytes[32 - secret_share_bytes.len()..]
                    .copy_from_slice(&secret_share_bytes);
            } else {
                field_bytes.copy_from_slice(&secret_share_bytes[..32]);
            }
            let secret_share = Scalar::from_repr(field_bytes).unwrap();
            sampling_points.insert(pubkey_bytes.clone(), secret_share);
            dleq_w.insert(pubkey_bytes.clone(), w);

            // Calculate X_i = Σ_j (position^j) * C_j (using EC operations)
            let mut x_val = self.group.identity();
            let mut exponent = Scalar::ONE;
            for j in 0..threshold {
                // C_j^(i^j) in EC notation = (i^j) * C_j (scalar multiplication)
                let c_j_pow =
                    self.group.exp(&commitments[j as usize], &exponent);
                x_val = self.group.mul(&x_val, &c_j_pow);
                // exponent *= position (mod order)
                let pos_scalar = Scalar::from(position as u64);
                exponent = self.group.scalar_mul(&exponent, &pos_scalar);
            }

            // Debug: Verify X_i = secret_share * g (for first participant)
            if position == 1 {
                // Calculate P(1) directly by summing all coefficients (P(1) = a0 + a1*1 + a2*1^2 + ...)
                let p1_bigint: BigInt =
                    polynomial.coefficients.iter().cloned().sum();
                let p1_mod = &p1_bigint % &group_order_bigint;

                eprintln!("  p1_bigint = {}", p1_bigint);
                eprintln!("  p1_mod = {}", p1_mod);
                eprintln!("  group_order_bigint = {}", group_order_bigint);

                // Convert to Scalar - verify the conversion
                let p1_bytes = p1_mod.to_bytes_be().1;
                eprintln!("  p1_mod to_bytes_be() result: {:?}", p1_bytes);
                let mut field_bytes = FieldBytes::<k256::Secp256k1>::default();
                if p1_bytes.len() < 32 {
                    eprintln!(
                        "  Right-aligning: copying {} bytes to end",
                        p1_bytes.len()
                    );
                    field_bytes[32 - p1_bytes.len()..]
                        .copy_from_slice(&p1_bytes);
                } else {
                    eprintln!("  Truncating: copying last 32 bytes");
                    field_bytes
                        .copy_from_slice(&p1_bytes[p1_bytes.len() - 32..]);
                }
                eprintln!("  field_bytes before from_repr: {:?}", field_bytes);
                let p1_scalar = Scalar::from_repr(field_bytes).unwrap();
                eprintln!(
                    "  p1_scalar bytes (after from_repr): {:?}",
                    self.group.scalar_to_bytes(&p1_scalar)
                );

                // Calculate g^P(1)
                let gp1 = self.group.exp(&subgroup_gen, &p1_scalar);

                eprintln!("DEBUG: Detailed verification:");
                eprintln!("  P(1) = sum of coefficients = {}", p1_bigint);
                eprintln!("  P(1) mod order = {}", p1_mod);
                let ss_val = BigInt::from_bytes_be(
                    num_bigint::Sign::Plus,
                    &self.group.scalar_to_bytes(&secret_share),
                );
                eprintln!(
                    "  secret_share (as Scalar back to BigInt) = {}",
                    ss_val
                );
                eprintln!(
                    "  P(1) mod order bytes: {:?}",
                    self.group.scalar_to_bytes(&p1_scalar)
                );
                eprintln!(
                    "  secret_share bytes: {:?}",
                    self.group.scalar_to_bytes(&secret_share)
                );
                eprintln!(
                    "  p1_scalar == secret_share as Scalar? {}",
                    p1_scalar == secret_share
                );
                eprintln!(
                    "  g^P(1) bytes: {:?}",
                    self.group.element_to_bytes(&gp1)
                );
                eprintln!(
                    "  X_i bytes: {:?}",
                    self.group.element_to_bytes(&x_val)
                );
                eprintln!(
                    "  Are P(1) mod and secret_share equal? {}",
                    p1_mod == ss_val
                );

                // Debug commitments
                for (i, c) in commitments.iter().enumerate() {
                    eprintln!(
                        "  C_{} bytes: {:?}",
                        i,
                        self.group.element_to_bytes(c)
                    );
                }

                // Manual calculation: sum all commitments should equal g^(sum of coefficients)
                let manual_sum =
                    commitments.iter().fold(self.group.identity(), |acc, c| {
                        self.group.mul(&acc, c)
                    });
                eprintln!(
                    "  Sum of commitments bytes: {:?}",
                    self.group.element_to_bytes(&manual_sum)
                );

                // Also try: direct scalar multiplication of each coefficient's commitment
                // This should equal what the X_i calculation loop does
                eprintln!("  DEBUG: Let's verify the commitments calculation:");
                eprintln!(
                    "    subgroup_gen bytes: {:?}",
                    self.group.element_to_bytes(&subgroup_gen)
                );

                // Recreate commitment C_0 = a0 * g and verify
                let a0_bytes = polynomial.coefficients[0].to_bytes_be().1;
                eprintln!("    a0 bytes: {:?}", a0_bytes);
                let mut fb0 = FieldBytes::<k256::Secp256k1>::default();
                if a0_bytes.len() < 32 {
                    fb0[32 - a0_bytes.len()..].copy_from_slice(&a0_bytes);
                } else {
                    fb0.copy_from_slice(&a0_bytes[a0_bytes.len() - 32..]);
                }
                eprintln!("    a0 field_bytes: {:?}", fb0);
                let a0_scalar = Scalar::from_repr(fb0).unwrap();
                eprintln!(
                    "    a0_scalar bytes (after from_repr): {:?}",
                    self.group.scalar_to_bytes(&a0_scalar)
                );
                let c0_recreated = self.group.exp(&subgroup_gen, &a0_scalar);
                eprintln!(
                    "    C_0 recreated bytes: {:?}",
                    self.group.element_to_bytes(&c0_recreated)
                );
                eprintln!(
                    "    C_0 == recreated? {}",
                    commitments[0] == c0_recreated
                );

                // Recreate commitment C_1 = a1 * g and verify
                let a1_bytes = polynomial.coefficients[1].to_bytes_be().1;
                eprintln!("    a1 bytes: {:?}", a1_bytes);
                let mut fb1 = FieldBytes::<k256::Secp256k1>::default();
                if a1_bytes.len() < 32 {
                    fb1[32 - a1_bytes.len()..].copy_from_slice(&a1_bytes);
                } else {
                    fb1.copy_from_slice(&a1_bytes[a1_bytes.len() - 32..]);
                }
                eprintln!("    a1 field_bytes: {:?}", fb1);
                let a1_scalar = Scalar::from_repr(fb1).unwrap();
                eprintln!(
                    "    a1_scalar bytes (after from_repr): {:?}",
                    self.group.scalar_to_bytes(&a1_scalar)
                );
                let c1_recreated = self.group.exp(&subgroup_gen, &a1_scalar);
                eprintln!(
                    "    C_1 recreated bytes: {:?}",
                    self.group.element_to_bytes(&c1_recreated)
                );
                eprintln!(
                    "    C_1 == recreated? {}",
                    commitments[1] == c1_recreated
                );

                // Now manually compute: a0*g + a1*g (should equal C_0 + C_1)
                let manual_from_scalars =
                    self.group.mul(&c0_recreated, &c1_recreated);
                eprintln!(
                    "    a0*g + a1*g bytes: {:?}",
                    self.group.element_to_bytes(&manual_from_scalars)
                );

                // Now compute (a0 + a1) * g and compare
                let a0_plus_a1_scalar = a0_scalar + a1_scalar;
                eprintln!(
                    "    a0_plus_a1_scalar bytes: {:?}",
                    self.group.scalar_to_bytes(&a0_plus_a1_scalar)
                );
                eprintln!(
                    "    p1_scalar bytes: {:?}",
                    self.group.scalar_to_bytes(&p1_scalar)
                );
                eprintln!(
                    "    a0_plus_a1_scalar == p1_scalar? {}",
                    a0_plus_a1_scalar == p1_scalar
                );
                eprintln!("    a0_scalar + a1_scalar (as BigInt back):");
                let a0_bi = BigInt::from_bytes_be(
                    num_bigint::Sign::Plus,
                    &self.group.scalar_to_bytes(&a0_scalar),
                );
                let a1_bi = BigInt::from_bytes_be(
                    num_bigint::Sign::Plus,
                    &self.group.scalar_to_bytes(&a1_scalar),
                );
                let sum_bi = &a0_bi + &a1_bi;
                eprintln!("      a0 (as BigInt) = {}", a0_bi);
                eprintln!("      a1 (as BigInt) = {}", a1_bi);
                eprintln!("      a0 + a1 (as BigInt) = {}", sum_bi);
                eprintln!("      p1_mod (as BigInt) = {}", p1_mod);
                eprintln!(
                    "      (a0 + a1) mod group_order = {}",
                    sum_bi % &group_order_bigint
                );
                let combined =
                    self.group.exp(&subgroup_gen, &a0_plus_a1_scalar);
                eprintln!(
                    "    (a0+a1)*g bytes: {:?}",
                    self.group.element_to_bytes(&combined)
                );

                // Check if p1_scalar equals a0_plus_a1_scalar
                eprintln!(
                    "    p1_scalar == a0_plus_a1? {}",
                    p1_scalar == a0_plus_a1_scalar
                );

                assert_eq!(
                    gp1, manual_sum,
                    "g^P(1) should equal sum of commitments"
                );
                assert_eq!(
                    manual_sum, x_val,
                    "X_i should equal sum of commitments"
                );
            }

            // Calculate Y_i = secret_share * y_i (encrypted share)
            let encrypted_secret_share = self.group.exp(pubkey, &secret_share);
            shares.insert(pubkey_bytes.clone(), encrypted_secret_share);

            // Generate DLEQ proof: DLEQ(g, X_i, y_i, Y_i)
            let mut dleq = DLEQ::new(self.group.clone());
            dleq.init(
                subgroup_gen,
                x_val,
                *pubkey,
                encrypted_secret_share,
                secret_share,
                w,
            );

            // Update challenge hash - use element_to_bytes() for EC points
            let a1 = dleq.get_a1();
            let a2 = dleq.get_a2();

            // Debug: print what's being hashed for first participant
            if idx == 0 {
                eprintln!("DEBUG: Distribution hashing - Participant 1:");
                eprintln!(
                    "  X_i bytes: {:?}",
                    self.group.element_to_bytes(&x_val)
                );
                eprintln!(
                    "  Y_i bytes: {:?}",
                    self.group.element_to_bytes(&encrypted_secret_share)
                );
                eprintln!("  a1 bytes: {:?}", self.group.element_to_bytes(&a1));
                eprintln!("  a2 bytes: {:?}", self.group.element_to_bytes(&a2));
            }

            challenge_hasher.update(self.group.element_to_bytes(&x_val));
            challenge_hasher
                .update(self.group.element_to_bytes(&encrypted_secret_share));
            challenge_hasher.update(self.group.element_to_bytes(&a1));
            challenge_hasher.update(self.group.element_to_bytes(&a2));

            position += 1;
        }

        // Compute common challenge
        let challenge_hash = challenge_hasher.finalize();
        let challenge = self.group.hash_to_scalar(&challenge_hash);

        // Compute responses: r_i = w - alpha_i * c
        let mut responses: std::collections::HashMap<Vec<u8>, Scalar> =
            std::collections::HashMap::new();
        for pubkey in publickeys {
            let pubkey_bytes = self.group.element_to_bytes(pubkey);
            let alpha = sampling_points.get(&pubkey_bytes).unwrap();
            let alpha_c = self.group.scalar_mul(alpha, &challenge);
            let w_i = dleq_w.get(&pubkey_bytes).unwrap();
            let response = self.group.scalar_sub(w_i, &alpha_c);

            // Debug: verify response computation for first participant
            if responses.is_empty() {
                eprintln!("DEBUG: Response computation:");
                eprintln!("  w bytes: {:?}", self.group.scalar_to_bytes(w_i));
                eprintln!(
                    "  alpha bytes: {:?}",
                    self.group.scalar_to_bytes(alpha)
                );
                eprintln!(
                    "  challenge bytes: {:?}",
                    self.group.scalar_to_bytes(&challenge)
                );
                eprintln!(
                    "  alpha*c bytes: {:?}",
                    self.group.scalar_to_bytes(&alpha_c)
                );
                eprintln!(
                    "  response (=w-alpha*c) bytes: {:?}",
                    self.group.scalar_to_bytes(&response)
                );
            }

            responses.insert(pubkey_bytes, response);
        }

        // Compute U = secret XOR H(G^s)
        let s_bigint = polynomial.get_value(&BigInt::zero());
        let s_bytes = s_bigint.to_bytes_be().1;
        let mut field_bytes = FieldBytes::<k256::Secp256k1>::default();
        if s_bytes.len() < 32 {
            field_bytes[32 - s_bytes.len()..].copy_from_slice(&s_bytes);
        } else {
            field_bytes.copy_from_slice(&s_bytes[s_bytes.len() - 32..]);
        }
        let s = Scalar::from_repr(field_bytes).unwrap();
        let g_s = self.group.exp(&main_gen, &s);

        // Hash the EC point to bytes
        let sha256_hash = Sha256::digest(self.group.element_to_bytes(&g_s));
        // Convert hash to BigUint and reduce modulo curve order
        let mut field_bytes2 = FieldBytes::<k256::Secp256k1>::default();
        let hash_len = sha256_hash.len().min(field_bytes2.len());
        field_bytes2[32 - hash_len..].copy_from_slice(&sha256_hash[..hash_len]);
        let hash_scalar = Scalar::from_repr(field_bytes2).unwrap();
        let hash_bytes = hash_scalar.to_bytes();
        let hash_biguint = BigUint::from_bytes_be(&hash_bytes);
        // For EC, we use the curve order as the modulus for U encoding

        let curve_order_bigint = BigUint::from_bytes_be(
            &self.group.order_as_bigint().to_bytes_be().1,
        );
        let hash_reduced = hash_biguint % curve_order_bigint;
        let u = secret.to_biguint().unwrap() ^ hash_reduced;

        // Build shares box
        let mut shares_box = DistributionSharesBox::new();
        shares_box.init(
            &commitments,
            positions,
            shares,
            publickeys,
            &challenge,
            responses,
            &u.to_bigint().unwrap(),
        );
        shares_box
    }

    /// Extract a secret share from the distribution box (Secp256k1Group implementation).
    ///
    /// # Parameters
    /// - `shares_box`: The distribution shares box from the dealer
    /// - `private_key`: The participant's private key (Scalar)
    /// - `w`: Random witness for DLEQ proof (Scalar)
    pub fn extract_secret_share(
        &self,
        shares_box: &DistributionSharesBox<Secp256k1Group>,
        private_key: &Scalar,
        w: &Scalar,
    ) -> Option<ShareBox<Secp256k1Group>> {
        let main_gen = self.group.generator();

        // Generate public key from private key using group method
        let public_key = self.group.generate_public_key(private_key);

        // Get encrypted share from distribution box (serialize key for HashMap lookup)
        let public_key_bytes = self.group.element_to_bytes(&public_key);
        let encrypted_secret_share =
            shares_box.shares.get(&public_key_bytes)?;

        // Decryption: S_i = Y_i^(1/x_i) using scalar_inverse
        let privkey_inverse = self.group.scalar_inverse(private_key)?;
        let decrypted_share =
            self.group.exp(encrypted_secret_share, &privkey_inverse);

        // Generate DLEQ proof: DLEQ(G, publickey, decrypted_share, encrypted_secret_share)
        let mut dleq = DLEQ::new(self.group.clone());
        dleq.init(
            main_gen,
            public_key,
            decrypted_share,
            *encrypted_secret_share,
            *private_key,
            *w,
        );

        // Compute challenge using element_to_bytes() for EC points
        let mut challenge_hasher = Sha256::new();
        challenge_hasher.update(self.group.element_to_bytes(&public_key));
        challenge_hasher
            .update(self.group.element_to_bytes(encrypted_secret_share));

        let a1 = dleq.get_a1();
        let a2 = dleq.get_a2();
        challenge_hasher.update(self.group.element_to_bytes(&a1));
        challenge_hasher.update(self.group.element_to_bytes(&a2));

        let challenge_hash = challenge_hasher.finalize();
        let challenge = self.group.hash_to_scalar(&challenge_hash);
        dleq.c = Some(challenge);

        // Compute response using scalar arithmetic
        let response = dleq.get_r()?;

        // Build share box
        let mut share_box = ShareBox::new();
        share_box.init(public_key, decrypted_share, challenge, response);
        Some(share_box)
    }

    /// Verify a decrypted share (Secp256k1Group implementation).
    ///
    /// # Parameters
    /// - `sharebox`: The share box containing the decrypted share
    /// - `distribution_sharebox`: The distribution shares box from the dealer
    /// - `publickey`: The public key (EC point) of the participant who created the share
    pub fn verify_share(
        &self,
        sharebox: &ShareBox<Secp256k1Group>,
        distribution_sharebox: &DistributionSharesBox<Secp256k1Group>,
        publickey: &AffinePoint,
    ) -> bool {
        let main_gen = self.group.generator();

        // Get encrypted share from distribution box (serialize key for HashMap lookup)
        let publickey_bytes = self.group.element_to_bytes(publickey);
        let encrypted_share =
            match distribution_sharebox.shares.get(&publickey_bytes) {
                Some(s) => s,
                None => return false,
            };

        // Verify DLEQ proof using EC operations
        // a_1 = r*G + c*publickey (point addition)
        let g1_r = self.group.exp(&main_gen, &sharebox.response);
        let h1_c = self.group.exp(publickey, &sharebox.challenge);
        let a1_verify = self.group.mul(&g1_r, &h1_c);

        // a_2 = r*decrypted_share + c*encrypted_share
        let g2_r = self.group.exp(&sharebox.share, &sharebox.response);
        let h2_c = self.group.exp(encrypted_share, &sharebox.challenge);
        let a2_verify = self.group.mul(&g2_r, &h2_c);

        // Compute challenge hash using element_to_bytes() for EC points
        let mut challenge_hasher = Sha256::new();
        challenge_hasher.update(self.group.element_to_bytes(publickey));
        challenge_hasher.update(self.group.element_to_bytes(encrypted_share));
        challenge_hasher.update(self.group.element_to_bytes(&a1_verify));
        challenge_hasher.update(self.group.element_to_bytes(&a2_verify));

        let challenge_hash = challenge_hasher.finalize();
        let challenge_computed = self.group.hash_to_scalar(&challenge_hash);

        challenge_computed == sharebox.challenge
    }

    /// Verify distribution shares box (Secp256k1Group implementation).
    ///
    /// Verifies that all encrypted shares are consistent with the commitments.
    /// This is the public verifiability part of PVSS - anyone can verify the dealer
    /// didn't cheat.
    ///
    /// # Parameters
    /// - `distribute_sharesbox`: The distribution shares box to verify
    ///
    /// # Returns
    /// `true` if the distribution is valid, `false` otherwise
    pub fn verify_distribution_shares(
        &self,
        distribute_sharesbox: &DistributionSharesBox<Secp256k1Group>,
    ) -> bool {
        let subgroup_gen = self.group.subgroup_generator();
        let mut challenge_hasher = Sha256::new();

        // Verify each participant's encrypted share and accumulate hash
        for (idx, publickey) in
            distribute_sharesbox.publickeys.iter().enumerate()
        {
            let publickey_bytes = self.group.element_to_bytes(publickey);
            let position = distribute_sharesbox.positions.get(&publickey_bytes);
            let response = distribute_sharesbox.responses.get(&publickey_bytes);
            let encrypted_share =
                distribute_sharesbox.shares.get(&publickey_bytes);

            if position.is_none()
                || response.is_none()
                || encrypted_share.is_none()
            {
                eprintln!("DEBUG: Participant {} missing data", idx + 1);
                return false;
            }

            let position = *position.unwrap();
            let response = response.unwrap();
            let encrypted_share = encrypted_share.unwrap();

            // Calculate X_i = Σ_j (position^j) * C_j using EC operations
            let mut x_val = self.group.identity();
            let mut exponent = Scalar::ONE;
            for j in 0..distribute_sharesbox.commitments.len() {
                // C_j^(position^j) in EC notation = (position^j) * C_j
                let c_j_pow = self
                    .group
                    .exp(&distribute_sharesbox.commitments[j], &exponent);
                x_val = self.group.mul(&x_val, &c_j_pow);
                let pos_scalar = Scalar::from(position as u64);
                exponent = self.group.scalar_mul(&exponent, &pos_scalar);
            }

            // Verify DLEQ proof for this participant
            // DLEQ(g, X_i, y_i, Y_i): proves log_g(X_i) = log_{y_i}(Y_i)
            // a_1 = r*g + c*X_i, a_2 = r*y_i + c*Y_i
            let g_r = self.group.exp(&subgroup_gen, response);
            let x_c = self.group.exp(&x_val, &distribute_sharesbox.challenge);
            let a1 = self.group.mul(&g_r, &x_c);

            let y_r = self.group.exp(publickey, response);
            let y_c = self
                .group
                .exp(encrypted_share, &distribute_sharesbox.challenge);
            let a2 = self.group.mul(&y_r, &y_c);

            // Update hash with X_i, Y_i, a_1, a_2 using element_to_bytes()

            // Debug: print what's being hashed for first participant
            if idx == 0 {
                eprintln!("DEBUG: Verification hashing - Participant 1:");
                eprintln!(
                    "  X_i bytes: {:?}",
                    self.group.element_to_bytes(&x_val)
                );
                eprintln!(
                    "  Y_i bytes: {:?}",
                    self.group.element_to_bytes(encrypted_share)
                );
                eprintln!("  a1 bytes: {:?}", self.group.element_to_bytes(&a1));
                eprintln!("  a2 bytes: {:?}", self.group.element_to_bytes(&a2));
            }

            challenge_hasher.update(self.group.element_to_bytes(&x_val));
            challenge_hasher
                .update(self.group.element_to_bytes(encrypted_share));
            challenge_hasher.update(self.group.element_to_bytes(&a1));
            challenge_hasher.update(self.group.element_to_bytes(&a2));

            // Debug: print detailed info for first participant
            if idx == 0 {
                eprintln!("DEBUG: Verification - Participant 1:");
                eprintln!(
                    "  X_i bytes: {:?}",
                    self.group.element_to_bytes(&x_val)
                );
                eprintln!(
                    "  Y_i bytes: {:?}",
                    self.group.element_to_bytes(encrypted_share)
                );
                eprintln!(
                    "  response bytes: {:?}",
                    self.group.scalar_to_bytes(response)
                );
                eprintln!(
                    "  challenge bytes: {:?}",
                    self.group.scalar_to_bytes(&distribute_sharesbox.challenge)
                );
                eprintln!(
                    "  g^r bytes: {:?}",
                    self.group.element_to_bytes(&g_r)
                );
                eprintln!(
                    "  X_i^c bytes: {:?}",
                    self.group.element_to_bytes(&x_c)
                );
                eprintln!(
                    "  a1 (=g^r+X_i^c) bytes: {:?}",
                    self.group.element_to_bytes(&a1)
                );
                eprintln!("  a2 bytes: {:?}", self.group.element_to_bytes(&a2));
                eprintln!(
                    "  subgroup_gen bytes: {:?}",
                    self.group.element_to_bytes(&subgroup_gen)
                );

                // Debug: what was hashed during distribution?
                eprintln!("DEBUG: During distribution, a1 was:");
                eprintln!("  This should equal g^w, let's verify:");
                // We need to find the w value for this participant
                // But we don't have it in the verification function
            }
        }

        // Calculate final challenge and check if it matches
        let challenge_hash = challenge_hasher.finalize();
        let computed_challenge = self.group.hash_to_scalar(&challenge_hash);

        let result = computed_challenge == distribute_sharesbox.challenge;
        if !result {
            eprintln!("DEBUG: Challenge mismatch!");
            eprintln!(
                "Stored challenge: {:?}",
                self.group.scalar_to_bytes(&distribute_sharesbox.challenge)
            );
            eprintln!(
                "Computed challenge: {:?}",
                self.group.scalar_to_bytes(&computed_challenge)
            );
        }
        result
    }

    /// Reconstruct secret from shares (Secp256k1Group implementation).
    ///
    /// # Parameters
    /// - `share_boxes`: Array of share boxes from participants
    /// - `distribute_share_box`: The distribution shares box from the dealer
    ///
    /// # Returns
    /// `Some(secret)` if reconstruction succeeds, `None` otherwise
    pub fn reconstruct(
        &self,
        share_boxes: &[ShareBox<Secp256k1Group>],
        distribute_share_box: &DistributionSharesBox<Secp256k1Group>,
    ) -> Option<BigInt> {
        use rayon::prelude::*;

        if share_boxes.len() < distribute_share_box.commitments.len() {
            return None;
        }

        // Build position -> share map
        let mut shares: std::collections::HashMap<i64, AffinePoint> =
            std::collections::HashMap::new();
        for share_box in share_boxes.iter() {
            let publickey_bytes =
                self.group.element_to_bytes(&share_box.publickey);
            let position =
                distribute_share_box.positions.get(&publickey_bytes)?;
            shares.insert(*position, share_box.share);
        }

        // Compute Lagrange factors and G^s = Σ S_i^λ_i
        let secret = self.group.identity();
        let values: Vec<i64> = shares.keys().copied().collect();
        let shares_vec: Vec<(i64, AffinePoint)> = shares.into_iter().collect();
        let shares_slice = shares_vec.as_slice();

        let factors: Vec<AffinePoint> = shares_slice
            .par_iter()
            .map(|(position, share)| {
                self.compute_lagrange_factor_secp256k1(
                    *position, share, &values,
                )
            })
            .collect();

        // Add all factors using group.mul() (EC point addition)
        let final_secret = factors
            .into_iter()
            .fold(secret, |acc, factor| self.group.mul(&acc, &factor));

        // Reconstruct secret = H(G^s) XOR U
        let secret_hash =
            Sha256::digest(self.group.element_to_bytes(&final_secret));
        // Convert hash to Scalar using from_repr (modular reduction)
        let mut field_bytes = FieldBytes::<k256::Secp256k1>::default();
        let hash_len = secret_hash.len().min(field_bytes.len());
        field_bytes[32 - hash_len..].copy_from_slice(&secret_hash[..hash_len]);
        let hash_scalar = Scalar::from_repr(field_bytes).unwrap();
        let hash_bytes = hash_scalar.to_bytes();
        let hash_biguint = BigUint::from_bytes_be(&hash_bytes);
        // For EC, we use the curve order as the modulus for U encoding

        let scalar_bytes = self.group.order_as_bigint().to_bytes_be().1;
        let curve_order_bigint = BigUint::from_bytes_be(&scalar_bytes);
        let hash_reduced = hash_biguint % curve_order_bigint;
        let decrypted_secret =
            hash_reduced ^ distribute_share_box.U.to_biguint().unwrap();

        Some(decrypted_secret.to_bigint().unwrap())
    }

    /// Compute Lagrange factor for secret reconstruction (Secp256k1Group implementation).
    ///
    /// This uses pure Scalar arithmetic to avoid BigInt/Scalar conversion issues.
    fn compute_lagrange_factor_secp256k1(
        &self,
        position: i64,
        share: &AffinePoint,
        values: &[i64],
    ) -> AffinePoint {
        // λ_i = ∏_{j≠i} j / (j - i)
        let mut lambda_num = Scalar::ONE;
        let mut lambda_den = Scalar::ONE;
        let mut sign = 1i64;

        for &j in values {
            if j == position {
                continue;
            }
            lambda_num *= Scalar::from(j as u64);
            let diff = j - position;
            if diff < 0 {
                sign *= -1;
                lambda_den *= Scalar::from((-diff) as u64);
            } else {
                lambda_den *= Scalar::from(diff as u64);
            }
        }

        // λ = numerator * denominator^(-1)
        let lambda = lambda_num * lambda_den.invert().unwrap();

        // Compute share^λ = λ * share (scalar multiplication)
        let mut factor = self.group.exp(share, &lambda);

        // Handle negative coefficients via point negation
        if sign < 0
            && let Some(negated) = self.group.element_inverse(&factor)
        {
            factor = negated;
        }

        factor
    }
}
