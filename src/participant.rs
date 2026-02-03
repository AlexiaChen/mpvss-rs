// Copyright 2020-2024 MathxH Chen.
//
// Code is licensed under GPLv3.0 License.

//! Participant implementation supporting multiple cryptographic groups.
//!
//! This module provides `Participant<G: Group>` which works with any group
//! implementation (MODP, secp256k1, etc.), enabling the PVSS scheme to use different
//! cryptographic backends.

use num_bigint::{BigInt, BigUint, ToBigInt};
use num_integer::Integer;
use num_traits::identities::{One, Zero};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::sync::Arc;

use crate::dleq::DLEQ;
use crate::group::Group;
use crate::groups::ModpGroup;
use crate::polynomial::Polynomial;
use crate::sharebox::{DistributionSharesBox, ShareBox};

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

    /// Distribute a secret among participants.
    ///
    /// - Parameters:
    ///   - `secret`: The value to be shared (as BigInt for cross-group compatibility)
    ///   - `publickeys`: Array of public keys of each participant
    ///   - `threshold`: Number of shares needed for reconstruction
    ///
    /// Returns a `DistributionSharesBox` containing encrypted shares and proofs
    pub fn distribute_secret(
        &mut self,
        secret: &BigInt,
        publickeys: &[G::Element],
        threshold: u32,
    ) -> DistributionSharesBox<G>
    where
        G::Scalar: Default,
    {
        self.distribute_secret_bytes(
            &secret.to_bytes_be().1,
            publickeys,
            threshold,
        )
    }

    /// Distribute a secret as bytes among participants.
    pub fn distribute_secret_bytes(
        &mut self,
        secret: &[u8],
        publickeys: &[G::Element],
        threshold: u32,
    ) -> DistributionSharesBox<G>
    where
        G::Scalar: Default,
    {
        // Stub implementation for generic groups
        // Full implementation is provided for ModpGroup via distribute_secret_modp
        let mut shares_box = DistributionSharesBox::new();
        let mut commitments: Vec<G::Element> = Vec::new();
        for _ in 0..threshold {
            commitments.push(self.group.subgroup_generator());
        }
        let challenge = self.group.hash_to_scalar(b"distribute_challenge");
        let secret_bigint =
            BigInt::from_bytes_be(num_bigint::Sign::Plus, secret);
        shares_box.init(
            &commitments,
            BTreeMap::new(),
            BTreeMap::new(),
            publickeys,
            &challenge,
            BTreeMap::new(),
            &secret_bigint,
        );
        shares_box
    }

    /// Extract a secret share from the distribution box.
    pub fn extract_secret_share(
        &self,
        _shares_box: &DistributionSharesBox<G>,
        _private_key: &G::Scalar,
    ) -> Option<ShareBox<G>> {
        // TODO: Implement generic share extraction
        None
    }

    /// Verify distribution shares.
    pub fn verify_distribution_shares(
        _shares_box: &DistributionSharesBox<G>,
    ) -> bool {
        // TODO: Implement generic verification
        true
    }

    /// Verify a decrypted share.
    pub fn verify_share(
        &self,
        _sharebox: &ShareBox<G>,
        _distribution_sharebox: &DistributionSharesBox<G>,
        _publickey: &G::Element,
    ) -> bool {
        // TODO: Implement generic verification
        true
    }

    /// Reconstruct secret from shares.
    pub fn reconstruct(
        &self,
        _share_boxs: &[ShareBox<G>],
        _distribute_share_box: &DistributionSharesBox<G>,
    ) -> Option<BigInt> {
        // TODO: Implement generic reconstruction
        None
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
    pub fn distribute_secret_modp(
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
        let mut positions: BTreeMap<BigInt, i64> = BTreeMap::new();
        let mut x: BTreeMap<BigInt, BigInt> = BTreeMap::new();
        let mut shares: BTreeMap<BigInt, BigInt> = BTreeMap::new();
        let mut challenge_hasher = Sha256::new();

        let mut sampling_points: BTreeMap<BigInt, BigInt> = BTreeMap::new();
        let mut dleq_w: BTreeMap<BigInt, BigInt> = BTreeMap::new();
        let mut position: i64 = 1;

        // Calculate commitments C_j = g^a_j using group.exp()
        for j in 0..threshold {
            let coeff = &polynomial.coefficients[j as usize];
            let commitment = self.group.exp(&subgroup_gen, coeff);
            commitments.push(commitment);
        }

        // Calculate encrypted shares for each participant
        for pubkey in publickeys {
            positions.insert(pubkey.clone(), position);

            // P(position) mod order (scalar arithmetic)
            let pos_scalar = &BigInt::from(position);
            let secret_share = polynomial.get_value(pos_scalar) % group_order;
            sampling_points.insert(pubkey.clone(), secret_share.clone());

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
            x.insert(pubkey.clone(), x_val.clone());

            // Calculate Y_i = y_i^P(i) (encrypted share) using group.exp()
            let encrypted_secret_share = self.group.exp(pubkey, &secret_share);
            shares.insert(pubkey.clone(), encrypted_secret_share.clone());

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
            dleq_w.insert(pubkey.clone(), w.clone());

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
        let mut responses: BTreeMap<BigInt, BigInt> = BTreeMap::new();
        for pubkey in publickeys {
            let alpha = sampling_points.get(pubkey).unwrap();
            let w_i = dleq_w.get(pubkey).unwrap();
            let alpha_c =
                self.group.scalar_mul(alpha, &challenge) % group_order;
            let response = self.group.scalar_sub(w_i, &alpha_c) % group_order;
            responses.insert(pubkey.clone(), response);
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
    pub fn extract_secret_share_modp(
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
        let encrypted_secret_share = shares_box.shares.get(&public_key)?;

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
    pub fn verify_share_modp(
        &self,
        sharebox: &ShareBox<ModpGroup>,
        distribution_sharebox: &DistributionSharesBox<ModpGroup>,
        publickey: &BigInt,
    ) -> bool {
        let main_gen = self.group.generator();

        // Get encrypted share from distribution box
        let encrypted_share = match distribution_sharebox.shares.get(publickey)
        {
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
    pub fn verify_distribution_shares_modp(
        &self,
        distribute_sharesbox: &DistributionSharesBox<ModpGroup>,
    ) -> bool {
        let subgroup_gen = self.group.subgroup_generator();
        let group_order = self.group.order();
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
    pub fn reconstruct_modp(
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
            let position =
                distribute_share_box.positions.get(&share_box.publickey)?;
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
        let dist_box = dealer.distribute_secret_modp(
            &secret.to_bigint().unwrap(),
            &publickeys,
            threshold,
        );

        // ===== Step 1: Verify distribution =====
        // Each participant should verify the distribution is valid
        let verified_by_p1 = dealer.verify_distribution_shares_modp(&dist_box);
        let verified_by_p2 = dealer.verify_distribution_shares_modp(&dist_box);
        let verified_by_p3 = dealer.verify_distribution_shares_modp(&dist_box);
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
            .extract_secret_share_modp(&dist_box, &p1.privatekey, &w)
            .unwrap();
        let s2 = p2
            .extract_secret_share_modp(&dist_box, &p2.privatekey, &w)
            .unwrap();
        let s3 = p3
            .extract_secret_share_modp(&dist_box, &p3.privatekey, &w)
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
        let p1_verifies_s2 =
            dealer.verify_share_modp(&s2, &dist_box, &p2.publickey);
        let p1_verifies_s3 =
            dealer.verify_share_modp(&s3, &dist_box, &p3.publickey);
        assert!(p1_verifies_s2, "P1 should verify P2's share as valid");
        assert!(p1_verifies_s3, "P1 should verify P3's share as valid");

        let p2_verifies_s1 =
            dealer.verify_share_modp(&s1, &dist_box, &p1.publickey);
        let p2_verifies_s3 =
            dealer.verify_share_modp(&s3, &dist_box, &p3.publickey);
        assert!(p2_verifies_s1, "P2 should verify P1's share as valid");
        assert!(p2_verifies_s3, "P2 should verify P3's share as valid");

        let p3_verifies_s1 =
            dealer.verify_share_modp(&s1, &dist_box, &p1.publickey);
        let p3_verifies_s2 =
            dealer.verify_share_modp(&s2, &dist_box, &p2.publickey);
        assert!(p3_verifies_s1, "P3 should verify P1's share as valid");
        assert!(p3_verifies_s2, "P3 should verify P2's share as valid");

        // ===== Step 4: Reconstruct secret from verified shares =====
        let shares = vec![s1, s2, s3];
        let reconstructed =
            dealer.reconstruct_modp(&shares, &dist_box).unwrap();

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
}
