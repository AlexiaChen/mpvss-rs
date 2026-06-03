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

use crate::dleq::{DLEQ, DLEQ2};
use crate::group::Group;
use crate::groups::ModpGroup;
use crate::polynomial::Polynomial;
use crate::sharebox::{DistributionSharesBox, PublicKey, ShareBox};

// secp256k1-specific imports (only available when feature is enabled)

use crate::groups::Secp256k1Group;

use k256::{AffinePoint, Scalar};

// Ristretto255-specific imports
use crate::groups::Ristretto255Group;

use curve25519_dalek::ristretto::RistrettoPoint;

use curve25519_dalek::scalar::Scalar as RistrettoScalar;

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
    pub publickey: PublicKey<G>,
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
        let primary = self.group.generate_public_key(&self.privatekey);
        let secondary =
            self.group.generate_blinding_public_key(&self.privatekey);
        self.publickey = PublicKey::new(primary, secondary);
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
        publickeys: &[PublicKey<ModpGroup>],
        threshold: u32,
    ) -> DistributionSharesBox<ModpGroup> {
        assert!(threshold <= publickeys.len() as u32);

        // Group generators
        let commitment_gen = self.group.subgroup_generator();
        let commitment_blinding_gen = self.group.subgroup_blinding_generator();
        let main_gen = self.group.generator();
        let main_blinding_gen = self.group.blinding_generator();
        let subgroup_order = self.group.subgroup_order();

        // Paper reference: Section 5.1, Distribution.  The improved scheme
        // samples two degree-(t-1) polynomials: `f(x)` for the secret exponent
        // and `g(x)` for the Pedersen hiding exponent.
        let mut polynomial = Polynomial::new();
        polynomial.init((threshold - 1) as i32, subgroup_order);
        let mut blinding_polynomial = Polynomial::new();
        blinding_polynomial.init((threshold - 1) as i32, subgroup_order);

        // Data structures
        let mut commitments: Vec<BigInt> = Vec::new();
        let mut positions: HashMap<Vec<u8>, i64> = HashMap::new();
        let mut shares: HashMap<Vec<u8>, BigInt> = HashMap::new();
        let mut challenge_hasher = Sha256::new();

        let mut sampling_points: HashMap<Vec<u8>, BigInt> = HashMap::new();
        let mut blinding_sampling_points: HashMap<Vec<u8>, BigInt> =
            HashMap::new();
        let mut dleq_w1: HashMap<Vec<u8>, BigInt> = HashMap::new();
        let mut dleq_w2: HashMap<Vec<u8>, BigInt> = HashMap::new();
        let mut position: i64 = 1;

        // Paper reference: Section 5.1, Distribution.  Each coefficient pair
        // `(alpha_j, beta_j)` is published only through the Pedersen
        // commitment `C_j = g^alpha_j h^beta_j`, replacing the older
        // Feldman/Schoenmakers-style `g^alpha_j` commitment.
        for j in 0..threshold {
            let coeff = &polynomial.coefficients[j as usize];
            let blinding_coeff = &blinding_polynomial.coefficients[j as usize];
            let commitment = self.group.mul(
                &self.group.exp(&commitment_gen, coeff),
                &self.group.exp(&commitment_blinding_gen, blinding_coeff),
            );
            commitments.push(commitment);
        }

        // Calculate encrypted shares for each participant
        for pubkey in publickeys {
            let pubkey_bytes = pubkey.to_bytes(self.group.as_ref());
            positions.insert(pubkey_bytes.clone(), position);

            // Paper reference: Section 5.1.  Participant i receives the
            // polynomial evaluations `f(i)` and `g(i)` only in encrypted group
            // form; they are never sent as scalars.
            let pos_scalar = &BigInt::from(position);
            let secret_share =
                polynomial.get_value(pos_scalar).mod_floor(subgroup_order);
            let blinding_share = blinding_polynomial
                .get_value(pos_scalar)
                .mod_floor(subgroup_order);
            sampling_points.insert(pubkey_bytes.clone(), secret_share.clone());
            blinding_sampling_points
                .insert(pubkey_bytes.clone(), blinding_share.clone());

            // Paper reference: Section 5.1, verifier-side recomputation of
            // `X_i`.  Expanding the commitments gives
            // `X_i = product C_j^(i^j) = g^f(i) h^g(i)`.
            let mut x_val = self.group.identity();
            let mut exponent = BigInt::one();
            for j in 0..threshold {
                let c_j_pow =
                    self.group.exp(&commitments[j as usize], &exponent);
                x_val = self.group.mul(&x_val, &c_j_pow);
                exponent = self.group.scalar_mul(&exponent, pos_scalar);
            }

            // Paper reference: Section 5.1, encrypted share equation:
            // `Y_i = y_i1^f(i) y_i2^g(i)`.  Since both public-key components
            // use the same private key, the holder can decrypt this to
            // `G^f(i) H^g(i)` by exponentiating with `1/x_i`.
            let encrypted_secret_share = self.group.mul(
                &self.group.exp(pubkey.primary(), &secret_share),
                &self.group.exp(pubkey.secondary(), &blinding_share),
            );
            shares.insert(pubkey_bytes.clone(), encrypted_secret_share.clone());

            // Paper reference: Sections 4 and 5.1.  The dealer proves that
            // the same hidden pair `(f(i), g(i))` opens both `X_i` and `Y_i`,
            // using the generalized Chaum-Pedersen proof.
            let witness1 = self.group.generate_private_key();
            let witness2 = self.group.generate_private_key();
            let (a1, a2) = DLEQ2::<ModpGroup>::prover_commitments(
                self.group.as_ref(),
                &commitment_gen,
                &commitment_blinding_gen,
                pubkey.primary(),
                pubkey.secondary(),
                &witness1,
                &witness2,
            );
            dleq_w1.insert(pubkey_bytes.clone(), witness1);
            dleq_w2.insert(pubkey_bytes.clone(), witness2);

            DLEQ2::<ModpGroup>::append_transcript_hash(
                self.group.as_ref(),
                &commitment_gen,
                &commitment_blinding_gen,
                pubkey.primary(),
                pubkey.secondary(),
                &x_val,
                &encrypted_secret_share,
                &a1,
                &a2,
                &mut challenge_hasher,
            );

            position += 1;
        }

        // Paper reference: Section 5.1.  All participant proofs are folded
        // into one Fiat-Shamir challenge, matching the paper's "n-fold
        // parallel composition" with a common challenge.
        let challenge_hash = challenge_hasher.finalize();
        let challenge = self.group.hash_to_scalar(&challenge_hash);

        // Paper reference: Section 4 generalized proof.  Each participant
        // gets two responses, one for `f(i)` and one for `g(i)`.
        let mut responses: HashMap<Vec<u8>, BigInt> = HashMap::new();
        let mut blinding_responses: HashMap<Vec<u8>, BigInt> = HashMap::new();
        for pubkey in publickeys {
            let pubkey_bytes = pubkey.to_bytes(self.group.as_ref());
            let alpha = sampling_points.get(&pubkey_bytes).unwrap();
            let beta = blinding_sampling_points.get(&pubkey_bytes).unwrap();
            let w1_i = dleq_w1.get(&pubkey_bytes).unwrap();
            let w2_i = dleq_w2.get(&pubkey_bytes).unwrap();
            let (response, blinding_response) = DLEQ2::<ModpGroup>::responses(
                self.group.as_ref(),
                w1_i,
                w2_i,
                alpha,
                beta,
                &challenge,
            );
            responses.insert(pubkey_bytes, response);
            blinding_responses.insert(
                pubkey.to_bytes(self.group.as_ref()),
                blinding_response,
            );
        }

        // Paper reference: Section 5.1.  The shared random value is
        // `S = G^s1 H^s2` where `s1 = f(0)` and `s2 = g(0)`.  This crate keeps
        // the existing hybrid encoding and masks the user secret with
        // `Hash(S)`.
        let s1 = polynomial
            .get_value(&BigInt::zero())
            .mod_floor(subgroup_order);
        let s2 = blinding_polynomial
            .get_value(&BigInt::zero())
            .mod_floor(subgroup_order);
        let g_s = self.group.mul(
            &self.group.exp(&main_gen, &s1),
            &self.group.exp(&main_blinding_gen, &s2),
        );
        let sha256_hash = Sha256::digest(self.group.element_to_bytes(&g_s));
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
            blinding_responses,
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
        let main_gen = self
            .group
            .mul(&self.group.generator(), &self.group.blinding_generator());

        // Generate registered public key from private key using group methods.
        let public_key = PublicKey::new(
            self.group.generate_public_key(private_key),
            self.group.generate_blinding_public_key(private_key),
        );
        let combined_public_key = public_key.combined(self.group.as_ref());

        // Get encrypted share from distribution box
        let pubkey_bytes = public_key.to_bytes(self.group.as_ref());
        let encrypted_secret_share = shares_box.shares.get(&pubkey_bytes)?;

        // Paper reference: Section 5.1, Reconstruction.  From
        // `Y_i = (G^x_i)^f(i) (H^x_i)^g(i)`, exponentiating by `1/x_i`
        // yields the released share `S_i = G^f(i) H^g(i)`.
        let privkey_inverse = self.group.scalar_inverse(private_key)?;
        let decrypted_share =
            self.group.exp(encrypted_secret_share, &privkey_inverse);

        // Paper reference: Section 5.1, proof of correct decryption.  The
        // text denotes this as a DLEQ proof over base `GH`, combined public
        // key `y_i1 y_i2`, released share `S_i`, and ciphertext `Y_i`.
        let mut dleq = DLEQ::new(self.group.clone());
        dleq.init(
            main_gen.clone(),
            combined_public_key.clone(),
            decrypted_share.clone(),
            encrypted_secret_share.clone(),
            private_key.clone(),
            w.clone(),
        );

        // Compute challenge using group operations
        let mut challenge_hasher = Sha256::new();
        let a1 = dleq.get_a1();
        let a2 = dleq.get_a2();
        DLEQ::<ModpGroup>::append_transcript_hash(
            self.group.as_ref(),
            &combined_public_key,
            encrypted_secret_share,
            &a1,
            &a2,
            &mut challenge_hasher,
        );

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
        publickey: &PublicKey<ModpGroup>,
    ) -> bool {
        let main_gen = self
            .group
            .mul(&self.group.generator(), &self.group.blinding_generator());
        let combined_public_key = publickey.combined(self.group.as_ref());

        // Get encrypted share from distribution box
        let pubkey_bytes = publickey.to_bytes(self.group.as_ref());
        let encrypted_share =
            match distribution_sharebox.shares.get(&pubkey_bytes) {
                Some(s) => s,
                None => return false,
            };

        // Verify share DLEQ proof through shared verifier object path.
        let mut dleq = DLEQ::<ModpGroup>::new(self.group.clone());
        dleq.g1 = main_gen;
        dleq.h1 = combined_public_key;
        dleq.g2 = sharebox.share.clone();
        dleq.h2 = encrypted_share.clone();
        dleq.c = Some(sharebox.challenge.clone());
        dleq.r = Some(sharebox.response.clone());
        dleq.verify()
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
        let commitment_gen = self.group.subgroup_generator();
        let commitment_blinding_gen = self.group.subgroup_blinding_generator();
        let mut challenge_hasher = Sha256::new();

        // Verify each participant's encrypted share and accumulate hash
        for publickey in &distribute_sharesbox.publickeys {
            let pubkey_bytes = publickey.to_bytes(self.group.as_ref());
            let position = distribute_sharesbox.positions.get(&pubkey_bytes);
            let response = distribute_sharesbox.responses.get(&pubkey_bytes);
            let blinding_response =
                distribute_sharesbox.blinding_responses.get(&pubkey_bytes);
            let encrypted_share =
                distribute_sharesbox.shares.get(&pubkey_bytes);

            if position.is_none()
                || response.is_none()
                || blinding_response.is_none()
                || encrypted_share.is_none()
            {
                return false;
            }

            // Paper reference: Section 5.1, public verification recomputes
            // `X_i = product C_j^(i^j)` from the public commitments.
            let mut x_val = self.group.identity();
            let mut exponent = BigInt::one();
            for j in 0..distribute_sharesbox.commitments.len() {
                let c_j_pow = self
                    .group
                    .exp(&distribute_sharesbox.commitments[j], &exponent);
                x_val = self.group.mul(&x_val, &c_j_pow);
                exponent = self
                    .group
                    .scalar_mul(&exponent, &BigInt::from(*position.unwrap()));
            }

            let _ = DLEQ2::<ModpGroup>::verifier_update_hash(
                self.group.as_ref(),
                &commitment_gen,
                &commitment_blinding_gen,
                publickey.primary(),
                publickey.secondary(),
                &x_val,
                encrypted_share.unwrap(),
                response.unwrap(),
                blinding_response.unwrap(),
                &distribute_sharesbox.challenge,
                &mut challenge_hasher,
            );
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

        let subgroup_order = self.group.subgroup_order();

        // Build position -> share map
        let mut shares: BTreeMap<i64, BigInt> = BTreeMap::new();
        for share_box in share_boxes.iter() {
            let pubkey_bytes =
                share_box.publickey.to_bytes(self.group.as_ref());
            let position = distribute_share_box.positions.get(&pubkey_bytes)?;
            shares.insert(*position, share_box.share.clone());
        }

        // Paper reference: Section 5.1, Pooling.  Lagrange interpolation on
        // the released group elements recovers
        // `product S_i^lambda_i = G^f(0) H^g(0)`.
        let mut secret = self.group.identity();
        let values: Vec<i64> = shares.keys().copied().collect();
        let shares_vec: Vec<(i64, BigInt)> = shares.into_iter().collect();
        let shares_slice = shares_vec.as_slice();

        let factor_options: Vec<Option<BigInt>> = shares_slice
            .par_iter()
            .map(|(position, share)| {
                self.compute_lagrange_factor(
                    *position,
                    share,
                    &values,
                    subgroup_order,
                )
            })
            .collect();
        let mut factors: Vec<BigInt> = Vec::with_capacity(factor_options.len());
        for factor in factor_options {
            factors.push(factor?);
        }

        // Multiply all factors using group.mul()
        secret = factors
            .into_iter()
            .fold(secret, |acc, factor| self.group.mul(&acc, &factor));

        // Reconstruct secret = H(G^s) XOR U
        let secret_hash = Sha256::digest(self.group.element_to_bytes(&secret));
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
        subgroup_order: &BigInt,
    ) -> Option<BigInt> {
        use crate::util::Util;

        let lagrange_coefficient =
            Util::lagrange_coefficient(&position, values);

        // Compute exponent λ_i in the subgroup scalar field.
        let is_negative = lagrange_coefficient.0.clone()
            * lagrange_coefficient.1.clone()
            < BigInt::zero();
        let mut numerator = Util::abs(&lagrange_coefficient.0);
        let mut denominator = Util::abs(&lagrange_coefficient.1);
        let gcd = numerator.gcd(&denominator);
        numerator /= &gcd;
        denominator /= &gcd;
        let denominator_inverse =
            Util::mod_inverse(&denominator, subgroup_order)?;
        let exponent =
            (numerator * denominator_inverse).mod_floor(subgroup_order);

        // Compute S_i^λ_i using group.exp()
        let mut factor = self.group.exp(share, &exponent);

        // Handle negative Lagrange coefficient using element_inverse
        if is_negative {
            factor = self.group.element_inverse(&factor)?;
        }

        Some(factor)
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
    use k256::elliptic_curve::{FieldBytes, ff::PrimeField};
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
    }

    /// Regression test: threshold-2 reconstruction must work for non-adjacent
    /// participant subset positions {1, 3}.
    #[test]
    fn test_threshold_subset_modp_positions_1_and_3() {
        use num_bigint::{BigUint, ToBigInt};

        let group = ModpGroup::new();
        let mut dealer = Participant::with_arc(group.clone());
        dealer.initialize();

        let mut p1 = Participant::with_arc(group.clone());
        let mut p2 = Participant::with_arc(group.clone());
        let mut p3 = Participant::with_arc(group.clone());
        p1.initialize();
        p2.initialize();
        p3.initialize();

        let secret = BigUint::from(123456u32).to_bigint().unwrap();
        let publickeys = vec![
            p1.publickey.clone(),
            p2.publickey.clone(),
            p3.publickey.clone(),
        ];
        let dist_box = dealer.distribute_secret(&secret, &publickeys, 2);

        let mut rng = rand::thread_rng();
        let w: BigInt = rng
            .gen_biguint_below(&group.modulus().to_biguint().unwrap())
            .to_bigint()
            .unwrap();

        let s1 = p1
            .extract_secret_share(&dist_box, &p1.privatekey, &w)
            .unwrap();
        let s3 = p3
            .extract_secret_share(&dist_box, &p3.privatekey, &w)
            .unwrap();

        let reconstructed = dealer.reconstruct(&[s1, s3], &dist_box).unwrap();
        assert_eq!(
            reconstructed, secret,
            "Threshold-2 reconstruction from positions 1 and 3 should recover original secret"
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

        let publickeys = vec![
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
        let g2 = *p2.publickey.primary();
        let h2 = group.exp(&g2, &alpha);

        // Create DLEQ
        let mut dleq = DLEQ::new(group.clone());
        dleq.init(g1, h1, g2, h2, alpha, w);

        // Compute challenge
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        dleq.update_hash(&mut hasher);
        let hash = hasher.finalize();
        let challenge = group.hash_to_scalar(&hash);

        dleq.c = Some(challenge.clone());
        let response = dleq.get_r().unwrap();
        dleq.r = Some(response);

        // Verify should succeed
        assert!(dleq.verify(), "Basic DLEQ proof should verify");
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

        let publickeys = vec![p1.publickey.clone(), p2.publickey.clone()];
        let threshold = 2;

        // Distribute secret
        let dist_box = dealer.distribute_secret(
            &secret.to_bigint().unwrap(),
            &publickeys,
            threshold,
        );

        // Verify DLEQ proofs
        assert!(
            dealer.verify_distribution_shares(&dist_box),
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
        publickeys: &[PublicKey<Secp256k1Group>],
        threshold: u32,
    ) -> DistributionSharesBox<Secp256k1Group> {
        assert!(threshold <= publickeys.len() as u32);

        // Paper reference: Section 5.1.  This is the same improved PVSS
        // algorithm as the MODP implementation above.  Because secp256k1 is
        // written additively, the paper's `g^a h^b` appears here as
        // `a*g + b*h`, and products of shares are point additions.

        // Group generators
        let commitment_gen = self.group.subgroup_generator();
        let commitment_blinding_gen = self.group.subgroup_blinding_generator();
        let main_gen = self.group.generator();
        let main_blinding_gen = self.group.blinding_generator();

        // Generate two random polynomials over the curve scalar field.
        let mut polynomial = Polynomial::new();
        let group_order_bigint = self.group.order_as_bigint().clone();
        polynomial.init((threshold - 1) as i32, &group_order_bigint);
        let mut blinding_polynomial = Polynomial::new();
        blinding_polynomial.init((threshold - 1) as i32, &group_order_bigint);

        // Data structures - use Vec<u8> keys (serialized points) since AffinePoint doesn't implement Hash
        let mut commitments: Vec<AffinePoint> = Vec::new();
        let mut positions: std::collections::HashMap<Vec<u8>, i64> =
            std::collections::HashMap::new();
        let mut shares: std::collections::HashMap<Vec<u8>, AffinePoint> =
            std::collections::HashMap::new();
        let mut challenge_hasher = Sha256::new();

        let mut sampling_points: std::collections::HashMap<Vec<u8>, Scalar> =
            std::collections::HashMap::new();
        let mut blinding_sampling_points: std::collections::HashMap<
            Vec<u8>,
            Scalar,
        > = std::collections::HashMap::new();
        let mut dleq_w1: std::collections::HashMap<Vec<u8>, Scalar> =
            std::collections::HashMap::new();
        let mut dleq_w2: std::collections::HashMap<Vec<u8>, Scalar> =
            std::collections::HashMap::new();
        let mut position: i64 = 1;

        // Calculate Pedersen commitments C_j = alpha_j*g + beta_j*h.
        for j in 0..threshold {
            let coeff = self
                .group
                .bigint_to_scalar(&polynomial.coefficients[j as usize]);
            let blinding_coeff = self.group.bigint_to_scalar(
                &blinding_polynomial.coefficients[j as usize],
            );
            let commitment = self.group.mul(
                &self.group.exp(&commitment_gen, &coeff),
                &self.group.exp(&commitment_blinding_gen, &blinding_coeff),
            );
            commitments.push(commitment);
        }

        // Calculate encrypted shares for each participant
        for pubkey in publickeys.iter() {
            let pubkey_bytes = pubkey.to_bytes(self.group.as_ref());
            positions.insert(pubkey_bytes.clone(), position);

            // f(position), g(position) as Scalars.
            let pos_scalar = BigInt::from(position);
            let secret_share = self
                .group
                .bigint_to_scalar(&polynomial.get_value(&pos_scalar));
            let blinding_share = self
                .group
                .bigint_to_scalar(&blinding_polynomial.get_value(&pos_scalar));
            sampling_points.insert(pubkey_bytes.clone(), secret_share);
            blinding_sampling_points
                .insert(pubkey_bytes.clone(), blinding_share);
            let witness1 = self.group.generate_private_key();
            let witness2 = self.group.generate_private_key();
            dleq_w1.insert(pubkey_bytes.clone(), witness1);
            dleq_w2.insert(pubkey_bytes.clone(), witness2);

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

            // Y_i = f(i)*y_i1 + g(i)*y_i2.
            let encrypted_secret_share = self.group.mul(
                &self.group.exp(pubkey.primary(), &secret_share),
                &self.group.exp(pubkey.secondary(), &blinding_share),
            );
            shares.insert(pubkey_bytes.clone(), encrypted_secret_share);

            let (a1, a2) = DLEQ2::<Secp256k1Group>::prover_commitments(
                self.group.as_ref(),
                &commitment_gen,
                &commitment_blinding_gen,
                pubkey.primary(),
                pubkey.secondary(),
                &witness1,
                &witness2,
            );

            DLEQ2::<Secp256k1Group>::append_transcript_hash(
                self.group.as_ref(),
                &commitment_gen,
                &commitment_blinding_gen,
                pubkey.primary(),
                pubkey.secondary(),
                &x_val,
                &encrypted_secret_share,
                &a1,
                &a2,
                &mut challenge_hasher,
            );

            position += 1;
        }

        // Compute common challenge
        let challenge_hash = challenge_hasher.finalize();
        let challenge = self.group.hash_to_scalar(&challenge_hash);

        // Compute responses: r_i = w - alpha_i * c
        let mut responses: std::collections::HashMap<Vec<u8>, Scalar> =
            std::collections::HashMap::new();
        let mut blinding_responses: std::collections::HashMap<Vec<u8>, Scalar> =
            std::collections::HashMap::new();
        for pubkey in publickeys {
            let pubkey_bytes = pubkey.to_bytes(self.group.as_ref());
            let alpha = sampling_points.get(&pubkey_bytes).unwrap();
            let beta = blinding_sampling_points.get(&pubkey_bytes).unwrap();
            let w1_i = dleq_w1.get(&pubkey_bytes).unwrap();
            let w2_i = dleq_w2.get(&pubkey_bytes).unwrap();
            let (response, blinding_response) =
                DLEQ2::<Secp256k1Group>::responses(
                    self.group.as_ref(),
                    w1_i,
                    w2_i,
                    alpha,
                    beta,
                    &challenge,
                );
            responses.insert(pubkey_bytes, response);
            blinding_responses.insert(
                pubkey.to_bytes(self.group.as_ref()),
                blinding_response,
            );
        }

        // Compute U = secret XOR H(G^s1 H^s2).
        let s1 = self
            .group
            .bigint_to_scalar(&polynomial.get_value(&BigInt::zero()));
        let s2 = self
            .group
            .bigint_to_scalar(&blinding_polynomial.get_value(&BigInt::zero()));
        let g_s = self.group.mul(
            &self.group.exp(&main_gen, &s1),
            &self.group.exp(&main_blinding_gen, &s2),
        );

        // Hash the EC point to bytes
        let sha256_hash = Sha256::digest(self.group.element_to_bytes(&g_s));
        let hash_biguint = BigUint::from_bytes_be(&sha256_hash[..]);
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
            blinding_responses,
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
        let main_gen = self
            .group
            .mul(&self.group.generator(), &self.group.blinding_generator());

        // Generate registered public key from private key using group methods.
        let public_key = PublicKey::new(
            self.group.generate_public_key(private_key),
            self.group.generate_blinding_public_key(private_key),
        );
        let combined_public_key = public_key.combined(self.group.as_ref());

        // Get encrypted share from distribution box (serialize key for HashMap lookup)
        let public_key_bytes = public_key.to_bytes(self.group.as_ref());
        let encrypted_secret_share =
            shares_box.shares.get(&public_key_bytes)?;

        // Decryption: S_i = Y_i^(1/x_i) using scalar_inverse
        let privkey_inverse = self.group.scalar_inverse(private_key)?;
        let decrypted_share =
            self.group.exp(encrypted_secret_share, &privkey_inverse);

        // Prove log_{G+H}(y_i1+y_i2) = log_{S_i}(Y_i).
        let mut dleq = DLEQ::new(self.group.clone());
        dleq.init(
            main_gen,
            combined_public_key,
            decrypted_share,
            *encrypted_secret_share,
            *private_key,
            *w,
        );

        // Compute challenge using shared DLEQ transcript helper.
        let mut challenge_hasher = Sha256::new();
        let a1 = dleq.get_a1();
        let a2 = dleq.get_a2();
        DLEQ::<Secp256k1Group>::append_transcript_hash(
            self.group.as_ref(),
            &combined_public_key,
            encrypted_secret_share,
            &a1,
            &a2,
            &mut challenge_hasher,
        );

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
        publickey: &PublicKey<Secp256k1Group>,
    ) -> bool {
        let main_gen = self
            .group
            .mul(&self.group.generator(), &self.group.blinding_generator());
        let combined_public_key = publickey.combined(self.group.as_ref());

        // Get encrypted share from distribution box (serialize key for HashMap lookup)
        let publickey_bytes = publickey.to_bytes(self.group.as_ref());
        let encrypted_share =
            match distribution_sharebox.shares.get(&publickey_bytes) {
                Some(s) => s,
                None => return false,
            };

        // Verify share DLEQ proof through shared verifier object path.
        let mut dleq = DLEQ::<Secp256k1Group>::new(self.group.clone());
        dleq.g1 = main_gen;
        dleq.h1 = combined_public_key;
        dleq.g2 = sharebox.share;
        dleq.h2 = *encrypted_share;
        dleq.c = Some(sharebox.challenge);
        dleq.r = Some(sharebox.response);
        dleq.verify()
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
        let commitment_gen = self.group.subgroup_generator();
        let commitment_blinding_gen = self.group.subgroup_blinding_generator();
        let mut challenge_hasher = Sha256::new();

        // Verify each participant's encrypted share and accumulate hash
        for publickey in distribute_sharesbox.publickeys.iter() {
            let publickey_bytes = publickey.to_bytes(self.group.as_ref());
            let position = distribute_sharesbox.positions.get(&publickey_bytes);
            let response = distribute_sharesbox.responses.get(&publickey_bytes);
            let blinding_response = distribute_sharesbox
                .blinding_responses
                .get(&publickey_bytes);
            let encrypted_share =
                distribute_sharesbox.shares.get(&publickey_bytes);

            if position.is_none()
                || response.is_none()
                || blinding_response.is_none()
                || encrypted_share.is_none()
            {
                return false;
            }

            let position = *position.unwrap();
            let response = response.unwrap();
            let blinding_response = blinding_response.unwrap();
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

            let _ = DLEQ2::<Secp256k1Group>::verifier_update_hash(
                self.group.as_ref(),
                &commitment_gen,
                &commitment_blinding_gen,
                publickey.primary(),
                publickey.secondary(),
                &x_val,
                encrypted_share,
                response,
                blinding_response,
                &distribute_sharesbox.challenge,
                &mut challenge_hasher,
            );
        }

        // Calculate final challenge and check if it matches
        let challenge_hash = challenge_hasher.finalize();
        let computed_challenge = self.group.hash_to_scalar(&challenge_hash);

        computed_challenge == distribute_sharesbox.challenge
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
                share_box.publickey.to_bytes(self.group.as_ref());
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
        let hash_biguint = BigUint::from_bytes_be(&secret_hash[..]);
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

// ============================================================================
// Ristretto255Group-Specific Implementation
// ============================================================================

impl Participant<Ristretto255Group> {
    /// Distribute a secret among participants (full implementation for Ristretto255Group).
    ///
    /// # Parameters
    /// - `secret`: The value to be shared (as BigInt for cross-group compatibility)
    /// - `publickeys`: Array of public keys (Ristretto points) of each participant
    /// - `threshold`: Number of shares needed for reconstruction
    ///
    /// Returns a `DistributionSharesBox` containing encrypted shares and DLEQ proofs
    pub fn distribute_secret(
        &mut self,
        secret: &BigInt,
        publickeys: &[PublicKey<Ristretto255Group>],
        threshold: u32,
    ) -> DistributionSharesBox<Ristretto255Group> {
        assert!(threshold <= publickeys.len() as u32);

        // Paper reference: Section 5.1.  Ristretto255 follows the same
        // information-theoretic PVSS construction as MODP, expressed in
        // additive group notation: `g^a h^b` becomes `a*g + b*h`.

        // Group generators
        let commitment_gen = self.group.subgroup_generator();
        let commitment_blinding_gen = self.group.subgroup_blinding_generator();
        let main_gen = self.group.generator();
        let main_blinding_gen = self.group.blinding_generator();

        // Generate two random polynomials over the group scalar field.
        let mut polynomial = Polynomial::new();
        let group_order_bigint = self.group.order_as_bigint().clone();
        polynomial.init((threshold - 1) as i32, &group_order_bigint);
        let mut blinding_polynomial = Polynomial::new();
        blinding_polynomial.init((threshold - 1) as i32, &group_order_bigint);

        // Data structures - use Vec<u8> keys (serialized points) since RistrettoPoint doesn't implement Hash
        let mut commitments: Vec<RistrettoPoint> = Vec::new();
        let mut positions: HashMap<Vec<u8>, i64> = HashMap::new();
        let mut shares: HashMap<Vec<u8>, RistrettoPoint> = HashMap::new();
        let mut challenge_hasher = Sha256::new();

        let mut sampling_points: HashMap<Vec<u8>, RistrettoScalar> =
            HashMap::new();
        let mut blinding_sampling_points: HashMap<Vec<u8>, RistrettoScalar> =
            HashMap::new();
        let mut dleq_w1: HashMap<Vec<u8>, RistrettoScalar> = HashMap::new();
        let mut dleq_w2: HashMap<Vec<u8>, RistrettoScalar> = HashMap::new();
        let mut position: i64 = 1;

        // Calculate Pedersen commitments C_j = alpha_j*g + beta_j*h.
        for j in 0..threshold {
            let coeff_bigint = &polynomial.coefficients[j as usize];
            let coeff = Ristretto255Group::bigint_to_scalar(coeff_bigint);
            let blinding_coeff = Ristretto255Group::bigint_to_scalar(
                &blinding_polynomial.coefficients[j as usize],
            );
            let commitment = self.group.mul(
                &self.group.exp(&commitment_gen, &coeff),
                &self.group.exp(&commitment_blinding_gen, &blinding_coeff),
            );
            commitments.push(commitment);
        }

        // Calculate encrypted shares for each participant
        for pubkey in publickeys {
            let pubkey_bytes = pubkey.to_bytes(self.group.as_ref());
            positions.insert(pubkey_bytes.clone(), position);

            // f(position), g(position) as Scalars.
            let pos_scalar = BigInt::from(position);
            let secret_share_bigint = polynomial.get_value(&pos_scalar);
            let secret_share_mod = &secret_share_bigint % &group_order_bigint;
            let secret_share =
                Ristretto255Group::bigint_to_scalar(&secret_share_mod);
            let blinding_share_bigint =
                blinding_polynomial.get_value(&pos_scalar);
            let blinding_share_mod =
                &blinding_share_bigint % &group_order_bigint;
            let blinding_share =
                Ristretto255Group::bigint_to_scalar(&blinding_share_mod);
            sampling_points.insert(pubkey_bytes.clone(), secret_share);
            blinding_sampling_points
                .insert(pubkey_bytes.clone(), blinding_share);
            let witness1 = self.group.generate_private_key();
            let witness2 = self.group.generate_private_key();
            dleq_w1.insert(pubkey_bytes.clone(), witness1);
            dleq_w2.insert(pubkey_bytes.clone(), witness2);

            // Calculate X_i = Σ_j (position^j) * C_j (using EC operations)
            let mut x_val = self.group.identity();
            let mut exponent = RistrettoScalar::ONE;

            for j in 0..threshold {
                // C_j^(i^j) in EC notation = (i^j) * C_j (scalar multiplication)
                let c_j_pow =
                    self.group.exp(&commitments[j as usize], &exponent);
                x_val = self.group.mul(&x_val, &c_j_pow);

                // exponent *= position (mod order)
                let pos_scalar = RistrettoScalar::from(position as u64);
                exponent = self.group.scalar_mul(&exponent, &pos_scalar);
            }

            // Y_i = f(i)*y_i1 + g(i)*y_i2.
            let encrypted_secret_share = self.group.mul(
                &self.group.exp(pubkey.primary(), &secret_share),
                &self.group.exp(pubkey.secondary(), &blinding_share),
            );
            shares.insert(pubkey_bytes.clone(), encrypted_secret_share);

            let (a1, a2) = DLEQ2::<Ristretto255Group>::prover_commitments(
                self.group.as_ref(),
                &commitment_gen,
                &commitment_blinding_gen,
                pubkey.primary(),
                pubkey.secondary(),
                &witness1,
                &witness2,
            );

            DLEQ2::<Ristretto255Group>::append_transcript_hash(
                self.group.as_ref(),
                &commitment_gen,
                &commitment_blinding_gen,
                pubkey.primary(),
                pubkey.secondary(),
                &x_val,
                &encrypted_secret_share,
                &a1,
                &a2,
                &mut challenge_hasher,
            );

            position += 1;
        }

        // Compute common challenge
        let challenge_hash = challenge_hasher.finalize();
        let challenge = self.group.hash_to_scalar(&challenge_hash);

        // Compute responses: r_i = w - alpha_i * c
        let mut responses: HashMap<Vec<u8>, RistrettoScalar> = HashMap::new();
        let mut blinding_responses: HashMap<Vec<u8>, RistrettoScalar> =
            HashMap::new();
        for pubkey in publickeys {
            let pubkey_bytes = pubkey.to_bytes(self.group.as_ref());
            let alpha = sampling_points.get(&pubkey_bytes).unwrap();
            let beta = blinding_sampling_points.get(&pubkey_bytes).unwrap();
            let w1_i = dleq_w1.get(&pubkey_bytes).unwrap();
            let w2_i = dleq_w2.get(&pubkey_bytes).unwrap();
            let (response, blinding_response) =
                DLEQ2::<Ristretto255Group>::responses(
                    self.group.as_ref(),
                    w1_i,
                    w2_i,
                    alpha,
                    beta,
                    &challenge,
                );
            responses.insert(pubkey_bytes, response);
            blinding_responses.insert(
                pubkey.to_bytes(self.group.as_ref()),
                blinding_response,
            );
        }

        // Compute U = secret XOR H(G^s1 H^s2).
        let s_bigint = polynomial.get_value(&BigInt::zero());
        let s1 = Ristretto255Group::bigint_to_scalar(&s_bigint);
        let s2_bigint = blinding_polynomial.get_value(&BigInt::zero());
        let s2 = Ristretto255Group::bigint_to_scalar(&s2_bigint);
        let g_s = self.group.mul(
            &self.group.exp(&main_gen, &s1),
            &self.group.exp(&main_blinding_gen, &s2),
        );

        // Hash the EC point to bytes
        let sha256_hash = Sha256::digest(self.group.element_to_bytes(&g_s));
        // Convert hash to BigUint and reduce modulo group order
        let hash_biguint = BigUint::from_bytes_be(&sha256_hash[..]);
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
            blinding_responses,
            &u.to_bigint().unwrap(),
        );
        shares_box
    }

    /// Extract a secret share from the distribution box (Ristretto255Group implementation).
    ///
    /// # Parameters
    /// - `shares_box`: The distribution shares box from the dealer
    /// - `private_key`: The participant's private key (Scalar)
    /// - `w`: Random witness for DLEQ proof (Scalar)
    pub fn extract_secret_share(
        &self,
        shares_box: &DistributionSharesBox<Ristretto255Group>,
        private_key: &RistrettoScalar,
        w: &RistrettoScalar,
    ) -> Option<ShareBox<Ristretto255Group>> {
        let main_gen = self
            .group
            .mul(&self.group.generator(), &self.group.blinding_generator());

        // Generate registered public key from private key using group methods.
        let public_key = PublicKey::new(
            self.group.generate_public_key(private_key),
            self.group.generate_blinding_public_key(private_key),
        );
        let combined_public_key = public_key.combined(self.group.as_ref());

        // Get encrypted share from distribution box (serialize key for HashMap lookup)
        let public_key_bytes = public_key.to_bytes(self.group.as_ref());
        let encrypted_secret_share =
            shares_box.shares.get(&public_key_bytes)?;

        // Decryption: S_i = Y_i^(1/x_i) using scalar_inverse
        let privkey_inverse = self.group.scalar_inverse(private_key)?;
        let decrypted_share =
            self.group.exp(encrypted_secret_share, &privkey_inverse);

        // Prove log_{G+H}(y_i1+y_i2) = log_{S_i}(Y_i).
        let mut dleq = DLEQ::new(self.group.clone());
        dleq.init(
            main_gen,
            combined_public_key,
            decrypted_share,
            *encrypted_secret_share,
            *private_key,
            *w,
        );

        // Compute challenge using shared DLEQ transcript helper.
        let mut challenge_hasher = Sha256::new();
        let a1 = dleq.get_a1();
        let a2 = dleq.get_a2();
        DLEQ::<Ristretto255Group>::append_transcript_hash(
            self.group.as_ref(),
            &combined_public_key,
            encrypted_secret_share,
            &a1,
            &a2,
            &mut challenge_hasher,
        );

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

    /// Verify a decrypted share (Ristretto255Group implementation).
    ///
    /// # Parameters
    /// - `sharebox`: The share box containing the decrypted share
    /// - `distribution_sharebox`: The distribution shares box from the dealer
    /// - `publickey`: The public key (Ristretto point) of the participant who created the share
    pub fn verify_share(
        &self,
        sharebox: &ShareBox<Ristretto255Group>,
        distribution_sharebox: &DistributionSharesBox<Ristretto255Group>,
        publickey: &PublicKey<Ristretto255Group>,
    ) -> bool {
        let main_gen = self
            .group
            .mul(&self.group.generator(), &self.group.blinding_generator());
        let combined_public_key = publickey.combined(self.group.as_ref());

        // Get encrypted share from distribution box (serialize key for HashMap lookup)
        let publickey_bytes = publickey.to_bytes(self.group.as_ref());
        let encrypted_share =
            match distribution_sharebox.shares.get(&publickey_bytes) {
                Some(s) => s,
                None => return false,
            };

        // Verify share DLEQ proof through shared verifier object path.
        let mut dleq = DLEQ::<Ristretto255Group>::new(self.group.clone());
        dleq.g1 = main_gen;
        dleq.h1 = combined_public_key;
        dleq.g2 = sharebox.share;
        dleq.h2 = *encrypted_share;
        dleq.c = Some(sharebox.challenge);
        dleq.r = Some(sharebox.response);
        dleq.verify()
    }

    /// Verify distribution shares box (Ristretto255Group implementation).
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
        distribute_sharesbox: &DistributionSharesBox<Ristretto255Group>,
    ) -> bool {
        let commitment_gen = self.group.subgroup_generator();
        let commitment_blinding_gen = self.group.subgroup_blinding_generator();
        let mut challenge_hasher = Sha256::new();

        // Verify each participant's encrypted share and accumulate hash
        for publickey in &distribute_sharesbox.publickeys {
            let publickey_bytes = publickey.to_bytes(self.group.as_ref());
            let position = distribute_sharesbox.positions.get(&publickey_bytes);
            let response = distribute_sharesbox.responses.get(&publickey_bytes);
            let blinding_response = distribute_sharesbox
                .blinding_responses
                .get(&publickey_bytes);
            let encrypted_share =
                distribute_sharesbox.shares.get(&publickey_bytes);

            if position.is_none()
                || response.is_none()
                || blinding_response.is_none()
                || encrypted_share.is_none()
            {
                return false;
            }

            let position = *position.unwrap();
            let response = response.unwrap();
            let blinding_response = blinding_response.unwrap();
            let encrypted_share = encrypted_share.unwrap();

            // Calculate X_i = Σ_j (position^j) * C_j using EC operations
            let mut x_val = self.group.identity();
            let mut exponent = RistrettoScalar::ONE;
            for j in 0..distribute_sharesbox.commitments.len() {
                // C_j^(position^j) in EC notation = (position^j) * C_j
                let c_j_pow = self
                    .group
                    .exp(&distribute_sharesbox.commitments[j], &exponent);
                x_val = self.group.mul(&x_val, &c_j_pow);
                let pos_scalar = RistrettoScalar::from(position as u64);
                exponent = self.group.scalar_mul(&exponent, &pos_scalar);
            }

            let _ = DLEQ2::<Ristretto255Group>::verifier_update_hash(
                self.group.as_ref(),
                &commitment_gen,
                &commitment_blinding_gen,
                publickey.primary(),
                publickey.secondary(),
                &x_val,
                encrypted_share,
                response,
                blinding_response,
                &distribute_sharesbox.challenge,
                &mut challenge_hasher,
            );
        }

        // Calculate final challenge and check if it matches
        let challenge_hash = challenge_hasher.finalize();
        let computed_challenge = self.group.hash_to_scalar(&challenge_hash);

        computed_challenge == distribute_sharesbox.challenge
    }

    /// Reconstruct secret from shares (Ristretto255Group implementation).
    ///
    /// # Parameters
    /// - `share_boxes`: Array of share boxes from participants
    /// - `distribute_share_box`: The distribution shares box from the dealer
    ///
    /// # Returns
    /// `Some(secret)` if reconstruction succeeds, `None` otherwise
    pub fn reconstruct(
        &self,
        share_boxes: &[ShareBox<Ristretto255Group>],
        distribute_share_box: &DistributionSharesBox<Ristretto255Group>,
    ) -> Option<BigInt> {
        use rayon::prelude::*;

        if share_boxes.len() < distribute_share_box.commitments.len() {
            return None;
        }

        // Build position -> share map
        let mut shares: HashMap<i64, RistrettoPoint> = HashMap::new();
        for share_box in share_boxes.iter() {
            let publickey_bytes =
                share_box.publickey.to_bytes(self.group.as_ref());
            let position =
                distribute_share_box.positions.get(&publickey_bytes)?;
            shares.insert(*position, share_box.share);
        }

        // Compute Lagrange factors and G^s = Σ S_i^λ_i
        let secret = self.group.identity();
        let values: Vec<i64> = shares.keys().copied().collect();
        let shares_vec: Vec<(i64, RistrettoPoint)> =
            shares.into_iter().collect();
        let shares_slice = shares_vec.as_slice();

        let factors: Vec<RistrettoPoint> = shares_slice
            .par_iter()
            .map(|(position, share)| {
                self.compute_lagrange_factor_ristretto(
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
        // Convert hash to BigUint and reduce modulo group order
        let hash_biguint = BigUint::from_bytes_be(&secret_hash[..]);
        let curve_order_bigint = BigUint::from_bytes_be(
            &self.group.order_as_bigint().to_bytes_be().1,
        );
        let hash_reduced = hash_biguint % curve_order_bigint;
        let decrypted_secret =
            hash_reduced ^ distribute_share_box.U.to_biguint().unwrap();

        Some(decrypted_secret.to_bigint().unwrap())
    }

    /// Compute Lagrange factor for secret reconstruction (Ristretto255Group implementation).
    ///
    /// This uses pure Scalar arithmetic to avoid BigInt/Scalar conversion issues.
    fn compute_lagrange_factor_ristretto(
        &self,
        position: i64,
        share: &RistrettoPoint,
        values: &[i64],
    ) -> RistrettoPoint {
        // λ_i = ∏_{j≠i} j / (j - i)
        let mut lambda_num = RistrettoScalar::ONE;
        let mut lambda_den = RistrettoScalar::ONE;
        let mut sign = 1i64;

        for &j in values {
            if j == position {
                continue;
            }
            lambda_num *= RistrettoScalar::from(j as u64);
            let diff = j - position;
            if diff < 0 {
                sign *= -1;
                lambda_den *= RistrettoScalar::from((-diff) as u64);
            } else {
                lambda_den *= RistrettoScalar::from(diff as u64);
            }
        }

        // λ = numerator * denominator^(-1)
        // Note: curve25519-dalek Scalar::invert() returns CtOption, convert to Option
        let lambda_den_inv = Option::from(lambda_den.invert());
        let lambda = match lambda_den_inv {
            Some(inv) => lambda_num * inv,
            None => {
                // This should never happen with valid Lagrange coefficients
                RistrettoScalar::ZERO
            }
        };

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
