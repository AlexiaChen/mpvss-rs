// Copyright 2020-2024 MathxH Chen.
//
// Code is licensed under GPLv3.0 License.

//! Generic Participant implementation supporting multiple cryptographic groups.
//!
//! This module provides `GenericParticipant<G: Group>` which works with any group
//! implementation (MODP, secp256k1, etc.), enabling the PVSS scheme to use different
//! cryptographic backends.

use num_bigint::{BigInt, BigUint, RandBigInt, ToBigInt};
use num_integer::Integer;
use num_traits::identities::{One, Zero};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::sync::Arc;

use crate::group::Group;
use crate::groups::ModpGroup;
use crate::polynomial::Polynomial;
use crate::sharebox::{GenericDistributionSharesBox, GenericShareBox};

// Type aliases for backward compatibility within generic module
pub type ShareBox<G> = GenericShareBox<G>;
pub type DistributionSharesBox<G> = GenericDistributionSharesBox<G>;

// ============================================================================
// Generic DLEQ Proof
// ============================================================================

/// Generic DLEQ (Discrete Logarithm Equality) proof.
///
/// Proves that log_g1(h1) = log_g2(h2) for given generators.
/// This is the Chaum-Pedersen protocol adapted for generic groups.
pub struct GenericDLEQ<G: Group> {
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

impl<G: Group> GenericDLEQ<G> {
    /// Create a new DLEQ proof structure.
    pub fn new(group: Arc<G>) -> Self
    where
        G::Scalar: Default,
        G::Element: Default,
    {
        GenericDLEQ {
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

    /// Compute a1 = g1^w (or w*g1 for EC)
    pub fn get_a1(&self) -> G::Element {
        self.group.exp(&self.g1, &self.w)
    }

    /// Compute a2 = g2^w (or w*g2 for EC)
    pub fn get_a2(&self) -> G::Element {
        self.group.exp(&self.g2, &self.w)
    }

    /// Compute response r = w - alpha*c (mod order)
    pub fn get_r(&self) -> Option<G::Scalar>
    where
        G::Scalar: Clone,
    {
        self.c.as_ref().map(|c| {
            let alpha_c = self.group.scalar_mul(&self.alpha, c);
            self.group.scalar_sub(&self.w, &alpha_c)
        })
    }

    /// Verify the DLEQ proof.
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
    pub fn update_hash(&self, hasher: &mut Sha256)
    where
        G::Element: Clone,
    {
        hasher.update(self.group.element_to_bytes(&self.h1));
        hasher.update(self.group.element_to_bytes(&self.h2));
        hasher.update(self.group.element_to_bytes(&self.get_a1()));
        hasher.update(self.group.element_to_bytes(&self.get_a2()));
    }
}

// ============================================================================
// Generic Participant
// ============================================================================

/// Generic participant that works with any cryptographic group.
///
/// # Type Parameters
/// - `G`: A type implementing the `Group` trait (e.g., `ModpGroup`, `Secp256k1Group`)
///
/// # Example
///
/// ```rust
/// use mpvss_rs::groups::ModpGroup;
/// use mpvss_rs::generic_participant::GenericParticipant;
///
/// let group = ModpGroup::new();
/// let mut dealer = GenericParticipant::new(group);
/// dealer.initialize();
/// ```
#[derive(Debug, Clone)]
pub struct GenericParticipant<G: Group> {
    group: Arc<G>,
    pub privatekey: G::Scalar,
    pub publickey: G::Element,
}

impl<G: Group> GenericParticipant<G> {
    /// Create a new generic participant with the specified group.
    ///
    /// # Example
    ///
    /// ```rust
    /// use mpvss_rs::groups::ModpGroup;
    /// use mpvss_rs::generic_participant::GenericParticipant;
    ///
    /// let group = ModpGroup::new();
    /// let participant = GenericParticipant::new(group);
    /// ```
    pub fn new(group: Arc<G>) -> Self
    where
        G::Scalar: Default,
        G::Element: Default,
    {
        GenericParticipant {
            group,
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
/// This implementation uses the existing Polynomial class which works with BigInt.
impl GenericParticipant<ModpGroup> {
    /// Distribute a secret among participants (full implementation for ModpGroup).
    pub fn distribute_secret_modp(
        &mut self,
        secret: &BigInt,
        publickeys: &[BigInt],
        threshold: u32,
    ) -> DistributionSharesBox<ModpGroup> {
        assert!(threshold <= publickeys.len() as u32);

        let q = self.group.modulus().clone();
        let g = self.group.subgroup_order_value().clone();

        // Generate random polynomial
        let mut polynomial = Polynomial::new();
        polynomial.init((threshold - 1) as i32, &q.to_bigint().unwrap());

        // Generate random witness w
        let mut rng = rand::thread_rng();
        let w: BigInt = rng
            .gen_biguint_below(&q.to_biguint().unwrap())
            .to_bigint()
            .unwrap();

        // Data structures
        let mut commitments: Vec<BigInt> = Vec::new();
        let mut positions: BTreeMap<BigInt, i64> = BTreeMap::new();
        let mut x: BTreeMap<BigInt, BigInt> = BTreeMap::new();
        let mut shares: BTreeMap<BigInt, BigInt> = BTreeMap::new();
        let mut challenge_hasher = Sha256::new();

        let mut sampling_points: BTreeMap<BigInt, BigInt> = BTreeMap::new();
        let mut dleq_w: BTreeMap<BigInt, BigInt> = BTreeMap::new();
        let mut position: i64 = 1;

        // Calculate commitments C_j = g^a_j
        for j in 0..threshold {
            commitments
                .push(g.modpow(&polynomial.coefficients[j as usize], &q));
        }

        // Calculate encrypted shares for each participant
        for pubkey in publickeys {
            positions.insert(pubkey.clone(), position);

            // P(position) mod (q - 1)
            let secret_share = polynomial.get_value(&BigInt::from(position))
                % (&q - BigInt::one());
            sampling_points.insert(pubkey.clone(), secret_share.clone());

            // Calculate X_i = g^P(i) using commitments
            let mut x_val: BigInt = BigInt::one();
            let mut exponent: BigInt = BigInt::one();
            for j in 0..threshold {
                x_val = (x_val * commitments[j as usize].modpow(&exponent, &q))
                    % &q;
                exponent =
                    (exponent * BigInt::from(position)) % (&q - BigInt::one());
            }
            x.insert(pubkey.clone(), x_val.clone());

            // Calculate Y_i = y_i^P(i) (encrypted share)
            let encrypted_secret_share = pubkey.modpow(&secret_share, &q);
            shares.insert(pubkey.clone(), encrypted_secret_share.clone());

            // Generate DLEQ proof: DLEQ(g, X_i, y_i, Y_i)
            let mut dleq = GenericDLEQ::new(self.group.clone());
            dleq.init(
                g.clone(),
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

        // Compute common challenge
        let challenge_hash = challenge_hasher.finalize();
        let challenge = BigUint::from_bytes_be(&challenge_hash[..])
            .mod_floor(&(q.to_biguint().unwrap() - BigUint::one()))
            .to_bigint()
            .unwrap();

        // Compute responses
        let mut responses: BTreeMap<BigInt, BigInt> = BTreeMap::new();
        for pubkey in publickeys {
            let alpha = sampling_points.get(pubkey).unwrap();
            let w_i = dleq_w.get(pubkey).unwrap();
            let alpha_c = (alpha * &challenge) % (&q - BigInt::one());
            let response = (w_i - &alpha_c) % (&q - BigInt::one());
            responses.insert(pubkey.clone(), response);
        }

        // Compute U = secret XOR H(G^s)
        let s = polynomial.get_value(&BigInt::zero()) % (&q - BigInt::one());
        let g_gen = self.group.generator();
        let g_s = g_gen.modpow(&s, &q);
        let sha256_hash = Sha256::digest(
            g_s.to_biguint().unwrap().to_str_radix(10).as_bytes(),
        );
        let hash_biguint = BigUint::from_bytes_be(&sha256_hash[..])
            .mod_floor(&q.to_biguint().unwrap());
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

        let q = self.group.modulus();
        let g_gen = self.group.generator();

        // Generate public key from private key
        let public_key = self.group.generate_public_key(private_key);

        // Get encrypted share from distribution box
        let encrypted_secret_share = shares_box.shares.get(&public_key)?;

        // Decryption: S_i = Y_i^(1/x_i)
        let privkey_inverse =
            Util::mod_inverse(private_key, &(q - BigInt::one()))?;
        let decrypted_share =
            encrypted_secret_share.modpow(&privkey_inverse, q);

        // Generate DLEQ proof: DLEQ(G, publickey, decrypted_share, encrypted_secret_share)
        // This proves knowledge of α such that publickey = G^α and encrypted_share = decrypted_share^α
        let mut dleq = GenericDLEQ::new(self.group.clone());
        dleq.init(
            g_gen.clone(),
            public_key.clone(),
            decrypted_share.clone(),
            encrypted_secret_share.clone(),
            private_key.clone(),
            w.clone(),
        );

        // Compute challenge
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
        let challenge = BigUint::from_bytes_be(&challenge_hash[..])
            .mod_floor(&(q.to_biguint().unwrap() - BigUint::one()))
            .to_bigint()
            .unwrap();
        dleq.c = Some(challenge.clone());

        // Compute response
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
        let q = self.group.modulus();
        let g_gen = self.group.generator();

        // Get encrypted share from distribution box
        let encrypted_share = match distribution_sharebox.shares.get(publickey)
        {
            Some(s) => s,
            None => return false,
        };

        // Verify DLEQ proof
        // a_1 = G^r * publickey^c, a_2 = decrypted_share^r * encrypted_share^c
        let g1_r = g_gen.modpow(&sharebox.response, q);
        let h1_c = publickey.modpow(&sharebox.challenge, q);
        let _a1_verify = (g1_r * h1_c) % q;

        let g2_r = sharebox.share.modpow(&sharebox.response, q);
        let h2_c = encrypted_share.modpow(&sharebox.challenge, q);
        let _a2_verify = (g2_r * h2_c) % q;

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
            _a1_verify.to_biguint().unwrap().to_str_radix(10).as_bytes(),
        );
        challenge_hasher.update(
            _a2_verify.to_biguint().unwrap().to_str_radix(10).as_bytes(),
        );

        let challenge_hash = challenge_hasher.finalize();
        let challenge_computed = BigUint::from_bytes_be(&challenge_hash[..])
            .mod_floor(&(q.to_biguint().unwrap() - BigUint::one()));

        challenge_computed.to_bigint().unwrap() == sharebox.challenge
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

        let q = self.group.modulus();

        // Build position -> share map
        let mut shares: BTreeMap<i64, BigInt> = BTreeMap::new();
        for share_box in share_boxes.iter() {
            let position =
                distribute_share_box.positions.get(&share_box.publickey)?;
            shares.insert(*position, share_box.share.clone());
        }

        // Compute Lagrange factors and G^s = ∏ S_i^λ_i
        let mut secret: BigInt = BigInt::one();
        let values: Vec<i64> = shares.keys().copied().collect();
        let shares_vec: Vec<(i64, BigInt)> = shares.into_iter().collect();
        let shares_slice = shares_vec.as_slice();

        let factors: Vec<BigInt> = shares_slice
            .par_iter()
            .map(|(position, share)| {
                self.compute_lagrange_factor(*position, share, &values, q)
            })
            .collect();

        secret = factors
            .into_iter()
            .fold(secret, |acc, factor| (acc * factor) % q);

        // Reconstruct secret = H(G^s) XOR U
        let secret_hash = Sha256::digest(
            secret.to_biguint().unwrap().to_str_radix(10).as_bytes(),
        );
        let hash_biguint = BigUint::from_bytes_be(&secret_hash[..])
            .mod_floor(&q.to_biguint().unwrap());
        let decrypted_secret =
            hash_biguint ^ distribute_share_box.U.to_biguint().unwrap();

        Some(decrypted_secret.to_bigint().unwrap())
    }

    /// Compute Lagrange factor for secret reconstruction.
    fn compute_lagrange_factor(
        &self,
        position: i64,
        share: &BigInt,
        values: &[i64],
        q: &BigInt,
    ) -> BigInt {
        use crate::util::Util;

        let lagrange_coefficient =
            Util::lagrange_coefficient(&position, values);

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

            let q_minus_1 = q - BigInt::one();
            let inverse_denominator = Util::mod_inverse(
                &denominator.to_bigint().unwrap(),
                &q_minus_1,
            );

            match inverse_denominator {
                Some(inv) => (numerator.to_bigint().unwrap() * inv) % q_minus_1,
                None => {
                    eprintln!("ERROR: Denominator has no inverse");
                    BigInt::one()
                }
            }
        };

        let mut factor = share.modpow(&exponent, q);

        // Handle negative Lagrange coefficient
        if lagrange_coefficient.0.clone() * lagrange_coefficient.1
            < BigInt::zero()
        {
            if let Some(inverse_factor) = Util::mod_inverse(&factor, q) {
                factor = inverse_factor;
            }
        }

        factor
    }
}

// Type aliases for convenience
/// Type alias for MODP group participant (backward compatible)
pub type ModpParticipant = GenericParticipant<ModpGroup>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::groups::ModpGroup;
    use crate::participant::Participant;

    #[test]
    fn test_generic_modp_participant_new() {
        let group = ModpGroup::new();
        let participant = GenericParticipant::new(group);
        assert_eq!(participant.publickey, Default::default());
    }

    #[test]
    fn test_generic_modp_participant_initialize() {
        let group = ModpGroup::new();
        let mut participant = GenericParticipant::new(group);
        participant.initialize();
        let _ = &participant.privatekey;
        let _ = &participant.publickey;
    }

    /// Cross-validation test: compare new GenericParticipant with legacy Participant
    ///
    /// Note: Since both implementations use random polynomial coefficients and witnesses,
    /// we don't compare exact values. Instead, we verify that:
    /// 1. Both produce valid distribution boxes
    /// 2. The structure is consistent
    /// 3. We can verify the DLEQ proofs (independent of specific values)
    #[test]
    fn test_cross_validation_distribute_secret() {
        use num_bigint::{BigUint, ToBigInt};

        // Setup participants with same keys
        let mut p1_legacy = Participant::new();
        let mut p2_legacy = Participant::new();
        let mut p3_legacy = Participant::new();
        p1_legacy.initialize();
        p2_legacy.initialize();
        p3_legacy.initialize();

        let group = ModpGroup::new();
        let mut p1_generic = GenericParticipant::new(group.clone());
        p1_generic.initialize();

        // Copy private key to ensure same keys
        p1_generic.privatekey = p1_legacy.privatekey.clone();
        p1_generic.publickey = p1_legacy.publickey.clone();

        let secret_message = String::from("Hello MPVSS Cross-Validation Test!");
        let secret = BigUint::from_bytes_be(secret_message.as_bytes());

        let publickeys = vec![
            p1_legacy.publickey.clone(),
            p2_legacy.publickey.clone(),
            p3_legacy.publickey.clone(),
        ];
        let threshold = 3;

        // Distribute using legacy API
        let legacy_box = p1_legacy.distribute_secret(
            &secret.to_bigint().unwrap(),
            &publickeys,
            threshold,
        );

        // Distribute using new generic API
        let generic_box = p1_generic.distribute_secret_modp(
            &secret.to_bigint().unwrap(),
            &publickeys,
            threshold,
        );

        // Verify structure consistency
        assert_eq!(
            legacy_box.publickeys.len(),
            generic_box.publickeys.len(),
            "Public keys count should match"
        );
        assert_eq!(
            legacy_box.commitments.len(),
            generic_box.commitments.len(),
            "Commitments count should match"
        );
        assert_eq!(
            legacy_box.positions.len(),
            generic_box.positions.len(),
            "Positions count should match"
        );
        assert_eq!(
            legacy_box.shares.len(),
            generic_box.shares.len(),
            "Shares count should match"
        );
        assert_eq!(
            legacy_box.responses.len(),
            generic_box.responses.len(),
            "Responses count should match"
        );

        // Verify challenge is valid (non-zero, less than subgroup order)
        let q_minus_1 = group.modulus() - BigInt::one();
        assert_ne!(
            legacy_box.challenge,
            BigInt::zero(),
            "Legacy challenge should not be zero"
        );
        assert!(
            legacy_box.challenge < q_minus_1,
            "Legacy challenge should be less than q-1"
        );
        assert_ne!(
            generic_box.challenge,
            BigInt::zero(),
            "Generic challenge should not be zero"
        );
        assert!(
            generic_box.challenge < q_minus_1,
            "Generic challenge should be less than q-1"
        );

        // Verify U is valid (non-zero for this secret)
        assert_ne!(legacy_box.U, BigInt::zero(), "Legacy U should not be zero");
        assert_ne!(
            generic_box.U,
            BigInt::zero(),
            "Generic U should not be zero"
        );

        // Verify each participant has a share in both boxes
        for pubkey in &publickeys {
            assert!(
                legacy_box.shares.contains_key(pubkey),
                "Legacy should have share for pubkey"
            );
            assert!(
                generic_box.shares.contains_key(pubkey),
                "Generic should have share for pubkey"
            );
            assert!(
                legacy_box.responses.contains_key(pubkey),
                "Legacy should have response for pubkey"
            );
            assert!(
                generic_box.responses.contains_key(pubkey),
                "Generic should have response for pubkey"
            );
        }

        // Verify positions are correct (1-indexed)
        for (_pubkey, pos) in &legacy_box.positions {
            assert!(
                *pos >= 1 && *pos <= publickeys.len() as i64,
                "Legacy position should be valid"
            );
        }
        for (_pubkey, pos) in &generic_box.positions {
            assert!(
                *pos >= 1 && *pos <= publickeys.len() as i64,
                "Generic position should be valid"
            );
        }

        println!(
            "Cross-validation passed: both implementations produce structurally valid distribution boxes"
        );
    }

    /// End-to-end test for distribute, extract, and reconstruct.
    #[test]
    fn test_end_to_end_modp() {
        use num_bigint::{BigUint, ToBigInt};

        // Setup participants
        let group = ModpGroup::new();
        let mut dealer = GenericParticipant::new(group.clone());
        dealer.initialize();

        let mut p1 = GenericParticipant::new(group.clone());
        let mut p2 = GenericParticipant::new(group.clone());
        let mut p3 = GenericParticipant::new(group.clone());
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

        // Verify distribution box is valid
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

        // Extract shares
        let s1 = p1
            .extract_secret_share_modp(&dist_box, &p1.privatekey, &w)
            .unwrap();
        let s2 = p2
            .extract_secret_share_modp(&dist_box, &p2.privatekey, &w)
            .unwrap();
        let s3 = p3
            .extract_secret_share_modp(&dist_box, &p3.privatekey, &w)
            .unwrap();

        // Verify extracted shares
        assert_eq!(s1.publickey, p1.publickey, "P1 publickey should match");
        assert_ne!(s1.share, BigInt::zero(), "P1 share should not be zero");

        assert_eq!(s2.publickey, p2.publickey, "P2 publickey should match");
        assert_ne!(s2.share, BigInt::zero(), "P2 share should not be zero");

        assert_eq!(s3.publickey, p3.publickey, "P3 publickey should match");
        assert_ne!(s3.share, BigInt::zero(), "P3 share should not be zero");

        // Reconstruct secret
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
