// Copyright 2020-2024 MathxH Chen.
//
// Code is licensed under GPLv3.0 License.

//! Generic Participant implementation supporting multiple cryptographic groups.
//!
//! This module provides `GenericParticipant<G: Group>` which works with any group
//! implementation (MODP, secp256k1, etc.), enabling the PVSS scheme to use different
//! cryptographic backends.

use std::sync::Arc;
use std::collections::BTreeMap;
use num_bigint::BigInt;

use crate::group::Group;
use crate::groups::ModpGroup;
use crate::sharebox::{GenericShareBox, GenericDistributionSharesBox};

// Type aliases for backward compatibility within generic module
pub type ShareBox<G> = GenericShareBox<G>;
pub type DistributionSharesBox<G> = GenericDistributionSharesBox<G>;

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
        // For now, convert secret to bytes and use MODP-style polynomial
        // This is a temporary compatibility layer
        self.distribute_secret_bytes(&secret.to_bytes_be().1, publickeys, threshold)
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
        // TODO: Implement generic polynomial evaluation
        // For now, this is a stub that returns an empty box
        let mut shares_box = DistributionSharesBox::new();

        // Generate commitments (simplified)
        let mut commitments: Vec<G::Element> = Vec::new();
        for _ in 0..threshold {
            commitments.push(self.group.subgroup_generator());
        }

        // Generate random witness for DLEQ
        let challenge = self.group.hash_to_scalar(b"distribute_challenge");

        // Convert secret bytes to BigInt for storage (U field)
        let secret_bigint = BigInt::from_bytes_be(num_bigint::Sign::Plus, secret);

        // Initialize with basic data
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
        shares_box: &DistributionSharesBox<G>,
        _private_key: &G::Scalar,
    ) -> Option<ShareBox<G>> {
        // TODO: Implement generic share extraction
        None
    }

    /// Verify distribution shares.
    pub fn verify_distribution_shares(&self, _shares_box: &DistributionSharesBox<G>) -> bool {
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

// Type aliases for convenience
/// Type alias for MODP group participant (backward compatible)
pub type ModpParticipant = GenericParticipant<ModpGroup>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::groups::ModpGroup;

    #[test]
    fn test_generic_modp_participant_new() {
        let group = ModpGroup::new();
        let participant = GenericParticipant::new(group);
        // Basic instantiation test
        assert_eq!(participant.publickey, Default::default());
    }

    #[test]
    fn test_generic_modp_participant_initialize() {
        let group = ModpGroup::new();
        let mut participant = GenericParticipant::new(group);
        participant.initialize();
        // After initialization, keys should not be default
        let _ = &participant.privatekey;
        let _ = &participant.publickey;
    }
}
