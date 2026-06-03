// Copyright 2020-2026 MathxH Chen.
//
// Code is licensed under MIT Apache Dual License

#![allow(non_snake_case)]

use num_bigint::BigInt;
use num_traits::identities::Zero;
use std::collections::HashMap;
use std::vec::Vec;

use crate::group::Group;

// ============================================================================
// Generic ShareBox Types for 1.0.0 API
// ============================================================================

/// Registered public key for the information-theoretic PVSS scheme.
///
/// The improved construction requires a pair of public keys generated from the
/// same private key over two independent bases: `primary = G^x` and
/// `secondary = H^x`.
///
/// Paper reference: Section 5.1, Initialization.  The paper denotes these as
/// `y_i1 = G^x_i` and `y_i2 = H^x_i`.  The public API still exposes one
/// `publickey` value, but internally it must carry both elements so that the
/// dealer proof can bind `Y_i` to both polynomial evaluations.
#[derive(Debug, Clone)]
pub struct PublicKey<G: Group> {
    primary: G::Element,
    secondary: G::Element,
}

impl<G: Group> PartialEq for PublicKey<G> {
    fn eq(&self, other: &Self) -> bool {
        self.primary == other.primary && self.secondary == other.secondary
    }
}

impl<G: Group> Eq for PublicKey<G> {}

impl<G: Group> Default for PublicKey<G>
where
    G::Element: Default,
{
    fn default() -> Self {
        PublicKey {
            primary: Default::default(),
            secondary: Default::default(),
        }
    }
}

impl<G: Group> PublicKey<G> {
    pub fn new(primary: G::Element, secondary: G::Element) -> Self {
        PublicKey { primary, secondary }
    }

    pub fn primary(&self) -> &G::Element {
        &self.primary
    }

    pub(crate) fn secondary(&self) -> &G::Element {
        &self.secondary
    }

    pub fn combined(&self, group: &G) -> G::Element {
        // Paper reference: Section 5.1, Reconstruction.  Participants prove a
        // decryption relation against `y_i = y_i1 y_i2` and base `GH`; in
        // additive EC groups, `mul` means point addition.
        group.mul(&self.primary, &self.secondary)
    }

    pub fn to_bytes(&self, group: &G) -> Vec<u8> {
        let primary = group.element_to_bytes(&self.primary);
        let secondary = group.element_to_bytes(&self.secondary);
        let mut bytes =
            Vec::with_capacity(16 + primary.len() + secondary.len());
        bytes.extend_from_slice(&(primary.len() as u64).to_be_bytes());
        bytes.extend_from_slice(&primary);
        bytes.extend_from_slice(&(secondary.len() as u64).to_be_bytes());
        bytes.extend_from_slice(&secondary);
        bytes
    }
}

/// Generic share box for any cryptographic group.
///
/// Used to store a decrypted share along with its DLEQ proof.
#[derive(Debug, Clone)]
pub struct GenericShareBox<G: Group> {
    pub publickey: PublicKey<G>,
    pub share: G::Element,
    pub challenge: G::Scalar,
    pub response: G::Scalar,
}

impl<G: Group> Default for GenericShareBox<G>
where
    G::Element: Default,
    G::Scalar: Default,
{
    fn default() -> Self {
        GenericShareBox {
            publickey: Default::default(),
            share: Default::default(),
            challenge: Default::default(),
            response: Default::default(),
        }
    }
}

impl<G: Group> GenericShareBox<G> {
    pub fn new() -> Self
    where
        G::Element: Default,
        G::Scalar: Default,
    {
        Self::default()
    }

    pub fn init(
        &mut self,
        publickey: PublicKey<G>,
        share: G::Element,
        challenge: G::Scalar,
        response: G::Scalar,
    ) {
        self.publickey = publickey;
        self.share = share;
        self.challenge = challenge;
        self.response = response;
    }
}

/// Generic distribution shares box for any cryptographic group.
///
/// Used to store all encrypted shares with commitments and proofs.
///
/// Note: Uses HashMap with Vec<u8> keys (serialized elements) instead of
/// G::Element directly, to support group elements that don't implement Hash
/// (e.g., EC points like AffinePoint).
#[derive(Debug, Clone)]
pub struct GenericDistributionSharesBox<G: Group> {
    pub commitments: Vec<G::Element>,
    /// Maps serialized public-key-pair bytes to position
    pub positions: HashMap<Vec<u8>, i64>,
    /// Maps serialized public-key-pair bytes to encrypted share
    pub shares: HashMap<Vec<u8>, G::Element>,
    pub publickeys: Vec<PublicKey<G>>,
    pub challenge: G::Scalar,
    /// Maps serialized public-key-pair bytes to the first response
    pub responses: HashMap<Vec<u8>, G::Scalar>,
    /// Maps serialized public-key-pair bytes to the second response
    pub blinding_responses: HashMap<Vec<u8>, G::Scalar>,
    pub U: BigInt, // Secret encoded as BigInt for cross-group compatibility
}

impl<G: Group> Default for GenericDistributionSharesBox<G>
where
    G::Scalar: Default,
{
    fn default() -> Self {
        GenericDistributionSharesBox {
            commitments: Vec::new(),
            positions: HashMap::new(),
            shares: HashMap::new(),
            publickeys: Vec::new(),
            challenge: Default::default(),
            responses: HashMap::new(),
            blinding_responses: HashMap::new(),
            U: BigInt::zero(),
        }
    }
}

impl<G: Group> GenericDistributionSharesBox<G> {
    pub fn new() -> Self
    where
        G::Scalar: Default,
    {
        Self::default()
    }

    /// Initialize the distribution shares box.
    ///
    /// Note: positions, shares, and responses should use Vec<u8> keys
    /// (serialized public-key pairs).
    #[allow(clippy::too_many_arguments)]
    pub fn init(
        &mut self,
        commitments: &[G::Element],
        positions: HashMap<Vec<u8>, i64>,
        shares: HashMap<Vec<u8>, G::Element>,
        publickeys: &[PublicKey<G>],
        challenge: &G::Scalar,
        responses: HashMap<Vec<u8>, G::Scalar>,
        blinding_responses: HashMap<Vec<u8>, G::Scalar>,
        U: &BigInt,
    ) {
        self.commitments = commitments.to_vec();
        self.positions = positions;
        self.shares = shares;
        self.publickeys = publickeys.to_vec();
        self.challenge = challenge.clone();
        self.responses = responses;
        self.blinding_responses = blinding_responses;
        self.U = U.clone();
    }
}

// ============================================================================
// Type Aliases (Primary API)
// ============================================================================

/// Type alias for the generic ShareBox - primary API for 1.0.0
/// Replaces the old non-generic ShareBox struct
pub type ShareBox<G> = GenericShareBox<G>;

/// Type alias for the generic DistributionSharesBox - primary API for 1.0.0
/// Replaces the old non-generic DistributionSharesBox struct
pub type DistributionSharesBox<G> = GenericDistributionSharesBox<G>;
