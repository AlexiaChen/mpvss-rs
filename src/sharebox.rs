// Copyright 2020-2024 MathxH Chen.
//
// Code is licensed under GPLv3.0 License.

#![allow(non_snake_case)]

use num_bigint::BigInt;
use num_traits::identities::Zero;
use std::collections::HashMap;
use std::vec::Vec;

use crate::group::Group;

// ============================================================================
// Generic ShareBox Types for 1.0.0 API
// ============================================================================

/// Generic share box for any cryptographic group.
///
/// Used to store a decrypted share along with its DLEQ proof.
#[derive(Debug, Clone)]
pub struct GenericShareBox<G: Group> {
    pub publickey: G::Element,
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
        publickey: G::Element,
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
    /// Maps serialized element bytes to position
    pub positions: HashMap<Vec<u8>, i64>,
    /// Maps serialized element bytes to encrypted share
    pub shares: HashMap<Vec<u8>, G::Element>,
    pub publickeys: Vec<G::Element>,
    pub challenge: G::Scalar,
    /// Maps serialized element bytes to response
    pub responses: HashMap<Vec<u8>, G::Scalar>,
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
    /// Note: positions, shares, and responses should use Vec<u8> keys (serialized elements).
    #[allow(clippy::too_many_arguments)]
    pub fn init(
        &mut self,
        commitments: &[G::Element],
        positions: HashMap<Vec<u8>, i64>,
        shares: HashMap<Vec<u8>, G::Element>,
        publickeys: &[G::Element],
        challenge: &G::Scalar,
        responses: HashMap<Vec<u8>, G::Scalar>,
        U: &BigInt,
    ) {
        self.commitments = commitments.to_vec();
        self.positions = positions;
        self.shares = shares;
        self.publickeys = publickeys.to_vec();
        self.challenge = challenge.clone();
        self.responses = responses;
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
