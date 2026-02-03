// Copyright 2020-2024 MathxH Chen.
//
// Code is licensed under GPLv3.0 License.

#![allow(non_snake_case)]

use num_bigint::BigInt;
use num_traits::identities::Zero;
use std::collections::BTreeMap;
use std::vec::Vec;

use crate::group::Group;

// ============================================================================
// Legacy (Non-Generic) ShareBox Types for Backward Compatibility
// ============================================================================

#[derive(Debug, Clone, Default)]
pub struct ShareBox {
    pub publickey: BigInt,
    pub share: BigInt,
    pub challenge: BigInt,
    pub response: BigInt,
}

impl ShareBox {
    pub fn new() -> Self {
        ShareBox {
            publickey: BigInt::zero(),
            share: BigInt::zero(),
            challenge: BigInt::zero(),
            response: BigInt::zero(),
        }
    }

    pub fn init(
        &mut self,
        publickey: BigInt,
        share: BigInt,
        challenge: BigInt,
        response: BigInt,
    ) {
        self.publickey = publickey;
        self.share = share;
        self.challenge = challenge;
        self.response = response;
    }
}

/// the  dealer  wishes to distribute a secret among participants P1,...,Pn.
/// The dealer picks a randompolynomialp of degree at most t−1 with coefficients in Z_q
#[derive(Debug, Clone, Default)]
pub struct DistributionSharesBox {
    pub commitments: Vec<BigInt>,
    pub positions: BTreeMap<BigInt, i64>,
    pub shares: BTreeMap<BigInt, BigInt>,
    pub publickeys: Vec<BigInt>,
    pub challenge: BigInt,
    pub responses: BTreeMap<BigInt, BigInt>,
    pub U: BigInt,
}

impl DistributionSharesBox {
    pub fn new() -> Self {
        DistributionSharesBox {
            commitments: Vec::new(),
            positions: BTreeMap::new(),
            shares: BTreeMap::new(),
            publickeys: Vec::new(),
            challenge: BigInt::zero(),
            responses: BTreeMap::new(),
            U: BigInt::zero(),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn init(
        &mut self,
        commitments: &[BigInt],
        positions: BTreeMap<BigInt, i64>,
        shares: BTreeMap<BigInt, BigInt>,
        publickeys: &[BigInt],
        challenge: &BigInt,
        responses: BTreeMap<BigInt, BigInt>,
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
#[derive(Debug, Clone)]
pub struct GenericDistributionSharesBox<G: Group> {
    pub commitments: Vec<G::Element>,
    pub positions: BTreeMap<G::Element, i64>,
    pub shares: BTreeMap<G::Element, G::Element>,
    pub publickeys: Vec<G::Element>,
    pub challenge: G::Scalar,
    pub responses: BTreeMap<G::Element, G::Scalar>,
    pub U: BigInt, // Secret encoded as BigInt for cross-group compatibility
}

impl<G: Group> Default for GenericDistributionSharesBox<G>
where
    G::Scalar: Default,
{
    fn default() -> Self {
        GenericDistributionSharesBox {
            commitments: Vec::new(),
            positions: BTreeMap::new(),
            shares: BTreeMap::new(),
            publickeys: Vec::new(),
            challenge: Default::default(),
            responses: BTreeMap::new(),
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

    #[allow(clippy::too_many_arguments)]
    pub fn init(
        &mut self,
        commitments: &[G::Element],
        positions: BTreeMap<G::Element, i64>,
        shares: BTreeMap<G::Element, G::Element>,
        publickeys: &[G::Element],
        challenge: &G::Scalar,
        responses: BTreeMap<G::Element, G::Scalar>,
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
