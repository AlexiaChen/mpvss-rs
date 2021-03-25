// Copyright 2020-2021  MathxH Chen.
//
// Code is licensed under GPLv3.0 License.

#![allow(non_snake_case)]

use num_bigint::BigInt;
use num_traits::identities::Zero;
use std::collections::BTreeMap;
use std::vec::Vec;

#[derive(Debug, Clone, Default)]
pub struct ShareBox {
    pub publickey: BigInt,
    pub share: BigInt,
    pub challenge: BigInt,
    pub response: BigInt,
}

impl ShareBox {
    pub fn new() -> Self {
        return ShareBox {
            publickey: BigInt::zero(),
            share: BigInt::zero(),
            challenge: BigInt::zero(),
            response: BigInt::zero(),
        };
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
        return DistributionSharesBox {
            commitments: Vec::new(),
            positions: BTreeMap::new(),
            shares: BTreeMap::new(),
            publickeys: Vec::new(),
            challenge: BigInt::zero(),
            responses: BTreeMap::new(),
            U: BigInt::zero(),
        };
    }

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
