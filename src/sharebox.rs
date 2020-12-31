// Copyright 2020-2021 The MPVSS Authors.
//
// Code is licensed under AGPL License, Version 3.0.

#![allow(non_snake_case)]

use num_bigint::BigUint;
use num_traits::identities::Zero;
use std::collections::HashMap;
use std::vec::Vec;

#[derive(Debug, Clone)]
pub struct ShareBox {
    pub publickey: BigUint,
    pub share: BigUint,
    pub challenge: BigUint,
    pub response: BigUint,
}

impl ShareBox {
    pub fn new() -> Self {
        return ShareBox {
            publickey: BigUint::zero(),
            share: BigUint::zero(),
            challenge: BigUint::zero(),
            response: BigUint::zero(),
        };
    }

    pub fn init(
        &mut self,
        publickey: BigUint,
        share: BigUint,
        challenge: BigUint,
        response: BigUint,
    ) {
        self.publickey = publickey;
        self.share = share;
        self.challenge = challenge;
        self.response = response;
    }
}

/// the  dealer  wishes to distribute a secret among participants P1,...,Pn.
/// The dealer picks a randompolynomialp of degree at most t−1 with coefficients in Z_q
pub struct DistributionSharesBox {
    pub commitments: Vec<BigUint>,
    pub positions: HashMap<BigUint, i64>,
    pub shares: HashMap<BigUint, BigUint>,
    pub publickeys: Vec<BigUint>,
    pub challenge: BigUint,
    pub responses: HashMap<BigUint, BigUint>,
    pub U: BigUint,
}

impl DistributionSharesBox {
    pub fn new() -> Self {
        return DistributionSharesBox {
            commitments: Vec::new(),
            positions: HashMap::new(),
            shares: HashMap::new(),
            publickeys: Vec::new(),
            challenge: BigUint::zero(),
            responses: HashMap::new(),
            U: BigUint::zero(),
        };
    }

    pub fn init(
        &mut self,
        commitments: Vec<BigUint>,
        positions: HashMap<BigUint, i64>,
        shares: HashMap<BigUint, BigUint>,
        publickeys: Vec<BigUint>,
        challenge: BigUint,
        responses: HashMap<BigUint, BigUint>,
        U: BigUint,
    ) {
        self.commitments = commitments;
        self.positions = positions;
        self.shares = shares;
        self.publickeys = publickeys;
        self.challenge = challenge;
        self.responses = responses;
        self.U = U;
    }
}
