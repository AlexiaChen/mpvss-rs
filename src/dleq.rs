// Copyright 2020 The MPVSS Authors.
//
// Code is licensed under AGPL License, Version 3.0.

use num_bigint::BigUint;
use num_integer::Integer;
use num_primes::Generator;
use num_traits::identities::Zero;
use std::ops::{Mul, Sub};
use std::option::Option;

/// Chaum and Pedersen Scheme
///
/// To prove that log_g1(h1)= log_g2(h2), for generators g1,h1,g2,h2 ∈ Gq,   Gq is group of order q and q is prime
///
/// We denote this protocol by DLEQ(g1,h1,g2,h2), and it consists of the following steps, where the prover knows α(alpha) such that h1 = g1^α and h2 = g2^α:
///
/// - The prover sends a1 = g1^w and a2 = g2^w to the verifier, with w ∈ R Zq
/// - The verifier sends a random challenge c ∈ R Zq to the prover.
/// - The prover responds with r = w − αc (mod q).
/// - The verifier checks that a1 = (g1^r) * (h1^c) and a2 = (g2^r) * (h2^c).
#[derive(Debug, Clone)]
pub struct DLEQ {
    pub g1: BigUint,
    pub h1: BigUint,
    pub g2: BigUint,
    pub h2: BigUint,

    pub w: BigUint,
    pub q: BigUint,
    pub alpha: BigUint,
    pub c: Option<BigUint>,
    pub a1: BigUint,
    pub a2: BigUint,
    pub r: Option<BigUint>,
}

impl DLEQ {
    /// new DLEQ instance
    pub fn new(
        g1: BigUint,
        h1: BigUint,
        g2: BigUint,
        h2: BigUint,
        length: i32,
        q: BigUint,
        alpha: BigUint,
    ) -> Self {
        let w: BigUint = Generator::new_prime(length as usize).mod_floor(&q);
        return DLEQ {
            g1: g1,
            h1: h1,
            g2: g2,
            h2: h2,
            w: w,
            q: q,
            alpha: alpha,

            a1: BigUint::zero(),
            a2: BigUint::zero(),
            c: None,
            r: None,
        };
    }

    /// get a1 value
    pub fn get_a1(&self) -> BigUint {
        self.g1.modpow(&self.w, &self.q)
    }

    /// get a2 value
    pub fn get_a2(&self) -> BigUint {
        self.g2.modpow(&self.w, &self.q)
    }

    /// get response value
    pub fn get_r(&self) -> Option<BigUint> {
        let response_r = match &self.c {
            None => None,
            Some(c) => Some(&self.w - &self.alpha * c),
        };
        response_r
    }
}
