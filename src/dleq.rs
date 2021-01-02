// Copyright 2020-2021 The MPVSS Authors.
//
// Code is licensed under AGPL License, Version 3.0.

use num_bigint::{BigInt, BigUint, ToBigInt, ToBigUint};
use num_integer::Integer;
use num_primes::Generator;
use num_traits::identities::{One, Zero};
use sha2::{Digest, Sha256};
use std::option::Option;

struct Prover {}

impl Prover {
    fn send(g: &BigInt, w: &BigInt, q: &BigInt) -> BigInt {
        g.modpow(w, q)
    }

    fn response(w: &BigInt, alpha: &BigInt, c: &Option<BigInt>, q: &BigInt) -> Option<BigInt> {
        let response_r = match c {
            None => None,
            Some(c) => {
                let r: BigInt = w.to_bigint().unwrap() - (alpha * c).to_bigint().unwrap();
                let result = r.mod_floor(&(q.clone().to_bigint().unwrap() - BigInt::one()));
                Some(result)
            }
        };
        response_r
    }
}

struct Verifier {}
impl Verifier {
    fn send() -> BigInt {
        BigInt::zero()
    }
    fn check(c: &BigInt, q: &BigInt, challenge_hasher: &Sha256) -> bool {
        // Calculate challenge
        let challenge_hash = challenge_hasher.clone().finalize();
        let challenge_big_uint = BigUint::from_bytes_le(&challenge_hash[..])
            .mod_floor(&(q.clone().to_biguint().unwrap() - BigUint::one()));
        challenge_big_uint == (*c).to_biguint().unwrap()
    }

    fn update(
        g1: &BigInt,
        h1: &BigInt,
        g2: &BigInt,
        h2: &BigInt,
        response: &BigInt,
        c: &BigInt,
        q: &BigInt,
        challenge_hasher: &mut Sha256,
    ) {
        // Calc a1 a2
        let a1 = (g1.modpow(response, q) * h1.modpow(c, q)) % q;
        let a2 = (g2.modpow(response, q) * h2.modpow(c, q)) % q;
        // Update hash
        challenge_hasher.update(h1.to_biguint().unwrap().to_bytes_le());
        challenge_hasher.update(h2.to_biguint().unwrap().to_bytes_le());
        challenge_hasher.update(a1.to_biguint().unwrap().to_bytes_le());
        challenge_hasher.update(a2.to_biguint().unwrap().to_bytes_le());
    }
}

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
    pub g1: BigInt,
    pub h1: BigInt,
    pub g2: BigInt,
    pub h2: BigInt,

    pub w: BigInt,
    pub q: BigInt,
    pub alpha: BigInt,
    pub c: Option<BigInt>,
    pub a1: BigInt,
    pub a2: BigInt,
    pub r: Option<BigInt>,
}

impl DLEQ {
    /// new DLEQ instance
    pub fn new() -> Self {
        return DLEQ {
            g1: BigInt::zero(),
            h1: BigInt::zero(),
            g2: BigInt::zero(),
            h2: BigInt::zero(),
            w: BigInt::zero(),
            q: BigInt::zero(),
            alpha: BigInt::zero(),

            a1: BigInt::zero(),
            a2: BigInt::zero(),
            c: None,
            r: None,
        };
    }
    pub fn init(
        &mut self,
        g1: BigInt,
        h1: BigInt,
        g2: BigInt,
        h2: BigInt,
        length: u32,
        q: BigInt,
        alpha: BigInt,
    ) {
        let w: BigUint = Generator::new_prime(length as usize).mod_floor(&q.to_biguint().unwrap());
        self.init2(g1, h1, g2, h2, q, alpha, w.to_bigint().unwrap());
    }

    pub fn init2(
        &mut self,
        g1: BigInt,
        h1: BigInt,
        g2: BigInt,
        h2: BigInt,
        q: BigInt,
        alpha: BigInt,
        w: BigInt,
    ) {
        self.g1 = g1;
        self.h1 = h1;
        self.g2 = g2;
        self.h2 = h2;
        self.w = w;
        self.q = q;
        self.alpha = alpha;
    }

    /// get a1 value
    pub fn get_a1(&self) -> BigInt {
        Prover::send(&self.g1, &self.w, &self.q)
    }

    /// get a2 value
    pub fn get_a2(&self) -> BigInt {
        Prover::send(&self.g2, &self.w, &self.q)
    }

    /// get response r value
    pub fn get_r(&self) -> Option<BigInt> {
        Prover::response(&self.w, &self.alpha, &self.c, &self.q)
    }

    /// send a random challenge c
    pub fn get_c(&self) -> BigInt {
        Verifier::send()
    }

    /// Update challenge hash
    pub fn update_hash(&self, challenge_hasher: &mut Sha256) {
        Verifier::update(
            &self.g1,
            &self.h1,
            &self.g2,
            &self.h2,
            &self.r.clone().unwrap(),
            &self.c.clone().unwrap(),
            &self.q,
            challenge_hasher,
        )
    }
    /// check and verify
    pub fn check(&self, challenge_hasher: &Sha256) -> bool {
        Verifier::check(&self.c.clone().unwrap(), &self.q, challenge_hasher)
    }
}
