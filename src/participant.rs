// Copyright 2020 The MPVSS Authors.
//
// Code is licensed under AGPL License, Version 3.0.

#[warn(non_snake_case)]
use crate::mpvss::MPVSS;
use crate::polynomial::Polynomial;
use crate::sharebox::{DistributionSharesBox, ShareBox};
use num_bigint::{BigUint, ToBigUint};
use num_integer::Integer;
use num_traits::identities::{One, Zero};
use sha2::{Digest, Sha256};
use std::clone::Clone;
use std::collections::HashMap;
use std::ops::*;
use std::option::Option;

/// A participant represents one party in the secret sharing scheme. The participant can share a secret among a group of other participants and it is then called the "dealer".
/// The receiving participants that receive a part of the secret can use it to reconstruct the secret Therefore the partticipants need to collaborate and exchange their parts.
/// A participant represents as a Node in the Distributed Public NetWork
#[derive(Debug, Clone)]
pub struct Participant {
    pub mpvss: MPVSS,
    pub privatekey: BigUint,
    pub publickey: BigUint,
}

impl Participant {
    /// Create A default participant
    pub fn new() -> Self {
        return Participant {
            mpvss: MPVSS::new(),
            privatekey: BigUint::zero(),
            publickey: BigUint::zero(),
        };
    }
    /// Initializes a new participant with the default MPVSS.
    pub fn initialize(&mut self) {
        self.privatekey = self.mpvss.generate_private_key();
        self.publickey = self.mpvss.generate_public_key(&self.publickey);
    }

    /// Takes a secret as input and returns the distribution shares Box which is going to be submitted to all the participants the secret is going to be shared with.
    /// Those participants are specified by their public keys.
    /// They use the distribution bundle to verify that the shares are correct (without learning anything about the shares that are not supposed to be decrypted by them) and extract their encrypted shares.
    /// In fact, the distribution bundle can be published to everyone allowing even external parties to verify the integrity of the shares.
    ///
    /// - Parameters:
    ///   - secret: The value that is going to be shared among the other participants.
    ///   - publicKeys: Array of public keys of each participant the secret is to be shared with.
    ///   - threshold: The number of shares that is needed in order to reconstruct the secret. It must not be greater than the total number of participants.
    ///   - polynomial: The polynomial which is going to be used to produce sampling points which represent the shares. Those sampling points allow the receiving participants to reconstruct the polynomial and with it the secret. The degree of the polynomial must be `threshold`-1.
    ///   - w: An arbitrary chosen value needed for creating the proof that the shares in the distribution shares box are consistent.
    /// - Requires:
    ///   - `threshold` <= number of participants
    ///   - degree of polynomial = `threshold` - 1
    /// - Returns: The distribution shares box that is published so everyone (especially but not only the participants) can check the shares' integrity. Furthermore the participants extract their shares from it.
    pub fn distribute(
        &mut self,
        secret: BigUint,
        publickeys: Vec<BigUint>,
        threshold: u32,
        polynomial: Polynomial,
        w: BigUint,
    ) -> DistributionSharesBox {
        // Data the distribution bundle is going to be consisting of
        let mut commitments: Vec<BigUint> = Vec::new();
        let mut positions: HashMap<BigUint, i64> = HashMap::new();
        let mut X: HashMap<BigUint, BigUint> = HashMap::new();
        let mut shares: HashMap<BigUint, BigUint> = HashMap::new();
        let mut challenge = Sha256::new();

        // Temp variable
        let mut sampling_points: HashMap<BigUint, BigUint> = HashMap::new();
        let mut a: HashMap<BigUint, (BigUint, BigUint)> = HashMap::new();
        let mut dleq_w: HashMap<BigUint, BigUint> = HashMap::new();
        let mut position: i64 = 1;

        // Calculate Ploynomial Coefficients Commitments C_j = g^(a_j) under group of prime q, and  0 <= j < threshold
        for j in 0..threshold {
            commitments.push(
                self.mpvss
                    .g
                    .modpow(&polynomial.coefficients[j as usize], &self.mpvss.q),
            )
        }

        // Calculate Every Encrypted shares with every participant's public key generated from their own private key
        // Y_i = (y_i)^p(i)  X_i = g^p(i) =  C_0^(i^0) * C_1^(i^1) * C_2^(i^2) * ... * C_j^(i^j)  and 1 <= i <= n  0 <= j <= threshhold - 1
        // n is participant current total number
        // p(i) is secret share without encrypt on the ploynomial of the degree t - 1
        // y_i is participant public key
        // Y_i is encrypted secret share
        for pubkey in publickeys {
            positions.insert(pubkey.clone(), position);
            // calc P(position % (q - 1)), from P(1) to P(n), actually is from share 1 to share n
            let secret_share = polynomial.get_value(
                BigUint::from(position as u64)
                    .mod_floor(&(self.mpvss.q.clone() - 1.to_biguint().unwrap())),
            );
            sampling_points.insert(pubkey.clone(), secret_share.clone());

            // Calc X_i
            let mut x: BigUint = BigUint::one();
            let mut exponent: BigUint = BigUint::one();
            for j in 0..=threshold - 1 {
                x = x * commitments[j as usize].modpow(&exponent, &self.mpvss.q);
                exponent = BigUint::from(position as u64).modpow(
                    &j.to_biguint().unwrap(),
                    &(self.mpvss.q.clone() - BigUint::one()),
                )
            }

            X.insert(pubkey.clone(), x);

            // Calc Y_i
            let encrypted_secret_share =
                pubkey.clone().modpow(&secret_share.clone(), &self.mpvss.q);
            shares.insert(pubkey.clone(), encrypted_secret_share);
        }
        DistributionSharesBox::new()
    }

    pub fn extract_share() -> Option<ShareBox> {
        None
    }
}
