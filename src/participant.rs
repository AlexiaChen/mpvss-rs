// Copyright 2020-2021  MathxH Chen.
//
// Code is licensed under GPLv3.0 License.

#![allow(non_snake_case)]

use crate::dleq::DLEQ;
use crate::mpvss::MPVSS;
use crate::polynomial::Polynomial;
use crate::sharebox::{DistributionSharesBox, ShareBox};
use crate::util::Util;
use num_bigint::{BigInt, BigUint, RandBigInt, ToBigInt};
use num_integer::Integer;
use num_primes::Generator;
use num_traits::identities::{One, Zero};
use sha2::{Digest, Sha256};
use std::clone::Clone;
use std::collections::BTreeMap;
use std::option::Option;

/// A participant represents one party in the secret sharing scheme. The participant can share a secret among a group of other participants and it is then called the "dealer".
/// The receiving participants that receive a part of the secret can use it to reconstruct the secret Therefore the partticipants need to collaborate and exchange their parts.
/// A participant represents as a Node in the Distributed Public NetWork
#[derive(Debug, Clone, Default)]
pub struct Participant {
    mpvss: MPVSS,
    pub privatekey: BigInt,
    pub publickey: BigInt,
}

impl Participant {
    /// Create A default participant
    ///
    /// ## Example
    ///
    /// ```rust
    /// use mpvss_rs::Participant;
    /// let mut dealer = Participant::new();
    /// ```
    pub fn new() -> Self {
        Participant {
            mpvss: MPVSS::new(),
            privatekey: BigInt::zero(),
            publickey: BigInt::zero(),
        }
    }
    /// Initializes a new participant with the default MPVSS.
    ///
    /// ## Example
    ///
    /// ```rust
    /// use mpvss_rs::Participant;
    /// let mut dealer = Participant::new();
    /// dealer.initialize();
    /// ```
    pub fn initialize(&mut self) {
        self.privatekey = self.mpvss.generate_private_key();
        self.publickey = self.mpvss.generate_public_key(&self.privatekey);
    }

    fn distribute(
        &mut self,
        secret: &BigInt,
        publickeys: &[BigInt],
        threshold: u32,
        polynomial: &Polynomial,
        w: &BigInt,
    ) -> DistributionSharesBox {
        assert!(threshold <= publickeys.len() as u32);
        // Data the distribution shares box is going to be consisting of
        let mut commitments: Vec<BigInt> = Vec::new();
        let mut positions: BTreeMap<BigInt, i64> = BTreeMap::new();
        let mut X: BTreeMap<BigInt, BigInt> = BTreeMap::new();
        let mut shares: BTreeMap<BigInt, BigInt> = BTreeMap::new();
        let mut challenge_hasher = Sha256::new();

        // Temp variable
        let mut sampling_points: BTreeMap<BigInt, BigInt> = BTreeMap::new();
        let mut a: BTreeMap<BigInt, (BigInt, BigInt)> = BTreeMap::new();
        let mut dleq_w: BTreeMap<BigInt, BigInt> = BTreeMap::new();
        let mut position: i64 = 1;

        // Calculate Ploynomial Coefficients Commitments C_j = g^(a_j) under group of prime q, and  0 <= j < threshold
        for j in 0..threshold {
            commitments.push(
                self.mpvss.g.modpow(
                    &polynomial.coefficients[j as usize],
                    &self.mpvss.q,
                ),
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
            // calc P(position) % (q - 1), from P(1) to P(n), actually is from share 1 to share n
            let secret_share = polynomial.get_value(&BigInt::from(position))
                % (&self.mpvss.q - BigInt::one());
            sampling_points.insert(pubkey.clone(), secret_share.clone());

            // Calc X_i
            let mut x: BigInt = BigInt::one();
            let mut exponent: BigInt = BigInt::one();
            for j in 0..=threshold - 1 {
                x = (x * commitments[j as usize]
                    .modpow(&exponent, &self.mpvss.q))
                    % &self.mpvss.q;
                exponent = (exponent * BigInt::from(position))
                    % (&self.mpvss.q - BigInt::one());
            }

            X.insert(pubkey.clone(), x.clone());

            // Calc Y_i
            let encrypted_secret_share =
                pubkey.modpow(&secret_share, &self.mpvss.q);
            shares.insert(pubkey.clone(), encrypted_secret_share.clone());

            // DLEQ(g1,h1,g2,h2) => DLEQ(g,X_i,y_i,Y_i) => DLEQ(g,commintment_with_secret_share,pubkey,enrypted_secret_share_from_pubkey)
            // Prove That  g^alpha = commintment_with_secret_share and pubkey^alpha = encrypted_secret_share_from_pubkey has same alpha value
            let mut dleq = DLEQ::new();
            dleq.init2(
                self.mpvss.g.clone(),
                x.clone(),
                pubkey.clone(),
                encrypted_secret_share.clone(),
                self.mpvss.q.clone(),
                secret_share.clone(),
                w.clone(),
            );

            dleq_w.insert(pubkey.clone(), dleq.w.clone());
            // Calc a_1i, a_2i
            a.insert(pubkey.clone(), (dleq.get_a1(), dleq.get_a2()));

            // Update challenge hash
            // the challenge c for the protocol is computed as a cryptographic hash of X_i,Y_i,a_1i,a_2i, 1 <= i <= n
            challenge_hasher
                .update(x.to_biguint().unwrap().to_str_radix(10).as_bytes());
            challenge_hasher.update(
                encrypted_secret_share
                    .to_biguint()
                    .unwrap()
                    .to_str_radix(10)
                    .as_bytes(),
            );
            challenge_hasher.update(
                dleq.get_a1()
                    .to_biguint()
                    .unwrap()
                    .to_str_radix(10)
                    .as_bytes(),
            );
            challenge_hasher.update(
                dleq.get_a2()
                    .to_biguint()
                    .unwrap()
                    .to_str_radix(10)
                    .as_bytes(),
            );
            position += 1;
        } // end for participant's publickeys

        // the common challenge c
        let challenge_hash = challenge_hasher.finalize();
        let challenge_big_uint = BigUint::from_bytes_be(&challenge_hash[..])
            .mod_floor(&(self.mpvss.q.to_biguint().unwrap() - BigUint::one()));

        // Calc response r_i
        let mut responses: BTreeMap<BigInt, BigInt> = BTreeMap::new();
        for pubkey in publickeys {
            // DLEQ(g1,h2,g2,h2) => DLEQ(g,X_i,y_i,Y_i) => DLEQ(g,commintment_with_secret_share,pubkey,encrypted_secret_share_from_pubkey)
            let x_i = X.get(pubkey).unwrap();
            let encrypted_secret_share = shares.get(pubkey).unwrap();
            let secret_share = sampling_points.get(pubkey).unwrap();
            let w = dleq_w.get(pubkey).unwrap();
            let mut dleq = DLEQ::new();
            dleq.init2(
                self.mpvss.g.clone(),
                x_i.clone(),
                pubkey.clone(),
                encrypted_secret_share.clone(),
                self.mpvss.q.clone(),
                secret_share.clone(),
                w.clone(),
            );
            dleq.c = Some(challenge_big_uint.to_bigint().unwrap());
            let response = dleq.get_r().unwrap();
            responses.insert(pubkey.clone(), response);
        } // end for pubkeys Calc r_i

        // Calc U = secret xor SHA256(G^s) = secret xor SHA256(G^p(0)).
        // [Section 4]
        // σ ∈ Σ, where 2 ≤ |Σ| ≤ q.
        // the general procedure is to let the dealer first run the distribution protocol for a random value s ∈ Zq, and then publish U = σ ⊕ H(G^s),
        // where H is an appropriate cryptographic hash function. The reconstruction protocol will yield G^s, from which we obtain σ = U ⊕ H(G^s).
        let shared_value = self.mpvss.G.modpow(
            &polynomial.get_value(&BigInt::zero()).mod_floor(
                &(self.mpvss.q.to_bigint().unwrap() - BigInt::one()),
            ),
            &self.mpvss.q,
        );
        let sha256_hash = sha2::Sha256::digest(
            shared_value
                .to_biguint()
                .unwrap()
                .to_str_radix(10)
                .as_bytes(),
        );
        let hash_big_uint = BigUint::from_bytes_be(&sha256_hash[..])
            .mod_floor(&self.mpvss.q.to_biguint().unwrap());
        let U = secret.to_biguint().unwrap() ^ hash_big_uint;

        // The proof consists of the common challenge c and the n responses r_i.
        let mut shares_box = DistributionSharesBox::new();
        shares_box.init(
            &commitments,
            positions,
            shares,
            publickeys,
            &challenge_big_uint.to_bigint().unwrap(),
            responses,
            &U.to_bigint().unwrap(),
        );
        shares_box
    }

    /// Takes a secret as input and returns the distribution shares Box which is going to be submitted to all the participants the secret is going to be shared with.
    /// Those participants are specified by their public keys. They use the distribution shares box to verify that the shares are correct (without learning anything about the shares that are not supposed to be decrypted by them)
    /// and extract their encrypted shares. In fact, the distribution shares box can be published to everyone allowing even external parties to verify the integrity of the shares.
    ///
    /// - Parameters:
    ///   - secret: The value that is going to be shared among the other participants.
    ///   - publicKeys: Array of public keys of each participant the secret is to be shared with.
    ///   - threshold: The number of shares that is needed in order to reconstruct the secret. It must not be greater than the total number of participants.
    /// - Requires: `threshold` <= number of participants
    /// - Returns: The distribution shares Box that is published to everyone (especially but not only the participants) can check the shares' integrity. Furthermore the participants extract their shares from it.
    ///
    /// ## Example
    ///
    /// ```rust
    /// use mpvss_rs::Participant;
    /// use num_bigint::{BigUint, ToBigInt};
    ///
    /// let secret_message = String::from("Hello MPVSS Example.");
    /// let secret = BigUint::from_bytes_be(&secret_message.as_bytes());
    /// let mut dealer = Participant::new();
    /// dealer.initialize();
    /// let mut p1 = Participant::new();
    /// let mut p2 = Participant::new();
    /// let mut p3 = Participant::new();
    /// p1.initialize();
    /// p2.initialize();
    /// p3.initialize();
    ///
    /// let distribute_shares_box = dealer.distribute_secret(
    ///    &secret.to_bigint().unwrap(),
    ///    &vec![
    ///        p1.publickey.clone(),
    ///        p2.publickey.clone(),
    ///        p3.publickey.clone(),
    ///    ],
    ///    3,
    /// );
    /// ```
    pub fn distribute_secret(
        &mut self,
        secret: &BigInt,
        publickeys: &[BigInt],
        threshold: u32,
    ) -> DistributionSharesBox {
        let mut polynomial = Polynomial::new();
        polynomial
            .init((threshold - 1) as i32, &self.mpvss.q.to_bigint().unwrap());

        let mut rng = rand::thread_rng();
        let w: BigUint =
            rng.gen_biguint_below(&self.mpvss.q.to_biguint().unwrap());
        self.distribute(
            secret,
            publickeys,
            threshold,
            &polynomial,
            &w.to_bigint().unwrap(),
        )
    }

    fn extract_share(
        &self,
        shares_box: &DistributionSharesBox,
        private_key: &BigInt,
        w: &BigInt,
    ) -> Option<ShareBox> {
        let public_key = self.mpvss.generate_public_key(private_key);
        let encrypted_secret_share =
            shares_box.shares.get(&public_key).unwrap();

        // Decryption of the shares.
        // Using its private key x_i, each participant finds the decrypted share S_i = G^p(i) from Y_i by computing S_i = Y_i^(1/x_i).
        // Y_i is encrypted share: Y_i = y_i^p(i)
        // find modular multiplicative inverses of private key
        let privkey_inverse =
            Util::mod_inverse(private_key, &(&self.mpvss.q - BigInt::one()))
                .unwrap();
        let decrypted_share =
            encrypted_secret_share.modpow(&privkey_inverse, &self.mpvss.q);

        // To this end it suffices to prove knowledge of an α such that y_i= G^α and Y_i= S_i^α, which is accomplished by the non-interactive version of the protocol DLEQ(G,y_i,S_i,Y_i).
        // DLEQ(G,y_i,S_i,Y_i) => DLEQ(G, publickey, decrypted_share, encryted_share)
        // All of this is to prove and tell participants that the decrypted share is must use your own public key encrypted,
        // and only you can decrypt the share with your own private key and verify the share's proof
        let mut dleq = DLEQ::new();
        dleq.init2(
            self.mpvss.G.clone(),
            public_key.clone(),
            decrypted_share.clone(),
            encrypted_secret_share.clone(),
            self.mpvss.q.clone(),
            private_key.clone(),
            w.clone(),
        );

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
        challenge_hasher.update(
            dleq.get_a1()
                .to_biguint()
                .unwrap()
                .to_str_radix(10)
                .as_bytes(),
        );
        challenge_hasher.update(
            dleq.get_a2()
                .to_biguint()
                .unwrap()
                .to_str_radix(10)
                .as_bytes(),
        );

        // the challenge c
        let challenge_hash = challenge_hasher.finalize();
        let challenge_big_uint = BigUint::from_bytes_be(&challenge_hash[..])
            .mod_floor(&(self.mpvss.q.to_biguint().unwrap() - BigUint::one()));
        dleq.c = Some(challenge_big_uint.to_bigint().unwrap());

        let mut share_box = ShareBox::new();
        share_box.init(
            public_key,
            decrypted_share,
            challenge_big_uint.to_bigint().unwrap(),
            dleq.get_r().unwrap(),
        );
        Some(share_box)
    }

    /// Extracts the share from a given distribution shares box that is addressed to the calling participant.
    /// The extracted share is boxed with a proof which allows the other participants to verify the share's correctness.
    ///
    /// - Parameters:
    ///   - shares_box: The distribution shares box that consists the share to be extracted.
    ///   - private_key: The participant's private key used to decrypt the share.
    /// - Returns: The share box that is to be submitted to all the other participants in order to reconstruct the secret.
    ///     It consists of the share itself and the proof that allows the receiving participant to verify its correctness.
    ///     Return `None` if the distribution shares box does not contain a share for the participant.
    ///
    /// ## Example
    ///
    /// ```rust
    /// use mpvss_rs::Participant;
    /// use num_bigint::{BigUint, ToBigInt};
    ///
    /// let secret_message = String::from("Hello MPVSS Example.");
    /// let secret = BigUint::from_bytes_be(&secret_message.as_bytes());
    /// let mut dealer = Participant::new();
    /// dealer.initialize();
    /// let mut p1 = Participant::new();
    /// let mut p2 = Participant::new();
    /// let mut p3 = Participant::new();
    /// p1.initialize();
    /// p2.initialize();
    /// p3.initialize();
    ///
    /// let distribute_shares_box = dealer.distribute_secret(
    ///    &secret.to_bigint().unwrap(),
    ///    &vec![
    ///        p1.publickey.clone(),
    ///        p2.publickey.clone(),
    ///        p3.publickey.clone(),
    ///    ],
    ///    3,
    /// );
    ///
    ///  let s1 = p1
    ///        .extract_secret_share(&distribute_shares_box, &p1.privatekey)
    ///        .unwrap();
    ///  let s2 = p2
    ///        .extract_secret_share(&distribute_shares_box, &p2.privatekey)
    ///        .unwrap();
    ///  let s3 = p3
    ///        .extract_secret_share(&distribute_shares_box, &p3.privatekey)
    ///        .unwrap();
    /// ```
    pub fn extract_secret_share(
        &self,
        shares_box: &DistributionSharesBox,
        private_key: &BigInt,
    ) -> Option<ShareBox> {
        let w = Generator::new_uint(self.mpvss.length as usize)
            .mod_floor(&self.mpvss.q.to_biguint().unwrap());
        self.extract_share(shares_box, private_key, &w.to_bigint().unwrap())
    }

    /// Verifies that the shares the distribution  shares box consists are consistent so that they can be used to reconstruct the secret later.
    ///
    /// - Parameter distribute_sharesbox: The distribution shares box whose consistency is to be verified.
    /// - Returns: Returns `true` if the shares are correct and `false` otherwise.
    ///
    /// ## Example
    ///
    /// ```rust
    /// use mpvss_rs::Participant;
    /// use num_bigint::{BigUint, ToBigInt};
    /// let secret_message = String::from("Hello MPVSS Example.");
    /// let secret = BigUint::from_bytes_be(&secret_message.as_bytes());
    /// let mut dealer = Participant::new();
    /// dealer.initialize();
    /// let mut p1 = Participant::new();
    /// let mut p2 = Participant::new();
    /// let mut p3 = Participant::new();
    /// p1.initialize();
    /// p2.initialize();
    /// p3.initialize();
    ///
    /// let distribute_shares_box = dealer.distribute_secret(
    ///     &secret.to_bigint().unwrap(),
    ///     &vec![
    ///         p1.publickey.clone(),
    ///         p2.publickey.clone(),
    ///         p3.publickey.clone(),
    ///     ],
    ///     3,
    /// );
    ///
    /// assert_eq!(
    ///     p1.verify_distribution_shares(&distribute_shares_box),
    ///     true
    /// );
    ///
    /// assert_eq!(
    ///     p2.verify_distribution_shares(&distribute_shares_box),
    ///     true
    /// );

    /// assert_eq!(
    ///     p3.verify_distribution_shares(&distribute_shares_box),
    ///     true
    /// );
    /// ```
    pub fn verify_distribution_shares(
        &self,
        distribute_sharesbox: &DistributionSharesBox,
    ) -> bool {
        self.mpvss.verify_distribution_shares(distribute_sharesbox)
    }

    /// Verifies if the share in the distribution share box was decrypted correctly by the respective participant.
    ///
    /// - Parameters:
    ///   - shareBox: The share box containing the share to be verified.
    ///   - distributionShareBox: The distribution share box that contains the share.
    ///   - publicKey: The public key of the sender of the share bundle.
    /// - Returns: Returns `true` if the share in the distribution share box matches the decryption of the encrypted share and `false` otherwise.
    ///
    /// ## Example
    ///
    /// ```rust
    /// use mpvss_rs::Participant;
    /// use num_bigint::{BigUint, ToBigInt};
    ///
    /// let secret_message = String::from("Hello MPVSS Example.");
    /// let secret = BigUint::from_bytes_be(&secret_message.as_bytes());
    /// let mut dealer = Participant::new();
    /// dealer.initialize();
    /// let mut p1 = Participant::new();
    /// let mut p2 = Participant::new();
    /// let mut p3 = Participant::new();
    /// p1.initialize();
    /// p2.initialize();
    /// p3.initialize();
    ///
    /// let distribute_shares_box = dealer.distribute_secret(
    ///    &secret.to_bigint().unwrap(),
    ///    &vec![
    ///        p1.publickey.clone(),
    ///        p2.publickey.clone(),
    ///        p3.publickey.clone(),
    ///    ],
    ///    3,
    /// );
    ///
    ///  let s1 = p1
    ///        .extract_secret_share(&distribute_shares_box, &p1.privatekey)
    ///        .unwrap();
    ///  let s2 = p2
    ///        .extract_secret_share(&distribute_shares_box, &p2.privatekey)
    ///        .unwrap();
    ///  let s3 = p3
    ///        .extract_secret_share(&distribute_shares_box, &p3.privatekey)
    ///        .unwrap();
    ///
    ///  assert_eq!(
    ///    p1.verify_share(&s2, &distribute_shares_box, &p2.publickey),
    ///      true
    ///   );
    ///
    ///  assert_eq!(
    ///    p2.verify_share(&s3, &distribute_shares_box, &p3.publickey),
    ///      true
    ///   );
    ///
    ///  assert_eq!(
    ///    p3.verify_share(&s1, &distribute_shares_box, &s1.publickey),
    ///      true
    ///   );
    /// ```
    pub fn verify_share(
        &self,
        sharebox: &ShareBox,
        distribution_sharebox: &DistributionSharesBox,
        publickey: &BigInt,
    ) -> bool {
        self.mpvss
            .verify_share(sharebox, distribution_sharebox, publickey)
    }

    /// Reconstruct secret from share boxs
    ///
    /// ## Example
    ///
    /// ```rust
    /// use mpvss_rs::Participant;
    /// use num_bigint::{BigUint, ToBigInt};
    /// let secret_message = String::from("Hello MPVSS Example.");
    /// let secret = BigUint::from_bytes_be(&secret_message.as_bytes());
    /// let mut dealer = Participant::new();
    /// dealer.initialize();
    /// let mut p1 = Participant::new();
    /// let mut p2 = Participant::new();
    /// let mut p3 = Participant::new();
    /// p1.initialize();
    /// p2.initialize();
    /// p3.initialize();
    ///
    /// let distribute_shares_box = dealer.distribute_secret(
    ///     &secret.to_bigint().unwrap(),
    ///     &vec![
    ///         p1.publickey.clone(),
    ///         p2.publickey.clone(),
    ///         p3.publickey.clone(),
    ///     ],
    ///     3,
    /// );
    ///
    /// assert_eq!(
    ///     p1.verify_distribution_shares(&distribute_shares_box),
    ///     true
    /// );
    ///
    /// assert_eq!(
    ///     p2.verify_distribution_shares(&distribute_shares_box),
    ///     true
    /// );
    ///
    /// assert_eq!(
    ///     p3.verify_distribution_shares(&distribute_shares_box),
    ///     true
    /// );
    ///
    ///
    /// let s1 = p1
    ///     .extract_secret_share(&distribute_shares_box, &p1.privatekey)
    ///     .unwrap();
    ///
    /// let s2 = p2
    ///     .extract_secret_share(&distribute_shares_box, &p2.privatekey)
    ///     .unwrap();
    /// let s3 = p3
    ///     .extract_secret_share(&distribute_shares_box, &p3.privatekey)
    ///     .unwrap();
    ///
    /// assert_eq!(
    ///     p1.verify_share(&s2, &distribute_shares_box, &p2.publickey),
    ///     true
    /// );
    ///
    /// assert_eq!(
    ///     p2.verify_share(&s3, &distribute_shares_box, &p3.publickey),
    ///     true
    /// );
    ///
    /// assert_eq!(
    ///     p3.verify_share(&s1, &distribute_shares_box, &s1.publickey),
    ///     true
    /// );
    ///
    /// let share_boxs = [s1, s2, s3];
    /// let r1 = p1
    ///     .reconstruct(&share_boxs, &distribute_shares_box)
    ///     .unwrap();
    /// let r2 = p2
    ///     .reconstruct(&share_boxs, &distribute_shares_box)
    ///     .unwrap();
    /// let r3 = p3
    ///     .reconstruct(&share_boxs, &distribute_shares_box)
    ///     .unwrap();
    ///
    /// let r1_str =
    ///     String::from_utf8(r1.to_biguint().unwrap().to_bytes_be()).unwrap();
    /// assert_eq!(secret_message.clone(), r1_str);
    /// let r2_str =
    ///     String::from_utf8(r2.to_biguint().unwrap().to_bytes_be()).unwrap();
    /// assert_eq!(secret_message.clone(), r2_str);
    /// let r3_str =
    ///     String::from_utf8(r3.to_biguint().unwrap().to_bytes_be()).unwrap();
    /// assert_eq!(secret_message.clone(), r3_str);
    /// ```
    pub fn reconstruct(
        &self,
        share_boxs: &[ShareBox],
        distribute_share_box: &DistributionSharesBox,
    ) -> Option<BigInt> {
        self.mpvss.reconstruct(share_boxs, distribute_share_box)
    }
}

#[cfg(test)]
mod tests {

    use super::BTreeMap;
    use super::BigInt;
    use super::Participant;
    use super::Polynomial;
    use super::MPVSS;
    use super::{DistributionSharesBox, ShareBox};
    use num_traits::{One, Zero};

    struct Setup {
        pub mpvss: MPVSS,
        pub privatekey: BigInt,
        pub secret: BigInt,
    }

    impl Setup {
        fn new() -> Self {
            let q = BigInt::from(179426549);
            let g = BigInt::from(1301081);
            let G = BigInt::from(15486487);

            let length: i64 = 64_i64;
            let mut mpvss = MPVSS::new();
            mpvss.length = length as u32;
            mpvss.g = g;
            mpvss.G = G;
            mpvss.q = q;

            return Setup {
                mpvss: mpvss,
                privatekey: BigInt::from(105929),
                secret: BigInt::from(1234567890),
            };
        }
    }

    // Use Fixed distribution shares box for tests
    fn get_distribute_shares_box() -> DistributionSharesBox {
        let setup = Setup::new();
        let mut dealer = Participant::new();
        dealer.mpvss = setup.mpvss.clone();
        dealer.privatekey = setup.privatekey.clone();
        dealer.publickey = setup.mpvss.generate_public_key(&setup.privatekey);

        let mut polynomial = Polynomial::new();
        polynomial.init_coefficients(&vec![
            BigInt::from(164102006),
            BigInt::from(43489589),
            BigInt::from(98100795),
        ]);
        let threshold: i32 = 3;
        // from participant 1 to 3
        let privatekeys =
            [BigInt::from(7901), BigInt::from(4801), BigInt::from(1453)];
        let mut publickeys = vec![];
        let w = BigInt::from(6345);

        for key in privatekeys.iter() {
            publickeys.push(setup.mpvss.generate_public_key(key));
        }

        return dealer.distribute(
            &setup.secret,
            &publickeys,
            threshold as u32,
            &polynomial,
            &w,
        );
    }

    // Use Fixed Share box for tests
    fn get_share_box() -> ShareBox {
        let distribution_shares_box = get_distribute_shares_box();
        // Use Participant 1's private key
        let private_key = BigInt::from(7901);
        let w = BigInt::from(1337);
        let mut participant = Participant::new();
        let setup = Setup::new();
        participant.mpvss = setup.mpvss.clone();
        participant.privatekey = private_key.clone();
        participant.publickey = setup.mpvss.generate_public_key(&private_key);

        participant
            .extract_share(&distribution_shares_box, &private_key, &w)
            .unwrap()
    }

    #[test]
    fn test_distribution() {
        let distribution = get_distribute_shares_box();

        let commitments = vec![
            BigInt::from(92318234),
            BigInt::from(76602245),
            BigInt::from(63484157),
        ];
        let mut shares: BTreeMap<BigInt, BigInt> = BTreeMap::new();
        shares
            .insert(distribution.publickeys[0].clone(), BigInt::from(42478042));
        shares
            .insert(distribution.publickeys[1].clone(), BigInt::from(80117658));
        shares
            .insert(distribution.publickeys[2].clone(), BigInt::from(86941725));

        let challenge = BigInt::from(41963410);
        let mut responses: BTreeMap<BigInt, BigInt> = BTreeMap::new();
        responses.insert(
            distribution.publickeys[0].clone(),
            BigInt::from(151565889),
        );
        responses.insert(
            distribution.publickeys[1].clone(),
            BigInt::from(146145105),
        );
        responses
            .insert(distribution.publickeys[2].clone(), BigInt::from(71350321));

        assert_eq!(distribution.publickeys[0], distribution.publickeys[0]);
        assert_eq!(distribution.publickeys[1], distribution.publickeys[1]);
        assert_eq!(distribution.publickeys[2], distribution.publickeys[2]);

        assert_eq!(distribution.challenge, challenge);

        for i in 0..=2 {
            assert_eq!(distribution.commitments[i], commitments[i]);
            assert_eq!(
                distribution.shares[&distribution.publickeys[i]],
                shares[&distribution.publickeys[i]]
            );
            assert_eq!(
                distribution.responses[&distribution.publickeys[i]],
                responses[&distribution.publickeys[i]]
            );
        }
    }

    #[test]
    fn test_distribution_verify() {
        let setup = Setup::new();
        let distribution = get_distribute_shares_box();
        assert_eq!(setup.mpvss.verify_distribution_shares(&distribution), true);
    }

    #[test]
    fn test_extract_share() {
        let share_box = get_share_box();
        assert_eq!(share_box.share, BigInt::from(164021044));
        assert_eq!(share_box.challenge, BigInt::from(134883166));
        assert_eq!(share_box.response, BigInt::from(81801891));
    }

    #[test]
    fn test_share_box_verify() {
        // participant 1 private key
        let private_key = BigInt::from(7901);
        let distribution_shares_box = get_distribute_shares_box();
        let share_box = get_share_box();

        let setup = Setup::new();
        assert_eq!(
            setup.mpvss.verify_share(
                &share_box,
                &distribution_shares_box,
                &setup.mpvss.generate_public_key(&private_key)
            ),
            true
        );
    }

    #[test]
    fn test_reconstruction_with_all_participants() {
        let distribution_shares_box = get_distribute_shares_box();
        let share_box1 = get_share_box();
        let mut share_box2 = ShareBox::new();
        share_box2.init(
            BigInt::from(132222922),
            BigInt::from(157312059),
            BigInt::zero(),
            BigInt::zero(),
        );
        let mut share_box3 = ShareBox::new();
        share_box3.init(
            BigInt::from(65136827),
            BigInt::from(63399333),
            BigInt::zero(),
            BigInt::zero(),
        );

        let setup = Setup::new();
        let share_boxs = [share_box1, share_box2, share_box3];
        let reconstructed_secret = setup
            .mpvss
            .reconstruct(&share_boxs, &distribution_shares_box)
            .unwrap();
        assert_eq!(reconstructed_secret, setup.secret);
    }

    // (3,4) threshhold reconstruct, participant 3 is not available, 1,2,4 is available
    #[test]
    fn test_reconstruction_with_sub_group() {
        let share_box1 = get_share_box();
        let mut share_box2 = ShareBox::new();
        share_box2.init(
            BigInt::from(132222922),
            BigInt::from(157312059),
            BigInt::zero(),
            BigInt::zero(),
        );

        let public_key4 = BigInt::from(42);
        let mut share_box4 = ShareBox::new();
        share_box4.init(
            public_key4.clone(),
            BigInt::from(59066181),
            BigInt::zero(),
            BigInt::zero(),
        );

        let mut positions = BTreeMap::new();
        positions.insert(share_box1.clone().publickey, 1_i64);
        positions.insert(share_box2.clone().publickey, 2_i64);
        positions.insert(share_box4.clone().publickey, 4_i64);

        let mut distribution_shares_box = DistributionSharesBox::new();
        distribution_shares_box.init(
            &vec![BigInt::zero(), BigInt::one(), BigInt::from(2)],
            positions,
            BTreeMap::new(),
            &vec![],
            &BigInt::zero(),
            BTreeMap::new(),
            &BigInt::from(1284073502),
        );

        let setup = Setup::new();
        let share_boxs = [share_box1, share_box2, share_box4];
        let reconstructed_secret = setup
            .mpvss
            .reconstruct(&share_boxs, &distribution_shares_box)
            .unwrap();
        assert_eq!(reconstructed_secret, setup.secret);
    }
}
