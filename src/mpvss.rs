// Copyright 2020-2021  MathxH Chen.
//
// Code is licensed under GPLv3.0 License.

#![allow(non_snake_case)]
#![allow(dead_code)]

use crate::dleq::DLEQ;
use crate::sharebox::{DistributionSharesBox, ShareBox};
use crate::util::Util;
use num_bigint::{BigInt, BigUint, RandBigInt, ToBigInt};
use num_integer::Integer;
use num_primes::Generator;
use num_traits::identities::{One, Zero};
use rayon::prelude::*;
use sha2::{Digest, Sha256};
use std::clone::Clone;
use std::collections::BTreeMap;

/// 2048-bit MODP Group
/// New Modular Exponential (MODP) Diffie-Hellman groups
///
/// This group is assigned id 14.
///
/// This prime is: 2^2048 - 2^1984 - 1 + 2^64 * { [2^1918 pi] + 124476 }
///
/// Its hexadecimal value is:
///
///    FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
///    29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
///    EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
///    E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
///    EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D
///    C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F
///    83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
///    670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B
///    E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9
///    DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510
///    15728E5A 8AACAA68 FFFFFFFF FFFFFFFF
///
/// The generator is: 2.

#[derive(Debug, Clone, Default)]
pub struct MPVSS {
    pub q: BigInt,
    pub g: BigInt,
    pub G: BigInt,

    pub length: u32,
}

impl MPVSS {
    /// `q` is a safe prime of length 2048 bit RFC3526 https://tools.ietf.org/html/rfc3526.
    /// `2` and the corresponding sophie germain prime are generators.
    /// sophie germain prime is p if 2*p + 1 is also prime, let 2*p + 1 = q
    pub fn new() -> Self {
        let q: BigUint = BigUint::parse_bytes(b"ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3be39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf6955817183995497cea956ae515d2261898fa051015728e5a8aacaa68ffffffffffffffff", 16).unwrap();
        let g: BigUint = (q.clone() - BigUint::one()) / BigUint::from(2_u64);
        return MPVSS {
            q: q.to_bigint().unwrap(),
            g: g.to_bigint().unwrap(),
            G: BigInt::from(2_i64),
            length: 2048,
        };
    }

    /// Initializes a MPVSS by generating a safe prime of `length` bit length.
    ///
    /// - Parameter length: Number of bits used for choosing numbers and doing calculations.
    pub fn init(length: u32) -> Self {
        let q: BigUint = Generator::safe_prime(length as usize);
        let g: BigUint = (q.clone() - BigUint::one()) / BigUint::from(2_u64);
        return MPVSS {
            q: q.to_bigint().unwrap(),
            g: g.to_bigint().unwrap(),
            G: BigInt::from(2_i64),
            length: length,
        };
    }

    pub fn generate_private_key(&self) -> BigInt {
        let mut rng = rand::thread_rng();
        let mut privkey: BigUint =
            rng.gen_biguint_below(&self.q.to_biguint().unwrap());
        // We need the private key and q-1 to be coprime so that we can calculate 1/key mod (q-1) during secret reconstruction.
        while privkey
            .gcd(&(self.q.clone().to_biguint().unwrap() - BigUint::one()))
            != BigUint::one()
        {
            privkey = rng.gen_biguint_below(&self.q.to_biguint().unwrap());
        }
        privkey.to_bigint().unwrap()
    }

    /// generate public key from private key
    /// P = G^k over the Group of the order q
    pub fn generate_public_key(&self, privkey: &BigInt) -> BigInt {
        // publicKey = G^privKey mod q
        self.G.modpow(privkey, &self.q)
    }

    /// Verifies if the share in the distribution share box was decrypted correctly by the respective participant.
    ///
    /// - Parameters:
    ///   - shareBox: The share box containing the share to be verified.
    ///   - distributionShareBox: The distribution share box that contains the share.
    ///   - publicKey: The public key of the sender of the share bundle.
    /// - Returns: Returns `true` if the share in the distribution share box matches the decryption of the encrypted share and `false` otherwise.
    pub fn verify_share(
        &self,
        sharebox: &ShareBox,
        distribution_sharebox: &DistributionSharesBox,
        publickey: &BigInt,
    ) -> bool {
        let encrypted_share = distribution_sharebox.shares.get(publickey);
        if encrypted_share.is_none() {
            return false;
        }
        self.verify(sharebox, encrypted_share.unwrap())
    }

    fn verify(&self, sharebox: &ShareBox, encrypted_share: &BigInt) -> bool {
        // Verification of the share.
        // Using publickey,encrypted_hsare,decrypted_share,response and c as input, the verifier computes a_1i,a_2i as:
        // a_1i = G^r * publickey^c,   a_2i = decrypted_shar^r * encrypted_share^c
        // and checks that the hash of publickey,encrypted_hsare,decrypted_share,response  matches c.
        let mut dleq = DLEQ::new();
        let mut challenge_haser = Sha256::new();
        dleq.g1 = self.G.clone();
        dleq.h1 = sharebox.publickey.clone();
        dleq.g2 = sharebox.share.clone();
        dleq.h2 = encrypted_share.clone();
        dleq.r = Some(sharebox.response.clone());
        dleq.c = Some(sharebox.challenge.clone());
        dleq.q = self.q.clone();
        dleq.update_hash(&mut challenge_haser);
        dleq.check(&challenge_haser)
    }

    /// Verifies that the shares the distribution  shares box consists are consistent so that they can be used to reconstruct the secret later.
    ///
    /// - Parameter distribute_sharesbox: The distribution shares box whose consistency is to be verified.
    /// - Returns: Returns `true` if the shares are correct and `false` otherwise.
    pub fn verify_distribution_shares(
        &self,
        distribute_sharesbox: &DistributionSharesBox,
    ) -> bool {
        // Verification of the shares.
        // The verifier computes X_i = ∏(j = 0 -> t - 1): (C_j)^(i^j) from the C_j values.
        // Using y_i,X_i,Y_i,r_i, 1 ≤ i ≤ n and c as input, the verifier computes a_1i,a_2i as:
        // a_1i = g^(r_i) * X_i^c,   a_2i = y_i^(r_i) * Y_i^c
        // and checks that the hash of X_i,Y_i, a_1i, a_2i,  1 ≤ i ≤ n, matches c.
        let mut dleq = DLEQ::new();
        let mut challenge_hasher = Sha256::new();
        for publickey in distribute_sharesbox.publickeys.clone() {
            let position = distribute_sharesbox.positions.get(&publickey);
            let response = distribute_sharesbox.responses.get(&publickey);
            let encrypted_share = distribute_sharesbox.shares.get(&publickey);
            if position.is_none()
                || response.is_none()
                || encrypted_share.is_none()
            {
                return false;
            }

            // Calculate X_i
            let mut x: BigInt = BigInt::one();
            let mut exponent: BigInt = BigInt::one();
            for j in 0..distribute_sharesbox.commitments.len() {
                x = (x * distribute_sharesbox.commitments[j]
                    .modpow(&exponent, &self.q))
                    % &self.q;
                exponent = (exponent
                    * BigInt::from(position.unwrap().clone() as i64))
                    % &(self.q.clone() - BigInt::one());
            }

            // Calculate a_1i, a_2i and update hash
            dleq.g1 = self.g.clone();
            dleq.h1 = x;
            dleq.g2 = publickey.clone();
            dleq.h2 = encrypted_share.unwrap().clone();
            dleq.r = Some(response.unwrap().clone());
            dleq.c = Some(distribute_sharesbox.challenge.clone());
            dleq.q = self.q.clone();
            dleq.update_hash(&mut challenge_hasher);
        } // end for participant's public keys

        // Calculate challenge and check if it is match c
        dleq.check(&challenge_hasher)
    }

    fn compute_factor(
        &self,
        position: i64,
        share: &BigInt,
        values: &[i64],
    ) -> BigInt {
        let mut exponent = BigInt::one();
        let lagrangeCoefficient = Util::lagrange_coefficient(&position, values);
        if lagrangeCoefficient.0.clone() % lagrangeCoefficient.1.clone()
            == BigInt::zero()
        {
            // Lagrange coefficient is an integer
            exponent = lagrangeCoefficient.0.clone()
                / Util::abs(&lagrangeCoefficient.1);
        } else {
            // Lagrange coefficient is a proper fraction
            // Cancel fraction if possible
            let mut numerator = lagrangeCoefficient.0.to_biguint().unwrap();
            let mut denominator =
                Util::abs(&lagrangeCoefficient.1).to_biguint().unwrap();
            let gcd = numerator.gcd(&denominator);
            numerator = numerator / gcd.clone();
            denominator = denominator / gcd.clone();

            let q1 = self.q.clone() - BigInt::one();
            let inverseDenominator = Util::mod_inverse(
                &denominator.to_bigint().unwrap(),
                &q1.to_bigint().unwrap(),
            );
            if inverseDenominator.is_some() {
                exponent = (numerator.to_bigint().unwrap()
                    * inverseDenominator.unwrap())
                    % q1.clone().to_bigint().unwrap();
            } else {
                eprintln!("ERROR: Denominator of Lagrange coefficient fraction does not have an inverse. Share cannot be processed.");
            }
        }
        let mut factor = share
            .to_bigint()
            .unwrap()
            .modpow(&exponent, &self.q.to_bigint().unwrap());
        if lagrangeCoefficient.0 * lagrangeCoefficient.1 < BigInt::zero() {
            // Lagrange coefficient was negative. S^(-lambda) = 1/(S^lambda)
            let inverseFactor =
                Util::mod_inverse(&factor, &self.q.to_bigint().unwrap());
            if inverseFactor.is_some() {
                factor = inverseFactor.unwrap();
            } else {
                eprintln!("ERROR: Lagrange coefficient was negative and does not have an inverse. Share cannot be processed.")
            }
        }

        factor
    }

    /// Reconstruct secret from share boxs
    pub fn reconstruct(
        &self,
        share_boxs: &[ShareBox],
        distribute_share_box: &DistributionSharesBox,
    ) -> Option<BigInt> {
        if share_boxs.len() < distribute_share_box.commitments.len() {
            return None;
        }
        let mut shares: BTreeMap<i64, BigInt> = BTreeMap::new();
        for share_box in share_boxs.iter() {
            let position =
                distribute_share_box.positions.get(&share_box.publickey);
            if position.is_none() {
                return None;
            }
            shares.insert(*position.unwrap(), share_box.share.clone());
        }
        // Pooling  the shares. Suppose
        // w.l.o.g.  that  participantsPiproduce  correctvalues for S_i, for i= 1,...,t.
        // The secret G^s is obtained by Lagrange interpolation:
        // ∏(i=1->t)(S^λ_i) = ∏(i=1->t)(G^p(i))^λ_i = G^(∑(i=1->t)p(i)*λ_i = G^p(0) = G^s,
        let mut secret: BigInt = BigInt::one();
        let values: Vec<i64> = shares.keys().map(|key| *key).collect();
        let shares_vec: Vec<(i64, BigInt)> = shares
            .into_iter()
            .map(|(postion, share)| (postion, share))
            .collect();
        let shares_slice = shares_vec.as_slice();
        let factors: Vec<BigInt> = shares_slice
            .par_iter()
            .map(|(position, share)| {
                self.compute_factor(*position, share, values.as_slice())
            })
            .collect();

        secret = factors
            .into_iter()
            .fold(secret, |acc, factor| (acc * factor) % self.q.clone());

        // Reconstruct the secret = H(G^s) xor U
        let secret_hash = sha2::Sha256::digest(
            &secret.to_biguint().unwrap().to_str_radix(10).as_bytes(),
        );
        let hash_big_uint = BigUint::from_bytes_be(&secret_hash[..])
            .mod_floor(&self.q.to_biguint().unwrap());
        let decrypted_secret = hash_big_uint
            ^ distribute_share_box.U.clone().to_biguint().unwrap();
        Some(decrypted_secret.to_bigint().unwrap())
    }
}

#[cfg(test)]
mod tests {
    use super::MPVSS;
    use num_bigint::{BigInt, BigUint, ToBigInt};
    use num_integer::Integer;
    use num_primes::Verification;
    use num_traits::One;
    #[test]
    fn test_new() {
        let mpvss = MPVSS::new();
        assert!(Verification::is_safe_prime(&mpvss.q.to_biguint().unwrap()));
        assert!(Verification::is_prime(&mpvss.g.to_biguint().unwrap()));
        assert!(!Verification::is_safe_prime(&mpvss.g.to_biguint().unwrap()));
    }

    #[test]
    fn test_init() {
        let mpvss = MPVSS::init(64);
        assert!(Verification::is_safe_prime(&mpvss.q.to_biguint().unwrap()));
        assert!(Verification::is_prime(&mpvss.g.to_biguint().unwrap()));
        assert!(!Verification::is_safe_prime(&mpvss.g.to_biguint().unwrap()));

        let mpvss = MPVSS::init(32);
        assert!(Verification::is_prime(&mpvss.q.to_biguint().unwrap()));
        assert!(Verification::is_prime(&mpvss.g.to_biguint().unwrap()));
        assert_eq!(
            mpvss.g,
            ((mpvss.q - BigInt::one()).to_biguint().unwrap()
                / BigUint::from(2_u32))
            .to_bigint()
            .unwrap()
        )
    }

    #[test]
    fn test_gen_priv_key() {
        let mut mpvss = MPVSS::new();
        mpvss.q = BigInt::from(49999_i32);
        assert!(Verification::is_prime(&mpvss.q.to_biguint().unwrap()));
        let priv_key = mpvss.generate_private_key();
        assert_eq!(
            priv_key.gcd(&(mpvss.q.clone() - BigInt::one())),
            BigInt::one()
        );
    }

    #[test]
    fn test_gen_public_key() {
        use super::BigInt;
        use super::MPVSS;
        let q: BigInt = BigInt::from(179426549);
        let g: BigInt = BigInt::from(1301081);
        let G: BigInt = BigInt::from(15486487);

        let length = 64_i64;
        drop(length);

        let mut mpvss = MPVSS::new();
        mpvss.q = q;
        mpvss.g = g;
        mpvss.G = G;

        let privatekey = BigInt::from(105929);
        let publickey = mpvss.generate_public_key(&privatekey);
        assert_eq!(publickey, BigInt::from(148446388));
    }
}
