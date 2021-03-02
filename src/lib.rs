// Copyright 2020-2021  MathxH Chen.
//
// Code is licensed under GPLv3.0 License.

//! # MPVSS - A Simple Publicly Verifiable Secret Sharing Library
//!
//! The library implements a simple PVSS scheme in Rust.
//!
//! ## What is PVSS?
//!
//! Secret sharing means a dealer can break a secret into secret shares among a group of participants which can reconstruct the secret only by collaboratively joining their parts of the secret. The library also implements threshold cryptography so that the dealer can decide whether all of the receiving participants need to collaborate or if a smaller subgroup of participants is sufficient to reconstruct the secret.
//!
//! In addition to the plain secret sharing scheme PVSS adds verifiability in the following way: All the parts the secret is split into are encrypted with the receivers' public keys respectively. The dealer publishes all the encrypted shares along with a non-interactive zero-knowledge proof that allows everbody (not only the receiving participants) to verify that the decrypted shares indeed can be used to reconstruct the secret. The participants then decrypt all their shares and exchange them along with another non-interactive zero-knowledge proof that allows the receiving participant to verify that the share is actually the result of the decryption.
//!
//! Thus PVSS can be used to share a secret among a group of participants so that either the secret can be reconstructed by the participants who all play fair or a participant that received a faked share can identify the malicious party.
//!
//! ## Documents
//!
//! See [Github README](https://github.com/AlexiaChen/mpvss-rs/blob/master/README.md)

mod dleq;
mod mpvss;
mod participant;
mod polynomial;
mod sharebox;
mod util;

pub use participant::Participant;
pub use sharebox::{DistributionSharesBox, ShareBox};

use num_bigint::{BigInt, BigUint, ToBigInt};

pub fn string_to_secret(message: &str) -> BigInt {
    BigUint::from_bytes_be(&message.as_bytes())
        .to_bigint()
        .unwrap()
}

pub fn string_from_secret(secret: &BigInt) -> String {
    String::from_utf8(secret.to_biguint().unwrap().to_bytes_be()).unwrap()
}
