// Copyright 2020-2021 The MPVSS Author: MathxH Chen.
//
// Code is licensed under AGPL License, Version 3.0.

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
//! ## Build
//!
//! ```bash
//! cargo build --release
//! ```
//!
//! ## Test
//!
//! ```bash
//! cargo test --release
//! ```
//!
//! ## Example
//!
//! ```rust
//! cargo run --release --example mpvss
//! ```
//!
//! ### Usage
//!
//! #### Initialization
//!
//! At first we convert our secret message into a numeric value if necessary. When creating the dealer a PVSS instance is created as well which holds all the global parameters that every participant needs to know.
//!
//! ```rust
//! let secret_message = String::from("Hello MPVSS.");
//! let secret = BigUint::from_bytes_be(&secret_message.as_bytes());
//!
//! let mut dealer = Participant::new();
//! dealer.initialize();
//!
//! let mut p1 = Participant::new();
//! let mut p2 = Participant::new();
//! let mut p3 = Participant::new();
//!
//! p1.initialize();
//! p2.initialize();
//! p3.initialize();
//! ```
//!
//! #### Distribution & Verification
//!
//! The dealer splits the secret into shares, encrypts them and creates a proof so that everybody can verify that the shares (once decrypted) can be used to reconstruct the secret. The threshold determines how many shares are necessary for the reconstruction. The encrypted shares and the proof are then bundled together.
//!
//! ```rust
//! // Dealer that shares the secret among p1, p2 and p3.
//! let distribute_shares_box = dealer.distribute_secret(
//!         secret.to_bigint().unwrap(),
//!         vec![p1.publickey, p2.publickey, p3.publickey],
//!         3,
//!     );
//!
//! // p1 verifies distribution shares box containing encryted shares and proof of zero-knowlege. [p2 and p3 do this as well.]
//! assert_eq!(
//!     p1.mpvss.verify_distribution_shares(&distribute_shares_box),
//!     true
//! );
//! assert_eq!(
//!     p2.mpvss.verify_distribution_shares(&distribute_shares_box),
//!     true
//! );
//! assert_eq!(
//!     p3.mpvss.verify_distribution_shares(&distribute_shares_box),
//!     true
//! );
//! ```
//!
//! #### Exchange & Verification
//!
//! The participants extract their shares from the distribution shares box and decrypt them. They bundle them together with a proof that allows the receiver to verify that the share is indeed the result of the decryption.
//!
//! ```rust
//! // p1 extracts the share. [p2 and p3 do this as well.]
//! let s1 = p1
//!     .extract_secret_share(&distribute_shares_box, &p1.privatekey)
//!     .unwrap();
//!
//! // p1, p2 and p3 exchange their descrypted shares.
//! // ...
//! let s2 = p2
//!     .extract_secret_share(&distribute_shares_box, &p2.privatekey)
//!     .unwrap();
//! let s3 = p3
//!     .extract_secret_share(&distribute_shares_box, &p3.privatekey)
//!     .unwrap();
//!
//! // p1 verifies the share received from p2. [Actually everybody verifies every received share.]
//! assert_eq!(
//!     p1.mpvss
//!         .verify(&s2, &distribute_shares_box.shares[&p2.publickey]),
//!     true
//! );
//! assert_eq!(
//!     p2.mpvss
//!         .verify(&s3, &distribute_shares_box.shares[&p3.publickey]),
//!     true
//! );
//! assert_eq!(
//!     p3.mpvss
//!         .verify(&s1, &distribute_shares_box.shares[&s1.publickey]),
//!     true
//! );
//! ```
//!
//! #### Reconstruction
//!
//! Once a participant collected at least `threshold` shares the secret can be reconstructed.
//!
//! ```rust
//! let share_boxs = [s1, s2, s3];
//! let r1 = p1
//!     .mpvss
//!     .reconstruct(&share_boxs, &distribute_shares_box)
//!     .unwrap();
//! let r2 = p2
//!     .mpvss
//!     .reconstruct(&share_boxs, &distribute_shares_box)
//!     .unwrap();
//! let r3 = p3
//!     .mpvss
//!     .reconstruct(&share_boxs, &distribute_shares_box)
//!     .unwrap();
//!
//! let r1_str = String::from_utf8(r1.to_biguint().unwrap().to_bytes_be()).unwrap();
//! assert_eq!(secret_message.clone(), r1_str);
//! let r2_str = String::from_utf8(r2.to_biguint().unwrap().to_bytes_be()).unwrap();
//! assert_eq!(secret_message.clone(), r2_str);
//! let r3_str = String::from_utf8(r3.to_biguint().unwrap().to_bytes_be()).unwrap();
//! assert_eq!(secret_message.clone(), r3_str);
//! ```

mod dleq;
mod mpvss;
mod participant;
mod polynomial;
mod sharebox;
mod util;

pub use participant::Participant;
pub use sharebox::{DistributionSharesBox, ShareBox};
