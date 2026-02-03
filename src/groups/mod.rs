// Copyright 2020-2024 MathxH Chen.
//
// Code is licensed under GPLv3.0 License.

//! Group implementations for PVSS scheme.
//!
//! This module provides concrete implementations of the `Group` trait for various
//! cryptographic backends:
//! - `modp`: MODP group using RFC 3526 2048-bit safe prime
//! - `secp256k1`: secp256k1 elliptic curve (Bitcoin's curve)

pub mod modp;

#[cfg(feature = "secp256k1")]
pub mod secp256k1;

// Re-export commonly used types
pub use modp::ModpGroup;

#[cfg(feature = "secp256k1")]
pub use secp256k1::Secp256k1Group;
