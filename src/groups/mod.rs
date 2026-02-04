// Copyright 2020-2026 MathxH Chen.
//
// Code is licensed under MIT Apache Dual License

//! Group implementations for PVSS scheme.
//!
//! This module provides concrete implementations of the `Group` trait for various
//! cryptographic backends:
//! - `modp`: MODP group using RFC 3526 2048-bit safe prime
//! - `secp256k1`: secp256k1 elliptic curve (Bitcoin's curve)

pub mod modp;

pub mod secp256k1;

// Re-export commonly used types
pub use modp::ModpGroup;

pub use secp256k1::Secp256k1Group;
