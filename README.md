# MPVSS - A Simple Publicly Verifiable Secret Sharing Library

[![CI](https://img.shields.io/github/actions/workflow/status/AlexiaChen/mpvss-rs/ci.yml?branch=master)](https://github.com/AlexiaChen/mpvss-rs/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/actions/workflow/status/AlexiaChen/mpvss-rs/release.yml?branch=release)](https://github.com/AlexiaChen/mpvss-rs/actions/workflows/release.yml)
[![Crates.io](https://img.shields.io/crates/v/mpvss-rs)](https://crates.io/crates/mpvss-rs)
[![License](https://img.shields.io/crates/l/mpvss-rs)](https://github.com/AlexiaChen/mpvss-rs)

The library implements a simple PVSS scheme in Rust with support for multiple cryptographic groups through a generic trait abstraction.

## What is PVSS?

Secret sharing means a dealer can break a secret into secret shares among a group of participants which can reconstruct the secret only by collaboratively joining their parts of the secret. The library also implements threshold cryptography so that the dealer can decide whether all of the receiving participants need to collaborate or if a smaller subgroup of participants is sufficient to reconstruct the secret.

In addition to the plain secret sharing scheme PVSS adds verifiability in the following way: All the parts the secret is split into are encrypted with the receivers' public keys respectively. The dealer publishes all the encrypted shares along with a non-interactive zero-knowledge proof that allows everbody (not only the receiving participants) to verify that the decrypted shares indeed can be used to reconstruct the secret. The participants then decrypt all their shares and exchange them along with another non-interactive zero-knowledge proof that allows the receiving participant to verify that the share is actually the result of the decryption.

Thus PVSS can be used to share a secret among a group of participants so that either the secret can be reconstructed by the participants who all play fair or a participant that received a faked share can identify the malicious party.

## Build

```bash
# Build all features
cargo build --release
```

## Test

```bash
# Run all tests
cargo test --release
```

## Examples

```bash
# MODP group examples (default)
cargo run --release --example mpvss_all
cargo run --release --example mpvss_sub

# secp256k1 elliptic curve examples
cargo run --release --example mpvss_all_secp256k1
cargo run --release --example mpvss_sub_secp256k1
```

### Usage

#### Initialization

First, create a cryptographic group instance (e.g., `ModpGroup`) and initialize participants with key pairs.

```rust
use mpvss_rs::groups::ModpGroup;
use mpvss_rs::Participant;

let secret_message = String::from("Hello MPVSS.");

// Create the group (returns Arc<ModpGroup>)
let group = ModpGroup::new();

// Create dealer and participants with the group
let mut dealer = Participant::with_arc(group.clone());
dealer.initialize();

let mut p1 = Participant::with_arc(group.clone());
let mut p2 = Participant::with_arc(group.clone());
let mut p3 = Participant::with_arc(group.clone());

p1.initialize();
p2.initialize();
p3.initialize();
```

#### Distribution & Verification

The dealer splits the secret into shares, encrypts them and creates a proof so that everybody can verify that the shares (once decrypted) can be used to reconstruct the secret. The threshold determines how many shares are necessary for the reconstruction. The encrypted shares and the proof are then bundled together.

```rust
// Dealer that shares the secret among p1, p2 and p3.
let distribute_shares_box = dealer.distribute_secret(
        &string_to_secret(&secret_message),
        &vec![p1.publickey.clone(), p2.publickey.clone(), p3.publickey.clone()],
        3,
    );

// p1 verifies distribution shares box containing encryted shares and proof of zero-knowlege. [p2 and p3 do this as well.]
assert_eq!(p1.verify_distribution_shares(&distribute_shares_box), true);
assert_eq!(p2.verify_distribution_shares(&distribute_shares_box), true);
assert_eq!(p3.verify_distribution_shares(&distribute_shares_box), true);
```

#### Exchange & Verification

The participants extract their shares from the distribution shares box and decrypt them. They bundle them together with a proof that allows the receiver to verify that the share is indeed the result of the decryption.

```rust
// Generate random witness for share extraction
use num_bigint::RandBigInt;
let mut rng = rand::thread_rng();
let w: num_bigint::BigInt = rng
    .gen_biguint_below(&group.modulus().to_biguint().unwrap())
    .to_bigint()
    .unwrap();

// p1 extracts the share. [p2 and p3 do this as well.]
let s1 = p1
    .extract_secret_share(&distribute_shares_box, &p1.privatekey, &w)
    .unwrap();

// p1, p2 and p3 exchange their descrypted shares.
// ...
let s2 = p2
    .extract_secret_share(&distribute_shares_box, &p2.privatekey, &w)
    .unwrap();
let s3 = p3
    .extract_secret_share(&distribute_shares_box, &p3.privatekey, &w)
    .unwrap();

// p1 verifies the share received from p2. [Actually everybody verifies every received share.]
assert_eq!(p1.verify_share(&s2, &distribute_shares_box, &p2.publickey), true);
assert_eq!(p2.verify_share(&s3, &distribute_shares_box, &p3.publickey), true);
assert_eq!(p3.verify_share(&s1, &distribute_shares_box, &s1.publickey), true);
```

#### Reconstruction

Once a participant collected at least `threshold` shares the secret can be reconstructed.

```rust
let share_boxs = [s1, s2, s3];
let r1 = p1.reconstruct(&share_boxs, &distribute_shares_box).unwrap();
let r2 = p2.reconstruct(&share_boxs, &distribute_shares_box).unwrap();
let r3 = p3.reconstruct(&share_boxs, &distribute_shares_box).unwrap();

let r1_str = string_from_secret(&r1);
assert_eq!(secret_message.clone(), r1_str);
let r2_str = string_from_secret(&r2);
assert_eq!(secret_message.clone(), r2_str);
let r3_str = string_from_secret(&r3);
assert_eq!(secret_message.clone(), r3_str);
```

### Generic Group Support

The library supports multiple cryptographic groups through a generic `Group` trait:

- **`ModpGroup`**: 2048-bit MODP group (RFC 3526) - Default implementation
- **`Secp256k1Group`**: secp256k1 elliptic curve (Bitcoin's curve) - Always available

The `Participant<G>` struct is generic over the group type, allowing the same PVSS operations to work with different cryptographic backends. The Rust compiler automatically selects the correct implementation based on the group type, so you use the same method names for all groups.

#### secp256k1 Usage

To use secp256k1 elliptic curve cryptography:

```rust
use mpvss_rs::groups::Secp256k1Group;
use mpvss_rs::Participant;
use mpvss_rs::group::Group; // Import Group trait for method access

let secret_message = String::from("Hello MPVSS (secp256k1).");

// Create the group (returns Arc<Secp256k1Group>)
let group = Secp256k1Group::new();

// Create dealer and participants with the group
let mut dealer = Participant::with_arc(group.clone());
dealer.initialize();

let mut p1 = Participant::with_arc(Secp256k1Group::new());
let mut p2 = Participant::with_arc(Secp256k1Group::new());
let mut p3 = Participant::with_arc(Secp256k1Group::new());

p1.initialize();
p2.initialize();
p3.initialize();

// Distribution - same method names as MODP
let distribute_shares_box = dealer.distribute_secret(
    &string_to_secret(&secret_message),
    &vec![p1.publickey.clone(), p2.publickey.clone(), p3.publickey.clone()],
    3,
);

// Verification - same method names
assert_eq!(p1.verify_distribution_shares(&distribute_shares_box), true);

// Share extraction
let w = group.generate_private_key(); // No need for BigInt RNG with secp256k1
let s1 = p1.extract_secret_share(&distribute_shares_box, &p1.privatekey, &w).unwrap();

// Reconstruction - same method names
let share_boxs = [s1, s2, s3];
let r1 = p1.reconstruct(&share_boxs, &distribute_shares_box).unwrap();
```

**Key Differences for secp256k1:**
- Elements are EC points (`k256::AffinePoint`) instead of `BigInt`
- Scalars are `k256::Scalar` (32 bytes) instead of `BigInt`
- Method names are the same as MODP (no suffix needed)
- Private keys are generated via `group.generate_private_key()` instead of manual BigInt RNG
- `Scalar::from_repr` expects big-endian byte representation

## Related References:

- Berry Schoenmakers. [A Simple Publicly Verifiable Secret Sharing Scheme and its Application to Electronic Voting](https://www.win.tue.nl/~berry/papers/crypto99.pdf)

- Adi Shamir. [How to share a secret](http://users.cms.caltech.edu/~vidick/teaching/101_crypto/Shamir1979.pdf)

- Tal Rabin. [Verifiable Secret Sharing and Multiparty Protocols with Honest Majority](https://www.cs.umd.edu/users/gasarch/TOPICS/secretsharing/rabinVSS.pdf)

- Markus Stadler. [Publicly Verifiable Secret Sharing](https://link.springer.com/content/pdf/10.1007%2F3-540-68339-9_17.pdf)

- bitcoinwiki-org. [Publicly Verifiable Secret Sharing](https://en.bitcoinwiki.org/wiki/Publicly_Verifiable_Secret_Sharing)

## Non-Related References

Because the ploynomial commitments does not Pedersen commitment and DLEQ is only computaional secure, not information-theoretic secure in this project.

- crypto-stackexchange. [What is a Pedersen commitment?](https://crypto.stackexchange.com/questions/64437/what-is-a-pedersen-commitment)

- Torben Pryds Pedersen. [Non-Interactive and Information-Theoretic Secure Verifiable Secret Sharing](https://link.springer.com/content/pdf/10.1007%2F3-540-46766-1_9.pdf)

- Chunming Tang. Dingyi Pei. [Non-Interactive and Information-Theoretic Secure Publicly Verifiable Secret Sharing](https://eprint.iacr.org/2004/201.pdf)

## License
Dual-licensed to be compatible with the Rust project.

Licensed under the Apache License, Version 2.0 [http://www.apache.org/licenses/LICENSE-2.0](http://www.apache.org/licenses/LICENSE-2.0) or the MIT license [http://opensource.org/licenses/MIT](http://opensource.org/licenses/MIT), at your option. This file may not be copied, modified, or distributed except according to those terms.
