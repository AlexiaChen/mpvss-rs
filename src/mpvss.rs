use ed25519_dalek::{Keypair, PublicKey, SecretKey, Signature, Signer};
use num_bigint::{BigInt, BigUint, RandBigInt, ToBigInt};
use num_integer::Integer;
use num_traits::identities::{One, Zero};
use rand::Rng;

pub enum KeyAlgorithm {
    Original,
    Ed25519,
}

pub struct MPVSS {
    pub q: BigInt,
    pub g: BigInt,
    pub G: BigInt,
    pub length: u32,
    pub key_algorithm: KeyAlgorithm,
}

impl MPVSS {
    pub fn new() -> Self {
        MPVSS {
            q: BigInt::zero(),
            g: BigInt::zero(),
            G: BigInt::zero(),
            length: 0,
            key_algorithm: KeyAlgorithm::Original,
        }
    }

    pub fn generate_ed25519_keypair() -> (SecretKey, PublicKey) {
        let mut csprng = rand::rngs::OsRng {};
        let keypair = Keypair::generate(&mut csprng);
        (keypair.secret, keypair.public)
    }

    pub fn generate_private_key(&self) -> BigInt {
        match self.key_algorithm {
            KeyAlgorithm::Original => {
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
            KeyAlgorithm::Ed25519 => {
                let (secret_key, _public_key) = MPVSS::generate_ed25519_keypair();
                BigInt::from_bytes_be(num_bigint::Sign::Plus, secret_key.as_bytes())
            }
        }
    }

    pub fn generate_public_key(&self, privkey: &BigInt) -> BigInt {
        match self.key_algorithm {
            KeyAlgorithm::Original => {
                // publicKey = G^privKey mod q
                self.G.modpow(privkey, &self.q)
            }
            KeyAlgorithm::Ed25519 => {
                let secret_key_bytes = privkey.to_bytes_be().1;
                let secret_key = SecretKey::from_bytes(&secret_key_bytes).unwrap();
                let public_key = PublicKey::from(&secret_key);
                BigInt::from_bytes_be(num_bigint::Sign::Plus, public_key.as_bytes())
            }
        }
    }
}
