use crate::mpvss::MPVSS;
use num_bigint::BigUint;
use num_traits::identities::Zero;
use std::clone::Clone;

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

    pub fn distribute() -> () {
        ()
    }

    pub fn extract_share() -> () {
        ()
    }
}
