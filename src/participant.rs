use crate::mpvss::MPVSS;
use num_bigint::BigUint;

/// A participant represents one party in the secret sharing scheme. The participant can share a secret among a group of other participants and it is then called the "dealer".
/// The receiving participants that receive a part of the secret can use it to reconstruct the secret Therefore the partticipants need to collaborate and exchange their parts.
/// A participant represents as a Node in the Distributed Public NetWork
#[derive(Debug)]
pub struct Participant {
    pub mpvss_instance: MPVSS,
    pub private_key: BigUint,
    pub public_key: BigUint,
}

impl Participant {
    pub fn new(mpvss: MPVSS, privkey: BigUint, publickey: BigUint) -> Self {
        return Participant {
            mpvss_instance: mpvss,
            private_key: privkey,
            public_key: publickey,
        };
    }

    pub fn distribute() -> () {
        ()
    }

    pub fn extract_share() -> () {
        ()
    }
}
