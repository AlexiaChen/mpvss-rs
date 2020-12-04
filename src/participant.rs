use crate::mpvss::MPVSS;
use num_bigint::BigUint;

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
