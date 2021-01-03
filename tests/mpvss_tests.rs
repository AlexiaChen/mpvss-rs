// Copyright 2020-2021 The MPVSS Authors.
//
// Code is licensed under AGPL License, Version 3.0.

use mpvss_rs::Participant;
use mpvss_rs::MPVSS;
use num_bigint::{BigInt, BigUint, ToBigInt};

#[test]
fn test_secret_str_utf8() {
    let secret_message = String::from("Hello MPVSS.");
    let secret = BigUint::from_bytes_be(&secret_message.as_bytes());
    assert_eq!(
        secret_message,
        String::from_utf8(secret.to_bytes_be()).unwrap()
    );
}

#[test]
fn test_mpvss_distribute_verify() {
    let secret_message = String::from("Hello MPVSS.");
    let secret = BigUint::from_bytes_be(&secret_message.as_bytes());
    let mut dealer = Participant::new();
    dealer.initialize();
    let mut p1 = Participant::new();
    let mut p2 = Participant::new();
    let mut p3 = Participant::new();
    p1.mpvss = dealer.mpvss.clone();
    p2.mpvss = dealer.mpvss.clone();
    p3.mpvss = dealer.mpvss.clone();
    p1.initialize();
    p2.initialize();
    p3.initialize();

    let distribute_shares_box = dealer.distribute_secret(
        secret.to_bigint().unwrap(),
        vec![p1.publickey, p2.publickey, p3.publickey],
        3,
    );

    assert_eq!(
        p1.mpvss.verify_distribution_shares(&distribute_shares_box),
        true
    );
}
