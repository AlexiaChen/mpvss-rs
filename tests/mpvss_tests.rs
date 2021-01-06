// Copyright 2020-2021 The MPVSS Authors.
//
// Code is licensed under AGPL License, Version 3.0.

use mpvss_rs::Participant;
use num_bigint::{BigUint, ToBigInt};

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
    p1.initialize();
    p2.initialize();
    p3.initialize();

    let distribute_shares_box = dealer.distribute_secret(
        secret.to_bigint().unwrap(),
        vec![
            p1.publickey.clone(),
            p2.publickey.clone(),
            p3.publickey.clone(),
        ],
        3,
    );

    assert_eq!(
        p1.mpvss.verify_distribution_shares(&distribute_shares_box),
        true
    );

    assert_eq!(
        p2.mpvss.verify_distribution_shares(&distribute_shares_box),
        true
    );

    assert_eq!(
        p3.mpvss.verify_distribution_shares(&distribute_shares_box),
        true
    );

    // p1 extracts the share. [p2 and p3 do this as well.]
    let s1 = p1
        .extract_secret_share(&distribute_shares_box, &p1.privatekey)
        .unwrap();

    // p1, p2 and p3 exchange their descrypted shares.
    // ...
    let s2 = p2
        .extract_secret_share(&distribute_shares_box, &p2.privatekey)
        .unwrap();
    let s3 = p3
        .extract_secret_share(&distribute_shares_box, &p3.privatekey)
        .unwrap();

    // p1 verifies the share received from p2. [Actually everybody verifies every received share.]

    assert_eq!(
        p1.mpvss
            .verify(&s2, &distribute_shares_box.shares[&p2.publickey]),
        true
    );

    assert_eq!(
        p2.mpvss
            .verify(&s3, &distribute_shares_box.shares[&p3.publickey]),
        true
    );

    assert_eq!(
        p3.mpvss
            .verify(&s1, &distribute_shares_box.shares[&s1.publickey]),
        true
    );
}
