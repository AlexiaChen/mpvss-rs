// Copyright 2020-2021  MathxH Chen.
//
// Code is licensed under GPLv3.0 License.

use mpvss_rs::Participant;
use num_bigint::{BigUint, ToBigInt};

fn main() {
    let secret_message = String::from("Hello MPVSS Example.");
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

    let share_boxs = [s1, s2, s3];
    let r1 = p1
        .mpvss
        .reconstruct(&share_boxs, &distribute_shares_box)
        .unwrap();
    let r2 = p2
        .mpvss
        .reconstruct(&share_boxs, &distribute_shares_box)
        .unwrap();
    let r3 = p3
        .mpvss
        .reconstruct(&share_boxs, &distribute_shares_box)
        .unwrap();

    let r1_str =
        String::from_utf8(r1.to_biguint().unwrap().to_bytes_be()).unwrap();
    assert_eq!(secret_message.clone(), r1_str);
    let r2_str =
        String::from_utf8(r2.to_biguint().unwrap().to_bytes_be()).unwrap();
    assert_eq!(secret_message.clone(), r2_str);
    let r3_str =
        String::from_utf8(r3.to_biguint().unwrap().to_bytes_be()).unwrap();
    assert_eq!(secret_message.clone(), r3_str);

    println!("secret message: {}", secret_message);
    println!("r1 str: {}", r1_str);
    println!("r2 str: {}", r2_str);
    println!("r3 str: {}", r3_str);
}
