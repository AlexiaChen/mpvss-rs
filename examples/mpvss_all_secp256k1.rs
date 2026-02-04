// Copyright 2020-2024 MathxH Chen.
//
// Code is licensed under GPLv3.0 License.

use mpvss_rs::Participant;
use mpvss_rs::group::Group;
use mpvss_rs::groups::Secp256k1Group;
use mpvss_rs::{string_from_secret, string_to_secret};

fn main() {
    let group = Secp256k1Group::new();
    let secret_message = String::from("Hello MPVSS Example (secp256k1).");
    let mut dealer = Participant::with_arc(group.clone());
    dealer.initialize();
    let mut p1 = Participant::with_arc(Secp256k1Group::new());
    let mut p2 = Participant::with_arc(Secp256k1Group::new());
    let mut p3 = Participant::with_arc(Secp256k1Group::new());
    p1.initialize();
    p2.initialize();
    p3.initialize();

    let publickeys = vec![
        p1.publickey.clone(),
        p2.publickey.clone(),
        p3.publickey.clone(),
    ];

    let distribute_shares_box = dealer.distribute_secret_secp256k1(
        &string_to_secret(&secret_message),
        &publickeys,
        3,
    );

    assert_eq!(
        p1.verify_distribution_shares_secp256k1(&distribute_shares_box),
        true
    );
    assert_eq!(
        p2.verify_distribution_shares_secp256k1(&distribute_shares_box),
        true
    );
    assert_eq!(
        p3.verify_distribution_shares_secp256k1(&distribute_shares_box),
        true
    );

    // p1 extracts the share. [p2 and p3 do this as well.]
    let w = group.generate_private_key();

    let s1 = p1
        .extract_secret_share_secp256k1(
            &distribute_shares_box,
            &p1.privatekey,
            &w,
        )
        .unwrap();

    // p1, p2 and p3 exchange their decrypted shares.
    let s2 = p2
        .extract_secret_share_secp256k1(
            &distribute_shares_box,
            &p2.privatekey,
            &w,
        )
        .unwrap();
    let s3 = p3
        .extract_secret_share_secp256k1(
            &distribute_shares_box,
            &p3.privatekey,
            &w,
        )
        .unwrap();

    // p1 verifies the share received from p2. [Actually everybody verifies every received share.]
    assert_eq!(
        p1.verify_share_secp256k1(&s2, &distribute_shares_box, &p2.publickey),
        true
    );

    assert_eq!(
        p2.verify_share_secp256k1(&s3, &distribute_shares_box, &p3.publickey),
        true
    );

    assert_eq!(
        p3.verify_share_secp256k1(&s1, &distribute_shares_box, &s1.publickey),
        true
    );

    let share_boxs = [s1, s2, s3];
    let r1 = dealer
        .reconstruct_secp256k1(&share_boxs, &distribute_shares_box)
        .unwrap();
    let r2 = dealer
        .reconstruct_secp256k1(&share_boxs, &distribute_shares_box)
        .unwrap();
    let r3 = dealer
        .reconstruct_secp256k1(&share_boxs, &distribute_shares_box)
        .unwrap();

    let r1_str = string_from_secret(&r1);
    assert_eq!(secret_message.clone(), r1_str);
    let r2_str = string_from_secret(&r2);
    assert_eq!(secret_message.clone(), r2_str);
    let r3_str = string_from_secret(&r3);
    assert_eq!(secret_message.clone(), r3_str);

    println!("secret message: {}", secret_message);
    println!("r1 str: {}", r1_str);
    println!("r2 str: {}", r2_str);
    println!("r3 str: {}", r3_str);
}
