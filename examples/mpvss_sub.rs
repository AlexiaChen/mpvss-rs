// Copyright 2020-2024 MathxH Chen.
//
// Code is licensed under GPLv3.0 License.

use mpvss_rs::Participant;
use mpvss_rs::groups::ModpGroup;
use mpvss_rs::{string_from_secret, string_to_secret};
use num_bigint::{RandBigInt, ToBigInt};

fn main() {
    let group = ModpGroup::new();
    let secret_message = String::from("Hello Sub MPVSS Example.");
    let mut dealer = Participant::with_arc(group.clone());
    dealer.initialize();
    let mut p1 = Participant::with_arc(ModpGroup::new());
    let mut p2 = Participant::with_arc(ModpGroup::new());
    let mut p3 = Participant::with_arc(ModpGroup::new());
    let mut p4 = Participant::with_arc(ModpGroup::new());
    p1.initialize();
    p2.initialize();
    p3.initialize();
    p4.initialize();

    let publickeys = vec![
        p1.publickey.clone(),
        p2.publickey.clone(),
        p3.publickey.clone(),
        p4.publickey.clone(),
    ];

    let distribute_shares_box = dealer.distribute_secret_modp(
        &string_to_secret(&secret_message),
        &publickeys,
        3,
    );

    assert_eq!(
        p1.verify_distribution_shares_modp(&distribute_shares_box),
        true
    );
    assert_eq!(
        p2.verify_distribution_shares_modp(&distribute_shares_box),
        true
    );
    assert_eq!(
        p3.verify_distribution_shares_modp(&distribute_shares_box),
        true
    );
    assert_eq!(
        p4.verify_distribution_shares_modp(&distribute_shares_box),
        true
    );

    // p1 extracts the share. [p2, p3 and p4 do this as well.]
    let mut rng = rand::thread_rng();
    let w: num_bigint::BigInt = rng
        .gen_biguint_below(&group.modulus().to_biguint().unwrap())
        .to_bigint()
        .unwrap();

    let s1 = p1
        .extract_secret_share_modp(&distribute_shares_box, &p1.privatekey, &w)
        .unwrap();

    // p1, p2, p3, p4 exchange their descrypted shares.
    let s2 = p2
        .extract_secret_share_modp(&distribute_shares_box, &p2.privatekey, &w)
        .unwrap();
    let s3 = p3
        .extract_secret_share_modp(&distribute_shares_box, &p3.privatekey, &w)
        .unwrap();
    let s4 = p4
        .extract_secret_share_modp(&distribute_shares_box, &p4.privatekey, &w)
        .unwrap();

    // p1 verifies the share received from p2. [Actually everybody verifies every received share.]
    assert_eq!(
        p1.verify_share_modp(&s2, &distribute_shares_box, &p2.publickey),
        true
    );

    assert_eq!(
        p2.verify_share_modp(&s3, &distribute_shares_box, &p3.publickey),
        true
    );

    assert_eq!(
        p3.verify_share_modp(&s1, &distribute_shares_box, &s1.publickey),
        true
    );

    assert_eq!(
        p4.verify_share_modp(&s2, &distribute_shares_box, &s2.publickey),
        true
    );

    // Threshold is 3, so p1, p2, p4 can reconstruct (or any 3 participants)
    let share_boxs = [s1.clone(), s2.clone(), s4.clone()];
    let r1 = dealer
        .reconstruct_modp(&share_boxs, &distribute_shares_box)
        .unwrap();
    let r2 = dealer
        .reconstruct_modp(&share_boxs, &distribute_shares_box)
        .unwrap();
    let r3 = dealer
        .reconstruct_modp(&share_boxs, &distribute_shares_box)
        .unwrap();
    let r4 = dealer
        .reconstruct_modp(&share_boxs, &distribute_shares_box)
        .unwrap();

    let r1_str = string_from_secret(&r1);
    assert_eq!(secret_message.clone(), r1_str);
    let r2_str = string_from_secret(&r2);
    assert_eq!(secret_message.clone(), r2_str);
    let r3_str = string_from_secret(&r3);
    assert_eq!(secret_message.clone(), r3_str);
    let r4_str = string_from_secret(&r4);
    assert_eq!(secret_message.clone(), r4_str);

    println!("secret message: {}", secret_message);
    println!("r1 str: {}", r1_str);
    println!("r2 str: {}", r2_str);
    println!("r3 str: {}", r3_str);
    println!("r4 str: {}", r4_str);
}
