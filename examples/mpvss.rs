// Copyright 2020-2021 The MPVSS Author: MathxH Chen.
//
// Code is licensed under AGPL License, Version 3.0.

use mpvss_rs::MPVSS;

fn main() {
    let mpvss = MPVSS::new();
    let secret_message = String::from("Hello MPVSS.");
    drop(mpvss);
    drop(secret_message);
}
