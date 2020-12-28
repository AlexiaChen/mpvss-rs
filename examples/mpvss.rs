// Copyright 2020 The MPVSS Authors.
//
// Code is licensed under AGPL License, Version 3.0.

use mpvss_rs::MPVSS;

fn main() {
    let mpvss = MPVSS::new();
    drop(mpvss);
}
