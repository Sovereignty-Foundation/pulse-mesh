// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! A counter left odd by a dead writer must not hang readers, and the next
//! write must heal it.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use core_region::PulseRegion;
use pulse_canon::Pulse;
use std::sync::atomic::Ordering;
use std::time::Duration;

fn filled(fill: u8) -> Pulse {
    let mut bytes = [fill; 128];
    bytes[..8].copy_from_slice(&[0u8; 8]); // seq_lock word belongs to the region
    Pulse::from_array(&bytes)
}

#[test]
fn a_poisoned_counter_bounds_the_read_and_the_next_write_heals_it() {
    let name = format!("pr-poison-{}", std::process::id());
    let mut region = PulseRegion::create(&name).expect("create");
    region.write(&filled(0x11));
    region.seq_atomic().fetch_or(1, Ordering::Release); // writer died after its odd mark

    let (tx, rx) = std::sync::mpsc::channel();
    let reader_name = name.clone();
    std::thread::spawn(move || {
        let reader = PulseRegion::open(&reader_name).expect("open");
        let _ = tx.send(reader.read().is_none());
    });
    let gave_up = rx
        .recv_timeout(Duration::from_secs(2))
        .expect("read must return within its spin budget");
    assert!(gave_up, "a poisoned counter must read as None");

    region.write(&filled(0x22));
    assert_eq!(
        region.seq_atomic().load(Ordering::Acquire) & 1,
        0,
        "write must re-base"
    );
    let p = region.read().expect("healed region reads back");
    assert!(p.as_bytes()[8..].iter().all(|&b| b == 0x22));
}
