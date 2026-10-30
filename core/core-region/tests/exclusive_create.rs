// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! `create_exclusive` refuses an existing object; `create_or_open` attaches
//! to it without re-initialising it.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use core_region::{PulseRegion, ShmError};
use pulse_canon::Pulse;

fn filled(fill: u8) -> Pulse {
    let mut bytes = [fill; 128];
    bytes[..8].copy_from_slice(&[0u8; 8]); // seq_lock word belongs to the region
    Pulse::from_array(&bytes)
}

#[test]
fn exclusive_create_refuses_an_existing_region() {
    let name = format!("pr-excl-{}", std::process::id());
    let first = PulseRegion::create_exclusive(&name).expect("first create");
    match PulseRegion::create_exclusive(&name) {
        Err(ShmError::Open(e)) => assert_eq!(e, libc::EEXIST),
        Err(other) => panic!("expected EEXIST, got {other:?}"),
        Ok(_) => panic!("second exclusive create must fail"),
    }
    drop(first);
}

#[test]
fn create_or_open_attaches_without_clobbering() {
    let name = format!("pr-coo-{}", std::process::id());
    let mut first = PulseRegion::create_or_open(&name).expect("create");
    first.write(&filled(0x33));
    let second = PulseRegion::create_or_open(&name).expect("attach");
    let p = second.read().expect("attached handle sees the pulse");
    assert!(p.as_bytes()[8..].iter().all(|&b| b == 0x33));
    assert_eq!(second.seq_version(), 2);
}
