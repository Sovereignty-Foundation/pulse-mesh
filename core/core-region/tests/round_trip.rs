// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! A pulse written through one handle is read back through another.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use core_region::PulseRegion;
use pulse_canon::Pulse;

fn filled(fill: u8) -> Pulse {
    let mut bytes = [fill; 128];
    bytes[..8].copy_from_slice(&[0u8; 8]); // seq_lock word belongs to the region
    Pulse::from_array(&bytes)
}

#[test]
fn a_write_is_visible_through_a_second_handle() {
    let name = format!("pr-rt-{}", std::process::id());
    let mut writer = PulseRegion::create(&name).expect("create");
    let reader = PulseRegion::open(&name).expect("open");
    assert!(reader.read().is_none(), "never written reads as None");
    writer.write(&filled(0x5A));
    let p = reader.read().expect("written region reads back");
    assert!(p.as_bytes()[8..].iter().all(|&b| b == 0x5A));
    assert_eq!(reader.seq_version(), 2);
}
