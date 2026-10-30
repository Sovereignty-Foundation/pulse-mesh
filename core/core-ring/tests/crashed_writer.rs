// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! Crashed-writer recovery for the SeqLock ring.
//!
//! A writer that dies between its odd mark and its even mark leaves the
//! slot's counter odd. Readers must give up on that slot rather than hand
//! back a torn Pulse, and the next publish into the slot must re-base the
//! counter so the slot becomes readable again: marks computed from the odd
//! value would keep the slot odd for ever.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use core_ring::PulseRing;
use pulse_canon::Pulse;
use std::sync::atomic::Ordering;

fn filled_pulse(fill: u8) -> Pulse {
    let mut bytes = [fill; 128];
    bytes[..8].copy_from_slice(&[0u8; 8]); // seq_lock word is the ring's
    Pulse::from_array(&bytes)
}

/// One publish path under test.
type Publish = Box<dyn Fn(&mut PulseRing)>;

/// Simulate a writer that died after its odd mark.
fn poison(ring: &PulseRing, slot: u64) {
    let seq = ring.slot_seq_atomic(slot);
    seq.store(seq.load(Ordering::Acquire) | 1, Ordering::Release);
}

#[test]
fn poisoned_slot_is_unreadable_then_recovers_on_publish() {
    let name = format!("crw-pub-{}", std::process::id());
    let mut ring = PulseRing::create(&name, 4).expect("create ring");
    ring.publish(&filled_pulse(1)); // slot 0, counter 2
    poison(&ring, 0);
    assert!(ring.read_slot(0).is_none(), "an odd counter must not read");
    for fill in 2..=5u8 {
        ring.publish(&filled_pulse(fill)); // slots 1, 2, 3, then 0 again
    }
    let seq = ring.slot_seq_atomic(0).load(Ordering::Acquire);
    assert_eq!(seq & 1, 0, "publish must re-base an odd counter, got {seq}");
    let p = ring
        .read_slot(0)
        .expect("slot 0 readable after the re-base");
    assert!(p.as_bytes()[8..].iter().all(|&b| b == 5), "stale payload");
}

#[test]
fn every_publish_variant_rebases_an_odd_counter() {
    let pid = std::process::id();
    let cases: Vec<(&str, Publish)> = vec![
        (
            "ret",
            Box::new(|r| {
                r.publish_returning_slot(&filled_pulse(9));
            }),
        ),
        (
            "at",
            Box::new(|r| {
                r.publish_at_slot(0, &filled_pulse(9));
            }),
        ),
        (
            "batch",
            Box::new(|r| {
                r.publish_batch(&[filled_pulse(9)])
                    .expect("a one-pulse batch fits a one-slot ring");
            }),
        ),
        (
            "crc",
            Box::new(|r| {
                r.publish_with_crc(&filled_pulse(9));
            }),
        ),
    ];
    for (tag, publish) in cases {
        let name = format!("crw-{tag}-{pid}");
        let mut ring = PulseRing::create(&name, 1).expect("create ring");
        poison(&ring, 0);
        publish(&mut ring);
        let seq = ring.slot_seq_atomic(0).load(Ordering::Acquire);
        assert_eq!(seq & 1, 0, "{tag}: counter still odd ({seq})");
        let readable = match tag {
            "crc" => ring.read_slot_verify_crc(0).expect("crc ok").is_some(),
            _ => ring.read_slot(0).is_some(),
        };
        assert!(readable, "{tag}: slot unreadable after the re-base");
    }
}
