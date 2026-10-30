// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! Torn reads of the SeqLock ring.
//!
//! One writer publishes pulses whose payload bytes are all equal to a
//! per-pulse fill value while several readers hammer `read_slot`. A read
//! that returns a pulse with mixed fill bytes is a torn read that the
//! sequence check failed to detect. The publish and read fences are what
//! make this hold on weakly ordered hardware such as aarch64; on x86 the
//! hardware's ordering would hide their absence.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use core_ring::PulseRing;
use pulse_canon::Pulse;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

fn filled_pulse(fill: u8) -> Pulse {
    let mut bytes = [fill; 128];
    bytes[..8].copy_from_slice(&[0u8; 8]); // seq_lock word is the ring's
    Pulse::from_array(&bytes)
}

#[test]
fn readers_never_observe_a_torn_pulse() {
    let name = format!("torn-read-{}", std::process::id());
    let capacity = 8u64;
    let mut ring = PulseRing::create(&name, capacity).expect("create ring");
    // The readers' handle: publishing takes the writer's `&mut`.
    let reader = Arc::new(PulseRing::open(&name, capacity).expect("attach readers"));
    let stop = Arc::new(AtomicBool::new(false));
    let reads = Arc::new(AtomicU64::new(0));
    let torn = Arc::new(AtomicU64::new(0));

    let readers: Vec<_> = (0..4)
        .map(|_| {
            let (ring, stop, reads, torn) =
                (reader.clone(), stop.clone(), reads.clone(), torn.clone());
            std::thread::spawn(move || {
                let mut slot = 0u64;
                while !stop.load(Ordering::Relaxed) {
                    if let Some(p) = ring.read_slot(slot % capacity) {
                        let b = p.as_bytes();
                        let fill = b[8];
                        if b[8..].iter().any(|&x| x != fill) {
                            torn.fetch_add(1, Ordering::Relaxed);
                        }
                        reads.fetch_add(1, Ordering::Relaxed);
                    }
                    slot = slot.wrapping_add(1);
                }
            })
        })
        .collect();

    let started = Instant::now();
    let mut i: u32 = 0;
    while started.elapsed() < Duration::from_millis(400) {
        let fill = (i % 250) as u8 + 1; // never 0: a zero seq means "empty"
        ring.publish(&filled_pulse(fill));
        i = i.wrapping_add(1);
    }
    stop.store(true, Ordering::Relaxed);
    for r in readers {
        r.join().unwrap();
    }
    assert!(i > 1000, "writer published too few pulses: {i}");
    assert!(
        reads.load(Ordering::Relaxed) > 1000,
        "readers saw too few pulses"
    );
    assert_eq!(torn.load(Ordering::Relaxed), 0, "torn reads observed");
}
