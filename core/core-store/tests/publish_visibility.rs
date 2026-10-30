// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! Readers never observe an envelope before its body is fully written.
//!
//! One writer stores envelopes whose payload is the cursor followed by a
//! run of one fill byte while several readers stream with `read_since`.
//! Every returned envelope must verify, carry a uniform fill, and fall in
//! cursor order inside the window the call reported: a reader racing the
//! writer must never return the previous lap's envelope for a cursor still
//! being written.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use core_store::EnvelopeStore;
use pulse_canon::PulseEnvelope;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[test]
fn readers_only_see_published_envelopes() {
    let name = format!("st-vis-{:x}", std::process::id());
    let store = Arc::new(EnvelopeStore::create_exclusive(&name, 4).expect("create"));
    let stop = Arc::new(AtomicBool::new(false));
    let seen = Arc::new(AtomicU64::new(0));
    let violations = Arc::new(AtomicU64::new(0));

    let readers: Vec<_> = (0..4)
        .map(|_| {
            let (store, stop, seen, violations) = (
                store.clone(),
                stop.clone(),
                seen.clone(),
                violations.clone(),
            );
            std::thread::spawn(move || {
                let mut since = 0u64;
                while !stop.load(Ordering::Relaxed) {
                    let (envs, next) = store.read_since(since);
                    let mut last: Option<u64> = None;
                    for e in envs {
                        seen.fetch_add(1, Ordering::Relaxed);
                        if !e.verify() {
                            violations.fetch_add(1, Ordering::Relaxed);
                            continue;
                        }
                        let raw = e.payload().as_raw().expect("raw payload");
                        let seq = u64::from_le_bytes(raw[..8].try_into().unwrap());
                        let fill = raw[8];
                        if raw[8..].iter().any(|&b| b != fill) {
                            violations.fetch_add(1, Ordering::Relaxed);
                        }
                        if seq < since || seq >= next || last.is_some_and(|l| seq <= l) {
                            violations.fetch_add(1, Ordering::Relaxed);
                        }
                        last = Some(seq);
                    }
                    since = next;
                }
            })
        })
        .collect();

    let started = Instant::now();
    let mut i: u64 = 0;
    while started.elapsed() < Duration::from_millis(400) {
        let fill = (i % 250) as u8 + 1;
        let mut payload = i.to_le_bytes().to_vec();
        payload.extend_from_slice(&[fill; 200]);
        let cursor = store.store(&PulseEnvelope::new(1, payload)).expect("store");
        assert_eq!(cursor, i);
        i += 1;
    }
    stop.store(true, Ordering::Relaxed);
    for r in readers {
        r.join().unwrap();
    }
    assert!(i > 1000, "writer stored too few envelopes: {i}");
    assert!(
        seen.load(Ordering::Relaxed) > 1000,
        "readers saw too few envelopes"
    );
    assert_eq!(
        violations.load(Ordering::Relaxed),
        0,
        "unpublished or torn data observed"
    );
}
