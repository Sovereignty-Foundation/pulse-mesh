// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! A lapped slot is never returned as new data, and `fetch` reports a
//! lapped id as gone.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use core_store::EnvelopeStore;
use pulse_canon::PulseEnvelope;

fn env(i: u64) -> PulseEnvelope {
    PulseEnvelope::new(1, i.to_le_bytes().to_vec())
}

fn payload_seq(e: &PulseEnvelope) -> u64 {
    let raw = e.payload().as_raw().expect("raw payload");
    u64::from_le_bytes(raw[..8].try_into().unwrap())
}

#[test]
fn read_since_and_fetch_respect_the_lap() {
    let name = format!("st-lap-{:x}", std::process::id());
    let store = EnvelopeStore::create_exclusive(&name, 4).expect("create");
    let envs: Vec<_> = (0..6).map(env).collect();
    for (i, e) in envs.iter().enumerate() {
        assert_eq!(store.store(e).expect("store"), i as u64);
    }
    let (got, next) = store.read_since(0);
    assert_eq!(next, 6);
    assert_eq!(
        got.iter().map(payload_seq).collect::<Vec<_>>(),
        vec![2, 3, 4, 5]
    );
    let (got, next) = store.read_since(4);
    assert_eq!((got.len(), next), (2, 6));
    let (got, next) = store.read_since(6);
    assert!(got.is_empty());
    assert_eq!(next, 6);
    assert!(store.fetch(&envs[0].id()).is_none(), "lapped id is gone");
    assert_eq!(
        store.fetch(&envs[5].id()).map(|e| e.id()),
        Some(envs[5].id())
    );
}
