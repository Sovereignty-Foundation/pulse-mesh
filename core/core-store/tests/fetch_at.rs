// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! A cursor names one stored copy. `fetch_at` returns the copy at that
//! cursor, with its own origin, time and flags, where `fetch` by id returns
//! a copy of the same content, the newest its index holds; and once a later
//! lap has overwritten the copy it returns nothing rather than the later
//! one.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use core_store::EnvelopeStore;
use pulse_canon::{PulseEnvelope, PulseEnvelopeFlags};

/// A store name private to this process and test.
fn name(tag: &str) -> String {
    format!("st-fat-{tag}-{:x}", std::process::id())
}

/// The same content from `origin` at `time`: the id is the same for every
/// origin and time.
fn reading(origin: u8, time: u64) -> PulseEnvelope {
    let mut envelope = PulseEnvelope::typed("sensor/level", b"42".to_vec());
    envelope.origin = [origin; 16];
    envelope.monotonic_nanos = time;
    envelope
}

#[test]
fn fetch_at_returns_the_copy_at_its_cursor_not_the_first_with_the_id() {
    let store = EnvelopeStore::create_exclusive(&name("copy"), 4).unwrap();
    let a = reading(0xaa, 100);
    let mut b = reading(0xbb, 200);
    b.flags = PulseEnvelopeFlags::BROADCAST;
    assert_eq!(
        a.id(),
        b.id(),
        "the id does not cover origin, time or flags"
    );
    let at_a = store.store(&a).unwrap();
    let at_b = store.store(&b).unwrap();

    let got_a = store.fetch_at(at_a, &a.id()).expect("A's copy");
    let got_b = store.fetch_at(at_b, &b.id()).expect("B's copy");
    assert_eq!((got_a.origin, got_a.monotonic_nanos), ([0xaa; 16], 100));
    assert_eq!((got_b.origin, got_b.monotonic_nanos), ([0xbb; 16], 200));
    assert_eq!(got_b.flags, PulseEnvelopeFlags::BROADCAST);
    assert_eq!(
        store.fetch(&a.id()).unwrap().origin,
        [0xbb; 16],
        "fetch by id takes the newest copy the index holds, whichever the caller meant"
    );
}

#[test]
fn fetch_at_refuses_a_lapped_copy_another_id_and_a_cursor_not_handed_out() {
    let store = EnvelopeStore::create_exclusive(&name("lap"), 2).unwrap();
    let envs: Vec<_> = (0..3u8).map(|i| reading(i, u64::from(i))).collect();
    // Three copies of one content through two slots: cursor 2 takes slot
    // 0 from cursor 0.
    for (i, e) in envs.iter().enumerate() {
        assert_eq!(store.store(e).unwrap(), i as u64);
    }
    let id = envs[0].id();
    assert!(
        store.fetch_at(0, &id).is_none(),
        "the copy at cursor 0 was overwritten; the one now in its slot is cursor 2's"
    );
    assert_eq!(store.fetch_at(1, &id).unwrap().origin, [1; 16]);
    assert_eq!(store.fetch_at(2, &id).unwrap().origin, [2; 16]);

    let other = PulseEnvelope::typed("sensor/level", b"43".to_vec());
    assert!(store.fetch_at(2, &other.id()).is_none(), "another id");
    assert!(store.fetch_at(3, &id).is_none(), "not handed out yet");
    assert!(store.fetch_at(u64::MAX, &id).is_none());
}
