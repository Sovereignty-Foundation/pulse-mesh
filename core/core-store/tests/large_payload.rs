// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! An entry holds the envelope's canonical bytes, so a payload of nearly
//! the whole entry round-trips and the limit is the canonical size.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use core_store::{EnvelopeStore, EnvelopeStoreError, MAX_ENTRY_SIZE};
use pulse_canon::envelope::MIN_CANONICAL_ENVELOPE;
use pulse_canon::{PulseEnvelope, PulseEnvelopeFlags};

#[test]
fn a_sixty_kilobyte_payload_round_trips() {
    let name = format!("st-big-{:x}", std::process::id());
    let store = EnvelopeStore::create_exclusive(&name, 4).expect("create");
    let payload: Vec<u8> = (0..60 * 1024u32).map(|i| (i % 251) as u8).collect();
    let mut sent = PulseEnvelope::typed_broadcast("bulk.blob", payload.clone());
    sent.origin = [7; 16];
    sent.monotonic_nanos = 42;
    let cursor = store.store(&sent).expect("a 60 KB payload fits one entry");

    let check = |got: &PulseEnvelope| {
        assert_eq!(got.id(), sent.id());
        assert!(got.verify());
        assert_eq!(got.origin, [7; 16]);
        assert_eq!(got.monotonic_nanos, 42);
        assert_eq!(got.type_name(), Some("bulk.blob"));
        assert_eq!(got.flags, PulseEnvelopeFlags::BROADCAST);
        assert_eq!(got.payload().as_raw(), Some(payload.as_slice()));
    };
    check(&store.fetch(&sent.id()).expect("fetch finds it"));
    let (got, next) = store.read_since(cursor);
    assert_eq!(next, cursor + 1);
    assert_eq!(got.len(), 1);
    check(&got[0]);
}

#[test]
fn the_entry_limit_is_the_canonical_size() {
    let name = format!("st-lim-{:x}", std::process::id());
    let store = EnvelopeStore::create_exclusive(&name, 2).expect("create");
    // An envelope with no type name and a raw payload spends
    // MIN_CANONICAL_ENVELOPE bytes on framing and the rest on its payload.
    let largest = MAX_ENTRY_SIZE - MIN_CANONICAL_ENVELOPE;
    let fits = PulseEnvelope::new(1, vec![0xA5; largest]);
    assert_eq!(fits.canonical_size(), MAX_ENTRY_SIZE);
    assert_eq!(store.store(&fits).expect("an entry-sized envelope"), 0);
    let found = store.fetch(&fits.id()).expect("fetch finds it");
    assert_eq!(found.payload_len(), largest);

    let over = PulseEnvelope::new(1, vec![0xA5; largest + 1]);
    match store.store(&over) {
        Err(EnvelopeStoreError::EnvelopeTooLarge { actual, max }) => {
            assert_eq!((actual, max), (MAX_ENTRY_SIZE + 1, MAX_ENTRY_SIZE));
        }
        other => panic!("expected EnvelopeTooLarge, got {other:?}"),
    }
    assert_eq!(
        store.write_cursor(),
        1,
        "a refused envelope claims no cursor"
    );
}
