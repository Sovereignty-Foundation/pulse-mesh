// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! An absurd store capacity is an error, not a panic or a wrap.
//!
//! Every constructor checks the capacity (at least one slot, within the
//! header's 32-bit field) and its size first, and refuses it with
//! `InvalidCapacity` before it creates or opens anything.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use core_store::{EnvelopeStore, EnvelopeStoreError};

type Constructor = fn(&str, usize) -> Result<EnvelopeStore, EnvelopeStoreError>;

const CONSTRUCTORS: [(&str, Constructor); 4] = [
    ("create", EnvelopeStore::create),
    ("create_exclusive", EnvelopeStore::create_exclusive),
    ("create_or_open", EnvelopeStore::create_or_open),
    ("open", EnvelopeStore::open),
];

/// Zero, one past what the header records, and past any `usize` product.
const ABSURD: [usize; 3] = [0, u32::MAX as usize + 1, usize::MAX];

fn expect_invalid(result: Result<EnvelopeStore, EnvelopeStoreError>, what: &str, capacity: usize) {
    match result {
        Err(EnvelopeStoreError::InvalidCapacity { capacity: c }) => {
            assert_eq!(c, capacity, "{what}");
        }
        Err(other) => panic!("{what}({capacity}): expected InvalidCapacity, got {other:?}"),
        Ok(_) => panic!("{what}({capacity}) must be refused"),
    }
}

#[test]
fn an_absurd_capacity_is_refused_before_anything_is_created() {
    let name = format!("st-cap-{:x}", std::process::id());
    EnvelopeStore::unlink(&name).unwrap();
    for capacity in ABSURD {
        for (what, make) in CONSTRUCTORS {
            expect_invalid(make(&name, capacity), what, capacity);
            assert!(
                !EnvelopeStore::unlink(&name).unwrap(),
                "{what}({capacity}) left an object under {name}"
            );
        }
    }
}

#[test]
fn an_absurd_capacity_is_refused_over_a_live_store_which_is_left_alone() {
    let name = format!("st-cap-live-{:x}", std::process::id());
    EnvelopeStore::unlink(&name).unwrap();
    let store = EnvelopeStore::create_exclusive(&name, 4).expect("create");
    let envelope = pulse_canon::PulseEnvelope::new(1, b"kept".to_vec());
    store.store(&envelope).expect("store");
    for capacity in ABSURD {
        for (what, make) in CONSTRUCTORS {
            expect_invalid(make(&name, capacity), what, capacity);
        }
    }
    // The live store is untouched, and still opens at its own capacity.
    let reader = EnvelopeStore::open(&name, 4).expect("open at the real capacity");
    assert_eq!(reader.write_cursor(), 1);
    let found = reader.fetch(&envelope.id()).expect("the stored envelope");
    assert_eq!(found.id(), envelope.id());
}
