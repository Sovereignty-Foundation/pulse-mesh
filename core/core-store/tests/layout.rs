// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! `open` checks the region's size and header before trusting it.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use core_store::{EnvelopeStore, EnvelopeStoreError};

#[test]
fn open_checks_capacity_and_size() {
    let name = format!("st-lay-{:x}", std::process::id());
    let store = EnvelopeStore::create_exclusive(&name, 4).expect("create");
    assert!(
        EnvelopeStore::open(&name, 4).is_ok(),
        "matching capacity opens"
    );
    match EnvelopeStore::open(&name, 2) {
        Err(EnvelopeStoreError::LayoutMismatch { field, have, need }) => {
            assert_eq!(field, "capacity");
            assert_eq!(have, 4);
            assert_eq!(need, 2);
        }
        Err(other) => panic!("expected LayoutMismatch, got {other:?}"),
        Ok(_) => panic!("open with the wrong capacity must fail"),
    }
    match EnvelopeStore::open(&name, 1024) {
        Err(EnvelopeStoreError::RegionTooSmall { .. }) => {}
        Err(other) => panic!("expected RegionTooSmall, got {other:?}"),
        Ok(_) => panic!("an oversized request must be refused"),
    }
    drop(store);
}
