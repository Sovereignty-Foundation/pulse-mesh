// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! Opening a store with a larger capacity than its creator used must fail
//! instead of mapping past the end of the shared-memory object.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use core_store::{EnvelopeStore, EnvelopeStoreError};

#[test]
fn open_refuses_a_region_smaller_than_requested() {
    let name = format!("store-size-{}", std::process::id());
    let creator = EnvelopeStore::create(&name, 4).expect("create");
    assert!(
        matches!(
            EnvelopeStore::open(&name, 1024),
            Err(EnvelopeStoreError::RegionTooSmall { .. })
        ),
        "oversized open must be refused"
    );
    assert!(
        EnvelopeStore::open(&name, 4).is_ok(),
        "matching capacity opens"
    );
    drop(creator);
}
