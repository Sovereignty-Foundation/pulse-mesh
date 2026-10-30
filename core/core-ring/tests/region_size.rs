// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! Opening a ring with a larger capacity than its creator used must fail
//! instead of mapping past the end of the shared-memory object.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use core_ring::{PulseRing, RingError};

#[test]
fn open_refuses_a_region_smaller_than_requested() {
    let name = format!("region-size-{}", std::process::id());
    let creator = PulseRing::create(&name, 4).expect("create");
    let err = PulseRing::open(&name, 1024)
        .err()
        .expect("oversized open must fail");
    match err {
        RingError::RegionTooSmall { have, need } => assert!(have < need, "{have} < {need}"),
        other => panic!("expected RegionTooSmall, got {other:?}"),
    }
    assert!(PulseRing::open(&name, 4).is_ok(), "matching capacity opens");
    drop(creator);
}
