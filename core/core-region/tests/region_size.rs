// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! `open` refuses an object smaller than a region instead of mapping it
//! (observable on Linux; macOS rounds shm objects up to a whole page, and
//! there the object is refused for carrying no region header).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use core_region::{PulseRegion, ShmError, REGION_SIZE};
use std::ffi::CString;

#[test]
fn open_refuses_a_region_smaller_than_a_pulse() {
    let name = format!("pr-small-{}", std::process::id());
    let cname = CString::new(name.clone()).unwrap();
    // SAFETY: plain libc calls on a name this test owns; every return value
    // is checked and the object is unlinked at the end.
    unsafe {
        let fd = libc::shm_open(cname.as_ptr(), libc::O_CREAT | libc::O_RDWR, 0o600);
        assert!(fd >= 0, "shm_open failed");
        assert_eq!(libc::ftruncate(fd, 64), 0, "ftruncate failed");
        libc::close(fd);
    }
    match PulseRegion::open(&name) {
        Err(ShmError::RegionTooSmall { have, need }) => {
            assert_eq!(have, 64);
            assert_eq!(need, REGION_SIZE as u64);
        }
        // macOS rounds a shared-memory object up to a whole page, so a
        // 64-byte object is not observable there, and the page carries no
        // region header; Linux (tmpfs) keeps the exact size and refuses it
        // on that.
        Err(ShmError::LayoutMismatch { field: "magic", .. }) if cfg!(target_os = "macos") => {}
        Ok(_) => panic!("open must refuse a 64-byte object"),
        Err(other) => panic!("expected RegionTooSmall, got {other:?}"),
    }
    // SAFETY: unlinking the object this test created.
    unsafe {
        libc::shm_unlink(cname.as_ptr());
    }
}
