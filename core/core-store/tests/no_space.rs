// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! A store that `/dev/shm` has no room for is refused at creation.
//!
//! Linux answers the first touch of a tmpfs page the filesystem cannot
//! supply with SIGBUS (Docker's default `/dev/shm` is 64 MB, and a hub's
//! store about 17 MB), so creation reserves the pages with
//! `posix_fallocate`, and a reservation that fails unlinks the object and
//! returns `NoSpace`. The test means something where `/dev/shm` is
//! smaller than a hub's store, as in the Linux test container run with an
//! 8 MB `/dev/shm`; elsewhere it says why it checks nothing and passes.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stderr
)]

/// Total and free bytes of the tmpfs behind `/dev/shm`, or `None` where
/// there is none with a size limit to measure.
#[cfg(target_os = "linux")]
#[allow(clippy::unnecessary_cast)] // the statvfs field types differ between targets
fn dev_shm_space() -> Option<(u64, u64)> {
    let path = std::ffi::CString::new("/dev/shm").unwrap();
    let mut st = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    // SAFETY: statvfs reads the NUL-terminated path and writes one
    // `statvfs` into the buffer, which is read only when it returns 0.
    if unsafe { libc::statvfs(path.as_ptr(), st.as_mut_ptr()) } != 0 {
        return None;
    }
    // SAFETY: statvfs returned 0, so it initialised the buffer.
    let st = unsafe { st.assume_init() };
    let unit = st.f_frsize as u64;
    let total = st.f_blocks as u64 * unit;
    (total > 0).then(|| (total, st.f_bavail as u64 * unit))
}

#[cfg(target_os = "linux")]
#[test]
fn a_store_dev_shm_has_no_room_for_is_no_space_and_leaves_nothing() {
    use core_store::{EnvelopeStore, EnvelopeStoreError, MAX_ENTRY_SIZE};
    use std::path::Path;

    type Make = fn(&str, usize) -> Result<EnvelopeStore, EnvelopeStoreError>;

    // A hub's store: a 64-byte header, then 256 slots of a 64-byte prefix
    // and a MAX_ENTRY_SIZE body (layout version 2).
    const SLOTS: usize = 256;
    let need = (64 + SLOTS * (64 + MAX_ENTRY_SIZE)) as u64;
    let Some((total, free)) = dev_shm_space() else {
        eprintln!("no size-limited /dev/shm to measure; nothing checked");
        return;
    };
    if need <= free {
        eprintln!("/dev/shm has {free} bytes free, room for a {need}-byte store; nothing checked");
        return;
    }
    if need <= total {
        // The kernel would allocate what is free before failing, filling
        // /dev/shm under whatever else is using it.
        eprintln!(
            "a {need}-byte store fits a {total}-byte /dev/shm once emptied; \
             reserving it now would fill /dev/shm, so nothing is checked"
        );
        return;
    }

    let name = format!("st-nospace-{:x}", std::process::id());
    EnvelopeStore::unlink(&name).unwrap();
    let attempts: [(&str, Make); 3] = [
        ("create_exclusive", EnvelopeStore::create_exclusive),
        ("create_or_open", EnvelopeStore::create_or_open),
        ("create", EnvelopeStore::create),
    ];
    for (what, make) in attempts {
        match make(&name, SLOTS) {
            Err(EnvelopeStoreError::NoSpace { need: n, errno }) => {
                assert_eq!(n, need, "{what} named the wrong size");
                assert!(
                    errno == libc::ENOSPC || errno == libc::ENOMEM,
                    "{what}: unexpected errno {errno}"
                );
            }
            Err(other) => panic!("{what}: expected NoSpace, got {other:?}"),
            Ok(_) => panic!("{what} made a {need}-byte store in a {total}-byte /dev/shm"),
        }
        assert!(
            !Path::new("/dev/shm").join(&name).exists(),
            "{what} left its half-made object behind"
        );
    }
    let (_, after) = dev_shm_space().unwrap();
    assert!(
        after >= free,
        "the refused creations kept {} bytes of /dev/shm",
        free - after
    );
}
