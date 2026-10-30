// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! A NUMA backing that `/dev/shm` has no room for is refused, not a SIGBUS:
//! `allocate_shm_backing` reserves its pages rather than touching them, and
//! removes a file it cannot back. The test means something where `/dev/shm`
//! is smaller than 16 MiB, as in the Linux test container run with an 8 MB
//! `/dev/shm`; elsewhere it says why it checks nothing and passes.
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
fn a_backing_dev_shm_has_no_space_for_is_an_error_and_is_removed() {
    use core_region::numa::{allocate_shm_backing, NumaError, PageSize, ShmNumaConfig};

    const BYTES: usize = 16 << 20;
    let need = BYTES as u64;
    let Some((total, free)) = dev_shm_space() else {
        eprintln!("no size-limited /dev/shm to measure; nothing checked");
        return;
    };
    if need <= free {
        eprintln!(
            "/dev/shm has {free} bytes free, room for a {need}-byte backing; nothing checked"
        );
        return;
    }
    if need <= total {
        // The kernel would allocate what is free before failing, filling
        // /dev/shm under whatever else is using it.
        eprintln!(
            "a {need}-byte backing fits a {total}-byte /dev/shm once emptied; \
             reserving it now would fill /dev/shm, so nothing is checked"
        );
        return;
    }

    let dir = tempfile::tempdir_in("/dev/shm").expect("tempdir in /dev/shm");
    let path = dir.path().join("no-room.shm");
    let cfg = ShmNumaConfig::new(&path, BYTES)
        .with_page_size(PageSize::Regular)
        .with_numa_node(None);
    match allocate_shm_backing(&cfg) {
        Err(NumaError::Io(e)) => assert!(
            matches!(e.raw_os_error(), Some(libc::ENOSPC | libc::ENOMEM)),
            "unexpected error {e}"
        ),
        Err(other) => panic!("expected an I/O error from the reservation, got {other}"),
        Ok(_) => panic!("a {need}-byte backing was made in a {total}-byte /dev/shm"),
    }
    assert!(
        !path.exists(),
        "the file that could not be backed is still there"
    );
}
