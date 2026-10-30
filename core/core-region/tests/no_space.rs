// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! A region created in a full `/dev/shm` is refused, not a SIGBUS.
//!
//! A region is one page, so it fails to fit only when `/dev/shm` is full.
//! The test fills `/dev/shm` itself, and therefore runs only where
//! `/dev/shm` is at most 16 MiB, as in the Linux test container run with an
//! 8 MB `/dev/shm`; nothing else would share so small a tmpfs, and anywhere
//! larger it says why it checks nothing and passes.
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

/// A file in `/dev/shm` holding every free page, removed on drop.
#[cfg(target_os = "linux")]
struct Filler(std::path::PathBuf);

#[cfg(target_os = "linux")]
impl Filler {
    fn fill() -> Self {
        use std::os::unix::io::AsRawFd;
        let path = std::path::PathBuf::from(format!("/dev/shm/pr-fill-{:x}", std::process::id()));
        let file = std::fs::File::create(&path).expect("create the filler");
        let filler = Filler(path);
        let mut len: libc::off_t = 0;
        let mut step = libc::off_t::MAX;
        for _ in 0..64 {
            let (_, free) = dev_shm_space().expect("measure /dev/shm");
            if free == 0 {
                return filler;
            }
            let add = step.min(free as libc::off_t);
            // SAFETY: posix_fallocate reads only its integer arguments and
            // allocates storage for the file `file` keeps open.
            match unsafe { libc::posix_fallocate(file.as_raw_fd(), len, add) } {
                0 => len += add,
                libc::EINTR => {}
                libc::ENOSPC if add > 4096 => step = add / 2,
                e => panic!("filling /dev/shm failed at {len} bytes: errno {e}"),
            }
        }
        panic!("/dev/shm still had room after filling {len} bytes");
    }
}

#[cfg(target_os = "linux")]
impl Drop for Filler {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

#[cfg(target_os = "linux")]
#[test]
fn create_exclusive_in_a_full_dev_shm_is_no_space_and_leaves_nothing() {
    use core_region::{PulseRegion, ShmError, REGION_SIZE};
    use std::path::Path;

    const SMALL: u64 = 16 << 20;
    let Some((total, _)) = dev_shm_space() else {
        eprintln!("no size-limited /dev/shm to measure; nothing checked");
        return;
    };
    if total > SMALL {
        eprintln!(
            "/dev/shm is {total} bytes; the test fills it only when it is at most \
             {SMALL} bytes, so nothing is checked"
        );
        return;
    }

    let name = format!("pr-full-{:x}", std::process::id());
    let filler = Filler::fill();
    match PulseRegion::create_exclusive(&name) {
        Err(ShmError::NoSpace { need, errno }) => {
            assert_eq!(need, REGION_SIZE as u64, "one region");
            assert_eq!(errno, libc::ENOSPC);
        }
        Err(other) => panic!("expected NoSpace, got {other:?}"),
        Ok(_) => panic!("a region was made in a full /dev/shm"),
    }
    assert!(
        !Path::new("/dev/shm").join(&name).exists(),
        "the half-made region was left behind"
    );

    // With room again, the name is free and the region is made.
    drop(filler);
    let region = PulseRegion::create_exclusive(&name).expect("a region once there is room");
    assert_eq!(region.seq_version(), 0, "a new region is never written");
}
