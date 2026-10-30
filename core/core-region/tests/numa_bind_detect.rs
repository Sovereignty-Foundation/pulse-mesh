// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! Binding a shm file to NUMA node 0 and detecting that placement, on a
//! Linux host that exposes a node. Skips (prints SKIP, returns) where the
//! sysfs node tree or `/dev/shm` is absent, or where the kernel refuses
//! `mbind` (sandboxed runners).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stderr
)]

#[cfg(target_os = "linux")]
use core_region::numa::{
    allocate_shm_backing, detect_numa_node_for_shm, NumaError, PageSize, ShmNumaConfig,
};

#[cfg(target_os = "linux")]
#[test]
fn bind_to_node_zero_then_detect_it() {
    if !std::path::Path::new("/sys/devices/system/node/node0").exists()
        || !std::path::Path::new("/dev/shm").exists()
    {
        eprintln!("SKIP: no NUMA sysfs node or /dev/shm on this host");
        return;
    }
    let dir = tempfile::tempdir_in("/dev/shm").expect("tempdir in /dev/shm");
    let path = dir.path().join("numa-bind.shm");
    let cfg = ShmNumaConfig::new(&path, 1 << 20)
        .with_page_size(PageSize::Regular)
        .with_numa_node(Some(0));
    // Held to the end: the backing removes its file when it drops.
    let _backing = match allocate_shm_backing(&cfg) {
        Ok(backing) => backing,
        Err(NumaError::NumaPin { reason, .. }) => {
            eprintln!("SKIP: kernel refused mbind ({reason})");
            return;
        }
        Err(other) => panic!("allocate_shm_backing failed: {other}"),
    };
    assert_eq!(detect_numa_node_for_shm(&path).expect("detect"), 0);
}
