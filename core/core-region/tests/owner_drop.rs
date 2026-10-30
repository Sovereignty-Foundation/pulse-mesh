// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! A region's creator unlinks its name when it drops only while the name is
//! still its region: a region a later owner put under the name outlives the
//! earlier owner's handle, as an envelope store does.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use core_region::{PulseRegion, ShmError};
use pulse_canon::Pulse;

/// A region name private to this process and test, at most 30 bytes.
fn name(tag: &str) -> String {
    format!("/rg-own-{tag}-{:x}", std::process::id())
}

fn gone(name: &str) -> bool {
    matches!(PulseRegion::open(name), Err(ShmError::Open(libc::ENOENT)))
}

/// Remove the name, as a later owner does before it creates its own region.
fn unlink(name: &str) -> bool {
    let name = std::ffi::CString::new(name).unwrap();
    // SAFETY: `name` is a valid NUL-terminated string for the duration of the
    // call, and shm_unlink touches nothing else.
    unsafe { libc::shm_unlink(name.as_ptr()) == 0 }
}

/// A pulse whose bytes after the SeqLock word are all `fill`.
fn filled(fill: u8) -> Pulse {
    let mut bytes = [fill; 128];
    bytes[..8].copy_from_slice(&[0u8; 8]);
    Pulse::from_array(&bytes)
}

#[test]
fn a_creator_unlinks_the_name_while_it_is_still_its_region() {
    let name = name("own");
    let creator = PulseRegion::create_exclusive(&name).unwrap();
    let reader = PulseRegion::open(&name).unwrap();
    drop(reader);
    assert!(!gone(&name), "a reader's drop leaves the name");
    drop(creator);
    assert!(gone(&name), "the creator's drop removes it");
}

#[test]
fn an_earlier_creator_leaves_a_later_owners_region_under_the_name() {
    let name = name("later");
    let earlier = PulseRegion::create_exclusive(&name).unwrap();
    // A later owner takes the name: it removes the region it finds there and
    // makes its own, which it goes on using while the earlier handle lives.
    assert!(unlink(&name));
    let mut later = PulseRegion::create_exclusive(&name).unwrap();
    later.write(&filled(0x5a));

    // The earlier creator's drop must leave the later owner's name.
    drop(earlier);
    let under_the_name =
        PulseRegion::open(&name).expect("the earlier creator's drop left the later owner's region");
    let pulse = under_the_name.read().expect("the later owner's pulse");
    assert!(pulse.as_bytes()[8..].iter().all(|&b| b == 0x5a));
    drop(under_the_name);

    drop(later);
    assert!(gone(&name), "the later owner still removes its own name");
}

#[test]
fn a_creator_whose_name_was_removed_leaves_it_gone() {
    let name = name("gone");
    let creator = PulseRegion::create_exclusive(&name).unwrap();
    assert!(unlink(&name));
    drop(creator);
    assert!(gone(&name));
    // The name is free for the next creator, whose drop removes it.
    drop(PulseRegion::create_exclusive(&name).unwrap());
    assert!(gone(&name));
}

#[test]
fn a_reader_still_reads_a_region_whose_creator_has_dropped() {
    let name = name("reader");
    let mut creator = PulseRegion::create_exclusive(&name).unwrap();
    creator.write(&filled(0x11));
    let reader = PulseRegion::open(&name).unwrap();
    // The drop writes its unlink token into the region the reader maps; the
    // reader's pulse and header are untouched by it.
    drop(creator);
    assert!(gone(&name));
    let pulse = reader.read().expect("the pulse is still readable");
    assert!(pulse.as_bytes()[8..].iter().all(|&b| b == 0x11));
    assert_eq!(reader.seq_version(), 2);
}
