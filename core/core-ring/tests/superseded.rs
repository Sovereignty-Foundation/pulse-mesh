// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! A ring whose writer has left it says so. Its creator marks it superseded
//! as the name goes, a reader still mapped to it sees the mark after every
//! pulse it held, the mark is set once, and a creator whose ring another
//! marked leaves the name, which may be a successor's, alone.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use core_ring::{PositionRead, PulseRing, RingError};
use pulse_canon::{Instruction, Pulse};

/// A ring name private to this process and test.
fn name(tag: &str) -> String {
    format!("/sup-{tag}-{:x}", std::process::id())
}

fn marked(step: u64) -> Pulse {
    let mut pulse = Pulse::zeroed();
    pulse.instruction = Instruction::Data as u16;
    pulse.chain_step = step;
    pulse
}

#[test]
fn a_new_ring_is_not_superseded() {
    let ring = PulseRing::create(&name("new"), 8).unwrap();
    assert!(!ring.is_superseded());
    assert!(!PulseRing::open(ring.name(), 8).unwrap().is_superseded());
}

#[test]
fn a_creator_marks_its_ring_superseded_as_it_unlinks_the_name() {
    let name = name("drop");
    let mut creator = PulseRing::create(&name, 8).unwrap();
    let reader = PulseRing::open(&name, 8).unwrap();
    creator.publish(&marked(7));
    assert!(!reader.is_superseded());

    drop(creator);
    assert!(
        reader.is_superseded(),
        "the reader, still mapped, sees the mark"
    );
    assert!(
        matches!(
            PulseRing::open(&name, 8),
            Err(RingError::Open(libc::ENOENT))
        ),
        "and the name is gone"
    );
    match reader.read_position(0) {
        PositionRead::Pulse(pulse) => assert_eq!(pulse.chain_step, 7),
        other => panic!("what the ring held is still readable: {other:?}"),
    }
}

#[test]
fn the_mark_is_set_once_and_a_marked_creator_leaves_a_successor_alone() {
    let name = name("once");
    let creator = PulseRing::create(&name, 8).unwrap();
    let other = PulseRing::open(&name, 8).unwrap();
    assert!(other.supersede(), "the first mark is this call's");
    assert!(!other.supersede(), "a second is refused");
    assert!(!creator.supersede());
    assert!(creator.is_superseded());

    // The name passes to a successor, as a new owner of a hub name passes
    // it: the old ring marked, its name unlinked, a new ring created.
    assert!(PulseRing::unlink(&name).unwrap());
    let successor = PulseRing::create_exclusive(&name, 8).unwrap();
    drop(creator);
    let named = PulseRing::open(&name, 8).expect("the successor's ring is still named");
    assert!(!named.is_superseded());
    drop(named);
    drop(successor);
    assert!(matches!(
        PulseRing::open(&name, 8),
        Err(RingError::Open(libc::ENOENT))
    ));
}
