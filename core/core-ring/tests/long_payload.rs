// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! A payload far longer than the ring crosses it intact.
//!
//! The payload is cut into pieces of the 120 bytes a pulse carries past
//! its SeqLock word, published through a ring of 16 slots so that it wraps
//! about 32 times, read back through a second mapping of the same ring and
//! put together again. The other tests fill pulses with one repeated byte
//! or a counter; this pattern is real data, pressed flat under the ring's
//! own mark, so its bytes are dense and irregular where a synthetic fill
//! repeats. Its digest is pinned, so the fixture itself can't drift.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use core_ring::{PulseRing, PULSE_SIZE};
use pulse_canon::Pulse;

/// The bytes of a pulse past its SeqLock word, which is the ring's.
const PIECE: usize = PULSE_SIZE - 8;

const CAPACITY: u64 = 16;

const PAYLOAD: &[u8] = include_bytes!("data/long-payload.bin");

#[test]
fn a_payload_longer_than_the_ring_crosses_it_intact() {
    let name = format!("/long-payload-{:x}", std::process::id());
    let mut writer = PulseRing::create_exclusive(&name, CAPACITY).expect("create ring");
    let reader = PulseRing::open(&name, CAPACITY).expect("attach a reader");

    let mut out = Vec::with_capacity(PAYLOAD.len());
    let mut published = 0u64;
    for piece in PAYLOAD.chunks(PIECE) {
        let mut bytes = [0u8; PULSE_SIZE];
        bytes[8..8 + piece.len()].copy_from_slice(piece);
        let slot = writer.publish_returning_slot(&Pulse::from_array(&bytes));
        published += 1;
        let pulse = reader.read_slot(slot).expect("the slot just written");
        out.extend_from_slice(&pulse.as_bytes()[8..8 + piece.len()]);
    }

    assert!(
        published / CAPACITY > 30,
        "the payload should lap the ring many times: {published} pulses"
    );
    assert!(out == PAYLOAD, "the payload changed crossing the ring");
    assert_eq!(
        blake3::hash(&out).to_hex().as_str(),
        "e94340c5f55764cad0b017ca263ffe1d5ef8b73e2bdbe6eb30e608f94fe162ca",
        "the fixture changed"
    );
}
