// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! The Data overlay of `_pad2`: a Data pulse names the stored copy of its
//! envelope by store cursor, all zeros names none, and only the Data
//! instruction carries it.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use pulse_canon::{DataPayload, HeartbeatPayload, Instruction, Pulse, PulseEnvelope};

#[test]
fn a_zeroed_pulse_names_no_stored_copy() {
    assert_eq!(Pulse::zeroed().store_cursor(), None);
    let mut data = Pulse::zeroed();
    data.instruction = Instruction::Data as u16;
    assert_eq!(data.data_payload(), Some(DataPayload::zeroed()));
    assert_eq!(data.store_cursor(), None, "all zeros names none");
}

#[test]
fn the_cursor_written_is_the_cursor_read_and_sits_in_pad2() {
    let envelope = PulseEnvelope::typed("event.fired", b"payload".to_vec());
    let cursor = 0x0102_0304_0506_0708;
    let mut pulse = Pulse::zeroed();
    pulse.set_envelope_id(&envelope.id());
    pulse.set_store_cursor(cursor);
    assert_eq!(pulse.instruction_code(), Instruction::Data);
    assert_eq!(pulse.store_cursor(), Some(cursor));
    assert_eq!(
        pulse.envelope_id(),
        Some(envelope.id()),
        "the id is untouched"
    );

    // Bytes 96..128 of the Pulse are `_pad2`: the cursor little-endian,
    // then the flag, then reserved zeros.
    let bytes = pulse.as_bytes();
    assert_eq!(&bytes[96..104], &cursor.to_le_bytes());
    assert_eq!(bytes[104], 1);
    assert!(bytes[105..].iter().all(|&b| b == 0));
    let copy = Pulse::from_bytes(bytes).unwrap();
    assert_eq!(
        copy.store_cursor(),
        Some(cursor),
        "it survives the wire bytes"
    );

    // The first cursor and the last are cursors too.
    for edge in [0, u64::MAX] {
        pulse.set_store_cursor(edge);
        assert_eq!(pulse.store_cursor(), Some(edge));
    }
}

#[test]
fn only_a_data_pulse_carries_a_cursor() {
    let mut pulse = Pulse::zeroed();
    pulse.set_store_cursor(7);
    // The same bytes under the heartbeat opcode are a heartbeat payload.
    pulse.instruction = Instruction::Heartbeat as u16;
    assert_eq!(pulse.data_payload(), None);
    assert_eq!(pulse.store_cursor(), None);
    assert!(pulse.heartbeat_payload().is_some());

    let mut beat = Pulse::zeroed();
    beat.set_heartbeat_payload(&HeartbeatPayload::zeroed());
    assert_eq!(beat.store_cursor(), None);
}

#[test]
fn a_flag_other_than_one_names_no_copy() {
    let mut bytes = DataPayload::with_store_cursor(9).to_bytes();
    assert_eq!(DataPayload::from_bytes(&bytes).store_cursor(), Some(9));
    for flag in [0, 2, 0xff] {
        bytes[8] = flag;
        assert_eq!(
            DataPayload::from_bytes(&bytes).store_cursor(),
            None,
            "{flag}"
        );
    }
    assert_eq!(DataPayload::from_bytes(&[0u8; 32]), DataPayload::zeroed());
}
