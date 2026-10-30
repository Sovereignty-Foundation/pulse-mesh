// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! The typed view of a Pulse's `envelope_ref`: the field holds a
//! `PulseEnvelopeId` byte for byte, and the accessors say so in the types.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use pulse_canon::{Instruction, Pulse, PulseEnvelope};

#[test]
fn a_zeroed_pulse_names_no_envelope() {
    let pulse = Pulse::zeroed();
    assert!(!pulse.has_envelope());
    assert_eq!(pulse.envelope_id(), None);
}

#[test]
fn the_id_written_is_the_id_read_and_the_raw_field_agrees() {
    let envelope = PulseEnvelope::typed("event.fired", b"payload".to_vec());
    let mut pulse = Pulse::zeroed();
    pulse.instruction = Instruction::Data as u16;
    pulse.set_envelope_id(&envelope.id());

    assert!(pulse.has_envelope());
    assert_eq!(pulse.envelope_id(), Some(envelope.id()));
    assert_eq!(pulse.envelope_ref, envelope.id().0);
}

#[test]
fn the_id_survives_the_wire_bytes() {
    let envelope = PulseEnvelope::typed("event.fired", b"payload".to_vec());
    let mut pulse = Pulse::zeroed();
    pulse.set_envelope_id(&envelope.id());

    // bytes 48..64 of the 128-byte Pulse are the envelope reference.
    assert_eq!(&pulse.as_bytes()[48..64], &envelope.id().0);
}
