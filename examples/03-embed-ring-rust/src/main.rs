// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! Example 03 — the ring and the store, used directly (Rust).
//!
//! Creates a shared-memory ring and an envelope store under a name, publishes
//! a Pulse that references an envelope, opens a second handle to both by
//! name as another process would, and reads the Pulse and its envelope back.
//! The book's tutorial T5 is this file, section by section.
#![forbid(unsafe_code)]
// A demonstration: the expected flow is "everything works, prints, exits 0",
// so fail-fast idioms are deliberate here.
#![allow(
    clippy::print_stdout,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

use core_ring::PulseRing;
use core_store::EnvelopeStore;
use pulse_canon::{Instruction, Pulse, PulseEnvelope};

fn main() {
    // A name of your own: rings and stores are POSIX shared-memory objects.
    let name = format!("/pms-example-{}", std::process::id());
    let store_name = format!("{name}-env");

    // ANCHOR: create
    // One writer creates the ring: a 64-byte header plus 64 slots of 128 bytes.
    // Under a name that already holds a ring, `create` attaches to that ring
    // as it stands instead.
    let mut ring = PulseRing::create(&name, 64).expect("create ring");
    let store = EnvelopeStore::create_or_open(&store_name, 16).expect("create store");

    // The payload travels as an envelope, addressed by its content.
    let envelope = PulseEnvelope::typed("event.fired", b"payload".to_vec());
    store.store(&envelope).expect("store envelope");

    // The Pulse is the signal: a Data instruction whose envelope_ref names the envelope.
    let mut pulse = Pulse::zeroed();
    pulse.instruction = Instruction::Data as u16;
    pulse.monotonic_nanos = 1;
    pulse.set_envelope_id(&envelope.id());
    let write_number = ring.publish(&pulse);
    assert_eq!(write_number, 1);
    // ANCHOR_END: create

    // ANCHOR: read
    // Another process opens both by name; the capacity must match the creator's.
    let reader = PulseRing::open(&name, 64).expect("open ring");
    let reader_store = EnvelopeStore::create_or_open(&store_name, 16).expect("open store");

    // The newest slot is one behind the cursor. read_slot copies it and keeps
    // the copy only if the slot's counter was even and unchanged across the copy.
    let newest = (reader.cursor_position() - 1) % reader.capacity();
    let seen = reader.read_slot(newest).expect("a consistent Pulse");
    assert_eq!(seen.instruction, Instruction::Data as u16);

    // The envelope comes back by identifier, from the store beside the ring.
    let id = seen.envelope_id().expect("the signal names an envelope");
    let found = reader_store.fetch(&id).expect("the referenced envelope");
    assert!(found.verify(), "the identifier matches the content");
    assert_eq!(found.type_name(), Some("event.fired"));
    // ANCHOR_END: read

    println!(
        "OK — published one Pulse referencing envelope {} and read both back through a second handle.",
        found.id().to_hex()
    );
}
