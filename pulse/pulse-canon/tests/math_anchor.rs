// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Math anchor — byte-equality invariants against locked conformance fixtures.
//!
//! These tests pin the canonical primitives against the conformance fixtures
//! under `pulse/pulse-spec/test-vectors/`. A failure here means the wire
//! format changed.
//!
//! Invariants pinned:
//!
//! - **SIG-C13** envelope content-ID
//!   `BLAKE3(domain ‖ envelope_type ‖ len-prefixed type_name? ‖
//!   len-prefixed payload)[..16]`
//!   anchored against the `envelope-raw-known-good` and
//!   `envelope-nested-3-level` fixtures. The fixtures name the framing
//!   revision in `expected.envelope_id_framing`; compare that field first
//!   when IDs disagree.
//! - **SIG-C14** node-ID-from-name
//!   `BLAKE3(name)[..16]`
//!   anchored against the fixed name-vector table below.
//! - **Pulse §2 wire layout**
//!   anchored against the `pulse-layout-known-good` fixture.
//!
//! A change to the `.json` / `.hex` fixtures is a conformance change, made
//! in a commit of its own with its rationale.
//!
//! The SeqLock torn-read test needs `PulseRing`, outside the canonical
//! layer, and lives in `core/core-ring/tests/torn_read.rs`.

use pulse_canon::{
    HeartbeatPayload, Instruction, NodeId, PayloadData, Pulse, PulseEnvelope, PulseEnvelopeId,
};
use serde_json::Value;
use std::path::PathBuf;

// =============================================================================
// Fixture loading
// =============================================================================

fn fixture_dir() -> PathBuf {
    // CARGO_MANIFEST_DIR = pulse/pulse-canon — fixtures live two levels up
    // at pulse/pulse-spec/test-vectors/.
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("pulse-spec")
        .join("test-vectors")
}

fn load_fixture(name: &str) -> (Value, String) {
    let dir = fixture_dir();
    let json: Value = serde_json::from_str(
        &std::fs::read_to_string(dir.join(format!("{name}.json")))
            .unwrap_or_else(|e| panic!("read {name}.json: {e}")),
    )
    .unwrap_or_else(|e| panic!("parse {name}.json: {e}"));
    let hex = std::fs::read_to_string(dir.join(format!("{name}.hex")))
        .unwrap_or_else(|e| panic!("read {name}.hex: {e}"))
        .trim()
        .to_string();
    (json, hex)
}

// =============================================================================
// SIG-C13 — envelope content-ID anchored on raw fixture
// =============================================================================

#[test]
fn sig_c13_envelope_raw_canonical_bytes_match_fixture() {
    let (json, expected_hex) = load_fixture("envelope-raw-known-good");

    let env = PulseEnvelope::new(0x0001, PayloadData::Raw(vec![0x42, 0x42, 0x42, 0x42]));
    let actual_hex = hex::encode(env.to_canonical_bytes());

    assert_eq!(
        actual_hex,
        expected_hex,
        "SIG-C13: envelope-raw canonical bytes diverged from fixture\n\
         expected: {expected_hex}\n\
         actual:   {actual_hex}\n\
         fixture:  {fixture}",
        fixture = json["name"].as_str().unwrap_or("?")
    );
}

#[test]
fn sig_c13_envelope_raw_id_matches_fixture() {
    let (json, _) = load_fixture("envelope-raw-known-good");
    let expected_id = json["expected"]["id_hex"].as_str().unwrap();

    let env = PulseEnvelope::new(0x0001, PayloadData::Raw(vec![0x42, 0x42, 0x42, 0x42]));
    let actual_id = env.id().to_hex();

    assert_eq!(
        actual_id, expected_id,
        "SIG-C13: envelope-raw ID diverged from fixture \
         (BLAKE3 over the length-prefixed preimage for 0x0001 ‖ 0x42*4)"
    );
}

#[test]
fn sig_c13_compute_matches_envelope_id() {
    // The constructor-derived ID and the directly-computed ID must agree.
    let payload = vec![0x42, 0x42, 0x42, 0x42];
    let env = PulseEnvelope::new(0x0001, PayloadData::Raw(payload.clone()));
    let direct = PulseEnvelopeId::compute(0x0001, &payload);
    assert_eq!(env.id(), direct);
}

#[test]
fn sig_c13_envelope_nested_canonical_bytes_match_fixture() {
    let (_, expected_hex) = load_fixture("envelope-nested-3-level");

    // Build the 3-level nested envelope per the fixture structure:
    //   outer (0x0040, Nested) -> [
    //     mid   (0x0020, Nested) -> [
    //       leaf (0x0010, Raw [0xaa 0xbb 0xcc])
    //     ],
    //     sib   (0x0030, Raw [0x11 0x22])
    //   ]
    let leaf = PulseEnvelope::new(0x0010, PayloadData::Raw(vec![0xaa, 0xbb, 0xcc]));
    let mid = PulseEnvelope::new(0x0020, PayloadData::Nested(vec![leaf]));
    let sib = PulseEnvelope::new(0x0030, PayloadData::Raw(vec![0x11, 0x22]));
    let outer = PulseEnvelope::new(0x0040, PayloadData::Nested(vec![mid, sib]));

    let actual_hex = hex::encode(outer.to_canonical_bytes());
    assert_eq!(
        actual_hex, expected_hex,
        "SIG-C13: envelope-nested canonical bytes diverged from fixture"
    );
}

#[test]
fn sig_c13_envelope_nested_id_matches_fixture() {
    let (json, _) = load_fixture("envelope-nested-3-level");
    let expected_outer = json["expected"]["id_hex"].as_str().unwrap();

    let leaf = PulseEnvelope::new(0x0010, PayloadData::Raw(vec![0xaa, 0xbb, 0xcc]));
    let mid = PulseEnvelope::new(0x0020, PayloadData::Nested(vec![leaf]));
    let sib = PulseEnvelope::new(0x0030, PayloadData::Raw(vec![0x11, 0x22]));
    let outer = PulseEnvelope::new(0x0040, PayloadData::Nested(vec![mid, sib]));

    assert_eq!(
        outer.id().to_hex(),
        expected_outer,
        "SIG-C13: outer nested envelope ID diverged"
    );
}

// =============================================================================
// SIG-C14 — node-ID-from-name
// =============================================================================

/// Locked (name → expected hex) vectors for `NodeId::from_name`. Each row is
/// `BLAKE3(name)[..16]` rendered as lowercase hex. Regenerating these requires
/// an explicit reviewed commit; do not edit casually.
const NODE_ID_VECTORS: &[(&str, &str)] = &[
    ("", "af1349b9f5f9a1a6a0404dea36dcc949"),
    ("a", "17762fddd969a453925d65717ac3eea2"),
    ("hello", "ea8f163db38682925e4491c5e58d4bb3"),
    ("pulse-mesh", "adc5abc57df104283522e4260bdc74bd"),
    ("agent-guard", "c6a20eeb9936121a29f0dbb737aedb34"),
];

#[test]
fn sig_c14_node_id_from_name_matches_locked_vectors() {
    for (name, expected_hex) in NODE_ID_VECTORS {
        let actual = NodeId::from_name(name);
        assert_eq!(
            actual.to_hex(),
            *expected_hex,
            "SIG-C14: NodeId::from_name({name:?}) diverged"
        );
    }
}

#[test]
fn sig_c14_node_id_independent_of_namespace() {
    // Two different names must produce different IDs.
    let a = NodeId::from_name("alpha");
    let b = NodeId::from_name("beta");
    assert_ne!(a, b);
}

// =============================================================================
// Pulse layout — §2 wire format anchor
// =============================================================================

#[test]
fn pulse_layout_canonical_bytes_match_fixture() {
    let (_, expected_hex) = load_fixture("pulse-layout-known-good");

    // Reconstruct the deterministic Heartbeat pulse exactly as
    // gen-test-vectors does.
    let mut pulse = Pulse::zeroed();
    pulse.instruction = Instruction::Heartbeat as u16;
    pulse.origin_id = [
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0x01,
    ];
    pulse.monotonic_nanos = 0x0102_0304_0506_0708;
    pulse.chain_step = 0;
    pulse.scope = 0x0001_0000;
    pulse.envelope_ref = [0u8; 16];
    pulse.preimage = [0u8; 32];

    let hb = HeartbeatPayload {
        schema_version: 1,
        uptime_ms: 1000,
        error_count: 0,
        stage_count: 4,
        path_count: 2,
        consecutive_errors: 0,
        wake_state: 7,
        health_state: 0,
        _reserved: [0u8; 4],
    };
    // SAFETY: HeartbeatPayload is repr(C) of size 32; _pad2 is exactly 32 bytes.
    unsafe {
        std::ptr::copy_nonoverlapping(
            &hb as *const HeartbeatPayload as *const u8,
            pulse._pad2.as_mut_ptr(),
            32,
        );
    }

    let actual_hex = hex::encode(pulse.as_bytes());
    assert_eq!(
        actual_hex, expected_hex,
        "Pulse §2 wire layout diverged from fixture"
    );
}

#[test]
fn pulse_layout_is_128_bytes() {
    assert_eq!(pulse_canon::PULSE_WIRE_SIZE, 128);
}
