// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! Regenerate the language-neutral conformance fixtures under `test-vectors/`.
//!
//! Run from the workspace root:
//!
//! ```bash
//! cargo run --release -p gen-test-vectors
//! ```
//!
//! The fixtures are generated, never edited by hand:
//!
//! 1. `pulse-layout-known-good.{json,hex}`: a 128-byte Heartbeat Pulse.
//! 2. `envelope-raw-known-good.{json,hex}`: a Raw envelope.
//! 3. `envelope-nested-3-level.{json,hex}`: a three-level Nested envelope.

#![allow(clippy::print_stdout)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;

use pulse_canon::{
    HeartbeatPayload, Instruction, PayloadData, Pulse, PulseEnvelope, ENVELOPE_ID_DOMAIN_TAG,
};
use serde_json::json;

fn main() {
    let workspace = workspace_root();
    let test_vectors = workspace.join("test-vectors");
    std::fs::create_dir_all(&test_vectors).expect("create test-vectors/");

    println!("Writing fixtures to {}", test_vectors.display());

    write_pulse_layout(&test_vectors);
    write_envelope_raw(&test_vectors);
    write_envelope_nested_3_level(&test_vectors);
    write_readme(&test_vectors);

    println!("OK — fixtures regenerated.");
}

fn workspace_root() -> std::path::PathBuf {
    // `pulse/pulse-spec`, two levels above this tool's manifest.
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .canonicalize()
        .expect("workspace root must exist")
}

/// A deterministic Heartbeat Pulse, exercising the `_pad2` overlay.
fn write_pulse_layout(dir: &Path) {
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

    let bytes = pulse.as_bytes();
    let hex = hex::encode(bytes);

    let manifest = json!({
        "name": "pulse-layout-known-good",
        "description": "Deterministic 128-byte Pulse with Heartbeat overlay. Exercises the cache-line-aligned wire layout and the _pad2 HeartbeatPayload overlay.",
        "spec_version": "draft-00",
        "spec_section": "2",
        "inputs": {
            "instruction": "Heartbeat (0x0001)",
            "origin_id_hex": hex::encode(pulse.origin_id),
            "monotonic_nanos": pulse.monotonic_nanos,
            "chain_step": pulse.chain_step,
            "scope_hex": format!("0x{:08x}", pulse.scope),
            "envelope_ref_hex": hex::encode(pulse.envelope_ref),
            "preimage_hex": hex::encode(pulse.preimage),
            "heartbeat_overlay": {
                "schema_version": hb.schema_version,
                "uptime_ms": hb.uptime_ms,
                "error_count": hb.error_count,
                "stage_count": hb.stage_count,
                "path_count": hb.path_count,
                "consecutive_errors": hb.consecutive_errors,
                "wake_state": hb.wake_state,
                "health_state": hb.health_state,
            }
        },
        "expected": {
            "size_bytes": 128,
            "canonical_hex": hex.clone(),
        }
    });

    write_json(dir, "pulse-layout-known-good.json", &manifest);
    write_hex(dir, "pulse-layout-known-good.hex", &hex);
    println!("  wrote pulse-layout-known-good ({} bytes)", bytes.len());
}

/// The Raw envelope of `pulse-canon`'s
/// `canonical_layout_is_stable_for_a_known_envelope` test.
fn write_envelope_raw(dir: &Path) {
    let env = PulseEnvelope::new(0x0001, PayloadData::Raw(vec![0x42, 0x42, 0x42, 0x42]));
    let bytes = env.to_canonical_bytes();
    let hex = hex::encode(&bytes);
    let id_hex = env.id().to_hex();

    let manifest = json!({
        "name": "envelope-raw-known-good",
        "description": "The canonical Raw envelope fixture. envelope_type=0x0001, no type_name, payload = [0x42, 0x42, 0x42, 0x42]. Total canonical size 54 bytes.",
        "spec_version": "draft-00",
        "spec_section": "3",
        "inputs": {
            "envelope_type": "0x0001",
            "type_name": null,
            "payload_variant": "Raw",
            "payload_hex": "42424242",
            "origin_hex": "00000000000000000000000000000000",
            "monotonic_nanos": 0,
            "flags": 0,
        },
        "expected": {
            "size_bytes": bytes.len(),
            "canonical_hex": hex.clone(),
            "id_hex": id_hex.clone(),
            "envelope_id_framing": id_framing(),
        }
    });

    write_json(dir, "envelope-raw-known-good.json", &manifest);
    write_hex(dir, "envelope-raw-known-good.hex", &hex);
    println!(
        "  wrote envelope-raw-known-good ({} bytes, id={})",
        bytes.len(),
        id_hex
    );
}

/// A three-level Nested envelope: a child's id is part of every ancestor's
/// preimage.
fn write_envelope_nested_3_level(dir: &Path) {
    let leaf = PulseEnvelope::new(0x0010, PayloadData::Raw(vec![0xaa, 0xbb, 0xcc]));

    let mid = PulseEnvelope::new(0x0020, PayloadData::Nested(vec![leaf.clone()]));

    let sibling = PulseEnvelope::new(0x0030, PayloadData::Raw(vec![0x11, 0x22]));
    let outer = PulseEnvelope::new(
        0x0040,
        PayloadData::Nested(vec![mid.clone(), sibling.clone()]),
    );

    let bytes = outer.to_canonical_bytes();
    let hex = hex::encode(&bytes);

    let manifest = json!({
        "name": "envelope-nested-3-level",
        "description": "A 3-level deep Nested envelope. The outermost envelope's payload is Nested(2 children): the first child is itself Nested(1 leaf), the second is a Raw sibling. Exercises recursive composition and id propagation.",
        "spec_version": "draft-00",
        "spec_section": "3",
        "structure": {
            "outer": {
                "envelope_type": "0x0040",
                "payload_variant": "Nested",
                "children": [
                    {
                        "envelope_type": "0x0020",
                        "payload_variant": "Nested",
                        "children": [
                            {
                                "envelope_type": "0x0010",
                                "payload_variant": "Raw",
                                "payload_hex": "aabbcc",
                                "id_hex": leaf.id().to_hex(),
                            }
                        ],
                        "id_hex": mid.id().to_hex(),
                    },
                    {
                        "envelope_type": "0x0030",
                        "payload_variant": "Raw",
                        "payload_hex": "1122",
                        "id_hex": sibling.id().to_hex(),
                    }
                ],
                "id_hex": outer.id().to_hex(),
            }
        },
        "expected": {
            "size_bytes": bytes.len(),
            "canonical_hex": hex.clone(),
            "id_hex": outer.id().to_hex(),
            "envelope_id_framing": id_framing(),
        }
    });

    write_json(dir, "envelope-nested-3-level.json", &manifest);
    write_hex(dir, "envelope-nested-3-level.hex", &hex);
    println!(
        "  wrote envelope-nested-3-level ({} bytes, outer_id={})",
        bytes.len(),
        outer.id().to_hex()
    );
}

/// The envelope-id framing revision the fixtures' ids were computed under:
/// an implementation whose ids disagree compares this first.
fn id_framing() -> String {
    String::from_utf8(ENVELOPE_ID_DOMAIN_TAG.to_vec()).expect("domain tag is UTF-8")
}

fn write_json(dir: &Path, name: &str, value: &serde_json::Value) {
    let path = dir.join(name);
    let pretty = serde_json::to_string_pretty(value).expect("json serialize");
    std::fs::write(&path, format!("{pretty}\n")).expect("write json");
}

fn write_hex(dir: &Path, name: &str, hex_str: &str) {
    let path = dir.join(name);
    std::fs::write(&path, format!("{hex_str}\n")).expect("write hex");
}

fn write_readme(dir: &Path) {
    let body = r#"# Conformance test vectors

This directory contains language-neutral conformance fixtures for the
Pulse Mesh Standard. Each fixture is provided in two formats:

- `.json` — input fields, expected canonical bytes (hex), expected BLAKE3 ID where applicable
- `.hex`  — just the expected canonical bytes as a single hex string (one line, no whitespace)

## Fixtures

| File | Spec section | What it asserts |
|---|---|---|
| `pulse-layout-known-good.json` / `.hex` | §2 | 128-byte Pulse layout with Heartbeat overlay |
| `envelope-raw-known-good.json` / `.hex` | §3 | Canonical Raw envelope (envelope_type=0x0001, payload=[0x42 × 4]) |
| `envelope-nested-3-level.json` / `.hex` | §3.4 | 3-level deep Nested envelope demonstrating recursive composition |

## Regenerating

Whenever the reference implementation changes, these fixtures are
regenerated by running:

```bash
cargo run --release -p gen-test-vectors
```

The generator lives at `tools/gen-test-vectors/`. The fixtures are
checked in so that external implementers and CI can verify byte-equality
without running Rust code.

## Conformance contract

A conformant implementation:

- MUST produce byte-identical output to the `.hex` content for the
  input fields in the corresponding `.json` manifest.
- MUST accept the `.hex` bytes and round-trip-decode them to a value
  that re-encodes to the same bytes.
- MUST compute the same BLAKE3-truncated `id` (where applicable) for
  the same field inputs, using the envelope-ID framing named in the
  fixture's `expected.envelope_id_framing` field. The ID preimage
  length-prefixes every variable-length field and tags the optional and
  enumerated ones; concatenating the fields without that framing lets
  distinct envelopes hash to one ID.

If any of these fail, the implementation is non-conformant for that
fixture. File an interop-report issue against the core repo with the
bytes you produced and a description of your environment.
"#;
    std::fs::write(dir.join("README.md"), body).expect("write test-vectors README");
}
