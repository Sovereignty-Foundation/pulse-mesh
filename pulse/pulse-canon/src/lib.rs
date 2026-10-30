// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! Canon™: the canonical primitive of Pulse Mesh™, tier 0.
//!
//! Three things and nothing else: `Pulse`, the 128-byte, 64-byte-aligned
//! control signal; `PulseEnvelope`, the variable-size payload addressed by
//! the BLAKE3 hash of its canonical bytes; and `NodeId`, the 16-byte node
//! identifier both carry. The codec here is the definition of the wire
//! format: every implementation in every language reproduces its bytes,
//! and the vectors under `pulse/pulse-spec/test-vectors` are the proof.
//!
//! With the `serde` feature the types implement `Serialize` and
//! `Deserialize`, and deserializing a `PulseEnvelope` recomputes its id and
//! refuses one that does not match.
//!
//! Nothing above this crate is needed to encode or verify an envelope.
//! The engine (`core/`), the fabric (`mesh/`) and the rings (`rings/`)
//! depend on it; it depends on no other Pulse Mesh crate.
//!
//! In the book: <https://pulse-mesh.net/docs/reference/spec/02-pulse.html> and
//! <https://pulse-mesh.net/docs/reference/spec/03-envelope.html>.

#![deny(unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]

// A Pulse's bytes in memory are its bytes on the wire (`Pulse::as_bytes`),
// and the specification makes every multi-byte integer of a Pulse
// little-endian (chapter 2). On a big-endian target the two would disagree,
// so the crate does not build there.
#[cfg(not(target_endian = "little"))]
compile_error!(
    "pulse-canon: a Pulse's bytes in memory are its wire format, which the specification makes little-endian; big-endian targets are not supported"
);

pub mod envelope;
pub mod node;
pub mod pulse;

pub use envelope::{
    EnvelopeCodecError, PayloadData, PulseEnvelope, PulseEnvelopeFlags, PulseEnvelopeId,
    CANONICAL_FIXED_HEADER, ENVELOPE_ID_DOMAIN_TAG, PAYLOAD_VARIANT_NESTED, PAYLOAD_VARIANT_RAW,
};
pub use node::{NodeCapabilities, NodeId};
pub use pulse::{DataPayload, HeartbeatPayload, Instruction, Pulse, PULSE_WIRE_SIZE};
