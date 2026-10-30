// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Property-based tests for the `PulseEnvelope` codec.
//!
//! These properties extend the locked-fixture math anchor
//! (`tests/math_anchor.rs`) from "encoded bytes for these specific
//! inputs match these specific outputs" to "the codec's structural
//! invariants hold over any valid input." Where the anchor pins point
//! observations, the proptests pin the abstract laws those observations
//! exemplify:
//!
//! 1. **Roundtrip closes**: `from_canonical_bytes(encode(env)) == env`
//!    for every envelope the public constructors can produce. If this
//!    breaks, the codec is no longer self-consistent.
//!
//! 2. **Content-ID equality follows content equality**: two envelopes
//!    with byte-identical (envelope_type, type_name, payload) produce
//!    byte-identical IDs.
//!
//! 3. **Content-ID changes when any input changes**: flipping any of
//!    envelope_type, type_name, or payload bytes changes the ID with
//!    probability ≈ 1 (BLAKE3 collision resistance). The proptest
//!    treats observed collisions as failures because the encoding
//!    space we explore is small relative to 2^128.
//!
//! 4. **`verify()` is total on constructed envelopes**: every envelope
//!    built by `new`/`typed`/etc. passes `verify()` (since the
//!    constructor itself computed the stored ID).

use proptest::prelude::*;
use pulse_canon::{PayloadData, PulseEnvelope, PulseEnvelopeFlags, PulseEnvelopeId};

// =============================================================================
// Generators
// =============================================================================

/// Reasonable envelope_type range: u16. The codec treats this as
/// opaque; no encoding pathology around any value.
fn arb_envelope_type() -> impl Strategy<Value = u16> {
    any::<u16>()
}

/// Type-name generator: `None` half the time; otherwise a bounded
/// non-empty UTF-8 string within the canonical-size budget. Names
/// above ~200 chars are vanishingly rare in practice; cap at 64 to
/// keep test runs fast.
fn arb_type_name() -> impl Strategy<Value = Option<String>> {
    proptest::option::of("[a-zA-Z0-9_./:-]{1,64}".prop_map(|s| s))
}

/// Raw payload: bounded length so the canonical encoder doesn't
/// allocate excessively. Below MAX_ENVELOPE (1315 B from
/// pulse-wire-udp's framing budget), so any envelope produced here
/// could in principle ride the wire.
fn arb_raw_payload() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..512)
}

/// Construct any of the four named-or-numbered envelope variants.
/// `typed_broadcast` and `broadcast` differ from the bare constructors
/// only by setting the BROADCAST flag — we exercise both flag states.
fn arb_envelope() -> impl Strategy<Value = PulseEnvelope> {
    (
        arb_envelope_type(),
        arb_type_name(),
        arb_raw_payload(),
        any::<bool>(), // broadcast or not
    )
        .prop_map(|(envelope_type, type_name, payload, broadcast)| {
            let pd = PayloadData::Raw(payload);
            let mut env = match type_name {
                Some(name) => PulseEnvelope::typed(name, pd),
                None => PulseEnvelope::new(envelope_type, pd),
            };
            if broadcast {
                env.flags |= PulseEnvelopeFlags::BROADCAST;
            }
            env
        })
}

// =============================================================================
// Property 1 — codec roundtrip closes
// =============================================================================

proptest! {
    /// `from_canonical_bytes(env.to_canonical_bytes()) == env` for any
    /// envelope the public constructors can produce. This is the
    /// load-bearing codec invariant — any failure means the wire
    /// format has lost information.
    #[test]
    fn codec_roundtrip_closes(env in arb_envelope()) {
        let bytes = env.to_canonical_bytes();
        let decoded = PulseEnvelope::from_canonical_bytes(&bytes)
            .expect("canonical bytes from to_canonical_bytes must decode");
        prop_assert_eq!(env, decoded);
    }

    /// Encoding is total (never panics) over the explored input space.
    /// Subsumed by `codec_roundtrip_closes` but stated separately to
    /// make the totality claim explicit.
    #[test]
    fn encoding_is_total(env in arb_envelope()) {
        let _bytes = env.to_canonical_bytes();
        prop_assert!(true, "to_canonical_bytes did not panic");
    }
}

// =============================================================================
// Property 2 — content-ID is content-derived (same content → same id)
// =============================================================================

proptest! {
    /// Two envelopes built from byte-identical (envelope_type,
    /// type_name, payload) tuples produce byte-identical IDs. This is
    /// the determinism axiom underlying every other anchor; without
    /// it the content-addressing scheme is meaningless.
    #[test]
    fn same_content_same_id(
        envelope_type in arb_envelope_type(),
        type_name in arb_type_name(),
        payload in arb_raw_payload(),
    ) {
        let pd1 = PayloadData::Raw(payload.clone());
        let pd2 = PayloadData::Raw(payload);

        let id1 = match &type_name {
            Some(name) => PulseEnvelopeId::compute_from_payload(0, Some(name), &pd1),
            None => PulseEnvelopeId::compute_from_payload(envelope_type, None, &pd1),
        };
        let id2 = match &type_name {
            Some(name) => PulseEnvelopeId::compute_from_payload(0, Some(name), &pd2),
            None => PulseEnvelopeId::compute_from_payload(envelope_type, None, &pd2),
        };
        prop_assert_eq!(id1, id2);
    }
}

// =============================================================================
// Property 3 — content-ID changes when any input changes
// =============================================================================

proptest! {
    /// Flipping envelope_type with the same payload produces a
    /// different ID. Treat a collision as a test failure — the input
    /// space we explore is tiny relative to BLAKE3's 2^128 image, so
    /// any observed collision indicates a bug, not a hash collision.
    #[test]
    fn changing_envelope_type_changes_id(
        t1 in arb_envelope_type(),
        t2 in arb_envelope_type(),
        payload in arb_raw_payload(),
    ) {
        prop_assume!(t1 != t2);
        let pd = PayloadData::Raw(payload);
        let id1 = PulseEnvelopeId::compute_from_payload(t1, None, &pd);
        let id2 = PulseEnvelopeId::compute_from_payload(t2, None, &pd);
        prop_assert_ne!(id1, id2);
    }

    /// Flipping the payload (with same type_name and envelope_type)
    /// changes the ID. The `prop_assume!` filters degenerate cases
    /// where the proptest happens to draw identical payloads.
    #[test]
    fn changing_payload_changes_id(
        envelope_type in arb_envelope_type(),
        p1 in arb_raw_payload(),
        p2 in arb_raw_payload(),
    ) {
        prop_assume!(p1 != p2);
        let pd1 = PayloadData::Raw(p1);
        let pd2 = PayloadData::Raw(p2);
        let id1 = PulseEnvelopeId::compute_from_payload(envelope_type, None, &pd1);
        let id2 = PulseEnvelopeId::compute_from_payload(envelope_type, None, &pd2);
        prop_assert_ne!(id1, id2);
    }

    /// Different type_name with the same payload changes the ID
    /// (envelope_type = 0 for both, mirroring how `typed()` builds
    /// envelopes).
    #[test]
    fn changing_type_name_changes_id(
        n1 in "[a-zA-Z0-9_./:-]{1,32}",
        n2 in "[a-zA-Z0-9_./:-]{1,32}",
        payload in arb_raw_payload(),
    ) {
        prop_assume!(n1 != n2);
        let pd = PayloadData::Raw(payload);
        let id1 = PulseEnvelopeId::compute_from_payload(0, Some(&n1), &pd);
        let id2 = PulseEnvelopeId::compute_from_payload(0, Some(&n2), &pd);
        prop_assert_ne!(id1, id2);
    }
}

// =============================================================================
// Property 4 — verify() succeeds on every constructed envelope
// =============================================================================

proptest! {
    /// Every envelope built by a public constructor passes `verify()`.
    /// The constructor computes the ID; verify recomputes it and
    /// compares. If this ever fails, the constructor and the verifier
    /// disagree about what content-addressing means.
    #[test]
    fn constructed_envelopes_verify(env in arb_envelope()) {
        prop_assert!(env.verify(), "constructor produced an envelope that doesn't verify");
    }
}

// =============================================================================
// Property 5 — the decoder accepts only what the encoder writes
// =============================================================================

proptest! {
    /// Set any byte of an envelope's canonical bytes to any value, and
    /// maybe append a few: whatever `decode_canonical_at` accepts
    /// re-encodes to exactly the prefix it consumed, and whatever
    /// `from_canonical_bytes` accepts re-encodes to exactly its input.
    /// Nothing is normalised on the way through, so no two byte strings
    /// decode to one envelope (a reserved flag bit included).
    #[test]
    fn accepted_bytes_re_encode_to_themselves(
        env in arb_envelope(),
        at in any::<prop::sample::Index>(),
        value in any::<u8>(),
        extra in prop::collection::vec(any::<u8>(), 0..4),
    ) {
        let mut bytes = env.to_canonical_bytes();
        let i = at.index(bytes.len());
        bytes[i] = value;
        bytes.extend_from_slice(&extra);
        if let Ok((decoded, used)) = PulseEnvelope::decode_canonical_at(&bytes, 0) {
            prop_assert_eq!(decoded.to_canonical_bytes(), &bytes[..used]);
        }
        // Accepted whole, the input must be exactly the envelope's encoding,
        // which also shows that no byte after the envelope was ignored. The
        // appended bytes may belong to it: a mutated length can take them in.
        if let Ok(decoded) = PulseEnvelope::from_canonical_bytes(&bytes) {
            prop_assert_eq!(decoded.to_canonical_bytes(), bytes);
        }
    }
}
