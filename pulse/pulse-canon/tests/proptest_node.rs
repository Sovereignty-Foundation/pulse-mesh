// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Property-based tests for `NodeId` derivation.
//!
//! `NodeId::from_name` is documented as `BLAKE3(name)[..16]`. The
//! locked fixture in `math_anchor.rs` pins this against a specific
//! set of name vectors; this file pins the surrounding abstract laws:
//!
//! 1. **Determinism**: same input name → same NodeId, every call.
//!    The pure-function axiom; without it, every node-identity check
//!    in the mesh becomes non-deterministic.
//!
//! 2. **Distinctness** (probabilistic): different names produce
//!    different IDs with overwhelming probability. Treat a collision
//!    in the explored space as a failure — 16 bytes is 2^128 image,
//!    so observed collisions indicate a bug, not a hash collision.
//!
//! 3. **Hex roundtrip**: `to_hex()` produces a 32-char lowercase
//!    hex string; decoding it via `hex::decode` recovers the
//!    underlying byte array.
//!
//! 4. **`from_bytes` is identity-on-bytes**: wrapping a `[u8; 16]`
//!    into a NodeId and reading the bytes back yields the same array.

use proptest::prelude::*;
use pulse_canon::NodeId;

// =============================================================================
// Generators
// =============================================================================

/// Names that exercise the realistic input space:
/// - empty strings (degenerate but valid input)
/// - alphanumeric with the punctuation characters PMS conventionally uses
/// - bounded length so the hash work stays cheap
fn arb_name() -> impl Strategy<Value = String> {
    prop_oneof![
        Just(String::new()),
        "[a-zA-Z0-9_./:-]{1,128}".prop_map(|s| s),
    ]
}

// =============================================================================
// Property 1 — determinism
// =============================================================================

proptest! {
    /// Two calls to `from_name` with the same input produce byte-equal
    /// NodeIds. Pure-function axiom.
    #[test]
    fn from_name_is_deterministic(name in arb_name()) {
        let a = NodeId::from_name(&name);
        let b = NodeId::from_name(&name);
        prop_assert_eq!(a, b);
    }
}

// =============================================================================
// Property 2 — distinctness (probabilistic, BLAKE3 collision-resistance)
// =============================================================================

proptest! {
    /// Distinct names produce distinct IDs with probability ≈ 1.
    /// `prop_assume!` filters degenerate cases where the proptest
    /// happens to draw identical names.
    #[test]
    fn distinct_names_distinct_ids(
        n1 in arb_name(),
        n2 in arb_name(),
    ) {
        prop_assume!(n1 != n2);
        let id1 = NodeId::from_name(&n1);
        let id2 = NodeId::from_name(&n2);
        prop_assert_ne!(id1, id2);
    }
}

// =============================================================================
// Property 3 — hex roundtrip
// =============================================================================

proptest! {
    /// `to_hex()` produces a 32-character lowercase hex string;
    /// decoding via `hex::decode` recovers the underlying 16-byte
    /// array. This is the form NodeIds travel in over JSON / TOML /
    /// logs.
    #[test]
    fn hex_roundtrip_recovers_bytes(name in arb_name()) {
        let id = NodeId::from_name(&name);
        let hex_string = id.to_hex();
        prop_assert_eq!(hex_string.len(), 32);
        prop_assert!(hex_string.chars().all(|c| c.is_ascii_hexdigit() && (c.is_numeric() || c.is_lowercase())));

        let decoded = hex::decode(&hex_string).expect("to_hex output must be valid hex");
        prop_assert_eq!(decoded.len(), 16);
        prop_assert_eq!(decoded.as_slice(), id.as_bytes().as_slice());
    }
}

// =============================================================================
// Property 4 — from_bytes is identity-on-bytes
// =============================================================================

proptest! {
    /// Wrapping arbitrary bytes via `from_bytes` and reading them
    /// back via `as_bytes()` yields the same array. NodeId is a
    /// transparent wrapper; this codifies that.
    #[test]
    fn from_bytes_identity(bytes in any::<[u8; 16]>()) {
        let id = NodeId::from_bytes(bytes);
        prop_assert_eq!(id.as_bytes(), &bytes);
    }

    /// `NodeId::ZERO == NodeId::from_bytes([0; 16])` — the const
    /// sentinel agrees with the constructor.
    #[test]
    fn zero_sentinel_matches_constructor(_ in 0..1) {
        prop_assert_eq!(NodeId::ZERO, NodeId::from_bytes([0u8; 16]));
        prop_assert!(NodeId::ZERO.is_zero());
    }
}
