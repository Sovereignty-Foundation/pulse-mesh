// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Property-based tests for the `Pulse` opcode dispatch.
//!
//! `Instruction::from_u16` is documented as **total** — every `u16`
//! maps to some variant, with unknown opcodes routing to `Null`. The
//! locked fixture in `math_anchor.rs` pins a specific known-good byte
//! layout; this file pins the surrounding behavioural invariants:
//!
//! 1. **`from_u16` is total**: every `u16` value yields a valid
//!    `Instruction` without panic.
//! 2. **Known opcodes map correctly**: 0x0001 → Heartbeat, 0x0010 →
//!    Data, 0x0000 → Null.
//! 3. **Unknown opcodes route to Null**: any `u16` outside the known
//!    set returns `Instruction::Null`.
//! 4. **Idempotence at the discriminant boundary**: converting an
//!    `Instruction` to its `u16` discriminant and back yields the
//!    same variant.

use proptest::prelude::*;
use pulse_canon::Instruction;

// =============================================================================
// Property 1 — Instruction::from_u16 is total
// =============================================================================

proptest! {
    /// Every `u16` produces a valid `Instruction` without panic. This
    /// is the totality axiom for the opcode dispatch; if it ever
    /// fails, an unhandled opcode is reaching the receiver and the
    /// wire-format compatibility guarantee is broken.
    #[test]
    fn from_u16_is_total(value in any::<u16>()) {
        let _ = Instruction::from_u16(value);
        prop_assert!(true, "from_u16 did not panic");
    }

    /// `from_u16(0x0001) == Heartbeat` — pinning the known opcode
    /// regardless of how the proptest engine schedules its cases.
    #[test]
    fn from_u16_known_opcodes_route_correctly(_ in 0..1) {
        prop_assert_eq!(Instruction::from_u16(0x0000), Instruction::Null);
        prop_assert_eq!(Instruction::from_u16(0x0001), Instruction::Heartbeat);
        prop_assert_eq!(Instruction::from_u16(0x0010), Instruction::Data);
    }

    /// Any `u16` outside the known set routes to `Null`. Pulls 8 K
    /// random values per run (proptest default); the chance of all
    /// of them missing the {0x0001, 0x0010} set on a 16-bit space
    /// is overwhelming (≈ 1 − 2/65536 per draw).
    #[test]
    fn unknown_opcodes_route_to_null(value in any::<u16>()) {
        prop_assume!(value != 0x0001 && value != 0x0010);
        prop_assert_eq!(Instruction::from_u16(value), Instruction::Null);
    }
}

// =============================================================================
// Property 2 — discriminant roundtrip
// =============================================================================

proptest! {
    /// For each known variant, casting the enum to its underlying u16
    /// discriminant and reading it back via `from_u16` yields the
    /// same variant. This is the loop the receiver actually runs:
    /// read the on-wire u16, decode to enum, re-emit on outbound.
    #[test]
    fn known_variant_discriminant_roundtrip(_ in 0..1) {
        for variant in [
            Instruction::Null,
            Instruction::Heartbeat,
            Instruction::Data,
        ] {
            let raw = variant as u16;
            let decoded = Instruction::from_u16(raw);
            prop_assert_eq!(decoded, variant);
        }
    }
}
