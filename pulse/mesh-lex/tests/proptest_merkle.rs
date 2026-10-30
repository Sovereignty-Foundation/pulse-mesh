// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Property-based tests of the laws `lex_root()` keeps, the publication
//! anchor external implementers must reproduce from the same registry.

use mesh_lex::{lex_root, Boundary, DescriptorKind, LexEntry, LexRegistry};
use proptest::prelude::*;

fn arb_kind() -> impl Strategy<Value = DescriptorKind> {
    prop_oneof![
        Just(DescriptorKind::EnvelopeType),
        Just(DescriptorKind::Producer),
        Just(DescriptorKind::Consumer),
        Just(DescriptorKind::BundleSchema),
    ]
}

/// Generate a public entry (participates in `lex_root()`).
fn arb_public_entry() -> impl Strategy<Value = LexEntry> {
    (
        any::<u16>(),
        "[a-zA-Z0-9_./:-]{1,40}",
        any::<u32>(),
        arb_kind(),
        prop::collection::vec(any::<u8>(), 0..128),
    )
        .prop_map(|(type_id, name, version, kind, schema_bytes)| {
            LexEntry::new(type_id, name, version, kind, Boundary::Public, schema_bytes)
        })
}

/// Generate a non-public entry (excluded from `lex_root()`).
fn arb_non_public_entry() -> impl Strategy<Value = LexEntry> {
    let arb_non_public_boundary =
        prop_oneof![Just(Boundary::MeshScoped), Just(Boundary::NodeScoped),];
    (
        any::<u16>(),
        "[a-zA-Z0-9_./:-]{1,40}",
        any::<u32>(),
        arb_kind(),
        arb_non_public_boundary,
        prop::collection::vec(any::<u8>(), 0..128),
    )
        .prop_map(|(type_id, name, version, kind, boundary, schema_bytes)| {
            LexEntry::new(type_id, name, version, kind, boundary, schema_bytes)
        })
}

/// Distinct-key set of public entries.
fn arb_public_entry_set(max_n: usize) -> impl Strategy<Value = Vec<LexEntry>> {
    prop::collection::vec(arb_public_entry(), 1..=max_n).prop_map(|entries| {
        let mut by_key: std::collections::BTreeMap<(u16, DescriptorKind), LexEntry> =
            std::collections::BTreeMap::new();
        for e in entries {
            by_key.insert((e.type_id, e.kind), e);
        }
        by_key.into_values().collect()
    })
}

proptest! {
    /// `lex_root(LexRegistry::new()) == BLAKE3("mesh-lex/empty/v1")`.
    #[test]
    fn empty_registry_matches_domain_sentinel(_ in 0..1) {
        let reg = LexRegistry::new();
        let root = lex_root(&reg);
        let expected = *blake3::hash(b"mesh-lex/empty/v1").as_bytes();
        prop_assert_eq!(root, expected);
    }
}

proptest! {
    /// The same registry computed twice yields byte-equal roots.
    #[test]
    fn determinism(entries in arb_public_entry_set(12)) {
        let reg = build_registry(&entries);
        let r1 = lex_root(&reg);
        let r2 = lex_root(&reg);
        prop_assert_eq!(r1, r2);
    }
}

proptest! {
    /// The same set of entries inserted in different orders gives the same
    /// root.
    #[test]
    fn insertion_order_independence(entries in arb_public_entry_set(12)) {
        let reg_a = build_registry(&entries);

        let mut shuffled = entries.clone();
        shuffled.reverse();
        let reg_b = build_registry(&shuffled);

        prop_assert_eq!(lex_root(&reg_a), lex_root(&reg_b));
    }
}

proptest! {
    /// Adding a non-public (MeshScoped or NodeScoped) entry does not
    /// change the root.
    #[test]
    fn non_public_entry_does_not_affect_root(
        public_entries in arb_public_entry_set(8),
        non_public in arb_non_public_entry(),
    ) {
        // A colliding (type_id, kind) is refused: another test's case.
        prop_assume!(
            !public_entries.iter().any(|e| e.type_id == non_public.type_id && e.kind == non_public.kind)
        );

        let reg_a = build_registry(&public_entries);
        let root_a = lex_root(&reg_a);

        let mut reg_b = reg_a.clone();
        reg_b.insert(non_public).expect("non-public insert");
        let root_b = lex_root(&reg_b);

        prop_assert_eq!(root_a, root_b);
    }
}

proptest! {
    /// Adding a public entry to a non-empty registry changes the root.
    #[test]
    fn adding_public_entry_changes_root(
        seed_entries in arb_public_entry_set(8),
        new_entry in arb_public_entry(),
    ) {
        prop_assume!(
            !seed_entries.iter().any(|e| e.type_id == new_entry.type_id && e.kind == new_entry.kind)
        );

        let reg_a = build_registry(&seed_entries);
        let root_a = lex_root(&reg_a);

        let mut reg_b = reg_a.clone();
        reg_b.insert(new_entry).expect("new public insert");
        let root_b = lex_root(&reg_b);

        prop_assert_ne!(root_a, root_b);
    }
}

fn build_registry(entries: &[LexEntry]) -> LexRegistry {
    let mut reg = LexRegistry::new();
    for entry in entries {
        reg.insert(entry.clone()).expect("test helper insert");
    }
    reg
}
