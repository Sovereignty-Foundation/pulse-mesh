// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Property-based tests of `LexRegistry`, whose entries `lex_root()` folds
//! into a Merkle root: lookup, the `(type_id, kind)` key, and iteration
//! independent of insertion order.

use mesh_lex::{Boundary, DescriptorKind, LexEntry, LexRegistry, LexRegistryError};
use proptest::prelude::*;

fn arb_kind() -> impl Strategy<Value = DescriptorKind> {
    prop_oneof![
        Just(DescriptorKind::EnvelopeType),
        Just(DescriptorKind::Producer),
        Just(DescriptorKind::Consumer),
        Just(DescriptorKind::BundleSchema),
    ]
}

fn arb_boundary() -> impl Strategy<Value = Boundary> {
    prop_oneof![
        Just(Boundary::Public),
        Just(Boundary::MeshScoped),
        Just(Boundary::NodeScoped),
    ]
}

/// One entry, its name in the conventional charset: the registry does not
/// care about exotic Unicode, so cases are not spent on it.
fn arb_entry() -> impl Strategy<Value = LexEntry> {
    (
        any::<u16>(),
        "[a-zA-Z0-9_./:-]{1,40}",
        any::<u32>(),
        arb_kind(),
        arb_boundary(),
        prop::collection::vec(any::<u8>(), 0..128),
    )
        .prop_map(|(type_id, name, version, kind, boundary, schema_bytes)| {
            LexEntry::new(type_id, name, version, kind, boundary, schema_bytes)
        })
}

/// Entries with distinct `(type_id, kind)` keys, so all of them insert.
fn arb_entry_set(max_n: usize) -> impl Strategy<Value = Vec<LexEntry>> {
    prop::collection::vec(arb_entry(), 1..=max_n).prop_map(|entries| {
        // The last entry of each key wins.
        let mut by_key: std::collections::BTreeMap<(u16, DescriptorKind), LexEntry> =
            std::collections::BTreeMap::new();
        for e in entries {
            by_key.insert((e.type_id, e.kind), e);
        }
        by_key.into_values().collect()
    })
}

proptest! {
    /// Inserting an entry makes it retrievable by `(type_id, kind)`.
    #[test]
    fn insert_then_lookup_by_key(entry in arb_entry()) {
        let mut reg = LexRegistry::new();
        reg.insert(entry.clone()).expect("first insert must succeed");
        let found = reg.lookup(entry.type_id, entry.kind);
        prop_assert_eq!(found, Some(&entry));
    }

    /// Inserting an entry makes it retrievable by name (linear scan).
    #[test]
    fn insert_then_lookup_by_name(entry in arb_entry()) {
        let mut reg = LexRegistry::new();
        let name = entry.name.clone();
        reg.insert(entry.clone()).expect("first insert must succeed");
        let found = reg.lookup_by_name(&name);
        prop_assert_eq!(found, Some(&entry));
    }
}

proptest! {
    /// A second insert with the same `(type_id, kind)` is rejected
    /// with `LexRegistryError::Duplicate` carrying the conflicting
    /// key.
    #[test]
    fn duplicate_key_rejected(entry in arb_entry()) {
        let mut reg = LexRegistry::new();
        reg.insert(entry.clone()).expect("first insert");

        // Build a sibling with the same key but different other fields.
        let sibling = LexEntry::new(
            entry.type_id,
            format!("{}-sibling", entry.name),
            entry.version.wrapping_add(1),
            entry.kind,
            entry.boundary,
            vec![],
        );
        let result = reg.insert(sibling);
        match result {
            Err(LexRegistryError::Duplicate { type_id, kind }) => {
                prop_assert_eq!(type_id, entry.type_id);
                prop_assert_eq!(kind, entry.kind);
            }
            other => panic!(
                "expected Duplicate error, got {:?}",
                other
            ),
        }
    }
}

proptest! {
    /// Two entries with the same `type_id` and different kinds both
    /// insert.
    #[test]
    fn same_type_id_different_kind_coexist(
        type_id in any::<u16>(),
        k1 in arb_kind(),
        k2 in arb_kind(),
        n1 in "[a-zA-Z0-9_./:-]{1,40}",
        n2 in "[a-zA-Z0-9_./:-]{1,40}",
    ) {
        prop_assume!(k1 != k2);
        prop_assume!(n1 != n2);

        let mut reg = LexRegistry::new();
        let e1 = LexEntry::new(type_id, &n1, 1, k1, Boundary::Public, vec![]);
        let e2 = LexEntry::new(type_id, &n2, 1, k2, Boundary::Public, vec![]);

        reg.insert(e1.clone()).expect("first insert");
        reg.insert(e2.clone()).expect("second insert with different kind");

        prop_assert_eq!(reg.len(), 2);
        prop_assert_eq!(reg.lookup(type_id, k1), Some(&e1));
        prop_assert_eq!(reg.lookup(type_id, k2), Some(&e2));
    }
}

proptest! {
    /// Two registries built from the same entries in different orders
    /// iterate identically.
    #[test]
    fn iteration_order_is_insertion_order_independent(
        entries in arb_entry_set(12),
    ) {
        let reg_a = build_registry(&entries);

        let mut shuffled = entries.clone();
        shuffled.reverse();
        let reg_b = build_registry(&shuffled);

        let seq_a: Vec<_> = reg_a.iter().collect();
        let seq_b: Vec<_> = reg_b.iter().collect();

        prop_assert_eq!(seq_a, seq_b);
        prop_assert_eq!(reg_a.len(), reg_b.len());
    }

    /// `iter().count() == len()` for any registry built by inserting
    /// a distinct-key entry set.
    #[test]
    fn iter_count_equals_len(entries in arb_entry_set(16)) {
        let reg = build_registry(&entries);
        prop_assert_eq!(reg.iter().count(), reg.len());
    }
}

fn build_registry(entries: &[LexEntry]) -> LexRegistry {
    let mut reg = LexRegistry::new();
    for entry in entries {
        reg.insert(entry.clone())
            .expect("entry insert in test helper");
    }
    reg
}
