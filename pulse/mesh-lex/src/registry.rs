// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! [`LexRegistry`], the catalog's entries by `(type_id, kind)`.

use std::collections::BTreeMap;

use crate::entry::{DescriptorKind, LexEntry};

/// Errors raised by [`LexRegistry`] operations.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum LexRegistryError {
    /// Insert refused: an entry with the same `(type_id, kind)` is
    /// already registered.
    #[error("duplicate entry: type_id 0x{type_id:04x}, kind {kind:?}")]
    Duplicate {
        /// The type_id that already exists.
        type_id: u16,
        /// The kind that already exists.
        kind: DescriptorKind,
    },
    /// [`LexRegistry::validate`] found two entries with one name.
    #[error(
        "name conflict: '{name}' used by both (0x{a_type_id:04x}, {a_kind:?}) \
         and (0x{b_type_id:04x}, {b_kind:?})"
    )]
    NameConflict {
        /// The conflicting name.
        name: String,
        /// First entry's type_id.
        a_type_id: u16,
        /// First entry's kind.
        a_kind: DescriptorKind,
        /// Second entry's type_id.
        b_type_id: u16,
        /// Second entry's kind.
        b_kind: DescriptorKind,
    },
}

/// [`LexEntry`]s by `(type_id, kind)`, iterated in key order, the order
/// [`lex_root`](crate::merkle::lex_root) takes its leaves in, so the root
/// agrees on every host.
#[derive(Debug, Clone, Default)]
pub struct LexRegistry {
    entries: BTreeMap<(u16, DescriptorKind), LexEntry>,
}

impl LexRegistry {
    /// Build an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of registered entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True when no entries are registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Register an entry. Names are not checked here ([`Self::validate`]).
    ///
    /// # Errors
    /// [`LexRegistryError::Duplicate`] if an entry with the same
    /// `(type_id, kind)` is present.
    pub fn insert(&mut self, entry: LexEntry) -> Result<(), LexRegistryError> {
        let key = (entry.type_id, entry.kind);
        if self.entries.contains_key(&key) {
            return Err(LexRegistryError::Duplicate {
                type_id: entry.type_id,
                kind: entry.kind,
            });
        }
        self.entries.insert(key, entry);
        Ok(())
    }

    /// Look up by `(type_id, kind)`.
    #[must_use]
    pub fn lookup(&self, type_id: u16, kind: DescriptorKind) -> Option<&LexEntry> {
        self.entries.get(&(type_id, kind))
    }

    /// The first entry with this name in key order, by a linear scan.
    #[must_use]
    pub fn lookup_by_name(&self, name: &str) -> Option<&LexEntry> {
        self.entries.values().find(|e| e.name == name)
    }

    /// Iterate every entry in deterministic key order.
    pub fn iter(&self) -> impl Iterator<Item = &LexEntry> {
        self.entries.values()
    }

    /// Iterate the [`crate::entry::Boundary::Public`] entries, the root's
    /// leaves, in key order.
    pub fn iter_public(&self) -> impl Iterator<Item = &LexEntry> {
        self.entries.values().filter(|e| e.boundary.is_public())
    }

    /// Check that names are unique; run it before
    /// [`commit_tick`](crate::commit::commit_tick).
    ///
    /// # Errors
    /// [`LexRegistryError::NameConflict`] for the first two entries that
    /// share a name.
    pub fn validate(&self) -> Result<(), LexRegistryError> {
        let mut seen: BTreeMap<&str, (u16, DescriptorKind)> = BTreeMap::new();
        for entry in self.entries.values() {
            if let Some(&(a_type_id, a_kind)) = seen.get(entry.name.as_str()) {
                return Err(LexRegistryError::NameConflict {
                    name: entry.name.clone(),
                    a_type_id,
                    a_kind,
                    b_type_id: entry.type_id,
                    b_kind: entry.kind,
                });
            }
            seen.insert(&entry.name, (entry.type_id, entry.kind));
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::entry::Boundary;

    fn entry(type_id: u16, name: &str, kind: DescriptorKind, boundary: Boundary) -> LexEntry {
        LexEntry::new(type_id, name, 1, kind, boundary, Vec::<u8>::new())
    }

    #[test]
    fn empty_registry_has_zero_length() {
        let reg = LexRegistry::new();
        assert_eq!(reg.len(), 0);
        assert!(reg.is_empty());
        assert!(reg.iter().next().is_none());
        assert!(reg.lookup(0x0001, DescriptorKind::EnvelopeType).is_none());
    }

    #[test]
    fn insert_lookup_roundtrip() {
        let mut reg = LexRegistry::new();
        let e = entry(
            0x0010,
            "canon/vector",
            DescriptorKind::EnvelopeType,
            Boundary::Public,
        );
        reg.insert(e.clone()).unwrap();
        let got = reg
            .lookup(0x0010, DescriptorKind::EnvelopeType)
            .expect("lookup");
        assert_eq!(got, &e);
    }

    #[test]
    fn insert_duplicate_key_is_refused() {
        let mut reg = LexRegistry::new();
        let a = entry(0x0010, "a", DescriptorKind::EnvelopeType, Boundary::Public);
        let b = entry(0x0010, "b", DescriptorKind::EnvelopeType, Boundary::Public);
        reg.insert(a).unwrap();
        let err = reg.insert(b).unwrap_err();
        match err {
            LexRegistryError::Duplicate { type_id, kind } => {
                assert_eq!(type_id, 0x0010);
                assert_eq!(kind, DescriptorKind::EnvelopeType);
            }
            other => panic!("expected Duplicate, got {other:?}"),
        }
    }

    #[test]
    fn same_type_id_different_kind_coexists() {
        let mut reg = LexRegistry::new();
        reg.insert(entry(
            0x0010,
            "ev",
            DescriptorKind::EnvelopeType,
            Boundary::Public,
        ))
        .unwrap();
        reg.insert(entry(
            0x0010,
            "prod",
            DescriptorKind::Producer,
            Boundary::MeshScoped,
        ))
        .unwrap();
        assert_eq!(reg.len(), 2);
    }

    #[test]
    fn iter_public_filters_non_public() {
        let mut reg = LexRegistry::new();
        reg.insert(entry(
            0x0010,
            "pub",
            DescriptorKind::EnvelopeType,
            Boundary::Public,
        ))
        .unwrap();
        reg.insert(entry(
            0x0020,
            "mesh",
            DescriptorKind::EnvelopeType,
            Boundary::MeshScoped,
        ))
        .unwrap();
        reg.insert(entry(
            0x0030,
            "node",
            DescriptorKind::EnvelopeType,
            Boundary::NodeScoped,
        ))
        .unwrap();
        let public_names: Vec<&str> = reg.iter_public().map(|e| e.name.as_str()).collect();
        assert_eq!(public_names, vec!["pub"]);
    }

    #[test]
    fn iter_order_is_deterministic_across_insertion_orders() {
        let mut a = LexRegistry::new();
        a.insert(entry(
            0x0030,
            "c",
            DescriptorKind::EnvelopeType,
            Boundary::Public,
        ))
        .unwrap();
        a.insert(entry(
            0x0010,
            "a",
            DescriptorKind::EnvelopeType,
            Boundary::Public,
        ))
        .unwrap();
        a.insert(entry(
            0x0020,
            "b",
            DescriptorKind::EnvelopeType,
            Boundary::Public,
        ))
        .unwrap();

        let mut b = LexRegistry::new();
        b.insert(entry(
            0x0010,
            "a",
            DescriptorKind::EnvelopeType,
            Boundary::Public,
        ))
        .unwrap();
        b.insert(entry(
            0x0020,
            "b",
            DescriptorKind::EnvelopeType,
            Boundary::Public,
        ))
        .unwrap();
        b.insert(entry(
            0x0030,
            "c",
            DescriptorKind::EnvelopeType,
            Boundary::Public,
        ))
        .unwrap();

        let order_a: Vec<u16> = a.iter().map(|e| e.type_id).collect();
        let order_b: Vec<u16> = b.iter().map(|e| e.type_id).collect();
        assert_eq!(order_a, vec![0x0010, 0x0020, 0x0030]);
        assert_eq!(order_a, order_b);
    }

    #[test]
    fn lookup_by_name_finds_a_match() {
        let mut reg = LexRegistry::new();
        reg.insert(entry(
            0x0010,
            "canon/vector",
            DescriptorKind::EnvelopeType,
            Boundary::Public,
        ))
        .unwrap();
        let found = reg.lookup_by_name("canon/vector").unwrap();
        assert_eq!(found.type_id, 0x0010);
        assert!(reg.lookup_by_name("missing").is_none());
    }

    #[test]
    fn validate_passes_on_unique_names() {
        let mut reg = LexRegistry::new();
        reg.insert(entry(
            0x0010,
            "alpha",
            DescriptorKind::EnvelopeType,
            Boundary::Public,
        ))
        .unwrap();
        reg.insert(entry(
            0x0020,
            "beta",
            DescriptorKind::EnvelopeType,
            Boundary::Public,
        ))
        .unwrap();
        reg.validate().unwrap();
    }

    #[test]
    fn validate_catches_name_conflict() {
        let mut reg = LexRegistry::new();
        reg.insert(entry(
            0x0010,
            "shared",
            DescriptorKind::EnvelopeType,
            Boundary::Public,
        ))
        .unwrap();
        // Different (type_id, kind) so insert succeeds, but name is duplicated.
        reg.insert(entry(
            0x0020,
            "shared",
            DescriptorKind::Producer,
            Boundary::Public,
        ))
        .unwrap();
        let err = reg.validate().unwrap_err();
        match err {
            LexRegistryError::NameConflict { name, .. } => {
                assert_eq!(name, "shared");
            }
            other => panic!("expected NameConflict, got {other:?}"),
        }
    }
}
