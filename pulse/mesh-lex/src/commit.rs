// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! The commit boundary: [`commit_tick`] turns a
//! [`crate::registry::LexRegistry`]'s state into a [`MerkleChangeEvent`],
//! which tells a subscriber the catalog moved without polling every entry.

use serde::{Deserialize, Serialize};

use crate::merkle::{lex_root, Digest32};
use crate::registry::LexRegistry;

/// What [`commit_tick`] reports: both roots, so a subscriber sees a change
/// cheaply ([`Self::root_changed`]) and can audit it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerkleChangeEvent {
    /// Previous root, or `None` for the first tick after startup.
    pub prev_root: Option<Digest32>,
    /// New root.
    pub next_root: Digest32,
    /// Tick number, one more per tick, so consumers can detect missed
    /// events.
    pub tick_id: u64,
}

impl MerkleChangeEvent {
    /// True when `next_root` differs from `prev_root`, and on the first
    /// tick, which has no `prev_root`.
    #[must_use]
    pub fn root_changed(&self) -> bool {
        match self.prev_root {
            None => true,
            Some(prev) => prev != self.next_root,
        }
    }

    /// Hex rendering of the new root (64 chars).
    #[must_use]
    pub fn next_root_hex(&self) -> String {
        self.next_root
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect()
    }
}

/// The [`MerkleChangeEvent`] for `reg`'s current state. Stateless: the
/// caller threads `prev_root` and `tick_id` through, as in:
///
/// ```text
/// loop {
///     let evt = commit_tick(&reg, last_root, next_tick_id);
///     if evt.root_changed() {
///         broadcast(&evt);
///     }
///     last_root = Some(evt.next_root);
///     next_tick_id += 1;
/// }
/// ```
#[must_use]
pub fn commit_tick(
    reg: &LexRegistry,
    prev_root: Option<Digest32>,
    tick_id: u64,
) -> MerkleChangeEvent {
    MerkleChangeEvent {
        prev_root,
        next_root: lex_root(reg),
        tick_id,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::entry::{Boundary, DescriptorKind, LexEntry};

    fn entry(type_id: u16, name: &str) -> LexEntry {
        LexEntry::new(
            type_id,
            name,
            1,
            DescriptorKind::EnvelopeType,
            Boundary::Public,
            Vec::<u8>::new(),
        )
    }

    #[test]
    fn first_tick_signals_change() {
        let reg = LexRegistry::new();
        let evt = commit_tick(&reg, None, 1);
        assert!(evt.root_changed());
        assert_eq!(evt.tick_id, 1);
        assert_eq!(evt.next_root, lex_root(&reg));
    }

    #[test]
    fn unchanged_registry_does_not_signal_change() {
        let mut reg = LexRegistry::new();
        reg.insert(entry(0x0010, "alpha")).unwrap();
        let root1 = lex_root(&reg);

        let evt = commit_tick(&reg, Some(root1), 2);
        assert!(!evt.root_changed());
    }

    #[test]
    fn changed_registry_signals_change() {
        let mut reg = LexRegistry::new();
        reg.insert(entry(0x0010, "alpha")).unwrap();
        let root1 = lex_root(&reg);

        reg.insert(entry(0x0020, "beta")).unwrap();
        let evt = commit_tick(&reg, Some(root1), 2);

        assert!(evt.root_changed());
        assert_eq!(evt.prev_root, Some(root1));
        assert_ne!(evt.next_root, root1);
    }

    #[test]
    fn tick_id_carries_through() {
        let reg = LexRegistry::new();
        let evt = commit_tick(&reg, None, 42);
        assert_eq!(evt.tick_id, 42);
    }

    #[test]
    fn next_root_hex_is_64_chars() {
        let reg = LexRegistry::new();
        let evt = commit_tick(&reg, None, 1);
        assert_eq!(evt.next_root_hex().len(), 64);
    }

    #[test]
    fn merkle_change_event_serde_roundtrip() {
        let reg = LexRegistry::new();
        let original = commit_tick(&reg, None, 1);
        let json = serde_json::to_string(&original).unwrap();
        let recovered: MerkleChangeEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(original, recovered);
    }
}
