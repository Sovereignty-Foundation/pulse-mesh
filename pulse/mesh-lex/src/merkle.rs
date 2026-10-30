// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! [`lex_root`], the public conformance anchor external implementers
//! recompute, with [`LexMerkle`] and [`MerkleDiff`].
//!
//! ## Algorithm
//!
//! 1. The leaves are the content hashes
//!    ([`crate::entry::LexEntry::content_hash`]) of the
//!    [`crate::entry::Boundary::Public`] entries, in
//!    [`crate::registry::LexRegistry::iter_public`] order.
//! 2. No leaves give `BLAKE3("mesh-lex/empty/v1")`.
//! 3. Otherwise each level hashes pairs as `BLAKE3(left ‖ right)`, an odd
//!    last leaf promoted unchanged, until one hash, the root, remains.
//!
//! The unit tests in `src/merkle.rs` pin each step.

use crate::registry::LexRegistry;

/// 32-byte digest type used throughout the substrate.
pub type Digest32 = [u8; 32];

/// The empty registry's root is this string's BLAKE3 hash.
const EMPTY_DOMAIN: &[u8] = b"mesh-lex/empty/v1";

/// The leaves and root over a registry's public entries, computed once at
/// construction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LexMerkle {
    leaves: Vec<Digest32>,
    root: Digest32,
}

impl LexMerkle {
    /// Leaf hashes in `iter_public` order — each is a
    /// [`crate::entry::LexEntry::content_hash`].
    #[must_use]
    pub fn leaves(&self) -> &[Digest32] {
        &self.leaves
    }

    /// Top-level hash. 32 bytes of BLAKE3.
    #[must_use]
    pub fn root(&self) -> Digest32 {
        self.root
    }

    /// Build a Merkle tree over a registry's public entries.
    #[must_use]
    pub fn from_registry(reg: &LexRegistry) -> Self {
        let leaves: Vec<Digest32> = reg.iter_public().map(|e| e.content_hash()).collect();
        let root = compute_root(&leaves);
        Self { leaves, root }
    }

    /// The tree of a registry with no public entries.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            leaves: Vec::new(),
            root: empty_root(),
        }
    }

    /// Lowercase hex rendering of [`Self::root`] (64 chars).
    #[must_use]
    pub fn root_hex(&self) -> String {
        hex_of(&self.root)
    }
}

/// The Merkle root over `reg`'s public entries: the value
/// `pulse/pulse-spec/lex-root.txt` records.
#[must_use]
pub fn lex_root(reg: &LexRegistry) -> Digest32 {
    LexMerkle::from_registry(reg).root
}

/// Convenience: hex-encoded [`lex_root`].
#[must_use]
pub fn lex_root_hex(reg: &LexRegistry) -> String {
    hex_of(&lex_root(reg))
}

fn empty_root() -> Digest32 {
    *blake3::hash(EMPTY_DOMAIN).as_bytes()
}

fn compute_root(leaves: &[Digest32]) -> Digest32 {
    if leaves.is_empty() {
        return empty_root();
    }
    let mut level: Vec<Digest32> = leaves.to_vec();
    while level.len() > 1 {
        let mut next: Vec<Digest32> = Vec::with_capacity(level.len().div_ceil(2));
        for chunk in level.chunks(2) {
            let combined = if chunk.len() == 2 {
                let mut hasher = blake3::Hasher::new();
                hasher.update(&chunk[0]);
                hasher.update(&chunk[1]);
                *hasher.finalize().as_bytes()
            } else {
                chunk[0]
            };
            next.push(combined);
        }
        level = next;
    }
    level[0]
}

fn hex_of(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Two roots, before and after; a per-entry diff is the caller's, from
/// the two registries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MerkleDiff {
    /// Previous root.
    pub prev: Digest32,
    /// New root.
    pub next: Digest32,
}

impl MerkleDiff {
    /// Construct a diff over two roots.
    #[must_use]
    pub fn between(prev: Digest32, next: Digest32) -> Self {
        Self { prev, next }
    }

    /// True when both roots are byte-equal.
    #[must_use]
    pub fn unchanged(&self) -> bool {
        self.prev == self.next
    }

    /// Lowercase hex rendering of the previous root.
    #[must_use]
    pub fn prev_hex(&self) -> String {
        hex_of(&self.prev)
    }

    /// Lowercase hex rendering of the new root.
    #[must_use]
    pub fn next_hex(&self) -> String {
        hex_of(&self.next)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::entry::{Boundary, DescriptorKind, LexEntry};

    fn entry(type_id: u16, name: &str, boundary: Boundary) -> LexEntry {
        LexEntry::new(
            type_id,
            name,
            1,
            DescriptorKind::EnvelopeType,
            boundary,
            Vec::<u8>::new(),
        )
    }

    #[test]
    fn empty_root_is_deterministic() {
        let a = LexMerkle::empty();
        let b = LexMerkle::empty();
        assert_eq!(a.root, b.root);
    }

    #[test]
    fn empty_root_matches_domain_hash() {
        let direct = *blake3::hash(b"mesh-lex/empty/v1").as_bytes();
        assert_eq!(LexMerkle::empty().root, direct);
    }

    #[test]
    fn empty_registry_yields_empty_root() {
        let reg = LexRegistry::new();
        assert_eq!(lex_root(&reg), LexMerkle::empty().root);
    }

    #[test]
    fn single_public_entry_root_is_that_leaf() {
        let mut reg = LexRegistry::new();
        let e = entry(0x0010, "alpha", Boundary::Public);
        let leaf = e.content_hash();
        reg.insert(e).unwrap();
        assert_eq!(lex_root(&reg), leaf);
    }

    #[test]
    fn non_public_entries_do_not_affect_root() {
        let mut reg_a = LexRegistry::new();
        reg_a
            .insert(entry(0x0010, "alpha", Boundary::Public))
            .unwrap();

        let mut reg_b = LexRegistry::new();
        reg_b
            .insert(entry(0x0010, "alpha", Boundary::Public))
            .unwrap();
        reg_b
            .insert(entry(0x0020, "mesh", Boundary::MeshScoped))
            .unwrap();
        reg_b
            .insert(entry(0x0030, "node", Boundary::NodeScoped))
            .unwrap();

        assert_eq!(lex_root(&reg_a), lex_root(&reg_b));
    }

    #[test]
    fn root_is_deterministic_across_insertion_orders() {
        let mut a = LexRegistry::new();
        a.insert(entry(0x0030, "c", Boundary::Public)).unwrap();
        a.insert(entry(0x0010, "a", Boundary::Public)).unwrap();
        a.insert(entry(0x0020, "b", Boundary::Public)).unwrap();

        let mut b = LexRegistry::new();
        b.insert(entry(0x0010, "a", Boundary::Public)).unwrap();
        b.insert(entry(0x0020, "b", Boundary::Public)).unwrap();
        b.insert(entry(0x0030, "c", Boundary::Public)).unwrap();

        assert_eq!(lex_root(&a), lex_root(&b));
    }

    #[test]
    fn root_differs_when_a_public_entry_changes() {
        let mut a = LexRegistry::new();
        a.insert(entry(0x0010, "alpha", Boundary::Public)).unwrap();

        let mut b = LexRegistry::new();
        b.insert(entry(0x0010, "alphax", Boundary::Public)).unwrap();

        assert_ne!(lex_root(&a), lex_root(&b));
    }

    #[test]
    fn two_entry_root_combines_via_blake3_pair() {
        let mut reg = LexRegistry::new();
        let e1 = entry(0x0010, "alpha", Boundary::Public);
        let e2 = entry(0x0020, "beta", Boundary::Public);
        let h1 = e1.content_hash();
        let h2 = e2.content_hash();
        reg.insert(e1).unwrap();
        reg.insert(e2).unwrap();

        let mut hasher = blake3::Hasher::new();
        hasher.update(&h1);
        hasher.update(&h2);
        let expected = *hasher.finalize().as_bytes();

        assert_eq!(lex_root(&reg), expected);
    }

    #[test]
    fn odd_leaf_count_is_promoted_at_level() {
        let mut reg = LexRegistry::new();
        let e1 = entry(0x0010, "a", Boundary::Public);
        let e2 = entry(0x0020, "b", Boundary::Public);
        let e3 = entry(0x0030, "c", Boundary::Public);
        let h1 = e1.content_hash();
        let h2 = e2.content_hash();
        let h3 = e3.content_hash();
        reg.insert(e1).unwrap();
        reg.insert(e2).unwrap();
        reg.insert(e3).unwrap();

        let mut hasher = blake3::Hasher::new();
        hasher.update(&h1);
        hasher.update(&h2);
        let pair = *hasher.finalize().as_bytes();

        let mut hasher = blake3::Hasher::new();
        hasher.update(&pair);
        hasher.update(&h3);
        let expected = *hasher.finalize().as_bytes();

        assert_eq!(lex_root(&reg), expected);
    }

    #[test]
    fn lex_root_hex_is_64_chars() {
        let reg = LexRegistry::new();
        assert_eq!(lex_root_hex(&reg).len(), 64);
    }

    #[test]
    fn merkle_diff_detects_change() {
        let a = LexMerkle::empty().root;
        let b = {
            let mut reg = LexRegistry::new();
            reg.insert(entry(0x0010, "alpha", Boundary::Public))
                .unwrap();
            lex_root(&reg)
        };

        let same = MerkleDiff::between(a, a);
        assert!(same.unchanged());
        assert_eq!(same.prev_hex(), same.next_hex());

        let changed = MerkleDiff::between(a, b);
        assert!(!changed.unchanged());
        assert_ne!(changed.prev_hex(), changed.next_hex());
    }
}
