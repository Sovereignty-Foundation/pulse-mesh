// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
#![forbid(unsafe_code)]

//! The context registry, tier 2: names for the high half of a Pulse's scope.
//! **Status: pre-integration** (ADR-0014): vendored from sovOS™, used by
//! nothing in the tree at this revision. The daemon, the tools and the
//! Lexicon read no context registry yet; the crate integrates when one of
//! them resolves a Pulse's context id through it.
//!
//! A Pulse's 32-bit `scope` field is a 16-bit context id and a 16-bit
//! subscope ([`pack_scope`]). This registry maps each context id to a name
//! and a description, so teams reserve ranges of the scope namespace
//! without a central party. It is a sibling of the Lexicon™ (R-LEX,
//! `mesh-lex`), not a subset: the Lexicon says which envelope types exist,
//! this crate which context ids are reserved and what they mean.
//!
//! In the book: <https://pulse-mesh.net/docs/daemon/architecture/mesh.html>.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Context identifier: the high 16 bits of [`pulse_canon::Pulse::scope`].
pub type ContextId = u16;

/// Free-form subscope inside a context — low 16 bits of
/// [`pulse_canon::Pulse::scope`].
pub type Subscope = u16;

/// First user-extensible context id: the ids below it are the project's
/// ([`ContextRegistry::default_book`]), the rest free for downstream books.
pub const STANDARD_RESERVED_END: ContextId = 256;

/// Pack `(context_id, subscope)` into the 32-bit scope field, the context
/// id in the high 16 bits.
#[inline]
pub fn pack_scope(context_id: ContextId, subscope: Subscope) -> u32 {
    ((context_id as u32) << 16) | (subscope as u32)
}

/// Unpack the 32-bit scope field into `(context_id, subscope)`: the
/// inverse of [`pack_scope`].
#[inline]
pub fn unpack_scope(scope: u32) -> (ContextId, Subscope) {
    let context_id = (scope >> 16) as u16;
    let subscope = (scope & 0xFFFF) as u16;
    (context_id, subscope)
}

/// One entry in the Book of Standards.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContextEntry {
    /// Numeric context ID (high 16 bits of [`pulse_canon::Pulse::scope`]).
    pub id: ContextId,
    /// Short human-readable name. Stable across registry versions: a new
    /// name takes a new id.
    pub name: String,
    /// One-sentence description of what this context covers.
    pub description: String,
}

/// A content-addressed context registry. Two registries are equal when
/// their hashes ([`Self::hash`]) are, which peers compare to detect
/// inconsistent books.
#[derive(Clone, Debug)]
pub struct ContextRegistry {
    entries: BTreeMap<ContextId, ContextEntry>,
    hash: [u8; 32],
}

#[non_exhaustive]
/// Errors raised by [`ContextRegistry`] construction or merging.
#[derive(Debug, thiserror::Error)]
pub enum ContextRegistryError {
    /// Two different entries share a `context_id`.
    #[error(
        "context_id {id} conflict: existing entry {existing_name:?} \
 vs incoming entry {incoming_name:?}"
    )]
    IdConflict {
        /// The conflicting context_id.
        id: ContextId,
        /// Name in the existing entry.
        existing_name: String,
        /// Name in the incoming entry.
        incoming_name: String,
    },
    /// TOML parse failure on [`ContextRegistry::from_toml`].
    #[error("toml parse: {0}")]
    Toml(String),
    /// JSON failure in [`ContextRegistry::from_json`] or
    /// [`ContextRegistry::to_json`].
    #[error("json parse: {0}")]
    Json(#[from] serde_json::Error),
}

#[derive(Serialize, Deserialize)]
struct RegistryFile {
    entries: Vec<ContextEntry>,
}

impl ContextRegistry {
    /// An empty registry.
    pub fn empty() -> Self {
        Self::from_entries(BTreeMap::new())
    }

    /// The project's Book of Standards, `v1`: four entries, all below
    /// [`STANDARD_RESERVED_END`]. Adding an entry changes the hash;
    /// downstream books add theirs with [`Self::with_user_book`].
    pub fn default_book() -> Self {
        let entries: Vec<ContextEntry> = vec![
            entry(0, "reserved", "Reserved — must not be used in deployments"),
            entry(
                1,
                "pms-core",
                "PMS protocol control: heartbeat, NACK, capability",
            ),
            entry(
                2,
                "pms-bench",
                "Benchmark traffic — scenarios and comparators",
            ),
            entry(3, "pulse-wire-udp", "UDP transport framing + ACK channel"),
        ];
        let mut map = BTreeMap::new();
        for e in entries {
            map.insert(e.id, e);
        }
        Self::from_entries(map)
    }

    /// Build a registry from entries; identical duplicates count once. Not
    /// named `from_iter`, which is `FromIterator`'s and cannot fail.
    ///
    /// # Errors
    ///
    /// [`ContextRegistryError::IdConflict`] if two entries share an id but
    /// differ in name or description.
    pub fn from_entries_iter(
        iter: impl IntoIterator<Item = ContextEntry>,
    ) -> Result<Self, ContextRegistryError> {
        let mut map = BTreeMap::new();
        for entry in iter {
            if let Some(existing) = map.get(&entry.id) {
                let existing_name: &String = &(existing as &ContextEntry).name;
                if existing != &entry {
                    return Err(ContextRegistryError::IdConflict {
                        id: entry.id,
                        existing_name: existing_name.clone(),
                        incoming_name: entry.name.clone(),
                    });
                }
            }
            map.insert(entry.id, entry);
        }
        Ok(Self::from_entries(map))
    }

    /// Parse a TOML registry file of the form:
    ///
    /// ```toml
    /// [[entries]]
    /// id = 256
    /// name = "my-app"
    /// description = "..."
    /// ```
    ///
    /// # Errors
    ///
    /// [`ContextRegistryError::Toml`] if `s` is not such a file;
    /// [`ContextRegistryError::IdConflict`] as in [`Self::from_entries_iter`].
    pub fn from_toml(s: &str) -> Result<Self, ContextRegistryError> {
        let file: RegistryFile =
            toml::from_str(s).map_err(|e| ContextRegistryError::Toml(e.to_string()))?;
        Self::from_entries_iter(file.entries)
    }

    /// Parse a JSON registry file of the form
    /// `{"entries": [{"id": 256, "name": "...", "description": "..."}]}`.
    ///
    /// # Errors
    ///
    /// [`ContextRegistryError::Json`] if `s` is not such a file;
    /// [`ContextRegistryError::IdConflict`] as in [`Self::from_entries_iter`].
    pub fn from_json(s: &str) -> Result<Self, ContextRegistryError> {
        let file: RegistryFile = serde_json::from_str(s)?;
        Self::from_entries_iter(file.entries)
    }

    /// Serialize to pretty JSON, entries in id order, which
    /// [`Self::from_json`] reads back.
    ///
    /// # Errors
    ///
    /// [`ContextRegistryError::Json`] if `serde_json` fails, which it does
    /// not for these plain fields.
    pub fn to_json(&self) -> Result<String, ContextRegistryError> {
        let file = RegistryFile {
            entries: self.entries.values().cloned().collect(),
        };
        Ok(serde_json::to_string_pretty(&file)?)
    }

    /// Look up a context entry by ID.
    pub fn lookup(&self, id: ContextId) -> Option<&ContextEntry> {
        self.entries.get(&id)
    }

    /// Iterator over all entries, sorted by ID.
    pub fn iter(&self) -> impl Iterator<Item = &ContextEntry> {
        self.entries.values()
    }

    /// Number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// BLAKE3 hash of the entry set, whatever the order the entries came in.
    pub fn hash(&self) -> [u8; 32] {
        self.hash
    }

    /// The hash's first six bytes in lowercase hex, for log lines.
    pub fn short_hash(&self) -> String {
        hex_lower(&self.hash[..6])
    }

    /// The union of two registries; an entry both hold appears once.
    ///
    /// # Errors
    ///
    /// [`ContextRegistryError::IdConflict`] if they hold different entries
    /// under one id.
    pub fn union(&self, other: &Self) -> Result<Self, ContextRegistryError> {
        let mut map = self.entries.clone();
        for (id, incoming) in &other.entries {
            match map.get(id) {
                None => {
                    map.insert(*id, incoming.clone());
                }
                Some(existing) if existing == incoming => {}
                Some(existing) => {
                    return Err(ContextRegistryError::IdConflict {
                        id: *id,
                        existing_name: existing.name.clone(),
                        incoming_name: incoming.name.clone(),
                    });
                }
            }
        }
        Ok(Self::from_entries(map))
    }

    /// Layer a user book over `self`: [`Self::union`], named for the
    /// default-book-plus-user-book pattern.
    ///
    /// # Errors
    ///
    /// [`ContextRegistryError::IdConflict`] if the user book redefines an id.
    pub fn with_user_book(&self, user: &Self) -> Result<Self, ContextRegistryError> {
        self.union(user)
    }

    /// Build the registry given a pre-validated map.
    fn from_entries(entries: BTreeMap<ContextId, ContextEntry>) -> Self {
        let hash = canonical_hash(&entries);
        Self { entries, hash }
    }
}

impl PartialEq for ContextRegistry {
    fn eq(&self, other: &Self) -> bool {
        self.hash == other.hash
    }
}
impl Eq for ContextRegistry {}

fn entry(id: ContextId, name: &str, description: &str) -> ContextEntry {
    ContextEntry {
        id,
        name: name.to_string(),
        description: description.to_string(),
    }
}

/// The registry's BLAKE3 hash, over the entries in id order.
fn canonical_hash(entries: &BTreeMap<ContextId, ContextEntry>) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    // Domain separator, so this hash collides with no other BLAKE3 use.
    hasher.update(b"pms-context-registry-v1\n");
    for entry in entries.values() {
        hasher.update(&entry.id.to_le_bytes());
        // Length prefixes keep "ab"+"c" apart from "a"+"bc"; the lengths
        // are assumed to fit in a u32.
        hasher.update(&(entry.name.len() as u32).to_le_bytes());
        hasher.update(entry.name.as_bytes());
        hasher.update(&(entry.description.len() as u32).to_le_bytes());
        hasher.update(entry.description.as_bytes());
    }
    *hasher.finalize().as_bytes()
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn pack_unpack_round_trip_at_extremes() {
        let cases = [
            (0u16, 0u16),
            (1, 0),
            (0, 1),
            (0x1234, 0xABCD),
            (u16::MAX, u16::MAX),
            (u16::MAX, 0),
            (0, u16::MAX),
        ];
        for (c, s) in cases {
            let scope = pack_scope(c, s);
            let (c2, s2) = unpack_scope(scope);
            assert_eq!(c, c2, "context_id mismatch for ({c}, {s})");
            assert_eq!(s, s2, "subscope mismatch for ({c}, {s})");
        }
    }

    #[test]
    fn pack_layout_is_high_low() {
        let scope = pack_scope(0xAABB, 0xCCDD);
        assert_eq!(scope, 0xAABB_CCDD);
    }

    #[test]
    fn default_book_contains_pms_core_at_id_1() {
        let book = ContextRegistry::default_book();
        let core = book.lookup(1).expect("pms-core must be present");
        assert_eq!(core.name, "pms-core");
        assert!(core.description.to_lowercase().contains("heartbeat"));
    }

    #[test]
    fn default_book_iter_is_sorted_by_id() {
        let book = ContextRegistry::default_book();
        let ids: Vec<ContextId> = book.iter().map(|e| e.id).collect();
        let mut sorted = ids.clone();
        sorted.sort_unstable();
        assert_eq!(ids, sorted);
    }

    #[test]
    fn hash_is_order_independent() {
        let a =
            ContextRegistry::from_entries_iter(vec![entry(1, "a", "alpha"), entry(2, "b", "beta")])
                .unwrap();
        let b =
            ContextRegistry::from_entries_iter(vec![entry(2, "b", "beta"), entry(1, "a", "alpha")])
                .unwrap();
        assert_eq!(a.hash(), b.hash());
        assert_eq!(a, b);
    }

    #[test]
    fn hash_differs_when_entry_changes() {
        let a = ContextRegistry::from_entries_iter(vec![entry(1, "a", "alpha")]).unwrap();
        let b = ContextRegistry::from_entries_iter(vec![entry(1, "a", "alpha-2")]).unwrap();
        assert_ne!(a.hash(), b.hash());
    }

    #[test]
    fn json_round_trip() {
        let original = ContextRegistry::default_book();
        let json = original.to_json().unwrap();
        let parsed = ContextRegistry::from_json(&json).unwrap();
        assert_eq!(original, parsed);
        assert_eq!(original.hash(), parsed.hash());
    }

    #[test]
    fn from_iter_rejects_id_conflict() {
        let err =
            ContextRegistry::from_entries_iter(vec![entry(1, "a", "alpha"), entry(1, "b", "beta")])
                .unwrap_err();
        match err {
            ContextRegistryError::IdConflict { id, .. } => assert_eq!(id, 1),
            other => panic!("expected IdConflict, got {other:?}"),
        }
    }

    #[test]
    fn from_iter_accepts_duplicate_identical_entry() {
        let r = ContextRegistry::from_entries_iter(vec![
            entry(1, "a", "alpha"),
            entry(1, "a", "alpha"),
        ])
        .unwrap();
        assert_eq!(r.len(), 1);
    }

    #[test]
    fn union_is_commutative_when_compatible() {
        let a = ContextRegistry::from_entries_iter(vec![entry(1, "a", "alpha")]).unwrap();
        let b = ContextRegistry::from_entries_iter(vec![entry(2, "b", "beta")]).unwrap();
        let ab = a.union(&b).unwrap();
        let ba = b.union(&a).unwrap();
        assert_eq!(ab.hash(), ba.hash());
        assert_eq!(ab.len(), 2);
    }

    #[test]
    fn union_rejects_id_conflict() {
        let a = ContextRegistry::from_entries_iter(vec![entry(1, "a", "alpha")]).unwrap();
        let b = ContextRegistry::from_entries_iter(vec![entry(1, "different", "x")]).unwrap();
        assert!(a.union(&b).is_err());
    }

    #[test]
    fn user_book_extends_default() {
        let default = ContextRegistry::default_book();
        let user = ContextRegistry::from_entries_iter(vec![entry(
            STANDARD_RESERVED_END,
            "user-app",
            "Application X scope",
        )])
        .unwrap();
        let merged = default.with_user_book(&user).unwrap();
        assert_eq!(merged.len(), default.len() + 1);
        assert!(merged.lookup(STANDARD_RESERVED_END).is_some());
        assert_ne!(merged.hash(), default.hash());
    }

    #[test]
    fn short_hash_is_12_lowercase_hex_chars() {
        let book = ContextRegistry::default_book();
        let s = book.short_hash();
        assert_eq!(s.len(), 12);
        assert!(s
            .chars()
            .all(|c| c.is_ascii_hexdigit() && (c.is_ascii_digit() || c.is_lowercase())));
    }
}
