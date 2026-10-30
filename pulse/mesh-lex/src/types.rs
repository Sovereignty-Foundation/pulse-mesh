// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! [`LineValue`], the value a line holds, and [`LineSet`], the name-keyed
//! container the schema layer composes over.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// A line's value. The set is narrow on purpose: consumers of the public
/// conformance contract must understand every variant, so a new one takes
/// a lex-format version bump, and anything richer belongs in the
/// proprietary sidecar.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LineValue {
    /// Opaque byte payload.
    Bytes(Vec<u8>),
    /// UTF-8 text.
    Text(String),
    /// Unsigned 64-bit integer.
    U64(u64),
    /// Signed 64-bit integer.
    I64(i64),
    /// Boolean flag.
    Bool(bool),
}

impl LineValue {
    /// Single-byte wire discriminant.
    #[must_use]
    pub fn discriminant(&self) -> u8 {
        match self {
            Self::Bytes(_) => 0x01,
            Self::Text(_) => 0x02,
            Self::U64(_) => 0x03,
            Self::I64(_) => 0x04,
            Self::Bool(_) => 0x05,
        }
    }

    /// Deterministic byte encoding. Layout: `discriminant:u8 |
    /// variant-tail`. Variant tails:
    ///
    /// - `Bytes(b)`: `len:u32_le | b`
    /// - `Text(s)`: `len:u32_le | utf8(s)`
    /// - `U64(n)`: `n:u64_le`
    /// - `I64(n)`: `n:i64_le`
    /// - `Bool(b)`: `0x00 | 0x01`
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(self.discriminant());
        match self {
            Self::Bytes(b) => {
                out.extend_from_slice(&(b.len() as u32).to_le_bytes());
                out.extend_from_slice(b);
            }
            Self::Text(s) => {
                let b = s.as_bytes();
                out.extend_from_slice(&(b.len() as u32).to_le_bytes());
                out.extend_from_slice(b);
            }
            Self::U64(n) => out.extend_from_slice(&n.to_le_bytes()),
            Self::I64(n) => out.extend_from_slice(&n.to_le_bytes()),
            Self::Bool(b) => out.push(if *b { 0x01 } else { 0x00 }),
        }
        out
    }
}

/// [`LineValue`]s by name, iterated and encoded in sorted name order.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LineSet {
    lines: BTreeMap<String, LineValue>,
}

impl LineSet {
    /// Empty `LineSet`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of lines registered.
    #[must_use]
    pub fn len(&self) -> usize {
        self.lines.len()
    }

    /// True when no lines are registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.lines.is_empty()
    }

    /// Insert a line; returns the previous value if `name` was already
    /// present.
    pub fn insert(&mut self, name: impl Into<String>, value: LineValue) -> Option<LineValue> {
        self.lines.insert(name.into(), value)
    }

    /// Borrow the value for `name`.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&LineValue> {
        self.lines.get(name)
    }

    /// Iterate `(name, value)` pairs in sorted name order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &LineValue)> {
        self.lines.iter().map(|(k, v)| (k.as_str(), v))
    }

    /// Deterministic byte encoding. Layout:
    ///
    /// ```text
    /// | count:u32_le | { name_len:u32_le | name | value.canonical_bytes }* |
    /// ```
    ///
    /// Entries go in sorted name order, so the bytes depend on the pairs
    /// alone.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&(self.lines.len() as u32).to_le_bytes());
        for (name, value) in &self.lines {
            let nb = name.as_bytes();
            out.extend_from_slice(&(nb.len() as u32).to_le_bytes());
            out.extend_from_slice(nb);
            out.extend_from_slice(&value.canonical_bytes());
        }
        out
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn line_value_discriminants_are_distinct() {
        let vs = [
            LineValue::Bytes(vec![]),
            LineValue::Text(String::new()),
            LineValue::U64(0),
            LineValue::I64(0),
            LineValue::Bool(false),
        ];
        let mut seen = std::collections::HashSet::new();
        for v in &vs {
            assert!(seen.insert(v.discriminant()));
        }
    }

    #[test]
    fn line_value_canonical_bytes_layout_is_stable() {
        assert_eq!(
            LineValue::Bytes(b"abc".to_vec()).canonical_bytes(),
            vec![0x01, 0x03, 0x00, 0x00, 0x00, b'a', b'b', b'c']
        );
        assert_eq!(
            LineValue::Text("hi".into()).canonical_bytes(),
            vec![0x02, 0x02, 0x00, 0x00, 0x00, b'h', b'i']
        );
        assert_eq!(
            LineValue::U64(1).canonical_bytes(),
            vec![0x03, 0x01, 0, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(
            LineValue::I64(-1).canonical_bytes(),
            vec![0x04, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]
        );
        assert_eq!(LineValue::Bool(true).canonical_bytes(), vec![0x05, 0x01]);
        assert_eq!(LineValue::Bool(false).canonical_bytes(), vec![0x05, 0x00]);
    }

    #[test]
    fn line_set_empty_canonical_bytes() {
        // count:u32 = 0; nothing else.
        assert_eq!(LineSet::new().canonical_bytes(), vec![0, 0, 0, 0]);
    }

    #[test]
    fn line_set_iter_in_sorted_name_order() {
        let mut set = LineSet::new();
        set.insert("zeta", LineValue::U64(0));
        set.insert("alpha", LineValue::U64(0));
        set.insert("beta", LineValue::U64(0));
        let names: Vec<&str> = set.iter().map(|(n, _)| n).collect();
        assert_eq!(names, vec!["alpha", "beta", "zeta"]);
    }

    #[test]
    fn line_set_canonical_bytes_independent_of_insertion_order() {
        let mut a = LineSet::new();
        a.insert("alpha", LineValue::U64(1));
        a.insert("beta", LineValue::U64(2));

        let mut b = LineSet::new();
        b.insert("beta", LineValue::U64(2));
        b.insert("alpha", LineValue::U64(1));

        assert_eq!(a.canonical_bytes(), b.canonical_bytes());
    }

    #[test]
    fn line_set_canonical_bytes_changes_with_any_field() {
        let mut a = LineSet::new();
        a.insert("alpha", LineValue::U64(1));

        let mut b = a.clone();
        b.insert("alpha", LineValue::U64(2)); // overwrite value
        assert_ne!(a.canonical_bytes(), b.canonical_bytes());

        let mut c = a.clone();
        c.insert("alphax", LineValue::U64(1)); // different name
        assert_ne!(a.canonical_bytes(), c.canonical_bytes());
    }

    #[test]
    fn line_set_serde_roundtrip_preserves_canonical_bytes() {
        let mut original = LineSet::new();
        original.insert("a", LineValue::Bytes(b"x".to_vec()));
        original.insert("b", LineValue::Text("y".into()));
        original.insert("c", LineValue::Bool(true));

        let json = serde_json::to_string(&original).unwrap();
        let recovered: LineSet = serde_json::from_str(&json).unwrap();
        assert_eq!(original.canonical_bytes(), recovered.canonical_bytes());
    }

    #[test]
    fn line_set_get_and_insert_overwrite() {
        let mut set = LineSet::new();
        assert!(set.get("k").is_none());
        let prev = set.insert("k", LineValue::U64(1));
        assert!(prev.is_none());
        let prev = set.insert("k", LineValue::U64(2));
        assert_eq!(prev, Some(LineValue::U64(1)));
        assert_eq!(set.get("k"), Some(&LineValue::U64(2)));
    }
}
