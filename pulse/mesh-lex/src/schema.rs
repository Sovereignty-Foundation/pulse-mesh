// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! The schema layer: a [`LineSchema`] describes one line's value, a
//! [`BundleSchema`] composes lines into a structured payload, carried as
//! JSON in a [`LexEntry`]'s `schema_bytes`, and [`LexSchemaRegistry`] reads
//! the bundles out of a registry.

use serde::{Deserialize, Serialize};

use crate::entry::{Boundary, DescriptorKind, LexEntry};
use crate::registry::LexRegistry;

/// The kind a [`LineSchema`] declares: [`crate::types::LineValue`]'s
/// variants, with optional bounds on the length-carrying ones.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind")]
pub enum LineKind {
    /// Opaque bytes with an optional upper bound on length.
    Bytes {
        /// Maximum permitted length; `None` for unbounded.
        max_len: Option<u32>,
    },
    /// UTF-8 text with an optional upper bound on length.
    Text {
        /// Maximum permitted length; `None` for unbounded.
        max_len: Option<u32>,
    },
    /// Unsigned 64-bit integer.
    U64,
    /// Signed 64-bit integer.
    I64,
    /// Boolean flag.
    Bool,
}

impl LineKind {
    /// Single-byte wire discriminant matching `LineValue::discriminant`.
    #[must_use]
    pub fn discriminant(&self) -> u8 {
        match self {
            Self::Bytes { .. } => 0x01,
            Self::Text { .. } => 0x02,
            Self::U64 => 0x03,
            Self::I64 => 0x04,
            Self::Bool => 0x05,
        }
    }
}

/// Schema for a single named line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LineSchema {
    /// Field name within the bundle (must be unique within a bundle).
    pub name: String,
    /// What kind of value this line carries.
    pub kind: LineKind,
    /// Whether the bundle is invalid if this line is absent.
    pub required: bool,
}

/// Schema for a bundle of named lines, which a
/// [`DescriptorKind::BundleSchema`] entry carries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleSchema {
    /// Bundle name (matches the `LexEntry::name` it travels with).
    pub name: String,
    /// Schema version; consumers compare-on-equal.
    pub version: u32,
    /// Lines composing the bundle, in an order that is part of the schema:
    /// consumers MAY rely on it for layout.
    pub lines: Vec<LineSchema>,
}

impl BundleSchema {
    /// Encode as JSON bytes for storage in a `LexEntry::schema_bytes`.
    ///
    /// # Errors
    /// Propagates the underlying `serde_json::Error`.
    pub fn to_schema_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }

    /// Decode from a `LexEntry::schema_bytes` payload.
    ///
    /// # Errors
    /// Propagates the underlying `serde_json::Error`.
    pub fn from_schema_bytes(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(bytes)
    }

    /// Build a `LexEntry` of kind [`DescriptorKind::BundleSchema`]
    /// carrying this schema.
    ///
    /// # Errors
    /// Propagates `to_schema_bytes`.
    pub fn into_lex_entry(
        self,
        type_id: u16,
        boundary: Boundary,
    ) -> Result<LexEntry, serde_json::Error> {
        let name = self.name.clone();
        let version = self.version;
        let bytes = self.to_schema_bytes()?;
        Ok(LexEntry::new(
            type_id,
            name,
            version,
            DescriptorKind::BundleSchema,
            boundary,
            bytes,
        ))
    }
}

/// A read-only view of a [`LexRegistry`]'s bundle schemas.
#[derive(Debug)]
pub struct LexSchemaRegistry<'a> {
    inner: &'a LexRegistry,
}

impl<'a> LexSchemaRegistry<'a> {
    /// Build a schema view over an existing registry.
    #[must_use]
    pub fn from_registry(inner: &'a LexRegistry) -> Self {
        Self { inner }
    }

    /// Iterate the bundle schemas in key order, skipping any whose
    /// `schema_bytes` do not decode ([`Self::lookup_bundle`] reports
    /// those).
    pub fn iter_bundles(&self) -> impl Iterator<Item = (u16, BundleSchema)> + '_ {
        self.inner
            .iter()
            .filter(|e| e.kind == DescriptorKind::BundleSchema)
            .filter_map(|e| {
                BundleSchema::from_schema_bytes(&e.schema_bytes)
                    .ok()
                    .map(|s| (e.type_id, s))
            })
    }

    /// The bundle schema for `type_id`, or `None`.
    ///
    /// # Errors
    /// The `serde_json::Error` if the entry's `schema_bytes` do not decode.
    pub fn lookup_bundle(&self, type_id: u16) -> Result<Option<BundleSchema>, serde_json::Error> {
        match self.inner.lookup(type_id, DescriptorKind::BundleSchema) {
            None => Ok(None),
            Some(entry) => BundleSchema::from_schema_bytes(&entry.schema_bytes).map(Some),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn sample_bundle() -> BundleSchema {
        BundleSchema {
            name: "canon/vector".into(),
            version: 1,
            lines: vec![
                LineSchema {
                    name: "id".into(),
                    kind: LineKind::Bytes { max_len: Some(16) },
                    required: true,
                },
                LineSchema {
                    name: "count".into(),
                    kind: LineKind::U64,
                    required: true,
                },
                LineSchema {
                    name: "label".into(),
                    kind: LineKind::Text { max_len: Some(64) },
                    required: false,
                },
            ],
        }
    }

    #[test]
    fn line_kind_discriminants_match_line_value() {
        // The same as LineValue's, so consumers route on one byte.
        assert_eq!(LineKind::Bytes { max_len: None }.discriminant(), 0x01);
        assert_eq!(LineKind::Text { max_len: None }.discriminant(), 0x02);
        assert_eq!(LineKind::U64.discriminant(), 0x03);
        assert_eq!(LineKind::I64.discriminant(), 0x04);
        assert_eq!(LineKind::Bool.discriminant(), 0x05);
    }

    #[test]
    fn bundle_schema_serde_roundtrip() {
        let original = sample_bundle();
        let bytes = original.to_schema_bytes().unwrap();
        let recovered = BundleSchema::from_schema_bytes(&bytes).unwrap();
        assert_eq!(original, recovered);
    }

    #[test]
    fn bundle_schema_into_lex_entry_roundtrip() {
        let bundle = sample_bundle();
        let entry = bundle
            .clone()
            .into_lex_entry(0x0010, Boundary::Public)
            .unwrap();
        assert_eq!(entry.type_id, 0x0010);
        assert_eq!(entry.name, "canon/vector");
        assert_eq!(entry.version, 1);
        assert_eq!(entry.kind, DescriptorKind::BundleSchema);
        assert_eq!(entry.boundary, Boundary::Public);

        let recovered = BundleSchema::from_schema_bytes(&entry.schema_bytes).unwrap();
        assert_eq!(bundle, recovered);
    }

    #[test]
    fn schema_registry_iter_bundles_filters_non_bundle() {
        let mut reg = LexRegistry::new();
        reg.insert(
            sample_bundle()
                .into_lex_entry(0x0010, Boundary::Public)
                .unwrap(),
        )
        .unwrap();
        reg.insert(LexEntry::new(
            0x0010,
            "producer",
            1,
            DescriptorKind::Producer,
            Boundary::Public,
            Vec::<u8>::new(),
        ))
        .unwrap();

        let view = LexSchemaRegistry::from_registry(&reg);
        let bundles: Vec<(u16, String)> = view.iter_bundles().map(|(id, b)| (id, b.name)).collect();
        assert_eq!(bundles, vec![(0x0010, "canon/vector".to_string())]);
    }

    #[test]
    fn schema_registry_lookup_bundle_found_and_missing() {
        let mut reg = LexRegistry::new();
        reg.insert(
            sample_bundle()
                .into_lex_entry(0x0010, Boundary::Public)
                .unwrap(),
        )
        .unwrap();
        let view = LexSchemaRegistry::from_registry(&reg);

        let found = view.lookup_bundle(0x0010).unwrap();
        assert_eq!(found.unwrap().name, "canon/vector");

        let missing = view.lookup_bundle(0xffff).unwrap();
        assert!(missing.is_none());
    }
}
