// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! [`LexEntry`], one registered descriptor: an envelope type's id, its
//! schema and its [`Boundary`]. Its [`LexEntry::canonical_bytes`] feed
//! [`crate::merkle`].

use serde::{Deserialize, Serialize};

/// What kind of descriptor an entry holds.
///
/// The derived `Ord` (declaration order) is part of the registry's key
/// order, and so of the Merkle leaf order: reordering the variants can
/// change the root.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum DescriptorKind {
    /// Envelope-type schema: payload shape + validation rules.
    EnvelopeType = 0x01,
    /// Producer relationship: a node permitted to emit this type.
    Producer = 0x02,
    /// Consumer relationship: a node permitted to subscribe to this type.
    Consumer = 0x03,
    /// Bundle schema: a multi-line structured-payload composition.
    BundleSchema = 0x04,
}

impl DescriptorKind {
    /// Single-byte wire encoding.
    #[must_use]
    pub fn as_byte(self) -> u8 {
        self as u8
    }

    /// Decode from a wire byte; `None` for unknown discriminants.
    #[must_use]
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(Self::EnvelopeType),
            0x02 => Some(Self::Producer),
            0x03 => Some(Self::Consumer),
            0x04 => Some(Self::BundleSchema),
            _ => None,
        }
    }
}

/// An entry's visibility, which decides whether it is in the public
/// conformance root.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum Boundary {
    /// In [`lex_root`](crate::merkle::lex_root), which external
    /// implementations must reproduce.
    Public = 0x01,
    /// Visible within one mesh deployment; not in the root.
    MeshScoped = 0x02,
    /// Visible only to the node that registered it; not in the root.
    NodeScoped = 0x03,
}

impl Boundary {
    /// Single-byte wire encoding.
    #[must_use]
    pub fn as_byte(self) -> u8 {
        self as u8
    }

    /// Decode from a wire byte; `None` for unknown discriminants.
    #[must_use]
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(Self::Public),
            0x02 => Some(Self::MeshScoped),
            0x03 => Some(Self::NodeScoped),
            _ => None,
        }
    }

    /// True for entries that participate in the public conformance root.
    #[must_use]
    pub fn is_public(self) -> bool {
        matches!(self, Self::Public)
    }
}

/// A single registered descriptor. Its schema is opaque bytes, hashed as
/// they are; [`crate::schema`] decodes them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LexEntry {
    /// Numeric envelope type ID (matches `PulseEnvelope::envelope_type`).
    pub type_id: u16,
    /// Human-readable name. SHOULD be globally unique
    /// ([`crate::registry::LexRegistry::validate`] checks).
    pub name: String,
    /// Schema version, bumped on a breaking change; consumers compare it
    /// for equality.
    pub version: u32,
    /// What kind of descriptor this is.
    pub kind: DescriptorKind,
    /// Visibility scope.
    pub boundary: Boundary,
    /// Serialized schema body, opaque here; empty for the `Producer` and
    /// `Consumer` relationships.
    pub schema_bytes: Vec<u8>,
}

impl LexEntry {
    /// Build a new entry with all fields explicit.
    #[must_use]
    pub fn new(
        type_id: u16,
        name: impl Into<String>,
        version: u32,
        kind: DescriptorKind,
        boundary: Boundary,
        schema_bytes: impl Into<Vec<u8>>,
    ) -> Self {
        Self {
            type_id,
            name: name.into(),
            version,
            kind,
            boundary,
            schema_bytes: schema_bytes.into(),
        }
    }

    /// The entry's cross-language content-address bytes, little-endian, no
    /// padding:
    ///
    /// ```text
    /// | type_id:u16 | name_len:u32 | name_bytes:n |
    /// | version:u32 | kind:u8 | boundary:u8 |
    /// | schema_len:u32 | schema_bytes:m |
    /// ```
    ///
    /// [`lex_root`](crate::merkle::lex_root) depends on this layout: change
    /// it only with a lex-format version bump.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let name_bytes = self.name.as_bytes();
        let cap = 2 + 4 + name_bytes.len() + 4 + 1 + 1 + 4 + self.schema_bytes.len();
        let mut out = Vec::with_capacity(cap);
        out.extend_from_slice(&self.type_id.to_le_bytes());
        out.extend_from_slice(&(name_bytes.len() as u32).to_le_bytes());
        out.extend_from_slice(name_bytes);
        out.extend_from_slice(&self.version.to_le_bytes());
        out.push(self.kind.as_byte());
        out.push(self.boundary.as_byte());
        out.extend_from_slice(&(self.schema_bytes.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.schema_bytes);
        out
    }

    /// BLAKE3 hash of [`Self::canonical_bytes`]: the entry's content
    /// address, and its Merkle leaf.
    #[must_use]
    pub fn content_hash(&self) -> [u8; 32] {
        *blake3::hash(&self.canonical_bytes()).as_bytes()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn sample_entry() -> LexEntry {
        LexEntry::new(
            0x0010,
            "canon/vector",
            1,
            DescriptorKind::EnvelopeType,
            Boundary::Public,
            b"{\"len\":[0,1024]}".to_vec(),
        )
    }

    #[test]
    fn descriptor_kind_byte_roundtrip() {
        for k in [
            DescriptorKind::EnvelopeType,
            DescriptorKind::Producer,
            DescriptorKind::Consumer,
            DescriptorKind::BundleSchema,
        ] {
            assert_eq!(DescriptorKind::from_byte(k.as_byte()), Some(k));
        }
        assert_eq!(DescriptorKind::from_byte(0x00), None);
        assert_eq!(DescriptorKind::from_byte(0xff), None);
    }

    #[test]
    fn boundary_byte_roundtrip() {
        for b in [Boundary::Public, Boundary::MeshScoped, Boundary::NodeScoped] {
            assert_eq!(Boundary::from_byte(b.as_byte()), Some(b));
        }
        assert_eq!(Boundary::from_byte(0x00), None);
    }

    #[test]
    fn boundary_is_public_only_for_public() {
        assert!(Boundary::Public.is_public());
        assert!(!Boundary::MeshScoped.is_public());
        assert!(!Boundary::NodeScoped.is_public());
    }

    #[test]
    fn canonical_bytes_layout_is_stable() {
        // A layout change fails this; it needs a lex-format version bump.
        let entry = LexEntry::new(
            0x0010,
            "canon/vector",
            1,
            DescriptorKind::EnvelopeType,
            Boundary::Public,
            b"abc".to_vec(),
        );
        let bytes = entry.canonical_bytes();

        // Expected layout: 2 + 4 + 12 + 4 + 1 + 1 + 4 + 3 = 31 bytes.
        assert_eq!(bytes.len(), 31);
        assert_eq!(&bytes[0..2], &[0x10, 0x00][..]); // type_id = 0x0010 LE
        assert_eq!(&bytes[2..6], &[0x0c, 0x00, 0x00, 0x00][..]); // name_len = 12 LE
        assert_eq!(&bytes[6..18], b"canon/vector"); // name
        assert_eq!(&bytes[18..22], &[0x01, 0x00, 0x00, 0x00][..]); // version = 1
        assert_eq!(bytes[22], DescriptorKind::EnvelopeType.as_byte());
        assert_eq!(bytes[23], Boundary::Public.as_byte());
        assert_eq!(&bytes[24..28], &[0x03, 0x00, 0x00, 0x00][..]); // schema_len = 3
        assert_eq!(&bytes[28..31], b"abc");
    }

    #[test]
    fn content_hash_is_deterministic() {
        let a = sample_entry();
        let b = sample_entry();
        assert_eq!(a.content_hash(), b.content_hash());
    }

    #[test]
    fn content_hash_differs_by_type_id() {
        let mut a = sample_entry();
        a.type_id = 0x0010;
        let mut b = sample_entry();
        b.type_id = 0x0011;
        assert_ne!(a.content_hash(), b.content_hash());
    }

    #[test]
    fn content_hash_differs_by_name() {
        let mut a = sample_entry();
        a.name = "alpha".to_string();
        let mut b = sample_entry();
        b.name = "beta".to_string();
        assert_ne!(a.content_hash(), b.content_hash());
    }

    #[test]
    fn content_hash_differs_by_schema_bytes() {
        let mut a = sample_entry();
        a.schema_bytes = b"foo".to_vec();
        let mut b = sample_entry();
        b.schema_bytes = b"bar".to_vec();
        assert_ne!(a.content_hash(), b.content_hash());
    }

    #[test]
    fn content_hash_differs_by_boundary() {
        let mut a = sample_entry();
        a.boundary = Boundary::Public;
        let mut b = sample_entry();
        b.boundary = Boundary::MeshScoped;
        assert_ne!(a.content_hash(), b.content_hash());
    }

    #[test]
    fn serde_roundtrip_preserves_content_hash() {
        let original = sample_entry();
        let json = serde_json::to_string(&original).unwrap();
        let recovered: LexEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(original.content_hash(), recovered.content_hash());
    }
}
