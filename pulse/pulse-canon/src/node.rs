// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! `NodeId`, the 16-byte node identifier, and `NodeCapabilities`.

/// 16-byte node identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct NodeId(pub [u8; 16]);

impl NodeId {
    /// Sentinel: all-zero identifier.
    pub const ZERO: Self = Self([0u8; 16]);

    /// Wrap explicit bytes.
    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Derive deterministically from a name as `BLAKE3(name)[..16]`.
    pub fn from_name(name: &str) -> Self {
        let hash = blake3::hash(name.as_bytes());
        let mut id = [0u8; 16];
        id.copy_from_slice(&hash.as_bytes()[..16]);
        Self(id)
    }

    /// True when every byte is zero.
    pub fn is_zero(&self) -> bool {
        self.0 == [0u8; 16]
    }

    /// Lowercase hex rendering (32 chars).
    pub fn to_hex(&self) -> String {
        self.0.iter().map(|b| format!("{:02x}", b)).collect()
    }

    /// Borrow the underlying byte array.
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl std::fmt::Display for NodeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "node:{}", &self.to_hex()[..8])
    }
}

impl From<[u8; 16]> for NodeId {
    fn from(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }
}

impl From<NodeId> for [u8; 16] {
    fn from(id: NodeId) -> Self {
        id.0
    }
}

/// Capability descriptor advertised by a node at registration. The canonical
/// layer does not interpret these fields; routing-layer consumers do.
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct NodeCapabilities {
    /// Envelope types this node can produce.
    pub produces: Vec<u16>,
    /// Envelope types this node can consume.
    pub consumes: Vec<u16>,
    /// Whether this node supports direct wire connections.
    pub direct_wire: bool,
}

impl NodeCapabilities {
    /// Empty descriptor with `direct_wire = true`.
    pub fn new() -> Self {
        Self {
            produces: Vec::new(),
            consumes: Vec::new(),
            direct_wire: true,
        }
    }

    /// Builder: append producible envelope types.
    pub fn produces(mut self, types: &[u16]) -> Self {
        self.produces.extend_from_slice(types);
        self
    }

    /// Builder: append consumable envelope types.
    pub fn consumes(mut self, types: &[u16]) -> Self {
        self.consumes.extend_from_slice(types);
        self
    }

    /// Builder: set the `direct_wire` flag.
    pub fn with_direct_wire(mut self, enabled: bool) -> Self {
        self.direct_wire = enabled;
        self
    }
}
