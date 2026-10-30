// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! The capability handshake, tier 2, vendored from sovOS™.
//!
//! Two peers exchange a 48-byte [`Hello`]. This crate encodes and decodes it
//! and reports a [`NegotiationOutcome`]; acting on an agreed upgrade belongs
//! to each backend. It is not in the UDP crate so that every backend speaks
//! one handshake without depending on a socket.
//!
//! The daemon's links to other daemons (`mesh-hub`, ADR-0021) use it: the
//! first control message of each link session is a Hello carrying this
//! crate's 48 bytes, sent inside the sealed session (ADR-0018, item 8) so
//! that nothing on the path can strip or forge its bits, and each daemon
//! records the outcome for its peer. A link runs on sealed UDP alone, so
//! nothing acts on an agreed upgrade yet.
//!
//! In the book: <https://pulse-mesh.net/docs/reference/spec/06-udp-transport.html> (section 6.4).
#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};

/// Magic prefixing every Hello datagram: ASCII `"PMSH"` on the wire,
/// distinct from the data frame's `PMSW` and the ACK, NACK and FEC magics.
pub const HELLO_MAGIC: u32 = 0x48534D50;

/// Length on the wire of one Hello datagram in bytes.
pub const HELLO_BYTES: usize = 4 + 2 + 4 + 32 + 6;

/// Highest protocol version this build understands; older versions are
/// translated at the receiver, not renegotiated.
pub const MAX_VERSION: u16 = 3;

/// Bit field of optional capabilities a peer can advertise.
///
/// New bits are added monotonically; existing bits are never repurposed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct CapabilityFlags(pub u32);

impl CapabilityFlags {
    /// Tier-2 backpressure (ACK feedback channel).
    pub const BACKPRESSURE: u32 = 1 << 0;
    /// NACK + retransmit from `SendCache`.
    pub const NACK: u32 = 1 << 1;
    /// Single-parity XOR forward error correction.
    pub const FEC: u32 = 1 << 2;
    /// AF_XDP / kernel-bypass (Linux only).
    pub const AF_XDP: u32 = 1 << 3;
    /// DPDK / SmartNIC offload (enterprise hardware).
    pub const DPDK: u32 = 1 << 4;
    /// TLS-1.3 over TCP/443 tunnelling backend.
    pub const TLS_443: u32 = 1 << 5;
    /// Honours the context registry's hash (the Book of Standards).
    pub const CONTEXT_REGISTRY: u32 = 1 << 6;

    /// All bits known to this build.
    pub const fn all() -> Self {
        Self(
            Self::BACKPRESSURE
                | Self::NACK
                | Self::FEC
                | Self::AF_XDP
                | Self::DPDK
                | Self::TLS_443
                | Self::CONTEXT_REGISTRY,
        )
    }

    /// Construct from a raw bit pattern.
    pub const fn from_bits(bits: u32) -> Self {
        Self(bits)
    }

    /// Raw bit pattern.
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Whether `flag` is set.
    pub const fn contains(self, flag: u32) -> bool {
        (self.0 & flag) == flag
    }

    /// Bitwise AND — used to intersect two peers' advertisements.
    pub const fn intersect(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }

    /// Bitwise OR.
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

/// One Hello datagram, on the wire and decoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Hello {
    /// Protocol version the sender speaks.
    pub version: u16,
    /// Capability bit field (see [`CapabilityFlags`]).
    pub capabilities: CapabilityFlags,
    /// BLAKE3 hash of the sender's `mesh-context::ContextRegistry`.
    pub registry_hash: [u8; 32],
}

#[non_exhaustive]
/// Errors from [`decode_hello`] and [`CapabilityNegotiator::observe_remote`].
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum NegotiationError {
    /// Buffer is shorter than [`HELLO_BYTES`].
    #[error("hello datagram too short: {len}, expected {expected}")]
    TooShort {
        /// Length on the wire.
        len: usize,
        /// Expected length ([`HELLO_BYTES`]).
        expected: usize,
    },
    /// First 4 bytes don't match [`HELLO_MAGIC`].
    #[error("hello magic mismatch: got 0x{got:08x}, expected 0x{expected:08x}")]
    MagicMismatch {
        /// Magic on the wire.
        got: u32,
        /// Expected magic.
        expected: u32,
    },
    /// Remote's protocol version is newer than [`MAX_VERSION`].
    #[error("unsupported peer version {got}, max known {max}")]
    UnsupportedVersion {
        /// Peer's advertised version.
        got: u16,
        /// Local [`MAX_VERSION`].
        max: u16,
    },
}

/// Encode a Hello into `out`, replacing its contents.
pub fn encode_hello(hello: &Hello, out: &mut Vec<u8>) {
    out.clear();
    out.extend_from_slice(&HELLO_MAGIC.to_le_bytes());
    out.extend_from_slice(&hello.version.to_le_bytes());
    out.extend_from_slice(&hello.capabilities.bits().to_le_bytes());
    out.extend_from_slice(&hello.registry_hash);
    // Six reserved bytes, all zero.
    out.extend_from_slice(&[0u8; 6]);
    debug_assert_eq!(out.len(), HELLO_BYTES);
}

/// Decode a Hello datagram. The reserved bytes are not checked, so a later
/// version may carry data there.
///
/// # Errors
///
/// [`NegotiationError::TooShort`] if `bytes` is shorter than
/// [`HELLO_BYTES`]; [`NegotiationError::MagicMismatch`] if it does not
/// start with [`HELLO_MAGIC`].
pub fn decode_hello(bytes: &[u8]) -> Result<Hello, NegotiationError> {
    if bytes.len() < HELLO_BYTES {
        return Err(NegotiationError::TooShort {
            len: bytes.len(),
            expected: HELLO_BYTES,
        });
    }
    // In range after the length check; `try_into` spares an unwrap.
    let magic_bytes: [u8; 4] = bytes[0..4]
        .try_into()
        .map_err(|_| NegotiationError::TooShort {
            len: bytes.len(),
            expected: HELLO_BYTES,
        })?;
    let magic = u32::from_le_bytes(magic_bytes);
    if magic != HELLO_MAGIC {
        return Err(NegotiationError::MagicMismatch {
            got: magic,
            expected: HELLO_MAGIC,
        });
    }
    let version_bytes: [u8; 2] =
        bytes[4..6]
            .try_into()
            .map_err(|_| NegotiationError::TooShort {
                len: bytes.len(),
                expected: HELLO_BYTES,
            })?;
    let version = u16::from_le_bytes(version_bytes);
    let cap_bytes: [u8; 4] = bytes[6..10]
        .try_into()
        .map_err(|_| NegotiationError::TooShort {
            len: bytes.len(),
            expected: HELLO_BYTES,
        })?;
    let cap_bits = u32::from_le_bytes(cap_bytes);
    let registry_hash: [u8; 32] =
        bytes[10..42]
            .try_into()
            .map_err(|_| NegotiationError::TooShort {
                len: bytes.len(),
                expected: HELLO_BYTES,
            })?;
    Ok(Hello {
        version,
        capabilities: CapabilityFlags::from_bits(cap_bits),
        registry_hash,
    })
}

/// Outcome of a capability negotiation between local and remote.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NegotiationOutcome {
    /// The capability bits both sides advertise: what the connection can use.
    pub agreed: CapabilityFlags,
    /// True iff both sides reported the same registry hash.
    pub registry_match: bool,
    /// True iff a capability was agreed: the transport should consider an
    /// upgrade.
    pub upgrade_recommended: bool,
    /// Effective protocol version (`min(local, remote)`).
    pub agreed_version: u16,
}

/// One peer's view of the negotiation: the local Hello, and the remote one
/// once observed.
#[derive(Debug, Clone)]
pub struct CapabilityNegotiator {
    local: Hello,
    remote: Option<Hello>,
}

impl CapabilityNegotiator {
    /// A negotiator for the local Hello, whose `registry_hash` is the local
    /// `mesh_context::ContextRegistry::hash`.
    pub fn new(local: Hello) -> Self {
        Self {
            local,
            remote: None,
        }
    }

    /// Local Hello.
    pub fn local(&self) -> &Hello {
        &self.local
    }

    /// Remote Hello, if observed.
    pub fn remote(&self) -> Option<&Hello> {
        self.remote.as_ref()
    }

    /// Record a peer's Hello and return the [`NegotiationOutcome`].
    ///
    /// # Errors
    ///
    /// [`NegotiationError::UnsupportedVersion`] if the peer's version is
    /// above [`MAX_VERSION`].
    pub fn observe_remote(
        &mut self,
        remote: Hello,
    ) -> Result<NegotiationOutcome, NegotiationError> {
        if remote.version > MAX_VERSION {
            return Err(NegotiationError::UnsupportedVersion {
                got: remote.version,
                max: MAX_VERSION,
            });
        }
        self.remote = Some(remote);
        let agreed = self.local.capabilities.intersect(remote.capabilities);
        let registry_match = self.local.registry_hash == remote.registry_hash;
        let upgrade_recommended = agreed.bits() != 0;
        let agreed_version = self.local.version.min(remote.version);
        Ok(NegotiationOutcome {
            agreed,
            registry_match,
            upgrade_recommended,
            agreed_version,
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn sample(caps: u32, hash_byte: u8) -> Hello {
        Hello {
            version: 3,
            capabilities: CapabilityFlags::from_bits(caps),
            registry_hash: [hash_byte; 32],
        }
    }

    #[test]
    fn hello_round_trip_zero_capabilities() {
        let h = sample(0, 0);
        let mut buf = Vec::new();
        encode_hello(&h, &mut buf);
        assert_eq!(buf.len(), HELLO_BYTES);
        let parsed = decode_hello(&buf).unwrap();
        assert_eq!(parsed, h);
    }

    #[test]
    fn hello_round_trip_full_capabilities() {
        let h = Hello {
            version: 3,
            capabilities: CapabilityFlags::all(),
            registry_hash: [0xAB; 32],
        };
        let mut buf = Vec::new();
        encode_hello(&h, &mut buf);
        let parsed = decode_hello(&buf).unwrap();
        assert_eq!(parsed, h);
    }

    #[test]
    fn decode_rejects_short() {
        match decode_hello(&[0u8; HELLO_BYTES - 1]) {
            Err(NegotiationError::TooShort { .. }) => {}
            other => panic!("expected TooShort, got {other:?}"),
        }
    }

    #[test]
    fn decode_rejects_wrong_magic() {
        let mut buf = vec![0u8; HELLO_BYTES];
        buf[..4].copy_from_slice(&0xDEADBEEFu32.to_le_bytes());
        match decode_hello(&buf) {
            Err(NegotiationError::MagicMismatch { .. }) => {}
            other => panic!("expected MagicMismatch, got {other:?}"),
        }
    }

    #[test]
    fn intersect_and_outcome_agree() {
        let local = sample(
            CapabilityFlags::BACKPRESSURE | CapabilityFlags::NACK | CapabilityFlags::FEC,
            0xAA,
        );
        let remote = sample(
            CapabilityFlags::BACKPRESSURE | CapabilityFlags::NACK | CapabilityFlags::TLS_443,
            0xAA,
        );
        let mut n = CapabilityNegotiator::new(local);
        let outcome = n.observe_remote(remote).unwrap();
        assert_eq!(
            outcome.agreed.bits(),
            CapabilityFlags::BACKPRESSURE | CapabilityFlags::NACK
        );
        assert!(outcome.registry_match);
        assert!(outcome.upgrade_recommended);
        assert_eq!(outcome.agreed_version, 3);
    }

    #[test]
    fn registry_mismatch_does_not_fail_negotiation() {
        let local = sample(CapabilityFlags::BACKPRESSURE, 0x11);
        let remote = sample(CapabilityFlags::BACKPRESSURE, 0x22);
        let mut n = CapabilityNegotiator::new(local);
        let outcome = n.observe_remote(remote).unwrap();
        assert!(!outcome.registry_match);
        assert!(outcome.upgrade_recommended);
    }

    #[test]
    fn unsupported_version_is_rejected() {
        let local = sample(0, 0);
        let mut remote = sample(0, 0);
        remote.version = MAX_VERSION + 1;
        let mut n = CapabilityNegotiator::new(local);
        match n.observe_remote(remote) {
            Err(NegotiationError::UnsupportedVersion { .. }) => {}
            other => panic!("expected UnsupportedVersion, got {other:?}"),
        }
    }

    #[test]
    fn lowest_common_version_chosen() {
        let mut local = sample(0, 0);
        local.version = 3;
        let mut remote = sample(0, 0);
        remote.version = 2;
        let mut n = CapabilityNegotiator::new(local);
        let o = n.observe_remote(remote).unwrap();
        assert_eq!(o.agreed_version, 2);
    }

    #[test]
    fn no_capabilities_agreed_is_no_upgrade() {
        let local = sample(CapabilityFlags::BACKPRESSURE, 0);
        let remote = sample(CapabilityFlags::FEC, 0);
        let mut n = CapabilityNegotiator::new(local);
        let o = n.observe_remote(remote).unwrap();
        assert_eq!(o.agreed.bits(), 0);
        assert!(!o.upgrade_recommended);
    }

    #[test]
    fn idempotent_observe_remote() {
        let local = sample(CapabilityFlags::all().bits(), 0xCC);
        let remote = sample(CapabilityFlags::NACK, 0xCC);
        let mut n = CapabilityNegotiator::new(local);
        let o1 = n.observe_remote(remote).unwrap();
        let o2 = n.observe_remote(remote).unwrap();
        assert_eq!(o1, o2);
    }

    #[test]
    fn capability_flags_constants_are_distinct_bits() {
        let bits = [
            CapabilityFlags::BACKPRESSURE,
            CapabilityFlags::NACK,
            CapabilityFlags::FEC,
            CapabilityFlags::AF_XDP,
            CapabilityFlags::DPDK,
            CapabilityFlags::TLS_443,
            CapabilityFlags::CONTEXT_REGISTRY,
        ];
        for (i, &a) in bits.iter().enumerate() {
            for (j, &b) in bits.iter().enumerate() {
                if i == j {
                    continue;
                }
                assert_ne!(a, b, "bit collision between #{i} and #{j}");
            }
            assert_eq!(a.count_ones(), 1, "#{i} is not a single-bit flag");
        }
    }
}
