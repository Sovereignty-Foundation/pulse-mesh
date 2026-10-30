// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! `pms-crc32c`: the integrity trailer for Pulse slots, tier 1.
//!
//! A CRC32C over bytes 8 to 124 of a Pulse, stored little-endian in bytes
//! 124 to 128 of its slot at publish time and verified on read. The ring's
//! `publish_with_crc` and `read_slot_verify_crc` call these functions, so
//! the trailer's byte ranges are defined once, here.
//!
//! In the book: <https://pulse-mesh.net/docs/reference/spec/04-ring.html> (section 4.4).
#![forbid(unsafe_code)]
#![warn(missing_docs)]

/// The CRC32C of a Pulse's bytes 8..124: the trailer for bytes 124..128.
#[inline]
pub fn compute_pulse_crc(pulse_bytes: &[u8; 128]) -> u32 {
    crc32c::crc32c(&pulse_bytes[8..124])
}

/// Check a Pulse's CRC32C trailer.
///
/// # Errors
///
/// [`CrcMismatch`] when the little-endian trailer at bytes 124..128 is not
/// the CRC32C of bytes 8..124.
pub fn verify_pulse_crc(pulse_bytes: &[u8; 128]) -> Result<(), CrcMismatch> {
    let computed = compute_pulse_crc(pulse_bytes);
    let expected = u32::from_le_bytes([
        pulse_bytes[124],
        pulse_bytes[125],
        pulse_bytes[126],
        pulse_bytes[127],
    ]);
    if computed == expected {
        Ok(())
    } else {
        Err(CrcMismatch { expected, computed })
    }
}

/// A trailer that does not match its data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CrcMismatch {
    /// The CRC32C that was stored in bytes 124..128 of the Pulse.
    pub expected: u32,
    /// The CRC32C computed over bytes 8..124 of the Pulse.
    pub computed: u32,
}

impl std::fmt::Display for CrcMismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "CRC mismatch: expected 0x{:08x}, computed 0x{:08x}",
            self.expected, self.computed
        )
    }
}

impl std::error::Error for CrcMismatch {}

#[cfg(test)]
// `needless_range_loop`: the loops fill bytes by their offset in the pulse.
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::needless_range_loop
)]
mod tests {
    use super::*;

    #[test]
    fn crc_round_trip() {
        let mut pulse = [0u8; 128];
        for i in 8..124 {
            pulse[i] = (i as u8).wrapping_mul(7);
        }
        let crc = compute_pulse_crc(&pulse);
        pulse[124..128].copy_from_slice(&crc.to_le_bytes());
        assert!(verify_pulse_crc(&pulse).is_ok());
    }

    #[test]
    fn crc_detects_corruption() {
        let mut pulse = [0u8; 128];
        for i in 8..124 {
            pulse[i] = (i as u8).wrapping_mul(7);
        }
        let crc = compute_pulse_crc(&pulse);
        pulse[124..128].copy_from_slice(&crc.to_le_bytes());
        pulse[50] ^= 0x01; // flip a bit
        assert!(verify_pulse_crc(&pulse).is_err());
    }
}
