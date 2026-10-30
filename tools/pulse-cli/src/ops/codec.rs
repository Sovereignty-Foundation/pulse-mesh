// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! Canonical-codec round-trip and content-address helpers.

use pulse_canon::{EnvelopeCodecError, PulseEnvelope};
use serde::Serialize;

/// Outcome of a canonical-codec round trip.
#[derive(Debug, Clone, Serialize)]
pub struct RoundtripResult {
    /// Canonical wire bytes, hex-encoded (lowercase, no `0x` prefix).
    pub canonical_hex: String,
    /// The envelope's id, its content address, hex-encoded.
    pub content_hash: String,
    /// Length of the canonical encoding in bytes.
    pub size: usize,
    /// Whether decoding the canonical bytes gives back an equal envelope.
    pub decoded_equal: bool,
}

/// Errors from [`roundtrip`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RoundtripError {
    /// The supplied envelope could not be re-decoded from its own canonical form.
    #[error("decode after encode failed: {0}")]
    DecodeFailed(#[from] EnvelopeCodecError),
}

/// Encode an envelope canonically, then decode it and compare.
///
/// # Errors
/// [`RoundtripError::DecodeFailed`] when the canonical bytes do not decode,
/// which means the codec has drifted.
pub fn roundtrip(envelope: &PulseEnvelope) -> Result<RoundtripResult, RoundtripError> {
    let bytes = envelope.to_canonical_bytes();
    let decoded = PulseEnvelope::from_canonical_bytes(&bytes)?;
    let decoded_equal = decoded == *envelope;

    Ok(RoundtripResult {
        canonical_hex: hex::encode(&bytes),
        content_hash: envelope.id().to_hex(),
        size: bytes.len(),
        decoded_equal,
    })
}

/// Decode a hex string, surrounding whitespace ignored, into an envelope.
///
/// # Errors
/// Returns [`DecodeError::Hex`] if the input is not valid hex, or
/// [`DecodeError::Codec`] if the decoded bytes are not a valid canonical
/// envelope.
pub fn decode_hex(hex_str: &str) -> Result<PulseEnvelope, DecodeError> {
    let bytes = hex::decode(hex_str.trim())?;
    let envelope = PulseEnvelope::from_canonical_bytes(&bytes)?;
    Ok(envelope)
}

/// Errors from [`decode_hex`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DecodeError {
    /// Input was not valid hex.
    #[error("invalid hex input: {0}")]
    Hex(#[from] hex::FromHexError),
    /// Decoded bytes did not parse as a canonical envelope.
    #[error("canonical decode failed: {0}")]
    Codec(#[from] EnvelopeCodecError),
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use pulse_canon::PayloadData;

    #[test]
    fn roundtrip_raw_envelope_is_byte_equal() {
        let env = PulseEnvelope::new(0x0001, PayloadData::Raw(b"hello".to_vec()));
        let r = roundtrip(&env).expect("roundtrip ok");
        assert!(r.decoded_equal, "raw envelope must roundtrip byte-equal");
        assert_eq!(r.size, env.canonical_size());
        assert_eq!(r.content_hash, env.id().to_hex());
    }

    #[test]
    fn roundtrip_nested_envelope_is_byte_equal() {
        let inner = PulseEnvelope::new(0x0001, PayloadData::Raw(b"inner".to_vec()));
        let outer = PulseEnvelope::new(0x0002, PayloadData::Nested(vec![inner]));
        let r = roundtrip(&outer).expect("roundtrip ok");
        assert!(r.decoded_equal, "nested envelope must roundtrip byte-equal");
    }

    #[test]
    fn decode_hex_recovers_envelope() {
        let env = PulseEnvelope::new(0x0042, PayloadData::Raw(b"abc".to_vec()));
        let hex_str = hex::encode(env.to_canonical_bytes());
        let recovered = decode_hex(&hex_str).expect("decode ok");
        assert_eq!(recovered, env);
    }
}
