// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! `pulse encode` and `pulse decode` — canonical-codec round-trip from the CLI.

use std::path::Path;
use std::process::ExitCode;

use anyhow::Context;
use pulse_canon::{PayloadData, PulseEnvelope};
use serde::Deserialize;

/// JSON shape accepted by `pulse encode --json <file>`.
#[derive(Debug, Deserialize)]
struct EnvelopeSpec {
    envelope_type: u16,
    #[serde(default)]
    type_name: Option<String>,
    /// Hex-encoded raw payload bytes (mutually exclusive with `payload_utf8`).
    #[serde(default)]
    payload_hex: Option<String>,
    /// UTF-8 payload bytes (mutually exclusive with `payload_hex`).
    #[serde(default)]
    payload_utf8: Option<String>,
}

impl EnvelopeSpec {
    fn to_envelope(&self) -> anyhow::Result<PulseEnvelope> {
        let payload_bytes = match (&self.payload_hex, &self.payload_utf8) {
            (Some(_), Some(_)) => {
                anyhow::bail!("envelope spec: provide payload_hex OR payload_utf8, not both")
            }
            (Some(h), None) => {
                hex::decode(h.trim()).with_context(|| "payload_hex is not valid hex")?
            }
            (None, Some(s)) => s.as_bytes().to_vec(),
            (None, None) => Vec::new(),
        };
        // The spec's whole content: a type name does not replace the type.
        Ok(PulseEnvelope::with_content(
            self.envelope_type,
            self.type_name.clone(),
            PayloadData::Raw(payload_bytes),
        ))
    }
}

/// Implementation of `pulse encode --json <file>`.
///
/// # Errors
/// Returns an error if the file cannot be read, the JSON cannot be parsed,
/// the spec is contradictory (e.g. both payload_hex and payload_utf8), or
/// the canonical round-trip fails.
pub fn run_encode(path: &Path, json: bool) -> anyhow::Result<ExitCode> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("cannot read envelope spec at {}", path.display()))?;
    let spec: EnvelopeSpec = serde_json::from_str(&raw)
        .with_context(|| format!("cannot parse envelope spec JSON in {}", path.display()))?;
    let env = spec.to_envelope()?;
    let result =
        crate::ops::codec::roundtrip(&env).with_context(|| "canonical codec round-trip failed")?;
    if json {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        println!("canonical_size  {} bytes", result.size);
        println!("content_hash    {}", result.content_hash);
        println!("decoded_equal   {}", result.decoded_equal);
        println!("canonical_hex   {}", result.canonical_hex);
    }
    Ok(ExitCode::SUCCESS)
}

/// Implementation of `pulse decode <hex>`. The exit code is failure when the
/// envelope does not verify: its content does not produce the identifier it
/// carries, so it is not the envelope it claims to be.
///
/// # Errors
/// Returns an error if the input is not valid hex or does not parse as a
/// canonical envelope.
pub fn run_decode(hex_input: &str, json: bool) -> anyhow::Result<ExitCode> {
    let env =
        crate::ops::codec::decode_hex(hex_input).with_context(|| "canonical decode failed")?;
    let verified = env.verify();
    if json {
        let payload_summary = match env.payload() {
            PayloadData::Raw(bytes) => serde_json::json!({
                "variant": "Raw",
                "size": bytes.len(),
                "hex": hex::encode(bytes),
            }),
            PayloadData::Nested(children) => serde_json::json!({
                "variant": "Nested",
                "child_count": children.len(),
            }),
        };
        let out = serde_json::json!({
            "envelope_type": env.envelope_type(),
            "type_name": env.type_name(),
            "content_hash": env.id().to_hex(),
            "verified": verified,
            "monotonic_nanos": env.monotonic_nanos,
            "flags": env.flags.bits(),
            "payload": payload_summary,
        });
        println!("{}", serde_json::to_string_pretty(&out)?);
    } else {
        println!("envelope_type    0x{:04x}", env.envelope_type());
        if let Some(name) = env.type_name() {
            println!("type_name        {name}");
        }
        println!("content_hash     {}", env.id().to_hex());
        println!("verified         {verified}");
        println!("monotonic_nanos  {}", env.monotonic_nanos);
        println!("flags            0x{:04x}", env.flags.bits());
        match env.payload() {
            PayloadData::Raw(bytes) => println!("payload          Raw, {} byte(s)", bytes.len()),
            PayloadData::Nested(children) => {
                println!("payload          Nested, {} children", children.len())
            }
        }
    }
    // Say so in the exit status too, so a script can refuse an envelope that
    // does not verify without reading the output.
    Ok(if verified {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    /// A spec with a type name keeps its numeric type, and the id covers
    /// both, as the wasm binding's encoder computes it.
    #[test]
    fn a_type_name_does_not_replace_the_type() {
        let spec: EnvelopeSpec = serde_json::from_str(
            r#"{ "envelope_type": 7, "type_name": "app/event", "payload_utf8": "x" }"#,
        )
        .unwrap();
        let env = spec.to_envelope().unwrap();
        assert_eq!(env.envelope_type(), 7);
        assert_eq!(env.type_name(), Some("app/event"));
        assert!(env.verify());
        assert_ne!(
            env.id(),
            PulseEnvelope::typed("app/event", b"x".to_vec()).id(),
            "the type is part of the id"
        );
    }

    /// The exit status follows verification: tutorial T1's envelope exits
    /// with success, and the same bytes with the payload's last byte
    /// changed, which still parse, exit with failure.
    #[test]
    fn decode_exit_status_follows_verification() {
        let good = "71aad243e722c17b9f1cf2723ec6148a0000000000000000000000000000000000000000000000000100000000000b00000068656c6c6f2c206d657368";
        let tampered = "71aad243e722c17b9f1cf2723ec6148a0000000000000000000000000000000000000000000000000100000000000b00000068656c6c6f2c206d657369";
        assert_eq!(run_decode(good, false).unwrap(), ExitCode::SUCCESS);
        assert_eq!(run_decode(tampered, false).unwrap(), ExitCode::FAILURE);
        assert_eq!(run_decode(tampered, true).unwrap(), ExitCode::FAILURE);
    }
}
