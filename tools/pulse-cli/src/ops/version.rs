// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! The version stamp behind `pulse version`, whose codec hash changes when a
//! build's `pulse-canon` drifts from the canonical wire format.

use pulse_canon::{PayloadData, PulseEnvelope};
use serde::Serialize;

/// Workspace + codec version stamp.
#[derive(Debug, Clone, Serialize)]
pub struct VersionInfo {
    /// The dev-functions crate's version, which is the workspace version.
    pub crate_version: &'static str,
    /// The `channel` that `rust-toolchain.toml` pinned when this crate was
    /// built, or `"unknown"` if it names none.
    pub rust_toolchain: &'static str,
    /// BLAKE3-16 of [`test_vector`]'s canonical encoding, hex-encoded.
    pub codec_test_vector_hash: String,
    /// The length of [`test_vector`]'s canonical encoding, in bytes.
    pub codec_test_vector_size: usize,
}

/// `rust-toolchain.toml` as it read when this crate was built: `build.rs`
/// finds it above the crate and copies it into `OUT_DIR`, so the crate need
/// not know how deep in a tree it sits; empty where no tree pins one.
const TOOLCHAIN_FILE: &str = include_str!(concat!(env!("OUT_DIR"), "/rust-toolchain.toml"));

/// The toolchain the repository pins, from [`TOOLCHAIN_FILE`].
fn rust_toolchain() -> &'static str {
    pinned_channel(TOOLCHAIN_FILE).unwrap_or("unknown")
}

/// The value of a toolchain file's `channel = "…"` line.
fn pinned_channel(toml: &str) -> Option<&str> {
    toml.lines().find_map(|line| {
        let value = line.trim_start().strip_prefix("channel")?.trim_start();
        let quoted = value.strip_prefix('=')?.trim_start().strip_prefix('"')?;
        quoted.split_once('"').map(|(channel, _)| channel)
    })
}

/// The fixed envelope behind the codec hash. Frozen: a test pins its hash.
pub fn test_vector() -> PulseEnvelope {
    PulseEnvelope::new(0x0001, PayloadData::Raw(b"pms/v0.1".to_vec()))
}

/// Compute the current version stamp.
pub fn info() -> VersionInfo {
    let env = test_vector();
    let bytes = env.to_canonical_bytes();
    let hash = blake3::hash(&bytes);

    VersionInfo {
        crate_version: env!("CARGO_PKG_VERSION"),
        rust_toolchain: rust_toolchain(),
        codec_test_vector_hash: hex::encode(&hash.as_bytes()[..16]),
        codec_test_vector_size: bytes.len(),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn the_stamp_carries_the_documented_codec_hash() {
        // Tutorial T1 shows `pms doctor` printing this. A failure means the
        // codec or the test vector changed, which the release notes record.
        let stamp = info();
        assert_eq!(
            stamp.codec_test_vector_hash,
            "57f2c2eec9bae1b5e69c97f88e9bfd8d"
        );
        assert_eq!(stamp.codec_test_vector_size, 58);
    }

    #[test]
    fn the_stamp_carries_the_toolchain_the_repository_pins() {
        // The file as it reads now, which the build took in: the first one
        // above this crate, as the build script finds it.
        let file = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .map(|dir| dir.join("rust-toolchain.toml"))
            .find(|file| file.is_file())
            .unwrap();
        let file = std::fs::read_to_string(file).unwrap();
        let stamp = info().rust_toolchain;
        assert!(
            file.lines()
                .any(|line| line.trim() == format!("channel = \"{stamp}\"")),
            "rust-toolchain.toml does not pin {stamp:?}:\n{file}"
        );
    }

    #[test]
    fn the_channel_is_read_from_the_channel_key_alone() {
        let file = "# channel = \"no\"\n[toolchain]\nchannels = \"no\"\n  channel   =  \"1.2.3\" # pinned\ncomponents = [\"rustfmt\"]\n";
        assert_eq!(pinned_channel(file), Some("1.2.3"));
        assert_eq!(pinned_channel("[toolchain]\nprofile = \"minimal\"\n"), None);
        assert_eq!(pinned_channel("channel = 1.2.3\n"), None);
    }
}
