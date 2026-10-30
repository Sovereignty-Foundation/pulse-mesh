// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! `pulse version` — workspace + codec version stamp.

use std::process::ExitCode;

/// Implementation of `pulse version` (and `pms version`). `program` is the
/// first column of the text report, the name the caller answers to (`pulse`
/// prints `pulse (pulse-cli)`, `pms` prints `pms (pms-cli)`); the JSON
/// report is the same from either.
///
/// # Errors
/// Returns an error only if the JSON report cannot be serialized.
pub fn run(program: &str, json: bool) -> anyhow::Result<ExitCode> {
    let info = crate::ops::version::info();
    if json {
        println!("{}", serde_json::to_string_pretty(&info)?);
    } else {
        println!("{program:<17} {}", info.crate_version);
        println!("rust-toolchain    {}", info.rust_toolchain);
        println!(
            "codec-test-vector {} bytes, BLAKE3-16 {}",
            info.codec_test_vector_size, info.codec_test_vector_hash
        );
    }
    Ok(ExitCode::SUCCESS)
}
