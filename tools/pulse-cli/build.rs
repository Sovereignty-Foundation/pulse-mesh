// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! The version stamp reads the toolchain the repository pins. This script
//! finds `rust-toolchain.toml` by walking up from the crate and copies it
//! into `OUT_DIR`, so the crate need not know how deep in a tree it sits:
//! the integrated tree and the standard's own repository place it
//! differently. Built where no tree pins a toolchain, the copy is empty and
//! the stamp reads "unknown".

// A build script's failure is a panic by design.
#![allow(clippy::expect_used)]

use std::path::Path;

fn main() {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").expect("cargo sets CARGO_MANIFEST_DIR");
    let out_dir = std::env::var("OUT_DIR").expect("cargo sets OUT_DIR");
    let pinned = Path::new(&manifest_dir)
        .ancestors()
        .map(|dir| dir.join("rust-toolchain.toml"))
        .find(|file| file.is_file());
    let contents = match &pinned {
        Some(file) => {
            println!("cargo:rerun-if-changed={}", file.display());
            std::fs::read_to_string(file).expect("rust-toolchain.toml is readable")
        }
        None => String::new(),
    };
    println!("cargo:rerun-if-changed=build.rs");
    std::fs::write(Path::new(&out_dir).join("rust-toolchain.toml"), contents)
        .expect("OUT_DIR is writable");
}
