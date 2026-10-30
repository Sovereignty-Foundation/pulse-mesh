// SPDX-License-Identifier: LicenseRef-Proprietary
//! Build script: regenerate `include/pulse_wire.h` via cbindgen on every
//! build. The header is committed to git so downstream C consumers do
//! not need a Rust toolchain.

use std::env;
use std::path::PathBuf;

fn main() {
    let crate_dir = env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR");
    let out_path = PathBuf::from(&crate_dir).join("include").join("pulse_wire.h");

    let cfg_path = PathBuf::from(&crate_dir).join("cbindgen.toml");
    let cfg = cbindgen::Config::from_file(&cfg_path)
        .expect("cbindgen.toml present and well-formed");

    cbindgen::Builder::new()
        .with_crate(&crate_dir)
        .with_config(cfg)
        .generate()
        .expect("unable to generate C bindings")
        .write_to_file(&out_path);

    println!("cargo:rerun-if-changed=src/lib.rs");
    println!("cargo:rerun-if-changed=cbindgen.toml");
    println!("cargo:rerun-if-changed=build.rs");
}
