// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! Regenerate `pulse/pulse-spec/lex-root.txt`, into the path given.
//!
//! The pulse-mesh public substrate (`mesh-lex`) ships its current
//! conformance anchor as a one-line hex file: the BLAKE3 Merkle root
//! over every `Boundary::Public` entry in the canonical default
//! registry. External implementations diff their computed root
//! against the file as a mechanical conformance check.
//!
//! Today the canonical default registry is empty — pulse-mesh does
//! not register any envelope-type entries in the public layer at
//! this revision — so the root reduces to the domain-separated empty
//! sentinel `BLAKE3("mesh-lex/empty/v1")`. As public entries get
//! registered in subsequent revisions, this tool will pick them up
//! and the published root will move accordingly.
//!
//! The output path is the one argument, so the tool lives with the other
//! tools under `peripheral/tools` rather than beside the file it writes
//! (ADR-0005, amended):
//!
//! ```bash
//! cargo run --release -p gen-lex-root -- pulse/pulse-spec/lex-root.txt
//! ```
#![forbid(unsafe_code)]
#![allow(clippy::print_stdout, clippy::print_stderr)]

use std::path::PathBuf;
use std::process::ExitCode;

use mesh_lex::{lex_root_hex, LexRegistry};

fn main() -> ExitCode {
    let mut args = std::env::args_os().skip(1);
    let (Some(path), None) = (args.next(), args.next()) else {
        eprintln!("usage: gen-lex-root <path to lex-root.txt>");
        return ExitCode::from(2);
    };
    let path = PathBuf::from(path);
    let registry = canonical_public_registry();
    let root_hex = lex_root_hex(&registry);
    if let Err(e) = std::fs::write(&path, format!("{root_hex}\n")) {
        eprintln!("gen-lex-root: cannot write {}: {e}", path.display());
        return ExitCode::FAILURE;
    }
    println!("wrote {} ({} bytes hex)", path.display(), root_hex.len());
    println!("lex_root = {root_hex}");
    ExitCode::SUCCESS
}

/// The canonical default public registry that the spec publishes.
/// Currently empty; future revisions populate it with the public
/// envelope-type entries pulse-mesh exposes.
fn canonical_public_registry() -> LexRegistry {
    LexRegistry::new()
}
