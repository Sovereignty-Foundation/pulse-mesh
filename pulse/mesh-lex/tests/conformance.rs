// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stderr
)]

//! Conformance: the published `pulse/pulse-spec/lex-root.txt`, the hex
//! Merkle root downstream implementers check against, verified as they
//! would, with the `mesh-lex` public API alone.

use mesh_lex::{lex_root, lex_root_hex, Boundary, DescriptorKind, LexEntry, LexRegistry};
use std::path::PathBuf;

/// The published `pulse/pulse-spec/lex-root.txt`.
fn published_lex_root_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("pulse")
        .join("pulse-spec")
        .join("lex-root.txt")
}

/// Load the published hex root, trimmed of trailing whitespace.
fn load_published_lex_root_hex() -> String {
    let path = published_lex_root_path();
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read {}: {}", path.display(), e))
        .trim()
        .to_string()
}

/// The canonical public registry, empty at this revision. It restates
/// `tools/gen-lex-root`'s on purpose: the test treats that tool
/// as opaque and rebuilds its input from the public API.
fn canonical_public_registry() -> LexRegistry {
    LexRegistry::new()
}

#[test]
fn published_lex_root_is_64_lowercase_hex_chars() {
    let hex = load_published_lex_root_hex();
    assert_eq!(
        hex.len(),
        64,
        "lex-root.txt must contain exactly 64 hex chars; got {}",
        hex.len()
    );
    assert!(
        hex.chars()
            .all(|c| c.is_ascii_digit() || (c.is_ascii_hexdigit() && c.is_lowercase())),
        "lex-root.txt must be lowercase hex; got {hex:?}"
    );
}

#[test]
fn published_lex_root_matches_canonical_registry_computation() {
    let published = load_published_lex_root_hex();
    let registry = canonical_public_registry();
    let computed = lex_root_hex(&registry);

    assert_eq!(
        computed, published,
        "published lex-root.txt ({published}) disagrees with the value computed from the canonical registry ({computed})"
    );
}

#[test]
fn empty_canonical_registry_matches_domain_sentinel() {
    // The first public entry in the canonical registry needs a fixture
    // for the populated state here, and a new lex-root.txt.
    let registry = canonical_public_registry();
    if !registry.is_empty() {
        eprintln!(
            "INFO: canonical_public_registry() is non-empty (len={}); \
             skipping empty-sentinel assertion. Extend this test with \
             a populated-state fixture.",
            registry.len()
        );
        return;
    }

    let expected_empty = *blake3::hash(b"mesh-lex/empty/v1").as_bytes();
    let actual = lex_root(&registry);
    assert_eq!(
        actual, expected_empty,
        "while the canonical registry is empty, lex_root MUST equal BLAKE3(\"mesh-lex/empty/v1\")"
    );
}

#[test]
fn adding_public_entry_shifts_published_root() {
    let baseline_hex = load_published_lex_root_hex();

    let mut extended = canonical_public_registry();
    let probe = LexEntry::new(
        0xABCD,
        "pulse-mesh-conformance/probe-entry",
        1,
        DescriptorKind::EnvelopeType,
        Boundary::Public,
        b"conformance probe payload".to_vec(),
    );
    extended.insert(probe).expect("probe insert must succeed");

    let extended_hex = lex_root_hex(&extended);
    assert_ne!(
        extended_hex, baseline_hex,
        "adding a public entry to the canonical registry MUST shift the lex root \
         (BLAKE3 leaf inclusion property)"
    );
}

#[test]
fn non_public_entries_excluded_from_root() {
    let baseline = lex_root(&canonical_public_registry());

    for boundary in [Boundary::MeshScoped, Boundary::NodeScoped] {
        let mut extended = canonical_public_registry();
        let entry = LexEntry::new(
            0xBEEF,
            format!("pulse-mesh-conformance/{boundary:?}-probe"),
            1,
            DescriptorKind::EnvelopeType,
            boundary,
            b"non-public probe".to_vec(),
        );
        extended.insert(entry).expect("non-public insert");
        let with_non_public = lex_root(&extended);
        assert_eq!(
            with_non_public, baseline,
            "Boundary::{boundary:?} entries MUST be excluded from lex_root() \
             — the Boundary contract requires the published root to \
             reflect only Boundary::Public entries"
        );
    }
}

#[test]
fn fixed_catalog_root_is_insertion_order_independent() {
    // Inserted ascending, then descending.
    let entries: Vec<LexEntry> = (0..6u16)
        .map(|i| {
            LexEntry::new(
                0x1000 + i,
                format!("conformance/entry-{i:03}"),
                1,
                if i % 2 == 0 {
                    DescriptorKind::EnvelopeType
                } else {
                    DescriptorKind::BundleSchema
                },
                Boundary::Public,
                vec![i as u8; 8],
            )
        })
        .collect();

    let mut reg_a = LexRegistry::new();
    for e in &entries {
        reg_a.insert(e.clone()).unwrap();
    }

    let mut reg_b = LexRegistry::new();
    for e in entries.iter().rev() {
        reg_b.insert(e.clone()).unwrap();
    }

    assert_eq!(
        lex_root(&reg_a),
        lex_root(&reg_b),
        "external implementers reading the catalog in any order MUST arrive at the same root"
    );
}
