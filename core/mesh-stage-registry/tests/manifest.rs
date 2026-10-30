// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! The macro emits the declared composition, in order, as path strings,
//! and binds each path to a module that exists: the layers here are
//! modules of this file, and a path that named nothing would not compile
//! (the crate's `compile_fail` doctest shows that).

/// A ring's functions layer, as the macro sees it.
mod my_ring_functions {
    pub(crate) mod module_a {}
}

/// A ring's stages layer, as the macro sees it.
mod my_ring_stages {
    pub(crate) mod stage_x {}
    pub(crate) mod stage_y {}
}

mod full {
    mesh_stage_registry::register_stages! {
        functions: [
            super::my_ring_functions::module_a,
        ],
        stages: [
            super::my_ring_stages::stage_x,
            super::my_ring_stages::stage_y,
        ],
    }
}

mod empty {
    mesh_stage_registry::register_stages! {}
}

#[test]
fn full_invocation_lists_functions_and_stages() {
    assert_eq!(full::RING_MANIFEST.len(), 2);
    assert_eq!(full::RING_MANIFEST[0].0, "functions");
    assert_eq!(
        full::RING_MANIFEST[0].1,
        ["super::my_ring_functions::module_a"]
    );
    assert_eq!(full::RING_MANIFEST[1].0, "stages");
    assert_eq!(
        full::RING_MANIFEST[1].1,
        [
            "super::my_ring_stages::stage_x",
            "super::my_ring_stages::stage_y"
        ]
    );
}

#[test]
fn empty_invocation_declares_an_empty_hub() {
    assert!(empty::RING_MANIFEST[0].1.is_empty());
    assert!(empty::RING_MANIFEST[1].1.is_empty());
}
