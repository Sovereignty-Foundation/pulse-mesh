// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! `register_stages!`, tier 1: the composition primitive of the four-crate ring.
//!
//! Each ring's `<ring>-hub` invokes the macro once, naming the functions
//! (from `<ring>-functions`) and the stages (from `<ring>-stages`) it
//! composes; the four hubs are the four invocations in the tree.
//!
//! ## Invocation shape
//!
//! The paths resolve where the macro is invoked; here modules of `core`
//! stand in for a ring's layers.
//!
//! ```
//! mesh_stage_registry::register_stages! {
//!     functions: [ core::mem, core::cmp ],
//!     stages: [ core::iter ],
//! }
//!
//! assert_eq!(RING_MANIFEST[0], ("functions", &["core::mem", "core::cmp"][..]));
//! assert_eq!(RING_MANIFEST[1], ("stages", &["core::iter"][..]));
//! ```
//!
//! A path that does not resolve is a compile error:
//!
//! ```compile_fail,E0432
//! mesh_stage_registry::register_stages! {
//!     functions: [ core::no_such_module ],
//!     stages: [],
//! }
//! ```
//!
//! In the book: <https://pulse-mesh.net/docs/explanation/README.html>.
#![forbid(unsafe_code)]
#![no_std]

/// Register the functions and stages that compose a ring hub.
///
/// Expands to `pub const RING_MANIFEST: &[(&str, &[&str])]`, whose entries
/// `("functions", [..])` and `("stages", [..])` hold the listed paths as
/// strings in declaration order, and imports every listed path, so a path
/// that does not resolve fails the build of the hub that lists it. An
/// empty invocation declares a hub with no functions and no stages.
#[macro_export]
macro_rules! register_stages {
    () => {
        /// The ring's composition as declared in its hub: no functions and no stages.
        pub const RING_MANIFEST: &[(&str, &[&str])] = &[("functions", &[]), ("stages", &[])];
    };
    (
        functions: [ $($f:path),* $(,)? ],
        stages: [ $($s:path),* $(,)? ] $(,)?
    ) => {
        /// The ring's composition as declared in its hub, as module paths.
        pub const RING_MANIFEST: &[(&str, &[&str])] = &[
            ("functions", &[$(stringify!($f)),*]),
            ("stages", &[$(stringify!($s)),*]),
        ];
        const _: () = {
            $(#[allow(unused_imports)] use $f as _;)*
            $(#[allow(unused_imports)] use $s as _;)*
        };
    };
}
