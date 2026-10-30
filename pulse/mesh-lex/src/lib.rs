// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! The Lexicon™ (R-LEX), tier 2: the public conformance catalog and its Merkle root.
//!
//! A registry of typed descriptors with a Merkle root over its public
//! entries. `pulse/pulse-spec/lex-root.txt` records the root a release was
//! cut with, and the daemon logs the root at start, so a peer can tell which
//! catalog it is speaking. The registry, its entries and boundaries, the
//! line and bundle schemas, the Merkle root with its diff, and the commit
//! tick each have a module; callers use [`lex_root`] and [`lex_root_hex`].
//!
//! In the book: <https://pulse-mesh.net/docs/reference/spec/08-conformance.html> (section 8.2).

#![forbid(unsafe_code)]

pub mod commit;
pub mod entry;
pub mod merkle;
pub mod registry;
pub mod schema;
pub mod types;

pub use commit::{commit_tick, MerkleChangeEvent};
pub use entry::{Boundary, DescriptorKind, LexEntry};
pub use merkle::{lex_root, lex_root_hex, Digest32, LexMerkle, MerkleDiff};
pub use registry::{LexRegistry, LexRegistryError};
pub use schema::{BundleSchema, LexSchemaRegistry, LineKind, LineSchema};
pub use types::{LineSet, LineValue};
