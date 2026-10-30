// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! Example 01 — Hello, Pulse (Rust).
//!
//! Encodes a fixed `PulseEnvelope` canonically, prints its 16-byte BLAKE3
//! content hash, then decodes the bytes back and asserts byte-equality. This
//! is the minimal proof that the canonical codec works end-to-end on your
//! machine. The same bytes come out of the codec in every language that
//! carries it (the Python and Node binding tests and the WASM build check them
//! against the specification's fixtures); that cross-language byte equality is
//! what the standard is built on (see the book's specification, chapter 3).
#![forbid(unsafe_code)]
#![allow(clippy::print_stdout)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use pulse_canon::{PayloadData, PulseEnvelope};

fn main() {
    let envelope = PulseEnvelope::new(0x0001, PayloadData::Raw(b"hello, mesh".to_vec()));

    let bytes = envelope.to_canonical_bytes();
    let canonical_hex = hex::encode(&bytes);
    let content_hash = envelope.id().to_hex();

    println!("envelope_type   0x{:04x}", 0x0001u16);
    println!("payload         \"hello, mesh\"");
    println!("canonical_size  {} bytes", bytes.len());
    println!("content_hash    {content_hash}");
    println!("canonical_hex   {canonical_hex}");

    let decoded = PulseEnvelope::from_canonical_bytes(&bytes)
        .expect("canonical decode must succeed for our own encoding");
    assert_eq!(decoded, envelope, "round-trip must be byte-equal");
    println!("\nOK — round-trip byte-equal.");
}
