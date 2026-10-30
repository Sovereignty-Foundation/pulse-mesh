// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! Decoding allocates in proportion to the bytes decoded, not to the
//! counts the bytes declare.
//!
//! A nested payload declares its child count before its children. The
//! decoder bounds that count by what the bytes after it could hold, but
//! every level of a deep nest counts the same remaining bytes: reserving
//! room for the declared children at each of 32 levels would hold about 66
//! times the buffer's length. The children are collected as they decode,
//! so each slot the decoder holds was paid for by a child's own bytes.
//!
//! The test counts every allocation through a global allocator of its
//! own, so it keeps to one test, and runs nothing else while it measures.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use pulse_canon::envelope::{MAX_NESTING_DEPTH, MIN_CANONICAL_ENVELOPE};
use pulse_canon::{EnvelopeCodecError, PulseEnvelope, CANONICAL_FIXED_HEADER};
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

/// Bytes allocated and not yet freed, and the most there have been since
/// the last reset.
static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

/// The system allocator, counting what is live.
struct Counting;

impl Counting {
    fn grew(size: usize) {
        let live = LIVE.fetch_add(size, Ordering::SeqCst) + size;
        PEAK.fetch_max(live, Ordering::SeqCst);
    }

    fn shrank(size: usize) {
        LIVE.fetch_sub(size, Ordering::SeqCst);
    }
}

// SAFETY: every call is passed to the system allocator unchanged, with the
// caller's layout and pointer, so this allocator keeps each of its
// contracts; the counters are only arithmetic on the side.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller upholds `alloc`'s contract, which this passes
        // on unchanged.
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            Self::grew(layout.size());
        }
        ptr
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: as for `alloc`.
        let ptr = unsafe { System.alloc_zeroed(layout) };
        if !ptr.is_null() {
            Self::grew(layout.size());
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: the caller upholds `dealloc`'s contract: `ptr` came from
        // this allocator, which is the system's, with this layout.
        unsafe { System.dealloc(ptr, layout) };
        Self::shrank(layout.size());
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // SAFETY: the caller upholds `realloc`'s contract, which this passes
        // on unchanged.
        let moved = unsafe { System.realloc(ptr, layout, new_size) };
        if !moved.is_null() {
            Self::shrank(layout.size());
            Self::grew(new_size);
        }
        moved
    }
}

#[global_allocator]
static COUNTING: Counting = Counting;

/// The most bytes live at once while `f` ran, beyond those live before it.
fn peak_while<T>(f: impl FnOnce() -> T) -> (T, usize) {
    let before = LIVE.load(Ordering::SeqCst);
    PEAK.store(before, Ordering::SeqCst);
    let out = f();
    (out, PEAK.load(Ordering::SeqCst) - before)
}

/// `len` bytes nesting one level deeper than the decoder accepts, each
/// level a nested envelope with no type name that declares as many
/// children as the bytes after its count could hold; zeros fill the rest.
fn crafted(len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    for level in 0..=MAX_NESTING_DEPTH {
        let at = level * MIN_CANONICAL_ENVELOPE;
        // No type name, then the nested variant tag.
        buf[at + CANONICAL_FIXED_HEADER] = 0;
        buf[at + CANONICAL_FIXED_HEADER + 1] = 1;
        let after_count = at + MIN_CANONICAL_ENVELOPE;
        let count = ((len - after_count) / MIN_CANONICAL_ENVELOPE) as u32;
        buf[after_count - 4..after_count].copy_from_slice(&count.to_le_bytes());
    }
    buf
}

#[test]
fn a_deep_nest_of_declared_children_allocates_about_its_own_length() {
    const LEN: usize = 1 << 20;
    let buf = crafted(LEN);
    let (decoded, peak) = peak_while(|| PulseEnvelope::from_canonical_bytes(&buf));

    // The nest is refused one level past the limit, at its first child
    // at each level.
    let mut cause = decoded.expect_err("a nest past the limit is refused");
    for _ in 0..MAX_NESTING_DEPTH {
        cause = match cause {
            EnvelopeCodecError::NestedDecode {
                child_index: 0,
                cause,
            } => *cause,
            other => panic!("expected the first child to fail, got {other:?}"),
        };
    }
    assert_eq!(
        cause,
        EnvelopeCodecError::NestingTooDeep {
            max: MAX_NESTING_DEPTH
        }
    );
    assert!(
        peak <= LEN,
        "decoding {LEN} bytes held {peak} bytes at its peak ({:.1} times its input)",
        peak as f64 / LEN as f64
    );
}
