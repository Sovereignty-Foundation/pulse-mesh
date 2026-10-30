// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//
// Fuzz target: `pulse_wire_udp::wire::decode`
//
// Feeds arbitrary bytes through the wire-format frame parser. The
// invariant is **totality + bounded output**: `decode` must
// terminate without panic on any byte input; on success the returned
// `Frame<'_>` must satisfy basic shape constraints (envelope length
// within MAX_ENVELOPE; pulse bytes within PULSE_WIRE_SIZE).
//
// What "real defects" look like here
// ----------------------------------
//
// - Panic in `decode` for any input. The parser is documented as
//   total over `&[u8]`; a panic is a correctness regression.
// - Out-of-bounds index in the success path. The frame's
//   envelope slice borrows from the input buffer; if the parser
//   produces a slice longer than the buffer, that's an unsoundness.
// - Excessive memory allocation. `decode` is documented as
//   allocation-free; any large alloc on the success path indicates
//   the parser is buffering when it shouldn't.

#![no_main]

use libfuzzer_sys::fuzz_target;
use pulse_canon::PULSE_WIRE_SIZE;
use pulse_wire_udp::wire::{decode, MAX_ENVELOPE};

fuzz_target!(|data: &[u8]| {
    // The parser must never panic, regardless of input.
    let result = decode(data);

    if let Ok(frame) = result {
        // Success-path shape invariants:
        //
        // 1. envelope slice fits within MAX_ENVELOPE
        assert!(
            frame.envelope.len() <= MAX_ENVELOPE,
            "decode succeeded with envelope.len() {} > MAX_ENVELOPE {}",
            frame.envelope.len(),
            MAX_ENVELOPE
        );
        // 2. pulse bytes are exactly PULSE_WIRE_SIZE
        assert_eq!(
            frame.pulse.len(),
            PULSE_WIRE_SIZE,
            "decode succeeded with pulse.len() != PULSE_WIRE_SIZE"
        );
        // 3. envelope slice originates inside the input buffer (borrow
        //    relationship — Rust's borrow checker guarantees this at
        //    compile time, but the assertion documents the contract).
        let env_ptr = frame.envelope.as_ptr() as usize;
        let buf_start = data.as_ptr() as usize;
        let buf_end = buf_start + data.len();
        assert!(
            env_ptr >= buf_start && env_ptr + frame.envelope.len() <= buf_end,
            "envelope slice escapes the input buffer (env_ptr={env_ptr:#x}, buf=[{buf_start:#x}..{buf_end:#x}])"
        );
    }
    // Err(_) is the boring case — the parser rejected the bytes.
    // That's correct behavior for any non-conforming input.
});
