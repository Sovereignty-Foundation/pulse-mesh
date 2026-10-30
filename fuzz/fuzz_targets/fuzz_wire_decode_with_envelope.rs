// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//
// Fuzz target: `pulse_wire_udp::wire::decode_with_envelope`
//
// Same totality invariant as `fuzz_wire_decode`, but additionally
// exercises the canonical envelope codec (`PulseEnvelope`) on the
// successfully-decoded wire frames. Catches integration bugs that
// only surface when the two parsers are composed.

#![no_main]

use libfuzzer_sys::fuzz_target;
use pulse_wire_udp::wire::decode_with_envelope;

fuzz_target!(|data: &[u8]| {
    // Must never panic — regardless of byte input.
    let result = decode_with_envelope(data);

    if let Ok((frame, envelope)) = result {
        // The frame must satisfy the same shape invariants as
        // `decode` (verified there; we don't re-assert here).
        //
        // The envelope must satisfy verify() — the canonical codec
        // recomputes the content-ID and compares against the stored
        // ID. A successful decode_with_envelope MUST yield an envelope
        // whose content-ID is self-consistent.
        assert!(
            envelope.verify(),
            "decode_with_envelope returned an envelope that fails verify()"
        );

        // The envelope's canonical_size must equal the frame's
        // envelope-slice length — the wire-frame's `n` field is the
        // envelope's canonical-encoded length.
        assert_eq!(
            envelope.canonical_size(),
            frame.envelope.len(),
            "envelope canonical_size ({}) disagrees with frame envelope slice len ({})",
            envelope.canonical_size(),
            frame.envelope.len()
        );
    }
    // Err is correct rejection — the input either failed wire
    // decoding or envelope canonical decoding.
});
