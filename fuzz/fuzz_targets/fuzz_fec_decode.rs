// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//
// Fuzz target: `pulse_wire_udp::fec::decode_fec`
//
// Feeds arbitrary bytes through the FEC parity-datagram parser. Same
// invariant family as the wire decode: totality + bounded output +
// borrow-relationship-into-input on the success path.
//
// FEC datagrams carry an XOR parity payload that the receiver applies
// to recover lost frames. A panic in `decode_fec` would crash the
// receiver on adversarial input.

#![no_main]

use libfuzzer_sys::fuzz_target;
use pulse_wire_udp::fec::decode_fec;

fuzz_target!(|data: &[u8]| {
    // Totality: must never panic.
    let result = decode_fec(data);

    if let Ok((header, parity_slice)) = result {
        // Success-path invariants:
        //
        // 1. The parity slice length equals the header's declared
        //    parity_len. Any mismatch would indicate the parser
        //    accepted a truncated or padded payload it should have
        //    rejected as Truncated.
        assert_eq!(
            parity_slice.len(),
            header.parity_len as usize,
            "decode_fec succeeded with parity slice len ({}) != header.parity_len ({})",
            parity_slice.len(),
            header.parity_len
        );

        // 2. The parity slice borrows from the input buffer.
        let p_ptr = parity_slice.as_ptr() as usize;
        let buf_start = data.as_ptr() as usize;
        let buf_end = buf_start + data.len();
        assert!(
            p_ptr >= buf_start && p_ptr + parity_slice.len() <= buf_end,
            "parity slice escapes the input buffer"
        );

        // 3. window_n > 0 — a zero-window FEC datagram has no
        //    meaning and should be rejected (if the parser accepts
        //    it, downstream FEC reconstruction will divide by zero
        //    or worse).
        assert!(
            header.window_n > 0,
            "decode_fec succeeded with header.window_n == 0"
        );
    }
});
