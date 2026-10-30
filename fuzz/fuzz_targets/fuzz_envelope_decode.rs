// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//
// Fuzz target: `pulse_canon::PulseEnvelope::decode_canonical_at` and
// `from_canonical_bytes`, the canonical codec on its own, judged against a
// reading of the specification that does not use it
// (`pulse_mesh_fuzz::canonical`).
//
// The codec on its own, without the UDP frame around it, so the input is
// not limited to one datagram: nested counts, nesting depth and type-name
// lengths are all attacker-controlled here. The first byte of the input
// chooses whether the envelope's identifiers are sealed first (every
// envelope in it given the id its content hashes to, innermost first), so
// that inputs that verify are as common as inputs that do not, and where a
// second decode starts.
//
// Invariants:
// - the decoder is total: it never panics, and never allocates from a size
//   the input declares (the harness's malloc limit stands guard);
// - `decode_canonical_at(data, 0)` accepts exactly what the reading of
//   chapter 3 accepts, reads the same fields and children, and ends where
//   that reading ends;
// - an envelope it accepts re-encodes to exactly the bytes it spans, and
//   `canonical_size` is their length: no field is normalised on the way
//   through, a reserved flag bit included (SAF-37a);
// - `from_canonical_bytes(data)` accepts exactly when that span is all of
//   `data`, re-encodes to `data`, and otherwise reports the trailing bytes;
// - `verify()` holds exactly when the id the envelope carries is the id
//   section 3.2 computes from its own bytes;
// - decoding at an offset reads what decoding the slice from that offset
//   reads, with the offset added.

#![no_main]

use libfuzzer_sys::fuzz_target;
use pulse_canon::{EnvelopeCodecError, PulseEnvelope};
use pulse_mesh_fuzz::canonical::{self, Payload};

fuzz_target!(|input: &[u8]| {
    let Some((&mode, rest)) = input.split_first() else {
        return;
    };
    let mut data = rest.to_vec();
    if mode & 1 == 1 {
        seal(&mut data, 0, 0);
    }
    check(&data);
    let at = usize::from(mode >> 1) % (data.len() + 1);
    check_offset(&data, at);
});

/// The codec against the specification, at the start of `data`.
fn check(data: &[u8]) {
    let spec = canonical::parse(data, 0, 0);
    let whole = PulseEnvelope::from_canonical_bytes(data);
    let Ok((env, used)) = PulseEnvelope::decode_canonical_at(data, 0) else {
        assert!(
            spec.is_none(),
            "the codec refused an envelope the specification reads: {spec:?}"
        );
        assert!(
            whole.is_err(),
            "from_canonical_bytes accepted what decode_canonical_at refused"
        );
        return;
    };
    let spec = spec.expect("the codec accepted bytes the specification refuses");
    assert_eq!(
        used, spec.span.end,
        "the codec and the specification end apart"
    );
    assert!(
        spec.matches(&env),
        "the codec read other fields than the specification"
    );
    assert_eq!(
        env.to_canonical_bytes(),
        &data[..used],
        "the envelope does not re-encode to the bytes it was read from"
    );
    assert_eq!(env.canonical_size(), used, "canonical_size is not the span");
    assert_eq!(
        env.verify(),
        spec.verifies(),
        "verify() disagrees with the id the specification computes"
    );
    match whole {
        Ok(env) => {
            assert_eq!(
                used,
                data.len(),
                "from_canonical_bytes ignored trailing bytes"
            );
            assert_eq!(
                env.to_canonical_bytes(),
                data,
                "from_canonical_bytes changed the bytes"
            );
        }
        Err(err) => {
            assert_ne!(
                used,
                data.len(),
                "from_canonical_bytes refused a whole envelope"
            );
            assert_eq!(
                err,
                EnvelopeCodecError::TrailingBytes {
                    used,
                    len: data.len()
                }
            );
        }
    }
}

/// Decoding at `at` reads what decoding the slice from `at` reads.
fn check_offset(data: &[u8], at: usize) {
    let inside = PulseEnvelope::decode_canonical_at(data, at);
    let alone = PulseEnvelope::decode_canonical_at(&data[at..], 0);
    match (inside, alone) {
        (Ok((a, used_a)), Ok((b, used_b))) => {
            assert_eq!(used_a, at + used_b, "the end moved with the offset");
            assert_eq!(a.to_canonical_bytes(), b.to_canonical_bytes());
        }
        (Err(_), Err(_)) => {}
        (a, b) => panic!("decoding at {at} and decoding the slice disagree: {a:?} / {b:?}"),
    }
}

/// Give every envelope in `buf` at `at` the id its content hashes to,
/// children before their parent, since a parent's id covers its children's
/// bytes. Bytes that are not an envelope are left alone.
fn seal(buf: &mut [u8], at: usize, depth: usize) {
    let Some(parsed) = canonical::parse(buf, at, depth) else {
        return;
    };
    if let Payload::Nested(children) = &parsed.payload {
        for child in children {
            seal(buf, child.span.start, depth + 1);
        }
    }
    if let Some(parsed) = canonical::parse(buf, at, depth) {
        buf[at..at + 16].copy_from_slice(&parsed.spec_id());
    }
}
