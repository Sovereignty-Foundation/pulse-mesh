// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//
// Fuzz target: `core_store::decode_body`, the check an `EnvelopeStore`
// reader applies to a slot's recorded id and the body it copied out, before
// `fetch`, `fetch_at` or `read_since` returns the envelope.
//
// Two kinds of input. Raw: an id and a body straight from the input. Built:
// an envelope drawn from the input (numeric or named type, raw or nested
// payload, any origin, timestamp and flags, now and then a reserved flag
// bit), written as the store writes it (its id in the slot, its canonical
// bytes as the body), then damaged by edits the input chooses (flipped
// bytes, truncation, insertion, removal, appended bytes) and filed under
// its own id or another.
//
// The oracle is not the codec: the slot is judged by a reading of the
// canonical layout and a computation of the content id written from the
// specification (`pulse_mesh_fuzz::canonical`), which takes the id's
// preimage from the body's own bytes.
//
// Invariants:
// - the reader returns an envelope exactly when the body is one canonical
//   envelope as the specification reads it, using every byte, carrying the
//   slot's id, whose content hashes to that id;
// - an envelope it returns holds the fields the specification reads, and
//   its canonical bytes are the body itself;
// - a slot as the store writes it reads back as the envelope written, when
//   that envelope's flags are defined ones; one with a reserved flag bit is
//   never read back;
// - whatever the damage, an envelope read under the written envelope's id
//   has that envelope's hashed content: type, type name and payload. The
//   id does not cover the origin, the timestamp or the flags, so damage
//   there may pass.

#![no_main]

use libfuzzer_sys::arbitrary::{Result, Unstructured};
use libfuzzer_sys::fuzz_target;
use pulse_canon::{PayloadData, PulseEnvelope, PulseEnvelopeFlags};
use pulse_mesh_fuzz::canonical;

/// Deepest nesting of a built envelope.
const MAX_DEPTH: usize = 3;
/// Most children of a nested payload.
const MAX_CHILDREN: usize = 3;
/// Longest raw payload drawn.
const MAX_PAYLOAD: usize = 256;
/// Most edits to a built body.
const MAX_EDITS: usize = 4;

fuzz_target!(|data: &[u8]| {
    let _ = fuzz(data);
});

fn fuzz(data: &[u8]) -> Result<()> {
    let mut u = Unstructured::new(data);
    if u.ratio(1, 4)? {
        let stored_id: [u8; 16] = u.arbitrary()?;
        read(&stored_id, u.take_rest());
        return Ok(());
    }

    let written = envelope(&mut u, 0)?;
    let pristine = written.to_canonical_bytes();
    let mut body = pristine.clone();
    for _ in 0..u.int_in_range(0..=MAX_EDITS)? {
        edit(&mut u, &mut body)?;
    }
    let stored_id = match u.int_in_range(0..=7u8)? {
        0 => u.arbitrary()?,
        1 => {
            let mut id = written.id().0;
            id[u.choose_index(id.len())?] ^= 1 << u.int_in_range(0..=7u8)?;
            id
        }
        _ => written.id().0,
    };

    let got = read(&stored_id, &body);
    if body == pristine && stored_id == written.id().0 {
        let reserved = written.flags.bits() & !PulseEnvelopeFlags::all().bits() != 0
            || nested_reserved(written.payload());
        if reserved {
            assert!(
                got.is_none(),
                "an envelope with a reserved flag bit read back"
            );
        } else {
            let env = got
                .as_ref()
                .expect("a slot as the store writes it reads back");
            assert_eq!(
                env.to_canonical_bytes(),
                pristine,
                "read back as another envelope"
            );
        }
    }
    if let Some(env) = &got {
        if stored_id == written.id().0 {
            assert_eq!(
                env.envelope_type(),
                written.envelope_type(),
                "type changed under the id"
            );
            assert_eq!(
                env.type_name(),
                written.type_name(),
                "type name changed under the id"
            );
            assert_eq!(
                env.payload().is_raw(),
                written.payload().is_raw(),
                "payload variant changed under the id"
            );
            assert_eq!(
                env.payload().to_bytes(),
                written.payload().to_bytes(),
                "payload changed under the id"
            );
        }
    }
    Ok(())
}

/// Apply the reader's check to one slot, and hold it to its contract as the
/// specification states it.
fn read(stored_id: &[u8; 16], body: &[u8]) -> Option<PulseEnvelope> {
    let got = core_store::decode_body(stored_id, body);

    let spec = canonical::parse_exact(body);
    let accept = spec
        .as_ref()
        .is_some_and(|p| p.id == *stored_id && p.verifies());
    assert_eq!(
        got.is_some(),
        accept,
        "the reader's verdict is not the specification's: {spec:?}"
    );

    if let (Some(env), Some(spec)) = (&got, &spec) {
        assert_eq!(env.id().0, *stored_id);
        assert!(
            spec.matches(env),
            "the reader returned other fields than the body holds"
        );
        assert_eq!(
            env.to_canonical_bytes(),
            body,
            "the envelope returned is not the body"
        );
    }
    got
}

/// Whether any envelope nested in `payload` sets a reserved flag bit.
fn nested_reserved(payload: &PayloadData) -> bool {
    payload.as_nested().is_some_and(|children| {
        children.iter().any(|c| {
            c.flags.bits() & !PulseEnvelopeFlags::all().bits() != 0 || nested_reserved(c.payload())
        })
    })
}

/// An envelope with a content id, built from the input.
fn envelope(u: &mut Unstructured<'_>, depth: usize) -> Result<PulseEnvelope> {
    let envelope_type: u16 = u.arbitrary()?;
    let type_name: Option<String> = if u.arbitrary()? {
        Some(u.arbitrary::<&str>()?.to_owned())
    } else {
        None
    };
    let payload = if depth < MAX_DEPTH && u.ratio(1, 3)? {
        let mut children = Vec::new();
        for _ in 0..u.int_in_range(0..=MAX_CHILDREN)? {
            children.push(envelope(u, depth + 1)?);
        }
        PayloadData::Nested(children)
    } else {
        let len = u.int_in_range(0..=MAX_PAYLOAD)?;
        PayloadData::Raw(u.bytes(len.min(u.len()))?.to_vec())
    };
    let mut envelope = PulseEnvelope::with_content(envelope_type, type_name, payload);
    envelope.origin = u.arbitrary()?;
    envelope.monotonic_nanos = u.arbitrary()?;
    // Mostly defined flags, as a producer sets them; now and then a
    // reserved bit kept, which the store writes and no reader returns.
    envelope.flags = if u.ratio(1, 8)? {
        PulseEnvelopeFlags::from_bits_retain(u.arbitrary()?)
    } else {
        PulseEnvelopeFlags::from_bits_truncate(u.arbitrary()?)
    };
    Ok(envelope)
}

/// One edit to a body, of a kind and at a place the input chooses.
fn edit(u: &mut Unstructured<'_>, body: &mut Vec<u8>) -> Result<()> {
    match u.int_in_range(0..=4u8)? {
        0 if !body.is_empty() => {
            let at = u.choose_index(body.len())?;
            body[at] ^= u.int_in_range(1..=u8::MAX)?;
        }
        1 => {
            let at = u.int_in_range(0..=body.len())?;
            body.truncate(at);
        }
        2 => {
            let at = u.int_in_range(0..=body.len())?;
            body.insert(at, u.arbitrary()?);
        }
        3 if !body.is_empty() => {
            let at = u.choose_index(body.len())?;
            body.remove(at);
        }
        _ => {
            let len = u.int_in_range(1..=8)?;
            body.extend_from_slice(u.bytes(len.min(u.len()))?);
        }
    }
    Ok(())
}
