// SPDX-License-Identifier: LicenseRef-Proprietary
// Cross-language byte-equality test for the canonical PulseEnvelope codec —
// Node.js implementation. Mirrors the Rust + Python codecs byte-for-byte.
//
// Checks that a PulseEnvelope encoded in Rust, Python and Node produces
// byte-identical output for the same field values: three independent
// implementations of chapter 3 of the specification agreeing byte for byte,
// which is the byte equality the standard is built on.
//
// This test does NOT depend on the napi-rs binding — it implements the canonical
// codec from scratch in pure JavaScript using Node's Buffer API. That keeps the
// cross-language equality independent of the binding implementation.
//
// The codec itself is canonical_codec.mjs, shared with envelope.test.mjs,
// which checks the binding's codec against it. Its id is the
// `pulse-envelope-id/v2` preimage the Rust codec hashes; the vectors below
// are the specification's, so a codec here that drifted from Rust's fails
// against them rather than only against itself.
//
// Run via:
//   cd bindings/node
//   npm ci
//   node --test __test__/canonical_codec_cross_language.test.mjs

import test from 'node:test';
import assert from 'node:assert/strict';

import {
  PAYLOAD_VARIANT_RAW,
  computeId,
  decodeEnvelopeAt,
  encodeEnvelope,
} from './canonical_codec.mjs';
import { exactInteger, hexNumber, loadVectors } from './vectors.mjs';

// ─────────────────────────────────────────────────────────────────────────
//  Tests
// ─────────────────────────────────────────────────────────────────────────

test('known envelope produces expected byte layout (54 B)', () => {
  const env = {
    envelopeType: 0x0001,
    payload: { variant: 'Raw', bytes: Buffer.from([0x42, 0x42, 0x42, 0x42]) },
  };
  const bytes = encodeEnvelope(env);

  // Expected layout (must match Rust + Python tests):
  //   [0..16]  id (BLAKE3 of envelope_type ‖ payload, truncated)
  //   [16..32] origin = all zeros
  //   [32..40] monotonic_nanos = 0
  //   [40..42] envelope_type = 0x0001
  //   [42..44] flags = 0
  //   [44]     type_name presence = 0
  //   [45]     payload variant tag = 0 (Raw)
  //   [46..50] payload_len = 4
  //   [50..54] payload = [0x42 0x42 0x42 0x42]
  assert.equal(bytes.length, 54);
  assert.deepEqual(bytes.subarray(16, 32), Buffer.alloc(16)); // origin
  assert.deepEqual(bytes.subarray(32, 40), Buffer.alloc(8)); // monotonic_nanos
  assert.deepEqual(bytes.subarray(40, 42), Buffer.from([0x01, 0x00])); // et LE
  assert.deepEqual(bytes.subarray(42, 44), Buffer.from([0x00, 0x00])); // flags
  assert.equal(bytes[44], 0); // tn? = None
  assert.equal(bytes[45], PAYLOAD_VARIANT_RAW);
  assert.deepEqual(bytes.subarray(46, 50), Buffer.from([0x04, 0x00, 0x00, 0x00]));
  assert.deepEqual(bytes.subarray(50, 54), Buffer.from([0x42, 0x42, 0x42, 0x42]));
});

test('round-trip preserves all fields', () => {
  const env = {
    envelopeType: 0x0042,
    payload: { variant: 'Raw', bytes: Buffer.from('hello cross-language', 'utf8') },
    typeName: 'api/inference',
    origin: Buffer.alloc(16, 0xAB),
    monotonicNanos: 1234567890,
    flags: 0b0101, // BROADCAST | PRIORITY
  };
  const encoded = encodeEnvelope(env);
  const { env: decoded } = decodeEnvelopeAt(encoded, 0);

  assert.equal(decoded.envelopeType, 0x0042);
  assert.deepEqual(decoded.payload.bytes, Buffer.from('hello cross-language', 'utf8'));
  assert.equal(decoded.typeName, 'api/inference');
  assert.deepEqual(decoded.origin, Buffer.alloc(16, 0xAB));
  assert.equal(decoded.monotonicNanos, 1234567890n);
  assert.equal(decoded.flags, 0b0101);
});

test('id is content-addressed via BLAKE3', () => {
  const envelopeType = 0x0010;
  const typeName = 'trace/event';
  const payload = { variant: 'Raw', bytes: Buffer.from('some data', 'utf8') };

  const env = { envelopeType, payload, typeName };
  const encoded = encodeEnvelope(env);
  const { env: decoded } = decodeEnvelopeAt(encoded, 0);

  const expectedId = computeId(envelopeType, typeName, payload);
  assert.deepEqual(Buffer.from(decoded.id), expectedId);
});

test('byte-identical to Rust + Python for known canonical fixture', () => {
  // Same fixture as Rust canonical_layout_is_stable_for_a_known_envelope
  // and Python test_byte_identical_to_rust_for_known_inputs.
  const env = {
    envelopeType: 0x0001,
    payload: { variant: 'Raw', bytes: Buffer.from([0x42, 0x42, 0x42, 0x42]) },
  };
  const nodeBytes = encodeEnvelope(env);

  // BLAKE3 of the v2 preimage of envelope_type=0x0001, no type name and the
  // raw payload [0x42,0x42,0x42,0x42], truncated: the id Rust and Python
  // compute, and the one the specification's vector states.
  const expectedId = computeId(0x0001, null, env.payload);
  assert.deepEqual(nodeBytes.subarray(0, 16), expectedId);
  assert.equal(expectedId.toString('hex'), 'fd68202c51ef2ee410929061581c4348');

  // The remaining 38 bytes are deterministic.
  const expectedTail = Buffer.concat([
    Buffer.alloc(16),                                       // origin
    Buffer.alloc(8),                                        // monotonic_nanos
    Buffer.from([0x01, 0x00]),                              // envelope_type
    Buffer.from([0x00, 0x00]),                              // flags
    Buffer.from([0x00]),                                    // tn? = None
    Buffer.from([PAYLOAD_VARIANT_RAW]),                     // variant tag
    Buffer.from([0x04, 0x00, 0x00, 0x00]),                  // payload_len
    Buffer.from([0x42, 0x42, 0x42, 0x42]),                  // payload
  ]);
  assert.deepEqual(nodeBytes.subarray(16), expectedTail);
  assert.equal(nodeBytes.length, 54);
});

test('Nested empty round-trips', () => {
  const parent = {
    envelopeType: 0x0050,
    payload: { variant: 'Nested', children: [] },
  };
  const encoded = encodeEnvelope(parent);
  const { env: decoded } = decodeEnvelopeAt(encoded, 0);
  assert.equal(decoded.payload.variant, 'Nested');
  assert.equal(decoded.payload.children.length, 0);
});

test('Nested single child round-trips', () => {
  const child = {
    envelopeType: 0x0001,
    payload: { variant: 'Raw', bytes: Buffer.from('child payload', 'utf8') },
  };
  const parent = {
    envelopeType: 0x0050,
    payload: { variant: 'Nested', children: [child] },
  };
  const encoded = encodeEnvelope(parent);
  const { env: decoded } = decodeEnvelopeAt(encoded, 0);
  assert.equal(decoded.payload.children.length, 1);
  assert.deepEqual(
    decoded.payload.children[0].payload.bytes,
    Buffer.from('child payload', 'utf8')
  );
});

test('Nested three-level recursion preserves structure', () => {
  const leaf = {
    envelopeType: 0x0001,
    payload: { variant: 'Raw', bytes: Buffer.from('leaf', 'utf8') },
  };
  const innerA = {
    envelopeType: 0x0050,
    payload: { variant: 'Nested', children: [leaf] },
  };
  const innerB = {
    envelopeType: 0x0002,
    payload: { variant: 'Raw', bytes: Buffer.from('sibling', 'utf8') },
  };
  const outer = {
    envelopeType: 0x0050,
    payload: { variant: 'Nested', children: [innerA, innerB] },
  };

  const encoded = encodeEnvelope(outer);
  const { env: decoded, nextOffset } = decodeEnvelopeAt(encoded, 0);

  assert.equal(nextOffset, encoded.length);
  assert.equal(decoded.payload.children.length, 2);
  assert.equal(decoded.payload.children[0].envelopeType, 0x0050);
  assert.equal(decoded.payload.children[1].envelopeType, 0x0002);

  // Drill into level-2 recursion
  const grandchildren = decoded.payload.children[0].payload.children;
  assert.equal(grandchildren.length, 1);
  assert.deepEqual(grandchildren[0].payload.bytes, Buffer.from('leaf', 'utf8'));
});

test('invalid payload variant tag rejected', () => {
  const env = {
    envelopeType: 0x0001,
    payload: { variant: 'Raw', bytes: Buffer.from([0x01]) },
  };
  const encoded = Buffer.from(encodeEnvelope(env));
  encoded[45] = 99; // corrupt variant tag
  assert.throws(() => decodeEnvelopeAt(encoded, 0), /invalid payload variant tag/);
});

test('truncated buffer rejected', () => {
  const env = {
    envelopeType: 0x0001,
    payload: { variant: 'Raw', bytes: Buffer.from('hello', 'utf8') },
  };
  const encoded = encodeEnvelope(env).subarray(0, 50); // chop tail
  assert.throws(() => decodeEnvelopeAt(encoded, 0), /truncated/);
});

// ───────────────────── The specification's vectors ─────────────────────

/** A vector's structure node (the nested vector's tree) as an envelope. */
function fromStructure(node) {
  const envelopeType = hexNumber(node.envelope_type);
  if (node.payload_variant === 'Raw') {
    return { envelopeType, payload: { variant: 'Raw', bytes: Buffer.from(node.payload_hex, 'hex') } };
  }
  return { envelopeType, payload: { variant: 'Nested', children: node.children.map(fromStructure) } };
}

/** Every id in a structure node, outermost first, with the envelope's. */
function structureIds(node, env, out = []) {
  out.push([node.id_hex, computeId(env.envelopeType, null, env.payload).toString('hex')]);
  (node.children ?? []).forEach((child, i) => structureIds(child, env.payload.children[i], out));
  return out;
}

for (const vector of loadVectors().filter((v) => v.name.startsWith('envelope-'))) {
  test(`specification vector ${vector.name}: encodes to its canonical bytes`, () => {
    let env;
    if (vector.inputs) {
      const inputs = vector.inputs;
      assert.equal(inputs.payload_variant, 'Raw');
      env = {
        envelopeType: hexNumber(inputs.envelope_type),
        typeName: inputs.type_name,
        payload: { variant: 'Raw', bytes: Buffer.from(inputs.payload_hex, 'hex') },
        origin: Buffer.from(inputs.origin_hex, 'hex'),
        monotonicNanos: exactInteger(vector, 'monotonic_nanos'),
        flags: inputs.flags,
      };
    } else {
      env = fromStructure(vector.structure.outer);
      for (const [stated, computed] of structureIds(vector.structure.outer, env)) {
        assert.equal(computed, stated, 'a nested envelope id');
      }
    }
    const bytes = encodeEnvelope(env);
    assert.equal(bytes.toString('hex'), vector.expected.canonical_hex);
    assert.equal(bytes.length, vector.expected.size_bytes);
    assert.equal(bytes.subarray(0, 16).toString('hex'), vector.expected.id_hex);

    const { env: decoded, nextOffset } = decodeEnvelopeAt(vector.bytes, 0);
    assert.equal(nextOffset, vector.bytes.length);
    assert.equal(Buffer.from(decoded.id).toString('hex'), vector.expected.id_hex);
    assert.equal(encodeEnvelope(decoded).toString('hex'), vector.expected.canonical_hex);
  });
}
