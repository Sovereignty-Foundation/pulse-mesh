// SPDX-License-Identifier: LicenseRef-Proprietary
// The binding's canonical envelope codec (encodeEnvelope, decodeEnvelope,
// envelopeId): every vector in pulse/pulse-spec/test-vectors/, and agreement
// byte for byte with the pure-JavaScript codec in canonical_codec.mjs, which
// the cross-language test checks against the same vectors.

import test from 'node:test';
import assert from 'node:assert/strict';

import {
  ErrorCode,
  Instruction,
  PULSE_WIRE_SIZE,
  Pulse,
  decodeEnvelope,
  encodeEnvelope,
  envelopeId,
} from '../index.js';
import * as js from './canonical_codec.mjs';
import { exactInteger, hexNumber, loadVectors } from './vectors.mjs';

const vectors = loadVectors();

/** A vector's structure node as an `encodeEnvelope` description. */
function fromStructure(node) {
  const envelopeType = hexNumber(node.envelope_type);
  if (node.payload_variant === 'Raw') {
    return { envelopeType, payload: Buffer.from(node.payload_hex, 'hex') };
  }
  return { envelopeType, payload: node.children.map(fromStructure) };
}

/** The same envelope as the pure-JS codec describes it. */
function toJs(env) {
  return {
    envelopeType: env.envelopeType,
    typeName: env.typeName ?? null,
    origin: env.origin,
    monotonicNanos: env.monotonicNanos,
    flags: env.flags,
    payload: Buffer.isBuffer(env.payload)
      ? { variant: 'Raw', bytes: env.payload }
      : { variant: 'Nested', children: env.payload.map(toJs) },
  };
}

/** Check a decoded envelope against a structure node, ids included. */
function assertStructure(decoded, node) {
  assert.equal(decoded.envelopeType, hexNumber(node.envelope_type));
  assert.equal(decoded.id.toString('hex'), node.id_hex);
  assert.equal(decoded.typeName, null);
  if (node.payload_variant === 'Raw') {
    assert.ok(Buffer.isBuffer(decoded.payload));
    assert.equal(decoded.payload.toString('hex'), node.payload_hex);
  } else {
    assert.ok(Array.isArray(decoded.payload));
    assert.equal(decoded.payload.length, node.children.length);
    node.children.forEach((child, i) => assertStructure(decoded.payload[i], child));
  }
}

// ─────────────────────── The specification's vectors ───────────────────────

test('the vectors directory holds only kinds this file checks', () => {
  assert.ok(vectors.length >= 3, `${vectors.length} vectors`);
  for (const vector of vectors) {
    assert.match(vector.name, /^(envelope|pulse)-/, `${vector.file}: a vector of a kind no test here checks`);
  }
});

for (const vector of vectors.filter((v) => v.name.startsWith('envelope-'))) {
  test(`vector ${vector.name}: encodeEnvelope writes its canonical bytes`, () => {
    let env;
    if (vector.inputs) {
      const inputs = vector.inputs;
      assert.equal(inputs.payload_variant, 'Raw');
      env = {
        envelopeType: hexNumber(inputs.envelope_type),
        typeName: inputs.type_name,
        payload: Buffer.from(inputs.payload_hex, 'hex'),
        origin: Buffer.from(inputs.origin_hex, 'hex'),
        monotonicNanos: exactInteger(vector, 'monotonic_nanos'),
        flags: inputs.flags,
      };
    } else {
      env = fromStructure(vector.structure.outer);
    }
    const bytes = encodeEnvelope(env);
    assert.equal(bytes.toString('hex'), vector.expected.canonical_hex);
    assert.equal(bytes.length, vector.expected.size_bytes);
    assert.equal(envelopeId(env).toString('hex'), vector.expected.id_hex);
  });

  test(`vector ${vector.name}: decodeEnvelope reads and verifies it`, () => {
    const decoded = decodeEnvelope(vector.bytes);
    assert.equal(decoded.id.toString('hex'), vector.expected.id_hex);
    if (vector.inputs) {
      const inputs = vector.inputs;
      assert.equal(decoded.envelopeType, hexNumber(inputs.envelope_type));
      assert.equal(decoded.typeName, inputs.type_name);
      assert.equal(decoded.payload.toString('hex'), inputs.payload_hex);
      assert.equal(decoded.origin.toString('hex'), inputs.origin_hex);
      assert.equal(decoded.monotonicNanos, exactInteger(vector, 'monotonic_nanos'));
      assert.equal(decoded.flags, inputs.flags);
    } else {
      assertStructure(decoded, vector.structure.outer);
    }
    // What decodes re-encodes to the same bytes.
    assert.deepEqual(encodeEnvelope(decoded), vector.bytes);
  });

  test(`vector ${vector.name}: a changed payload byte is refused as an id mismatch`, () => {
    const bytes = Buffer.from(vector.bytes);
    bytes[bytes.length - 1] ^= 0xff;
    assert.throws(() => decodeEnvelope(bytes), (err) => {
      assert.equal(err.code, ErrorCode.EnvelopeIdMismatch);
      assert.match(err.message, /states id [0-9a-f]{32} but its content's id is [0-9a-f]{32}/);
      return true;
    });
  });
}

for (const vector of vectors.filter((v) => v.name.startsWith('pulse-'))) {
  test(`vector ${vector.name}: Pulse.fromBytes reads its fields and toBytes writes it back`, () => {
    const inputs = vector.inputs;
    assert.equal(vector.bytes.length, PULSE_WIRE_SIZE);
    const pulse = Pulse.fromBytes(vector.bytes);
    assert.equal(pulse.instruction, Instruction.Heartbeat);
    assert.match(inputs.instruction, /\(0x0001\)/);
    assert.equal(pulse.scope, hexNumber(inputs.scope_hex));
    assert.equal(pulse.monotonicNanos, exactInteger(vector, 'monotonic_nanos'));
    assert.equal(pulse.chainStep, exactInteger(vector, 'chain_step'));
    assert.equal(pulse.originId.toString('hex'), inputs.origin_id_hex);
    assert.equal(pulse.envelopeRef.toString('hex'), inputs.envelope_ref_hex);
    assert.equal(pulse.hasEnvelope(), false);
    assert.equal(pulse.storeCursor, null);
    assert.equal(pulse.toBytes().toString('hex'), vector.expected.canonical_hex);
  });
}

// ─────────────────── Agreement with the pure-JS codec ───────────────────

const samples = [
  { envelopeType: 0x0001, payload: Buffer.from([0x42, 0x42, 0x42, 0x42]) },
  { envelopeType: 0, typeName: 'pulse/channel', payload: Buffer.alloc(0) },
  {
    envelopeType: 0x0042,
    typeName: 'api/inference',
    payload: Buffer.from('hello cross-language', 'utf8'),
    origin: Buffer.alloc(16, 0xab),
    monotonicNanos: 1234567890n,
    flags: 0b0101,
  },
  { envelopeType: 0xffff, typeName: 'ünïcødé/名前', payload: Buffer.alloc(1000, 7), monotonicNanos: 2n ** 64n - 1n },
  { envelopeType: 0x0050, payload: [] },
  {
    envelopeType: 0x0050,
    typeName: 'batch',
    payload: [
      { envelopeType: 0x0050, payload: [{ envelopeType: 1, payload: Buffer.from('leaf') }] },
      { envelopeType: 2, typeName: 'sibling', payload: Buffer.from('sib'), origin: Buffer.alloc(16, 1), flags: 1 },
    ],
  },
];

for (const [i, sample] of samples.entries()) {
  test(`sample ${i}: the binding and the pure-JS codec write the same bytes and read each other's`, () => {
    const ours = encodeEnvelope(sample);
    const theirs = js.encodeEnvelope(toJs(sample));
    assert.equal(ours.toString('hex'), theirs.toString('hex'));
    assert.equal(envelopeId(sample).toString('hex'), theirs.subarray(0, 16).toString('hex'));

    const decoded = decodeEnvelope(theirs);
    assert.equal(decoded.envelopeType, sample.envelopeType);
    assert.equal(decoded.typeName, sample.typeName ?? null);
    assert.deepEqual(decoded.origin, sample.origin ?? Buffer.alloc(16));
    assert.equal(decoded.monotonicNanos, sample.monotonicNanos ?? 0n);
    assert.equal(decoded.flags, sample.flags ?? 0);
    assert.deepEqual(encodeEnvelope(decoded), theirs);

    const { env, nextOffset } = js.decodeEnvelopeAt(ours, 0);
    assert.equal(nextOffset, ours.length);
    assert.equal(Buffer.from(env.id).toString('hex'), decoded.id.toString('hex'));
  });
}

test('the id hashes the content, not the origin, clock or flags', () => {
  const content = { envelopeType: 9, typeName: 'x', payload: Buffer.from('same') };
  const id = envelopeId(content);
  assert.equal(id.length, 16);
  assert.deepEqual(envelopeId({ ...content, origin: Buffer.alloc(16, 5), monotonicNanos: 77n, flags: 8 }), id);
  assert.notDeepEqual(envelopeId({ ...content, typeName: 'y' }), id);
  assert.notDeepEqual(envelopeId({ ...content, typeName: null }), id);
  assert.notDeepEqual(envelopeId({ ...content, envelopeType: 10 }), id);
  // A raw payload of four zero bytes is not an empty nested one.
  assert.notDeepEqual(
    envelopeId({ envelopeType: 1, payload: Buffer.alloc(4) }),
    envelopeId({ envelopeType: 1, payload: [] }),
  );
});

// ─────────────────────────────── Refusals ───────────────────────────────

test('encodeEnvelope refuses a description that is not an envelope', () => {
  const bad = [
    [{ payload: Buffer.alloc(1) }, /envelopeType must be a number/],
    [{ envelopeType: 65536, payload: Buffer.alloc(1) }, /envelopeType must be an integer from 0 to 65535/],
    [{ envelopeType: -1, payload: Buffer.alloc(1) }, /envelopeType must be an integer/],
    [{ envelopeType: 1.5, payload: Buffer.alloc(1) }, /envelopeType must be an integer/],
    [{ envelopeType: 1 }, /payload must be a Buffer/],
    [{ envelopeType: 1, payload: 'text' }, /payload must be a Buffer/],
    [{ envelopeType: 1, payload: [Buffer.alloc(1)] }, /nested payload element 0 must be an envelope object/],
    [{ envelopeType: 1, payload: [{ envelopeType: 1 }] }, /payload must be a Buffer/],
    [{ envelopeType: 1, typeName: 5, payload: Buffer.alloc(1) }, /typeName must be a string/],
    [{ envelopeType: 1, payload: Buffer.alloc(1), origin: Buffer.alloc(15) }, /origin must be exactly 16 bytes/],
    [{ envelopeType: 1, payload: Buffer.alloc(1), monotonicNanos: 5 }, /monotonicNanos must be a BigInt/],
    [{ envelopeType: 1, payload: Buffer.alloc(1), monotonicNanos: -5n }, /monotonicNanos must be a BigInt from 0/],
    [{ envelopeType: 1, payload: Buffer.alloc(1), flags: 16 }, /flags must be an integer of the defined bits/],
  ];
  for (const [env, message] of bad) {
    assert.throws(() => encodeEnvelope(env), (err) => {
      assert.equal(err.code, ErrorCode.InvalidArg);
      assert.match(err.message, message);
      return true;
    }, JSON.stringify(env, (_k, v) => (typeof v === 'bigint' ? `${v}n` : v)));
    assert.throws(() => envelopeId(env), message);
  }
});

test('encodeEnvelope refuses nesting deeper than the decoder reads', () => {
  const nest = (depth) => (depth === 0 ? { envelopeType: 1, payload: Buffer.alloc(0) } : { envelopeType: 2, payload: [nest(depth - 1)] });
  // 32 levels below the outermost decode; one more is refused both ways.
  assert.ok(decodeEnvelope(encodeEnvelope(nest(32))));
  assert.throws(() => encodeEnvelope(nest(33)), /nests deeper than 32 levels/);
});

test('decodeEnvelope refuses bytes that are not one canonical envelope', () => {
  const good = encodeEnvelope({ envelopeType: 1, payload: Buffer.from('ok') });
  const cases = [
    [good.subarray(0, 20), /buffer too small/],
    [good.subarray(0, good.length - 1), /truncated/],
    [Buffer.concat([good, Buffer.from([0])]), /after the envelope|trailing/i],
    [(() => { const b = Buffer.from(good); b[45] = 9; return b; })(), /variant tag/],
    [(() => { const b = Buffer.from(good); b[42] = 0x10; return b; })(), /flag/i],
  ];
  for (const [bytes, message] of cases) {
    assert.throws(() => decodeEnvelope(bytes), (err) => {
      assert.equal(err.code, ErrorCode.InvalidArg);
      assert.match(err.message, message);
      return true;
    });
  }
});

test('decodeEnvelope checks a nested child\'s id, not only the outermost', () => {
  // A parent whose id is computed over a child whose stated id is wrong:
  // the parent verifies, the child does not.
  const child = { envelopeType: 1, payload: { variant: 'Raw', bytes: Buffer.from('c') }, id: Buffer.alloc(16, 0xee) };
  const parent = { envelopeType: 2, payload: { variant: 'Nested', children: [child] } };
  const bytes = js.encodeEnvelope(parent);
  assert.throws(() => decodeEnvelope(bytes), (err) => {
    assert.equal(err.code, ErrorCode.EnvelopeIdMismatch);
    assert.match(err.message, /nested child 0 states id e{32}/);
    return true;
  });
});
