// SPDX-License-Identifier: LicenseRef-Proprietary
// A pure-JavaScript canonical PulseEnvelope codec, written from chapter 3 of
// the specification with Node's Buffer API and no use of the napi binding,
// so that the binding's codec (envelope.test.mjs) and the Rust and Python
// codecs (canonical_codec_cross_language.test.mjs) are checked against an
// implementation independent of all of them.
//
// Wire layout (must match
//   pulse/pulse-canon/src/envelope.rs::PulseEnvelope::write_canonical_into
//   bindings/python/tests/test_canonical_codec_cross_language.py):
//
//   | id:16 | origin:16 | mono_ns:u64 | et:u16 | flg:u16 |       (44 B fixed)
//   | tn?:u8 | tn_len:u32 | tn_bytes:tn_len |                    (1 + 4 + L if Some)
//   | variant:u8 | <variant data> |                              (variant-specific)
//
//   variant=0 (Raw):    | payload_len:u32 | payload_bytes:n |
//   variant=1 (Nested): | count:u32 | child_canonical_bytes... |
//
// All multi-byte fields are little-endian. The id is the first 16 bytes of
// BLAKE3 over the `pulse-envelope-id/v2` preimage
// (PulseEnvelopeId::compute_from_payload):
//
//   | "pulse-envelope-id/v2" | et:u16 | tn?:u8 | tn_len:u32 | tn_bytes |
//                                     | pv:u8 | pl_len:u32 | pl_bytes |
//
// where pl_bytes is the payload's bytes: a Raw payload verbatim, a Nested one
// `count:u32 ‖ child canonical bytes...`.
//
// Envelope shape: { envelopeType, payload, typeName?, origin?, monotonicNanos?, flags?, id? }
// Payload shape:  { variant: 'Raw', bytes: Buffer } | { variant: 'Nested', children: [envelope, ...] }

// @noble/hashes is a pure-JS hash library that includes BLAKE3. We use the
// npm package rather than a native binding for portability: the cross-
// language proof must hold without depending on platform-specific native
// hash bindings.
import { blake3 } from '@noble/hashes/blake3.js';

export const PAYLOAD_VARIANT_RAW = 0;
export const PAYLOAD_VARIANT_NESTED = 1;
export const CANONICAL_FIXED_HEADER = 44;
export const ENVELOPE_ID_DOMAIN_TAG = Buffer.from('pulse-envelope-id/v2', 'utf8');

function u16(value) {
  const b = Buffer.alloc(2);
  b.writeUInt16LE(value, 0);
  return b;
}

function u32(value) {
  const b = Buffer.alloc(4);
  b.writeUInt32LE(value, 0);
  return b;
}

/** Mirror of PayloadData::to_bytes — the payload part of the id's preimage. */
export function payloadToBytes(payload) {
  if (payload.variant === 'Raw') {
    return Buffer.from(payload.bytes);
  }
  if (payload.variant === 'Nested') {
    return Buffer.concat([u32(payload.children.length), ...payload.children.map(encodeEnvelope)]);
  }
  throw new Error(`unknown payload variant: ${payload.variant}`);
}

/** Reproduce PulseEnvelopeId::compute_from_payload. */
export function computeId(envelopeType, typeName, payload) {
  const variant = payload.variant === 'Raw' ? PAYLOAD_VARIANT_RAW : PAYLOAD_VARIANT_NESTED;
  const payloadBytes = payloadToBytes(payload);
  const parts = [ENVELOPE_ID_DOMAIN_TAG, u16(envelopeType)];
  if (typeName === null) {
    parts.push(Buffer.from([0]));
  } else {
    const name = Buffer.from(typeName, 'utf8');
    parts.push(Buffer.from([1]), u32(name.length), name);
  }
  parts.push(Buffer.from([variant]), u32(payloadBytes.length), payloadBytes);
  // @noble/hashes blake3 returns Uint8Array; truncate to 16 bytes.
  return Buffer.from(blake3(Buffer.concat(parts))).subarray(0, 16);
}

/** Encode a PulseEnvelope to its canonical wire bytes. */
export function encodeEnvelope(env) {
  const origin = env.origin ?? Buffer.alloc(16);
  if (origin.length !== 16) throw new Error('origin must be exactly 16 bytes');
  const monotonicNanos = BigInt(env.monotonicNanos ?? 0);
  const flags = env.flags ?? 0;
  const typeName = env.typeName ?? null;
  const id = env.id ?? computeId(env.envelopeType, typeName, env.payload);

  const mono = Buffer.alloc(8);
  mono.writeBigUInt64LE(monotonicNanos, 0);
  const parts = [Buffer.from(id), Buffer.from(origin), mono, u16(env.envelopeType), u16(flags)];

  if (typeName === null) {
    parts.push(Buffer.from([0]));
  } else {
    const name = Buffer.from(typeName, 'utf8');
    parts.push(Buffer.from([1]), u32(name.length), name);
  }

  if (env.payload.variant === 'Raw') {
    parts.push(Buffer.from([PAYLOAD_VARIANT_RAW]), u32(env.payload.bytes.length), Buffer.from(env.payload.bytes));
  } else if (env.payload.variant === 'Nested') {
    parts.push(Buffer.from([PAYLOAD_VARIANT_NESTED]), u32(env.payload.children.length));
    for (const child of env.payload.children) {
      parts.push(encodeEnvelope(child));
    }
  } else {
    throw new Error(`unknown payload variant: ${env.payload.variant}`);
  }

  return Buffer.concat(parts);
}

/** Decode the envelope at `start`; returns { env, nextOffset }. */
export function decodeEnvelopeAt(buf, start = 0) {
  const minSize = CANONICAL_FIXED_HEADER + 1 + 1 + 4;
  if (buf.length - start < minSize) {
    throw new Error(`buffer too small: ${buf.length - start} bytes from offset ${start}`);
  }

  const id = buf.subarray(start, start + 16);
  const origin = buf.subarray(start + 16, start + 32);
  const monotonicNanos = buf.readBigUInt64LE(start + 32);
  const envelopeType = buf.readUInt16LE(start + 40);
  const flags = buf.readUInt16LE(start + 42);

  let cursor = start + 44;
  const presence = buf[cursor];
  cursor += 1;
  let typeName = null;
  if (presence === 0) {
    // None
  } else if (presence === 1) {
    if (cursor + 4 > buf.length) throw new Error('truncated at type_name_len');
    const tnLen = buf.readUInt32LE(cursor);
    cursor += 4;
    if (cursor + tnLen > buf.length) throw new Error('truncated at type_name');
    typeName = buf.toString('utf8', cursor, cursor + tnLen);
    cursor += tnLen;
  } else {
    throw new Error(`invalid type_name presence tag: ${presence}`);
  }

  if (cursor + 1 > buf.length) throw new Error('truncated at payload_variant_tag');
  const variant = buf[cursor];
  cursor += 1;

  let payload;
  if (variant === PAYLOAD_VARIANT_RAW) {
    if (cursor + 4 > buf.length) throw new Error('truncated at payload_len');
    const payloadLen = buf.readUInt32LE(cursor);
    cursor += 4;
    if (cursor + payloadLen > buf.length) throw new Error('truncated at payload');
    payload = { variant: 'Raw', bytes: buf.subarray(cursor, cursor + payloadLen) };
    cursor += payloadLen;
  } else if (variant === PAYLOAD_VARIANT_NESTED) {
    if (cursor + 4 > buf.length) throw new Error('truncated at nested_count');
    const count = buf.readUInt32LE(cursor);
    cursor += 4;
    const children = [];
    for (let i = 0; i < count; i++) {
      try {
        const { env, nextOffset } = decodeEnvelopeAt(buf, cursor);
        children.push(env);
        cursor = nextOffset;
      } catch (e) {
        throw new Error(`nested child ${i} decode failed: ${e.message}`);
      }
    }
    payload = { variant: 'Nested', children };
  } else {
    throw new Error(`invalid payload variant tag: ${variant}`);
  }

  return {
    env: { id, origin, monotonicNanos, envelopeType, flags, typeName, payload },
    nextOffset: cursor,
  };
}
