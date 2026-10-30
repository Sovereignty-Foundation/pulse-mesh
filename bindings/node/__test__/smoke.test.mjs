// SPDX-License-Identifier: LicenseRef-Proprietary
// Node.js smoke tests for the pulse-wire bindings.
// Run via: npm test  (uses Node's built-in test runner; no Jest dep)

import test from 'node:test';
import assert from 'node:assert/strict';

import {
  PULSE_WIRE_SIZE,
  MAX_ENVELOPE,
  HEADER_BYTES,
  Instruction,
  Pulse,
  Sender,
  Receiver,
} from '../index.js';

// ──────────────────────── Module-level constants ────────────────────────

test('exported constants', () => {
  assert.equal(PULSE_WIRE_SIZE, 128);
  assert.equal(MAX_ENVELOPE, 1315);
  assert.equal(HEADER_BYTES, 153);
  assert.equal(Instruction.Null, 0);
  assert.equal(Instruction.Heartbeat, 1);
  assert.equal(Instruction.Data, 0x10);
});

// ──────────────────────────── Pulse class ───────────────────────────────

test('Pulse — zeroed defaults', () => {
  const p = new Pulse();
  assert.equal(p.instruction, Instruction.Null);
  assert.equal(p.scope, 0);
  assert.equal(p.monotonicNanos, 0n);
  assert.equal(p.chainStep, 0n);
  assert.equal(p.hasEnvelope(), false);
  assert.deepEqual([...p.originId], new Array(16).fill(0));
});

test('Pulse — field round-trip', () => {
  const p = new Pulse();
  p.instruction = Instruction.Data;
  p.scope = 0xdeadbeef;
  p.monotonicNanos = 12345678901234n;
  p.chainStep = 99n;
  p.originId = Buffer.from(new Uint8Array(16).fill(0x11));

  assert.equal(p.instruction, Instruction.Data);
  assert.equal(p.scope, 0xdeadbeef);
  assert.equal(p.monotonicNanos, 12345678901234n);
  assert.equal(p.chainStep, 99n);
  assert.deepEqual([...p.originId], new Array(16).fill(0x11));
});

test('Pulse — u64 fields refuse negative and oversized BigInts', () => {
  const p = new Pulse();
  p.monotonicNanos = 5n;
  assert.throws(() => { p.monotonicNanos = -5n; }, /monotonicNanos must be a BigInt from 0 to 2\^64 - 1/);
  assert.throws(() => { p.chainStep = 2n ** 64n; }, /chainStep must be a BigInt from 0 to 2\^64 - 1/);
  assert.equal(p.monotonicNanos, 5n, 'a refused value leaves the field as it was');
  p.chainStep = 2n ** 64n - 1n;
  assert.equal(p.chainStep, 2n ** 64n - 1n, 'the largest u64 still round-trips');
});

test('Pulse — bytes round-trip', () => {
  const p = new Pulse();
  p.instruction = Instruction.Data;
  p.scope = 7;
  p.monotonicNanos = 42n;

  const raw = p.toBytes();
  assert.equal(raw.length, 128);

  const p2 = Pulse.fromBytes(raw);
  assert.equal(p2.instruction, p.instruction);
  assert.equal(p2.scope, p.scope);
  assert.equal(p2.monotonicNanos, p.monotonicNanos);
  assert.deepEqual([...p2.toBytes()], [...raw]);
});

test('Pulse — fromBytes rejects wrong length', () => {
  assert.throws(() => Pulse.fromBytes(Buffer.alloc(64)), /128 bytes/);
});

test('Pulse — origin_id rejects wrong length', () => {
  const p = new Pulse();
  assert.throws(
    () => { p.originId = Buffer.alloc(8); },
    /16 bytes/,
  );
});

// ─────────────────────────── Loopback round-trip ────────────────────────

function spinUpPair() {
  const recv = Receiver.bind('127.0.0.1:0');
  recv.setReadTimeoutMs(2000);
  const sender = Sender.bind('127.0.0.1:0');
  sender.connect(recv.localAddr());
  return { sender, recv };
}

test('loopback — send + recv preserves all fields', () => {
  const { sender, recv } = spinUpPair();

  const out = new Pulse();
  out.instruction = Instruction.Data;
  out.scope = 42;
  out.monotonicNanos = 7777n;

  const payload = Buffer.from('hello from node smoke test', 'utf8');
  const seq = sender.send(BigInt(Date.now()) * 1_000_000n, out, payload);
  assert.equal(seq, 0n);

  const result = recv.recv();
  assert.equal(result.envelope.length, payload.length);
  assert.deepEqual([...result.envelope], [...payload]);
  assert.equal(result.seq, 0n);
  assert.equal(result.peer.startsWith('127.0.0.1:'), true);

  const got = Pulse.fromBytes(result.pulseBytes);
  assert.equal(got.scope, 42);
  assert.equal(got.monotonicNanos, 7777n);
});

test('loopback — send refuses a negative timestamp', () => {
  const { sender } = spinUpPair();
  assert.throws(() => sender.send(-1n, new Pulse(), Buffer.alloc(0)), /sendNs must be a BigInt from 0 to 2\^64 - 1/);
});

test('loopback — multiple sequential sends preserve seq order', () => {
  const { sender, recv } = spinUpPair();
  const N = 10;

  for (let i = 0; i < N; i++) {
    const p = new Pulse();
    p.instruction = Instruction.Data;
    p.scope = i;
    sender.send(BigInt(i), p, Buffer.from(`msg-${i}`, 'utf8'));
  }

  for (let i = 0; i < N; i++) {
    const r = recv.recv();
    assert.equal(r.seq, BigInt(i));
    assert.equal(Pulse.fromBytes(r.pulseBytes).scope, i);
    assert.equal(r.envelope.toString('utf8'), `msg-${i}`);
  }
});

// ──────────────────── recvInto: caller-owned buffer ────────────────────

test('recvInto — writes into caller buffer, no per-recv allocation', () => {
  const { sender, recv } = spinUpPair();
  const buf = Buffer.alloc(MAX_ENVELOPE);

  const N = 20;
  for (let i = 0; i < N; i++) {
    const p = new Pulse();
    p.instruction = Instruction.Data;
    p.scope = i;
    sender.send(BigInt(i), p, Buffer.from(`payload-${i}`, 'utf8'));
  }

  for (let i = 0; i < N; i++) {
    const meta = recv.recvInto(buf);
    assert.equal(meta.seq, BigInt(i));
    assert.equal(buf.subarray(0, meta.envLen).toString('utf8'), `payload-${i}`);
    assert.equal(Pulse.fromBytes(meta.pulseBytes).scope, i);
  }
});

test('recvInto — buffer too small throws', () => {
  const { sender, recv } = spinUpPair();
  const p = new Pulse();
  p.instruction = Instruction.Data;
  sender.send(0n, p, Buffer.alloc(200));

  const small = Buffer.alloc(50);
  assert.throws(() => recv.recvInto(small), /buffer too small|envelope buffer too small/);
});

// ───────────────────────────── Error paths ──────────────────────────────

test('recv — timeout surfaces as error containing "timeout"', () => {
  const recv = Receiver.bind('127.0.0.1:0');
  recv.setReadTimeoutMs(50);
  assert.throws(() => recv.recv(), /timeout/i);
});

test('Sender.bind — invalid address throws', () => {
  assert.throws(() => Sender.bind('not-an-address'), /address|invalid/i);
});

test('Sender.send — without connect throws', () => {
  const sender = Sender.bind('127.0.0.1:0');
  const p = new Pulse();
  // No connect(); should throw.
  assert.throws(
    () => sender.send(0n, p, Buffer.from('x')),
    /destination|connect/i,
  );
});

// ───────────────────────────── Static methods ───────────────────────────

test('static maxEnvelope — class-level access', () => {
  assert.equal(Sender.maxEnvelope(), MAX_ENVELOPE);
  assert.equal(Receiver.maxEnvelope(), MAX_ENVELOPE);
});

// ────────────────────────────── Diagnostic ─────────────────────────────

test('Sender — nextSeq / localAddr surface diagnostic info', () => {
  const sender = Sender.bind('127.0.0.1:0');
  const addr = sender.localAddr();
  assert.match(addr, /^127\.0\.0\.1:\d+$/);
  assert.equal(sender.nextSeq(), 0n);
});

// ───────────────── Class-argument type checking (SAF-67) ─────────────────
// send / sendTo take `pulse: &Pulse`. Under plain #[napi] napi-rs unwraps
// any wrapped object's native pointer as a Pulse: a Receiver passed here
// had its heap bytes (pointers included) sent on the wire, and a debug
// build aborted on the misaligned read. #[napi(strict)] makes napi-rs
// refuse a non-Pulse argument before it is unwrapped.

test('send — a Receiver where a Pulse belongs is refused, not unwrapped', () => {
  const { sender, recv } = spinUpPair();
  assert.throws(
    () => sender.send(1n, recv, Buffer.from('x')),
    /instanceof class .?Pulse/,
  );
  // The socket saw nothing: no frame was sent.
  assert.throws(() => recv.recv(), /timeout/i);
});

test('sendTo — a Receiver where a Pulse belongs is refused', () => {
  const sender = Sender.bind('127.0.0.1:0');
  const other = Receiver.bind('127.0.0.1:0');
  assert.throws(
    () => sender.sendTo(1n, other, Buffer.from('x'), other.localAddr()),
    /instanceof class .?Pulse/,
  );
});

test('send / sendTo — a plain object is refused', () => {
  const sender = Sender.bind('127.0.0.1:0');
  sender.connect('127.0.0.1:9');
  assert.throws(() => sender.send(1n, {}, Buffer.from('x')), /instanceof class .?Pulse/);
  assert.throws(
    () => sender.sendTo(1n, {}, Buffer.from('x'), '127.0.0.1:9'),
    /instanceof class .?Pulse/,
  );
});

test('send — a Sender passed as the Pulse is refused', () => {
  const { sender, recv } = spinUpPair();
  assert.throws(() => sender.send(1n, sender, Buffer.from('x')), /instanceof class .?Pulse/);
  assert.throws(() => recv.recv(), /timeout/i);
});

test('send — a real Pulse still works after the type check', () => {
  const { sender, recv } = spinUpPair();
  const p = new Pulse();
  p.scope = 5;
  sender.send(0n, p, Buffer.from('ok'));
  const r = recv.recv();
  assert.equal(r.envelope.toString('utf8'), 'ok');
  assert.equal(Pulse.fromBytes(r.pulseBytes).scope, 5);
});
