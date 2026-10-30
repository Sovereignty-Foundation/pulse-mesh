// SPDX-License-Identifier: LicenseRef-Proprietary
// Receiver.recvAsync, which waits on a thread of the receiver's own and
// leaves the event loop running, and bindPair, a Sender and a Receiver on
// one UDP socket.

import test from 'node:test';
import assert from 'node:assert/strict';
import { setTimeout as sleep } from 'node:timers/promises';

import { ErrorCode, Instruction, Pulse, Receiver, Sender, bindPair } from '../index.js';

function dataPulse(scope = 0) {
  const p = new Pulse();
  p.instruction = Instruction.Data;
  p.scope = scope;
  return p;
}

function spinUpPair() {
  const recv = Receiver.bind('127.0.0.1:0');
  const sender = Sender.bind('127.0.0.1:0');
  sender.connect(recv.localAddr());
  return { sender, recv };
}

// ─────────────────────────────── recvAsync ───────────────────────────────

test('recvAsync — resolves with the frame, as recv returns it', async () => {
  const { sender, recv } = spinUpPair();
  const out = dataPulse(42);
  out.monotonicNanos = 7777n;
  sender.send(123n, out, Buffer.from('hello async', 'utf8'));

  const result = await recv.recvAsync(2000);
  assert.ok(result);
  assert.deepEqual(Object.keys(result).sort(), ['envelope', 'peer', 'pulseBytes', 'sendNs', 'seq']);
  assert.equal(result.envelope.toString('utf8'), 'hello async');
  assert.equal(result.seq, 0n);
  assert.equal(result.sendNs, 123n);
  assert.equal(result.peer, sender.localAddr());
  const got = Pulse.fromBytes(result.pulseBytes);
  assert.equal(got.scope, 42);
  assert.equal(got.monotonicNanos, 7777n);
});

test('recvAsync — the event loop runs while it waits: a setInterval timer keeps firing', async () => {
  const recv = Receiver.bind('127.0.0.1:0');
  let ticks = 0;
  const timer = setInterval(() => { ticks += 1; }, 10);
  try {
    const started = Date.now();
    const result = await recv.recvAsync(300);
    const waited = Date.now() - started;
    assert.equal(result, null, 'nothing was sent: the wait times out to null');
    assert.ok(waited >= 280, `waited ${waited} ms`);
    // A 10 ms timer over 300 ms: about 30 ticks; a blocked loop gives none.
    assert.ok(ticks >= 10, `${ticks} timer ticks while recvAsync waited`);
  } finally {
    clearInterval(timer);
  }
});

test('recvAsync — a frame sent while it waits, from a timer, resolves it', async () => {
  const { sender, recv } = spinUpPair();
  setTimeout(() => sender.send(1n, dataPulse(), Buffer.from('later')), 50);
  const result = await recv.recvAsync(5000);
  assert.equal(result.envelope.toString(), 'later');
});

test('recvAsync — without a timeout it waits as setReadTimeoutMs says', async () => {
  const recv = Receiver.bind('127.0.0.1:0');
  recv.setReadTimeoutMs(50);
  const started = Date.now();
  assert.equal(await recv.recvAsync(), null);
  assert.ok(Date.now() - started < 2000);
});

test('recvAsync(0) — takes a frame already queued and waits for none', async () => {
  const { sender, recv } = spinUpPair();
  assert.equal(await recv.recvAsync(0), null);
  sender.send(5n, dataPulse(), Buffer.from('queued'));
  await sleep(20);
  const result = await recv.recvAsync(0);
  assert.equal(result.envelope.toString(), 'queued');
});

test('recvAsync — receives asked for together settle in order, each with the next frame', async () => {
  const { sender, recv } = spinUpPair();
  const waits = [recv.recvAsync(2000), recv.recvAsync(2000), recv.recvAsync(2000)];
  for (let i = 0; i < 3; i++) {
    sender.send(BigInt(i), dataPulse(i), Buffer.from(`msg-${i}`));
  }
  const results = await Promise.all(waits);
  assert.deepEqual(results.map((r) => r.envelope.toString()), ['msg-0', 'msg-1', 'msg-2']);
  assert.deepEqual(results.map((r) => r.seq), [0n, 1n, 2n]);
});

test('recvAsync — the timeout counts from the call, not from when the wait starts', async () => {
  const recv = Receiver.bind('127.0.0.1:0');
  const started = Date.now();
  // The second waits behind the first; both time out at about 200 ms.
  const [a, b] = await Promise.all([recv.recvAsync(200), recv.recvAsync(200)]);
  assert.equal(a, null);
  assert.equal(b, null);
  const waited = Date.now() - started;
  assert.ok(waited < 380, `two 200 ms receives asked together took ${waited} ms`);
});

test('recv / recvInto — Busy while a recvAsync has not settled, usable once it has', async () => {
  const { sender, recv } = spinUpPair();
  const pending = recv.recvAsync(300);
  for (const call of [() => recv.recv(), () => recv.recvInto(Buffer.alloc(64))]) {
    assert.throws(call, (err) => {
      assert.equal(err.code, ErrorCode.Busy);
      assert.match(err.message, /recvAsync on this Receiver has not settled/);
      return true;
    });
  }
  // The receiver's accessors do not wait for the receive in progress.
  assert.match(recv.localAddr(), /^127\.0\.0\.1:\d+$/);
  recv.setReadTimeoutMs(1000);
  assert.equal(await pending, null);

  // Settled: the synchronous receive works again, with its own timeout.
  sender.send(9n, dataPulse(), Buffer.from('sync again'));
  assert.equal(recv.recv().envelope.toString(), 'sync again');
});

test('recvAsync — a frame that does not decode rejects, as recv throws', async () => {
  const recv = Receiver.bind('127.0.0.1:0');
  const { createSocket } = await import('node:dgram');
  const raw = createSocket('udp4');
  const [host, port] = recv.localAddr().split(':');
  await new Promise((resolve, reject) => raw.send(Buffer.from('not a pulse-wire frame'), Number(port), host, (e) => (e ? reject(e) : resolve())));
  raw.close();
  await assert.rejects(recv.recvAsync(2000), (err) => {
    assert.equal(err.code, ErrorCode.InvalidArg);
    assert.match(err.message, /decode/);
    return true;
  });
});

test('setReadTimeoutMs(0) is refused: 0 is no timeout the socket can have', () => {
  const recv = Receiver.bind('127.0.0.1:0');
  assert.throws(() => recv.setReadTimeoutMs(0), /at least 1 ms/);
  recv.setReadTimeoutMs(null);
  recv.setReadTimeoutMs();
});

// ─────────────────────────────── bindPair ───────────────────────────────

test('bindPair — the sender and the receiver share one port', () => {
  const { sender, receiver } = bindPair('127.0.0.1:0');
  assert.ok(sender instanceof Sender);
  assert.ok(receiver instanceof Receiver);
  assert.equal(sender.localAddr(), receiver.localAddr());
});

test('bindPair — a reply to the observed source comes back to the requester', async () => {
  // A requester and a responder, each on one socket.
  const req = bindPair('127.0.0.1:0');
  const resp = bindPair('127.0.0.1:0');
  req.receiver.setReadTimeoutMs(2000);
  resp.receiver.setReadTimeoutMs(2000);

  req.sender.sendTo(1n, dataPulse(), Buffer.from('ping'), resp.receiver.localAddr());
  const request = resp.receiver.recv();
  assert.equal(request.envelope.toString(), 'ping');
  // The request came from the requester's one port.
  assert.equal(request.peer, req.receiver.localAddr());

  // The responder answers the address it saw, from its own one port.
  resp.sender.sendTo(2n, dataPulse(), Buffer.from('pong'), request.peer);
  const reply = await req.receiver.recvAsync(2000);
  assert.equal(reply.envelope.toString(), 'pong');
  assert.equal(reply.peer, resp.receiver.localAddr());
});

test('bindPair — an address that cannot be bound throws', () => {
  assert.throws(() => bindPair('not-an-address'), /address|invalid|resolve|known/i);
});
