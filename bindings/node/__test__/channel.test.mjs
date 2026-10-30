// SPDX-License-Identifier: LicenseRef-Proprietary
// Channel: messages over the shared-memory ring and envelope store, in one
// process and between this process and a forked child.
//
// Each test uses a fresh, short channel name (the store's name, the
// channel's plus "-e", must fit macOS's 31-byte shared-memory name limit).

import test from 'node:test';
import assert from 'node:assert/strict';
import { fork } from 'node:child_process';
import { fileURLToPath } from 'node:url';

import { Channel, ErrorCode } from '../index.js';

let made = 0;
function freshName() {
  made += 1;
  // "/pwn" + pid + a per-test counter: well under 29 bytes.
  return `pwn${process.pid % 100000}-${made}`;
}

function frames(...texts) {
  return texts.map((t) => Buffer.from(t));
}

function u64(n) {
  const b = Buffer.alloc(8);
  b.writeBigUInt64LE(BigInt(n), 0);
  return b;
}

function hasCode(code, message) {
  return (err) => {
    assert.equal(err.code, code, `code of: ${err.message}`);
    if (message) assert.match(err.message, message);
    return true;
  };
}

test('round trip — multi-frame, empty and single-Buffer messages, in order', () => {
  const name = freshName();
  const tx = Channel.create(name, 64, 16);
  const rx = Channel.open(name);
  try {
    assert.equal(tx.isWriter, true);
    assert.equal(rx.isWriter, false);
    assert.equal(tx.name, `/${name}`);
    assert.equal(tx.capacity, 64);
    assert.equal(tx.storeSlots, 16);
    const messages = [
      [Buffer.from('header'), Buffer.alloc(0), Buffer.alloc(200, 0xff)],
      frames('one'),
      [],
    ];
    for (const message of messages) tx.send(message);
    tx.send(Buffer.from('single buffer'));
    assert.equal(tx.pending, 4);
    for (const message of messages) assert.deepEqual(rx.recv(1000), message);
    assert.deepEqual(rx.recv(1000), frames('single buffer'));
    assert.equal(rx.recv(0), null);
    assert.equal(tx.pending, 0);
  } finally {
    rx.close();
    tx.close();
  }
});

test('recvAsync — resolves with the message, and with null on timeout', async () => {
  const name = freshName();
  const tx = Channel.create(name, 8, 8);
  const rx = Channel.open(name);
  try {
    tx.send(frames('a', 'bc'));
    assert.deepEqual(await rx.recvAsync(1000), frames('a', 'bc'));
    assert.equal(await rx.recvAsync(50), null);
    // Sent while it waits, from a timer: the event loop is free.
    setTimeout(() => tx.send(frames('later')), 30);
    assert.deepEqual(await rx.recvAsync(5000), frames('later'));
  } finally {
    rx.close();
    tx.close();
  }
});

test('recvAsync — the event loop runs while it waits: a setInterval timer keeps firing', async () => {
  const name = freshName();
  const tx = Channel.create(name, 8, 8);
  const rx = Channel.open(name);
  let ticks = 0;
  const timer = setInterval(() => { ticks += 1; }, 10);
  try {
    const started = Date.now();
    assert.equal(await rx.recvAsync(300), null);
    const waited = Date.now() - started;
    assert.ok(waited >= 280, `waited ${waited} ms`);
    assert.ok(ticks >= 10, `${ticks} timer ticks while recvAsync waited`);
  } finally {
    clearInterval(timer);
    rx.close();
    tx.close();
  }
});

test('recvAsync — receives asked for together settle in order', async () => {
  const name = freshName();
  const tx = Channel.create(name, 16, 16);
  const rx = Channel.open(name);
  try {
    const waits = [0, 1, 2, 3].map(() => rx.recvAsync(2000));
    for (let i = 0; i < 4; i++) tx.send([u64(i)]);
    const got = await Promise.all(waits);
    assert.deepEqual(got.map((m) => m[0].readBigUInt64LE(0)), [0n, 1n, 2n, 3n]);
  } finally {
    rx.close();
    tx.close();
  }
});

test('recv — Busy while a recvAsync has not settled; accessors still answer', async () => {
  const name = freshName();
  const tx = Channel.create(name, 8, 8);
  const rx = Channel.open(name);
  try {
    const waiting = rx.recvAsync(300);
    assert.throws(() => rx.recv(0), hasCode(ErrorCode.Busy, /recvAsync on this Channel has not settled/));
    // A look at the ring holds the lock only briefly: these do not wait.
    const started = Date.now();
    assert.equal(rx.pending, 0);
    assert.equal(rx.name, `/${name}`);
    assert.equal(rx.closed, false);
    assert.ok(Date.now() - started < 100);
    assert.equal(await waiting, null);
    tx.send(frames('sync'));
    assert.deepEqual(rx.recv(1000), frames('sync'));
  } finally {
    rx.close();
    tx.close();
  }
});

test('maxPayload — the largest message fits; one byte more is EnvelopeTooLarge', async () => {
  const name = freshName();
  // One frame: 4 for the count + 4 for its length.
  const biggest = Channel.maxPayload() - 8;
  assert.equal(Channel.maxPayload(), 65536 - 67);
  const tx = Channel.create(name, 8, 8);
  const rx = Channel.open(name);
  try {
    tx.send([Buffer.alloc(biggest, 0x78)]);
    assert.deepEqual(await rx.recvAsync(1000), [Buffer.alloc(biggest, 0x78)]);
    assert.throws(() => tx.send([Buffer.alloc(biggest + 1)]), hasCode(ErrorCode.EnvelopeTooLarge, /64 KB/));
    assert.throws(() => tx.send([Buffer.alloc(40_000), Buffer.alloc(40_000)]), hasCode(ErrorCode.EnvelopeTooLarge));
    // Nothing was sent.
    assert.equal(tx.pending, 0);
    assert.equal(rx.recv(50), null);
    tx.send(frames('after'));
    assert.deepEqual(rx.recv(1000), frames('after'));
  } finally {
    rx.close();
    tx.close();
  }
});

test('recv — waits its timeout, then null', () => {
  const name = freshName();
  const tx = Channel.create(name);
  const rx = Channel.open(name);
  try {
    const started = Date.now();
    assert.equal(rx.recv(200), null);
    const waited = Date.now() - started;
    assert.ok(waited >= 190 && waited < 1000, `waited ${waited} ms`);
  } finally {
    rx.close();
    tx.close();
  }
});

test('names — too long, or with a slash, is InvalidArg; 28 bytes fits', () => {
  assert.throws(() => Channel.create('x'.repeat(29)), hasCode(ErrorCode.InvalidArg, /too long/));
  assert.throws(() => Channel.open('/' + 'x'.repeat(29), 0), hasCode(ErrorCode.InvalidArg, /too long/));
  assert.throws(() => Channel.create('a/b'), hasCode(ErrorCode.InvalidArg, /no '\/'/));
  assert.throws(() => Channel.create(''), hasCode(ErrorCode.InvalidArg));
  assert.throws(() => Channel.create(freshName(), 0, 8), hasCode(ErrorCode.InvalidArg, /must be positive/));
  const name = 'c'.repeat(22) + String(process.pid % 1000000).padStart(6, '0');
  const tx = Channel.create(name, 4, 1);
  try {
    assert.equal(tx.name, '/' + name);
  } finally {
    tx.close();
  }
});

test('open — a channel no writer created times out with Timeout', () => {
  assert.throws(() => Channel.open(freshName(), 50), hasCode(ErrorCode.Timeout, /found no channel/));
});

test('wrong end and closed end — InvalidArg', async () => {
  const name = freshName();
  const tx = Channel.create(name, 8, 8);
  const rx = Channel.open(name);
  assert.throws(() => rx.send(frames('no')), hasCode(ErrorCode.InvalidArg, /reader end/));
  assert.throws(() => tx.recv(0), hasCode(ErrorCode.InvalidArg, /writer end/));
  await assert.rejects(tx.recvAsync(0), hasCode(ErrorCode.InvalidArg, /writer end/));
  rx.close();
  rx.close();
  assert.equal(rx.closed, true);
  assert.throws(() => rx.recv(0), hasCode(ErrorCode.InvalidArg, /closed Channel/));
  assert.throws(() => rx.pending, hasCode(ErrorCode.InvalidArg, /closed Channel/));
  await assert.rejects(rx.recvAsync(0), hasCode(ErrorCode.InvalidArg, /closed Channel/));
  tx.close();
});

test('close — a recvAsync waiting on the end closed rejects', async () => {
  const name = freshName();
  const tx = Channel.create(name, 8, 8);
  const rx = Channel.open(name);
  const waiting = rx.recvAsync(5000);
  setTimeout(() => rx.close(), 30);
  const started = Date.now();
  await assert.rejects(waiting, hasCode(ErrorCode.InvalidArg, /closed before recvAsync took a message/));
  assert.ok(Date.now() - started < 1000);
  tx.close();
});

test("the writer's close — the reader drains what was sent, then ChannelClosed", async () => {
  const name = freshName();
  const tx = Channel.create(name, 8, 8);
  const rx = Channel.open(name);
  tx.send(frames('last'));
  tx.send(frames('really last'));
  tx.close();
  assert.deepEqual(rx.recv(1000), frames('last'));
  assert.deepEqual(await rx.recvAsync(1000), frames('really last'));
  assert.throws(() => rx.recv(1000), hasCode(ErrorCode.ChannelClosed, /every message was read/));
  await assert.rejects(rx.recvAsync(1000), hasCode(ErrorCode.ChannelClosed));
  rx.close();
  // The writer's close removed the names.
  assert.throws(() => Channel.open(name, 50), hasCode(ErrorCode.Timeout));
});

test('send — stalls without a reader, then Timeout with nothing sent', () => {
  const name = freshName();
  const tx = Channel.create(name, 4, 4);
  try {
    for (let i = 0; i < 4; i++) tx.send([Buffer.from([i])], 100);
    assert.equal(tx.pending, 4);
    assert.throws(() => tx.send(frames('full'), 50), hasCode(ErrorCode.Timeout, /Nothing was sent/));
    assert.equal(tx.pending, 4);
  } finally {
    tx.close();
  }
});

test('store window smaller than the ring — the store bounds the messages unread', () => {
  const name = freshName();
  const tx = Channel.create(name, 64, 4);
  const rx = Channel.open(name);
  try {
    for (let i = 0; i < 4; i++) tx.send([Buffer.from([i])], 100);
    assert.throws(() => tx.send(frames('over'), 50), hasCode(ErrorCode.Timeout));
    for (let i = 0; i < 4; i++) assert.deepEqual(rx.recv(1000), [Buffer.from([i])]);
    tx.send(frames('room'), 100);
    assert.deepEqual(rx.recv(1000), frames('room'));
  } finally {
    rx.close();
    tx.close();
  }
});

test('send — refuses frames that are not Buffers', () => {
  const name = freshName();
  const tx = Channel.create(name, 4, 4);
  try {
    assert.throws(() => tx.send(['text']));
    assert.throws(() => tx.send('text'));
    assert.equal(tx.pending, 0);
  } finally {
    tx.close();
  }
});

test('two processes — a forked reader receives every message in order', async () => {
  const name = freshName();
  const n = 5000;
  const tx = Channel.create(name, 256, 64);
  const child = fork(fileURLToPath(new URL('./channel_child.mjs', import.meta.url)), [name, String(n)], {
    stdio: ['ignore', 'inherit', 'inherit', 'ipc'],
  });
  const report = new Promise((resolve) => child.once('message', resolve));
  const exited = new Promise((resolve) => child.once('exit', (code, signal) => resolve({ code, signal })));
  try {
    for (let seq = 0; seq < n; seq++) {
      tx.send([u64(seq), Buffer.alloc(seq % 512, 'm')], 30_000);
    }
  } finally {
    // The child reads the rest, then sees the close as ChannelClosed.
    tx.close();
  }
  const { ok, why, count, closed } = await report;
  assert.ok(ok, why);
  assert.equal(count, n);
  assert.equal(closed, 'ChannelClosed');
  assert.deepEqual(await exited, { code: 0, signal: null });
});
