// SPDX-License-Identifier: LicenseRef-Proprietary
// The reader channel.test.mjs forks: opens the channel named on its command
// line, receives the number of messages named with recvAsync, checks each
// is `[seq:u64_le, 'm' * (seq % 512)]` in order, then waits for the writer's
// close and reports to its parent over IPC.

import { Channel, ErrorCode } from '../index.js';

const [name, count] = process.argv.slice(2);
const n = Number(count);

const rx = Channel.open(name, 10_000);
let expected = 0;
let ok = true;
let why = '';
while (expected < n) {
  const frames = await rx.recvAsync(10_000);
  if (frames === null || frames.length !== 2) {
    ok = false;
    why = `message ${expected}: ${frames === null ? 'none came' : `${frames.length} frames`}`;
    break;
  }
  const seq = frames[0].readBigUInt64LE(0);
  if (seq !== BigInt(expected) || !frames[1].equals(Buffer.alloc(expected % 512, 'm'))) {
    ok = false;
    why = `message ${expected}: seq ${seq}, ${frames[1].length} bytes`;
    break;
  }
  expected += 1;
}

// Every message read: the writer's close ends the channel.
let closed = '';
try {
  await rx.recvAsync(10_000);
} catch (err) {
  closed = err.code === ErrorCode.ChannelClosed ? 'ChannelClosed' : `${err.code}: ${err.message}`;
}
rx.close();
process.send({ ok, why, count: expected, closed }, () => process.exit(0));
