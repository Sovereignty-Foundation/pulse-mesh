// SPDX-License-Identifier: LicenseRef-Proprietary
// The specification's conformance vectors (pulse/pulse-spec/test-vectors/),
// found by walking up from this directory, so the tests find them in the
// integrated tree (bindings/node) and in a repository cut from it
// (bindings/node).

import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

function vectorsDir() {
  let dir = dirname(fileURLToPath(import.meta.url));
  for (;;) {
    const candidate = join(dir, 'pulse', 'pulse-spec', 'test-vectors');
    if (existsSync(candidate)) return candidate;
    const parent = dirname(dir);
    if (parent === dir) {
      throw new Error('pulse/pulse-spec/test-vectors not found above ' + dirname(fileURLToPath(import.meta.url)));
    }
    dir = parent;
  }
}

/**
 * Every vector: its JSON, with `bytes` the canonical bytes its `.hex`
 * sibling holds (checked to be the JSON's own `canonical_hex`).
 */
export function loadVectors() {
  const dir = vectorsDir();
  return readdirSync(dir)
    .filter((file) => file.endsWith('.json'))
    .sort()
    .map((file) => {
      const text = readFileSync(join(dir, file), 'utf8');
      const vector = JSON.parse(text);
      const hex = readFileSync(join(dir, file.replace(/\.json$/, '.hex')), 'utf8').trim();
      if (hex !== vector.expected.canonical_hex) {
        throw new Error(`${file}: the .hex file is not the JSON's canonical_hex`);
      }
      return { file, text, ...vector, bytes: Buffer.from(hex, 'hex') };
    });
}

/** A `"0x0040"`-style hex number from a vector. */
export function hexNumber(text) {
  return Number.parseInt(text, 16);
}

/**
 * The integer `key` holds in a vector's JSON, as a BigInt read from the text:
 * `JSON.parse` rounds one past 2^53 to the nearest double.
 */
export function exactInteger(vector, key) {
  const match = vector.text.match(new RegExp(`"${key}":\\s*(\\d+)`));
  if (!match) throw new Error(`${vector.file}: no integer "${key}"`);
  return BigInt(match[1]);
}
