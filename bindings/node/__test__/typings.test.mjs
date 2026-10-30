// SPDX-License-Identifier: LicenseRef-Proprietary
// index.d.ts against the module: every name it declares as a runtime value
// is exported and every export is declared, each class's methods, statics
// and accessors are the module's, each enum's members are its values, and
// every type a declaration names is declared or built in. napi-rs writes
// index.d.ts from the Rust (`napi build`); this catches one left stale or
// edited by hand into disagreement.

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const binding = require('../index.js');
const dts = readFileSync(new URL('../index.d.ts', import.meta.url), 'utf8');

/** index.d.ts without its comments. */
const code = dts.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');

/** The top-level declarations: `{ kind, name, body }`. */
function declarations() {
  const found = [];
  const re = /^export (const enum|const|declare class|declare function|interface|type) (\w+)/gm;
  for (let m; (m = re.exec(code)); ) {
    let body = '';
    if (m[1] === 'const enum' || m[1] === 'declare class' || m[1] === 'interface') {
      const open = code.indexOf('{', m.index);
      const close = code.indexOf('\n}', open);
      body = code.slice(open + 1, close);
    }
    found.push({ kind: m[1], name: m[2], body });
  }
  return found;
}

const declared = declarations();
const values = declared.filter((d) => ['const enum', 'const', 'declare class', 'declare function'].includes(d.kind));

test('index.d.ts declares exactly the runtime exports', () => {
  const declaredNames = values.map((d) => d.name).sort();
  const exported = Object.keys(binding).sort();
  assert.deepEqual(declaredNames, exported);
  for (const d of values) {
    const actual = typeof binding[d.name];
    const expected = { const: ['number', 'string', 'bigint'], 'const enum': ['object'], 'declare class': ['function'], 'declare function': ['function'] }[d.kind];
    assert.ok(expected.includes(actual), `${d.name} is declared a ${d.kind} but is a ${actual}`);
  }
});

test('each declared class has the runtime methods, statics and accessors, and no others', () => {
  for (const d of values.filter((v) => v.kind === 'declare class')) {
    const members = { methods: new Set(), statics: new Set(), getters: new Set(), setters: new Set() };
    for (const line of d.body.split('\n')) {
      const m = line.match(/^ {2}(static |get |set )?(\w+)\s*\(/);
      if (!m || m[2] === 'constructor') continue;
      const kind = { 'static ': 'statics', 'get ': 'getters', 'set ': 'setters' }[m[1] ?? ''] ?? 'methods';
      members[kind].add(m[2]);
    }

    const Class = binding[d.name];
    const runtime = { methods: new Set(), statics: new Set(), getters: new Set(), setters: new Set() };
    for (const [key, desc] of Object.entries(Object.getOwnPropertyDescriptors(Class.prototype))) {
      if (key === 'constructor') continue;
      if (typeof desc.value === 'function') runtime.methods.add(key);
      if (desc.get) runtime.getters.add(key);
      if (desc.set) runtime.setters.add(key);
    }
    // A function's own built-ins, not statics. Node 24 and earlier also give
    // a native class `arguments` and `caller`; Node 25 does not.
    for (const key of Object.getOwnPropertyNames(Class)) {
      if (['length', 'name', 'prototype', 'arguments', 'caller'].includes(key)) continue;
      runtime.statics.add(key);
    }

    for (const kind of Object.keys(members)) {
      assert.deepEqual([...members[kind]].sort(), [...runtime[kind]].sort(), `${d.name} ${kind}`);
    }
  }
});

test('each declared enum has the runtime members and values', () => {
  for (const d of values.filter((v) => v.kind === 'const enum')) {
    const members = {};
    for (const m of d.body.matchAll(/^\s*(\w+) = ('[^']*'|-?\d+)/gm)) {
      members[m[1]] = m[2].startsWith("'") ? m[2].slice(1, -1) : Number(m[2]);
    }
    assert.deepEqual(members, { ...binding[d.name] }, d.name);
  }
});

test('every type the declarations name is declared or built in', () => {
  const builtIn = new Set(['Buffer', 'Promise', 'Array', 'Uint8Array']);
  const known = new Set(declared.map((d) => d.name));
  const named = new Set();
  for (const m of code.matchAll(/:\s*([^\n=]+)/g)) {
    for (const t of m[1].matchAll(/\b([A-Z]\w*)\b/g)) named.add(t[1]);
  }
  const unknown = [...named].filter((t) => !builtIn.has(t) && !known.has(t));
  assert.deepEqual(unknown, [], 'types named but never declared');
});

test('the asynchronous receives are declared to return promises', () => {
  const receiver = values.find((d) => d.name === 'Receiver').body;
  const channel = values.find((d) => d.name === 'Channel').body;
  assert.match(receiver, /recvAsync\(timeoutMs\?: number \| undefined \| null\): Promise<RecvResult \| null>/);
  assert.match(channel, /recvAsync\(timeoutMs\?: number \| undefined \| null\): Promise<Buffer\[\] \| null>/);
});
