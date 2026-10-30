// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
// Conformance smoke test for the wasm codec: every fixture under
// pulse/pulse-spec/test-vectors must reproduce byte-for-byte, and a
// tampered envelope must fail verification.  Run: node tests/smoke.mjs
import { existsSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import init, * as pw from '../pkg/pulse_wasm.js';

const here = dirname(fileURLToPath(import.meta.url));
// The vectors sit at the root of the tree this binding is in, however deep
// the binding sits (under peripheral/ in the integrated tree, at the top
// level in the standard's own repository).
const above = (rel) => {
  for (let dir = here; ; dir = dirname(dir)) {
    if (existsSync(join(dir, rel))) return join(dir, rel);
    if (dirname(dir) === dir) throw new Error(`${rel} not found above ${here}`);
  }
};
const vectors = above('pulse/pulse-spec/test-vectors');
await init({ module_or_path: readFileSync(join(here, '../pkg/pulse_wasm_bg.wasm')) });

let failed = 0;
const check = (label, ok, detail = '') => { console.log(`${ok ? 'ok  ' : 'FAIL'} ${label}${detail ? ' — ' + detail : ''}`); if (!ok) failed++; };

const cargo = readFileSync(join(here, '../Cargo.toml'), 'utf8');
const packageVersion = cargo.match(/^\[package\][^\[]*?^version = "([^"]+)"/m)?.[1];
check('version is the package version', pw.version() === packageVersion, `${pw.version()}, Cargo.toml says ${packageVersion}`);
for (const name of ['envelope-raw-known-good', 'envelope-nested-3-level', 'pulse-layout-known-good']) {
  const json = readFileSync(join(vectors, `${name}.json`), 'utf8');
  const hex = readFileSync(join(vectors, `${name}.hex`), 'utf8');
  const report = JSON.parse(pw.check_fixture(json, hex));
  check(`fixture ${name}`, report.ok, report.checks.filter(c => !c.ok).map(c => `${c.check}: expected ${c.expected} got ${c.actual}`).join('; ') || `${report.checks.length} checks`);
}
const raw = JSON.parse(readFileSync(join(vectors, 'envelope-raw-known-good.json'), 'utf8'));
check('envelope_id_hex matches fixture', pw.envelope_id_hex(1, undefined, Uint8Array.from([0x42, 0x42, 0x42, 0x42])) === raw.expected.id_hex);

const bytes = pw.envelope_encode(JSON.stringify({ type_name: 'demo/hello', payload_text: 'hello, pulse' }));
const decoded = JSON.parse(pw.envelope_decode(bytes));
check('typed envelope round-trips', decoded.effective_type_name === 'demo/hello' && decoded.verified === true && decoded.payload.variant === 'Raw', `${bytes.length} bytes, id ${decoded.id_hex}`);
const tampered = Uint8Array.from(bytes); tampered[tampered.length - 1] ^= 0x01;
check('tampered payload fails verify', pw.envelope_verify(tampered) === false);
const nested = JSON.parse(pw.envelope_describe(JSON.stringify({ envelope_type: '0x0040', nested: [{ envelope_type: '0x0020', nested: [{ envelope_type: '0x0010', payload_hex: 'aabbcc' }] }, { envelope_type: '0x0030', payload_hex: '1122' }] })));
const nestedFx = JSON.parse(readFileSync(join(vectors, 'envelope-nested-3-level.json'), 'utf8'));
check('nested description reproduces the fixture id', nested.id_hex === nestedFx.expected.id_hex && nested.canonical_size === nestedFx.expected.size_bytes, nested.id_hex);
const refuses = (f) => { try { f(); return false; } catch { return true; } };
check('a reserved flag bit is refused, not dropped', refuses(() => pw.envelope_encode(JSON.stringify({ envelope_type: 1, flags: 0x10 }))) && refuses(() => pw.envelope_describe(JSON.stringify({ envelope_type: 1, flags: '0x8001' }))) && !refuses(() => pw.envelope_encode(JSON.stringify({ envelope_type: 1, flags: 0x0f }))));
const reserved = Uint8Array.from(pw.envelope_encode(JSON.stringify({ envelope_type: 1, payload_hex: '42' }))); reserved[43] = 0x80;
check('decoding refuses a reserved flag bit', refuses(() => pw.envelope_decode(reserved)));
const pulseHex = readFileSync(join(vectors, 'pulse-layout-known-good.hex'), 'utf8').trim();
const pulse = JSON.parse(pw.pulse_decode(Uint8Array.from(pulseHex.match(/../g).map(b => parseInt(b, 16)))));
check('pulse_decode reads the heartbeat overlay', pulse.instruction_name === 'Heartbeat' && pulse.heartbeat?.uptime_ms === '1000' && pulse.heartbeat?.stage_count === 4, `${pulse.instruction_name}, scope ${pulse.scope_hex}`);
const layout = JSON.parse(pw.pulse_layout());
check('pulse_layout is 128 bytes / 64-aligned with 10 fields', layout.size === 128 && layout.align === 64 && layout.fields.length === 10);
check('node_id_from_name is 16 bytes hex', /^[0-9a-f]{32}$/.test(pw.node_id_from_name('demo')));
console.log(failed === 0 ? '\nall checks passed' : `\n${failed} check(s) FAILED`);
process.exit(failed === 0 ? 0 : 1);
