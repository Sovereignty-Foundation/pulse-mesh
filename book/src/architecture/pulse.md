# Cornerstone: `pulse/`

<p class="pm-kind"><b>Reference</b> · the cornerstone tier, crate by crate</p>

This is the bottom of the four-tier stack: the canonical Pulse atom and envelope codec, plus the conformance artifacts that pin their wire format. See also the crate-level notes in `pulse/README.md`.

## `pulse-canon`

The canonical primitive crate, and it's intentionally minimal. It defines exactly three things:

- **`Pulse`** — the 128-byte, cache-aligned wire-format atom.
- **`PulseEnvelope`** — the variable-size canonical payload carrier.
- **`NodeId`** — the 16-byte node identifier.

Everything with more behavior — engine primitives, fabric primitives, domain surfaces — lives one or more tiers up: the engine in `core/`, and the fabric and the domain surfaces in the daemon and profiles repositories. If you find yourself wanting to add a helper function to `pulse-canon`, that's usually a signal it belongs in `core/` instead.

## `pulse-spec`

Not a Rust crate — a directory of conformance-spec artifacts, the tool that regenerates the vectors, and the root the tools under `peripheral/tools` regenerate:

- **`lex-root.txt`** — the published Merkle root over the canonical `mesh-lex` registry.
- **`test-vectors/`** — language-neutral conformance fixtures: a known-good 128-byte Pulse layout, a canonical Raw envelope, and a 3-level-deep Nested envelope. Any language implementation (Rust, the C/Python/Node bindings, a future port) can replay these to verify byte-for-byte compatibility with the reference codec.
- **`gen-lex-root`** (`tools/gen-lex-root`; a tool over the `mesh-lex` registry, so it lives with the tools rather than in tier 0) — regenerates `lex-root.txt` into the path given, `cargo run -p gen-lex-root -- pulse/pulse-spec/lex-root.txt`, by computing the BLAKE3 Merkle root over every `Boundary::Public` entry in the `mesh-lex` registry. Today that registry is empty, so the root reduces to the domain-separated empty sentinel `BLAKE3("mesh-lex/empty/v1")`.
- **`tools/gen-test-vectors`** — regenerates `test-vectors/`.

Regenerate both tools' output before treating a wire-format change as final. The wire format is the thing every downstream language binding depends on longest — a change here has the widest and longest-lived blast radius of anything in the workspace.
