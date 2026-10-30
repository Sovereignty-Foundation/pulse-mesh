# Working in this repository

This file is for a coding agent opening the Pulse Mesh standard for the first time, and for the person working with it. Read it whole before changing anything; it is short so that you can.

## What this repository is

The Pulse Mesh standard: the 128-byte Pulse and the PulseEnvelope that carries it, their canonical codec and the conformance vectors that pin their bytes, the SeqLock ring and envelope store that move Pulses through shared memory, the UDP transport that moves them between machines, the `pulse` command line, three examples and the C, Python, Node and WebAssembly bindings. It depends on nothing outside itself. Two repositories build on it as a sibling checkout at `../pulse-mesh`: `pulse-mesh-daemon` (the `mesh-hub` daemon and its client) and `pulse-mesh-profiles` (the enterprise, HFT and robotics rings).

## Set up

- Rust: `rust-toolchain.toml` pins the version, and `rustup` installs it on the first `cargo` command.
- The gate also uses `cargo-deny`, `mdbook` and `python3`. A check whose tool is missing fails and prints the command that installs it, so install what it names and run it again.
- `just` is optional: every recipe in `justfile` is a thin wrapper, and `scripts/gate.sh` runs the gate without it.

## Prove the tree works, in this order

1. `cargo run --release -p pulse-cli -- version` prints the toolchain and the codec's test-vector identifier.
2. `scripts/gate.sh --quick` runs the per-commit checks.
3. `scripts/gate.sh` runs the gate a change passes before it merges. `--full` adds the bindings, the fuzz build and the Linux and x86 legs.

The gate prints one line per check and a summary, and writes each check's output to `target/gate/<check>.log`. A change is done when the gate passes, not when the tests you chose pass.

## Map

| Path | What it holds |
|---|---|
| `pulse/pulse-canon` | The Pulse, the PulseEnvelope and their canonical codec |
| `pulse/pulse-spec/test-vectors` | The bytes every implementation must reproduce |
| `pulse/mesh-lex`, `mesh-context`, `mesh-capability` | The vocabulary crates |
| `core/core-ring`, `core-store`, `core-region` | The SeqLock ring, the envelope store and the single-slot region |
| `core/pulse-wire-udp` | The UDP transport |
| `core/mesh-stage-registry` | `register_stages!`, the macro every ring's hub composes with |
| `tools/pulse-cli` | The `pulse` command line, the quickest tour of what the standard does |
| `examples/` | The three programs the tutorials include |
| `bindings/`, `fuzz/` | Not workspace members; each builds from its own directory |
| `book/` | Tutorials, guides, the specification, reference and explanation; rendered at <https://pulse-mesh.net/docs/>, every page listed in <https://pulse-mesh.net/llms.txt> |
| `decisions/` | The architectural decision records |

## What is true, in order of authority

1. The specification, `book/src/reference/spec/`. A MUST there is normative.
2. The test vectors in `pulse/pulse-spec/test-vectors`.
3. The rustdoc, the API contract: `cargo doc --workspace --no-deps --open`.
4. The decision records in `decisions/`, for why a call was made.
5. The rest of the book, which explains and guides.

When two of them disagree, one is wrong. Report it; do not pick the one that suits the change.

## Rules that hold for every change

- Never edit a test vector, or a layout constant, to make a test pass. A change to either is a change to the specification and needs a new decision record.
- `unsafe` is allowed only with a `// SAFETY:` comment on the block. A crate with no `unsafe` forbids it at its root, and keeps doing so.
- Every public item carries a doc comment, and the gate treats warnings as errors.
- A crate marked `status = "partial"` returns deferred errors on purpose (ADR-0017). Leave the label until the feature works; never make a deferred path look implemented.
- Decision records are append-only: add a record, never rewrite an accepted one.
- No measured figures in docs, comments or read-mes. A guide gives the command; the reader measures on their own machine.
- No links to a source-code host or server. Book pages link to each other relatively; links that leave the repository go to `https://pulse-mesh.net/docs/`. `scripts/docs/check-hosts.py` enforces this in the gate.
- Leave `LICENSE`, `STATUS.md`, the notices and the file headers exactly as they are.

## Making a change

Follow `CONTRIBUTING.md`: its gate table is the list of checks, and its four-question test says where new code goes. Code contributions are closed until the Proving Grounds' full launch, expected in the fourth quarter of 2026, and are then routed through it, so for now a change you make is for the person you work with, and for a report of what did not hold. Put tests beside the code they cover. If the change is visible to someone using the standard, update the book page that describes it in the same change. If you made a call a later contributor would have to reverse-engineer, add a decision record. Then run the gate.

## Where to look

| Question | Read |
|---|---|
| What are the bytes of a Pulse or an envelope? | Spec chapters 2 and 3 |
| How does the ring keep a reader from a torn write? | Spec chapter 4, then `core/core-ring/src/lib.rs` |
| How does a Pulse cross a network? | Spec chapter 6, then `core/pulse-wire-udp` |
| How does another language prove it conforms? | Spec chapter 8 and the guide *Write a language binding* |
| Why is it shaped this way? | `book/src/explanation/` and `decisions/` |
| What does an error mean? | `book/src/reference/errors.md` |

## Reporting back

When you hand work back, say what changed and why, paste the gate's summary line, and name anything you skipped or could not run.
