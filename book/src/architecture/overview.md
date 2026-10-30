# Workspace Layout

<p class="pm-kind"><b>Reference</b> · the two tiers, the leaves beside them, and the repositories built on this one, for anyone finding their way around the tree</p>

This repository holds the bottom two tiers of the Pulse Mesh stack. A tier depends only on the tiers below it, and nothing here depends on anything outside the repository: a consumer that wants the wire codec alone depends on `pulse-canon` and pulls in neither the ring nor the transport.

| Tier | Path | What lives here |
|---|---|---|
| 0 — cornerstone | `pulse/` | `pulse-canon` (the Pulse atom + canonical envelope codec), `pulse-spec/` (the conformance test vectors, the lex root, and the generators that (re)produce them), and the vocabulary crates: `mesh-lex` (the Lexicon), `mesh-context` and `mesh-capability` (the context and capability registries) |
| 1 — engine | `core/` | reference SeqLock ring, envelope store, region map, backoff strategies, the transport trait, the reference UDP transport, the CRC32C integrity primitive, and `mesh-stage-registry`, the `register_stages!` macro every ring hub composes with |

Beside the tiers sit the leaves: they consume the tiers and are consumed by nothing.

| Path | What lives here |
|---|---|
| `tools/` | `pulse-cli`, the `pulse` command line (encode, decode, verify, send, receive, the loopback bench; see [Across a network](../examples/across-a-network.md)), and `gen-lex-root`, which regenerates `pulse/pulse-spec/lex-root.txt` |
| `examples/` | the three programs the book includes: hello-pulse, the UDP loopback ([Across a network](../examples/across-a-network.md)) and the embedded ring and store ([The ring inside your process](../workflows/ring-in-process.md)) |
| `bindings/` | the C, Python, Node and WebAssembly bindings over the codec and the UDP transport; not workspace members, each builds from its own directory ([Language bindings](../reference/bindings.md)) |
| `fuzz/` | the `cargo-fuzz` harness over the standard's parsers of untrusted bytes; not a workspace member: `cargo +nightly fuzz run <target> --fuzz-dir fuzz` runs one, and `just check-fuzz` builds them all |

## The repositories built on this one

Tiers 2 and 3 are two repositories that depend on this one, as a sibling checkout (`../pulse-mesh`) while developing and as a pinned tag at a release. [The daemon](/docs/daemon/architecture/overview.html) is tier 2 and the dev ring: `mesh-hub` and its port protocol, the hub runtime, the Rust client, and the `pms` tools. [The profiles](/docs/profiles/architecture/overview.html) are tier 3: the enterprise, HFT and robotics rings, each the same four crates (`core`, `functions`, `stages`, `hub`) composed through the `register_stages!` macro this repository holds. Neither adds anything below this repository; where a change here is needed for one of them, it is made here first.

## Deciding where new code goes

`CONTRIBUTING.md` frames this as a four-question test: does the code touch the canonical Pulse atom, touch the canonical envelope, cross a ring boundary, or sit on the hot path? Code that touches the atom or the envelope belongs in `pulse/`; a hot-path primitive every consumer may need belongs in `core/`; a stage that crosses a ring boundary belongs in a ring, in the profiles; anything that only uses the tiers (a tool, an example, a binding) is a leaf here. Record any non-obvious classification call as a new ADR under `decisions/` rather than only justifying it in the PR.
