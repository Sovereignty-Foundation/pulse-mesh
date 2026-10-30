# Developer Onboarding

<p class="pm-kind"><b>Start here</b> · five minutes from a fresh checkout to a tree you know works, by hand</p>

Working with a coding agent? Start with [Onboard your agent](../start/onboard-your-agent.md): one prompt sets up all three repositories. This page is the same setup by hand.

## By hand

1. **Set up.** `rust-toolchain.toml` pins the Rust version, and `rustup` installs it on the first `cargo` command.
2. **See it work.**
   ```bash
   cargo install --path tools/pulse-cli --locked
   pulse version
   ```
   `pulse version` prints the version, the pinned toolchain and the identifier the codec computes for the reference test vector. When that identifier matches the one in the specification's fixtures, the codec you built agrees with the standard.
3. **Encode one envelope.** [Across a network](../examples/across-a-network.md) encodes one, decodes it, shows the check fail on one changed byte, and then sends Pulses over UDP.
4. **Prove the tree.** `scripts/gate.sh --quick` runs the per-commit checks; `scripts/gate.sh` runs the gate a change passes before it merges. A check whose tool is missing fails and prints the command that installs it.

From there, [The ring inside your process](../workflows/ring-in-process.md) puts the ring and the store inside one program.

## Before your first change

- `CONTRIBUTING.md` says what a contribution means during the beta, holds the table of every check the gate runs, and gives the four-question test for where new code goes, which [Workspace Layout](../architecture/overview.md) explains.
- `AGENTS.md` lists the rules every change keeps, for a person as much as for an agent: never edit a test vector to pass a test, `unsafe` only with a `// SAFETY:` comment, a doc comment on every public item, decision records added and never rewritten.
- The specification is normative, the rustdoc is the API contract, and the [Decision log](../explanation/decision-log.md) records why the non-obvious calls were made. This book explains and guides; where it and the code disagree, one of them is wrong.

## Where to read first

- `pulse/pulse-canon` and `core/pulse-wire-udp`: the two layouts, their codec, and the wire that carries them.
- `core/core-ring/src/lib.rs`, the SeqLock ring, and `core/core-store/src/lib.rs` beside it, the envelope store.
- `tools/pulse-cli/src/main.rs` and `src/ops/`: the `pulse` command line, the most concrete tour of what the standard does.
- `pulse/pulse-spec/test-vectors`: the bytes every implementation must reproduce; [chapter 8](../reference/spec/08-conformance.md) says how they are checked.
