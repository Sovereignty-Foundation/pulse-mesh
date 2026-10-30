<div class="pm-hero">
  <img class="pm-logo pm-logo-light" src="images/sov-mark-black.svg" alt="Sovereignty Foundation Inc.">
  <img class="pm-logo pm-logo-dark" src="images/sov-mark-white.svg" alt="">
  <span class="pm-eyebrow">Sovereignty Foundation Inc. · The Pulse Mesh™ Book</span>
  <h1>Pulse <span class="pm-accent">Mesh</span><sup class="pm-tm">™</sup></h1>
  <p class="pm-sub">The standard: two byte layouts, the codec that pins them, the ring, the store and the wire that carry them, and the bindings that prove them in other languages.</p>
  <p class="pm-ident">Pulse Mesh Standard · working draft · reference implementation</p>
  <div class="pm-status">Nothing in this book is a release announcement. Licensing questions go to <a href="mailto:legal@sovfound.org">legal@sovfound.org</a>.</div>
  <div class="pm-cta-row">
    <a class="pm-cta pm-cta-primary" href="start/onboard-your-agent.html">Onboard your agent</a>
    <a class="pm-cta pm-cta-secondary" href="examples/across-a-network.html">Send Pulses across a network</a>
    <a class="pm-cta pm-cta-secondary" href="reference/README.html">Read the reference</a>
  </div>
</div>

Pulse Mesh™ is a transport substrate built on two byte layouts. The **Pulse** is a 128-byte control signal that occupies two cache lines and moves through a shared-memory ring without a lock. The **PulseEnvelope** carries anything larger, at any size, and is addressed by the 16-byte BLAKE3 hash of its canonical bytes, so the same content produces the same identifier in every language that implements the codec. Everything above the two layouts is layered: an implementer can take the codec alone, the codec with the reference ring, or a full domain ring with its composed surface.

This repository is the standard: the two layouts and their canonical codec, the conformance vectors that pin their bytes, the SeqLock ring, the envelope store and the single-slot region that move Pulses through shared memory, the UDP transport that moves them between machines, the vocabulary crates (the Lexicon, the context and capability registries), the composition macro the rings build with, the `pulse` command line, three examples, and the C, Python, Node and WebAssembly bindings. It depends on nothing outside itself. Two repositories build on it: [the daemon](/docs/daemon/introduction.html), a runner that routes envelopes between processes through a local port, and [the profiles](/docs/profiles/introduction.html), the enterprise, HFT and robotics rings. Each has a book of its own, shaped like this one.

This book documents the reference implementation in this repository. It is organised in four parts, each answering one kind of question, and every page states at its top which kind it is and whom it is for.

## The four parts

| Part | The question it answers | How to read it |
|---|---|---|
| [Examples](examples/README.md) | How do I see it working? | Hand the prompt to your agent, or follow the steps; each ends with something running and checks you can run. |
| [Workflows](workflows/README.md) | How do I do my domain's job with it? | An example's shape for one domain, saying what is implemented and what is deferred. |
| [How-to guides](guides/README.md) | How do I do this particular task? | Find the task, follow the steps. |
| [Reference](reference/README.md) | What exactly is true? | Look things up. The specification and the generated tables live here. |
| [Concepts](explanation/README.md) | Why is it built this way? | Read for understanding. One invariant and one figure per page. |

A last part, [Contributing](contributing/README.md), is for people changing the tree: the workspace, the gates, the decision record, and the documentation's own rules.

## Where to start

- **Seeing Pulse Mesh work:** [Across a network](examples/across-a-network.md) encodes, verifies and sends Pulses over UDP with nothing but this repository; [Two programs talk through the daemon](/docs/daemon/examples/two-programs.html) and [An agent swarm](/docs/daemon/examples/agent-swarm.html) are in the daemon's book.
- **Building on it from another language or another process:** [Language bindings](reference/bindings.md) and the [API reference](reference/overview.md); the ring and the store inside your own process is [the first workflow](workflows/ring-in-process.md).
- **Understanding how the pieces fit:** the workspace pages in the [Reference](reference/README.md) part follow the repository's two tiers, and the [Concepts](explanation/README.md) part says why they are shaped as they are and where the daemon and the rings sit above them.
- **Contributing:** [Developer Onboarding](contributing/onboarding.md), then the [documentation style](contributing/style.md) if you are writing.

## How this book relates to the rest of the repository

Two records are authoritative, and this book defers to both. The rustdoc (`cargo doc --workspace --no-deps --open`) is the API contract: every crate opens with an overview, every public item is documented, and a workspace lint keeps it that way. The decision log under `decisions/` records why the non-obvious calls were made, in order and without rewriting. The book is the guided path through that material. Where the book and the code disagree, one of them is wrong, and either way it is a defect to report.

## What this book claims and what it does not

The book describes the tree at the version shown in the sidebar. It records no measured figures. Where it describes a measurement it gives the command that produces one. Where a behaviour is specified but not yet implemented, the page says so and names the test that will prove it. Refutations are welcome: the fastest way to improve a page is to show where it is wrong.
