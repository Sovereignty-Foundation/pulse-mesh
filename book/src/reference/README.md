<div class="pm-part">
  <img class="pm-logo pm-logo-light" src="../images/sov-mark-black.svg" alt="Sovereignty Foundation Inc.">
  <img class="pm-logo pm-logo-dark" src="../images/sov-mark-white.svg" alt="">
  <span class="pm-eyebrow">Part 03 · Reference</span>
  <h1>What is <span class="pm-accent">exactly</span> true</h1>
  <p class="pm-sub">The specification, the workspace crate by crate, and the tables generated from the code.</p>
</div>

<p class="pm-kind"><b>Part opener</b> · for implementers and integrators looking something up</p>

Reference pages state what is true and nothing else. They do not teach and they do not persuade. Where a table can be produced from the code, it is, and a check in continuous integration fails when the page and the code disagree.

The part has four layers. [The specification](spec/README.md) is the normative text: the Pulse, the PulseEnvelope, the ring, the store, the UDP transport, conformance, and what changes require a draft revision; the vectors under `pulse/pulse-spec/test-vectors` are its executable form. The workspace pages describe each tier and each crate, following the tree's own structure. The API pages describe the surfaces other languages see. The generated pages are produced from the code by the gate.

- [The specification](spec/README.md): seven chapters here and an appendix; chapter 7, the port protocol, is [in the daemon's book](/docs/daemon/reference/spec/07-port-protocol.html), since the daemon speaks it.
- Workspace: [Layout](../architecture/overview.md), [pulse/](../architecture/pulse.md), [core/](../architecture/core.md). The daemon's tier and the rings have their pages in [the daemon's book](/docs/daemon/architecture/mesh.html) and [the profiles' book](/docs/profiles/architecture/rings/overview.html).
- Generated from the code: the [crate index](crates.md) and the [error catalogue](errors.md); the gate regenerates them and fails on any difference.
- API: [Overview](overview.md), [Python](python.md), [Node](node.md), [C](c.md), and the [language bindings](bindings.md) by kind.
- [Glossary](../glossary.md).
