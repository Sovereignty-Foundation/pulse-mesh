# 8. Conformance and the normative surface

<p class="pm-kind"><b>Reference · normative</b> · what a conformant implementation reproduces, and which changes to this standard require a draft revision</p>

## 8.1 What conformance is

Conformance is byte equality against the vectors under `pulse/pulse-spec/test-vectors`, not similarity of API. A conformant implementation:

- MUST produce byte-identical canonical bytes and identifiers to the vectors for the inputs they define (`pulse-layout-known-good`, `envelope-raw-known-good`, `envelope-nested-3-level`, each as JSON fields and as hex bytes);
- MUST accept byte-identical input that any other conformant implementation produces for the same fields;
- MUST treat the canonical envelope size as unbounded (3.7);
- MUST accept nested envelopes to a depth of 32 and MAY reject deeper ones (3.4);
- MUST validate UTF-8 in a type name and MUST reject unknown type-name and payload-variant tags (3.1, 3.3);
- SHOULD expose self-verification (3.5);
- SHOULD treat an unknown instruction as `Null` (2.2).

The vectors are language-neutral and are the source of truth for byte-level interoperability. They are regenerated only by the tool under `pulse/pulse-spec/tools`, and a change to them is a draft revision (8.3).

## 8.2 How conformance is shown

In this repository the codec's own tests assert the vectors; the WebAssembly binding exposes `check_fixture`, which runs them in the browser; and the Python, Node and C bindings carry byte-equality tests against the same files. The port protocol has fixtures of its own, under `mesh/mesh-port-protocol/fixtures`, which the Rust types write and the two thin clients' tests read (chapter 7). A satellite implementation shows conformance the same way: it reproduces the vectors, and its entry in `modules.toml`, which defines the registration fields and lists no satellite today, names the surface it conforms to.

The Lexicon™ anchors the published catalog of envelope types: `mesh-lex` computes a Merkle root over its public entries, the daemon logs that root at start, and `pulse/pulse-spec/lex-root.txt` records the root the release was cut with, so an implementation can tell which catalog a peer speaks.

## 8.3 The normative surface

| Surface | Status | On change |
|---|---|---|
| Chapter 2: the Pulse layout, alignment and instructions | Normative | Draft revision |
| Chapter 3: the canonical envelope bytes, the identifier, the variants, the nesting rules | Normative | Draft revision |
| Chapter 4: the ring protocol | Normative for shared-memory substrates | Draft revision |
| Chapter 5: the store layout | Reference implementation | Layout version bump, recorded in the decision log |
| Chapter 6: the UDP framing, feedback, parity and handshake | Normative for the reference transport | Draft revision when the framing changes; other transports unaffected |
| Chapter 7: the port protocol | Normative for the daemon's clients | Protocol version bump |
| The vectors under `pulse/pulse-spec/test-vectors` | Normative, the executable contract | Draft revision on any addition or change |
| The registration fields `modules.toml` (profiles repository) defines for a satellite (tier, registry status, targets, conformance surface) | Normative | Draft revision when a meaning changes; entries added without a change of meaning do not |
| The reference crates, the tools, the examples and this book | Reference and informative | Release versions; not a revision of the standard |

A change to the reference implementation that leaves the vectors' output unchanged is not an event for the standard. A change that alters the vectors' output is a draft revision, and the superseded rule stays in the text, marked, with the revision that replaced it.
