# 1. Introduction

<p class="pm-kind"><b>Reference · normative</b> · scope and terminology</p>

Pulse Mesh is a wire format and a shared-memory transport for high-throughput, low-latency message passing. It is built on two primitives, both specified normatively in this standard.

- The **Pulse**: a 128-byte, fixed-size, cache-aligned control and data signal, exchanged through a shared-memory ring or a UDP datagram.
- The **PulseEnvelope**: a variable-size, content-addressed, byte-stable payload, referenced from a Pulse when data exceeds the Pulse boundary.

The Pulse is the core primitive. The PulseEnvelope is the standard primitive for variable-size payloads. Chapters 2 and 3 are the load-bearing standardisation claims; chapters 4 to 7 describe the substrates and the protocol the primitives flow through; chapter 8 defines conformance.

## 1.1 Scope

This standard defines the byte layout, alignment and field semantics of the Pulse (chapter 2); the canonical byte layout, the content-addressing scheme, the payload variants and the self-verification invariant of the PulseEnvelope (chapter 3); the SeqLock-protected shared-memory ring protocol Pulses are exchanged through (chapter 4); the envelope store that holds envelopes referenced from Pulses (chapter 5); the reference UDP transport's framing, feedback, error correction and capability handshake (chapter 6); the Universal Port Protocol the daemon speaks to its clients (chapter 7); and the conformance requirements and the normative surface (chapter 8).

It does not define higher-layer routing, governance, identity or scheduling semantics, which build on Pulse Mesh and are specified elsewhere in the Sovereignty stack; production hardening such as failover, persistence, replication or consensus, since the reference implementation is reference-grade; or language bindings, optimised variants and alternative transports, which live in satellite repositories that conform through the vectors in chapter 8 and register in the profiles repository's `modules.toml`.

## 1.2 Terminology

**Requirement words.** MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT, RECOMMENDED, MAY and OPTIONAL are to be read as in RFC 2119.

**Conformance terms.** A conformant implementation produces byte-identical output to the vectors under `pulse/pulse-spec/test-vectors` for the field inputs they define, and accepts byte-identical input that any other conformant implementation produces. Conformance is byte equality, not API parity.

**Surface terms.** The *wire format* is the byte representation of a Pulse or an envelope. The *canonical encoding* is the specific byte sequence a PulseEnvelope produces under section 3.1. A *substrate* is the medium a Pulse or an envelope is exchanged through: a shared-memory ring, a UDP datagram, a daemon connection.

**Names.** The [glossary](../../glossary.md) owns every other term this standard uses, in the sense this standard uses it.
