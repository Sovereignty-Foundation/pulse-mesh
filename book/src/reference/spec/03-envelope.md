# 3. The PulseEnvelope

<p class="pm-kind"><b>Reference · normative</b> · the variable-size, content-addressed payload and the cross-language byte-equality contract</p>

The PulseEnvelope™ carries anything larger than a Pulse. It is referenced from a Pulse whose instruction is `Data` through the 16-byte `envelope_ref`, and it is addressed by its content: two envelopes with the same content have the same identifier in every language that implements this chapter. The reference type is `pulse_canon::PulseEnvelope`; the vectors `envelope-raw-known-good` and `envelope-nested-3-level` under `pulse/pulse-spec/test-vectors` are its executable form.

## 3.1 Canonical byte layout

The canonical bytes of an envelope are a fixed header, a type-name section and a payload section, in that order, with no padding. All multi-byte integers are little-endian. The reference publishes `CANONICAL_FIXED_HEADER = 44` and `MIN_CANONICAL_ENVELOPE = 50` (the smallest well-formed envelope: the header, an absent type name, a variant tag and a zero length) as public constants.

**Fixed header, 44 bytes**

| Offset | Size | Field | Type | Notes |
|---|---|---|---|---|
| 0 | 16 | `id` | `[u8; 16]` | The content identifier (3.2). |
| 16 | 16 | `origin` | `[u8; 16]` | The producing node. Not part of the identifier, so the same content from two origins shares one id. All zeros when unset. |
| 32 | 8 | `monotonic_nanos` | `u64` | The producer's creation time. Not part of the identifier. |
| 40 | 2 | `envelope_type` | `u16` | The numeric type. Part of the identifier. |
| 42 | 2 | `flags` | `u16` | Routing and behaviour flags (below). Not part of the identifier. |

**Type-name section**

| Offset | Size | Field | Type | Notes |
|---|---|---|---|---|
| 44 | 1 | `type_name_present` | `u8` | `0` absent, `1` present. Any other value MUST be rejected (the reference reports `InvalidTypeNameTag`). |
| 45 | 4 | `type_name_len` | `u32` | Present only when the tag is `1`: the byte length L of the name. |
| 49 | L | `type_name` | `[u8; L]` | The UTF-8 bytes of the name. A decoder MUST validate UTF-8 (`InvalidTypeName`). |

**Payload section**, starting at T = 45 when the name is absent and T = 49 + L when present

| Offset | Size | Field | Type | Notes |
|---|---|---|---|---|
| T | 1 | `payload_variant` | `u8` | `0` raw, `1` nested. Any other value MUST be rejected (`InvalidPayloadVariantTag`). |
| T + 1 | 4 | `payload_len` or `nested_count` | `u32` | The byte length M of a raw payload, or the number N of nested envelopes. |
| T + 5 | M or … | payload | bytes | M opaque bytes, or N envelopes each encoded by this same rule, concatenated. |

**Flags** at offset 42:

| Bit | Mask | Name | Meaning |
|---|---|---|---|
| 0 | `0x0001` | `BROADCAST` | Fan out to every listener rather than point to point. |
| 1 | `0x0002` | `ACK_REQUIRED` | The sender expects an acknowledgement. |
| 2 | `0x0004` | `PRIORITY` | Schedule with elevated priority. |
| 3 | `0x0008` | `COMPRESSED` | The payload is compressed; the codec is outside this layer. |
| 4 to 15 | | reserved | Encoders MUST NOT set them. The reference decoder drops unknown bits on decode; since flags are outside the identifier, an envelope that arrived with a reserved bit set decodes with it cleared and its id is unaffected. |

## 3.2 The content identifier

The identifier is the first 16 bytes of a BLAKE3 hash of this preimage, in this order:

1. the domain tag, the ASCII bytes of `pulse-envelope-id/v2`, with no terminator;
2. `envelope_type` as two little-endian bytes;
3. the type-name section exactly as it appears on the wire: the byte `0`, or the byte `1` followed by the four-byte length and the name bytes;
4. the payload variant tag as one byte;
5. the length of the payload bytes as four little-endian bytes;
6. the payload bytes: a raw payload verbatim, or for a nested payload the count as four little-endian bytes followed by each child's canonical bytes.

The domain tag keeps identifiers computed under this rule distinct from any other hash of the same fields, and the explicit lengths keep a name and a payload from being read as one another. `origin`, `monotonic_nanos`, `flags` and the identifier field itself are outside the preimage. The reference computes it with `PulseEnvelopeId::compute_from_payload` and renders it as 32 lowercase hexadecimal characters; the all-zero identifier means "no envelope" in a Pulse's `envelope_ref`.

## 3.3 Payload variants

A **raw** payload (`0`) is a sequence of opaque bytes. Receivers MUST NOT interpret them at this layer; their meaning is carried by `envelope_type` or `type_name`.

A **nested** payload (`1`) is a sequence of envelopes, each in its canonical form. Its byte form is the count followed by the children, which is also how it enters the identifier's preimage.

A decoder that meets any other variant tag MUST reject the envelope. Future draft revisions MAY define further variants.

## 3.4 Recursive composition

An outer envelope may contain inner envelopes, and those may contain envelopes in turn. Because a parent's identifier covers its children's canonical bytes, and each child's canonical bytes begin with the child's own identifier, tampering with any descendant changes every identifier above it. Three uses follow: a batch of K events travels as one envelope with one identifier and is verified with one recomputation; an audit chain nests the previous state in the next so provenance is tamper-evident inline; a broadcast of a nested batch fans out K events to N subscribers without per-event framing.

**Bounds.** The reference decoder refuses nesting deeper than `MAX_NESTING_DEPTH = 32` (`NestingTooDeep`) and refuses a nested count larger than the remaining bytes could hold at fifty bytes per child (`NestedCountExceedsBuffer`) before it allocates anything. A conformant decoder MUST accept nesting to a depth of 32 and MAY reject deeper structures; an encoder SHOULD NOT produce them. The vector `envelope-nested-3-level` pins three levels.

*Superseded rule.* Draft-00 required decoders to handle recursion "to arbitrary depth bounded only by available memory". That rule is superseded by the depth and count bounds above, adopted after the decoder was found to allocate from an attacker-chosen count.

## 3.5 Self-verification

A receiver verifies an envelope by recomputing the identifier from `envelope_type`, `type_name` and the payload and comparing it with the stored `id`; the reference exposes this as `PulseEnvelope::verify()`. Decoding checks structure only, so verification is a separate step; the reference UDP transport performs it on every decoded envelope and rejects a mismatch (`EnvelopeIdMismatch`). Receivers SHOULD verify envelopes that arrive over an untrusted transport and MAY skip verification on a trusted one, such as local shared memory.

## 3.6 Byte stability across languages

Two conformant implementations in different languages MUST produce byte-identical canonical bytes, and therefore identical identifiers, for identical field inputs. The reference's canonical-layout tests are the executable contract in Rust; the same fixture appears as `envelope-raw-known-good` for language-neutral conformance; the Python, Node, C and WebAssembly bindings in this repository, and the satellite implementations, prove equality against it.

## 3.7 Size is unbounded

The canonical envelope has no maximum size. A conformant implementation MUST accept any byte count subject only to its memory. Three limits exist at other layers, and none of them is part of the envelope contract:

| Limit | What it is | Where it lives |
|---|---|---|
| 1,315 bytes | The most envelope bytes one datagram of the reference UDP transport carries: the 1,472-byte MTU less the 153-byte frame header and the 4-byte CRC trailer (chapter 6). | `pulse-wire-udp`, `MAX_ENVELOPE` |
| 65,536 bytes | The most bytes one entry of the reference envelope store holds; recorded in the store's header so an attaching reader discovers it (chapter 5). | `core-store`, `MAX_ENTRY_SIZE` |
| The daemon's frame cap | The largest message the daemon accepts on one connection (chapter 7). | `mesh-hub` |

A transport MAY refuse to carry an envelope its substrate cannot hold; that refusal is a substrate concern, not a violation of this chapter.

## 3.8 A Pulse, an envelope, or both

This section is informative. A Pulse alone is sufficient when the signal fits in its fields: `Null`, `Heartbeat` with the overlay, or `Data` with nothing attached. An envelope is required when the application carries variable-size data, needs an identity that survives transmission, needs to bundle several messages atomically, or needs cross-language byte equality. The common pattern is both: a Pulse with `instruction` `Data` and `envelope_ref` set to the envelope's identifier, the Pulse carrying the transport-level signal and the envelope the payload.

## 3.9 What would refute this chapter

The two envelope vectors give the canonical bytes and the identifiers of a raw envelope and a three-level nested one. An implementation that produces different bytes or a different identifier for their inputs, accepts a tag outside `0` and `1`, accepts an invalid type name, or computes an identifier without the domain tag and the lengths, does not conform.
