# 2. The Pulse

<p class="pm-kind"><b>Reference · normative</b> · the 128-byte atom every conformant transport carries or references</p>

The Pulse is the core primitive. Every message exchanged through a conformant transport is a Pulse or references one. The reference type is `pulse_canon::Pulse`; the vector `pulse-layout-known-good` under `pulse/pulse-spec/test-vectors` is its executable form.

## 2.1 Wire layout

A Pulse MUST be exactly 128 bytes. The layout is C-compatible field order with no padding beyond the declared fields, and the type is aligned to a 64-byte boundary in memory (`#[repr(C, align(64))]` in the reference). All multi-byte integers are little-endian on the wire. The reference keeps a Pulse in memory as exactly these bytes, so it builds only for little-endian targets.

| Offset | Size | Field | Type | Semantics |
|---|---|---|---|---|
| 0 | 8 | `seq_lock` | `u64`, atomic | The SeqLock word of the slot the Pulse sits in: odd while a writer is in progress, even when stable. Owned by the substrate (chapter 4); a Pulse on the wire carries whatever value the sender's slot had, and receivers MUST ignore it. |
| 8 | 16 | `origin_id` | `[u8; 16]` | The producing node's identifier: a truncated hash of the node's name or key. A hub writes its own instance identifier, sixteen random bytes drawn when it was created or opened, into an `origin_id` left unset on the Pulses it publishes, and uses it to skip the envelope signals it wrote itself. |
| 24 | 8 | `monotonic_nanos` | `u64` | A monotonic clock reading at creation, set by the producer, in nanoseconds. A hub stamps the signals it writes and the envelopes it routes with the host's monotonic clock, the clock this field is defined on: CLOCK_MONOTONIC on Linux and CLOCK_UPTIME_RAW on macOS, both in nanosecond steps and neither counting time asleep. An application may drive the hub's clock instead with `set_monotonic_nanos`. |
| 32 | 8 | `chain_step` | `u64` | Remaining steps in the optional hash chain; a countdown to zero is a time to live. Zero when the replay defence is not used. |
| 40 | 2 | `instruction` | `u16` | The opcode, from the table below. |
| 42 | 2 | `_pad0` | `u16` | Alignment padding. MUST be zero. |
| 44 | 4 | `scope` | `u32` | The execution scope bound; interpreted as a context id and a subscope by the context registry. |
| 48 | 16 | `envelope_ref` | `[u8; 16]` | The content id of an associated PulseEnvelope, or all zeros when none is attached. |
| 64 | 32 | `preimage` | `[u8; 32]` | The hash-chain preimage for the optional replay defence. MAY be zero. |
| 96 | 32 | `_pad2` | `[u8; 32]` | Fills the second cache line. Carries the heartbeat overlay (2.5) when the instruction is `Heartbeat`, and the data overlay (2.6) when it is `Data`. |

The first 64 bytes are one cache line and the second 64 bytes another; a Pulse occupies exactly two.

**Compile-time invariant.** A conformant implementation MUST assert at build time that its Pulse type is exactly 128 bytes and 64-byte aligned. The reference does so with a constant assertion in `pulse/pulse-canon/src/pulse.rs`, and `PULSE_WIRE_SIZE` is published as a public constant.

## 2.2 Instructions

| Opcode | Name | Meaning |
|---|---|---|
| `0x0000` | `Null` | A blank slot: zeroed memory or an empty buffer. |
| `0x0001` | `Heartbeat` | A liveness signal. Bytes 96 to 128 carry the heartbeat overlay (2.5). |
| `0x0010` | `Data` | A data signal. `envelope_ref` names the PulseEnvelope that carries the payload, and bytes 96 to 128 carry the data overlay (2.6). |

Receivers MUST treat an unknown opcode as `Null` and MUST NOT fail-stop on one; the reference's `Instruction::from_u16` maps every other value to `Null`. Future draft revisions MAY assign further opcodes.

## 2.3 Alignment

The Pulse type MUST be aligned to a 64-byte boundary, one cache line on contemporary x86-64 and AArch64 processors. The alignment prevents false sharing when adjacent slots are touched by different cores, makes a read a single cache-line fetch per line, and permits zero-copy reinterpretation of an aligned byte slice as a Pulse. Implementations on platforms with a different cache-line size MUST still align to 64 bytes for wire compatibility.

## 2.4 SeqLock access and multi-slot atomicity

When Pulses are exchanged through a shared-memory ring, the `seq_lock` word gives readers torn-read detection without a mutex; the protocol is chapter 4. The layout provides atomicity for one Pulse at a time. A producer that needs several Pulses to be observed together MAY wrap them as inner envelopes of one nested PulseEnvelope (3.4), identified by a single content id, and publish one Pulse that references it.

## 2.5 The heartbeat overlay

When `instruction` is `Heartbeat`, bytes 96 to 128 MUST be read as a `HeartbeatPayload`:

| Offset within `_pad2` | Size | Field | Type | Meaning |
|---|---|---|---|---|
| 0 | 8 | `schema_version` | `u64` | An opaque schema or configuration version, compared bytewise. |
| 8 | 8 | `uptime_ms` | `u64` | Milliseconds since the node started. |
| 16 | 4 | `error_count` | `u32` | Errors since the node started. |
| 20 | 2 | `stage_count` | `u16` | Registered processing stages. |
| 22 | 2 | `path_count` | `u16` | Registered processing paths. |
| 24 | 2 | `consecutive_errors` | `u16` | Errors in the most recent window. |
| 26 | 1 | `wake_state` | `u8` | Position in the wake cycle, 0 to 15. |
| 27 | 1 | `health_state` | `u8` | 0 healthy, 1 warning, 2 restarting, 3 isolated. |
| 28 | 4 | `_reserved` | `[u8; 4]` | MUST be zero. |

The reference reads and writes the overlay through `heartbeat_payload` and `set_heartbeat_payload`. When the instruction is neither `Heartbeat` nor `Data`, bytes 96 to 128 MAY hold any pattern and receivers MUST ignore them.

## 2.6 The data overlay

When `instruction` is `Data`, bytes 96 to 128 are a `DataPayload`, which names the stored copy of the envelope that `envelope_ref` identifies. Envelopes with the same content share an id, so the id alone cannot say which copy an envelope store (chapter 5) holds; the overlay names one by its store cursor.

| Offset within `_pad2` | Size | Field | Type | Meaning |
|---|---|---|---|---|
| 0 | 8 | `store_cursor` | `u64` | The cursor at which the envelope store holds the copy, when `has_store_cursor` is 1. |
| 8 | 1 | `has_store_cursor` | `u8` | 1 when `store_cursor` names a copy; any other value names none. |
| 9 | 23 | `reserved` | `[u8; 23]` | MUST be zero. |

All zeros, the `_pad2` of a zeroed Pulse, name no copy. A receiver that reads envelopes from a store MAY fetch the copy at the named cursor, and MUST treat what it finds there as the signalled envelope only when it carries the id `envelope_ref` names, since the store may have reused the slot. A receiver that does not read a store MAY ignore the overlay. The reference writes it through `set_data_payload` and `set_store_cursor`, reads it through `data_payload` and `store_cursor`, and its hub fetches the named copy with `EnvelopeStore::fetch_at`, which checks the id.

## 2.7 What would refute this chapter

The vector `pulse-layout-known-good.hex` is the bytes of a Pulse with known field values. An implementation whose Pulse does not reproduce them field for field, or whose type is not 128 bytes and 64-byte aligned, does not conform; a reference build in which the layout assertion fails contradicts this chapter and is a defect.
