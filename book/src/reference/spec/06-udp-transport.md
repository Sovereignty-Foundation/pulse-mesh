# 6. The UDP transport

<p class="pm-kind"><b>Reference · normative for the reference transport</b> · how `pulse-wire-udp` frames a Pulse and its envelope in one datagram, and the feedback, parity and handshake around it; another transport MAY frame differently and conforms through its own vectors</p>

The reference transport carries one Pulse and at most one envelope per datagram, checks every datagram with a CRC, and layers three optional mechanisms on top: acknowledgement-driven backpressure, negative acknowledgement with retransmission from a send cache, and single-parity forward error correction. A capability handshake lets two peers agree which of those to use. Amber in every figure.

## 6.1 Datagram framing

One datagram is one frame, little-endian, with no padding:

| Field | Size | Contents |
|---|---|---|
| `magic` | 4 | `PMSW` as little-endian bytes, `0x57534D50`; tells Pulse Mesh traffic apart from anything else on the socket. |
| `version` | 1 | `1`. Bumped on any layout-incompatible change. |
| `seq` | 8 | A per-run monotonic sequence number; feedback refers to it. |
| `send_ns` | 8 | The sender's clock in nanoseconds, so a receiver can compute one-way latency without a side channel. |
| `pulse` | 128 | The Pulse's bytes, verbatim. |
| `n` | 4 | The envelope length, `0` to `MAX_ENVELOPE`. |
| `envelope` | n | The envelope's canonical bytes, when present. |
| `crc32c` | 4 | A Castagnoli CRC over every preceding byte. |

The header is 153 bytes and the trailer 4. The transport assumes a 1,500-byte path MTU less 20 bytes of IPv4 and 8 of UDP, so `MTU_BYTES = 1472` and `MAX_ENVELOPE = 1315`; a sender MUST reject a larger envelope at encode time, and the transport does not fragment. A receiver drops a datagram whose CRC does not match, silently, because this tier is fire and forget; it rejects a datagram whose magic or version differ; and when an envelope is present it decodes it canonically and verifies its identifier, rejecting a mismatch (`EnvelopeIdMismatch`). The reference publishes these constants and the frame vectors in its `wire_format` tests.

## 6.2 Feedback: acknowledgement and retransmission

Two 12-byte feedback datagrams travel from the receiver to the sender's feedback socket:

| Frame | Bytes | Contents |
|---|---|---|
| ACK | `PMSA` (`0x41534D50`) then a `u64` | The receiver's cursor: one past the highest sequence it has seen, whether or not every lower sequence has arrived. |
| NACK | `PMSN` (`0x4E534D50`) then a `u64` | One sequence number the receiver is missing. |

**Backpressure.** The receiver sends an ACK every acknowledgement period, one millisecond by default. The sender keeps the highest cursor it has seen (an ACK can only move it forward, so a replayed or reordered ACK is harmless) and stalls a send while the frames in flight beyond that cursor would exceed `target_queue_depth`, sixteen by default, backing off through spins and yields into fifty-microsecond sleeps until the cursor moves or the stall deadline passes (`stall_timeout`, five seconds by default, set with `with_stall_timeout`, `None` for no deadline), when the send fails with `Stalled` and the frame is not sent. A cursor ahead of the sender's next sequence, which a receiver that outlived a restart of the sender leaves behind, counts as nothing in flight. A target queue depth of zero is refused when backpressure is enabled (`InvalidQueueDepth`), because it would admit no frame.

**Retransmission.** Only an arrival above the highest sequence seen reveals missing sequences, the ones between the two, and the receiver stages exactly those, once each, in a set capped at its recovery window, which is the sender's send-cache capacity (1,024 frames by default). A gap wider than the window keeps only its newest window of sequences staged; the rest are given up without a request and counted (`nack_drop_count`), as are the sequences before the first frame of a receiver that joins a stream late, and the receiver moves its head past what it gave up and counts a resync. It emits at most sixteen NACKs per acknowledgement period, requests a sequence again after four periods if it is still missing, and gives up on it after three requests. The sender keeps the last 1,024 encoded frames in a cache, accepts NACKs into a queue bounded by that capacity (a NACK arriving at a full queue is dropped and counted), drains at most sixteen NACKs per frame sent, for a batch as for a single send, and retransmits the cached bytes exactly as first sent, to its data destination and never to the NACK's source, so a forged NACK cannot redirect traffic.

**Admission.** The sender's feedback socket MAY be restricted to one peer address (`feedback_peer`); a datagram from any other address is dropped and counted. Without the restriction it accepts feedback from any source, which is the historical behaviour. Every mechanism exposes its counters: retransmits, cache misses, rejected feedback and dropped NACKs at the sender; NACKs sent, sequences given up on and gap resyncs at the receiver.

**Batches.** A batch send (`send_batch`) follows the same rules frame by frame. On Linux the batch goes out in `sendmmsg(2)` calls and elsewhere through the single send, and either way backpressure holds every frame to the window the receiver's cursor leaves open, a frame that waits past the stall deadline ends the batch at its index (`FrameError`) with the frames before it sent and the sequence counter advanced only for them, so the caller can resend the unsent tail under the sequence numbers it left unused; the NACKs pending for a call's frames, sixteen at most per frame, are retransmitted before the call; every frame sent is cached for retransmission; and with parity enabled no call runs past the last frame of a parity window, so each parity datagram follows the frame that completes its window before any later frame. A batch larger than `MAX_BATCH_FRAMES` is refused before anything is sent (`BatchTooLarge`). Frames go out in order, and on an error the frames before the failure were sent and the rest were not: on Linux, `Io` means the kernel refused the batch's first frame and nothing went out, and `PartialSend` means it took only some of the frames it was given, without saying why. A batch receive (`recv_batch`) takes every datagram through what the single receive does, on every platform: a data frame advances the ACK cursor and feeds gap tracking and NACK staging when backpressure is on, so a sender under backpressure is not stalled by a receiver that reads in batches, and the FEC decoder when FEC is on; a parity datagram goes to the decoder, or is dropped when FEC is off, and is never reported as an error; frames the decoder rebuilds are delivered after the frames decoded from the call's own datagrams, in the slots left, and the rest are held for the next receive call, which returns held frames first and, when it finds any, does not read the socket. A call with nothing held blocks until the first datagram arrives or the read timeout passes, then takes the datagrams already queued without waiting (on Windows each further read waits as the first does); a call whose datagrams were all parity delivers no frames; and a failure to read the first datagram, the timeout included, is the batch's `Io` error, after which nothing was read.

**Delivery.** The transport promises nothing about how many times a sequence is delivered. A sequence can arrive zero times, once, or more than once: a late original after its retransmission, or a frame rebuilt from parity followed by its late original. The receiver does not suppress duplicates; a caller that needs each sequence once filters on `RecvMeta::seq`, the frame's sequence number, which every delivery carries.

## 6.3 Forward error correction

With FEC enabled, the sender groups K consecutive frames into a window (K at least 1; sixteen by default; a window size of zero MUST be rejected) and after the K-th frame emits one parity datagram on the same socket:

| Field | Size | Contents |
|---|---|---|
| `magic` | 4 | `PMSF` (`0x46534D50`). |
| `window_start` | 8 | The sequence number of the window's first frame. |
| `window_n` | 2 | K, so a receiver detects a mismatched configuration. |
| `parity_len` | 4 | The length of the parity, the longest frame in the window. |
| `parity` | `parity_len` | The byte-wise exclusive or of the K encoded frames, each zero-padded to the longest. |

A receiver that holds K − 1 of the window's frames and the parity rebuilds the missing frame's bytes by the same exclusive or and passes them through the ordinary decode path, CRC included; a window with two or more losses falls through to retransmission. Parity trades sender and receiver CPU for the round trip a NACK would cost on a long path.

## 6.4 The capability handshake

Two peers start on plain UDP and exchange a 48-byte Hello, defined in `mesh-capability` so every transport backend speaks the same one:

| Field | Size | Contents |
|---|---|---|
| `magic` | 4 | `PMSH` (`0x48534D50`). |
| `version` | 2 | The protocol version the sender speaks, at most 3 in this revision. |
| `capabilities` | 4 | A bit field: `BACKPRESSURE` 1, `NACK` 2, `FEC` 4, `AF_XDP` 8, `DPDK` 16, `TLS_443` 32. |
| `registry_hash` | 32 | The BLAKE3 hash of the sender's context registry. |
| `reserved` | 6 | MUST be zero; receivers ignore it. |

The outcome is the intersection of the two capability fields; a peer upgrades only to what both sides announced. A registry-hash mismatch is advisory: the peers confirm that their books of scopes agree before promoting traffic. The socket handoff that follows an agreed upgrade belongs to each backend, not to this chapter.

## 6.5 What would refute this chapter

The frame vectors in the transport's `wire_format` tests give the bytes of known frames; a loopback test carries Pulses and envelopes end to end; the backpressure, retransmission, gap-bound, queue-bound, feedback-filter and FEC tests exercise each mechanism at its limits. A sender that fragments, a receiver that accepts a datagram with a bad CRC or an unverified envelope, a retransmission that goes to a NACK's source, an unbounded NACK queue, or a parity window of zero frames each contradicts this chapter.
