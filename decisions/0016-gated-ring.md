# ADR-0016 — Gated rings: one store per publish, one check per read

**Status:** Accepted
**Date:** 2026-10-04
**Accepted:** 2026-10-19, by the Architect.
**Amended:** 2026-10-19: ADR-0019, accepted after this was written, gave SeqLock rings a reader table, a companion object `<ring>.readers` whose registered readers a blocking publish waits for. That does not change this decision: a SeqLock ring with a table still takes overwriting publishes and readers that do not register, so its writer still stores each counter twice and its readers still re-check, and only a ring that enforces the gate can drop both. The gated ring keeps its reader records in its own header (layout version 2), the alternative ADR-0019 left for later. The context's account of blocking publish is restated, and an open question added.

## Context

The SeqLock ring (`core_ring::PulseRing`, chapter 4 of the specification) lets its writer overwrite a slot a reader may still be copying. That is what makes lossy fan-out possible, and what lets a reader survive a writer that dies mid-write, and it is paid for twice on every message. The writer stores the slot's counter twice, odd before the payload and even after it, so the line every waiting reader polls changes hands twice per message. The reader copies the slot and then re-reads the counter behind an acquire fence, keeping its copy only if the counter did not move, so every read pays a second look at that line and a fence.

The LMAX Disruptor pays neither. Its producer never writes a slot a consumer has not finished with: it waits on the consumers' sequences, so a consumer can never see a slot change under it, and one store of the cursor after the payload is enough. On pinned Intel at eight receivers, with the Disruptor carrying the same 128-byte payload as the ring, the ring's paced latency to the last receiver is 1.07 to 1.14 times the Disruptor's at the median and 1.17 to 1.29 times at p99, with burst throughput level (forge:arc/ring-reader-side-1). That forge ruled out the payload, batch reads, UMWAIT with the uncore clock held, the version-2 ready line and processes against threads. What it left untested is exactly the two costs above.

Both costs exist only because the writer may overwrite an unread slot. Many of the ring's demanding uses never want that: the blocking publish paths and the fan-out harness's lossless policy (per-reader cursor rings, the writer waiting on the slowest) wait for their readers already. They wait in the harness or by convention, though, not in the ring. `advance_read_cursor` keeps one cursor that follows the furthest reader; ADR-0019's reader table makes a blocking publish wait for every registered reader, but nothing stops a reader that does not register, or an overwriting publish, on the same ring. *(Amended 2026-10-19: it said blocking publish protects one reporting reader, which ADR-0019 has since changed.)* A contributed batch-publish prototype showed what an unenforced contract costs: a publish path that met every functional test still handed a lapped reader another position's Pulse, and only a race test written for the purpose (#41) would have caught it.

## Decision

Add a second kind of ring, the gated ring, in which the writer can never overwrite a slot that any reader has not released, and in which that rule is kept by the ring itself. Because it is kept, a gated publish stores the slot's counter once and a gated read checks it once.

**A separate kind, recorded in the region.** A gated ring is made by `GatedRing::create_exclusive(name, capacity, max_readers)` (and a `from_fd` form) in a new module, `core/core-ring/src/gated.rs`. Its header is layout version 2: bytes 0..48 as in version 1, bytes 48..52 the ring's mode (`1`, gated) and 52..56 `max_readers`, 56..64 zero. After the header come `max_readers` reader records of 64 bytes each, one cache line per reader, and then the slots, so a gated region spans `64 + 64·max_readers + capacity · slot size` bytes. SeqLock rings keep layout version 1, byte for byte: nothing about an existing ring changes. `PulseRing::open` and `open_existing` refuse a version-2 header (`LayoutMismatch`), and `GatedRing` refuses a version-1 one, so no SeqLock writer or reader can attach to a gated ring and no gated handle to a SeqLock ring. Version-1 and version-2 slot sizes (128 bytes, or 192 with a ready line) both apply.

**Readers register.** A reader attaches with `GatedReader::attach(name)`, which claims a free reader record. A record holds the reader's cursor (an atomic `u64`, every position below it released) and its state (free, joining, active). Joining is a handshake, so the writer never misses a reader: the reader claims a free record by compare-and-swap, writes the position it will start from, the current write cursor, and sets the state to joining. The writer looks at the reader records whenever its cached floor no longer proves room, and at least once every `capacity / 4` publishes; it counts a joining reader from that reader's start position on and marks it active. The reader reads nothing until it sees itself active. A reader leaves by setting its record free, and a full table is `RingError::NoReaderRecord`.

**Writer protocol.** For position `p` in slot `p mod capacity` the writer:

1. waits until `p − floor < capacity`, where `floor` is the smallest cursor among active readers, read from the records with acquire ordering only when the cached floor stops proving room; a wait past its timeout is `RingError::Stalled`, naming the reader record that holds the floor;
2. stores the Pulse's bytes 8 to 128 into the slot as atomic words, relaxed;
3. stores the slot's counter once, with release ordering, as `2·(p / capacity + 1)`, the value a SeqLock publish leaves for that lap;
4. on a version-2 slot, bumps the ready line with release ordering;
5. advances `total_writes` and then `write_cursor`, each with release ordering.

There is no odd mark and no fence before the payload. The slot being written is one every reader has released, so no reader is copying it.

**Reader protocol.** To read position `p`, a reader loads the slot's counter with acquire ordering. Below `2·(p / capacity + 1)` the position is not written yet. Equal to it, the reader copies the 128 bytes as atomic words and keeps the copy, with no re-check and no fence: the writer cannot store to the slot again until this reader's cursor passes `p`. Above it is impossible for an active reader, and is reported as `PositionRead::Lost` rather than trusted. The reader releases what it has read by storing its cursor with release ordering, at least every `capacity / 4` positions, as the fan-out harness's readers report today. That release store is what orders the reader's copy before the writer's next store to the slot (the writer's acquire load of the cursor synchronises with it), which is the whole of the gated ring's safety argument.

**A crashed writer** dies before step 3 or after it. Before, the slot's counter still shows the previous lap, which every reader has released, so the position reads as not written and the next writer's publish completes it. After, the Pulse is whole. A torn slot is never visible to a reader.

**A crashed or stalled reader** holds the floor, and the writer stops at most a capacity later with `RingError::Stalled` naming its record. Detecting that a reader is dead is the owner's job, as one writer per ring is today (the hub's owner lock): `GatedRing::evict(record)` frees a record, after which the writer counts that reader no longer, and the evicted reader's next read reports that it was evicted. A gated ring trades loss for back-pressure, by design, and the SeqLock ring stays for anyone who wants loss instead.

**Publish paths.** `GatedRing` has `publish` and `publish_batch`, both waiting for room as above, and no path that overwrites, writes a chosen slot or skips the wait. Every one moves the cursor per slot, never once per batch: the reader-side rule does not need it, but nothing gated should differ from what #36 taught without a measured reason. `core/core-ring/tests/publish_paths.rs` grows to read `gated.rs` too and refuse any `pub fn publish*` there that it does not race, and a gated race runs a writer against readers that join, lag, leave and are evicted, asserting every read is the Pulse written for its position.

**Measurement.** A gated contestant joins the fan-out harness. The first sitting is the like-for-like one of forge:arc/ring-reader-side-1: pinned Intel with the uncore clock held, eight receivers, the Disruptor carrying the full payload, with the prediction written before the run. If gating does not close most of the paced gap, the record says so and the gated ring is judged on its other merit, enforced lossless delivery to many readers.

## Alternatives considered

- **Drop the SeqLock from every ring.** It would end lossy fan-out and the ring's tolerance of a writer that dies mid-write, which other code relies on (chapter 4.2 and 4.3). The gated ring is opt-in instead.
- **Keep gating in the harness.** That is today's lossless policy: the speed-up would need the reader to trust a contract the ring cannot see, which is the shape of #36's failure. Rejected.
- **Poll a separate ready line.** Measured on Intel in forge:arc/ring-reader-side-1: 13% slower at the median than polling the counter, and 22% lower burst throughput. Rejected as the lever, kept as a slot format.
- **One counter store per publish without gating.** A reader could then copy a slot while the writer overwrites it, and nothing would tell it. Unsafe; rejected.
- **A per-reader mailbox writer.** Forge:arc/fanout-copies-1 measured the cost of a sequential copy per group of readers: about 160 ns plus 35 ns per reader polling it. A copy per reader costs more than it saves at 8 and 16 readers. Rejected.

## Consequences

Existing rings, readers and the hub do not change; a gated ring is a new kind with a new header version, and the two kinds refuse each other at open. The specification gains a section on gated rings in chapter 4 (layout version 2, reader records, the writer and reader protocols and the joining handshake), which the Docs lane writes and PM checks against the code. The guardrail of #41 extends to the new module before any gated publish path merges. A gated ring needs `max_readers` fixed at creation and gives a stalled reader the power to stop its writer, which the owner answers with `evict`. Whether the gated ring replaces the harness's lossless policy, and whether the hub (which overwrites today, chapter 4.3) adopts it, are later decisions, taken on the measured result.

## Open questions

- Should a reader's cursor record carry a heartbeat the writer can read, so `RingError::Stalled` can say whether the reader is alive, or is that the owner's alone?
- Does the joining handshake need a bound on how long a reader waits to become active when the writer is idle, or should an idle writer adopt joining readers on a timer?
- Should `max_readers` default to a fixed number (16?) when a caller does not name one?
- Should a reader record reuse the reader table's claim word (ADR-0019: the claimant's process id and a generation), so that a stalled writer can free a dead reader's record itself, as a blocking publish on a SeqLock ring with a table does, rather than leaving every eviction to the owner?
