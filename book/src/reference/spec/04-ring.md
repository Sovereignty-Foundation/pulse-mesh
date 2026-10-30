# 4. The SeqLock ring

<p class="pm-kind"><b>Reference · normative for shared-memory substrates</b> · the ring Pulses are exchanged through on one machine, and the protocol that keeps a reader from ever using a torn Pulse</p>

A PulseRing is a fixed-capacity ring of Pulse slots in POSIX shared memory, with one writer per slot at a time and any number of readers, protected slot by slot by a SeqLock: a sequence counter that is odd while a write is in progress and even when the slot is stable. The reference type is `core_ring::PulseRing`. This chapter is normative for any implementation that exchanges Pulses through shared memory; a different substrate MAY use a different protocol and conforms through the vectors of chapter 8.

## 4.1 Region layout

| Bytes | Contents |
|---|---|
| 0 to 8 | `write_cursor`, atomic `u64`: the number of publishes so far; the next publish lands in slot `write_cursor mod capacity`. |
| 8 to 16 | `total_writes`, atomic `u64`: the count readers poll for new data. |
| 16 to 24 | `read_cursor`, atomic `u64`: the slowest reader's position, consulted only by the blocking publish mode. |
| 24 to 28 | The magic `PMSR`, stored last when the ring is formatted, with release ordering. |
| 28 to 32 | The header layout version, `1`; it numbers the header, not the slot format. |
| 32 to 40 | The capacity in slots, `u64`. |
| 40 to 44 | The slot size in bytes: 128, or 192 for version-2 slots. |
| 44 to 64 | Reserved, zero; the header is one cache line. |
| 64 onward | `capacity` slots of one Pulse each. |

A version-1 slot is 128 bytes, the Pulse itself, whose first 8 bytes are the slot's SeqLock counter. A version-2 slot is 192 bytes: the same 128-byte Pulse, then an 8-byte **ready line** at offset 128 that the writer bumps once after every publish, then padding to the next 64-byte boundary. The ready line exists so a receiver waiting in hardware (a monitor-and-wait instruction on the line) is woken by one write rather than by the two SeqLock stores; a reader MAY also poll it in place of the slot's counter (4.3). The reference publishes `HEADER_SIZE = 64`, `PULSE_SIZE = 128`, `PULSE_SIZE_V2 = 192` and `READY_LINE_OFFSET = 128`; a region MUST be `HEADER_SIZE + capacity × slot size` bytes. Whoever formats a region writes the version, the capacity and the slot size and then stores the magic with release ordering, so a reader whose acquire load sees the magic sees the rest. An implementation that opens a region MUST check its size and then its header before using it: the reference refuses a smaller object with `RegionTooSmall` and a header whose magic, version, capacity or slot size is not what it would map with `LayoutMismatch`, after waiting about fifty milliseconds on a zero magic for a creator that has sized the object but not yet published its header. `open_existing` takes the capacity and slot size from the header, so a reader need not know how the ring was made.

## 4.2 Writer protocol

To publish a Pulse into slot *i*, a writer MUST:

1. read the slot's counter and clear its low bit, so that a counter left odd by a writer that died is re-based rather than compounded;
2. store the odd value (the even base plus one) with release ordering, marking the write in progress;
3. issue a release fence, so the mark is visible before any payload byte;
4. copy the Pulse's bytes 8 to 128 into the slot, leaving the counter word alone;
5. store the even value (the base plus two) with release ordering, marking the slot stable;
6. on a version-2 slot, bump the ready line with release ordering.

The reference has seven publish paths (`publish`, `publish_returning_slot`, `publish_at_slot`, `publish_batch`, `publish_blocking`, `publish_batch_blocking` and `publish_with_crc`), and all seven write each slot by these steps; the counter is monotonic across them. Every path but `publish_at_slot` then advances `total_writes` and `write_cursor`, each with release ordering, so a reader whose acquire load sees either sees the slot stable. `publish_at_slot` overwrites a slot in place and moves neither, which is why the counter and ready-line readers of 4.3 exclude a ring it writes.

**Crashed writers.** A writer that dies between steps 2 and 5 leaves the counter odd. Readers give up on that slot (4.3) until the next publish into it, whose first step re-bases the counter, after which the slot reads normally. No reader ever accepts the torn contents.

**Publish modes.** In the default overwrite mode a publish always succeeds and a writer more than `capacity` ahead of a reader overwrites unread slots; the ring is lossy under sustained over-rate by design. In the blocking mode (`publish_blocking`) the writer spins while `write_cursor − read_cursor` would reach `capacity`, for workloads where every message matters.

## 4.3 Reader protocol

To read slot *i*, a reader MUST:

1. load the counter with acquire ordering; if it is odd, a write is in progress: retry;
2. copy the slot's bytes out;
3. issue an acquire fence, so the copy completes before the re-read;
4. load the counter again; if it differs from the first load, the slot changed under the copy: retry;
5. if the counter is zero, the slot has never been written: report nothing;
6. otherwise the copy is a consistent Pulse.

The retry is bounded. The reference tries one hundred times and then reports nothing, which is the correct answer for a slot whose writer died; an implementation MUST bound its retries so a dead writer cannot hang a reader. Readers never write, so a writer never waits for a reader.

### Readers that fall behind

A ring whose writer overwrites the oldest slot cannot promise a slow reader every publish, and it MUST NOT hand a reader the same publish twice or a newer lap's Pulse under an older index. The reference's readers that keep a cursor of their own, the SPMC ring and each multilane lane, apply one rule. Before a read, a cursor more than `capacity` behind the write cursor moves to `write cursor − capacity`, the oldest publish the ring still holds, and the publishes passed over are counted as lost. After the SeqLock copy, a copy the writer may have overwritten with the slot's next lap, because the write cursor has passed the cursor plus the capacity or the counter shows a write newer than the reader's lap, is discarded and counted; at the exact boundary the counter decides, and uncertainty is resolved as a counted loss. The SPMC ring reports a jump once as `Lagged { skipped }` and keeps a count per reader; a lane keeps a count per lane, and a round-robin poll that discarded a copy may return nothing for that pass, meaning retry. The hub runtime's `PulseHub::poll` does not yet apply this rule and can re-deliver after being lapped. The hub runtime's poll reads the same way through `PulseRing::read_position`, which the ring provides for any reader that walks the write positions in order: it returns each position's Pulse once, as itself, reports a position the writer has not reached as not written, or reports it lost together with every position up to the next one to read, and never returns a later lap's Pulse under an earlier position. The rule is the one above with the slot counter as the lap count: the counter starts at zero and each completed write adds two, so a stable copy whose counter shows more writes than the position's lap needs may hold the next lap and is counted lost. The counter can run ahead of the laps, after a writer that died between its slot write and its cursor move, a batch cut short the same way, or a `publish_at_slot`, and never behind them under the single-writer contract, so every case the reader cannot settle is a counted loss and never a Pulse twice. A hub attaching to a ring that already holds Pulses starts at the oldest one still held, so its count of lost Pulses excludes the history from before it attached. Two variants serve a ring written only through its cursor (`publish`, `publish_blocking` and the batch forms), never `publish_at_slot`, and keep the same promise. `read_position_by_counter` trusts the slot's counter alone: below the position's lap count the position is not written, above it the position is lost, and equal to it a stable copy that still shows that count is the position's Pulse. It loads the header's write cursor only to place a loss, so a reader in step with the writer shares no cache line the writer updates per message. `read_position_by_ready` reads a version-2 ring the same way with the slot's ready line as the lap count, one per completed write counted from one, so a reader waiting on it does not touch the slot's two lines while the writer is storing them; the copy must still show the position's counter, and on a version-1 ring it is `read_position_by_counter`. Either reports a loss with the oldest position the ring still holds, or the one after the lost position if that is later, as the next to read. Where `publish_at_slot` is in use, a counter run ahead could pass that slot's Pulse off as a position not yet written, so such a ring MUST be read with `read_position`.

The fences in steps 3 of both protocols are what make the protocol correct on weakly ordered processors; the vector for this chapter is executable rather than static: the reference's torn-read test drives four readers against one writer and asserts that no reader ever observes a Pulse with mixed bytes.

## 4.4 Integrity trailer

A writer MAY publish with a CRC32C trailer: the checksum of the Pulse's bytes 8 to 124, stored little-endian in bytes 124 to 128 of the slot, which is the tail of the Pulse's second padding field. A reader that verifies the trailer recomputes it over the same bytes and rejects a mismatch. The trailer sits at the same offset in version-1 and version-2 slots because both carry the Pulse in their first 128 bytes. `pms-crc32c` owns the computation.

## 4.5 Ownership and descriptors

A ring is created by name or opened by name (`open`). `create_exclusive` requires a free name and refuses one that holds an object. `create` and `create_or_open` are one call: a free name gets a new object, sized and formatted, that the handle owns and unlinks when it drops; a name that already holds a ring is attached as `open` attaches it, after the size and header checks, and is never resized, cleared or reformatted, so the Pulses a live ring holds survive the call on every platform, and a handle that attached does not unlink the name and reports `is_creator` false, which the hub runtime uses to make the creating hub the ring's one writer. Concurrent callers are safe: one creates and the others attach, after waiting out, for about fifty milliseconds, a creator that has made the object but not yet sized it. A capacity of zero, or one whose ring would not fit a file offset, is refused (`InvalidCapacity`) before anything is created. Everyone closes the descriptor they opened. A ring MAY also be built over a descriptor the caller already holds (`from_fd`), for memory-file-backed or NUMA-placed rings; such a ring never unlinks a name, and it closes the descriptor only when the caller hands over ownership. `from_fd` formats a fresh, zeroed region with the header it needs, and checks the header of a populated one the way `open` does. A version-2 ring is made with `create_exclusive_v2` or `from_fd_v2`; `open` refuses one, and `open_existing` attaches to either version. A new object is not zero-filled, since the kernel supplies zero pages; on Linux its pages are reserved with `posix_fallocate` when it is sized, so a `/dev/shm` without room for the ring is `NoSpace` at creation, with the half-made object unlinked, rather than SIGBUS at the first touch of a page; a reservation a signal interrupts is tried again, eight attempts in all (`RESERVE_ATTEMPTS`), and then reported the same way with `EINTR`. The envelope store, the single-slot region and the NUMA backing reserve their pages the same way, and the region's `create` creates or attaches as the ring's does.

## 4.6 What would refute this chapter

A reader that returns a Pulse whose bytes are not all from one publish, a writer that leaves a slot permanently unreadable after a crash, a reader that hangs on a dead writer, a region opened without a size check that faults on first access, a region whose header records another capacity or slot size than the caller's and maps anyway, a lapped reader that receives a publish twice or a newer lap under an older index, a `create` that resizes or clears a live ring, or a creation that a full `/dev/shm` answers with SIGBUS rather than an error, each contradicts this chapter. The reference's torn-read, crashed-writer, region-size, header, overrun, read-position, create and no-space tests are the checks.
