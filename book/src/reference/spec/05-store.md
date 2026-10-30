# 5. The envelope store

<p class="pm-kind"><b>Reference · normative for the reference implementation</b> · the content-addressed shared-memory store beside the ring; other implementations MAY store envelopes differently and conform through chapter 8</p>

When a Pulse's `envelope_ref` is not zero, the envelope it names lives in an envelope store: a shared-memory circular buffer of envelopes in their canonical encoding that sits beside a ring. Readers resolve the reference by content identifier, so two Pulses that reference the same content share one entry. The reference type is `core_store::EnvelopeStore`; the layout below is version 2, adopted in decisions 0008 and 0011 of the decision record.

## 5.1 Region layout, version 2

| Bytes | Contents |
|---|---|
| 0 to 8 | The write cursor, atomic `u64`: a claim counter that hands out cursors and proves nothing about contents. |
| 8 to 12 | The magic `PMES`, stored last when the region is created, with release ordering. |
| 12 to 16 | The layout version, `2`. |
| 16 to 20 | The capacity in slots. |
| 20 to 24 | The maximum entry size in bytes, 65,536 in this build. |
| 24 to 32 | Busy claims, atomic `u64`: claims that found their slot held or taken and gave up their cursor. |
| 32 to 64 | Reserved, zero. |
| 64 onward | `capacity` slots of 64 + 65,536 bytes each. |

Each slot begins with a 64-byte header: a sequence word at 0 to 8 (`0` never written, `2·lap + 1` while a write is in progress, `2·lap + 2` once published, where `lap` is the cursor divided by the capacity), the envelope's identifier at 8 to 24, the body length at 24 to 28, and reserved zeros to 64; the body, the envelope's canonical encoding (3.1), follows and is at most the maximum entry size, so an envelope with no type name and a raw payload carries up to 65,486 payload bytes. A store for the runtime's 256 slots is a little over sixteen megabytes.

An implementation that opens a store MUST check the region's size and then its header, and refuse a region whose magic, version, capacity or maximum entry size disagree with its own (`LayoutMismatch`). A version-1 region, whose bodies were JSON, is refused on its version. There is no migration, because no store outlives the daemon that created it. A store is created as a ring is: the region is sized and, on Linux, its pages are reserved with `posix_fallocate` before the header is written, so shared memory without room for it is `NoSpace` at creation rather than SIGBUS later; a store the daemon's hub cannot create for lack of room is logged, and the hub runs without persistence. A capacity of zero, above the header's 32-bit field, or whose region would not fit a file offset is refused (`InvalidCapacity`) by `open` and by every creator alike, before anything is opened or created.

## 5.2 Writer protocol

To store an envelope, a writer:

1. encodes it canonically and refuses a body larger than the maximum entry size (`EnvelopeTooLarge`, naming the canonical size) before claiming anything;
2. claims a cursor by incrementing the write cursor;
3. claims the slot for that cursor by moving its sequence word from an even value no newer than `2·lap` to `2·lap + 1` with a compare-and-swap; a claim never starts from an odd word, so no writer ever writes a slot another writer holds;
4. if the slot is held (another writer mid-store, or one that died there) or already taken by a newer lap, leaves it alone, adds one to the busy-claims counter, and returns to step 2 for a fresh cursor, up to four cursors in all, after which the store fails with `SlotBusy` naming the last cursor tried;
5. issues a release fence and writes the identifier, the length and the body;
6. stores `2·lap + 2`.

The cursor is handed out before the body exists, so the cursor alone is never evidence that a slot holds data; the sequence word is. A cursor given up in step 4 is never written, and readers skip it.

## 5.3 Reader protocol

A reader trusts a slot only when its sequence word is the published value for the cursor it wants both before and after the body is copied out, with an acquire fence between the copy and the second load, and it copies the body before decoding it rather than decoding shared memory in place. As defence in depth against a copy corrupted or torn outside that protocol, it returns an envelope only if its copy decodes as exactly one canonical envelope whose identifier is the slot's and whose content verifies against that identifier; nothing is returned unverified. A reader spends its retry budget only on the writer of the cursor it wants, and skips at once a slot held by an older lap's writer, because that cursor's own writer routed around the held slot rather than wait for it.

`fetch` by identifier scans the slots and skips any that is unwritten, in progress, held by an older lap, torn, has an implausible length or does not decode and verify, rather than ending the scan. `read_since(cursor)` returns the envelopes for consecutive cursors from the later of the requested cursor and the oldest cursor still in the region; it skips a cursor whose own writer has not published within the reader's budget (stalled or dead mid-store, or yet to claim), skips at once a cursor whose slot is held by an older lap, skips a slot lapped during the call, and returns the cursor to resume from, so a streaming reader neither wedges on a dead writer nor mistakes a lapped slot's stale body for new data. Nothing older than `write cursor − capacity` is ever returned.

## 5.4 What this store is and is not

The store is a cache as much as a store: identical content is stored once and a thousand Pulses carrying the same event reference one entry. Its maximum entry size is a deployment tunable recorded in the header, not a limit on the envelope contract (3.7). Sizing the region to the envelopes actually stored, rather than reserving the maximum per slot, is a hub-configuration question outside this chapter. A writer that dies between its odd and even marks holds its slot until the region is recreated; it loses its own envelope and no other, because each later claim on that slot routes to the next cursor, at the cost of one cursor and one busy claim per lap. Taking over a stale mark was considered and rejected: the age of a mark cannot tell a dead writer from a preempted one, and taking over a live writer's slot would tear its store.

## 5.5 What would refute this chapter

A reader that returns a body from a slot whose sequence word was not the published value for the cursor it asked for, or a body that does not verify against the slot's identifier; a `read_since` that returns an envelope older than the window or skips silently past a live slot; a second writer that overwrites a slot another writer holds; a claim that gives up before its fourth cursor or leaves the busy count unchanged; or an `open` that maps a region of another layout, each contradicts this chapter. The reference's layout, lapping, held-slot and publish-visibility tests are the checks; the last runs four readers against a writer for four hundred milliseconds and asserts that every returned envelope verifies and carries the cursor arithmetic.
