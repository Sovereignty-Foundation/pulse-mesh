# The ring inside your process

<p class="pm-kind"><b>Workflow</b> · for a Rust developer who wants the shared-memory ring and the envelope store without the daemon; about fifteen minutes, with the standard alone</p>

<figure class="pm-art"><svg class="uc-diagram" viewBox="0 0 380 240" role="img" aria-label="The ring carries the signal, the store holds the content"><circle cx="190" cy="120" r="58" class="uc-ring"/><circle cx="190" cy="120" r="46" class="uc-ring-dash"/><line x1="236.0" y1="120.0" x2="248.0" y2="120.0" class="uc-edge"/><line x1="232.5" y1="137.6" x2="243.6" y2="142.2" class="uc-edge"/><line x1="222.5" y1="152.5" x2="231.0" y2="161.0" class="uc-edge"/><line x1="207.6" y1="162.5" x2="212.2" y2="173.6" class="uc-edge"/><line x1="190.0" y1="166.0" x2="190.0" y2="178.0" class="uc-edge"/><line x1="172.4" y1="162.5" x2="167.8" y2="173.6" class="uc-edge"/><line x1="157.5" y1="152.5" x2="149.0" y2="161.0" class="uc-edge"/><line x1="147.5" y1="137.6" x2="136.4" y2="142.2" class="uc-edge"/><line x1="144.0" y1="120.0" x2="132.0" y2="120.0" class="uc-edge"/><line x1="147.5" y1="102.4" x2="136.4" y2="97.8" class="uc-edge"/><line x1="157.5" y1="87.5" x2="149.0" y2="79.0" class="uc-edge"/><line x1="172.4" y1="77.5" x2="167.8" y2="66.4" class="uc-edge"/><line x1="190.0" y1="74.0" x2="190.0" y2="62.0" class="uc-edge"/><line x1="207.6" y1="77.5" x2="212.2" y2="66.4" class="uc-edge"/><line x1="222.5" y1="87.5" x2="231.0" y2="79.0" class="uc-edge"/><line x1="232.5" y1="102.4" x2="243.6" y2="97.8" class="uc-edge"/><text x="190" y="200" class="uc-label">ring, 64 slots</text><circle cx="50" cy="120" r="16" class="uc-node-strong"/><text x="50" y="156" class="uc-label">writer</text><line x1="66" y1="120" x2="132" y2="120" class="uc-edge"/><rect x="300" y="100" width="40" height="40" rx="2" class="uc-node"/><text x="320" y="160" class="uc-label">reader</text><line x1="248" y1="120" x2="300" y2="120" class="uc-edge"/><rect x="150" y="26" width="80" height="22" rx="2" class="uc-frame"/><text x="190" y="20" class="uc-label">store</text><line x1="190" y1="48" x2="190" y2="62" class="uc-edge-dash"/><text x="190" y="226" class="uc-label">the pulse carries the envelope's name</text><circle class="uc-pulse" r="3"><animateMotion dur="1.6s" begin="0s" repeatCount="indefinite" path="M66,120 L132,120"/></circle><circle class="uc-pulse" r="2.5"><animateMotion dur="1.6s" begin="0.8s" repeatCount="indefinite" path="M248,120 L300,120"/></circle></svg><figcaption>The ring carries the signal, the store holds the content</figcaption></figure>

**You will have:** one program that creates a ring and a store in shared memory under a name, publishes a Pulse that points at an envelope, opens both again by name the way a second process would, and reads the Pulse and the envelope back, verified; the ring's and the store's own test suites run; and the edges seen rather than read about: a ring opened with the wrong capacity, a ring opened by name alone, two envelopes with the same content, a fetch of an envelope never stored, and the names gone once their creator drops.

**You need:** the standard's repository set up as [Start here](../start/onboard-your-agent.md) describes, and the Rust toolchain, on Linux or macOS: the ring and the store are POSIX shared memory.

The daemon is a convenience on top of two primitives. The ring carries 128-byte Pulses through shared memory with no lock, and the store beside it holds payloads under their content identifiers. Both come from the `core-ring` and `core-store` crates, and any process can use them.

## Hand this to your agent

```text
Run the workflow "The ring inside your process" from book/src/workflows/ring-in-process.md in the pulse-mesh repository:
1. Run cargo run --release -p example-03-embed-ring-rust and show me its output. Expect one line beginning "OK — published one Pulse referencing envelope b6a5ee1e601cf94a3bd3ba244ddc0ee8".
2. Read examples/03-embed-ring-rust/src/main.rs and explain in plain words what crosses the ring and what sits in the store, and how the reader knows its copy of a slot is whole.
3. Beside the repositories, make a crate (cargo new ring-edges) with path dependencies core-ring, core-store and pulse-canon on ../pulse-mesh/core/core-ring, ../pulse-mesh/core/core-store and ../pulse-mesh/pulse/pulse-canon; save the edges program from the page as src/main.rs and run it. Expect: a capacity-mismatch error for the open with the wrong capacity, 64 from open_existing, "same id: true", "None" for the fetch, 0 publishes before any, and an shm_open error with errno 2 after the creator dropped.
4. Run cargo test -p core-ring --release and cargo test -p core-store --release in pulse-mesh and show me the result lines; they hold the ring and the store to the rules the specification states.
Stop and tell me if anything fails, and say which step.
```

## Or do it by hand

### 1. Run the example

From the repository root:

```bash
cargo run --release -p example-03-embed-ring-rust
```

```text
OK — published one Pulse referencing envelope b6a5ee1e601cf94a3bd3ba244ddc0ee8 and read both back through a second handle.
```

The envelope's identifier is the same on every run and every machine, because it is a hash of the envelope's content and the content is fixed.

### 2. Create the ring and the store, and publish

The program is `examples/03-embed-ring-rust`; these two listings are its `main`, apart from choosing a name and the final line.

```rust
{{#include ../../../examples/03-embed-ring-rust/src/main.rs:create}}
```

`PulseRing::create` makes a shared-memory object named `/pms-example-<pid>`, sizes it for a 64-byte header plus 64 slots of 128 bytes, and maps it; under a name that already holds a ring it attaches to that ring as it stands instead, and a handle that attached does not unlink the name when it drops. `EnvelopeStore::create_or_open` does the same for the store. `store` writes the envelope once, under its identifier. The Pulse is the signal: a `Data` instruction whose envelope reference `set_envelope_id` sets to the envelope's identifier. `publish` marks the next slot's counter odd, copies the Pulse in, marks the counter even, and advances the cursor; it returns 1 because this is the ring's first publish.

### 3. Open both by name and read

```rust
{{#include ../../../examples/03-embed-ring-rust/src/main.rs:read}}
```

`PulseRing::open` attaches to the existing object, checks its size and then the header the creator wrote, and refuses a ring whose header records another capacity or slot size, so a mismatch is an error rather than a fault; `PulseRing::open_existing` opens a ring by name alone and takes the geometry from the header. The newest slot is one behind the cursor. `read_slot` copies it and keeps the copy only if the slot's counter was even before the copy and unchanged after it; it retries up to a hundred times and returns `None` if the slot was never written or a writer is stuck on it. `envelope_id` reads the reference back as an identifier, `fetch` looks the envelope up by it, and `verify` recomputes the identifier from the content.

The creator unlinks the shared-memory names when it drops, so running the program twice leaves nothing behind.

### 4. See the edges

Beside the repositories, `cargo new ring-edges`, with these under `[dependencies]`:

```toml
core-ring = { path = "../pulse-mesh/core/core-ring" }
core-store = { path = "../pulse-mesh/core/core-store" }
pulse-canon = { path = "../pulse-mesh/pulse/pulse-canon" }
```

and this as `src/main.rs`:

```rust
use core_ring::PulseRing;
use core_store::EnvelopeStore;
use pulse_canon::PulseEnvelope;

fn main() {
    let name = format!("/pms-edges-{}", std::process::id());
    let ring = PulseRing::create(&name, 64).expect("create");

    if let Err(e) = PulseRing::open(&name, 32) {
        println!("open with the wrong capacity: {e}");
    }
    let by_header = PulseRing::open_existing(&name).expect("open_existing");
    println!("open_existing took the capacity from the header: {}", by_header.capacity());

    let store = EnvelopeStore::create_or_open(&format!("{name}-env"), 16).expect("store");
    let a = PulseEnvelope::typed("event.fired", b"payload".to_vec());
    let b = PulseEnvelope::typed("event.fired", b"payload".to_vec());
    println!("two envelopes with the same content, same id: {}", a.id() == b.id());
    store.store(&a).expect("store a");
    let c = PulseEnvelope::typed("event.fired", b"payloaD".to_vec());
    println!("fetch of an envelope never stored: {:?}", store.fetch(&c.id()).map(|e| e.id()));

    println!("reader sees {} publish(es) before any", ring.cursor_position());
    drop(ring);
    if let Err(e) = PulseRing::open_existing(&name) {
        println!("open after the creator dropped: {e}");
    }
}
```

```bash
cargo run --release
```

```text
open with the wrong capacity: ring header capacity mismatch: the region has 64, the caller expects 32
open_existing took the capacity from the header: 64
two envelopes with the same content, same id: true
fetch of an envelope never stored: None
reader sees 0 publish(es) before any
open after the creator dropped: shm_open failed: errno 2
```

### 5. Run the rules under test

```bash
cargo test -p core-ring --release
cargo test -p core-store --release
```

Every `test result` line reads `ok`. The ring's suites include the torn-read test: one writer as fast as it can against four readers, counting reads assembled from two publishes, and the count is zero.

## Check it worked

| Check | Command | Pass |
|---|---|---|
| A Pulse and its envelope crossed to a second handle and verified | `cargo run --release -p example-03-embed-ring-rust` | The `OK —` line with `b6a5ee1e601cf94a3bd3ba244ddc0ee8` |
| A mismatched open is an error, not a fault | The edges program | `ring header capacity mismatch: the region has 64, the caller expects 32`, then `64` from `open_existing` |
| Identity is content | The edges program | `same id: true`; the never-stored envelope fetches `None` |
| The creator owns the names | The edges program | `shm_open failed: errno 2` after `drop(ring)` |
| The guarantees hold | `cargo test -p core-ring --release`, `cargo test -p core-store --release` | Every result line `ok` |

If `create` fails with `RegionTooSmall` or `LayoutMismatch`, the name holds something other than a ring of that capacity, likely left by a program that did not exit cleanly; `create` never resizes or reformats an object, so pick another name or remove it. A leftover ring of the same capacity is attached to as it stands, old slots and cursor included, and a handle that attached does not unlink it. On Linux, `NoSpace` at creation means `/dev/shm` cannot hold the ring or the store; the pages are reserved when the object is made, so this is an error then rather than a fault at the first touch.

## What happened

- **The ring is the signal, the store is the content.** A 128-byte Pulse carries the envelope's 16-byte identifier; the envelope sits in the store under that identifier, written once. Any process that maps both by name reads the Pulse, fetches the envelope, and verifies it by recomputing the identifier from the content.
- **A reader never sees a torn Pulse.** Each slot carries a counter that is odd while a write is in progress and even when the slot is stable. A reader copies the slot and keeps the copy only if the counter was even before and unchanged after; otherwise it retries, up to a hundred times, and reports nothing for a slot whose writer died mid-write. Readers never write, so the writer never waits for a reader. [The SeqLock ring](../reference/spec/04-ring.md) states the protocol; [The SeqLock memory model](../explanation/seqlock-memory-model.md) says why it holds.
- **Geometry is checked, not assumed.** The ring's header records its capacity and slot size, and `open` refuses a header that disagrees with what the caller expects; `open_existing` takes the geometry from the header and needs no capacity.
- **The creator owns the names.** A handle that created an object unlinks its name when it drops; a handle that attached does not. Running a program twice leaves nothing behind, and a second process must open the names while the creator lives.
- **Identity is content.** Two envelopes with the same type name and payload have the same identifier, so the store holds one copy per distinct envelope, and a fetch by an identifier nothing was stored under is `None`.

What these two do not do: the ring overwrites the oldest slot when it is full, so a reader more than a capacity behind loses publishes; one that walks positions with `read_position` is told which, as lost ([the ring chapter](../reference/spec/04-ring.md), readers that fall behind); the store is shared memory and vanishes with its creator, so it is not persistence (the daemon's basket is the record); and neither routes, so two programs that share a ring agree on its name out of band, which is what the daemon does for them.

## Make it yours

- **Two real processes.** One program creates the ring and the store and publishes; another opens them by name with `PulseRing::open_existing` and `EnvelopeStore::open_existing` (or `open(name, capacity)`) and reads; a reader must not `create_or_open` the store, or one that starts after the creator has gone makes a fresh, empty store instead of failing. Keep the creator running while the reader opens.
- **Walk every publish.** `PulseRing::read_position(position)` returns each position's Pulse once, as itself, reports a position the writer has not reached as not written, and reports a lapped position as lost; it is what the daemon's runtime polls with.
- **Many readers, no copy per reader.** [HFT: one feed, many readers](/docs/profiles/workflows/hft-fanout.html) does this in process memory; across processes, `PulseRing::create_with_readers(name, capacity, max_readers)` gives each reader a cursor and `publish_blocking` keeps the slowest registered reader's pace.
- **Payloads too large for a store slot.** [Robotics: a 4 MiB scan through shared memory](/docs/profiles/workflows/robotics-large-payload.html) puts the payload in a pool and a 16-byte reference in the Pulse.

## Next

- [The SeqLock ring](../reference/spec/04-ring.md) and [The envelope store](../reference/spec/05-store.md): the chapters these crates are held to.
- [Why a 128-byte atom](../explanation/why-128-bytes.md) and [Why content addressing](../explanation/why-content-addressing.md): the two decisions underneath.
- [Two programs talk through the daemon](/docs/daemon/examples/two-programs.html): the same two primitives behind a socket, with routing.

## Spoken walkthrough

*A script for the video and audio version of this page, about ninety seconds.*

Take the daemon away, and two things are left: a ring and a store, both in shared memory, both opened by name.

The program creates them, writes an envelope into the store, and publishes one Pulse into the ring. The Pulse is a hundred and twenty-eight bytes, and sixteen of them are the envelope's identifier, a hash of its content.

Then it opens both again by name, the way a second process would, reads the newest slot, fetches the envelope by the identifier the Pulse carries, and verifies it by recomputing the hash. One line: OK.

How does the reader know its copy of the slot is whole? Each slot has a counter. Odd while a write is happening, even when it is done. The reader copies, checks the counter was even before and unchanged after, and otherwise copies again. The writer never waits for anyone.

The second program walks the edges. Open the ring with the wrong capacity, and it tells you what the header says. Open it by name alone, and it takes the geometry from the header. Make two envelopes with the same content, and they have the same identifier. Ask for one you never stored, and you get none. Drop the creator, and the names are gone. Everything the daemon does for you, you have just done by hand.
