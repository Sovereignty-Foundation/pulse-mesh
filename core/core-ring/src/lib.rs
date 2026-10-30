// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! `PulseRing`: the SeqLock ring, tier 1.
//!
//! A fixed-capacity ring of Pulse slots in POSIX shared memory, with one
//! writer and any number of readers. Each slot's sequence counter is odd
//! while a write is in progress. A reader keeps its copy of a slot only if
//! the counter was even and unchanged across the copy, and gives up after a
//! bounded number of retries, so a writer that died mid-write never hangs a
//! reader; the next publish into that slot re-bases its counter.
//!
//! Layout in shared memory, little-endian:
//!
//! | bytes      | contents                                |
//! |------------|-----------------------------------------|
//! | `0..8`     | `AtomicU64` write_cursor                |
//! | `8..16`    | `AtomicU64` total_writes                |
//! | `16..24`   | `AtomicU64` read_cursor (for blocking-publish backpressure) |
//! | `24..28`   | `AtomicU32` magic `PMSR`, stored last when the ring is formatted |
//! | `28..32`   | `u32` layout version, [`LAYOUT_VERSION`] |
//! | `32..40`   | `u64` capacity in slots                 |
//! | `40..44`   | `u32` slot size in bytes: 128, or 192 in version 2 |
//! | `44..48`   | `AtomicU32` superseded: 0 while the ring's writer uses it, 1 once the ring is superseded |
//! | `48..64`   | reserved, zero (the header is one cache line) |
//! | `64..`     | N × 128-byte pulse slots (192-byte slots with a ready line in version 2) |
//!
//! - Making and opening: [`PulseRing::create_exclusive`] makes a ring under
//!   a free name, [`PulseRing::create_or_open`] also attaches to a ring
//!   already there, [`PulseRing::open`] and [`PulseRing::open_existing`]
//!   attach, and [`PulseRing::from_fd`] maps a descriptor the caller holds.
//!   [`PulseRing::create_exclusive_v2`] and [`PulseRing::from_fd_v2`] make
//!   version-2 rings, whose slots carry a ready line for readers that wait.
//!   No constructor resizes or clears a live ring, and every open checks
//!   the size and the header before it maps anything (ADR-0015).
//! - Writing: [`PulseRing::publish`] overwrites and never blocks;
//!   [`PulseRing::publish_blocking`] waits for the reader: the one read
//!   cursor in the header, or, on a ring made with a reader table
//!   ([`PulseRing::create_with_readers`], ADR-0019), the slowest of the
//!   readers registered there ([`PulseRing::register_reader`]), so every
//!   registered reader sees every pulse. Every
//!   publish takes `&mut self`, so a handle has one writer, and readers in
//!   the writer's process read through a handle of their own. One writer
//!   per ring across handles and processes is the owner's to keep: the hub
//!   runtime's owner lock keeps it for a hub.
//! - Reading: [`PulseRing::read_slot`] reads a slot;
//!   [`PulseRing::read_position`] walks the write positions in order and
//!   reports those overwritten before it read them as lost;
//!   [`PulseRing::read_position_by_counter`] and, on a version-2 ring,
//!   [`PulseRing::read_position_by_ready`] do the same for a ring written
//!   only through its cursor, watching the slot's counter or its ready line.
//! - Retiring: a ring is marked superseded before its name goes
//!   ([`PulseRing::supersede`]), so a reader still mapped to it knows to
//!   reopen the name.
//!
//! The shared-memory calls are `core_region::shm`'s (ADR-0013).
//!
//! In the book: <https://pulse-mesh.net/docs/reference/spec/04-ring.html> and
//! <https://pulse-mesh.net/docs/explanation/seqlock-memory-model.html>.

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use core_region::shm::{self, Mapping, Name, Opened};
use pulse_canon::Pulse;

mod overrun;
mod readers;
pub use overrun::PositionRead;
use readers::ReaderTable;
pub use readers::{ReaderSlot, MAX_READERS, READERS_NAME_MAX, READERS_SUFFIX};

/// Slot size in bytes: a Pulse's wire size, [`pulse_canon::PULSE_WIRE_SIZE`].
pub const PULSE_SIZE: usize = pulse_canon::PULSE_WIRE_SIZE;
/// Header bytes: a ring spans `HEADER_SIZE + capacity × slot size` bytes.
pub const HEADER_SIZE: usize = 64;
/// Header layout version, recorded in every ring and checked by every open.
/// The slot format is recorded separately, as the slot size.
pub const LAYOUT_VERSION: u32 = 1;
const MAGIC: u32 = u32::from_le_bytes(*b"PMSR");
// Header field offsets; the layout table in the module docs.
const H_MAGIC: usize = 24;
const H_VERSION: usize = 28;
const H_CAPACITY: usize = 32;
const H_SLOT_SIZE: usize = 40;
const H_SUPERSEDED: usize = 44;
const SUPERSEDED: u32 = 1;
pub use core_region::shm::RESERVE_ATTEMPTS;

/// Slot size in bytes of a version-2 ring: the Pulse, then a data-ready
/// line of its own cache line ([`PulseRing::ready_line_atomic`]).
pub const PULSE_SIZE_V2: usize = READY_LINE_OFFSET + 64;
/// Offset in a version-2 slot of its data-ready `AtomicU64`.
pub const READY_LINE_OFFSET: usize = PULSE_SIZE;

#[non_exhaustive]
/// Errors returned by `PulseRing` operations.
#[derive(Debug)]
pub enum RingError {
    /// `shm_open(3)`, `fstat(2)` or a header read failed; the field is the
    /// `errno`.
    Open(i32),
    /// `ftruncate` failed; the field is the `errno`.
    Truncate(i32),
    /// Linux could not reserve a new ring's pages: `posix_fallocate(3)`
    /// failed, with `ENOSPC` on a full `/dev/shm`, `ENOMEM`, or `EINTR`
    /// after [`RESERVE_ATTEMPTS`] tries. Nothing was mapped: a creator by
    /// name unlinked its object, and [`PulseRing::from_fd`] left the
    /// descriptor open and unformatted. Never returned off Linux.
    NoSpace {
        /// Bytes the object needed.
        need: u64,
        /// The error number `posix_fallocate` returned.
        errno: i32,
    },
    /// `mmap` failed; the field is the `errno`.
    Map(i32),
    /// `shm_unlink` failed; the field is the `errno`.
    Unlink(i32),
    /// The ring name contains a NUL byte, or is not a valid hub name.
    InvalidName,
    /// Zero slots; or, from a constructor that sizes or formats a region, a
    /// ring whose size, `HEADER_SIZE + capacity × slot size`, does not fit
    /// a `usize` and a file offset. Nothing was created, opened or mapped.
    InvalidCapacity {
        /// Slots asked for.
        capacity: u64,
    },
    /// A batch publish was given more pulses than the ring has slots;
    /// nothing was written. Publish at most `capacity` pulses per batch.
    BatchTooLarge {
        /// Pulses in the batch.
        len: usize,
        /// Slots in the ring.
        capacity: u64,
    },
    /// A blocking publish waited its whole timeout and the slowest reader
    /// never freed the room it needed: it stopped, died, or there is none.
    /// Nothing was published, so the call can be retried.
    Stalled {
        /// Positions written and not yet read when the publish gave up.
        in_flight: u64,
        /// How long the publish waited.
        waited: Duration,
        /// On a ring with a reader table, the line of the slowest reader,
        /// which [`PulseRing::evict_reader`] frees.
        slowest_reader: Option<u32>,
    },
    /// [`PulseRing::register_reader`] on a ring made without a reader
    /// table.
    NoReaderTable,
    /// Every line of the ring's reader table is taken.
    ReadersFull {
        /// Lines in the table.
        max: usize,
    },
    /// A reader table of `max_readers` lines: it needs from 1 to
    /// [`MAX_READERS`]. Nothing was created.
    InvalidReaders {
        /// Lines asked for.
        max_readers: u32,
    },
    /// A derived shared-memory name exceeds the platform limit.
    NameTooLong {
        /// Bytes the name would have.
        len: usize,
        /// Bytes allowed.
        max: usize,
    },
    /// The object is smaller than the ring the caller asked to map, which
    /// would fault past its end.
    RegionTooSmall {
        /// Size of the object, from `fstat(2)`.
        have: u64,
        /// Bytes the ring needs.
        need: u64,
    },
    /// The header does not describe the ring the caller maps: the magic is
    /// not `PMSR` (not a ring, or not yet formatted), or the layout
    /// version, capacity or slot size differs.
    LayoutMismatch {
        /// `magic`, `version`, `capacity` or `slot_size`.
        field: &'static str,
        /// Value found in the header.
        have: u64,
        /// Value the caller needs.
        need: u64,
    },
    /// [`PulseRing::read_slot_verify_crc`] found a slot whose CRC32C
    /// trailer does not match its data.
    CrcMismatch {
        /// Slot whose CRC failed.
        slot: u64,
        /// CRC32C from the slot trailer (bytes 124..128).
        expected: u32,
        /// CRC32C computed at read time over bytes 8..124.
        computed: u32,
    },
}

impl std::fmt::Display for RingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Open(e) => write!(f, "shm_open failed: errno {}", e),
            Self::Truncate(e) => write!(f, "ftruncate failed: errno {}", e),
            Self::NoSpace { need, errno } => write!(
                f,
                "could not reserve {need} bytes of shared memory: posix_fallocate failed with errno {errno}"
            ),
            Self::Map(e) => write!(f, "mmap failed: errno {}", e),
            Self::Unlink(e) => write!(f, "shm_unlink failed: errno {}", e),
            Self::InvalidName => write!(f, "ring name contains NUL byte"),
            Self::InvalidCapacity { capacity } => write!(
                f,
                "a ring of {capacity} slots cannot be made or opened: it needs at least one slot, and its size in bytes must fit a file offset"
            ),
            Self::BatchTooLarge { len, capacity } => write!(
                f,
                "a batch of {len} pulses does not fit a ring of {capacity} slots; nothing was published"
            ),
            Self::Stalled {
                in_flight,
                waited,
                slowest_reader,
            } => {
                write!(
                    f,
                    "blocking publish stalled for {waited:?} with {in_flight} positions unread; nothing was published"
                )?;
                match slowest_reader {
                    Some(line) => write!(f, " (the slowest reader holds line {line})"),
                    None => Ok(()),
                }
            }
            Self::NoReaderTable => f.write_str("the ring was made without a reader table"),
            Self::ReadersFull { max } => {
                write!(f, "every one of the reader table's {max} lines is taken")
            }
            Self::InvalidReaders { max_readers } => write!(
                f,
                "a reader table of {max_readers} lines cannot be made: it needs from 1 to {MAX_READERS}"
            ),
            Self::NameTooLong { len, max } => {
                write!(f, "shared-memory name is {len} bytes; the limit is {max}")
            }
            Self::RegionTooSmall { have, need } => write!(
                f,
                "shared-memory object is {have} bytes but the requested capacity needs {need}"
            ),
            Self::LayoutMismatch {
                field: "magic",
                have,
                need,
            } => write!(
                f,
                "shared-memory object is not a formatted ring: magic {have:#010x}, expected {need:#010x}"
            ),
            Self::LayoutMismatch { field, have, need } => write!(
                f,
                "ring header {field} mismatch: the region has {have}, the caller expects {need}"
            ),
            Self::CrcMismatch {
                slot,
                expected,
                computed,
            } => write!(
                f,
                "CRC32C mismatch at slot {}: expected {:#010x}, computed {:#010x}",
                slot, expected, computed
            ),
        }
    }
}

impl std::error::Error for RingError {}

fn shm_error(e: shm::Error) -> RingError {
    match e {
        shm::Error::Open(e) => RingError::Open(e),
        shm::Error::Truncate(e) => RingError::Truncate(e),
        shm::Error::NoSpace { need, errno } => RingError::NoSpace { need, errno },
        shm::Error::Map(e) => RingError::Map(e),
        shm::Error::InvalidName => RingError::InvalidName,
        shm::Error::TooSmall { have, need } => RingError::RegionTooSmall { have, need },
    }
}

/// Hand the slot's two cache lines to the shared L3 once a write is done
/// (`cldemote`, where the x86_64 part has it), so the reader's next fetch
/// of them is served by the L3 rather than by a snoop of the writer's
/// private cache, which on a mesh part costs it two to three times as long.
/// A hint: it changes nothing a reader can observe. Nothing elsewhere.
#[inline(always)]
fn demote_slot(slot_ptr: *mut u8) {
    #[cfg(target_arch = "x86_64")]
    if cldemote_available() {
        // SAFETY: cldemote is a cache hint on the lines holding `slot_ptr`
        // and `slot_ptr + 64`, both inside the slot (a slot spans at least
        // 128 bytes); it reads and writes no memory and never faults.
        unsafe {
            core::arch::asm!(
                "cldemote [{a}]",
                "cldemote [{b}]",
                a = in(reg) slot_ptr,
                b = in(reg) slot_ptr.add(64),
                options(nostack, preserves_flags, readonly)
            );
        }
    }
    #[cfg(not(target_arch = "x86_64"))]
    let _ = slot_ptr;
}

/// On aarch64, clean the slot's two cache lines to the point of coherency
/// (`dc cvac`) before a version-2 ring's ready line moves, so the readers
/// watching it fetch the lines from the shared level instead of each
/// snooping the writer's cache. On Graviton4 with 4 to 16 pinned readers
/// it cut the paced p99 latency to the last reader by 5 to 32% (the most
/// at 16) and kept the first reader's flat, and it cost 21 to 55% of burst
/// throughput for the write-back, which is why only version-2 rings, the
/// layout for readers that wait, take it. Linux and macOS let user space issue `dc cvac`. A hint: it
/// changes no value a reader can observe. Nothing elsewhere; x86_64 demotes
/// every slot already ([`demote_slot`]).
#[inline(always)]
fn clean_slot(slot_ptr: *mut u8) {
    #[cfg(target_arch = "aarch64")]
    // SAFETY: `dc cvac` cleans the lines holding `slot_ptr` and
    // `slot_ptr + 64`, both inside the slot; it changes no value and never
    // faults on mapped memory. Not `nomem`: the payload stores before it
    // stay before it.
    unsafe {
        core::arch::asm!(
            "dc cvac, {a}",
            "dc cvac, {b}",
            a = in(reg) slot_ptr,
            b = in(reg) slot_ptr.add(64),
            options(nostack, preserves_flags)
        );
    }
    #[cfg(not(target_arch = "aarch64"))]
    let _ = slot_ptr;
}

/// Whether this x86_64 part has `cldemote` (CPUID.(EAX=7,ECX=0):ECX[25]),
/// read once.
#[cfg(target_arch = "x86_64")]
#[inline(always)]
fn cldemote_available() -> bool {
    use std::sync::atomic::AtomicU8;
    static STATE: AtomicU8 = AtomicU8::new(0);
    match STATE.load(Ordering::Relaxed) {
        1 => true,
        2 => false,
        _ => {
            let has = (core::arch::x86_64::__cpuid_count(7, 0).ecx >> 25) & 1 == 1;
            STATE.store(if has { 1 } else { 2 }, Ordering::Relaxed);
            has
        }
    }
}

/// A SeqLock ring of Pulse slots in POSIX shared memory.
pub struct PulseRing {
    map: Mapping,
    capacity: u64,
    owner: bool,
    /// [`PULSE_SIZE`], or [`PULSE_SIZE_V2`] for a version-2 ring.
    slot_size: usize,
    /// The reader's cursor as this writer last saw it: the header's, or
    /// the slowest registered reader's. It only moves forward, so the value
    /// still bounds the room until the ring looks full, and a blocking
    /// publish reads the shared cursors only then.
    read_cursor_seen: u64,
    /// The ring's reader table, when it has one and this handle has it.
    readers: Option<Arc<ReaderTable>>,
}

// SAFETY: the ring owns its mapping, valid until it drops and tied to no
// thread. Through `&self` the header words change only as atomics, and a
// slot's bytes only as atomic words under its SeqLock (`write_slot`, and
// `read_slot`, which keeps a copy only if the counter was even and
// unchanged across it). Every publish takes `&mut self`, so no two
// publishes run through one handle at once.
unsafe impl Send for PulseRing {}
// SAFETY: as for `Send` above.
unsafe impl Sync for PulseRing {}

impl PulseRing {
    /// [`PulseRing::create_or_open`]: create a ring of `capacity` 128-byte
    /// slots under `name`, or attach to the ring already there.
    ///
    /// # Errors
    ///
    /// Those of [`PulseRing::create_or_open`].
    pub fn create(name: &str, capacity: u64) -> Result<Self, RingError> {
        Self::create_or_open(name, capacity)
    }

    /// Create a ring of `capacity` 128-byte slots under a name that must
    /// be free. The handle is the ring's creator ([`PulseRing::is_creator`]).
    ///
    /// On Linux the pages are reserved before the object is mapped, so a
    /// full `/dev/shm` is [`RingError::NoSpace`] here rather than SIGBUS at
    /// the first touch of a page (`tests/no_space.rs`). A failure after the
    /// object exists unlinks it.
    ///
    /// # Errors
    ///
    /// - [`RingError::InvalidCapacity`] if `capacity` is zero or its ring
    ///   is too large to size; nothing is created.
    /// - [`RingError::InvalidName`] if `name` contains a NUL byte.
    /// - [`RingError::Open`] if `shm_open(2)` fails: `EEXIST` when the name
    ///   already holds an object, `EACCES` where shared memory is refused.
    /// - [`RingError::Truncate`] if `ftruncate(2)` cannot size the object.
    /// - [`RingError::NoSpace`] on Linux if its pages cannot be reserved.
    /// - [`RingError::Map`] if `mmap(2)` fails.
    pub fn create_exclusive(name: &str, capacity: u64) -> Result<Self, RingError> {
        Self::create_inner(name, capacity, PULSE_SIZE)
    }

    /// [`PulseRing::create_exclusive`] for a version-2 ring, of
    /// [`PULSE_SIZE_V2`]-byte slots: each slot carries a ready line of its
    /// own after the Pulse, which a reader can watch instead of the slot's
    /// counter ([`PulseRing::read_position_by_ready`]). Readers attach with
    /// [`PulseRing::open_existing`].
    ///
    /// # Errors
    ///
    /// Those of [`PulseRing::create_exclusive`].
    pub fn create_exclusive_v2(name: &str, capacity: u64) -> Result<Self, RingError> {
        Self::create_inner(name, capacity, PULSE_SIZE_V2)
    }

    /// [`PulseRing::create_exclusive`] with a reader table of `max_readers`
    /// lines beside the ring, named `<name>.readers` (ADR-0019): readers
    /// register in it ([`PulseRing::register_reader`]), and this handle's
    /// blocking publishes wait for the slowest of them, so each sees every
    /// pulse from its registration on. With no reader registered a blocking
    /// publish does not wait. The ring itself is an ordinary ring, which any
    /// open maps as before. A table left under the derived name by a ring
    /// that is gone is replaced. The creator's drop unlinks the table's name
    /// before the ring's.
    ///
    /// # Errors
    ///
    /// [`RingError::InvalidReaders`] for zero or more than [`MAX_READERS`]
    /// lines, and [`RingError::NameTooLong`] when `<name>.readers` exceeds
    /// [`READERS_NAME_MAX`] bytes, both before anything is created; then
    /// those of [`PulseRing::create_exclusive`], and of making the table,
    /// after which the ring is unlinked again.
    pub fn create_with_readers(
        name: &str,
        capacity: u64,
        max_readers: u32,
    ) -> Result<Self, RingError> {
        if max_readers == 0 || max_readers > MAX_READERS {
            return Err(RingError::InvalidReaders { max_readers });
        }
        readers::table_name(name)?;
        let mut ring = Self::create_inner(name, capacity, PULSE_SIZE)?;
        // On an error the ring drops here, and its creator unlinks it.
        ring.readers = Some(Arc::new(ReaderTable::create(name, capacity, max_readers)?));
        Ok(ring)
    }

    /// Attach this handle to its ring's reader table, so that its blocking
    /// publishes wait for the registered readers: for a writer that opened
    /// a ring made with [`PulseRing::create_with_readers`] rather than
    /// creating it. `Ok(false)` when the ring has no table.
    ///
    /// # Errors
    ///
    /// When the name holds a table this build cannot read:
    /// [`RingError::LayoutMismatch`] (fields `readers magic`, `readers
    /// version`, `readers capacity`) or [`RingError::RegionTooSmall`], and
    /// the libc and mapping failures.
    pub fn attach_readers(&mut self) -> Result<bool, RingError> {
        if self.readers.is_none() {
            self.readers = ReaderTable::open(self.name(), self.capacity)?.map(Arc::new);
        }
        Ok(self.readers.is_some())
    }

    /// Register a reader in the ring's reader table, from the next position
    /// the writer writes: the returned [`ReaderSlot`] reports the reader's
    /// progress with [`ReaderSlot::advance`], and frees its line when it
    /// drops. Any handle on the ring may register, in any process. A table
    /// its creator has not made yet is waited for briefly. A writer that had
    /// already written a ring's worth past the reader's start before the
    /// registration took effect moves the start to its cursor.
    ///
    /// # Errors
    ///
    /// [`RingError::NoReaderTable`] when the ring has none,
    /// [`RingError::ReadersFull`] when every line is taken, and those of
    /// [`PulseRing::attach_readers`] for a table this build cannot read.
    pub fn register_reader(&self) -> Result<ReaderSlot, RingError> {
        let table = match &self.readers {
            Some(table) => Arc::clone(table),
            None => {
                // The creator makes the table just after the ring.
                let found = shm::wait_out_creator(
                    || ReaderTable::open(self.name(), self.capacity),
                    |opened| matches!(opened, Ok(None)),
                );
                Arc::new(found?.ok_or(RingError::NoReaderTable)?)
            }
        };
        let (line, claim) = table
            .claim(self.cursor_position())
            .ok_or(RingError::ReadersFull { max: table.lines() })?;
        let slot = ReaderSlot::new(table, line, claim);
        // Before the claim was seen, the writer did not wait for this
        // reader; from then on it does.
        let now = self.cursor_position();
        if now.saturating_sub(slot.position()) >= self.capacity {
            slot.advance(now);
        }
        Ok(slot)
    }

    /// Readers registered in the ring's reader table now; zero without one,
    /// or when this handle has none attached.
    pub fn registered_readers(&self) -> usize {
        self.readers.as_ref().map_or(0, |table| table.registered())
    }

    /// Free line `line` of the ring's reader table, whoever holds it: for a
    /// reader that stalls blocking publishes ([`RingError::Stalled`] names
    /// its line) and is alive, or whose process id has been reused. False
    /// when the line was free or this handle has no table.
    pub fn evict_reader(&self, line: usize) -> bool {
        self.readers.as_ref().is_some_and(|table| table.evict(line))
    }

    /// Create a ring of `capacity` 128-byte slots under `name`, or attach
    /// to the ring already there. Safe for concurrent callers: one creates
    /// the ring, as [`PulseRing::create_exclusive`] does, and the others
    /// attach as [`PulseRing::open`] does, after waiting out a creator that
    /// has not yet sized the object. An existing object is never resized,
    /// cleared or reformatted (`tests/create.rs`).
    ///
    /// # Errors
    ///
    /// - Those of [`PulseRing::create_exclusive`] but `EEXIST`, when the
    ///   name is free.
    /// - Those of [`PulseRing::open`], when it holds an object:
    ///   [`RingError::RegionTooSmall`] for one too small (including one
    ///   still at size zero after the wait), [`RingError::LayoutMismatch`]
    ///   for one that is not a ring of `capacity` 128-byte slots.
    pub fn create_or_open(name: &str, capacity: u64) -> Result<Self, RingError> {
        match Self::create_exclusive(name, capacity) {
            Err(RingError::Open(libc::EEXIST)) => Self::open_after_creator(name, capacity),
            created => created,
        }
    }

    /// [`PulseRing::open`], retried while the object is at size zero: its
    /// creator may be between `shm_open` and sizing it.
    fn open_after_creator(name: &str, capacity: u64) -> Result<Self, RingError> {
        shm::wait_out_creator(
            || Self::open(name, capacity),
            |opened| matches!(opened, Err(RingError::RegionTooSmall { have: 0, .. })),
        )
    }

    /// Remove the name `name` without opening the object behind it:
    /// `Ok(true)` when an object was removed, `Ok(false)` when none
    /// existed. Mappings stay valid until they unmap. The ring is not
    /// marked superseded: an owner clearing a crashed predecessor's ring
    /// calls [`PulseRing::supersede`] on it first, so its readers learn it.
    ///
    /// # Errors
    ///
    /// - [`RingError::InvalidName`] if `name` contains a NUL byte.
    /// - [`RingError::Unlink`] if `shm_unlink(2)` fails for a reason other
    ///   than the object not existing.
    pub fn unlink(name: &str) -> Result<bool, RingError> {
        let name = Name::new(name).map_err(shm_error)?;
        shm::unlink(&name).map_err(RingError::Unlink)
    }

    /// Attach to an existing ring of `capacity` 128-byte slots.
    ///
    /// The size and then the header are checked before anything is mapped,
    /// so a ring of another geometry, or with no magic, is refused rather
    /// than mis-mapped (`tests/header.rs`), and an open never touches a page
    /// its creator has not reserved, which a full `/dev/shm` answers with
    /// SIGBUS (`tests/full_dev_shm.rs`). A zero magic may be a creator still
    /// formatting, so it is re-read for about 50 ms before it is refused.
    /// [`PulseRing::open_existing`] needs no capacity.
    ///
    /// # Errors
    ///
    /// - [`RingError::InvalidCapacity`] if `capacity` is zero; the name is
    ///   not opened.
    /// - [`RingError::InvalidName`] if `name` contains a NUL byte.
    /// - [`RingError::Open`] if `shm_open(2)` (`ENOENT` for no object,
    ///   `EACCES`), `fstat(2)` or the header's `pread(2)` fails.
    /// - [`RingError::RegionTooSmall`] if the object is smaller than
    ///   `capacity` slots need.
    /// - [`RingError::Map`] if `mmap(2)` fails.
    /// - [`RingError::LayoutMismatch`] if the header's magic, version,
    ///   capacity or slot size is not that of a ring of `capacity` 128-byte
    ///   slots.
    pub fn open(name: &str, capacity: u64) -> Result<Self, RingError> {
        if capacity == 0 {
            return Err(RingError::InvalidCapacity { capacity });
        }
        let name = Name::new(name).map_err(shm_error)?;
        let opened = Opened::open(name).map_err(shm_error)?;
        Self::attach(opened, capacity, PULSE_SIZE)
    }

    /// Attach to an existing ring by name alone, taking its capacity and
    /// slot size (128, or 192 for version-2 slots) from its header, read
    /// and checked as [`PulseRing::open`] reads and checks it.
    ///
    /// # Errors
    ///
    /// - [`RingError::InvalidName`] if `name` contains a NUL byte.
    /// - [`RingError::Open`] if `shm_open(2)`, `fstat(2)` or the header's
    ///   `pread(2)` fails.
    /// - [`RingError::RegionTooSmall`] if the object is smaller than a
    ///   header, or than the ring its header describes.
    /// - [`RingError::Map`] if `mmap(2)` fails.
    /// - [`RingError::LayoutMismatch`] if the magic or version is not this
    ///   layout's, or the header records a capacity of zero or a slot size
    ///   other than 128 or 192.
    pub fn open_existing(name: &str) -> Result<Self, RingError> {
        let name = Name::new(name).map_err(shm_error)?;
        let opened = Opened::open(name).map_err(shm_error)?;
        let (capacity, slot_size) = read_geometry(&opened)?;
        Self::attach(opened, capacity, slot_size)
    }

    /// Map the opened ring as `capacity` slots of `slot_size` bytes, once
    /// its size and its published header check out.
    fn attach(opened: Opened, capacity: u64, slot_size: usize) -> Result<Self, RingError> {
        let have = opened.len();
        // Checked: the capacity may come from a header.
        let total_size = match ring_bytes(capacity, slot_size) {
            Some(n) if n as u64 <= have => n,
            need => {
                return Err(RingError::RegionTooSmall {
                    have,
                    need: need.map_or(u64::MAX, |n| n as u64),
                })
            }
        };
        published_header(opened.fd())?.check(capacity, slot_size)?;
        // A published magic means the pages were reserved (Linux), so
        // touching them cannot fault for want of room.
        let map = opened.map(total_size).map_err(shm_error)?;
        let ring = PulseRing {
            map,
            capacity,
            owner: false,
            slot_size,
            read_cursor_seen: 0,
            readers: None,
        };
        // Checked again through the mapping: its load of the magic, fenced
        // with acquire, orders this handle's reads after the formatting.
        ring.header().check(capacity, slot_size)?;
        Ok(ring)
    }

    /// Create the object behind `name`, which must be free, and format a
    /// ring of `capacity` slots of `slot_size` bytes in it. Not zero-filled:
    /// the kernel's zero pages are already an empty ring, and a fill would
    /// touch every page, which a full tmpfs answers with SIGBUS.
    fn create_inner(name: &str, capacity: u64, slot_size: usize) -> Result<Self, RingError> {
        let total_size = sized_ring_bytes(capacity, slot_size)?;
        let name = Name::new(name).map_err(shm_error)?;
        let map = Mapping::create_exclusive(name, total_size).map_err(shm_error)?;

        // Huge pages spare a large ring most of its TLB misses.
        map.advise_hugepages();

        let ring = PulseRing {
            map,
            capacity,
            owner: true,
            slot_size,
            read_cursor_seen: 0,
            readers: None,
        };
        ring.header().format(capacity, slot_size);
        Ok(ring)
    }

    /// The descriptor behind the mapping, for a second view of a ring with
    /// no name (a memfd). The ring closes it on drop unless it came from
    /// `from_fd` with `owner = false`; `dup(2)` it to keep it longer.
    #[inline(always)]
    pub fn raw_fd(&self) -> libc::c_int {
        self.map.fd()
    }

    /// The mapping's base address, for placement calls such as `mbind(2)`.
    #[inline(always)]
    pub fn mmap_addr(&self) -> *mut u8 {
        self.map.ptr()
    }

    /// Bytes the mapping spans: [`HEADER_SIZE`] + capacity × slot size.
    #[inline(always)]
    pub fn mmap_total_size(&self) -> usize {
        self.total_size()
    }

    /// Build a ring over a descriptor the caller holds (a memfd, or a
    /// hugepage or NUMA-placed region) of at least
    /// `HEADER_SIZE + capacity * PULSE_SIZE` bytes, open for writing.
    ///
    /// The header decides. A region whose magic is zero is fresh, and is
    /// formatted with `capacity` and the slot size, zero-filled first if
    /// `init` is set (for bytes not known to be zero). A region that carries
    /// a header is only validated, whatever `init` says, so a second view
    /// cannot clobber a live ring. Formatting is not a lock: format through
    /// one view before building others over `dup(2)`'d descriptors. On
    /// Linux a fresh region's pages are reserved before it is touched.
    ///
    /// `name` is for diagnostics only and is never unlinked. With
    /// `owner = true` the ring closes the descriptor when it drops; either
    /// way the descriptor must stay open while the ring lives.
    ///
    /// # Errors
    ///
    /// On every error the descriptor is left open and the caller's,
    /// whatever `owner` says (`tests/from_fd_ownership.rs`).
    ///
    /// - [`RingError::InvalidCapacity`] if `capacity` is zero or its ring
    ///   is too large to size; the descriptor is not touched.
    /// - [`RingError::InvalidName`] if `name` contains a NUL byte.
    /// - [`RingError::Open`] if `fstat(2)` fails (`EBADF` for a descriptor
    ///   that is not open), or on Linux the header's `pread(2)`.
    /// - [`RingError::RegionTooSmall`] if the object is smaller than the
    ///   ring.
    /// - [`RingError::NoSpace`] on Linux if a fresh region's pages cannot
    ///   be reserved; nothing is formatted.
    /// - [`RingError::Map`] if `mmap(2)` fails, as it does for a descriptor
    ///   not open for writing.
    /// - [`RingError::LayoutMismatch`] if the region carries a header whose
    ///   magic, version, capacity or slot size is not this ring's.
    pub fn from_fd(
        name: &str,
        fd: libc::c_int,
        capacity: u64,
        owner: bool,
        init: bool,
    ) -> Result<Self, RingError> {
        Self::from_fd_with_slot_size(name, fd, capacity, owner, init, PULSE_SIZE)
    }

    /// [`PulseRing::from_fd`] for a version-2 ring, of [`PULSE_SIZE_V2`]-byte
    /// slots, which [`PulseRing::open`] refuses and
    /// [`PulseRing::open_existing`] opens.
    ///
    /// # Errors
    ///
    /// Those of [`PulseRing::from_fd`]. A region formatted with 128-byte
    /// slots is refused with [`RingError::LayoutMismatch`] on `slot_size`,
    /// or [`RingError::RegionTooSmall`] when it cannot hold 192-byte slots.
    pub fn from_fd_v2(
        name: &str,
        fd: libc::c_int,
        capacity: u64,
        owner: bool,
        init: bool,
    ) -> Result<Self, RingError> {
        Self::from_fd_with_slot_size(name, fd, capacity, owner, init, PULSE_SIZE_V2)
    }

    fn from_fd_with_slot_size(
        name: &str,
        fd: libc::c_int,
        capacity: u64,
        owner: bool,
        init: bool,
        slot_size: usize,
    ) -> Result<Self, RingError> {
        assert!(
            slot_size == PULSE_SIZE || slot_size == PULSE_SIZE_V2,
            "slot_size must be PULSE_SIZE (v1) or PULSE_SIZE_V2 (v2)"
        );
        let total_size = sized_ring_bytes(capacity, slot_size)?;
        let name = Name::new(name).map_err(shm_error)?;
        let opened = Opened::from_fd(name, fd, owner).map_err(shm_error)?;
        opened.at_least(total_size).map_err(shm_error)?;
        // A fresh region is reserved before it is touched, and so before its
        // magic is published; a populated one was reserved by its formatter
        // and is checked before it is mapped. The check through the mapping
        // below decides.
        #[cfg(target_os = "linux")]
        {
            let header = read_header(fd)?;
            if header.magic == 0 {
                match shm::reserve_pages(fd, total_size as libc::off_t) {
                    Ok(()) => {}
                    Err(errno @ (libc::ENOSPC | libc::ENOMEM | libc::EINTR)) => {
                        return Err(RingError::NoSpace {
                            need: total_size as u64,
                            errno,
                        });
                    }
                    // Nothing to reserve (not writable, or no tmpfs file):
                    // the mapping decides.
                    Err(_) => {}
                }
            } else {
                header.check(capacity, slot_size)?;
            }
        }
        let map = opened.map(total_size).map_err(shm_error)?;
        let mut ring = PulseRing {
            map,
            capacity,
            // Never unlinks: the name is synthetic.
            owner: false,
            slot_size,
            read_cursor_seen: 0,
            readers: None,
        };
        let header = ring.header();
        let checked = if header.is_blank() {
            // A zero magic does not mean zero cursors and counters: the
            // region is the caller's and may hold old bytes.
            if init {
                let after_magic = H_MAGIC + 4;
                let base = ring.map.ptr();
                // SAFETY: the mapping spans `total_size` writable bytes, more
                // than HEADER_SIZE. With no magic published no view reads
                // the cursors, fields or slots; the fill skips the magic
                // word itself, which an open waiting on this region may be
                // loading, and ends before `format` publishes it.
                unsafe {
                    std::ptr::write_bytes(base, 0, H_MAGIC);
                    std::ptr::write_bytes(base.add(after_magic), 0, total_size - after_magic);
                }
            }
            header.format(capacity, slot_size);
            Ok(())
        } else {
            header.check(capacity, slot_size)
        };
        if let Err(e) = checked {
            // The descriptor stays the caller's on error.
            ring.map.leave_fd_open();
            return Err(e);
        }
        Ok(ring)
    }

    /// Publish a pulse into the slot of the write cursor, overwriting what
    /// it held, and return its write number (1 for the first write).
    #[inline(always)]
    pub fn publish(&mut self, pulse: &Pulse) -> u64 {
        self.publish_bytes(pulse.as_bytes()).1
    }

    /// [`Self::publish`], returning the slot index written instead of the
    /// write number, for a later [`Self::publish_at_slot`].
    #[inline(always)]
    pub fn publish_returning_slot(&mut self, pulse: &Pulse) -> u64 {
        self.publish_bytes(pulse.as_bytes()).0
    }

    /// Overwrite slot `slot % capacity` in place, under its SeqLock, without
    /// moving the write cursor or the write count, and return the slot's
    /// new (even) counter. For writers that keep one slot per key.
    #[inline(always)]
    pub fn publish_at_slot(&mut self, slot: u64, pulse: &Pulse) -> u64 {
        self.write_slot(slot % self.capacity, pulse.as_bytes())
    }

    /// Write `bytes` into the slot of the write cursor, then count the
    /// write and move the cursor past it; the slot index and the write
    /// number.
    #[inline(always)]
    fn publish_bytes(&self, bytes: &[u8; PULSE_SIZE]) -> (u64, u64) {
        let cursor = self.write_cursor();
        let total = self.total_writes();
        // Only this writer moves either count, so each is loaded once and
        // stored, as `write_batch` does. A store is a plain write; the
        // read-modify-write it replaces is a full barrier on x86 that held
        // the writer until the slot's lines had crossed to every reader,
        // on every message.
        let position = cursor.load(Ordering::Acquire);
        let slot = position % self.capacity;
        self.write_slot(slot, bytes);
        // Wraps: the count lives in shared memory, which anything can write.
        let write_num = total.load(Ordering::Acquire).wrapping_add(1);
        // Release: a reader whose acquire load sees the count or the cursor
        // sees the slot written.
        total.store(write_num, Ordering::Release);
        cursor.store(position.wrapping_add(1), Ordering::Release);
        (slot, write_num)
    }

    /// The SeqLock write, the one place the ring writes a slot: mark the
    /// counter odd, store the 120 bytes after it as atomic words, mark it
    /// even, and return the even counter. A counter a writer left odd by
    /// dying mid-write is re-based, so the slot heals on its next write.
    #[inline(always)]
    fn write_slot(&self, slot: u64, bytes: &[u8; PULSE_SIZE]) -> u64 {
        let slot_ptr = self.slot_ptr(slot);
        let seq = self.slot_counter(slot_ptr);
        // `& !1` re-bases a counter a writer left odd by dying mid-write.
        let prev = seq.load(Ordering::Relaxed) & !1;
        seq.store(prev | 1, Ordering::Release);
        // Release fence: the odd mark is visible before any payload word.
        std::sync::atomic::fence(Ordering::Release);
        // SAFETY: bytes 8..PULSE_SIZE of the slot lie in the mapping, 8-byte
        // aligned (a slot starts 64-byte aligned), and are only ever accessed
        // as atomic words (`shm::load_words`, `shm::store_words`); 120 is a
        // multiple of eight.
        unsafe { shm::store_words(slot_ptr.add(8), &bytes[8..]) };
        let next = prev.wrapping_add(2);
        // Release: a reader whose acquire load sees the even mark sees every
        // payload word.
        seq.store(next, Ordering::Release);
        demote_slot(slot_ptr);
        self.maybe_signal_ready(slot_ptr);
        next
    }

    /// The SeqLock counter at the start of the slot at `slot_ptr`.
    #[inline(always)]
    fn slot_counter(&self, slot_ptr: *mut u8) -> &AtomicU64 {
        // SAFETY: a slot's first 8 bytes are its SeqLock counter, 8-byte
        // aligned (slots start 64-byte aligned in a page-aligned mapping), in
        // the mapping, which outlives the borrow of `self`, and only ever
        // accessed atomically.
        unsafe { AtomicU64::from_ptr(slot_ptr.cast::<u64>()) }
    }

    /// Read the pulse in slot `slot % capacity`: `None` for a slot never
    /// written, or one with no stable copy within the retry budget (a writer
    /// mid-write, or one that died there).
    #[inline(always)]
    pub fn read_slot(&self, slot: u64) -> Option<Pulse> {
        let slot_idx = slot % self.capacity;
        let slot_ptr = self.slot_ptr(slot_idx);
        let seq = self.slot_counter(slot_ptr);

        for _ in 0..100 {
            let v1 = seq.load(Ordering::Acquire);
            if v1 & 1 != 0 {
                std::hint::spin_loop();
                continue;
            }

            let mut buf = [0u8; PULSE_SIZE];
            // SAFETY: the slot's PULSE_SIZE bytes lie in the mapping, 8-byte
            // aligned, and are only ever accessed as atomic words.
            unsafe { shm::load_words(slot_ptr, &mut buf) };
            #[cfg(fuzzing)]
            fuzzing::mid_copy(self, slot_idx, PULSE_SIZE / 2, &mut buf[PULSE_SIZE / 2..]);

            // Acquire fence: the copy completes before the counter is re-read.
            std::sync::atomic::fence(Ordering::Acquire);
            let v2 = seq.load(Ordering::Acquire);
            if v1 != v2 {
                std::hint::spin_loop();
                continue;
            }

            if v1 == 0 {
                return None;
            }

            return Some(Pulse::from_array(&buf));
        }
        None
    }

    /// [`Self::publish`], once the slowest reader has left a slot free,
    /// waiting at most `timeout`: the writer keeps the reader's pace instead
    /// of overwriting what it has not read.
    ///
    /// The reader frees slots with [`Self::advance_read_cursor`]. The wait
    /// spins and never sleeps. A `timeout` the clock cannot represent as a
    /// deadline, such as `Duration::MAX`, sets none.
    ///
    /// # Errors
    ///
    /// [`RingError::Stalled`] if no slot was free by the deadline; nothing
    /// was published, so the call can be retried.
    #[inline(always)]
    pub fn publish_blocking(&mut self, pulse: &Pulse, timeout: Duration) -> Result<u64, RingError> {
        self.wait_for_room(1, timeout)?;
        Ok(self.publish(pulse))
    }

    /// [`Self::publish_batch`], once the slowest reader has freed room for
    /// the whole batch, waiting as [`Self::publish_blocking`] does. An empty
    /// batch never waits.
    ///
    /// # Errors
    ///
    /// - [`RingError::BatchTooLarge`] at once, without waiting, if `pulses`
    ///   holds more pulses than the ring has slots.
    /// - [`RingError::Stalled`] if the room was not free by the deadline.
    ///
    /// Either way nothing was written, so the call can be retried.
    #[inline(always)]
    pub fn publish_batch_blocking(
        &mut self,
        pulses: &[Pulse],
        timeout: Duration,
    ) -> Result<u64, RingError> {
        let n = self.batch_len(pulses)?;
        if n == 0 {
            return Ok(self.write_count());
        }
        self.wait_for_room(n, timeout)?;
        Ok(self.write_batch(pulses))
    }

    /// `Ok` once `needed` (at most the capacity) slots are free, or
    /// [`RingError::Stalled`] at `timeout`.
    #[inline(always)]
    fn wait_for_room(&mut self, needed: u64, timeout: Duration) -> Result<(), RingError> {
        // Loaded once: only the caller, the writer, moves it.
        let written = self.write_cursor().load(Ordering::Acquire);
        // The cursor the reader last showed still proves room while the ring
        // is not full against it, so the shared cursor, which the reader's
        // core holds, is read only when it stops proving room.
        if written
            .saturating_sub(self.read_cursor_seen)
            .saturating_add(needed)
            <= self.capacity
        {
            return Ok(());
        }
        self.read_cursor_seen = self.reader_floor(written).0;
        if self.fits(written, needed).is_ok() {
            return Ok(());
        }
        // Out of room: a registered reader whose process is gone holds the
        // writer back for nothing, so its line goes first (ADR-0019).
        if let Some(table) = &self.readers {
            if table.evict_dead() > 0 && self.fits(written, needed).is_ok() {
                self.read_cursor_seen = self.reader_floor(written).0;
                return Ok(());
            }
        }
        self.wait_for_reader(written, needed, timeout)?;
        self.read_cursor_seen = self.reader_floor(written).0;
        Ok(())
    }

    /// The position below which every reader has read, with the slowest
    /// registered reader's line: the header's read cursor, or, with a reader
    /// table, the smallest registered cursor, or `written` when no reader is
    /// registered.
    #[inline(always)]
    fn reader_floor(&self, written: u64) -> (u64, Option<usize>) {
        match &self.readers {
            None => (self.read_cursor().load(Ordering::Acquire), None),
            Some(table) => table
                .slowest()
                .map_or((written, None), |(cursor, line)| (cursor, Some(line))),
        }
    }

    /// `Ok` when `needed` more slots fit beside the positions the readers
    /// have not read, the write cursor being `written`; otherwise how many
    /// those are, with the slowest registered reader's line.
    #[inline(always)]
    fn fits(&self, written: u64, needed: u64) -> Result<(), (u64, Option<usize>)> {
        let (floor, line) = self.reader_floor(written);
        let in_flight = written.saturating_sub(floor);
        if in_flight.saturating_add(needed) <= self.capacity {
            Ok(())
        } else {
            Err((in_flight, line))
        }
    }

    /// The spin of [`Self::wait_for_room`] once the ring was found full.
    #[cold]
    #[inline(never)]
    fn wait_for_reader(
        &self,
        written: u64,
        needed: u64,
        timeout: Duration,
    ) -> Result<(), RingError> {
        // Few enough that the deadline is overshot by microseconds at most.
        const SPINS_PER_CLOCK_READ: u32 = 64;
        let started = std::time::Instant::now();
        let deadline = started.checked_add(timeout);
        loop {
            let (mut in_flight, mut slowest) = (0, None);
            for _ in 0..SPINS_PER_CLOCK_READ {
                std::hint::spin_loop();
                match self.fits(written, needed) {
                    Ok(()) => return Ok(()),
                    Err((unread, line)) => (in_flight, slowest) = (unread, line),
                }
            }
            let now = std::time::Instant::now();
            if deadline.is_some_and(|deadline| now >= deadline) {
                return Err(RingError::Stalled {
                    in_flight,
                    waited: now.duration_since(started),
                    slowest_reader: slowest.and_then(|line| u32::try_from(line).ok()),
                });
            }
        }
    }

    /// Publish `pulses` into consecutive slots, to the effect of one
    /// [`Self::publish`] per pulse, and return the last one's write number,
    /// or the write count for an empty batch. The cursors are loaded once
    /// per batch and advanced with stores, not read-modify-writes.
    ///
    /// # Errors
    ///
    /// [`RingError::BatchTooLarge`] if `pulses` holds more pulses than the
    /// ring has slots; nothing is written.
    #[inline(always)]
    pub fn publish_batch(&mut self, pulses: &[Pulse]) -> Result<u64, RingError> {
        self.batch_len(pulses)?;
        Ok(self.write_batch(pulses))
    }

    /// The length of a batch that fits the ring, or
    /// [`RingError::BatchTooLarge`].
    #[inline(always)]
    fn batch_len(&self, pulses: &[Pulse]) -> Result<u64, RingError> {
        match u64::try_from(pulses.len()) {
            Ok(n) if n <= self.capacity => Ok(n),
            _ => Err(RingError::BatchTooLarge {
                len: pulses.len(),
                capacity: self.capacity,
            }),
        }
    }

    /// The write of [`Self::publish_batch`], for a batch that fits the ring.
    #[inline(always)]
    fn write_batch(&self, pulses: &[Pulse]) -> u64 {
        let cursor = self.write_cursor();
        let total = self.total_writes();
        // One writer: nothing else moves either counter during the batch,
        // so each store below writes what a `fetch_add` would have.
        let start = cursor.load(Ordering::Acquire);
        let mut written = total.load(Ordering::Acquire);
        for (i, pulse) in pulses.iter().enumerate() {
            let position = start.wrapping_add(i as u64);
            self.write_slot(position % self.capacity, pulse.as_bytes());
            // Count the slot, then move the cursor past it, before touching
            // the next: `read_position` needs a slot refilled only once the
            // cursor shows the position it is refilled for. The release
            // stores publish the slot as `publish`'s `fetch_add`s do.
            written = written.wrapping_add(1);
            total.store(written, Ordering::Release);
            cursor.store(position.wrapping_add(1), Ordering::Release);
        }
        written
    }

    /// Read consecutive slots from `start_slot` into `out`, each as
    /// [`Self::read_slot`] reads it, up to the first `None`; returns how
    /// many were read.
    #[inline(always)]
    pub fn read_slots_batch(&self, start_slot: u64, out: &mut [Pulse]) -> usize {
        let mut written = 0;
        for i in 0..out.len() {
            match self.read_slot(start_slot.wrapping_add(i as u64)) {
                Some(p) => {
                    out[written] = p;
                    written += 1;
                }
                None => break,
            }
        }
        written
    }

    /// The write cursor: the position the next publish writes, in slot
    /// `cursor_position() % capacity`.
    pub fn cursor_position(&self) -> u64 {
        self.write_cursor().load(Ordering::Acquire)
    }

    /// Total number of writes since the ring was created.
    pub fn write_count(&self) -> u64 {
        self.total_writes().load(Ordering::Acquire)
    }

    /// Number of slots in the ring.
    pub fn capacity(&self) -> u64 {
        self.capacity
    }

    /// The ring's name (POSIX shm path).
    pub fn name(&self) -> &str {
        self.map.name().as_str()
    }

    /// Whether this handle created the ring under its name (from
    /// [`Self::create_exclusive`], or [`Self::create_or_open`] on a free
    /// name), and so marks it superseded and unlinks the name when it drops
    /// ([`Self::supersede`]). Attached handles and `from_fd` rings did not.
    #[must_use]
    pub fn is_creator(&self) -> bool {
        self.owner
    }

    /// Mark the ring superseded: its writer has left it for good. `true`
    /// when this call set the mark, `false` when it was already set.
    ///
    /// The mark is set once, and whoever sets it decides the name's fate.
    /// The creating handle's drop unlinks the name only if its own call set
    /// the mark, so a creator whose ring another has marked (the next owner
    /// of a hub name, replacing a ring left behind) never unlinks what may
    /// by then be a successor's ring (ADR-0015; `tests/superseded.rs`).
    pub fn supersede(&self) -> bool {
        // Release: a reader whose acquire load sees the mark sees every
        // publish before it.
        self.header()
            .superseded
            .compare_exchange(0, SUPERSEDED.to_le(), Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    /// Whether the ring is marked superseded ([`Self::supersede`]). A reader
    /// that sees the mark has only to read what the ring still holds, then
    /// reopen the name, where a new ring may be by now.
    #[must_use]
    pub fn is_superseded(&self) -> bool {
        self.header().superseded.load(Ordering::Acquire) != 0
    }

    /// The SeqLock counter of slot `slot % capacity`, for a waiter that
    /// watches a slot for changes without reading it.
    #[inline(always)]
    pub fn slot_seq_atomic(&self, slot: u64) -> &AtomicU64 {
        self.slot_counter(self.slot_ptr(slot % self.capacity))
    }

    /// Hint the CPU to fetch both cache lines of slot `slot % capacity`
    /// into L1 (`prefetcht0` on x86_64, `prfm pldl1keep` on aarch64, nothing
    /// elsewhere), for a reader about to poll a slot whose lines may have
    /// been evicted.
    #[inline(always)]
    pub fn prefetch_slot(&self, slot: u64) {
        let slot_idx = slot % self.capacity;
        let ptr = self.slot_ptr(slot_idx) as *const i8;
        // SAFETY: a slot spans at least 128 bytes, so offset 64, its second
        // cache line, is inside it.
        let ptr_line2 = unsafe { ptr.add(64) };

        // SAFETY: `_mm_prefetch` is a hint that never faults; both pointers
        // are inside the slot.
        #[cfg(target_arch = "x86_64")]
        unsafe {
            use std::arch::x86_64::{_mm_prefetch, _MM_HINT_T0};
            _mm_prefetch(ptr, _MM_HINT_T0);
            _mm_prefetch(ptr_line2, _MM_HINT_T0);
        }

        // SAFETY: `prfm` is a prefetch hint that never faults; the asm takes
        // only `readonly` register inputs and has no other effect.
        #[cfg(target_arch = "aarch64")]
        unsafe {
            // Prefetch for load into L1, and keep.
            std::arch::asm!(
                "prfm pldl1keep, [{0}]",
                "prfm pldl1keep, [{1}]",
                in(reg) ptr,
                in(reg) ptr_line2,
                options(nostack, preserves_flags, readonly),
            );
        }

        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        {
            let _ = (ptr, ptr_line2);
        }
    }

    #[inline(always)]
    fn write_cursor(&self) -> &AtomicU64 {
        // SAFETY: bytes 0..8 of the mapped region hold the AtomicU64
        // write_cursor. The pointer is valid for the lifetime of self.
        unsafe { &*(self.map.ptr() as *const AtomicU64) }
    }

    #[inline(always)]
    fn total_writes(&self) -> &AtomicU64 {
        // SAFETY: bytes 8..16 of the mapped region hold the AtomicU64
        // total_writes counter. The pointer is valid for the lifetime of self.
        unsafe { &*((self.map.ptr() as *const u8).add(8) as *const AtomicU64) }
    }

    #[inline(always)]
    fn read_cursor(&self) -> &AtomicU64 {
        // SAFETY: bytes 16..24 of the mapped region hold the AtomicU64
        // read_cursor. The pointer is valid for the lifetime of self.
        unsafe { &*((self.map.ptr() as *const u8).add(16) as *const AtomicU64) }
    }

    /// The read cursor: the position the reader reads next, as it last
    /// reported with [`Self::advance_read_cursor`].
    #[inline(always)]
    pub fn read_cursor_position(&self) -> u64 {
        self.read_cursor().load(Ordering::Acquire)
    }

    /// Tell blocking publishers the reader has read every position below
    /// `new_position`. The cursor only moves forward; with several readers
    /// it follows the furthest, so blocking publish assumes one reader.
    #[inline(always)]
    pub fn advance_read_cursor(&self, new_position: u64) {
        let cur = self.read_cursor();
        let mut current = cur.load(Ordering::Relaxed);
        while current < new_position {
            // Release: the reader's reads of the slots it frees happen
            // before a writer that sees the new cursor refills them.
            match cur.compare_exchange_weak(
                current,
                new_position,
                Ordering::Release,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(observed) => current = observed,
            }
        }
    }

    #[inline(always)]
    fn slot_ptr(&self, slot: u64) -> *mut u8 {
        // SAFETY: every caller passes `slot < capacity`, and the mapping
        // spans HEADER_SIZE + capacity × slot_size bytes.
        unsafe {
            self.map
                .ptr()
                .add(HEADER_SIZE + (slot as usize) * self.slot_size)
        }
    }

    fn total_size(&self) -> usize {
        // Cannot overflow: every constructor computed this size with
        // checked arithmetic before it mapped the region.
        HEADER_SIZE + (self.capacity as usize) * self.slot_size
    }

    /// The header fields of this ring's mapping.
    fn header(&self) -> RingHeader<'_> {
        // SAFETY: every constructor maps at least HEADER_SIZE bytes from a
        // page-aligned address and keeps the mapping until Drop, so it
        // outlives this borrow of `self`.
        unsafe { RingHeader::at(self.map.ptr()) }
    }

    /// Whether the ring has version-2 slots ([`PULSE_SIZE_V2`]).
    #[inline(always)]
    pub fn is_v2(&self) -> bool {
        self.slot_size == PULSE_SIZE_V2
    }

    /// On a version-2 ring, bump the slot's ready line. Every publish calls
    /// it after the even mark, so a waiter it wakes finds the slot stable.
    /// The slot's two lines are cleaned first ([`clean_slot`]), so readers
    /// watching the ready line fetch them from the shared level.
    #[inline(always)]
    fn maybe_signal_ready(&self, slot_ptr: *mut u8) {
        if self.slot_size == PULSE_SIZE_V2 {
            clean_slot(slot_ptr);
            // SAFETY: READY_LINE_OFFSET=128 is within the 192-byte v2 slot;
            // 8-byte aligned via the slot's 64-byte cache-line alignment + the
            // offset. Atomic semantics: Release ordering pairs with the
            // receiver's Acquire load on the same cache line.
            unsafe {
                let ready = &*(slot_ptr.add(READY_LINE_OFFSET) as *const AtomicU64);
                // One writer: a release store writes what a `fetch_add`
                // would, as `write_batch` moves the cursor, without a locked
                // read-modify-write per message.
                ready.store(
                    ready.load(Ordering::Relaxed).wrapping_add(1),
                    Ordering::Release,
                );
            }
        }
    }

    /// [`Self::publish`], with a CRC32C trailer ([`pms_crc32c`]) in place of
    /// the pulse's bytes 124..128, for [`Self::read_slot_verify_crc`].
    #[inline(always)]
    pub fn publish_with_crc(&mut self, pulse: &Pulse) -> u64 {
        let mut bytes = *pulse.as_bytes();
        let crc = pms_crc32c::compute_pulse_crc(&bytes);
        bytes[124..].copy_from_slice(&crc.to_le_bytes());
        self.publish_bytes(&bytes).1
    }

    /// [`Self::read_slot`], verifying the CRC32C trailer of a slot written
    /// with [`Self::publish_with_crc`]. A torn read is `Ok(None)`, as in
    /// `read_slot`, never a mismatch.
    ///
    /// # Errors
    ///
    /// [`RingError::CrcMismatch`] when the trailer does not match the data:
    /// memory corruption or tampering.
    #[inline(always)]
    pub fn read_slot_verify_crc(&self, slot: u64) -> Result<Option<Pulse>, RingError> {
        match self.read_slot(slot) {
            None => Ok(None),
            Some(pulse) => match pms_crc32c::verify_pulse_crc(pulse.as_bytes()) {
                Ok(()) => Ok(Some(pulse)),
                Err(pms_crc32c::CrcMismatch { expected, computed }) => {
                    Err(RingError::CrcMismatch {
                        slot,
                        expected,
                        computed,
                    })
                }
            },
        }
    }

    /// The data-ready line of slot `slot % capacity`, or `None` on a
    /// version-1 ring. Each publish increments it once, after the slot is
    /// stable, where the SeqLock counter changes twice, so a waiter that
    /// monitors one address (UMWAIT) wakes once per publish.
    #[inline(always)]
    pub fn ready_line_atomic(&self, slot: u64) -> Option<&AtomicU64> {
        if !self.is_v2() {
            return None;
        }
        let slot_idx = slot % self.capacity;
        let slot_ptr = self.slot_ptr(slot_idx);
        // SAFETY: slot_ptr is within the mapped region; READY_LINE_OFFSET=128
        // is a valid offset into a 192-byte v2 slot. AtomicU64 alignment is
        // 8 bytes, satisfied by the slot's own 64-byte cache-line alignment
        // + the 128-byte offset.
        unsafe { Some(&*(slot_ptr.add(READY_LINE_OFFSET) as *const AtomicU64)) }
    }
}

/// Bytes a ring of `capacity` slots of `slot_size` bytes spans, header
/// included, or `None` when that does not fit in `usize`.
fn ring_bytes(capacity: u64, slot_size: usize) -> Option<usize> {
    usize::try_from(capacity)
        .ok()?
        .checked_mul(slot_size)?
        .checked_add(HEADER_SIZE)
}

/// [`ring_bytes`] for a constructor that sizes or formats a region, which
/// also needs a slot and a size that fits `ftruncate`'s `off_t`;
/// [`RingError::InvalidCapacity`] otherwise.
fn sized_ring_bytes(capacity: u64, slot_size: usize) -> Result<usize, RingError> {
    ring_bytes(capacity, slot_size)
        .filter(|&bytes| capacity >= 1 && libc::off_t::try_from(bytes).is_ok())
        .ok_or(RingError::InvalidCapacity { capacity })
}

/// The capacity and slot size the opened ring's header records
/// ([`published_header`]), once the object is at least a header long.
fn read_geometry(opened: &Opened) -> Result<(u64, usize), RingError> {
    let have = opened.len();
    if have < HEADER_SIZE as u64 {
        return Err(RingError::RegionTooSmall {
            have,
            need: HEADER_SIZE as u64,
        });
    }
    published_header(opened.fd())?.geometry()
}

/// The header of the ring behind `fd`, at least a header long, read
/// without mapping it and re-read while the magic is zero, as a creator
/// that has not yet published it leaves it ([`shm::wait_out_creator`]).
fn published_header(fd: libc::c_int) -> Result<HeaderFields, RingError> {
    shm::wait_out_creator(
        || read_header(fd),
        |header| matches!(header, Ok(header) if header.magic == 0),
    )
}

/// One read of the header behind `fd` with `pread(2)`, which allocates no
/// page ([`shm::pread_exact`]).
///
/// `pread` copies in no set order, so a copy that shows the magic may hold
/// a field from before the creator wrote it. The header is read again after
/// an acquire fence, which orders that read after the load that saw the
/// magic, and so after the creator's writes of the fields. The check
/// through the mapping, once an open has mapped the ring, decides.
#[cfg(target_os = "linux")]
fn read_header(fd: libc::c_int) -> Result<HeaderFields, RingError> {
    let header = HeaderFields::from_bytes(&pread_header(fd)?);
    if header.magic == 0 {
        return Ok(header);
    }
    std::sync::atomic::fence(Ordering::Acquire);
    Ok(HeaderFields::from_bytes(&pread_header(fd)?))
}

/// The first [`HEADER_SIZE`] bytes of the object behind `fd`.
#[cfg(target_os = "linux")]
fn pread_header(fd: libc::c_int) -> Result<[u8; HEADER_SIZE], RingError> {
    let mut bytes = [0u8; HEADER_SIZE];
    shm::pread_exact(fd, 0, &mut bytes).map_err(shm_error)?;
    Ok(bytes)
}

/// One read of the header behind `fd`, through a read-only mapping of it
/// ([`shm::with_prefix_mapped`] says why that is safe off Linux).
#[cfg(not(target_os = "linux"))]
fn read_header(fd: libc::c_int) -> Result<HeaderFields, RingError> {
    shm::with_prefix_mapped(fd, HEADER_SIZE, |ptr| {
        // SAFETY: `ptr` is the page-aligned start of a live mapping of
        // HEADER_SIZE bytes, which stays mapped until the closure returns.
        // The view only loads, with relaxed ordering (`fields`), which a
        // read-only mapping allows.
        unsafe { RingHeader::at(ptr.cast_mut()) }.fields()
    })
    .map_err(shm_error)
}

/// The header fields an open checks, as one read of the header found them,
/// in native byte order.
#[derive(Clone, Copy)]
struct HeaderFields {
    magic: u32,
    version: u32,
    capacity: u64,
    slot_size: u32,
}

impl HeaderFields {
    /// The fields of a header's little-endian bytes.
    #[cfg(target_os = "linux")]
    fn from_bytes(bytes: &[u8; HEADER_SIZE]) -> Self {
        let word = |at: usize| {
            u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
        };
        let mut capacity = [0u8; 8];
        capacity.copy_from_slice(&bytes[H_CAPACITY..H_CAPACITY + 8]);
        Self {
            magic: word(H_MAGIC),
            version: word(H_VERSION),
            capacity: u64::from_le_bytes(capacity),
            slot_size: word(H_SLOT_SIZE),
        }
    }

    /// Check the magic and the layout version.
    fn check_layout(&self) -> Result<(), RingError> {
        mismatch("magic", self.magic.into(), MAGIC.into())?;
        mismatch("version", self.version.into(), LAYOUT_VERSION.into())
    }

    /// Check that the header describes a ring of `capacity` slots of
    /// `slot_size` bytes.
    fn check(&self, capacity: u64, slot_size: usize) -> Result<(), RingError> {
        self.check_layout()?;
        mismatch("capacity", self.capacity, capacity)?;
        mismatch("slot_size", self.slot_size.into(), slot_size as u64)
    }

    /// The capacity and slot size the header describes, if this build can
    /// map them: at least one slot, of 128 or 192 bytes.
    fn geometry(&self) -> Result<(u64, usize), RingError> {
        self.check_layout()?;
        let slot_size = self.slot_size as usize;
        if slot_size != PULSE_SIZE && slot_size != PULSE_SIZE_V2 {
            return Err(RingError::LayoutMismatch {
                field: "slot_size",
                have: slot_size as u64,
                need: PULSE_SIZE as u64,
            });
        }
        if self.capacity == 0 {
            return Err(RingError::LayoutMismatch {
                field: "capacity",
                have: 0,
                need: 1,
            });
        }
        Ok((self.capacity, slot_size))
    }
}

/// Typed access to the header fields at bytes 24..48 of a ring mapping.
/// The fields are atomics, so a reader racing a creator's formatting reads
/// each one whole, and they hold little-endian values.
struct RingHeader<'a> {
    magic: &'a AtomicU32,
    version: &'a AtomicU32,
    capacity: &'a AtomicU64,
    slot_size: &'a AtomicU32,
    superseded: &'a AtomicU32,
}

impl RingHeader<'_> {
    /// View the header of the mapping that starts at `base`.
    ///
    /// # Safety
    ///
    /// `base` must be the page-aligned start of a live mapping of at least
    /// [`HEADER_SIZE`] bytes that stays mapped while the view is used.
    unsafe fn at(base: *mut u8) -> Self {
        // SAFETY: the caller guarantees a live mapping of at least
        // HEADER_SIZE bytes for as long as the view is used. Offsets 24, 28,
        // 32, 40 and 44 lie inside it and, from a page-aligned base, are
        // aligned for the u32, u32, u64, u32 and u32 atomics placed there;
        // nothing accesses those bytes other than through atomics, apart
        // from `from_fd`'s zero-fill of a region before it publishes the
        // magic.
        unsafe {
            Self {
                magic: &*(base.add(H_MAGIC) as *const AtomicU32),
                version: &*(base.add(H_VERSION) as *const AtomicU32),
                capacity: &*(base.add(H_CAPACITY) as *const AtomicU64),
                slot_size: &*(base.add(H_SLOT_SIZE) as *const AtomicU32),
                superseded: &*(base.add(H_SUPERSEDED) as *const AtomicU32),
            }
        }
    }

    /// True while no creator has published the magic.
    fn is_blank(&self) -> bool {
        self.magic.load(Ordering::Acquire) == 0
    }

    /// Write the version, capacity and slot size and clear the superseded
    /// flag, then publish the magic with release ordering: a reader that
    /// sees the magic and fences with acquire ([`Self::fields`]) sees these
    /// fields and everything the creator wrote before them.
    fn format(&self, capacity: u64, slot_size: usize) {
        self.version
            .store(LAYOUT_VERSION.to_le(), Ordering::Relaxed);
        self.capacity.store(capacity.to_le(), Ordering::Relaxed);
        self.slot_size
            .store((slot_size as u32).to_le(), Ordering::Relaxed);
        self.superseded.store(0, Ordering::Relaxed);
        self.magic.store(MAGIC.to_le(), Ordering::Release);
    }

    /// The fields as they stand. The magic is loaded relaxed, then an
    /// acquire fence: the loads after it see the fields a creator wrote
    /// before it published the magic seen. Not an acquire load, because a
    /// relaxed load is the only atomic load std allows through the
    /// read-only mapping `read_header` uses off Linux.
    fn fields(&self) -> HeaderFields {
        let magic = u32::from_le(self.magic.load(Ordering::Relaxed));
        std::sync::atomic::fence(Ordering::Acquire);
        HeaderFields {
            magic,
            version: u32::from_le(self.version.load(Ordering::Relaxed)),
            capacity: u64::from_le(self.capacity.load(Ordering::Relaxed)),
            slot_size: u32::from_le(self.slot_size.load(Ordering::Relaxed)),
        }
    }

    /// Check that the header describes a ring of `capacity` slots of
    /// `slot_size` bytes. One read suffices: callers check only a published
    /// header, whose magic never changes.
    fn check(&self, capacity: u64, slot_size: usize) -> Result<(), RingError> {
        self.fields().check(capacity, slot_size)
    }
}

/// `Ok` when a header field holds the value the caller needs, and the
/// `LayoutMismatch` naming it otherwise.
fn mismatch(field: &'static str, have: u64, need: u64) -> Result<(), RingError> {
    if have == need {
        Ok(())
    } else {
        Err(RingError::LayoutMismatch { field, have, need })
    }
}

impl Drop for PulseRing {
    fn drop(&mut self) {
        // Unlinks only the name this ring created, and only if this call
        // set the mark (`PulseRing::supersede`).
        if self.owner && self.supersede() {
            // The table's name first, the ring's last (ADR-0019).
            if let Some(table) = &self.readers {
                table.unlink();
            }
            let _ = shm::unlink(self.map.name());
        }
    }
}

/// Fuzzing instrumentation, built only under `--cfg fuzzing` and public
/// only for `fuzz` (`fuzz_ring_header` describes it): a hook run
/// between a reader's copy of a slot and its re-check of the counter.
#[cfg(fuzzing)]
#[doc(hidden)]
pub mod fuzzing {
    use super::{PulseRing, PULSE_SIZE};
    use std::cell::RefCell;

    /// What runs at the interleaving point: given the ring being read and
    /// the index of the slot being copied.
    pub type MidCopy = Box<dyn FnMut(&PulseRing, u64)>;

    thread_local! {
        static MID_COPY: RefCell<Option<MidCopy>> = const { RefCell::new(None) };
    }

    /// Run `hook` at every interleaving point this thread's reads reach,
    /// until [`take_mid_copy`] removes it.
    pub fn set_mid_copy(hook: MidCopy) {
        MID_COPY.with(|h| *h.borrow_mut() = Some(hook));
    }

    /// Remove the hook [`set_mid_copy`] set, if any, and return it.
    pub fn take_mid_copy() -> Option<MidCopy> {
        MID_COPY.with(|h| h.borrow_mut().take())
    }

    /// Run the hook, then copy the slot's bytes from `offset` into `rest`
    /// again, so the reader's copy mixes before and after, as a copy a
    /// writer overtook part-way would. The hook is taken out while it runs,
    /// so a read inside it goes straight through.
    pub(super) fn mid_copy(ring: &PulseRing, slot: u64, offset: usize, rest: &mut [u8]) {
        let Some(mut hook) = take_mid_copy() else {
            return;
        };
        hook(ring, slot);
        MID_COPY.with(|h| {
            h.borrow_mut().get_or_insert(hook);
        });
        assert!(
            offset + rest.len() <= PULSE_SIZE,
            "a copy past the slot's pulse"
        );
        assert!(offset.is_multiple_of(8), "a re-read starts on a word");
        // SAFETY: `slot` is below the ring's capacity (every reader passes
        // its position modulo the capacity), so `slot_ptr` is the start of a
        // mapped slot of at least PULSE_SIZE bytes, 8-byte aligned; the
        // asserts keep the `rest.len()` bytes from `offset` inside it and
        // word-aligned, and the slot is only ever accessed as atomic words.
        unsafe { core_region::shm::load_words(ring.slot_ptr(slot).add(offset), rest) };
    }
}

#[cfg(test)]
mod counter_tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    /// The write count lives in shared memory, where anything can set it to
    /// u64::MAX; every publish path wraps it.
    #[test]
    fn a_write_count_at_the_top_wraps() {
        let name = format!("/test-wrap-{}", std::process::id());
        let mut ring = PulseRing::create(&name, 4).expect("create");
        let pulse = Pulse::zeroed();
        ring.total_writes().store(u64::MAX, Ordering::Release);
        assert_eq!(ring.publish(&pulse), 0);
        ring.total_writes().store(u64::MAX, Ordering::Release);
        assert_eq!(ring.publish_with_crc(&pulse), 0);
        assert_eq!(ring.write_count(), 0);
        assert_eq!(ring.cursor_position(), 2);
    }
}

#[cfg(test)]
mod opt7_crc_tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use pulse_canon::Pulse;

    #[test]
    fn crc_round_trip_succeeds() {
        let name = format!("/test-crc-rt-{}", std::process::id());
        let mut ring = PulseRing::create(&name, 64).expect("create");
        let mut bytes = [0u8; 128];
        bytes[8..16].copy_from_slice(&0x1234567890ABCDEFu64.to_le_bytes());
        bytes[100..108].copy_from_slice(b"AAPL@152");
        let pulse = Pulse::from_bytes(&bytes).expect("from_bytes");
        ring.publish_with_crc(&pulse);
        let recovered = ring.read_slot_verify_crc(0).expect("verify").expect("Some");
        assert_eq!(
            &recovered.as_bytes()[8..16],
            &0x1234567890ABCDEFu64.to_le_bytes()
        );
        assert_eq!(&recovered.as_bytes()[100..108], b"AAPL@152");
    }

    #[test]
    fn crc_trailer_agrees_with_pms_crc32c() {
        let name = format!("/test-crc-agree-{}", std::process::id());
        let mut ring = PulseRing::create(&name, 4).expect("create");
        let mut bytes = [0u8; 128];
        bytes[8..16].copy_from_slice(&0xDEAD_BEEFu64.to_le_bytes());
        let pulse = Pulse::from_bytes(&bytes).expect("from_bytes");
        ring.publish_with_crc(&pulse);
        let stored = ring.read_slot(0).expect("Some");
        assert!(pms_crc32c::verify_pulse_crc(stored.as_bytes()).is_ok());
    }

    #[test]
    fn crc_mismatch_detected_after_corruption() {
        let name = format!("/test-crc-mm-{}", std::process::id());
        let mut ring = PulseRing::create(&name, 64).expect("create");
        let mut bytes = [0u8; 128];
        bytes[8..16].copy_from_slice(&0xDEADBEEFCAFEBABEu64.to_le_bytes());
        let pulse = Pulse::from_bytes(&bytes).expect("from_bytes");
        ring.publish_with_crc(&pulse);

        // Corrupt the slot's data area directly (simulating bit-flip)
        let slot_ptr = ring.slot_ptr(0);
        // SAFETY: `slot_ptr(0)` returns a pointer into the ring's
        // mapped region for slot 0. Byte offset 50 is within the
        // 128-byte slot data area (between the seq_lock at 0..8 and
        // the CRC trailer at 124..128). The test owns the ring
        // exclusively for the duration of this assertion; no
        // concurrent writer can race.
        unsafe {
            *slot_ptr.add(50) ^= 0xFF;
        } // flip a byte mid-payload

        let result = ring.read_slot_verify_crc(0);
        assert!(matches!(result, Err(RingError::CrcMismatch { .. })));
    }
}
