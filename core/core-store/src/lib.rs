// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! `EnvelopeStore`: a shared-memory ring of `PulseEnvelope`s in their
//! canonical encoding, which a Pulse names by id and store cursor, tier 1.
//!
//! ## Layout (version 3)
//!
//! The region starts with a 64-byte header, continues with `capacity`
//! fixed-size slots, and ends with an index of `B` buckets:
//!
//! ```text
//! header:  0..8   write cursor (AtomicU64): claims cursors, proves nothing
//!          8..12  magic "PMES" (AtomicU32, stored last on create)
//!         12..16  layout version (u32 LE) = 2
//!         16..20  capacity (u32 LE)
//!         20..24  MAX_ENTRY_SIZE (u32 LE)
//!         24..32  busy claims (AtomicU64): claims that found their slot
//!                 held or taken and gave up their cursor
//!         32..40  unlink token (AtomicU64): zero until the creator drops
//!                 its handle, which writes a token here to learn whether
//!                 the name is still this store's before it unlinks it
//!         40..44  index buckets B (u32 LE): a power of two, at most the
//!                 capacity rounded up to one
//!         44..64  reserved, zero
//! slot:    0..8   seq (AtomicU64): 0 never written, 2·lap+1 write in
//!                 progress, 2·lap+2 published, with lap = cursor / capacity
//!          8..24  envelope id
//!         24..28  body length (u32 LE)
//!         28..64  reserved, zero
//!         64..    body: the envelope's canonical bytes, at most
//!                 MAX_ENTRY_SIZE
//! index:  B buckets of 32 bytes, each four AtomicU64 entries: a cursor
//!         plus one, zero for empty
//! ```
//!
//! A writer takes a cursor with `fetch_add` and claims its slot by moving
//! the seq, by compare-and-swap, from an even value no newer than `2·lap`
//! to its mark `2·lap+1`; it writes id, length and body, then publishes
//! `2·lap+2`. A claim never starts from an odd seq, so no two writers
//! write one slot. A slot held by another writer, mid-store or crashed, or
//! taken by a newer lap is left alone: the writer counts the failed claim
//! in the header and takes a fresh cursor, up to [`CLAIM_ATTEMPTS`]. A
//! crashed writer thus costs one slot, not an envelope per lap.
//!
//! A reader keeps a copy only when the slot's seq was the published value
//! for the cursor it wants both before and after the copy, and waits only
//! for that cursor's writer, skipping at once a slot an older lap's writer
//! holds. It returns an envelope only when the copy decodes as one
//! canonical envelope carrying the slot's id that verifies.
//! [`EnvelopeStore::fetch_at`] reads the copy at one cursor,
//! [`EnvelopeStore::fetch`] a copy with an id, and
//! [`EnvelopeStore::read_since`] every copy after a cursor.
//!
//! The index is a hint, never the truth (ADR-0020). A writer that publishes
//! an envelope at cursor `c` stores `c + 1` in its id's bucket, entry
//! `c mod 4`, with one relaxed store, after the publish. `fetch` tries the
//! bucket's cursors newest first through `fetch_at`, which refuses a cursor
//! whose slot was overwritten or holds another id, and only when none
//! returns the envelope scans the slots; so a hit costs one bucket and one
//! slot copy whatever the capacity, and a lost or stale entry costs the
//! scan, never a wrong answer. The creator chooses `B`
//! ([`EnvelopeStore::create_exclusive_with_index`]); a store made without a
//! choice gets [`default_index_buckets`] of its capacity. Opens check the
//! size and the header, as the ring's do, before they map anything.
//! ADR-0011 records the reasons; the POSIX calls are `core_region::shm`'s
//! (ADR-0013).

use std::sync::atomic::{fence, AtomicU32, AtomicU64, Ordering};

use core_region::shm::{self, Mapping, Name, Opened};
use pulse_canon::{PulseEnvelope, PulseEnvelopeId};

/// One cache line, so the write cursor does not share slot 0's.
const HEADER_SIZE: usize = 64;
/// Maximum size of a single envelope body: the envelope's canonical
/// encoding, framing included.
pub const MAX_ENTRY_SIZE: usize = 65_536;
/// A slot's prefix, one cache line, so its seq never shares the previous
/// body's.
const ENTRY_HEADER: usize = 64;
/// Layout version written into the header and checked by `open`.
pub const LAYOUT_VERSION: u32 = 3;
const MAGIC: u32 = u32::from_le_bytes(*b"PMES");

const H_MAGIC: usize = 8;
const H_VERSION: usize = 12;
const H_CAPACITY: usize = 16;
const H_MAX_ENTRY: usize = 20;
const H_BUSY_CLAIMS: usize = 24;
const H_INDEX_BUCKETS: usize = 40;
/// Entries per index bucket: four cursors, half a cache line.
const INDEX_WAYS: usize = 4;
/// Bytes per index bucket.
const BUCKET_BYTES: usize = INDEX_WAYS * 8;
const SLOT_ID: usize = 8;
const SLOT_LEN: usize = 24;

/// Cursors [`EnvelopeStore::store`] tries before it reports
/// [`EnvelopeStoreError::SlotBusy`]: a held slot costs a cursor, not an
/// envelope.
pub const CLAIM_ATTEMPTS: usize = 4;
/// Spins a reader waits for the writer of the cursor it wants: more than
/// the ring's, as a body of up to 64 KiB takes longer to land.
const READ_SPINS: usize = 1_000;
pub use core_region::shm::RESERVE_ATTEMPTS;

#[non_exhaustive]
/// Errors returned by `EnvelopeStore` operations.
#[derive(Debug)]
pub enum EnvelopeStoreError {
    /// `shm_open(3)`, `fstat(2)` or a header read failed; the field is the
    /// `errno`.
    Open(i32),
    /// `ftruncate` failed; the field is the `errno`.
    Truncate(i32),
    /// Linux could not reserve a new store's pages: `posix_fallocate(3)`
    /// failed, with `ENOSPC` on a full `/dev/shm`, `ENOMEM`, or `EINTR`
    /// after [`RESERVE_ATTEMPTS`] tries. The object was unlinked and
    /// nothing was mapped. Never returned off Linux.
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
    /// The name contains a NUL byte.
    InvalidName,
    /// Zero slots, more than the header's 32-bit capacity field can record,
    /// or so many that `64 + capacity × slot size` does not fit a `usize`
    /// and a file offset. Nothing was opened, created or mapped.
    InvalidCapacity {
        /// Slots asked for.
        capacity: usize,
    },
    /// The object is smaller than the store the caller asked to map, or,
    /// for [`EnvelopeStore::open_existing`], than a header or the store its
    /// header describes.
    RegionTooSmall {
        /// Size of the object, from `fstat(2)`.
        have: u64,
        /// Bytes the requested capacity needs.
        need: u64,
    },
    /// The header does not describe the layout this build uses.
    LayoutMismatch {
        /// `magic`, `version`, `capacity` or `max_entry`.
        field: &'static str,
        /// Value found in the region.
        have: u64,
        /// Value this build needs.
        need: u64,
    },
    /// Each of the [`CLAIM_ATTEMPTS`] cursors tried found its slot held or
    /// taken by a newer lap, or named a lap too large to mark (a write
    /// cursor corrupted in shared memory). Nothing was written; readers
    /// skip every cursor given up.
    SlotBusy {
        /// The last cursor tried.
        cursor: u64,
    },
    /// An index of `buckets` buckets for a store of `capacity` slots: the
    /// count must be a power of two no larger than the capacity rounded up
    /// to one. Nothing was created.
    InvalidIndex {
        /// Buckets asked for.
        buckets: usize,
        /// The store's capacity.
        capacity: usize,
    },
    /// The envelope's canonical encoding exceeds [`MAX_ENTRY_SIZE`] bytes.
    EnvelopeTooLarge {
        /// Size of the canonical encoding in bytes.
        actual: usize,
        /// Maximum permitted size in bytes.
        max: usize,
    },
}

impl std::fmt::Display for EnvelopeStoreError {
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
            Self::InvalidName => write!(f, "envelope-store name contains NUL byte"),
            Self::InvalidCapacity { capacity } => write!(
                f,
                "an envelope store of {capacity} slots cannot be made or opened: it needs at least one slot, at most {} slots, and a size in bytes that fits a file offset",
                u32::MAX
            ),
            Self::RegionTooSmall { have, need } => write!(
                f,
                "shared-memory object is {have} bytes but the requested capacity needs {need}"
            ),
            Self::LayoutMismatch { field, have, need } => write!(
                f,
                "envelope-store {field} mismatch: region has {have}, this build needs {need}"
            ),
            Self::SlotBusy { cursor } => write!(
                f,
                "no slot could be claimed in {CLAIM_ATTEMPTS} attempts (last cursor tried: {cursor})"
            ),
            Self::EnvelopeTooLarge { actual, max } => {
                write!(f, "envelope too large: {} > {} bytes", actual, max)
            }
            Self::InvalidIndex { buckets, capacity } => write!(
                f,
                "an index of {buckets} buckets does not suit a store of {capacity} slots: it needs a power of two no larger than {}",
                (*capacity).max(1).next_power_of_two()
            ),
        }
    }
}

impl std::error::Error for EnvelopeStoreError {}

fn shm_error(e: shm::Error) -> EnvelopeStoreError {
    match e {
        shm::Error::Open(e) => EnvelopeStoreError::Open(e),
        shm::Error::Truncate(e) => EnvelopeStoreError::Truncate(e),
        shm::Error::NoSpace { need, errno } => EnvelopeStoreError::NoSpace { need, errno },
        shm::Error::Map(e) => EnvelopeStoreError::Map(e),
        shm::Error::InvalidName => EnvelopeStoreError::InvalidName,
        shm::Error::TooSmall { have, need } => EnvelopeStoreError::RegionTooSmall { have, need },
    }
}

/// Whether an open's result is what an unfinished creator leaves: an object
/// too small (not yet sized) or a zero magic.
fn creator_unfinished(opened: &Result<EnvelopeStore, EnvelopeStoreError>) -> bool {
    matches!(
        opened,
        Err(EnvelopeStoreError::RegionTooSmall { .. })
            | Err(EnvelopeStoreError::LayoutMismatch {
                field: "magic",
                have: 0,
                ..
            })
    )
}

/// A shared-memory ring of envelopes. The handle that created the store
/// unlinks its name on drop, while the name still names the store, unless
/// it gave the name up ([`EnvelopeStore::disown`]); other handles only
/// unmap (`tests/owner_drop.rs`).
pub struct EnvelopeStore {
    /// Its descriptor is closed once mapped: the mapping keeps the object
    /// alive.
    map: Mapping,
    capacity: usize,
    /// Index buckets, a power of two.
    buckets: usize,
    owner: bool,
}

// SAFETY: the handle owns a mapping that stays valid until it drops and
// holds nothing tied to the thread that made it. Through `&self` the header
// cursor, the busy-claim counter and every slot's seq word change only as
// atomics. A slot's bytes are written only by the writer whose
// compare-and-swap moved its seq from an even value to that writer's odd
// mark, and only until it stores the next even value; a claim never starts
// from an odd seq, so no two writers ever write the same slot. A reader's
// copy can overlap a writer's plain writes, as in any SeqLock, but every
// copy is bounded to its slot and taken into private memory, and the reader
// keeps it only if the seq was the published value for the cursor it wants
// both before and after the copy.
unsafe impl Send for EnvelopeStore {}
// SAFETY: see the `Send` impl above; the same protocol covers `Sync`.
unsafe impl Sync for EnvelopeStore {}

impl EnvelopeStore {
    /// [`Self::create_or_open`].
    ///
    /// # Errors
    /// Those of [`Self::create_or_open`].
    pub fn create(name: &str, capacity: usize) -> Result<Self, EnvelopeStoreError> {
        Self::create_or_open(name, capacity)
    }

    /// Create a store of `capacity` slots under a name that must be free;
    /// the handle is its creator. On Linux the pages are reserved before
    /// they are mapped, so a full `/dev/shm` is
    /// [`EnvelopeStoreError::NoSpace`] here rather than SIGBUS at the first
    /// touch of a page (`tests/no_space.rs`). A failure after the object
    /// exists unlinks it.
    ///
    /// # Errors
    /// [`EnvelopeStoreError::Open`] with `EEXIST` when the name holds an
    /// object, [`EnvelopeStoreError::InvalidCapacity`] for a zero or
    /// oversized `capacity` (nothing is created), on Linux
    /// [`EnvelopeStoreError::NoSpace`], and the other libc and mapping
    /// failures.
    pub fn create_exclusive(name: &str, capacity: usize) -> Result<Self, EnvelopeStoreError> {
        Self::create_inner(name, capacity, default_index_buckets(capacity))
    }

    /// [`Self::create_exclusive`] with an index of `index_buckets` buckets
    /// rather than [`default_index_buckets`] of the capacity: more buckets
    /// keep more envelopes findable without a scan, for 32 bytes each
    /// (ADR-0020). Opens read the count from the header.
    ///
    /// # Errors
    /// Those of [`Self::create_exclusive`], and
    /// [`EnvelopeStoreError::InvalidIndex`] when `index_buckets` is not a
    /// power of two no larger than the capacity rounded up to one, before
    /// anything is created.
    pub fn create_exclusive_with_index(
        name: &str,
        capacity: usize,
        index_buckets: usize,
    ) -> Result<Self, EnvelopeStoreError> {
        Self::create_inner(name, capacity, index_buckets)
    }

    /// Create a store under `name`, or attach to the one already there.
    /// Safe for concurrent callers: a creator that has not yet sized the
    /// object or written its header is waited for, briefly, before its
    /// object is refused.
    ///
    /// # Errors
    /// Those of [`Self::create_exclusive`] and [`Self::open`]:
    /// [`EnvelopeStoreError::InvalidCapacity`] before anything is created
    /// or opened, and [`EnvelopeStoreError::LayoutMismatch`] for an
    /// existing store of another layout or capacity.
    pub fn create_or_open(name: &str, capacity: usize) -> Result<Self, EnvelopeStoreError> {
        match Self::create_exclusive(name, capacity) {
            Err(EnvelopeStoreError::Open(libc::EEXIST)) => {
                shm::wait_out_creator(|| Self::open(name, capacity), creator_unfinished)
            }
            created => created,
        }
    }

    /// Remove the name `name` without opening the object behind it:
    /// `Ok(true)` when an object was removed, `Ok(false)` when none
    /// existed. Mappings stay valid until they unmap.
    ///
    /// # Errors
    ///
    /// - [`EnvelopeStoreError::InvalidName`] if `name` contains a NUL byte.
    /// - [`EnvelopeStoreError::Unlink`] if `shm_unlink(2)` fails for a reason other
    ///   than the object not existing.
    pub fn unlink(name: &str) -> Result<bool, EnvelopeStoreError> {
        let name = Name::new(name).map_err(shm_error)?;
        shm::unlink(&name).map_err(EnvelopeStoreError::Unlink)
    }

    /// Attach to an existing store of `capacity` slots.
    /// [`Self::open_existing`] needs no capacity.
    ///
    /// The size and then the header are checked before anything is mapped,
    /// so an open never touches a page its creator has not reserved, which
    /// a full `/dev/shm` answers with SIGBUS (`tests/full_dev_shm.rs`).
    ///
    /// # Errors
    /// [`EnvelopeStoreError::InvalidCapacity`] for a zero or oversized
    /// `capacity`, before the name is opened;
    /// [`EnvelopeStoreError::RegionTooSmall`] when the object cannot hold
    /// it; [`EnvelopeStoreError::LayoutMismatch`] when the header disagrees
    /// with this build, a zero magic included (`open` does not wait on
    /// one); `Open` when `shm_open(2)`, `fstat(2)` or the header's
    /// `pread(2)` fails, and the other libc and mapping failures.
    pub fn open(name: &str, capacity: usize) -> Result<Self, EnvelopeStoreError> {
        // The smallest store of this capacity, with a one-bucket index: an
        // object shorter than that is refused before its header is read.
        let smallest = store_bytes(capacity, 1)?;
        let name = Name::new(name).map_err(shm_error)?;
        let opened = Opened::open(name).map_err(shm_error)?;
        let have = opened.len();
        if have < smallest as u64 {
            return Err(EnvelopeStoreError::RegionTooSmall {
                have,
                need: smallest as u64,
            });
        }
        let (capacity, buckets) = StoreHeader::read(opened.fd())?.check(Some(capacity))?;
        Self::attach(opened, capacity, buckets)
    }

    /// Attach to an existing store by name alone, taking its capacity from
    /// its header, read and checked as [`Self::open`] reads and checks it.
    /// An object at size zero, or with a zero magic, may be a creator that
    /// has not finished, so it is retried, as [`Self::create_or_open`]
    /// retries it, before it is refused.
    ///
    /// # Errors
    /// - [`EnvelopeStoreError::InvalidName`] if `name` contains a NUL byte.
    /// - [`EnvelopeStoreError::Open`] if `shm_open(2)`, `fstat(2)` or the
    ///   header's `pread(2)` fails: `ENOENT` when no object exists under
    ///   the name.
    /// - [`EnvelopeStoreError::RegionTooSmall`] if the object is smaller
    ///   than a header, or than the store its header describes.
    /// - [`EnvelopeStoreError::LayoutMismatch`] if the magic, the layout
    ///   version or the entry size is not this build's, or the header
    ///   records a capacity of zero.
    /// - [`EnvelopeStoreError::Map`] if `mmap(2)` fails.
    pub fn open_existing(name: &str) -> Result<Self, EnvelopeStoreError> {
        let name = Name::new(name).map_err(shm_error)?;
        shm::wait_out_creator(
            || Self::open_by_header(&name),
            |opened| {
                matches!(
                    opened,
                    Err(EnvelopeStoreError::RegionTooSmall { have: 0, .. })
                        | Err(EnvelopeStoreError::LayoutMismatch {
                            field: "magic",
                            have: 0,
                            ..
                        })
                )
            },
        )
    }

    /// One attempt of [`Self::open_existing`].
    fn open_by_header(name: &Name) -> Result<Self, EnvelopeStoreError> {
        let opened = Opened::open(name.clone()).map_err(shm_error)?;
        let have = opened.len();
        if have < HEADER_SIZE as u64 {
            return Err(EnvelopeStoreError::RegionTooSmall {
                have,
                need: HEADER_SIZE as u64,
            });
        }
        let (capacity, buckets) = StoreHeader::read(opened.fd())?.check(None)?;
        Self::attach(opened, capacity, buckets)
    }

    /// Map the opened store as `capacity` slots and an index of `buckets`,
    /// as its published header describes, once the object is long enough.
    fn attach(opened: Opened, capacity: usize, buckets: usize) -> Result<Self, EnvelopeStoreError> {
        let have = opened.len();
        // A size that fits no `usize` fits no object either.
        let total_size =
            store_bytes(capacity, buckets).map_err(|_| EnvelopeStoreError::RegionTooSmall {
                have,
                need: u64::MAX,
            })?;
        if have < total_size as u64 {
            return Err(EnvelopeStoreError::RegionTooSmall {
                have,
                need: total_size as u64,
            });
        }
        // A published magic means the pages were reserved (Linux), so
        // touching them cannot fault for want of room.
        let mut map = opened.map(total_size).map_err(shm_error)?;
        map.close_fd();
        let store = Self {
            map,
            capacity,
            buckets,
            owner: false,
        };
        // Checked again through the mapping: its load of the magic, fenced
        // with acquire, orders this handle's reads after the formatting.
        store.check_header()?;
        Ok(store)
    }

    /// Create the object behind `name`, which must be free, and format a
    /// store of `capacity` slots in it. Not zero-filled: the kernel's zero
    /// pages are already an empty store, and a fill would touch every page,
    /// which a full tmpfs answers with SIGBUS.
    fn create_inner(
        name: &str,
        capacity: usize,
        buckets: usize,
    ) -> Result<Self, EnvelopeStoreError> {
        // The capacity first, so a bad one is InvalidCapacity whatever the
        // index.
        store_bytes(capacity, 1)?;
        if !index_fits(capacity, buckets) {
            return Err(EnvelopeStoreError::InvalidIndex { buckets, capacity });
        }
        let total_size = store_bytes(capacity, buckets)?;
        let name = Name::new(name).map_err(shm_error)?;
        let mut map = Mapping::create_exclusive(name, total_size).map_err(shm_error)?;
        map.close_fd();

        let store = Self {
            map,
            capacity,
            buckets,
            owner: true,
        };
        store.write_header_u32(H_VERSION, LAYOUT_VERSION);
        store.write_header_u32(H_CAPACITY, u32::try_from(capacity).unwrap_or(u32::MAX));
        store.write_header_u32(H_MAX_ENTRY, MAX_ENTRY_SIZE as u32);
        // Fits: the count is at most the capacity rounded up to a power of
        // two, and the capacity fits a `u32`.
        store.write_header_u32(H_INDEX_BUCKETS, buckets as u32);
        // The magic last, with release ordering: a reader that sees it and
        // fences with acquire sees the fields above.
        store.magic_atomic().store(MAGIC, Ordering::Release);
        Ok(store)
    }

    fn check_header(&self) -> Result<(), EnvelopeStoreError> {
        // SAFETY: the mapping's start is page aligned, spans the header and
        // lives as long as `self`.
        let (_, buckets) =
            unsafe { StoreHeader::from_mapping(self.map.ptr()) }.check(Some(self.capacity))?;
        mismatch("index_buckets", buckets as u32, self.buckets as u32)
    }

    /// Store an envelope's canonical bytes and return the cursor it took.
    /// A held slot is given up for the next cursor, counted in
    /// [`Self::busy_claims`], so the cursor can be later than the write
    /// cursor was when the call began. The envelope is not verified: one
    /// whose id does not match its content is stored but never read back.
    ///
    /// # Errors
    /// - [`EnvelopeStoreError::EnvelopeTooLarge`] when the canonical
    ///   encoding exceeds [`MAX_ENTRY_SIZE`] (64 KiB); no cursor is claimed.
    /// - [`EnvelopeStoreError::SlotBusy`] when every one of the
    ///   [`CLAIM_ATTEMPTS`] cursors tried landed on a held or taken slot, or
    ///   named a lap too large to mark (a corrupted write cursor). Nothing is
    ///   written, and readers skip the cursors given up.
    pub fn store(&self, envelope: &PulseEnvelope) -> Result<u64, EnvelopeStoreError> {
        let data = envelope.to_canonical_bytes();

        if data.len() > MAX_ENTRY_SIZE {
            return Err(EnvelopeStoreError::EnvelopeTooLarge {
                actual: data.len(),
                max: MAX_ENTRY_SIZE,
            });
        }

        let cap = self.capacity as u64;
        let mut cursor = 0;
        for _ in 0..CLAIM_ATTEMPTS {
            cursor = self.cursor_atomic().fetch_add(1, Ordering::AcqRel);
            let slot_idx = (cursor % cap) as usize;
            let Some(in_progress) = lap_mark(cursor, cap) else {
                // A lap too large to mark: give the cursor up.
                self.busy_claims_atomic().fetch_add(1, Ordering::Relaxed);
                continue;
            };
            let seq = self.slot_seq(slot_idx);
            if !claim_slot(seq, in_progress) {
                self.busy_claims_atomic().fetch_add(1, Ordering::Relaxed);
                continue;
            }
            // Release fence: the odd mark is visible before any payload byte.
            fence(Ordering::Release);

            let slot = self.slot_ptr(slot_idx);
            // The id, the length and the four zero bytes after it: the
            // slot's bytes SLOT_ID..SLOT_LEN + 8, three words.
            let mut head = [0u8; SLOT_LEN + 8 - SLOT_ID];
            head[..16].copy_from_slice(&envelope.id().0);
            head[SLOT_LEN - SLOT_ID..][..4].copy_from_slice(&(data.len() as u32).to_le_bytes());
            let whole = data.len() / 8 * 8;
            let mut tail = [0u8; 8];
            tail[..data.len() - whole].copy_from_slice(&data[whole..]);
            // SAFETY: slot_ptr is within the mapped region and 8-byte aligned
            // (slots are whole words apart from a page-aligned start), and
            // every store below stays inside ENTRY_HEADER + MAX_ENTRY_SIZE
            // bytes of the slot because `data.len()` was bounded above and
            // MAX_ENTRY_SIZE is a multiple of eight; the bytes are only ever
            // accessed as atomic words. The claim made the slot this
            // writer's alone until it publishes, because no writer claims a
            // slot whose seq is odd.
            unsafe {
                shm::store_words(slot.add(SLOT_ID), &head);
                shm::store_words(slot.add(ENTRY_HEADER), &data[..whole]);
                if whole < data.len() {
                    shm::store_words(slot.add(ENTRY_HEADER + whole), &tail);
                }
            }

            #[cfg(test)]
            hook::before_publish(self);

            seq.store(in_progress + 1, Ordering::Release);
            // After the publish, so an entry never names an unpublished
            // copy; relaxed, since `fetch_at` checks the slot's seq anyway.
            self.index_entry(&envelope.id(), cursor)
                .store(cursor.wrapping_add(1), Ordering::Relaxed);
            return Ok(cursor);
        }
        Err(EnvelopeStoreError::SlotBusy { cursor })
    }

    /// An envelope with id `id`, or `None` if every copy was overwritten or
    /// none was stored. The index's cursors for the id's bucket are tried
    /// first, newest first, through [`Self::fetch_at`]; only when none
    /// returns the envelope are the slots scanned in order, past held
    /// slots, corrupt lengths and unverifiable bodies (ADR-0020). Envelopes
    /// with the same id have the same bytes, so which copy comes back is
    /// seen only by its cursor, which [`Self::fetch_at`] names.
    pub fn fetch(&self, id: &PulseEnvelopeId) -> Option<PulseEnvelope> {
        self.fetch_indexed(id).or_else(|| self.fetch_by_scan(id))
    }

    /// [`Self::fetch`] through the index alone: the bucket's cursors, newest
    /// first, each read with [`Self::fetch_at`].
    fn fetch_indexed(&self, id: &PulseEnvelopeId) -> Option<PulseEnvelope> {
        let mut cursors = [0u64; INDEX_WAYS];
        for (way, cursor) in cursors.iter_mut().enumerate() {
            *cursor = self.bucket_entry(id, way).load(Ordering::Relaxed);
        }
        cursors.sort_unstable_by(|a, b| b.cmp(a));
        cursors
            .iter()
            .take_while(|&&c| c != 0)
            .find_map(|&c| self.fetch_at(c - 1, id))
    }

    /// [`Self::fetch`]'s fallback: the first copy with `id`, scanning the
    /// slots in order.
    fn fetch_by_scan(&self, id: &PulseEnvelopeId) -> Option<PulseEnvelope> {
        #[cfg(test)]
        hook::count_scan();
        let current = self.write_cursor();
        let cap = self.capacity as u64;
        for i in 0..self.capacity {
            let index = i as u64;
            // A lap too large to mark, from a corrupted write cursor, is newer
            // than any mark a slot can hold.
            let newest_mark = if current > index {
                lap_mark(current - 1 - index, cap).unwrap_or(u64::MAX)
            } else {
                0
            };
            if let Some(env) = self.fetch_in_slot(i, id, newest_mark) {
                return Some(env);
            }
        }
        None
    }

    /// The envelope stored at `cursor`, if that copy is still in its slot and
    /// carries `id`: the copy a signal names, where [`Self::fetch`] returns
    /// the first holding the id (envelopes with the same content share an
    /// id). `None` when the cursor was never handed out, was given up or not
    /// published within the read budget, was overwritten, or holds another
    /// id or an unverifiable body (`tests/fetch_at.rs`).
    pub fn fetch_at(&self, cursor: u64, id: &PulseEnvelopeId) -> Option<PulseEnvelope> {
        if cursor >= self.write_cursor() {
            return None; // never handed out
        }
        let cap = self.capacity as u64;
        let slot_idx = (cursor % cap) as usize;
        let mark = (cursor / cap).checked_mul(2)?.checked_add(1)?;
        let want = mark.checked_add(1)?;
        let seq = self.slot_seq(slot_idx);
        for _ in 0..READ_SPINS {
            let v1 = seq.load(Ordering::Acquire);
            if v1 > want {
                return None; // a later lap has the slot: the copy is gone
            }
            if v1 & 1 != 0 && v1 < mark {
                // Held by an older lap's writer: this cursor's writer
                // routed around it and never wrote here.
                return None;
            }
            if v1 < want {
                reader_spin();
                continue; // this cursor's writer is yet to claim, or mid-write
            }
            match self.copy_slot(slot_idx, want) {
                SlotCopy::Body { id: slot_id, body } => {
                    return if slot_id == id.0 {
                        decode_body(&slot_id, &body)
                    } else {
                        None
                    };
                }
                SlotCopy::BadLength => return None,
                SlotCopy::Changed => reader_spin(), // lapped under the copy: re-read
            }
        }
        None
    }

    /// One slot of [`Self::fetch`]: `Some` only for a stable, published
    /// slot whose id matches and whose body decodes and verifies.
    /// `newest_mark` is the in-progress mark of the newest cursor handed
    /// out for the slot, the only writer worth waiting for.
    fn fetch_in_slot(
        &self,
        index: usize,
        id: &PulseEnvelopeId,
        newest_mark: u64,
    ) -> Option<PulseEnvelope> {
        let slot = self.slot_ptr(index);
        let seq = self.slot_seq(index);
        for _ in 0..READ_SPINS {
            let v1 = seq.load(Ordering::Acquire);
            if v1 == 0 {
                return None; // never written
            }
            if v1 & 1 != 0 {
                if v1 < newest_mark {
                    return None; // held by an older lap's writer: skip at once
                }
                reader_spin();
                continue; // the newest cursor's writer holds the slot
            }
            let mut stored_id = [0u8; 16];
            // SAFETY: the id lives at a fixed, 8-byte aligned offset inside
            // the slot, and is only ever accessed as atomic words.
            unsafe { shm::load_words(slot.add(SLOT_ID), &mut stored_id) };
            #[cfg(fuzzing)]
            fuzzing::mid_copy(self, index);
            fence(Ordering::Acquire);
            if seq.load(Ordering::Acquire) != v1 {
                reader_spin();
                continue; // the id changed under us
            }
            if stored_id != id.0 {
                return None; // stable and not ours
            }
            match self.copy_slot(index, v1) {
                SlotCopy::Changed => reader_spin(),
                SlotCopy::BadLength => return None,
                SlotCopy::Body { id: slot_id, body } => {
                    return if slot_id == id.0 {
                        decode_body(&slot_id, &body)
                    } else {
                        None
                    };
                }
            }
        }
        None
    }

    /// Copy a slot's id and body out under seq `want`, so they can be
    /// decoded from private memory.
    fn copy_slot(&self, index: usize, want: u64) -> SlotCopy {
        let slot = self.slot_ptr(index);
        let seq = self.slot_seq(index);
        let mut head = [0u8; SLOT_LEN + 4 - SLOT_ID];
        // SAFETY: the id and the length live at fixed, 8-byte aligned
        // offsets inside the slot's 64-byte prefix, only ever accessed as
        // atomic words.
        unsafe { shm::load_words(slot.add(SLOT_ID), &mut head) };
        #[cfg(fuzzing)]
        fuzzing::mid_copy(self, index);
        let mut id = [0u8; 16];
        id.copy_from_slice(&head[..16]);
        let mut len_bytes = [0u8; 4];
        len_bytes.copy_from_slice(&head[SLOT_LEN - SLOT_ID..]);
        let len = u32::from_le_bytes(len_bytes) as usize;
        if len == 0 || len > MAX_ENTRY_SIZE {
            fence(Ordering::Acquire);
            return if seq.load(Ordering::Acquire) == want {
                SlotCopy::BadLength
            } else {
                SlotCopy::Changed
            };
        }
        let mut body = vec![0u8; len];
        // SAFETY: `len` was bounded to MAX_ENTRY_SIZE, a multiple of eight,
        // so the words that cover it stay inside the slot, from an 8-byte
        // aligned offset, and they are only ever accessed atomically. The
        // body is copied out before it is decoded, so a concurrent overwrite
        // can only change the copy, never what is dereferenced.
        unsafe { shm::load_words(slot.add(ENTRY_HEADER), &mut body) };
        // Acquire fence: the copy completes before the seq is re-read.
        fence(Ordering::Acquire);
        if seq.load(Ordering::Acquire) == want {
            SlotCopy::Body { id, body }
        } else {
            SlotCopy::Changed
        }
    }

    /// The envelopes stored since `since_cursor`, in cursor order (only the
    /// newest `capacity` if the writer has lapped), and the cursor to pass
    /// next. A cursor is skipped, after at most the read budget, when its
    /// writer has not published it or gave it up, its slot was overwritten,
    /// or its body is unverifiable, so a streaming reader never wedges.
    pub fn read_since(&self, since_cursor: u64) -> (Vec<PulseEnvelope>, u64) {
        let current = self.write_cursor();
        if current <= since_cursor {
            return (Vec::new(), since_cursor);
        }

        let cap = self.capacity as u64;
        let elapsed = current - since_cursor;
        let start = if elapsed > cap {
            current - cap
        } else {
            since_cursor
        };

        let mut envelopes = Vec::with_capacity((current - start) as usize);
        for i in start..current {
            let slot_idx = (i % cap) as usize;
            let Some(mark) = lap_mark(i, cap) else {
                // A lap the seq word cannot mark, from a corrupted write
                // cursor, was never published: skip it as a lapped slot.
                continue;
            };
            let want = mark + 1;
            let seq = self.slot_seq(slot_idx);
            for _ in 0..READ_SPINS {
                let v1 = seq.load(Ordering::Acquire);
                if v1 > want {
                    break; // lapped during the call: the envelope is gone
                }
                if v1 & 1 != 0 && v1 < mark {
                    // Held by an older lap's writer. Cursor i's writer
                    // routes around a held slot, so there is nothing to
                    // wait for.
                    break;
                }
                if v1 < want {
                    reader_spin();
                    continue; // cursor i's writer is yet to claim, or mid-write
                }
                match self.copy_slot(slot_idx, want) {
                    SlotCopy::Body { id, body } => {
                        envelopes.extend(decode_body(&id, &body));
                        break;
                    }
                    SlotCopy::BadLength => break, // unusable length: skip the slot
                    SlotCopy::Changed => reader_spin(), // changed under us: retry
                }
            }
        }

        (envelopes, current)
    }

    /// The write cursor: the next cursor a store takes.
    pub fn write_cursor(&self) -> u64 {
        self.cursor_atomic().load(Ordering::Acquire)
    }

    /// Cursors given up by [`Self::store`] since the region was created, by
    /// every writer, because their slot was held or taken by a newer lap, or
    /// their lap was too large to mark. A writer that crashed mid-store adds
    /// one each time the ring comes round to its slot. The count is in the
    /// header, so every handle reads the same value.
    pub fn busy_claims(&self) -> u64 {
        self.busy_claims_atomic().load(Ordering::Relaxed)
    }

    /// Index buckets, fixed when the store was created:
    /// [`default_index_buckets`] of the capacity unless its creator chose.
    pub fn index_buckets(&self) -> usize {
        self.buckets
    }

    /// Number of slots in the buffer.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// The store's name.
    pub fn name(&self) -> &str {
        self.map.name().as_str()
    }

    /// Give up the name: the creating handle then only unmaps on drop,
    /// leaving the name to another owner that has taken it (a hub whose ring
    /// another owner has marked does this). No effect on other handles.
    pub fn disown(&mut self) {
        self.owner = false;
    }

    fn cursor_atomic(&self) -> &AtomicU64 {
        // SAFETY: bytes 0..8 of the mapped region hold the AtomicU64 cursor;
        // the pointer is valid for the lifetime of self.
        unsafe { &*(self.map.ptr() as *const AtomicU64) }
    }

    fn magic_atomic(&self) -> &AtomicU32 {
        // SAFETY: bytes 8..12 of the header hold the magic word, 4-byte
        // aligned because the mapping is page aligned.
        unsafe { &*(self.map.ptr().add(H_MAGIC) as *const AtomicU32) }
    }

    fn busy_claims_atomic(&self) -> &AtomicU64 {
        // SAFETY: bytes 24..32 of the header hold the busy-claim counter,
        // 8-byte aligned because the mapping is page aligned; the pointer is
        // valid for the lifetime of self.
        unsafe { &*(self.map.ptr().add(H_BUSY_CLAIMS) as *const AtomicU64) }
    }

    fn write_header_u32(&self, offset: usize, value: u32) {
        // SAFETY: `offset` is one of the 4-byte-aligned header fields inside
        // the 64-byte header, which lies inside the mapping; only the
        // creator writes here, before it publishes the magic, and readers
        // read the fields only once they have seen the magic.
        unsafe { (self.map.ptr().add(offset) as *mut u32).write(value) }
    }

    fn slot_seq(&self, index: usize) -> &AtomicU64 {
        // SAFETY: the first 8 bytes of every slot are its seq word; slots
        // start at 64-byte multiples from the page-aligned mapping.
        unsafe { &*(self.slot_ptr(index) as *const AtomicU64) }
    }

    fn slot_ptr(&self, index: usize) -> *mut u8 {
        // SAFETY: HEADER_SIZE + index * slot_size() is within the mapped
        // region for any `index < capacity`.
        unsafe { self.map.ptr().add(HEADER_SIZE + index * slot_size()) }
    }

    /// Entry `way` of the index bucket `id` falls in: the id's first eight
    /// bytes, a content hash, masked to the bucket count.
    fn bucket_entry(&self, id: &PulseEnvelopeId, way: usize) -> &AtomicU64 {
        let [a, b, c, d, e, f, g, h, ..] = id.0;
        let bucket = (u64::from_le_bytes([a, b, c, d, e, f, g, h]) as usize) & (self.buckets - 1);
        let offset = HEADER_SIZE + self.capacity * slot_size() + bucket * BUCKET_BYTES + way * 8;
        // SAFETY: the index follows the slots, `buckets` buckets of
        // BUCKET_BYTES, inside the mapping, which lives as long as `self`;
        // `bucket < buckets` and `way < INDEX_WAYS`. The offset is 8-byte
        // aligned (the slots end on a multiple of 64 from a page-aligned
        // start), and every entry is only ever accessed atomically.
        unsafe { &*(self.map.ptr().add(offset) as *const AtomicU64) }
    }

    /// The index entry the envelope `id` stored at `cursor` goes to.
    fn index_entry(&self, id: &PulseEnvelopeId, cursor: u64) -> &AtomicU64 {
        self.bucket_entry(id, (cursor % INDEX_WAYS as u64) as usize)
    }
}

impl Drop for EnvelopeStore {
    fn drop(&mut self) {
        // Only while the name still names this store
        // (`shm::Mapping::unlink_if_token`; ADR-0011 has the race that
        // remains within a hub).
        if self.owner {
            self.map.unlink_if_token(H_UNLINK_TOKEN);
        }
    }
}

/// The header word of the unlink token.
const H_UNLINK_TOKEN: usize = 32;

fn slot_size() -> usize {
    ENTRY_HEADER + MAX_ENTRY_SIZE
}

/// Bytes a store of `capacity` slots and `buckets` index buckets spans,
/// header and index included, for a capacity of at least one slot that the
/// header's `u32` records and a size that fits a `usize` and `ftruncate`'s
/// `off_t`; [`EnvelopeStoreError::InvalidCapacity`] otherwise.
fn store_bytes(capacity: usize, buckets: usize) -> Result<usize, EnvelopeStoreError> {
    Some(capacity)
        .filter(|&c| c >= 1 && u32::try_from(c).is_ok())
        .and_then(|c| c.checked_mul(slot_size()))
        .and_then(|bytes| bytes.checked_add(HEADER_SIZE))
        .and_then(|bytes| bytes.checked_add(buckets.checked_mul(BUCKET_BYTES)?))
        .filter(|&bytes| libc::off_t::try_from(bytes).is_ok())
        .ok_or(EnvelopeStoreError::InvalidCapacity { capacity })
}

/// The index a store of `capacity` slots gets when its creator does not
/// choose one: the smallest power of two no smaller than a quarter of the
/// capacity, so every store of one capacity made by default has one layout
/// (ADR-0020).
#[must_use]
pub fn default_index_buckets(capacity: usize) -> usize {
    capacity.div_ceil(INDEX_WAYS).max(1).next_power_of_two()
}

/// Whether `buckets` suits a store of `capacity` slots: a power of two no
/// larger than the capacity rounded up to one.
fn index_fits(capacity: usize, buckets: usize) -> bool {
    buckets.is_power_of_two() && buckets <= capacity.max(1).next_power_of_two()
}

/// The header fields an open checks, as one read of the header found them.
#[derive(Clone, Copy)]
struct StoreHeader {
    magic: u32,
    version: u32,
    capacity: u32,
    max_entry: u32,
    index_buckets: u32,
}

impl StoreHeader {
    /// The header at the start of a store mapping. The magic is loaded
    /// relaxed, then an acquire fence, which orders the reads after it as an
    /// acquire load would; not an acquire load, because a relaxed load is
    /// the only atomic load std allows through the read-only mapping `read`
    /// uses off Linux. The other fields are plain words the creator writes
    /// once, before the magic, so they are read only after a magic that
    /// checks out, and are left zero otherwise.
    ///
    /// # Safety
    ///
    /// `base` must be the page-aligned start of a live mapping of at least
    /// [`HEADER_SIZE`] bytes that stays mapped during the call. The call
    /// only loads, its atomic load relaxed, so a read-only mapping serves.
    unsafe fn from_mapping(base: *const u8) -> Self {
        // SAFETY: bytes 8..12 of the header lie inside the mapping the
        // caller vouched for, 4-byte aligned from its page-aligned start,
        // and the magic there is only ever accessed atomically.
        let magic = unsafe { &*(base.add(H_MAGIC) as *const AtomicU32) }.load(Ordering::Relaxed);
        fence(Ordering::Acquire);
        let mut header = Self {
            magic,
            version: 0,
            capacity: 0,
            max_entry: 0,
            index_buckets: 0,
        };
        if magic == MAGIC {
            let field = |offset: usize| {
                // SAFETY: `offset` is one of the 4-byte-aligned words at
                // 12..24 or 40..44, inside the mapping the caller vouched for. The
                // creator wrote them before it published the magic with
                // release ordering and never writes them again, and the
                // load above saw the magic before the acquire fence, so
                // nothing writes them during this read.
                unsafe { (base.add(offset) as *const u32).read() }
            };
            header.version = field(H_VERSION);
            header.capacity = field(H_CAPACITY);
            header.max_entry = field(H_MAX_ENTRY);
            header.index_buckets = field(H_INDEX_BUCKETS);
        }
        header
    }

    /// One read of the header behind `fd`, at least a header long, with
    /// `pread(2)`, which allocates no page ([`shm::pread_exact`]).
    ///
    /// `pread` copies in no set order, so a copy that shows the magic may
    /// hold a field from before the creator wrote it. The header is read
    /// again after an acquire fence, which orders that read after the load
    /// that saw the magic, and so after the creator's writes of the fields.
    /// The check through the mapping, once an open has mapped the store,
    /// decides.
    #[cfg(target_os = "linux")]
    fn read(fd: libc::c_int) -> Result<Self, EnvelopeStoreError> {
        let header = Self::from_bytes(&pread_header(fd)?);
        if header.magic == 0 {
            return Ok(header);
        }
        fence(Ordering::Acquire);
        Ok(Self::from_bytes(&pread_header(fd)?))
    }

    /// The fields of a header's little-endian bytes.
    #[cfg(target_os = "linux")]
    fn from_bytes(bytes: &[u8; HEADER_SIZE]) -> Self {
        let word = |at: usize| {
            u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
        };
        Self {
            magic: word(H_MAGIC),
            version: word(H_VERSION),
            capacity: word(H_CAPACITY),
            max_entry: word(H_MAX_ENTRY),
            index_buckets: word(H_INDEX_BUCKETS),
        }
    }

    /// One read of the header behind `fd`, at least a header long, through
    /// a read-only mapping of it ([`shm::with_prefix_mapped`] says why that
    /// is safe off Linux).
    #[cfg(not(target_os = "linux"))]
    fn read(fd: libc::c_int) -> Result<Self, EnvelopeStoreError> {
        shm::with_prefix_mapped(fd, HEADER_SIZE, |ptr| {
            // SAFETY: `ptr` is the page-aligned start of a live mapping of
            // HEADER_SIZE bytes, which stays mapped until the closure
            // returns; the view only loads, its atomic load relaxed, which
            // a read-only mapping allows.
            unsafe { Self::from_mapping(ptr) }
        })
        .map_err(shm_error)
    }

    /// Check the magic, the layout version, the entry size, the capacity
    /// (`capacity`, or, when `None`, any but zero) and the index; returns
    /// the capacity and the index buckets the header records.
    fn check(&self, capacity: Option<usize>) -> Result<(usize, usize), EnvelopeStoreError> {
        mismatch("magic", self.magic, MAGIC)?;
        mismatch("version", self.version, LAYOUT_VERSION)?;
        match capacity {
            Some(need) => mismatch(
                "capacity",
                self.capacity,
                u32::try_from(need).unwrap_or(u32::MAX),
            )?,
            None if self.capacity == 0 => mismatch("capacity", self.capacity, 1)?,
            None => {}
        }
        mismatch("max_entry", self.max_entry, MAX_ENTRY_SIZE as u32)?;
        let (capacity, buckets) = (self.capacity as usize, self.index_buckets as usize);
        if !index_fits(capacity, buckets) {
            return Err(EnvelopeStoreError::LayoutMismatch {
                field: "index_buckets",
                have: u64::from(self.index_buckets),
                need: default_index_buckets(capacity) as u64,
            });
        }
        Ok((capacity, buckets))
    }
}

/// The first [`HEADER_SIZE`] bytes of the object behind `fd`.
#[cfg(target_os = "linux")]
fn pread_header(fd: libc::c_int) -> Result<[u8; HEADER_SIZE], EnvelopeStoreError> {
    let mut bytes = [0u8; HEADER_SIZE];
    shm::pread_exact(fd, 0, &mut bytes).map_err(shm_error)?;
    Ok(bytes)
}

/// `Ok` when a header field holds the value the caller needs, and the
/// `LayoutMismatch` naming it otherwise.
fn mismatch(field: &'static str, have: u32, need: u32) -> Result<(), EnvelopeStoreError> {
    if have == need {
        Ok(())
    } else {
        Err(EnvelopeStoreError::LayoutMismatch {
            field,
            have: u64::from(have),
            need: u64::from(need),
        })
    }
}

/// The in-progress mark `2·L+1` of `cursor`'s lap `L` in a store of `cap`
/// slots, or `None` when `2·L+2` overflows the seq word, a lap only a write
/// cursor corrupted in shared memory reaches. Every reader and writer
/// computes the mark here, so none overflows.
fn lap_mark(cursor: u64, cap: u64) -> Option<u64> {
    let published = (cursor / cap).checked_mul(2)?.checked_add(2)?;
    Some(published - 1)
}

/// Claim a slot for the writer whose mark is `in_progress` (`2·L+1` for lap
/// `L`), moving its seq by compare-and-swap from an even value no newer than
/// `2·L` to that mark. `false`, with nothing written, when another writer
/// holds the slot (its seq is odd), a newer lap has taken it, or another
/// claim moved the seq first.
fn claim_slot(seq: &AtomicU64, in_progress: u64) -> bool {
    let prev = seq.load(Ordering::Acquire);
    prev & 1 == 0
        && prev < in_progress
        && seq
            .compare_exchange(prev, in_progress, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
}

/// One step of a reader's bounded wait for a writer to publish.
fn reader_spin() {
    #[cfg(test)]
    hook::count_spin();
    std::hint::spin_loop();
}

/// What a SeqLock copy of one slot produced.
enum SlotCopy {
    /// The seq moved during the copy; the caller may retry.
    Changed,
    /// The seq held, but the recorded length is outside `1..=MAX_ENTRY_SIZE`.
    BadLength,
    /// The slot's id and body as they stood under the wanted seq.
    Body { id: [u8; 16], body: Vec<u8> },
}

/// The envelope a slot's copied body holds: `None` unless the bytes are
/// exactly one canonical envelope carrying `stored_id` that verifies.
/// Defence in depth behind the SeqLock, against a copy damaged outside the
/// protocol; the id does not cover the origin, time or flags. Public only
/// for `fuzz` (`fuzz_store_slot`).
#[doc(hidden)]
#[must_use]
pub fn decode_body(stored_id: &[u8; 16], body: &[u8]) -> Option<PulseEnvelope> {
    let (envelope, used) = PulseEnvelope::decode_canonical_at(body, 0).ok()?;
    (used == body.len() && envelope.id().0 == *stored_id && envelope.verify()).then_some(envelope)
}

/// Test instrumentation: an interleaving point inside `EnvelopeStore::store`
/// and a count of reader spins, both per thread.
#[cfg(test)]
mod hook {
    use super::EnvelopeStore;
    use std::cell::{Cell, RefCell};

    type Hook = Box<dyn FnOnce(&EnvelopeStore)>;

    thread_local! {
        static BEFORE_PUBLISH: RefCell<Option<Hook>> = const { RefCell::new(None) };
        static SPINS: Cell<u64> = const { Cell::new(0) };
        static SCANS: Cell<u64> = const { Cell::new(0) };
    }

    /// Called by every `fetch` that falls back to scanning the slots.
    pub(super) fn count_scan() {
        SCANS.with(|s| s.set(s.get() + 1));
    }

    /// Fallback scans on this thread since the last call.
    pub(super) fn take_scans() -> u64 {
        SCANS.with(|s| s.replace(0))
    }

    /// Called by every step of a reader's wait.
    pub(super) fn count_spin() {
        SPINS.with(|s| s.set(s.get() + 1));
    }

    /// Reader spins on this thread since the last call.
    pub(super) fn take_spins() -> u64 {
        SPINS.with(|s| s.replace(0))
    }

    /// Run `f` once, on this thread, after the next `store` has written
    /// its body and before it publishes.
    pub(super) fn set_before_publish(f: impl FnOnce(&EnvelopeStore) + 'static) {
        BEFORE_PUBLISH.with(|h| *h.borrow_mut() = Some(Box::new(f)));
    }

    /// Called by `store`. The hook is taken out before it runs, so a
    /// `store` inside it goes straight through.
    pub(super) fn before_publish(store: &EnvelopeStore) {
        if let Some(f) = BEFORE_PUBLISH.with(|h| h.borrow_mut().take()) {
            f(store);
        }
    }
}

/// Fuzzing instrumentation, built only under `--cfg fuzzing` and public
/// only for `fuzz` (`fuzz_store_region` describes it): a hook
/// run inside a reader's copy of a slot, before it re-reads the seq.
#[cfg(fuzzing)]
#[doc(hidden)]
pub mod fuzzing {
    use super::EnvelopeStore;
    use std::cell::RefCell;

    /// What runs at the interleaving point: given the store being read and
    /// the index of the slot being copied.
    pub type MidCopy = Box<dyn FnMut(&EnvelopeStore, usize)>;

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

    /// The interleaving point. The hook is taken out while it runs, so a
    /// read inside it goes straight through.
    pub(super) fn mid_copy(store: &EnvelopeStore, index: usize) {
        let Some(mut hook) = take_mid_copy() else {
            return;
        };
        hook(store, index);
        MID_COPY.with(|h| {
            h.borrow_mut().get_or_insert(hook);
        });
    }
}

#[cfg(test)]
mod layout_tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn unique(tag: &str) -> String {
        format!("st-{tag}-{:x}", std::process::id())
    }

    fn env(i: u64) -> PulseEnvelope {
        PulseEnvelope::new(1, i.to_le_bytes().to_vec())
    }

    fn payload_seq(e: &PulseEnvelope) -> u64 {
        let raw = e.payload().as_raw().expect("raw payload");
        u64::from_le_bytes(raw[..8].try_into().unwrap())
    }

    /// A write cursor corrupted in shared memory can name a lap of 2^63 or
    /// more, whose seq the word cannot hold: a store gives every such cursor
    /// up, and the readers pass them by.
    #[test]
    fn a_write_cursor_past_the_last_markable_lap_is_survived() {
        let store = EnvelopeStore::create_exclusive(&unique("top"), 1).unwrap();
        store.store(&env(1)).unwrap();
        let top = 1u64 << 63;
        store.cursor_atomic().store(top, Ordering::Release);
        match store.store(&env(2)) {
            Err(EnvelopeStoreError::SlotBusy { cursor }) => {
                assert_eq!(cursor, top + CLAIM_ATTEMPTS as u64 - 1);
            }
            other => panic!("expected SlotBusy, got {other:?}"),
        }
        assert_eq!(store.busy_claims(), CLAIM_ATTEMPTS as u64);
        assert_eq!(store.write_cursor(), top + CLAIM_ATTEMPTS as u64);
        // The slot still holds lap 0's envelope, which `fetch` finds by id;
        // no cursor that far on names it.
        assert_eq!(store.fetch(&env(1).id()).map(|e| e.id()), Some(env(1).id()));
        assert!(store.fetch_at(top, &env(1).id()).is_none());
        let (got, next) = store.read_since(0);
        assert!(got.is_empty());
        assert_eq!(next, top + CLAIM_ATTEMPTS as u64);
    }

    #[test]
    fn read_since_skips_a_slot_that_never_publishes() {
        let store = EnvelopeStore::create_exclusive(&unique("skip"), 4).unwrap();
        for i in 0..3 {
            store.store(&env(i)).unwrap();
        }
        let seq = store.slot_seq(1);
        let saved = seq.load(Ordering::Acquire);
        seq.store(saved - 1, Ordering::Release); // back to "in progress"
        let (got, next) = store.read_since(0);
        assert_eq!(next, 3);
        assert_eq!(got.iter().map(payload_seq).collect::<Vec<_>>(), vec![0, 2]);
        seq.store(saved, Ordering::Release);
        let (got, _) = store.read_since(0);
        assert_eq!(got.len(), 3);
    }

    #[test]
    fn read_since_ignores_a_claimed_but_unwritten_cursor() {
        let store = EnvelopeStore::create_exclusive(&unique("claim"), 2).unwrap();
        for i in 0..4 {
            store.store(&env(i)).unwrap();
        }
        // A claim with no write: cursor 4 lands on slot 0, which still
        // holds cursor 2's envelope under lap 1's published seq.
        store.cursor_atomic().fetch_add(1, Ordering::AcqRel);
        let (got, next) = store.read_since(3);
        assert_eq!(next, 5);
        assert_eq!(got.iter().map(payload_seq).collect::<Vec<_>>(), vec![3]);
    }

    #[test]
    fn fetch_continues_past_poisoned_and_bad_length_slots() {
        let store = EnvelopeStore::create_exclusive(&unique("fetch"), 4).unwrap();
        let e = env(7);
        store.store(&e).unwrap();
        store.store(&e).unwrap(); // the same id in slots 0 and 1
        let seq0 = store.slot_seq(0);
        let saved = seq0.load(Ordering::Acquire);
        seq0.store(saved | 1, Ordering::Release);
        assert!(store.fetch(&e.id()).is_some(), "slot 1 must still be found");
        seq0.store(saved, Ordering::Release);
        // SAFETY: writing a zero length into slot 0's fixed length field.
        unsafe {
            std::ptr::write_bytes(store.slot_ptr(0).add(SLOT_LEN), 0, 4);
        }
        assert!(
            store.fetch(&e.id()).is_some(),
            "a bad length must not end the scan"
        );
    }

    #[test]
    fn open_refuses_wrong_magic_and_version() {
        let name = unique("magic");
        let store = EnvelopeStore::create_exclusive(&name, 2).unwrap();
        // SAFETY: bytes 12..16 of the live store's header hold its version,
        // written when the store was created, before this read.
        let version = unsafe { (store.map.ptr().add(H_VERSION) as *const u32).read() };
        assert_eq!(version, LAYOUT_VERSION, "this build writes its own version");
        store.magic_atomic().store(0xDEAD_BEEF, Ordering::Release);
        match EnvelopeStore::open(&name, 2) {
            Err(EnvelopeStoreError::LayoutMismatch { field: "magic", .. }) => {}
            Err(other) => panic!("expected a magic mismatch, got {other:?}"),
            Ok(_) => panic!("wrong magic must be refused"),
        }
        store.magic_atomic().store(MAGIC, Ordering::Release);
        // A version-1 (JSON bodies) or version-2 (no index) region has this
        // layout's magic, so it is refused on its version, as is a newer
        // one; create_or_open reports the mismatch rather than retrying.
        for version in [1, 2, LAYOUT_VERSION + 1] {
            store.write_header_u32(H_VERSION, version);
            let attempts = [
                EnvelopeStore::open(&name, 2),
                EnvelopeStore::create_or_open(&name, 2),
            ];
            for attempt in attempts {
                match attempt {
                    Err(EnvelopeStoreError::LayoutMismatch {
                        field: "version",
                        have,
                        need,
                    }) => {
                        assert_eq!(have, u64::from(version));
                        assert_eq!(need, u64::from(LAYOUT_VERSION));
                    }
                    Err(other) => panic!("expected a version mismatch, got {other:?}"),
                    Ok(_) => panic!("layout version {version} must be refused"),
                }
            }
        }
        store.write_header_u32(H_VERSION, LAYOUT_VERSION);
        assert!(EnvelopeStore::open(&name, 2).is_ok());
    }

    /// A writer's in-progress mark for `lap`.
    fn in_progress(lap: u64) -> u64 {
        2 * lap + 1
    }

    /// The seq of a slot published on `lap`.
    fn published(lap: u64) -> u64 {
        2 * lap + 2
    }

    fn seqs(envs: &[PulseEnvelope]) -> Vec<u64> {
        envs.iter().map(payload_seq).collect()
    }

    #[test]
    fn store_never_claims_a_newer_laps_slot() {
        let store = EnvelopeStore::create_exclusive(&unique("newer"), 1).unwrap();
        store.store(&env(0)).unwrap();
        // Lap 9's writer holds the only slot, then has published into it:
        // either way it belongs to a newer lap than every cursor tried.
        let attempts = CLAIM_ATTEMPTS as u64;
        for (round, seq) in [in_progress(9), published(9)].into_iter().enumerate() {
            store.slot_seq(0).store(seq, Ordering::Release);
            match store.store(&env(1)) {
                Err(EnvelopeStoreError::SlotBusy { cursor }) => {
                    assert_eq!(cursor, attempts * (round as u64 + 1));
                }
                other => panic!("expected SlotBusy, got {other:?}"),
            }
            assert_eq!(store.slot_seq(0).load(Ordering::Acquire), seq);
            assert_eq!(store.busy_claims(), attempts * (round as u64 + 1));
        }
    }

    #[test]
    fn a_crashed_writers_slot_is_routed_around_and_read_past_at_once() {
        let store = EnvelopeStore::create_exclusive(&unique("route"), 4).unwrap();
        store.store(&env(0)).unwrap();
        // The writer of cursor 1 claims slot 1 and crashes before publishing.
        assert_eq!(store.cursor_atomic().fetch_add(1, Ordering::AcqRel), 1);
        store.slot_seq(1).store(in_progress(0), Ordering::Release);

        // On its own lap a crashed writer cannot be told from a slow one, so
        // a reader of its cursor spends the read budget waiting for it.
        hook::take_spins();
        let (got, next) = store.read_since(0);
        assert_eq!((seqs(&got), next), (vec![0], 2));
        assert_eq!(hook::take_spins(), READ_SPINS as u64);

        // Every later envelope is stored, and found by read_since and by
        // fetch as soon as it is.
        let mut since = next;
        let mut store_and_find = |k: u64| {
            let e = env(k);
            let cursor = store.store(&e).unwrap();
            let (got, next) = store.read_since(since);
            assert_eq!(seqs(&got), vec![k], "read_since after envelope {k}");
            assert_eq!(next, cursor + 1);
            assert_eq!(
                store.fetch(&e.id()).map(|g| g.id()),
                Some(e.id()),
                "fetch {k}"
            );
            since = next;
            cursor
        };
        // Until the ring comes round, cursor 1 is still the newest cursor
        // for slot 1. The index finds each envelope without a scan, so no
        // fetch waits there; a fetch that scans past slot 1 (for the
        // envelope in slot 2) still waits out its budget there.
        let first_lap: Vec<u64> = (2..5).map(&mut store_and_find).collect();
        assert_eq!(first_lap, vec![2, 3, 4]);
        assert_eq!(
            hook::take_spins(),
            0,
            "an indexed fetch waited on the held slot"
        );
        assert_eq!(
            store.fetch_by_scan(&env(2).id()).map(|g| g.id()),
            Some(env(2).id())
        );
        assert_eq!(hook::take_spins(), READ_SPINS as u64);
        assert_eq!(store.busy_claims(), 0);

        // From then on each cursor that lands on slot 1 is given up and
        // counted, and no reader waits on the slot.
        let later: Vec<u64> = (5..14).map(&mut store_and_find).collect();
        assert_eq!(later, vec![6, 7, 8, 10, 11, 12, 14, 15, 16]);
        assert_eq!(hook::take_spins(), 0, "a reader waited on the held slot");
        assert_eq!(store.busy_claims(), 3, "cursors 5, 9 and 13 were given up");
        assert_eq!(
            store.slot_seq(1).load(Ordering::Acquire),
            in_progress(0),
            "the held slot is never written"
        );
        assert_eq!(
            EnvelopeStore::open(store.name(), 4).unwrap().busy_claims(),
            3
        );
    }

    #[test]
    fn slot_busy_comes_back_only_when_every_attempt_lands_on_a_held_slot() {
        let attempts = CLAIM_ATTEMPTS as u64;
        // Both slots of a two-slot store are held by writers that crashed.
        let store = EnvelopeStore::create_exclusive(&unique("full"), 2).unwrap();
        assert_eq!(store.cursor_atomic().fetch_add(2, Ordering::AcqRel), 0);
        for slot in 0..2 {
            store
                .slot_seq(slot)
                .store(in_progress(0), Ordering::Release);
        }
        match store.store(&env(9)) {
            Err(EnvelopeStoreError::SlotBusy { cursor }) => assert_eq!(cursor, 2 + attempts - 1),
            other => panic!("expected SlotBusy, got {other:?}"),
        }
        assert_eq!(store.busy_claims(), attempts);
        assert_eq!(store.write_cursor(), 2 + attempts);
        for slot in 0..2 {
            assert_eq!(store.slot_seq(slot).load(Ordering::Acquire), in_progress(0));
        }

        // With a free slot at the last cursor the attempts reach, the store
        // lands there.
        let cap = CLAIM_ATTEMPTS;
        let store = EnvelopeStore::create_exclusive(&unique("last"), cap).unwrap();
        store
            .cursor_atomic()
            .fetch_add(attempts - 1, Ordering::AcqRel);
        for slot in 0..cap - 1 {
            store
                .slot_seq(slot)
                .store(in_progress(0), Ordering::Release);
        }
        assert_eq!(store.store(&env(0)).unwrap(), attempts - 1);
        let e = env(1);
        assert_eq!(store.store(&e).unwrap(), 2 * attempts - 1);
        assert_eq!(store.busy_claims(), attempts - 1);
        assert_eq!(store.fetch(&e.id()).map(|g| g.id()), Some(e.id()));
    }

    #[test]
    fn a_preempted_writer_finishes_while_later_writers_route_around_it() {
        let store = EnvelopeStore::create_exclusive(&unique("preempt"), 4).unwrap();
        let held = env(100);
        // The writer of cursor 0 is preempted between its marks, its body
        // written, while the ring comes round to its slot.
        hook::set_before_publish(|s| {
            let cursors: Vec<u64> = (1..5).map(|k| s.store(&env(k)).unwrap()).collect();
            assert_eq!(cursors, vec![1, 2, 3, 5], "cursor 4 found slot 0 held");
            assert_eq!(s.busy_claims(), 1);
            assert_eq!(
                s.slot_seq(0).load(Ordering::Acquire),
                in_progress(0),
                "the held slot was left alone"
            );
        });
        assert_eq!(
            store.store(&held).unwrap(),
            0,
            "the preempted writer finishes"
        );
        assert_eq!(store.slot_seq(0).load(Ordering::Acquire), published(0));

        // Each slot holds what its own claimant wrote: the preempted
        // writer's envelope whole in slot 0, and the three newest others.
        let found = store
            .fetch(&held.id())
            .expect("the preempted writer's envelope");
        assert_eq!(found.payload(), held.payload());
        for k in 2..5 {
            assert!(store.fetch(&env(k).id()).is_some(), "envelope {k}");
        }
        assert!(
            store.fetch(&env(1).id()).is_none(),
            "cursor 5 lapped cursor 1, as the ring does"
        );
        // Cursor 4 was given up, and slot 0's older holder has published
        // since: a reader cannot tell that from a writer yet to claim, so it
        // spends its budget there before skipping the cursor.
        hook::take_spins();
        let (got, next) = store.read_since(1);
        assert_eq!((seqs(&got), next), (vec![2, 3, 4], 6));
        assert_eq!(hook::take_spins(), READ_SPINS as u64);
    }

    #[test]
    fn a_corrupted_body_is_rejected_by_fetch_and_skipped_by_read_since() {
        use pulse_canon::CANONICAL_FIXED_HEADER;

        let store = EnvelopeStore::create_exclusive(&unique("torn"), 4).unwrap();
        let envs: Vec<_> = (0..3).map(env).collect();
        for e in &envs {
            store.store(e).unwrap();
        }
        let slot = store.slot_ptr(1);
        let mut original = vec![0u8; ENTRY_HEADER + envs[1].canonical_size() + 1];
        // SAFETY: the copy stays inside slot 1: its prefix, its body and one
        // byte past the body.
        unsafe {
            std::ptr::copy_nonoverlapping(slot, original.as_mut_ptr(), original.len());
        }
        // Offsets in slot 1 of the payload variant tag and the first payload
        // byte of an envelope with no type name.
        let variant_at = ENTRY_HEADER + CANONICAL_FIXED_HEADER + 1;
        let payload_at = variant_at + 1 + 4;
        // Each change leaves slot 1 published under its seq; only bytes of
        // the slot are wrong.
        let changes = [
            ("a payload byte", payload_at, original[payload_at] ^ 0x80),
            (
                "the id inside the body",
                ENTRY_HEADER,
                original[ENTRY_HEADER] ^ 0x01,
            ),
            ("the payload variant tag", variant_at, 7),
            ("the slot's recorded id", SLOT_ID, original[SLOT_ID] ^ 0x01),
            (
                "a length past the envelope",
                SLOT_LEN,
                original[SLOT_LEN] + 1,
            ),
        ];
        for (what, at, value) in changes {
            // SAFETY: `at` is inside slot 1's prefix or body.
            unsafe { slot.add(at).write(value) };
            assert!(store.fetch(&envs[1].id()).is_none(), "fetch took {what}");
            let (got, next) = store.read_since(0);
            assert_eq!(next, 3);
            let seqs: Vec<_> = got.iter().map(payload_seq).collect();
            assert_eq!(seqs, vec![0, 2], "read_since took {what}");
            // SAFETY: as above; the original byte goes back.
            unsafe { slot.add(at).write(original[at]) };
            assert_eq!(
                store.fetch(&envs[1].id()).map(|e| e.id()),
                Some(envs[1].id())
            );
        }

        // fetch scans past a rejected slot to a good copy of the envelope.
        assert_eq!(store.store(&envs[1]).unwrap(), 3);
        // SAFETY: as above.
        unsafe { slot.add(payload_at).write(original[payload_at] ^ 0x80) };
        assert_eq!(
            store.fetch(&envs[1].id()).map(|e| e.id()),
            Some(envs[1].id())
        );
        let (got, _) = store.read_since(0);
        let seqs: Vec<_> = got.iter().map(payload_seq).collect();
        assert_eq!(seqs, vec![0, 2, 1]);
    }
}

#[cfg(test)]
mod index_tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn unique(tag: &str) -> String {
        format!("sti-{tag}-{:x}", std::process::id())
    }

    fn env(i: u64) -> PulseEnvelope {
        PulseEnvelope::new(1, i.to_le_bytes().to_vec())
    }

    #[test]
    fn the_default_index_is_a_quarter_of_the_capacity_rounded_up_to_a_power_of_two() {
        for (capacity, buckets) in [(1, 1), (4, 1), (5, 2), (64, 16), (256, 64), (1000, 256)] {
            assert_eq!(
                default_index_buckets(capacity),
                buckets,
                "capacity {capacity}"
            );
        }
        let store = EnvelopeStore::create_exclusive(&unique("dflt"), 16).unwrap();
        assert_eq!(store.index_buckets(), 4);
    }

    /// The envelope stored last is always in the index, so fetching it never
    /// scans, whatever the store holds.
    #[test]
    fn a_fresh_envelope_is_found_without_a_scan() {
        let store = EnvelopeStore::create_exclusive(&unique("hit"), 32).unwrap();
        hook::take_scans();
        for i in 0..200 {
            store.store(&env(i)).unwrap();
            assert_eq!(store.fetch(&env(i).id()).map(|e| e.id()), Some(env(i).id()));
        }
        assert_eq!(hook::take_scans(), 0, "an indexed fetch scanned");
    }

    /// With one bucket, the fifth envelope stored evicts the first from the
    /// index: still in its slot, it is found by the scan.
    #[test]
    fn an_envelope_the_index_has_lost_is_found_by_the_scan() {
        let store = EnvelopeStore::create_exclusive_with_index(&unique("evict"), 16, 1).unwrap();
        for i in 0..6 {
            store.store(&env(i)).unwrap();
        }
        hook::take_scans();
        assert_eq!(store.fetch(&env(0).id()).map(|e| e.id()), Some(env(0).id()));
        assert_eq!(
            hook::take_scans(),
            1,
            "evicted from the index, found by the scan"
        );
        assert_eq!(store.fetch(&env(5).id()).map(|e| e.id()), Some(env(5).id()));
        assert_eq!(hook::take_scans(), 0, "the newest is indexed");
    }

    /// An entry naming a cursor whose slot a later lap overwrote is refused
    /// by `fetch_at`, and an envelope no slot holds any more is `None`.
    #[test]
    fn a_stale_entry_never_returns_the_wrong_envelope() {
        let store = EnvelopeStore::create_exclusive_with_index(&unique("stale"), 2, 2).unwrap();
        store.store(&env(1)).unwrap();
        for i in 10..14 {
            store.store(&env(i)).unwrap();
        }
        assert!(
            store.fetch(&env(1).id()).is_none(),
            "lapped out of the store"
        );
        for i in 12..14 {
            assert_eq!(store.fetch(&env(i).id()).map(|e| e.id()), Some(env(i).id()));
        }
    }

    #[test]
    fn the_creator_chooses_the_index_and_opens_read_it_from_the_header() {
        let name = unique("chosen");
        let store = EnvelopeStore::create_exclusive_with_index(&name, 64, 8).unwrap();
        assert_eq!(store.index_buckets(), 8);
        assert_eq!(EnvelopeStore::open(&name, 64).unwrap().index_buckets(), 8);
        let other = EnvelopeStore::open_existing(&name).unwrap();
        assert_eq!(other.index_buckets(), 8);
        // A copy stored through one handle is found through the other's index.
        store.store(&env(7)).unwrap();
        hook::take_scans();
        assert_eq!(other.fetch(&env(7).id()).map(|e| e.id()), Some(env(7).id()));
        assert_eq!(hook::take_scans(), 0);
    }

    #[test]
    fn an_index_that_is_not_a_power_of_two_or_too_large_is_refused() {
        for buckets in [0, 3, 128] {
            assert!(matches!(
                EnvelopeStore::create_exclusive_with_index(&unique("bad"), 64, buckets),
                Err(EnvelopeStoreError::InvalidIndex { buckets: b, capacity: 64 }) if b == buckets
            ));
        }
        assert!(matches!(
            EnvelopeStore::create_exclusive_with_index(&unique("cap0"), 0, 1),
            Err(EnvelopeStoreError::InvalidCapacity { capacity: 0 })
        ));
        let largest = EnvelopeStore::create_exclusive_with_index(&unique("big"), 64, 64).unwrap();
        assert_eq!(largest.index_buckets(), 64);
        let odd = EnvelopeStore::create_exclusive_with_index(&unique("odd"), 5, 8).unwrap();
        assert_eq!(
            odd.index_buckets(),
            8,
            "up to the capacity rounded up to a power of two"
        );
    }
}
