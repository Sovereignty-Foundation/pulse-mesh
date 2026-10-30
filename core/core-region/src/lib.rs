// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! `PulseRegion`: a single-slot shared-memory region, tier 1, and the
//! shared-memory mechanism every mapped object in the workspace uses.
//!
//! [`PulseRegion`] holds one Pulse in one POSIX shared-memory object, under
//! the same SeqLock protocol as the ring's slots. [`shm`] owns the POSIX
//! calls that the region, the ring (`core-ring`), the envelope store
//! (`core-store`) and the NUMA backings ([`numa`]) share; each keeps its
//! own header, geometry and error type (ADR-0013). [`numa`] places a ring's
//! memory on hugepages and NUMA nodes, and pins threads beside it; the HFT
//! ring re-exports it.
//!
//! Layout in shared memory, [`REGION_SIZE`] bytes:
//!
//! | bytes      | contents                                                   |
//! |------------|------------------------------------------------------------|
//! | `0..128`   | the Pulse; its first 8 bytes are the `AtomicU64` SeqLock counter |
//! | `128..132` | `AtomicU32` magic `PMRG`, stored last when the region is created |
//! | `132..136` | `AtomicU32` layout version, [`LAYOUT_VERSION`]             |
//! | `136..144` | `AtomicU64` unlink token: zero until the creator drops its handle |
//! | `144..192` | reserved, zero                                             |
//!
//! The creator reserves the page (on Linux) before it publishes the magic,
//! and `open` checks the size and the header before it maps anything, as
//! the ring's does, so no open touches a page that does not exist. The
//! creator's drop unlinks the name only while it still names its region
//! ([`shm::Mapping::unlink_if_token`]).
//!
//! In the book: <https://pulse-mesh.net/docs/reference/spec/04-ring.html>.

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use pulse_canon::Pulse;

pub mod numa;
pub mod shm;

use shm::{Mapping, Name, Opened};

const PULSE_SIZE: usize = pulse_canon::PULSE_WIRE_SIZE;

/// Bytes a region spans: the Pulse, then a header of one cache line.
pub const REGION_SIZE: usize = PULSE_SIZE + 64;

/// Layout version the region header records and every open checks.
pub const LAYOUT_VERSION: u32 = 1;

const MAGIC: u32 = u32::from_le_bytes(*b"PMRG");
// Header field offsets; the layout table in the module docs.
const H_MAGIC: usize = PULSE_SIZE;
const H_VERSION: usize = PULSE_SIZE + 4;
const H_UNLINK_TOKEN: usize = PULSE_SIZE + 8;

pub use shm::RESERVE_ATTEMPTS;

#[non_exhaustive]
/// Errors returned by `PulseRegion` operations.
#[derive(Debug)]
pub enum ShmError {
    /// `shm_open(3)`, `fstat(2)` or a header read failed; the field is the
    /// `errno`.
    Open(i32),
    /// `ftruncate` failed; the field is the `errno`.
    Truncate(i32),
    /// Linux could not reserve a new region's page: `posix_fallocate(3)`
    /// failed, with `ENOSPC` on a full `/dev/shm`, `ENOMEM`, or `EINTR`
    /// after [`RESERVE_ATTEMPTS`] tries. The object was unlinked and
    /// nothing was mapped. Never returned off Linux.
    NoSpace {
        /// Bytes the region needed.
        need: u64,
        /// The error number `posix_fallocate` returned.
        errno: i32,
    },
    /// `mmap` failed; the field is the `errno`.
    Map(i32),
    /// The name contains a NUL byte.
    InvalidName,
    /// The object is smaller than a region, [`REGION_SIZE`] bytes.
    RegionTooSmall {
        /// Bytes the object actually has.
        have: u64,
        /// Bytes one region needs.
        need: u64,
    },
    /// The header is not a region's: the magic is not `PMRG` (not a region,
    /// or not yet published), or the layout version is not
    /// [`LAYOUT_VERSION`]. Nothing was mapped.
    LayoutMismatch {
        /// `magic` or `version`.
        field: &'static str,
        /// Value found in the header.
        have: u64,
        /// Value a region has.
        need: u64,
    },
}

impl std::fmt::Display for ShmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Open(e) => write!(f, "shm_open failed: errno {}", e),
            Self::Truncate(e) => write!(f, "ftruncate failed: errno {}", e),
            Self::NoSpace { need, errno } => write!(
                f,
                "could not reserve {need} bytes of shared memory: posix_fallocate failed with errno {errno}"
            ),
            Self::Map(e) => write!(f, "mmap failed: errno {}", e),
            Self::InvalidName => write!(f, "shm name contains NUL byte"),
            Self::RegionTooSmall { have, need } => {
                write!(f, "shm region too small: have {have} bytes, need {need}")
            }
            Self::LayoutMismatch {
                field: "magic",
                have,
                need,
            } => write!(
                f,
                "shared-memory object is not a region: magic {have:#010x}, expected {need:#010x}"
            ),
            Self::LayoutMismatch { field, have, need } => write!(
                f,
                "region header {field} mismatch: the object has {have}, this build needs {need}"
            ),
        }
    }
}

impl std::error::Error for ShmError {}

fn shm_error(e: shm::Error) -> ShmError {
    match e {
        shm::Error::Open(e) => ShmError::Open(e),
        shm::Error::Truncate(e) => ShmError::Truncate(e),
        shm::Error::NoSpace { need, errno } => ShmError::NoSpace { need, errno },
        shm::Error::Map(e) => ShmError::Map(e),
        shm::Error::InvalidName => ShmError::InvalidName,
        shm::Error::TooSmall { have, need } => ShmError::RegionTooSmall { have, need },
    }
}

/// Spins before `read` gives up on a counter that stays odd or keeps
/// changing, as the ring's readers do.
const READ_SPINS: usize = 100;

/// The header of the region behind `fd`, at least a region long, read
/// without mapping it and re-read while the magic is zero, as a creator
/// that has not yet published it leaves it ([`shm::wait_out_creator`]).
fn published_header(fd: libc::c_int) -> Result<RegionHeader, ShmError> {
    shm::wait_out_creator(
        || RegionHeader::read(fd),
        |header| matches!(header, Ok(header) if header.magic == 0),
    )
}

/// The header fields an open checks, as one read of the header found them,
/// in native byte order.
#[derive(Clone, Copy)]
struct RegionHeader {
    magic: u32,
    version: u32,
}

impl RegionHeader {
    /// The header of the mapping that starts at `base`. The magic is loaded
    /// relaxed, then an acquire fence: the load after it sees the version a
    /// creator wrote before it published the magic seen. Not an acquire
    /// load, because a relaxed load is the only atomic load std allows
    /// through the read-only mapping `read` uses off Linux.
    ///
    /// # Safety
    ///
    /// `base` must be the page-aligned start of a live mapping of at least
    /// [`REGION_SIZE`] bytes that stays mapped during the call. The call
    /// only loads, with relaxed ordering, so a read-only mapping serves.
    unsafe fn from_mapping(base: *const u8) -> Self {
        // SAFETY: the caller vouches for a live mapping of REGION_SIZE
        // bytes; offsets 128 and 132 lie inside it and, from a page-aligned
        // base, are aligned for the u32 atomics placed there, which nothing
        // accesses other than through atomics.
        let (magic, version) = unsafe {
            (
                &*(base.add(H_MAGIC) as *const AtomicU32),
                &*(base.add(H_VERSION) as *const AtomicU32),
            )
        };
        let magic = u32::from_le(magic.load(Ordering::Relaxed));
        std::sync::atomic::fence(Ordering::Acquire);
        Self {
            magic,
            version: u32::from_le(version.load(Ordering::Relaxed)),
        }
    }

    /// One read of the header behind `fd` with `pread(2)`, which allocates
    /// no page ([`shm::pread_exact`]). A copy that shows the magic is taken
    /// again after an acquire fence, which orders the second read after the
    /// load that saw the magic, and so after the creator's write of the
    /// version. The check through the mapping, once an open has mapped the
    /// region, decides.
    #[cfg(target_os = "linux")]
    fn read(fd: libc::c_int) -> Result<Self, ShmError> {
        let header = Self::from_bytes(pread_header(fd)?);
        if header.magic == 0 {
            return Ok(header);
        }
        std::sync::atomic::fence(Ordering::Acquire);
        Ok(Self::from_bytes(pread_header(fd)?))
    }

    /// The fields of a header's little-endian bytes: the magic, then the
    /// version.
    #[cfg(target_os = "linux")]
    fn from_bytes(bytes: [u8; 8]) -> Self {
        Self {
            magic: u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
            version: u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
        }
    }

    /// One read of the header behind `fd`, through a read-only mapping of
    /// the region ([`shm::with_prefix_mapped`] says why that is safe off
    /// Linux).
    #[cfg(not(target_os = "linux"))]
    fn read(fd: libc::c_int) -> Result<Self, ShmError> {
        shm::with_prefix_mapped(fd, REGION_SIZE, |ptr| {
            // SAFETY: `ptr` is the page-aligned start of a live mapping of
            // REGION_SIZE bytes, which stays mapped until the closure
            // returns; the view only loads, with relaxed ordering, which a
            // read-only mapping allows.
            unsafe { Self::from_mapping(ptr) }
        })
        .map_err(shm_error)
    }

    /// Check the magic and the layout version.
    fn check(&self) -> Result<(), ShmError> {
        for (field, have, need) in [
            ("magic", self.magic, MAGIC),
            ("version", self.version, LAYOUT_VERSION),
        ] {
            if have != need {
                return Err(ShmError::LayoutMismatch {
                    field,
                    have: have.into(),
                    need: need.into(),
                });
            }
        }
        Ok(())
    }
}

/// The eight header bytes at 128..136 of the object behind `fd`; an object
/// truncated since its size was checked is [`ShmError::RegionTooSmall`].
#[cfg(target_os = "linux")]
fn pread_header(fd: libc::c_int) -> Result<[u8; 8], ShmError> {
    let mut bytes = [0u8; 8];
    shm::pread_exact(fd, H_MAGIC, &mut bytes).map_err(|e| match e {
        shm::Error::TooSmall { have, .. } => ShmError::RegionTooSmall {
            have,
            need: REGION_SIZE as u64,
        },
        other => shm_error(other),
    })?;
    Ok(bytes)
}

/// One `Pulse` in shared memory. The handle that created the region
/// unlinks its name on drop, while the name still names the region
/// (`tests/owner_drop.rs`); a handle that attached never unlinks. `Send`,
/// not `Sync`: the SeqLock has one writer at a time.
pub struct PulseRegion {
    map: Mapping,
    owner: bool,
}

impl PulseRegion {
    /// [`PulseRegion::create_or_open`]: create a region under `name`, or
    /// attach to the region already there.
    ///
    /// # Errors
    ///
    /// Those of [`PulseRegion::create_or_open`].
    pub fn create(name: &str) -> Result<Self, ShmError> {
        Self::create_or_open(name)
    }

    /// Create a region under a name that must be free; the handle is its
    /// creator. On Linux the page is reserved before it is mapped, so a full
    /// `/dev/shm` is [`ShmError::NoSpace`] here rather than SIGBUS at the
    /// first touch (`tests/no_space.rs`). A failure after the object exists
    /// unlinks it.
    ///
    /// # Errors
    ///
    /// - [`ShmError::InvalidName`] if `name` contains a NUL byte.
    /// - [`ShmError::Open`] if `shm_open(2)` fails: `EEXIST` when the name
    ///   already holds an object, `EACCES` where shared memory is refused,
    ///   `ENOMEM`.
    /// - [`ShmError::Truncate`] if `ftruncate(2)` cannot size the object.
    /// - [`ShmError::NoSpace`] on Linux if its page cannot be reserved.
    /// - [`ShmError::Map`] if `mmap(2)` fails.
    pub fn create_exclusive(name: &str) -> Result<Self, ShmError> {
        Self::create_inner(name)
    }

    /// Create a region under `name`, or attach to the region already there.
    /// Safe for concurrent callers: one creates the region, as
    /// [`PulseRegion::create_exclusive`] does, and the others attach as
    /// [`PulseRegion::open`] does, after waiting out a creator that has not
    /// yet sized the object or published its header. An existing object is
    /// never resized or cleared (`tests/create.rs`).
    ///
    /// # Errors
    ///
    /// - Those of [`PulseRegion::create_exclusive`] but `EEXIST`, when the
    ///   name is free.
    /// - Those of [`PulseRegion::open`], when it holds an object:
    ///   [`ShmError::RegionTooSmall`] for one too small (including one
    ///   still at size zero after the wait), [`ShmError::LayoutMismatch`]
    ///   for one that is not a region.
    pub fn create_or_open(name: &str) -> Result<Self, ShmError> {
        match Self::create_exclusive(name) {
            Err(ShmError::Open(libc::EEXIST)) => Self::open_after_creator(name),
            created => created,
        }
    }

    /// [`PulseRegion::open`], retried while the object is at size zero: its
    /// creator may be between `shm_open` and sizing it.
    fn open_after_creator(name: &str) -> Result<Self, ShmError> {
        shm::wait_out_creator(
            || Self::open(name),
            |opened| matches!(opened, Err(ShmError::RegionTooSmall { have: 0, .. })),
        )
    }

    /// Create and format the region under `name`, which must be free. Not
    /// zero-filled: the kernel's zero page is already a region never
    /// written.
    fn create_inner(name: &str) -> Result<Self, ShmError> {
        let name = Name::new(name).map_err(shm_error)?;
        let map = Mapping::create_exclusive(name, REGION_SIZE).map_err(shm_error)?;
        let region = PulseRegion { map, owner: true };
        // The version first, then the magic with release ordering: an open
        // that sees the magic sees the version, and the page it maps.
        region
            .header_word(H_VERSION)
            .store(LAYOUT_VERSION.to_le(), Ordering::Relaxed);
        region
            .header_word(H_MAGIC)
            .store(MAGIC.to_le(), Ordering::Release);
        Ok(region)
    }

    /// Attach to an existing region; the handle never unlinks it.
    ///
    /// The size and then the header are checked before anything is mapped,
    /// so an open never touches a page its creator has not reserved, which
    /// a full `/dev/shm` answers with SIGBUS (`tests/full_dev_shm.rs`). A
    /// zero magic may be a creator still formatting, so it is re-read for
    /// about 50 ms before it is refused.
    ///
    /// # Errors
    ///
    /// - [`ShmError::InvalidName`] if `name` contains a NUL byte.
    /// - [`ShmError::Open`] if `shm_open(2)` (`ENOENT` for no region,
    ///   `EACCES`), `fstat(2)` or the header's `pread(2)` fails.
    /// - [`ShmError::RegionTooSmall`] if the object is smaller than a
    ///   region.
    /// - [`ShmError::LayoutMismatch`] if the header is not a region's: no
    ///   magic after the wait, another magic, or another layout version.
    /// - [`ShmError::Map`] if `mmap(2)` fails.
    pub fn open(name: &str) -> Result<Self, ShmError> {
        let name = Name::new(name).map_err(shm_error)?;
        let opened = Opened::open(name).map_err(shm_error)?;
        opened.at_least(REGION_SIZE).map_err(shm_error)?;
        published_header(opened.fd()).and_then(|header| header.check())?;
        // A published magic means the page was reserved (Linux), so
        // touching it cannot fault for want of room.
        let map = opened.map(REGION_SIZE).map_err(shm_error)?;
        let region = PulseRegion { map, owner: false };
        // Checked again through the mapping: its load of the magic, fenced
        // with acquire, orders this handle's reads after the creator's
        // writes.
        // SAFETY: the mapping is the page-aligned start of REGION_SIZE
        // bytes, which lives as long as `region`.
        unsafe { RegionHeader::from_mapping(region.map.ptr()) }.check()?;
        Ok(region)
    }

    /// The header word at `offset` (the magic or the version) of this
    /// region's mapping.
    fn header_word(&self, offset: usize) -> &AtomicU32 {
        // SAFETY: `offset` is 128 or 132, inside the REGION_SIZE-byte
        // mapping, which lives as long as `self`, and 4-byte aligned from
        // its page-aligned start; the header words are only ever accessed
        // as atomics.
        unsafe { &*(self.map.ptr().add(offset) as *const AtomicU32) }
    }

    /// Write `pulse` under the SeqLock. A counter left odd by a writer that
    /// died mid-write is re-based, so the region heals on its next write
    /// (`tests/poisoned_read_is_bounded.rs`).
    pub fn write(&mut self, pulse: &Pulse) {
        let seq = self.seq_atomic();

        let prev = seq.load(Ordering::Relaxed) & !1;
        seq.store(prev | 1, Ordering::Release);
        // Release fence: the odd mark is visible before any payload byte.
        std::sync::atomic::fence(Ordering::Release);

        // SAFETY: bytes 8..PULSE_SIZE of the mapping, after the counter,
        // are 8-byte aligned (the mapping is page aligned) and only ever
        // accessed as atomic words; 120 is a multiple of eight.
        unsafe { shm::store_words(self.map.ptr().add(8), &pulse.as_bytes()[8..]) };

        // Release: a reader whose acquire load sees the even mark sees the
        // payload.
        seq.store(prev.wrapping_add(2), Ordering::Release);
    }

    /// Read the pulse under the SeqLock: `None` if the region was never
    /// written, or gives no stable copy within the retry budget (a writer
    /// mid-write, or one that died there).
    pub fn read(&self) -> Option<Pulse> {
        let seq = self.seq_atomic();

        for _ in 0..READ_SPINS {
            let v1 = seq.load(Ordering::Acquire);

            if v1 & 1 != 0 {
                std::hint::spin_loop();
                continue;
            }

            let mut buf = [0u8; PULSE_SIZE];
            // SAFETY: the mapping spans PULSE_SIZE bytes and more from a
            // page-aligned start, only ever accessed as atomic words.
            unsafe { shm::load_words(self.map.ptr(), &mut buf) };

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

    /// The SeqLock counter, for pollers and for tests that poison it.
    pub fn seq_atomic(&self) -> &AtomicU64 {
        // SAFETY: the mapping starts page aligned and spans the Pulse, whose
        // first 8 bytes are the counter, an AtomicU64; the borrow of `self`
        // keeps the mapping alive for as long as the reference lives.
        unsafe { &*(self.map.ptr() as *const AtomicU64) }
    }

    /// The SeqLock counter's value, for change detection.
    pub fn seq_version(&self) -> u64 {
        self.seq_atomic().load(Ordering::Acquire)
    }

    /// The region's name.
    pub fn name(&self) -> &str {
        self.map.name().as_str()
    }
}

impl Drop for PulseRegion {
    fn drop(&mut self) {
        // Only while the name still names this region
        // (`shm::Mapping::unlink_if_token`).
        if self.owner {
            self.map.unlink_if_token(H_UNLINK_TOKEN);
        }
    }
}
