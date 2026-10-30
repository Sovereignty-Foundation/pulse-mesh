// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! The reader table (ADR-0019): a companion shared-memory object named
//! `<ring name>.readers`, with one cursor line per registered reader, which
//! the ring's blocking publishes keep pace with. The ring's header and slots
//! are unchanged; a ring made without a table behaves as before.
//!
//! ## Layout (version 1)
//!
//! ```text
//! header:  0..8   unlink token (AtomicU64): zero until the ring's creator
//!                 drops it, as in the envelope store
//!          8..12  magic "PMRT" (AtomicU32, stored last on create)
//!         12..16  version (u32 LE) = 1
//!         16..20  lines (u32 LE): the most readers registered at once
//!         20..24  claims made (AtomicU32): the next claim's generation
//!         24..32  the ring's capacity (u64 LE)
//!         32..64  reserved, zero
//! line:    0..8   claim (AtomicU64): zero while free, all ones while a
//!                 reader is taking it, otherwise the reader's process id
//!                 in the high 32 bits and its generation in the low 32
//!          8..16  cursor (AtomicU64): the position the reader reads next
//!         16..64  reserved, zero; each line is a cache line of its own
//! ```
//!
//! A reader takes a free line by compare-and-swap of its claim from zero to
//! all ones, writes its starting cursor, then publishes its claim with
//! release ordering, so a writer that sees the claim sees the cursor. It
//! reports progress by raising its cursor and frees the line when it drops.
//! A writer's blocking publish waits for the smallest cursor of the claimed
//! lines; with none claimed it does not wait. When it runs out of room it
//! first frees the lines of readers whose process no longer exists; one that
//! still stalls it is named in [`crate::RingError::Stalled`] and can be freed
//! with [`crate::PulseRing::evict_reader`].

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;

use core_region::shm::{self, Mapping, Name, Opened};

use crate::{shm_error, RingError};

/// The suffix of a ring's reader table's name.
pub const READERS_SUFFIX: &str = ".readers";

/// The longest name a reader table may have: the hub's limit for every
/// derived shared-memory name, which fits macOS's.
pub const READERS_NAME_MAX: usize = 30;

/// The most readers one table holds.
pub const MAX_READERS: u32 = 4096;

const MAGIC: u32 = u32::from_le_bytes(*b"PMRT");
const VERSION: u32 = 1;
const HEADER: usize = 64;
const LINE: usize = 64;

const H_TOKEN: usize = 0;
const H_MAGIC: usize = 8;
const H_VERSION: usize = 12;
const H_LINES: usize = 16;
const H_CLAIMS: usize = 20;
const H_CAPACITY: usize = 24;

const L_CLAIM: usize = 0;
const L_CURSOR: usize = 8;

/// A line's claim while a reader is taking it: no writer counts the line.
const TAKING: u64 = u64::MAX;

/// The name of `ring`'s reader table.
pub(crate) fn table_name(ring: &str) -> Result<Name, RingError> {
    let name = format!("{ring}{READERS_SUFFIX}");
    if name.len() > READERS_NAME_MAX {
        return Err(RingError::NameTooLong {
            len: name.len(),
            max: READERS_NAME_MAX,
        });
    }
    Name::new(&name).map_err(shm_error)
}

/// A mapped reader table.
pub(crate) struct ReaderTable {
    map: Mapping,
    lines: usize,
    /// Whether the ring's creator made it, and so unlinks it.
    owner: bool,
}

// SAFETY: the table owns its mapping, valid until it drops and tied to no
// thread; every word in it is accessed only as an atomic.
unsafe impl Send for ReaderTable {}
// SAFETY: as for `Send` above.
unsafe impl Sync for ReaderTable {}

impl ReaderTable {
    /// Make `ring`'s table, of `lines` lines, for a ring of `capacity`
    /// slots. The ring's name was free when its creator took it, so a table
    /// already under the derived name is a dead ring's: it is unlinked and
    /// replaced.
    pub(crate) fn create(ring: &str, capacity: u64, lines: u32) -> Result<Self, RingError> {
        if lines == 0 || lines > MAX_READERS {
            return Err(RingError::InvalidReaders { max_readers: lines });
        }
        let name = table_name(ring)?;
        let len = HEADER + lines as usize * LINE;
        let map = match Mapping::create_exclusive(name.clone(), len) {
            Err(shm::Error::Open(libc::EEXIST)) => {
                shm::unlink(&name).map_err(RingError::Unlink)?;
                Mapping::create_exclusive(name, len)
            }
            made => made,
        }
        .map_err(shm_error)?;
        let table = Self {
            map,
            lines: lines as usize,
            owner: true,
        };
        table.u32_at(H_VERSION).store(VERSION, Ordering::Relaxed);
        table.u32_at(H_LINES).store(lines, Ordering::Relaxed);
        table.u64_at(H_CAPACITY).store(capacity, Ordering::Relaxed);
        // The magic last, with release ordering: an opener that sees it sees
        // the fields above.
        table.u32_at(H_MAGIC).store(MAGIC, Ordering::Release);
        Ok(table)
    }

    /// Map `ring`'s table, for a ring of `capacity` slots: `None` when the
    /// ring has none, or a name too long to hold one.
    pub(crate) fn open(ring: &str, capacity: u64) -> Result<Option<Self>, RingError> {
        let Ok(name) = table_name(ring) else {
            return Ok(None);
        };
        let opened = match Opened::open(name) {
            Err(shm::Error::Open(libc::ENOENT)) => return Ok(None),
            opened => opened.map_err(shm_error)?,
        };
        let have = opened.len();
        if have < HEADER as u64 {
            return Err(RingError::RegionTooSmall {
                have,
                need: HEADER as u64,
            });
        }
        // A published magic means the creator reserved the pages, and the
        // object is never longer than its lines, so the whole maps safely.
        let len = usize::try_from(have).map_err(|_| RingError::RegionTooSmall {
            have,
            need: u64::MAX,
        })?;
        let mut map = opened.map(len).map_err(shm_error)?;
        map.close_fd();
        let table = Self {
            map,
            lines: 0,
            owner: false,
        };
        let magic = table.u32_at(H_MAGIC).load(Ordering::Acquire);
        crate::mismatch("readers magic", u64::from(magic), u64::from(MAGIC))?;
        let version = table.u32_at(H_VERSION).load(Ordering::Relaxed);
        crate::mismatch("readers version", u64::from(version), u64::from(VERSION))?;
        let recorded = table.u64_at(H_CAPACITY).load(Ordering::Relaxed);
        crate::mismatch("readers capacity", recorded, capacity)?;
        let lines = table.u32_at(H_LINES).load(Ordering::Relaxed);
        let need = (HEADER + lines as usize * LINE) as u64;
        if lines == 0 || lines > MAX_READERS || have < need {
            return Err(RingError::RegionTooSmall { have, need });
        }
        Ok(Some(Self {
            lines: lines as usize,
            ..table
        }))
    }

    /// Lines in the table: the most readers registered at once.
    pub(crate) fn lines(&self) -> usize {
        self.lines
    }

    /// Take a free line for a reader starting at `start`: the line and the
    /// claim it holds, or `None` when every line is taken.
    pub(crate) fn claim(&self, start: u64) -> Option<(usize, u64)> {
        let generation = self.u32_at(H_CLAIMS).fetch_add(1, Ordering::Relaxed);
        let claim = u64::from(std::process::id()) << 32 | u64::from(generation);
        for line in 0..self.lines {
            let word = self.claim_word(line);
            if word.load(Ordering::Relaxed) != 0
                || word
                    .compare_exchange(0, TAKING, Ordering::Acquire, Ordering::Relaxed)
                    .is_err()
            {
                continue;
            }
            self.cursor_word(line).store(start, Ordering::Relaxed);
            // Release: a writer whose acquire load sees the claim sees the
            // cursor.
            word.store(claim, Ordering::Release);
            return Some((line, claim));
        }
        None
    }

    /// The smallest cursor of the claimed lines and its line, or `None`
    /// when no reader is registered.
    pub(crate) fn slowest(&self) -> Option<(u64, usize)> {
        (0..self.lines)
            .filter_map(|line| {
                let claim = self.claim_word(line).load(Ordering::Acquire);
                (claim != 0 && claim != TAKING)
                    .then(|| (self.cursor_word(line).load(Ordering::Acquire), line))
            })
            .min()
    }

    /// Readers registered now.
    pub(crate) fn registered(&self) -> usize {
        (0..self.lines)
            .filter(|&line| {
                let claim = self.claim_word(line).load(Ordering::Acquire);
                claim != 0 && claim != TAKING
            })
            .count()
    }

    /// Free every line whose claimant's process no longer exists; returns
    /// how many. A recycled process id looks alive, which is why
    /// [`Self::evict`] exists.
    pub(crate) fn evict_dead(&self) -> usize {
        (0..self.lines)
            .filter(|&line| {
                let word = self.claim_word(line);
                let claim = word.load(Ordering::Acquire);
                claim != 0
                    && claim != TAKING
                    && process_gone((claim >> 32) as u32)
                    && word
                        .compare_exchange(claim, 0, Ordering::AcqRel, Ordering::Relaxed)
                        .is_ok()
            })
            .count()
    }

    /// Free `line`, whoever holds it; false when it was free.
    pub(crate) fn evict(&self, line: usize) -> bool {
        if line >= self.lines {
            return false;
        }
        let word = self.claim_word(line);
        let claim = word.load(Ordering::Acquire);
        claim != 0
            && claim != TAKING
            && word
                .compare_exchange(claim, 0, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
    }

    /// Unlink the table's name while it still names this table.
    pub(crate) fn unlink(&self) {
        if self.owner {
            self.map.unlink_if_token(H_TOKEN);
        }
    }

    fn claim_word(&self, line: usize) -> &AtomicU64 {
        self.u64_at(HEADER + line * LINE + L_CLAIM)
    }

    fn cursor_word(&self, line: usize) -> &AtomicU64 {
        self.u64_at(HEADER + line * LINE + L_CURSOR)
    }

    fn u64_at(&self, offset: usize) -> &AtomicU64 {
        debug_assert!(offset + 8 <= self.map.len() && offset.is_multiple_of(8));
        // SAFETY: every caller passes an 8-byte-aligned offset of the header
        // or of a line below `lines`, inside the page-aligned mapping, which
        // lives as long as `self`; every word is only ever accessed
        // atomically.
        unsafe { &*(self.map.ptr().add(offset) as *const AtomicU64) }
    }

    fn u32_at(&self, offset: usize) -> &AtomicU32 {
        debug_assert!(offset + 4 <= HEADER && offset.is_multiple_of(4));
        // SAFETY: as `u64_at`, for a 4-byte-aligned word of the header.
        unsafe { &*(self.map.ptr().add(offset) as *const AtomicU32) }
    }
}

/// Whether no process has the id `pid`: `kill(pid, 0)` fails with `ESRCH`.
fn process_gone(pid: u32) -> bool {
    let Ok(pid) = libc::pid_t::try_from(pid) else {
        return false;
    };
    // SAFETY: signal 0 sends nothing; kill only checks that the process
    // exists and may be signalled, and touches no memory of this process.
    unsafe { libc::kill(pid, 0) == -1 && shm::errno() == libc::ESRCH }
}

/// A reader's line in a ring's reader table
/// ([`crate::PulseRing::register_reader`]). The reader reads with the
/// ring's `read_position` calls and reports each position it has read past
/// with [`Self::advance`]; a blocking publish never overwrites a position
/// this reader has not passed. Dropping it frees the line.
pub struct ReaderSlot {
    table: Arc<ReaderTable>,
    line: usize,
    claim: u64,
}

impl std::fmt::Debug for ReaderSlot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReaderSlot")
            .field("line", &self.line)
            .field("position", &self.position())
            .finish_non_exhaustive()
    }
}

impl ReaderSlot {
    pub(crate) fn new(table: Arc<ReaderTable>, line: usize, claim: u64) -> Self {
        Self { table, line, claim }
    }

    /// The reader's line in the table, which [`crate::RingError::Stalled`]
    /// names and [`crate::PulseRing::evict_reader`] takes.
    pub fn line(&self) -> usize {
        self.line
    }

    /// The position the reader reads next, as it last reported.
    pub fn position(&self) -> u64 {
        self.table.cursor_word(self.line).load(Ordering::Acquire)
    }

    /// Report that the reader has read every position below `position`;
    /// the cursor only moves forward. False, and nothing changed, when the
    /// line is no longer this reader's: it was evicted.
    pub fn advance(&self, position: u64) -> bool {
        if !self.is_registered() {
            return false;
        }
        // Release: the reader's reads of the slots it frees happen before a
        // writer that sees the new cursor refills them.
        self.table
            .cursor_word(self.line)
            .fetch_max(position, Ordering::Release);
        true
    }

    /// Whether the line is still this reader's.
    pub fn is_registered(&self) -> bool {
        self.table.claim_word(self.line).load(Ordering::Acquire) == self.claim
    }
}

impl Drop for ReaderSlot {
    fn drop(&mut self) {
        // Only while the line is still this reader's.
        let _ = self.table.claim_word(self.line).compare_exchange(
            self.claim,
            0,
            Ordering::AcqRel,
            Ordering::Relaxed,
        );
    }
}
