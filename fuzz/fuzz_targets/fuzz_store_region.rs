// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//
// Fuzz target: an `EnvelopeStore` over a real shared-memory region whose
// header and slots hold bytes the input chooses: `open_existing` and
// `open`, then `fetch_at`, `fetch`, `read_since` and `store` over the
// slots. Every reader copies a slot with `copy_slot` and judges the copy
// with `decode_body`, so this reaches both over arbitrary slot bytes.
//
// Each input makes the object afresh under a name unique to the process,
// sized for one to three slots (now and then for a header alone, for one
// slot fewer than it records, or not sized at all), writes a header that
// is mostly well formed with fields the input may bend (magic, version,
// capacity, entry size, index buckets, a write cursor anywhere in the u64
// range, the busy-claim count), fills the slots with sequence words, ids,
// lengths and bodies, mostly canonical envelopes built from the input and
// sealed with their ids, fills the index with entries mostly naming
// cursors near the write cursor, and unlinks the object once the input is
// done.
//
// Half the reads are raced. A build for fuzzing has an interleaving point,
// `core_store::fuzzing`, inside every reader's SeqLock copy of a slot:
// once the reader has copied the slot's id and length and before it
// copies the body (and, in `fetch`, once it has copied the id it compares),
// in each case before it reads the slot's sequence word again. The input
// chooses at which of the read's points one or two writers run, as other
// threads or processes would, and what they write: an envelope of their
// own, or a twin of the one being copied (the same content, so the same id
// and length, from another origin, at another time or with other flags);
// through `store`, or by hand as the layout documents it, publishing, or
// stopping part-way through the body, preempted or crashed with the slot
// held.
//
// The oracle reads the region's bytes itself, by the layout the crate's
// documentation gives, and judges each body with the specification's
// reading of the canonical envelope (`pulse_mesh_fuzz::canonical`), not
// with the codec.
//
// Invariants:
// - `open_existing` and `open` accept exactly the regions the layout says
//   they accept, with the capacity the header records; a refusal names a
//   field that is wrong with the value found and the value needed, or the
//   size the region has and the size its header needs;
// - an opened store reports the header's capacity, write cursor and busy
//   claims;
// - `fetch_at(cursor, id)` returns an envelope exactly when the cursor was
//   handed out, its slot's sequence word is the value published for that
//   cursor's lap, the recorded length is between 1 and the entry size, the
//   recorded id is `id`, and the body is one canonical envelope carrying
//   that id whose content hashes to it; the envelope is the body;
// - `fetch(id)` returns what `fetch_at` returns for the first of the
//   cursors the id's index bucket names (each entry less one, zero entries
//   skipped, newest first) that gives an envelope, and otherwise the first
//   slot, in slot order, whose sequence word is published (even and not
//   zero) and whose id, length and body pass the same checks;
// - `read_since(since)` returns, in cursor order, the envelope of every
//   cursor from the later of `since` and the write cursor less the capacity
//   up to the write cursor whose slot passes the checks for that cursor,
//   and the write cursor, or nothing and `since` when nothing was written
//   after it;
// - a raced read judges each of its units (the cursor `fetch_at` names,
//   each cursor `fetch`'s index bucket names and each slot it scans, each
//   cursor `read_since` covers, from the
//   write cursor it found) by those rules on the slots either as they
//   stood before the writers ran or as they stand after, and returns what
//   that gives: so every envelope it returns is one a write stored whole
//   in that unit, never one whose bytes mix two writes nor one under a
//   cursor that did not hold it, and a cursor overwritten under the copy
//   is returned whole as it was, or skipped;
// - `store` claims, of the cursors it takes from the write cursor on, the
//   first whose slot's sequence word is even and older than that cursor's
//   in-progress mark, writes the envelope's id, length and canonical bytes
//   there and publishes it, counting every cursor it gave up in the busy
//   claims; `SlotBusy` after `CLAIM_ATTEMPTS` cursors given up; and
//   `fetch_at` then returns the envelope under the cursor `store` returned,
//   when the envelope's flags are defined ones and its id is its own, and
//   the write cursor has not wrapped past `u64::MAX`; the same holds for a
//   writer's `store` that runs while a read is copying a slot;
// - nothing panics, whatever the header says: no cursor, lap or size is
//   computed where it can overflow.

#![no_main]

use std::cell::Cell;
use std::ops::Range;
use std::rc::Rc;

use core_store::fuzzing::{set_mid_copy, take_mid_copy};
use core_store::{
    default_index_buckets, EnvelopeStore, EnvelopeStoreError, CLAIM_ATTEMPTS, LAYOUT_VERSION,
    MAX_ENTRY_SIZE,
};
use libfuzzer_sys::arbitrary::{Result, Unstructured};
use libfuzzer_sys::fuzz_target;
use pulse_canon::{PayloadData, PulseEnvelope, PulseEnvelopeFlags, PulseEnvelopeId};
use pulse_mesh_fuzz::canonical;
use pulse_mesh_fuzz::shm::{unique_name, RawObject};
use pulse_mesh_fuzz::{rarely, take};

/// The layout of the crate's documentation (version 3).
const HEADER: usize = 64;
const SLOT_PREFIX: usize = 64;
const SLOT: usize = SLOT_PREFIX + MAX_ENTRY_SIZE;
const MAGIC: u32 = u32::from_le_bytes(*b"PMES");
const H_CURSOR: usize = 0;
const H_MAGIC: usize = 8;
const H_VERSION: usize = 12;
const H_CAPACITY: usize = 16;
const H_MAX_ENTRY: usize = 20;
const H_BUSY: usize = 24;
const H_INDEX_BUCKETS: usize = 40;
const INDEX_WAYS: usize = 4;
const BUCKET: usize = INDEX_WAYS * 8;
/// Most index buckets an object is sized and filled for; a bent count
/// above it is written to the header, but the object is not sized for it.
const MAX_BUCKETS: u32 = 64;
const S_SEQ: usize = 0;
const S_ID: usize = 8;
const S_LEN: usize = 24;

/// Most slots an object is sized for.
const MAX_SLOTS: usize = 3;
/// Most operations on one opened store.
const MAX_OPS: usize = 12;
/// Longest raw payload drawn.
const MAX_PAYLOAD: usize = 96;
/// The last of a read's interleaving points its writers may run at.
const MAX_POINT: u8 = 5;
/// Most writers that run at one interleaving point.
const MAX_WRITERS: usize = 2;

fuzz_target!(|data: &[u8]| {
    let _ = fuzz(data);
});

fn fuzz(data: &[u8]) -> Result<()> {
    let mut u = Unstructured::new(data);
    let slots = u.int_in_range(1..=MAX_SLOTS)?;
    // Sizes whose open waits 50 ms for a creator (an object not yet sized,
    // a magic not yet published) are rare, so they do not slow the rest.
    // Each choice's first value is the well-formed one, which an input that
    // has run out takes; the choices an open waits 50 ms on (an object not
    // yet sized, a magic not yet published) are rare.
    let recorded: u32 = match u.int_in_range(0..=15u8)? {
        1 => 0,
        2 => u.arbitrary()?,
        3 => slots as u32 + 1,
        4 => slots as u32 - 1,
        _ => slots as u32,
    };
    let well_formed = default_index_buckets(slots) as u32;
    let buckets: u32 = match u.int_in_range(0..=15u8)? {
        1 => 0,
        2 => 3,
        3 => u.arbitrary()?,
        4 => well_formed * 2,
        5 => 1,
        _ => well_formed,
    };
    let index_bytes = if buckets <= MAX_BUCKETS {
        buckets as usize * BUCKET
    } else {
        0
    };
    let full = HEADER + slots * SLOT + index_bytes;
    let size = if rarely(&mut u, 64)? {
        0
    } else {
        match u.int_in_range(0..=31u8)? {
            1 => HEADER,
            2 => full - SLOT,
            3 => full - 1,
            4 => full + u.int_in_range(1..=4096)?,
            _ => full,
        }
    };
    let magic = if rarely(&mut u, 64)? {
        0
    } else {
        match u.int_in_range(0..=31u8)? {
            1 => u.arbitrary::<u32>()?.max(1),
            _ => MAGIC,
        }
    };
    let version = if rarely(&mut u, 16)? {
        u.arbitrary()?
    } else {
        LAYOUT_VERSION
    };
    let max_entry = if rarely(&mut u, 16)? {
        u.arbitrary()?
    } else {
        MAX_ENTRY_SIZE as u32
    };
    let laps = u64::from(recorded.max(1));
    let cursor: u64 = match u.int_in_range(0..=7u8)? {
        5 => u.arbitrary()?,
        6 => u64::MAX - u64::from(u.int_in_range(0..=8u8)?),
        7 => (1u64 << 63) + u64::from(u.int_in_range(0..=8u8)?),
        _ => u.int_in_range(0..=4 * laps + 3)?,
    };
    let busy: u64 = if rarely(&mut u, 4)? {
        u.arbitrary()?
    } else {
        0
    };

    let name = unique_name("st");
    // Shared with the writers a raced read runs.
    let obj = Rc::new(RawObject::create(&name, size));
    obj.write(H_CURSOR, &cursor.to_le_bytes());
    obj.write(H_VERSION, &version.to_le_bytes());
    obj.write(H_CAPACITY, &recorded.to_le_bytes());
    obj.write(H_MAX_ENTRY, &max_entry.to_le_bytes());
    obj.write(H_BUSY, &busy.to_le_bytes());
    if rarely(&mut u, 8)? {
        obj.write(32, u.bytes(32.min(u.len()))?);
    }
    // After the bytes above, which reach over it.
    obj.write(H_INDEX_BUCKETS, &buckets.to_le_bytes());
    obj.write(H_MAGIC, &magic.to_le_bytes());
    for slot in 0..slots {
        fill_slot(&mut u, &obj, slot, cursor, laps)?;
    }
    fill_index(&mut u, &obj, recorded, buckets.min(MAX_BUCKETS), cursor)?;

    let have = obj.size();
    let opened = EnvelopeStore::open(&name, slots);
    check_open(&opened, expect_open(&obj, have, Some(slots)));
    drop(opened);
    let waits = size == 0 || magic == 0;
    if waits && !rarely(&mut u, 16)? {
        return Ok(());
    }
    let opened = EnvelopeStore::open_existing(&name);
    check_open(&opened, expect_open(&obj, have, None));
    let Ok(store) = opened else {
        return Ok(());
    };
    let view = View {
        obj: &*obj,
        cap: u64::from(recorded),
    };
    assert_eq!(
        store.capacity(),
        recorded as usize,
        "the capacity is not the header's"
    );
    assert_eq!(
        store.write_cursor(),
        view.u64_at(H_CURSOR),
        "the write cursor is not the header's"
    );
    assert_eq!(
        store.busy_claims(),
        view.u64_at(H_BUSY),
        "the busy claims are not the header's"
    );

    for _ in 0..u.int_in_range(1..=MAX_OPS)? {
        if u.is_empty() {
            break;
        }
        let read = match u.int_in_range(0..=4u8)? {
            0 | 1 => {
                let at = pick_cursor(&mut u, &view)?;
                Read::FetchAt(at, pick_id(&mut u, &view)?)
            }
            2 => Read::Fetch(pick_id(&mut u, &view)?),
            3 => Read::Since(pick_cursor(&mut u, &view)?),
            _ => {
                let env = envelope(&mut u, 0)?;
                check_store(&store, &view, &env);
                continue;
            }
        };
        let race = if u.ratio(1, 2)? {
            Some(race(&mut u)?)
        } else {
            None
        };
        check_read(&store, &obj, view.cap, read, race);
    }
    drop(store);
    drop(obj);
    Ok(())
}

/// Fill the index where a store of `recorded` slots has it: each entry
/// mostly a cursor near the write cursor, plus one, or zero, now and then
/// any value.
fn fill_index(
    u: &mut Unstructured<'_>,
    obj: &RawObject,
    recorded: u32,
    buckets: u32,
    cursor: u64,
) -> Result<()> {
    let base = HEADER + recorded as usize * SLOT;
    for entry in 0..buckets as usize * INDEX_WAYS {
        if u.is_empty() {
            break;
        }
        let value: u64 = match u.int_in_range(0..=7u8)? {
            0 | 1 => 0,
            2 => u.arbitrary()?,
            _ => cursor
                .saturating_sub(u64::from(u.int_in_range(0..=8u8)?))
                .wrapping_add(1),
        };
        obj.write(base + entry * 8, &value.to_le_bytes());
    }
    Ok(())
}

/// Write one slot: a sequence word, an id, a length and a body.
fn fill_slot(
    u: &mut Unstructured<'_>,
    obj: &RawObject,
    slot: usize,
    cursor: u64,
    laps: u64,
) -> Result<()> {
    let base = HEADER + slot * SLOT;
    let env = envelope(u, 0)?;
    let mut body = env.to_canonical_bytes();
    if rarely(u, 8)? && !body.is_empty() {
        let at = u.choose_index(body.len())?;
        body[at] ^= u.int_in_range(1..=u8::MAX)?;
    }
    if rarely(u, 16)? {
        body = take(u, 64)?.to_vec();
    }
    // A lap near the write cursor's, so that the word is often the one a
    // reader wants for some cursor.
    let lap = (cursor / laps).saturating_add_signed(u.int_in_range(-2..=1)?);
    let seq = match u.int_in_range(0..=7u8)? {
        0 => 0,
        1 => u.arbitrary()?,
        2 => lap.wrapping_mul(2).wrapping_add(1),
        _ => lap.wrapping_mul(2).wrapping_add(2),
    };
    let id = if rarely(u, 8)? {
        u.arbitrary()?
    } else {
        env.id().0
    };
    let len: u32 = match u.int_in_range(0..=15u8)? {
        0 => 0,
        1 => u.arbitrary()?,
        2 => MAX_ENTRY_SIZE as u32 + 1,
        _ => body.len() as u32,
    };
    obj.write(base + S_SEQ, &seq.to_le_bytes());
    obj.write(base + S_ID, &id);
    obj.write(base + S_LEN, &len.to_le_bytes());
    obj.write(base + SLOT_PREFIX, &body);
    Ok(())
}

/// What an open should do, by the documented layout.
#[derive(Debug)]
enum Expect {
    Capacity(usize),
    TooSmall {
        have: u64,
        need: u64,
    },
    /// Any one of these (field, found, needed) triples.
    Mismatch(Vec<(&'static str, u64, u64)>),
    InvalidCapacity,
}

/// `open(name, Some(capacity))` or `open_existing(name)` (`None`) over the
/// object as it stands.
fn expect_open(obj: &RawObject, have: u64, asked: Option<usize>) -> Expect {
    let header = obj.read(0, HEADER);
    let word = |at: usize| {
        header
            .get(at..at + 4)
            .map_or(0, |b| u32::from_le_bytes(b.try_into().unwrap_or_default()))
    };
    let bytes_for = |cap: u64, buckets: u64| -> Option<u64> {
        cap.checked_mul(SLOT as u64)?
            .checked_add(HEADER as u64)?
            .checked_add(buckets.checked_mul(BUCKET as u64)?)
    };
    if let Some(cap) = asked {
        // The smallest store of the capacity asked for, with a one-bucket
        // index, before the header is read.
        let Some(need) = u32::try_from(cap)
            .ok()
            .filter(|&c| c >= 1)
            .and_then(|c| bytes_for(u64::from(c), 1))
        else {
            return Expect::InvalidCapacity;
        };
        if have < need {
            return Expect::TooSmall { have, need };
        }
    } else if have < HEADER as u64 {
        return Expect::TooSmall {
            have,
            need: HEADER as u64,
        };
    }
    let recorded = word(H_CAPACITY);
    let mut wrong = Vec::new();
    let mut check = |field, found: u32, needed: u32| {
        if found != needed {
            wrong.push((field, u64::from(found), u64::from(needed)));
        }
    };
    check("magic", word(H_MAGIC), MAGIC);
    check("version", word(H_VERSION), LAYOUT_VERSION);
    match asked {
        Some(cap) => check("capacity", recorded, cap as u32),
        None if recorded == 0 => check("capacity", 0, 1),
        None => {}
    }
    check("max_entry", word(H_MAX_ENTRY), MAX_ENTRY_SIZE as u32);
    // The index: a power of two no larger than the capacity rounded up to
    // a power of two (ADR-0020).
    let buckets = word(H_INDEX_BUCKETS);
    let fits = buckets.is_power_of_two()
        && u64::from(buckets) <= u64::from(recorded.max(1)).next_power_of_two();
    if !fits {
        wrong.push((
            "index_buckets",
            u64::from(buckets),
            default_index_buckets(recorded as usize) as u64,
        ));
    }
    if !wrong.is_empty() {
        return Expect::Mismatch(wrong);
    }
    let need = bytes_for(u64::from(recorded), u64::from(buckets)).unwrap_or(u64::MAX);
    if have < need {
        return Expect::TooSmall { have, need };
    }
    Expect::Capacity(recorded as usize)
}

fn check_open(got: &std::result::Result<EnvelopeStore, EnvelopeStoreError>, want: Expect) {
    match (got, &want) {
        (Ok(store), Expect::Capacity(cap)) => assert_eq!(store.capacity(), *cap),
        (
            Err(EnvelopeStoreError::RegionTooSmall { have, need }),
            Expect::TooSmall { have: h, need: n },
        ) => {
            assert_eq!(
                (*have, *need),
                (*h, *n),
                "the size refusal names other sizes"
            );
        }
        (
            Err(EnvelopeStoreError::LayoutMismatch { field, have, need }),
            Expect::Mismatch(wrong),
        ) => {
            assert!(
                wrong.contains(&(*field, *have, *need)),
                "refused on {field} ({have} for {need}), which is not among {wrong:?}"
            );
        }
        (Err(EnvelopeStoreError::InvalidCapacity { .. }), Expect::InvalidCapacity) => {}
        (got, want) => panic!(
            "open gave {:?}, the layout says {want:?}",
            got.as_ref().map(EnvelopeStore::capacity)
        ),
    }
}

/// Bytes of the region to read the layout from: the live object, or a copy
/// of it taken at one moment.
trait Region {
    /// `n` bytes at `offset`, cut short at the end of the region.
    fn read(&self, offset: usize, n: usize) -> Vec<u8>;
}

impl Region for RawObject {
    fn read(&self, offset: usize, n: usize) -> Vec<u8> {
        RawObject::read(self, offset, n)
    }
}

/// The region's bytes as they stood at one moment.
struct Snapshot(Vec<u8>);

impl Snapshot {
    fn of(obj: &RawObject) -> Self {
        Self(obj.read(0, obj.mapped()))
    }
}

impl Region for Snapshot {
    fn read(&self, offset: usize, n: usize) -> Vec<u8> {
        let rest = self.0.get(offset..).unwrap_or_default();
        rest[..n.min(rest.len())].to_vec()
    }
}

/// The region's bytes, read by the documented layout.
struct View<'a> {
    obj: &'a dyn Region,
    cap: u64,
}

impl View<'_> {
    fn u64_at(&self, at: usize) -> u64 {
        let b = self.obj.read(at, 8);
        u64::from_le_bytes(b.try_into().unwrap_or_default())
    }

    fn slot(&self, index: u64) -> (u64, [u8; 16], usize, usize) {
        let base = HEADER + index as usize * SLOT;
        let seq = self.u64_at(base + S_SEQ);
        let id: [u8; 16] = self
            .obj
            .read(base + S_ID, 16)
            .try_into()
            .unwrap_or_default();
        let len_bytes = self.obj.read(base + S_LEN, 4);
        let len = u32::from_le_bytes(len_bytes.try_into().unwrap_or_default()) as usize;
        (seq, id, len, base + SLOT_PREFIX)
    }

    /// The envelope a slot's copy holds: one canonical envelope, as the
    /// specification reads it, carrying the slot's id, whose content hashes
    /// to that id; as its canonical bytes, which are the body.
    fn reads_as(&self, index: u64) -> Option<Vec<u8>> {
        let (_, id, len, at) = self.slot(index);
        if len == 0 || len > MAX_ENTRY_SIZE {
            return None;
        }
        let body = self.obj.read(at, len);
        let spec = canonical::parse_exact(&body)?;
        (spec.id == id && spec.verifies()).then_some(body)
    }

    /// The value a slot's sequence word holds once `cursor` is published
    /// there, when the word can hold it.
    fn published(&self, cursor: u64) -> Option<u64> {
        (cursor / self.cap).checked_mul(2)?.checked_add(2)
    }

    /// The envelope `cursor`'s slot holds for that cursor: published for
    /// its lap and passing the checks.
    fn at(&self, cursor: u64) -> Option<Vec<u8>> {
        let index = cursor % self.cap;
        let (seq, ..) = self.slot(index);
        if Some(seq) != self.published(cursor) {
            return None;
        }
        self.reads_as(index)
    }

    /// [`Self::at`], when the slot's recorded id is `id`.
    fn at_with_id(&self, cursor: u64, id: &[u8; 16]) -> Option<Vec<u8>> {
        let (_, slot_id, ..) = self.slot(cursor % self.cap);
        if slot_id != *id {
            return None;
        }
        self.at(cursor)
    }

    fn fetch_at(&self, cursor: u64, id: &[u8; 16]) -> Option<Vec<u8>> {
        if cursor >= self.u64_at(H_CURSOR) {
            return None;
        }
        self.at_with_id(cursor, id)
    }

    /// The envelope slot `index` holds for `fetch(id)`: published (even
    /// and not zero), with the recorded id `id`, and passing the checks.
    fn holding(&self, index: u64, id: &[u8; 16]) -> Option<Vec<u8>> {
        let (seq, slot_id, _, _) = self.slot(index);
        if seq == 0 || seq % 2 == 1 || slot_id != *id {
            return None;
        }
        self.reads_as(index)
    }

    /// The cursors the index bucket of `id` names, newest first: each
    /// non-zero entry less one.
    fn index_cursors(&self, id: &[u8; 16]) -> Vec<u64> {
        let header = self.obj.read(H_INDEX_BUCKETS, 4);
        let buckets = u32::from_le_bytes(header.try_into().unwrap_or_default());
        if !buckets.is_power_of_two() {
            return Vec::new();
        }
        let hash = u64::from_le_bytes(id[..8].try_into().unwrap_or_default());
        let bucket = (hash & u64::from(buckets - 1)) as usize;
        let base = HEADER + self.cap as usize * SLOT + bucket * BUCKET;
        let mut cursors: Vec<u64> = (0..INDEX_WAYS)
            .map(|way| self.u64_at(base + way * 8))
            .filter(|&entry| entry != 0)
            .map(|entry| entry - 1)
            .collect();
        cursors.sort_unstable_by(|a, b| b.cmp(a));
        cursors
    }

    /// The cursors `read_since(since)` covers.
    fn since(&self, since: u64) -> Range<u64> {
        let current = self.u64_at(H_CURSOR);
        if current <= since {
            return since..since;
        }
        since.max(current.saturating_sub(self.cap))..current
    }
}

/// A read the input chooses.
#[derive(Debug, Clone, Copy)]
enum Read {
    FetchAt(u64, [u8; 16]),
    Fetch([u8; 16]),
    Since(u64),
}

/// What one unit of a read holds as the slots stood before the writers ran
/// and as they stand after.
type Unit = (Option<Vec<u8>>, Option<Vec<u8>>);

impl Read {
    /// The envelopes the read returns, as canonical bytes, and the cursor
    /// `read_since` returns.
    fn run(self, store: &EnvelopeStore) -> (Vec<Vec<u8>>, Option<u64>) {
        let bytes = |env: PulseEnvelope| env.to_canonical_bytes();
        match self {
            Read::FetchAt(at, id) => (
                store
                    .fetch_at(at, &PulseEnvelopeId(id))
                    .map(bytes)
                    .into_iter()
                    .collect(),
                None,
            ),
            Read::Fetch(id) => (
                store
                    .fetch(&PulseEnvelopeId(id))
                    .map(bytes)
                    .into_iter()
                    .collect(),
                None,
            ),
            Read::Since(since) => {
                let (envs, next) = store.read_since(since);
                (envs.into_iter().map(bytes).collect(), Some(next))
            }
        }
    }

    /// The units the read judges, each as the slots stood `before` the
    /// writers ran and as they stand `after`: the cursor `fetch_at` names,
    /// when it was handed out; each cursor `fetch`'s index names, then each
    /// slot it scans; each cursor `read_since` covers, from the write cursor
    /// it found.
    fn units(self, before: &View<'_>, after: &View<'_>) -> Vec<Unit> {
        match self {
            Read::FetchAt(at, id) if at < before.u64_at(H_CURSOR) => {
                vec![(before.at_with_id(at, &id), after.at_with_id(at, &id))]
            }
            Read::FetchAt(..) => Vec::new(),
            // The index first, as it stood before the read, then the scan.
            Read::Fetch(id) => before
                .index_cursors(&id)
                .into_iter()
                .map(|cursor| (before.fetch_at(cursor, &id), after.fetch_at(cursor, &id)))
                .chain(
                    (0..before.cap)
                        .map(|index| (before.holding(index, &id), after.holding(index, &id))),
                )
                .collect(),
            Read::Since(since) => before
                .since(since)
                .map(|cursor| (before.at(cursor), after.at(cursor)))
                .collect(),
        }
    }

    /// What the read returns when its units judge as `found`: every
    /// envelope, in order, or for `fetch` the first.
    fn returns(self, found: Vec<Option<Vec<u8>>>) -> Vec<Vec<u8>> {
        let found = found.into_iter().flatten();
        match self {
            Read::Fetch(_) => found.take(1).collect(),
            _ => found.collect(),
        }
    }

    /// Judge what the read returned against the slots `before` and `after`
    /// the writers of `race` ran (the same view when none ran).
    fn check(
        self,
        got: &(Vec<Vec<u8>>, Option<u64>),
        before: &View<'_>,
        after: &View<'_>,
        race: Option<&str>,
    ) {
        if let Read::Since(since) = self {
            let covered = before.since(since);
            let next = if covered.is_empty() {
                since
            } else {
                covered.end
            };
            assert_eq!(got.1, Some(next), "{self:?} returned another cursor");
        }
        let units = self.units(before, after);
        assert!(
            units.len() <= MAX_SLOTS + INDEX_WAYS,
            "a read of more units than slots and index entries"
        );
        // Each unit judged before or after the writers, independently.
        let explained = (0..1u32 << units.len()).any(|mask| {
            let found = units
                .iter()
                .enumerate()
                .map(|(i, (was, is))| if mask >> i & 1 == 1 { is } else { was }.clone())
                .collect();
            self.returns(found) == got.0
        });
        match race {
            None => assert!(
                explained,
                "{self:?} returned {:?}, and the slots hold {units:?}",
                got.0
            ),
            Some(race) => assert!(
                explained,
                "{self:?}, raced by {race}, returned {:?}: not what its units held \
                 before the writers or after them, {units:?}",
                got.0
            ),
        }
    }
}

/// Writers that run at one of a read's interleaving points.
#[derive(Debug)]
struct Race {
    /// Which of the read's points, counted from zero.
    at: u8,
    writers: Vec<Writer>,
}

/// A writer on another thread or in another process.
#[derive(Debug)]
struct Writer {
    what: What,
    how: How,
}

/// What a writer writes.
#[derive(Debug)]
enum What {
    /// An envelope of its own.
    Fresh(PulseEnvelope),
    /// The envelope in the slot being copied, from another origin, at
    /// another time or with other flags: the same content, so the same id
    /// and the same length.
    Twin {
        origin: [u8; 16],
        nanos: u64,
        flags: u16,
    },
}

/// How a writer writes.
#[derive(Debug)]
enum How {
    /// With `store`.
    Store,
    /// By hand, as the layout documents it: all of it, published, or, when
    /// `publish` is false, only the id, the length and a prefix of the body
    /// chosen by `upto`, stopping there with the slot held.
    Hand { upto: u16, publish: bool },
}

fn race(u: &mut Unstructured<'_>) -> Result<Race> {
    let at = u.int_in_range(0..=MAX_POINT)?;
    let mut writers = Vec::new();
    for _ in 0..u.int_in_range(1..=MAX_WRITERS)? {
        let what = if u.ratio(1, 2)? {
            What::Twin {
                origin: u.arbitrary()?,
                nanos: u.arbitrary()?,
                flags: u.arbitrary()?,
            }
        } else {
            What::Fresh(envelope(u, 0)?)
        };
        let how = if u.ratio(1, 2)? {
            How::Store
        } else {
            How::Hand {
                upto: u.arbitrary()?,
                publish: u.ratio(1, 3)?,
            }
        };
        writers.push(Writer { what, how });
    }
    Ok(Race { at, writers })
}

/// A read, alone or raced by writers at one of its interleaving points,
/// judged against the slots before and after them.
fn check_read(
    store: &EnvelopeStore,
    obj: &Rc<RawObject>,
    cap: u64,
    read: Read,
    race: Option<Race>,
) {
    let live = View { obj: &**obj, cap };
    let Some(race) = race else {
        let got = read.run(store);
        read.check(&got, &live, &live, None);
        return;
    };
    let shown = format!("{race:?}");
    let snapshot = Snapshot::of(obj);
    let ran = arm(race, Rc::clone(obj), cap);
    let got = read.run(store);
    drop(take_mid_copy());
    let before = View {
        obj: &snapshot,
        cap,
    };
    match ran.get() {
        None => read.check(&got, &before, &before, None),
        Some(index) => {
            let race = format!("{shown} at slot {index}");
            read.check(&got, &before, &live, Some(&race));
        }
    }
}

/// Set the interleaving point so that the writers run at the read's
/// `race.at`-th point, once. The cell comes to hold the slot whose copy
/// was under way when they ran.
fn arm(race: Race, obj: Rc<RawObject>, cap: u64) -> Rc<Cell<Option<usize>>> {
    let ran = Rc::new(Cell::new(None));
    let noted = Rc::clone(&ran);
    let mut point = 0u8;
    let mut writers = Some(race.writers);
    set_mid_copy(Box::new(move |store, index| {
        let now = point;
        point = point.saturating_add(1);
        if now != race.at {
            return;
        }
        let Some(writers) = writers.take() else {
            return;
        };
        noted.set(Some(index));
        let live = View { obj: &*obj, cap };
        for writer in writers {
            writer.run(store, &obj, &live, index);
        }
    }));
    ran
}

impl Writer {
    fn run(self, store: &EnvelopeStore, obj: &RawObject, live: &View<'_>, index: usize) {
        let env = match self.what {
            What::Fresh(env) => env,
            What::Twin {
                origin,
                nanos,
                flags,
            } => {
                let Some(mut twin) = decoded(live, index) else {
                    return;
                };
                twin.origin = origin;
                twin.monotonic_nanos = nanos;
                twin.flags = PulseEnvelopeFlags::from_bits_truncate(flags);
                twin
            }
        };
        match self.how {
            How::Store => check_store(store, live, &env),
            How::Hand { upto, publish } => {
                let body = env.to_canonical_bytes();
                let upto = usize::from(upto) % (body.len() + 1);
                write_by_hand(obj, live, &env.id().0, &body, upto, publish);
            }
        }
    }
}

/// The envelope slot `index`'s body holds, as the codec reads it, for a
/// twin to be made of.
fn decoded(view: &View<'_>, index: usize) -> Option<PulseEnvelope> {
    let (_, _, len, at) = view.slot(index as u64);
    if len == 0 || len > MAX_ENTRY_SIZE {
        return None;
    }
    let body = view.obj.read(at, len);
    PulseEnvelope::decode_canonical_at(&body, 0)
        .ok()
        .map(|(env, _)| env)
}

/// A writer of another process, following the protocol the crate
/// documents: it takes the next cursor, and claims that cursor's slot when
/// its sequence word is even and older than the cursor's in-progress mark
/// (otherwise it counts a busy claim and gives the cursor up); it writes
/// the id, the length and the first `upto` bytes of the body, and, when
/// `publish`, the rest and the published word; otherwise it stops there,
/// preempted or crashed, holding the slot.
fn write_by_hand(
    obj: &RawObject,
    live: &View<'_>,
    id: &[u8; 16],
    body: &[u8],
    upto: usize,
    publish: bool,
) {
    let cursor = live.u64_at(H_CURSOR);
    obj.write(H_CURSOR, &cursor.wrapping_add(1).to_le_bytes());
    let base = HEADER + (cursor % live.cap) as usize * SLOT;
    let seq = live.u64_at(base + S_SEQ);
    let claim = live
        .published(cursor)
        .filter(|&published| seq % 2 == 0 && seq < published - 1);
    let Some(published) = claim else {
        let busy = live.u64_at(H_BUSY).wrapping_add(1);
        obj.write(H_BUSY, &busy.to_le_bytes());
        return;
    };
    obj.write(base + S_SEQ, &(published - 1).to_le_bytes());
    obj.write(base + S_ID, id);
    obj.write(base + S_LEN, &(body.len() as u32).to_le_bytes());
    if publish {
        obj.write(base + SLOT_PREFIX, body);
        obj.write(base + S_SEQ, &published.to_le_bytes());
    } else {
        obj.write(base + SLOT_PREFIX, &body[..upto]);
    }
}

/// `store` against the claim rule, and the envelope read back where it went.
fn check_store(store: &EnvelopeStore, view: &View<'_>, env: &PulseEnvelope) {
    let bytes = env.to_canonical_bytes();
    let first = view.u64_at(H_CURSOR);
    let busy = view.u64_at(H_BUSY);
    // The claim rule: the first cursor, of those taken in turn, whose slot's
    // word is even and older than the cursor's in-progress mark.
    let mut claimed = None;
    let mut tried = 0u64;
    for attempt in 0..CLAIM_ATTEMPTS as u64 {
        let cursor = first.wrapping_add(attempt);
        tried += 1;
        let Some(published) = view.published(cursor) else {
            continue;
        };
        let (seq, ..) = view.slot(cursor % view.cap);
        if seq % 2 == 0 && seq < published - 1 {
            claimed = Some((cursor, published));
            break;
        }
    }
    let got = store.store(env);
    assert_eq!(
        view.u64_at(H_CURSOR),
        first.wrapping_add(tried),
        "store took another number of cursors"
    );
    let given_up = tried - u64::from(claimed.is_some());
    assert_eq!(
        view.u64_at(H_BUSY),
        busy.wrapping_add(given_up),
        "the busy claims did not count the cursors given up"
    );
    match (got, claimed) {
        (Ok(cursor), Some((want, published))) => {
            assert_eq!(cursor, want, "store claimed another cursor");
            let index = cursor % view.cap;
            let (seq, id, len, at) = view.slot(index);
            assert_eq!(seq, published, "the slot is not published for its cursor");
            assert_eq!(id, env.id().0, "the slot holds another id");
            assert_eq!(len, bytes.len(), "the slot holds another length");
            assert_eq!(view.obj.read(at, len), bytes, "the slot holds another body");
            // The index entry for the id, way `cursor mod 4`, names the copy.
            let buckets = u64::from(store.index_buckets() as u32);
            let hash = u64::from_le_bytes(env.id().0[..8].try_into().unwrap_or_default());
            let entry = HEADER
                + view.cap as usize * SLOT
                + (hash & (buckets - 1)) as usize * BUCKET
                + (cursor % INDEX_WAYS as u64) as usize * 8;
            assert_eq!(
                view.u64_at(entry),
                cursor.wrapping_add(1),
                "store did not index the copy"
            );
            let back = store
                .fetch_at(cursor, &env.id())
                .map(|e| e.to_canonical_bytes());
            assert_eq!(
                back,
                view.fetch_at(cursor, &env.id().0),
                "fetch_at after the store"
            );
            // Unless the write cursor wrapped past u64::MAX, which only a
            // header written by hand reaches, the cursor was handed out and
            // its copy reads back.
            if cursor < view.u64_at(H_CURSOR) {
                let readable = canonical::parse_exact(&bytes).is_some_and(|p| p.verifies());
                assert_eq!(
                    back,
                    readable.then_some(bytes),
                    "the envelope stored is not what fetch_at returns"
                );
            }
        }
        (Err(EnvelopeStoreError::SlotBusy { cursor }), None) => {
            assert_eq!(
                cursor,
                first.wrapping_add(tried - 1),
                "SlotBusy names another cursor"
            );
        }
        (got, want) => panic!("store gave {got:?}, the claim rule says {want:?}"),
    }
}

/// A cursor near the write cursor, a lap boundary, or anywhere.
fn pick_cursor(u: &mut Unstructured<'_>, view: &View<'_>) -> Result<u64> {
    let current = view.u64_at(H_CURSOR);
    Ok(match u.int_in_range(0..=3u8)? {
        0 => u.arbitrary()?,
        1 => current / view.cap * view.cap,
        _ => current.wrapping_add_signed(u.int_in_range(-(2 * view.cap as i64 + 2)..=1)?),
    })
}

/// A slot's id, or any id.
fn pick_id(u: &mut Unstructured<'_>, view: &View<'_>) -> Result<[u8; 16]> {
    if u.ratio(1, 4)? {
        return u.arbitrary();
    }
    let index = u.int_in_range(0..=view.cap - 1)?;
    Ok(view.slot(index).1)
}

/// An envelope drawn from the input, with the id of its content.
fn envelope(u: &mut Unstructured<'_>, depth: usize) -> Result<PulseEnvelope> {
    let envelope_type: u16 = u.arbitrary()?;
    let type_name: Option<String> = if u.ratio(1, 3)? {
        Some(u.arbitrary::<&str>()?.to_owned())
    } else {
        None
    };
    let payload = if depth < 2 && u.ratio(1, 4)? {
        let mut children = Vec::new();
        for _ in 0..u.int_in_range(0..=2)? {
            children.push(envelope(u, depth + 1)?);
        }
        PayloadData::Nested(children)
    } else {
        let len = u.int_in_range(0..=MAX_PAYLOAD)?;
        PayloadData::Raw(u.bytes(len.min(u.len()))?.to_vec())
    };
    let mut envelope = PulseEnvelope::with_content(envelope_type, type_name, payload);
    envelope.origin = u.arbitrary()?;
    envelope.monotonic_nanos = u.arbitrary()?;
    envelope.flags = if rarely(u, 16)? {
        PulseEnvelopeFlags::from_bits_retain(u.arbitrary()?)
    } else {
        PulseEnvelopeFlags::from_bits_truncate(u.arbitrary()?)
    };
    Ok(envelope)
}
