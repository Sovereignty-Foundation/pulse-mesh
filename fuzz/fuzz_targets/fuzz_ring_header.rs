// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//
// Fuzz target: `core_ring::PulseRing::open_existing` and `open` over a
// shared-memory object whose header holds bytes the input chooses, then
// the ring's reads over slots that hold arbitrary bytes, and publishes.
//
// Each input makes the object afresh under a name unique to the process,
// sized for the ring its header describes or not (a size of zero now and
// then, or one too small), writes a header that is mostly well formed with
// fields the input may bend (magic, version, capacity anywhere in the u64
// range, slot size, the cursors, the superseded mark), fills the slots, and
// unlinks the object once the input is done. The oracle reads the region's
// bytes itself, by the layout in core-ring's documentation.
//
// Half the reads are raced. A build for fuzzing has an interleaving point,
// `core_ring::fuzzing`, inside the SeqLock copy of `read_slot` (which
// `read_position` and `read_slots_batch` read through): once the reader has
// copied the slot and before it loads the slot's counter again. The reader
// then copies the second half of the slot again, so the copy
// it checks holds the slot as it stood before whatever ran at the point in
// its first part and as it stands after in the rest. The input chooses at
// which of the read's points one or two writers run, as the ring's writer
// in another thread or process would, and what they write: a pulse
// published at the cursor or at the slot being read, through the API, or
// written by hand into the slot being read as the layout documents it,
// publishing, or stopping part-way through the pulse with the counter odd,
// preempted or crashed.
//
// Invariants:
// - `open_existing` accepts exactly a region at least a header long whose
//   magic is `PMSR`, version 1, slot size 128 or 192 and capacity at least
//   one, and that is long enough for the ring its header describes; a
//   refusal names a wrong field with the value found and the value needed,
//   or the size the region has and the size its header needs (`u64::MAX`
//   when that size overflows);
// - `open(name, capacity)` accepts exactly such a region of 128-byte slots
//   holding that capacity, and refuses a capacity of zero before it opens
//   anything, since every read and publish takes a position modulo it;
// - an opened ring reports the header's capacity, cursors, write count,
//   slot size and superseded mark;
// - `read_slot` returns a slot's 128 bytes exactly when its counter is even
//   and not zero;
// - `read_position` follows the documented rule: not written at or past the
//   cursor; lost up to the cursor less the capacity for a position further
//   behind; lost up to the next position when the slot has no stable copy,
//   or exactly a capacity behind the cursor, a counter that may show a
//   later lap; the slot's pulse otherwise;
// - a publish, or a batch of at most the capacity, writes each pulse at the
//   cursor and moves the cursor and the write count one past it, and the
//   position it took reads back as that pulse or as lost, never as another;
//   a batch larger than the capacity writes nothing;
// - a raced read judges each slot it reads by those rules on the slot as it
//   stood before the writers ran or as it stands after, and `read_position`
//   its position with the cursor it found before its copy and the one after
//   the writers: so no read returns a slot whose bytes mix two writes, and
//   no position reads back as a pulse the rule would call lost;
// - nothing panics, whatever the header says.

#![no_main]

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use core_ring::fuzzing::{set_mid_copy, take_mid_copy};
use core_ring::{PositionRead, PulseRing, RingError, LAYOUT_VERSION, PULSE_SIZE, PULSE_SIZE_V2};
use libfuzzer_sys::arbitrary::{Result, Unstructured};
use libfuzzer_sys::fuzz_target;
use pulse_canon::Pulse;
use pulse_mesh_fuzz::shm::{unique_name, RawObject};
use pulse_mesh_fuzz::{rarely, take};

/// The layout of core-ring's documentation.
const HEADER: usize = 64;
const MAGIC: u32 = u32::from_le_bytes(*b"PMSR");
const H_CURSOR: usize = 0;
const H_TOTAL: usize = 8;
const H_READ: usize = 16;
const H_MAGIC: usize = 24;
const H_VERSION: usize = 28;
const H_CAPACITY: usize = 32;
const H_SLOT_SIZE: usize = 40;
const H_SUPERSEDED: usize = 44;

/// Largest capacity a well-formed header is drawn with.
const MAX_CAPACITY: u64 = 48;
/// Most operations on one opened ring.
const MAX_OPS: usize = 12;
/// The last of a read's interleaving points its writers may run at.
const MAX_POINT: u8 = 5;
/// Most writers that run at one interleaving point.
const MAX_WRITERS: usize = 2;

fuzz_target!(|data: &[u8]| {
    let _ = fuzz(data);
});

fn fuzz(data: &[u8]) -> Result<()> {
    let mut u = Unstructured::new(data);
    // Each choice's first value is the well-formed one, which an input that
    // has run out takes; a zero magic, which an open waits 50 ms on, is rare.
    let capacity: u64 = match u.int_in_range(0..=15u8)? {
        13 => 0,
        14 => u.arbitrary()?,
        15 => u64::MAX / 64 + u64::from(u.arbitrary::<u8>()?),
        _ => u.int_in_range(1..=MAX_CAPACITY)?,
    };
    let slot_size: u32 = match u.int_in_range(0..=15u8)? {
        15 => u.arbitrary()?,
        10..=14 => PULSE_SIZE_V2 as u32,
        _ => PULSE_SIZE as u32,
    };
    let wanted = capacity
        .checked_mul(u64::from(slot_size))
        .and_then(|n| n.checked_add(HEADER as u64))
        .filter(|&n| n <= 1 << 20)
        .unwrap_or(HEADER as u64) as usize;
    // A size of zero makes no wait here (an open by name alone does not wait
    // for a creator to size the object), but a zero magic does: 50 ms.
    let size = match u.int_in_range(0..=31u8)? {
        28 => 0,
        29 => u.int_in_range(1..=HEADER)?,
        30 => wanted.saturating_sub(1).max(1),
        31 => wanted + u.int_in_range(1..=1024)?,
        _ => wanted,
    };
    let magic = if rarely(&mut u, 64)? {
        0
    } else {
        match u.int_in_range(0..=31u8)? {
            31 => u.arbitrary::<u32>()?.max(1),
            _ => MAGIC,
        }
    };
    let version = if rarely(&mut u, 16)? {
        u.arbitrary()?
    } else {
        LAYOUT_VERSION
    };
    let laps = capacity.max(1);
    let cursor: u64 = match u.int_in_range(0..=7u8)? {
        6 => u.arbitrary()?,
        7 => u64::MAX - u64::from(u.int_in_range(0..=4u8)?),
        _ => u.int_in_range(0..=3 * laps.min(MAX_CAPACITY) + 2)?,
    };
    let total: u64 = if rarely(&mut u, 4)? {
        u.arbitrary()?
    } else {
        cursor
    };
    let read: u64 = if rarely(&mut u, 4)? {
        u.arbitrary()?
    } else {
        0
    };
    let superseded: u32 = match u.int_in_range(0..=7u8)? {
        6 => 1,
        7 => u.arbitrary()?,
        _ => 0,
    };

    let name = unique_name("rg");
    let obj = Rc::new(RawObject::create(&name, size));
    obj.write(H_CURSOR, &cursor.to_le_bytes());
    obj.write(H_TOTAL, &total.to_le_bytes());
    obj.write(H_READ, &read.to_le_bytes());
    obj.write(H_VERSION, &version.to_le_bytes());
    obj.write(H_CAPACITY, &capacity.to_le_bytes());
    obj.write(H_SLOT_SIZE, &slot_size.to_le_bytes());
    obj.write(H_SUPERSEDED, &superseded.to_le_bytes());
    if rarely(&mut u, 8)? {
        obj.write(48, u.bytes(16.min(u.len()))?);
    }
    obj.write(H_MAGIC, &magic.to_le_bytes());
    // The slots: a counter for each, mostly even, and arbitrary bytes.
    let stride = if slot_size as usize == PULSE_SIZE_V2 {
        PULSE_SIZE_V2
    } else {
        PULSE_SIZE
    };
    let mut slot = 0usize;
    while HEADER + slot * stride < obj.mapped() && slot < MAX_CAPACITY as usize && !u.is_empty() {
        let base = HEADER + slot * stride;
        let lap = cursor / laps;
        let counter: u64 = match u.int_in_range(0..=7u8)? {
            0 => 0,
            1 => u.arbitrary()?,
            2 => lap.wrapping_mul(2).wrapping_add(1),
            3 => lap.wrapping_mul(2).wrapping_add(4),
            _ => lap.wrapping_mul(2).wrapping_add(2),
        };
        obj.write(base, &counter.to_le_bytes());
        let fill = take(&mut u, stride - 8)?;
        obj.write(base + 8, fill);
        slot += 1;
    }

    let have = obj.size();
    let view = View { obj: &*obj };
    if magic != 0 || rarely(&mut u, 16)? {
        let asked = if u.ratio(1, 2)? {
            capacity
        } else {
            u.int_in_range(1..=MAX_CAPACITY)?
        };
        let opened = PulseRing::open(&name, asked);
        check_open(&opened, view.expect_open(have, Some(asked)));
        if let Ok(mut ring) = opened {
            let writer = second_handle(&name);
            exercise(&mut u, &mut ring, &writer, &obj)?;
        }
    }
    if magic == 0 && !rarely(&mut u, 16)? {
        return Ok(());
    }
    let opened = PulseRing::open_existing(&name);
    check_open(&opened, view.expect_open(have, None));
    if let Ok(mut ring) = opened {
        let writer = second_handle(&name);
        exercise(&mut u, &mut ring, &writer, &obj)?;
    }
    drop(obj);
    Ok(())
}

/// A second handle on the ring `name` names, for the writers of a raced
/// read: publishing takes a handle's `&mut`, and the read borrows the other.
/// The ring already opened, so this open does too.
fn second_handle(name: &str) -> Rc<RefCell<PulseRing>> {
    Rc::new(RefCell::new(
        PulseRing::open_existing(name).expect("a ring that opened opens again"),
    ))
}

/// Read and publish through an opened ring, each result held to the
/// documented rule over the region's bytes as they stand, or, for a raced
/// read, as they stood before its writers or stand after them; the writers
/// of a raced read publish through `writer`.
fn exercise(
    u: &mut Unstructured<'_>,
    ring: &mut PulseRing,
    writer: &Rc<RefCell<PulseRing>>,
    obj: &Rc<RawObject>,
) -> Result<()> {
    let view = View { obj: &**obj };
    let geometry = Geometry {
        capacity: ring.capacity(),
        stride: if ring.is_v2() {
            PULSE_SIZE_V2
        } else {
            PULSE_SIZE
        },
    };
    assert_eq!(
        ring.capacity(),
        view.u64_at(H_CAPACITY),
        "the capacity is not the header's"
    );
    assert_eq!(
        geometry.stride as u32,
        view.u32_at(H_SLOT_SIZE),
        "the slot size is not the header's"
    );
    assert_eq!(ring.cursor_position(), view.u64_at(H_CURSOR));
    assert_eq!(ring.write_count(), view.u64_at(H_TOTAL));
    assert_eq!(ring.read_cursor_position(), view.u64_at(H_READ));
    assert_eq!(ring.is_superseded(), view.u32_at(H_SUPERSEDED) != 0);

    for _ in 0..u.int_in_range(1..=MAX_OPS)? {
        if u.is_empty() {
            break;
        }
        match u.int_in_range(0..=5u8)? {
            0 => {
                let at = pick_position(u, &view)?;
                let race = maybe_race(u)?;
                let (got, before, race) = raced(obj, geometry, race, writer, || {
                    ring.read_slot(at).map(|p| p.as_bytes().to_vec())
                });
                let candidates = before.views(&view).map(|v| v.read_slot(&geometry, at));
                judge(
                    &got,
                    &candidates,
                    race.as_deref(),
                    &format!("read_slot({at})"),
                );
            }
            1 | 2 => {
                let at = pick_position(u, &view)?;
                let race = maybe_race(u)?;
                let (got, before, race) =
                    raced(obj, geometry, race, writer, || ring.read_position(at));
                let [then, now] = before.views(&view);
                // The cursor is loaded before the copy and again after it:
                // before the writers and after them. The copy is the slot
                // as it stood before them or as it stands after.
                let candidates =
                    [&then, &now].map(|copy| position_rule(&then, copy, &now, &geometry, at));
                judge(
                    &position(&got),
                    &candidates,
                    race.as_deref(),
                    &format!("read_position({at})"),
                );
            }
            3 => {
                let pulse = pulse(u)?;
                let before = (view.u64_at(H_CURSOR), view.u64_at(H_TOTAL));
                let number = ring.publish(&pulse);
                check_published(ring, &view, &geometry, before, &[pulse], number, 0);
            }
            4 => {
                let n = u.int_in_range(0..=3usize)?;
                let pulses = (0..n).map(|_| pulse(u)).collect::<Result<Vec<_>>>()?;
                let before = (view.u64_at(H_CURSOR), view.u64_at(H_TOTAL));
                match ring.publish_batch(&pulses) {
                    Ok(number) => {
                        assert!(
                            n as u64 <= geometry.capacity,
                            "a batch past the capacity was written"
                        );
                        if n == 0 {
                            assert_eq!(number, before.1, "an empty batch is not the write count");
                        }
                        for i in 0..n {
                            check_published(ring, &view, &geometry, before, &pulses, number, i);
                        }
                    }
                    Err(RingError::BatchTooLarge { len, capacity }) => {
                        assert_eq!((len, capacity), (n, geometry.capacity));
                        assert!(
                            n as u64 > geometry.capacity,
                            "a batch that fits was refused"
                        );
                        assert_eq!(
                            (view.u64_at(H_CURSOR), view.u64_at(H_TOTAL)),
                            before,
                            "a refused batch moved the cursor"
                        );
                    }
                    Err(e) => panic!("publish_batch failed with {e}"),
                }
            }
            _ => {
                let at = pick_position(u, &view)?;
                let mut out: Vec<Pulse> = (0..u.int_in_range(0..=4usize)?)
                    .map(|_| Pulse::zeroed())
                    .collect();
                let race = maybe_race(u)?;
                let (n, before, race) = raced(obj, geometry, race, writer, || {
                    ring.read_slots_batch(at, &mut out)
                });
                let views = before.views(&view);
                let candidates =
                    |position: u64| views.each_ref().map(|v| v.read_slot(&geometry, position));
                for (i, got) in out.iter().enumerate().take(n) {
                    let position = at.wrapping_add(i as u64);
                    judge(
                        &Some(got.as_bytes().to_vec()),
                        &candidates(position),
                        race.as_deref(),
                        &format!("read_slots_batch item {i} at {position}"),
                    );
                }
                if n < out.len() {
                    let position = at.wrapping_add(n as u64);
                    judge(
                        &None,
                        &candidates(position),
                        race.as_deref(),
                        &format!("read_slots_batch stopping at {position}"),
                    );
                }
            }
        }
    }
    Ok(())
}

/// `got` is one of `candidates`: what the rule gives on the slots as they
/// stood before the writers of `race` ran and as they stand after (the
/// same when none ran).
fn judge<T: PartialEq + std::fmt::Debug>(
    got: &T,
    candidates: &[T; 2],
    race: Option<&str>,
    what: &str,
) {
    match race {
        None => assert_eq!(got, &candidates[1], "{what}"),
        Some(race) => assert!(
            candidates.contains(got),
            "{what}, raced by {race}, returned {got:?}: not what the slot held before the \
             writers or after them, {candidates:?}"
        ),
    }
}

/// Half the reads are raced, by the writers the input draws.
fn maybe_race(u: &mut Unstructured<'_>) -> Result<Option<Race>> {
    if !u.ratio(1, 2)? {
        return Ok(None);
    }
    let at = u.int_in_range(0..=MAX_POINT)?;
    let mut writers = Vec::new();
    for _ in 0..u.int_in_range(1..=MAX_WRITERS)? {
        let pulse = pulse(u)?;
        writers.push(match u.int_in_range(0..=3u8)? {
            0 => Writer::Publish(pulse),
            1 => Writer::AtSlot(pulse),
            _ => Writer::Hand {
                pulse,
                upto: usize::from(u.int_in_range(0..=(PULSE_SIZE - 8) as u8)?),
                publish: u.ratio(2, 3)?,
            },
        });
    }
    Ok(Some(Race { at, writers }))
}

/// Writers that run at one of a read's interleaving points.
#[derive(Debug)]
struct Race {
    /// Which of the read's points, counted from zero.
    at: u8,
    writers: Vec<Writer>,
}

/// A writer of the ring, in another thread or process.
#[derive(Debug)]
enum Writer {
    /// `publish`: the pulse into the slot at the cursor, which may or may
    /// not be the slot being read, then the cursor and the write count on.
    Publish(Pulse),
    /// `publish_at_slot` into the slot being read.
    AtSlot(Pulse),
    /// By hand into the slot being read, as the layout documents a write:
    /// the counter made odd, the pulse's bytes after the counter up to
    /// `upto` of them, and, when `publish`, the rest and the counter made
    /// even, two past what it was; otherwise the writer stops there,
    /// preempted or crashed, with the counter odd.
    Hand {
        pulse: Pulse,
        upto: usize,
        publish: bool,
    },
}

impl Writer {
    fn run(&self, ring: &mut PulseRing, obj: &RawObject, geometry: &Geometry, slot: u64) {
        match self {
            Writer::Publish(pulse) => {
                ring.publish(pulse);
            }
            Writer::AtSlot(pulse) => {
                ring.publish_at_slot(slot, pulse);
            }
            Writer::Hand {
                pulse,
                upto,
                publish,
            } => {
                let base = HEADER + slot as usize * geometry.stride;
                let prev = (View { obj }).u64_at(base) & !1;
                obj.write(base, &(prev | 1).to_le_bytes());
                let bytes = pulse.as_bytes();
                let upto = 8 + upto;
                obj.write(base + 8, &bytes[8..upto]);
                if *publish {
                    obj.write(base + upto, &bytes[upto..PULSE_SIZE]);
                    obj.write(base, &prev.wrapping_add(2).to_le_bytes());
                }
            }
        }
    }
}

/// Run `read`, alone or raced by `race`. Returns what it returned, the
/// region as it stood before the writers when some ran, and the race with
/// the slot whose copy was under way when they ran.
fn raced<T>(
    obj: &Rc<RawObject>,
    geometry: Geometry,
    race: Option<Race>,
    writer: &Rc<RefCell<PulseRing>>,
    read: impl FnOnce() -> T,
) -> (T, Before, Option<String>) {
    let Some(race) = race else {
        return (read(), Before(None), None);
    };
    let shown = format!("{race:?}");
    let snapshot = Snapshot::of(obj);
    let ran = arm(race, Rc::clone(obj), geometry, Rc::clone(writer));
    let got = read();
    drop(take_mid_copy());
    match ran.get() {
        None => (got, Before(None), None),
        Some(slot) => (
            got,
            Before(Some(snapshot)),
            Some(format!("{shown} at slot {slot}")),
        ),
    }
}

/// Set the interleaving point so that the writers run at the read's
/// `race.at`-th point, once. The cell comes to hold the slot whose copy
/// was under way when they ran.
fn arm(
    race: Race,
    obj: Rc<RawObject>,
    geometry: Geometry,
    handle: Rc<RefCell<PulseRing>>,
) -> Rc<Cell<Option<u64>>> {
    let ran = Rc::new(Cell::new(None));
    let noted = Rc::clone(&ran);
    let mut point = 0u8;
    let mut writers = Some(race.writers);
    set_mid_copy(Box::new(move |_reader, slot| {
        let now = point;
        point = point.saturating_add(1);
        if now != race.at {
            return;
        }
        let Some(writers) = writers.take() else {
            return;
        };
        noted.set(Some(slot));
        let mut ring = handle.borrow_mut();
        for writer in &writers {
            writer.run(&mut ring, &obj, &geometry, slot);
        }
    }));
    ran
}

/// The region as it stood before a raced read's writers ran, when some ran.
struct Before(Option<Snapshot>);

impl Before {
    /// The views to judge a read by: the region before the writers, or as
    /// it stands when none ran, then the region as it stands.
    fn views<'a>(&'a self, now: &View<'a>) -> [View<'a>; 2] {
        let then = match &self.0 {
            Some(snapshot) => View { obj: snapshot },
            None => View { obj: now.obj },
        };
        [then, View { obj: now.obj }]
    }
}

/// A copy of the region's bytes.
struct Snapshot(Vec<u8>);

impl Snapshot {
    fn of(obj: &RawObject) -> Self {
        Self(obj.read(0, obj.mapped()))
    }
}

/// Bytes the oracle reads: the live object, or a snapshot of it.
trait Region {
    fn read(&self, offset: usize, n: usize) -> Vec<u8>;
}

impl Region for RawObject {
    fn read(&self, offset: usize, n: usize) -> Vec<u8> {
        RawObject::read(self, offset, n)
    }
}

impl Region for Snapshot {
    fn read(&self, offset: usize, n: usize) -> Vec<u8> {
        let rest = self.0.get(offset..).unwrap_or_default();
        rest[..n.min(rest.len())].to_vec()
    }
}

/// What an open should do, by the documented layout.
#[derive(Debug)]
enum Expect {
    Opens {
        capacity: u64,
        stride: usize,
    },
    /// `open` asked for no slots at all.
    NoSlots,
    TooSmall {
        have: u64,
        need: u64,
    },
    /// Any one of these (field, found, needed) triples.
    Mismatch(Vec<(&'static str, u64, u64)>),
}

fn check_open(got: &std::result::Result<PulseRing, RingError>, want: Expect) {
    match (got, &want) {
        (Ok(ring), Expect::Opens { capacity, stride }) => {
            assert_eq!(ring.capacity(), *capacity);
            assert_eq!(ring.is_v2(), *stride == PULSE_SIZE_V2);
        }
        (Err(RingError::InvalidCapacity { capacity: 0 }), Expect::NoSlots) => {}
        (Err(RingError::RegionTooSmall { have, need }), Expect::TooSmall { have: h, need: n }) => {
            assert_eq!(
                (*have, *need),
                (*h, *n),
                "the size refusal names other sizes"
            );
        }
        (Err(RingError::LayoutMismatch { field, have, need }), Expect::Mismatch(wrong)) => {
            assert!(
                wrong.contains(&(*field, *have, *need)),
                "refused on {field} ({have} for {need}), which is not among {wrong:?}"
            );
        }
        (got, want) => panic!(
            "open gave {:?}, the layout says {want:?}",
            got.as_ref().map(PulseRing::capacity)
        ),
    }
}

/// The capacity and slot stride of an opened ring.
#[derive(Clone, Copy)]
struct Geometry {
    capacity: u64,
    stride: usize,
}

/// The region's bytes, read by the documented layout.
struct View<'a> {
    obj: &'a dyn Region,
}

impl View<'_> {
    fn u64_at(&self, at: usize) -> u64 {
        u64::from_le_bytes(self.obj.read(at, 8).try_into().unwrap_or_default())
    }

    fn u32_at(&self, at: usize) -> u32 {
        u32::from_le_bytes(self.obj.read(at, 4).try_into().unwrap_or_default())
    }

    /// `open(name, Some(capacity))` of 128-byte slots, or `open_existing`
    /// (`None`), over the object as it stands.
    fn expect_open(&self, have: u64, asked: Option<u64>) -> Expect {
        let bytes_for = |capacity: u64, stride: usize| {
            capacity
                .checked_mul(stride as u64)
                .and_then(|n| n.checked_add(HEADER as u64))
                .filter(|&n| usize::try_from(n).is_ok())
        };
        if asked == Some(0) {
            // A ring of no slots is refused before anything is opened.
            return Expect::NoSlots;
        }
        if let Some(capacity) = asked {
            // `open` maps what the caller asked for, after the size check.
            let need = bytes_for(capacity, PULSE_SIZE).unwrap_or(u64::MAX);
            if have < need || bytes_for(capacity, PULSE_SIZE).is_none() {
                return Expect::TooSmall { have, need };
            }
        } else if have < HEADER as u64 {
            return Expect::TooSmall {
                have,
                need: HEADER as u64,
            };
        }
        let recorded = self.u64_at(H_CAPACITY);
        let stride = self.u32_at(H_SLOT_SIZE);
        let mut wrong = Vec::new();
        let mut check = |field, found: u64, needed: u64| {
            if found != needed {
                wrong.push((field, found, needed));
            }
        };
        check("magic", u64::from(self.u32_at(H_MAGIC)), u64::from(MAGIC));
        check(
            "version",
            u64::from(self.u32_at(H_VERSION)),
            u64::from(LAYOUT_VERSION),
        );
        match asked {
            Some(capacity) => {
                check("capacity", recorded, capacity);
                check("slot_size", u64::from(stride), PULSE_SIZE as u64);
            }
            None => {
                if stride as usize != PULSE_SIZE && stride as usize != PULSE_SIZE_V2 {
                    check("slot_size", u64::from(stride), PULSE_SIZE as u64);
                }
                if recorded == 0 {
                    check("capacity", 0, 1);
                }
            }
        }
        if !wrong.is_empty() {
            return Expect::Mismatch(wrong);
        }
        match asked {
            Some(capacity) => Expect::Opens {
                capacity,
                stride: PULSE_SIZE,
            },
            None => match bytes_for(recorded, stride as usize) {
                Some(need) if need <= have => Expect::Opens {
                    capacity: recorded,
                    stride: stride as usize,
                },
                need => Expect::TooSmall {
                    have,
                    need: need.unwrap_or(u64::MAX),
                },
            },
        }
    }

    fn slot(&self, geometry: &Geometry, position: u64) -> (u64, Vec<u8>) {
        let index = (position % geometry.capacity) as usize;
        let base = HEADER + index * geometry.stride;
        (self.u64_at(base), self.obj.read(base, PULSE_SIZE))
    }

    /// A stable copy of the slot: its 128 bytes when its counter is even
    /// and not zero.
    fn read_slot(&self, geometry: &Geometry, position: u64) -> Option<Vec<u8>> {
        let (counter, bytes) = self.slot(geometry, position);
        (counter % 2 == 0 && counter != 0).then_some(bytes)
    }
}

/// The documented rule of `read_position`: the slot's counter, read first,
/// below the count its lap's write leaves says the position is not written
/// yet, whatever the cursor says (a cursor ahead of its slots, which no
/// writer under the single-writer contract leaves, reads so until the
/// writer laps them); otherwise the cursor found before the copy (`head`)
/// decides whether the position was written and is still held; `copy` is
/// the slot the copy read; the cursor found after it (`after`) decides
/// whether the slot may hold a later lap. Unraced, all three are the region
/// as it stands.
fn position_rule(
    head: &View<'_>,
    copy: &View<'_>,
    after: &View<'_>,
    geometry: &Geometry,
    position: u64,
) -> Position {
    // The count a slot shows once its lap's write is done, wrapping as the
    // writer's increments do.
    let lap_counter = (position / geometry.capacity)
        .wrapping_add(1)
        .wrapping_mul(2);
    if head.slot(geometry, position).0 < lap_counter {
        return Position::NotWritten;
    }
    let head = head.u64_at(H_CURSOR);
    if position >= head {
        return Position::NotWritten;
    }
    let oldest = head.saturating_sub(geometry.capacity);
    if position < oldest {
        return Position::Lost(oldest);
    }
    let Some(bytes) = copy.read_slot(geometry, position) else {
        return Position::Lost(position + 1);
    };
    let counter = copy.slot(geometry, position).0;
    // More than a capacity behind the cursor, the slot has been written
    // again; exactly a capacity behind, the counter says whether it has
    // taken more writes than the lap `position` is on: at most
    // `position / capacity + 1` for that lap.
    let ahead = after.u64_at(H_CURSOR).saturating_sub(position);
    let later_lap = ahead > geometry.capacity
        || (ahead == geometry.capacity && counter / 2 > position / geometry.capacity + 1);
    if later_lap {
        Position::Lost(position + 1)
    } else {
        Position::Pulse(bytes)
    }
}

/// What `read_position` should return.
#[derive(Debug, PartialEq, Eq)]
enum Position {
    NotWritten,
    Lost(u64),
    Pulse(Vec<u8>),
}

/// What `read_position` returned, as the oracle states it.
fn position(got: &PositionRead) -> Position {
    match got {
        PositionRead::NotWritten => Position::NotWritten,
        PositionRead::Lost { next } => Position::Lost(*next),
        PositionRead::Pulse(p) => Position::Pulse(p.as_bytes().to_vec()),
    }
}

/// The `i`-th of `pulses`, published from the cursor and count `before`:
/// its slot holds it, the cursor and count moved past the batch, and its
/// position reads back as it or as lost.
fn check_published(
    ring: &PulseRing,
    view: &View<'_>,
    geometry: &Geometry,
    before: (u64, u64),
    pulses: &[Pulse],
    number: u64,
    i: usize,
) {
    let n = pulses.len() as u64;
    let position = before.0.wrapping_add(i as u64);
    assert_eq!(
        view.u64_at(H_CURSOR),
        before.0.wrapping_add(n),
        "the cursor moved by another count"
    );
    assert_eq!(
        view.u64_at(H_TOTAL),
        before.1.wrapping_add(n),
        "the write count moved by another count"
    );
    if n > 0 {
        assert_eq!(
            number,
            before.1.wrapping_add(n),
            "the write number is not the count"
        );
    }
    // A later pulse of the batch takes the same slot only where the cursor
    // wraps at u64::MAX, which only a header written by hand reaches: the
    // positions either side of the wrap need not be a capacity apart.
    let later = (i + 1..pulses.len()).any(|j| {
        position.wrapping_add((j - i) as u64) % geometry.capacity == position % geometry.capacity
    });
    if later {
        return;
    }
    let (counter, bytes) = view.slot(geometry, position);
    assert_eq!(counter % 2, 0, "a published slot's counter is odd");
    assert_eq!(
        &bytes[8..],
        &pulses[i].as_bytes()[8..],
        "the slot holds another pulse"
    );
    match ring.read_position(position) {
        PositionRead::Pulse(p) => {
            assert_eq!(
                &p.as_bytes()[8..],
                &pulses[i].as_bytes()[8..],
                "read back as another pulse"
            );
        }
        PositionRead::Lost { .. } | PositionRead::NotWritten => {}
    }
}

/// A position near the cursor, or anywhere.
fn pick_position(u: &mut Unstructured<'_>, view: &View<'_>) -> Result<u64> {
    let head = view.u64_at(H_CURSOR);
    Ok(match u.int_in_range(0..=3u8)? {
        0 => u.arbitrary()?,
        _ => head.wrapping_add_signed(u.int_in_range(-(2 * MAX_CAPACITY as i64 + 2)..=1)?),
    })
}

/// A pulse whose bytes after the counter come from the input.
fn pulse(u: &mut Unstructured<'_>) -> Result<Pulse> {
    let mut bytes = [0u8; PULSE_SIZE];
    let fill = u.bytes((PULSE_SIZE - 8).min(u.len()))?;
    bytes[8..8 + fill.len()].copy_from_slice(fill);
    Ok(Pulse::from_bytes(&bytes).unwrap_or_else(Pulse::zeroed))
}
