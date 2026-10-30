// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! In-order reads that never return a later lap's pulse under an earlier
//! position: [`PulseRing::read_position`].

use pulse_canon::Pulse;

use crate::PulseRing;
use std::sync::atomic::Ordering;

/// What [`PulseRing::read_position`] found at one write position.
/// Exhaustive by construction, so not `non_exhaustive`.
#[derive(Debug)]
pub enum PositionRead {
    /// The pulse written at the position. The next position to read is the
    /// one after it.
    Pulse(Pulse),
    /// The writer has not written the position yet.
    NotWritten,
    /// The position is lost to this reader, and so is every position after
    /// it up to `next`: the writer has refilled their slots, or may have,
    /// before they were read.
    Lost {
        /// The position to read next. `next` minus the position asked for
        /// is the number of positions lost.
        next: u64,
    },
}

impl PulseRing {
    /// Read the pulse written at `position` (the write cursor's value when
    /// it was written, one less than its write number), for a reader that
    /// walks the positions in order: each comes back once, as itself, or is
    /// reported lost, never as another position's pulse. What the method
    /// cannot settle is a loss, never a duplicate. This rests on the ring's
    /// single-writer contract (`tests/read_position.rs`,
    /// `tests/batch_publish.rs`). A region whose cursor runs ahead of its
    /// slots, which no writer under that contract leaves, reads as not
    /// written at those positions until the writer laps them: the slot's own
    /// counter is read first, so that a reader in step with the writer reads
    /// the header's cursor once per message rather than on every poll.
    pub fn read_position(&self, position: u64) -> PositionRead {
        // The slot's own counter first: it starts at zero and each completed
        // write adds two, so below `expected` this lap's write has not
        // completed (an odd `expected - 1` is that write in progress), and
        // the header's write cursor, which the writer updates after every
        // publish, is read only once the slot shows the write. A reader in
        // step with the writer then touches the writer's line once per
        // message instead of on every poll, which on a mesh part is most of
        // what a message costs.
        if self.slot_seq_atomic(position).load(Ordering::Acquire) < self.lap_counter(position) {
            return PositionRead::NotWritten;
        }
        let head = self.cursor_position();
        if position >= head {
            return PositionRead::NotWritten;
        }
        // More than a capacity behind: overwritten, with every position up
        // to the oldest the ring holds.
        let oldest = oldest_held(head, self.capacity);
        if position < oldest {
            return PositionRead::Lost { next: oldest };
        }
        let lost = PositionRead::Lost { next: position + 1 };
        // No stable copy within the budget: the next lap is being written,
        // or its writer died mid-write.
        let Some(pulse) = self.read_slot(position) else {
            return lost;
        };
        // The copy's counter is the slot's: `read_slot` keeps a copy only
        // when the counter was even and unchanged across it.
        let seq = pulse.seq_lock();
        if lapped(position, self.cursor_position(), self.capacity, seq) {
            lost
        } else {
            PositionRead::Pulse(pulse)
        }
    }
}

impl PulseRing {
    /// [`PulseRing::read_position`] for a ring written only through its
    /// cursor ([`PulseRing::publish`], [`PulseRing::publish_blocking`] and
    /// the batch forms), never [`PulseRing::publish_at_slot`]: it trusts
    /// the slot's counter alone and reads a position the moment its write
    /// completes, without the header's write cursor, so a reader in step
    /// with the writer shares no cache line the writer updates per message.
    /// Where `publish_at_slot` is in use, a counter run ahead could return
    /// that slot's pulse for a position not yet written; such a ring reads
    /// with `read_position`.
    pub fn read_position_by_counter(&self, position: u64) -> PositionRead {
        let expected = self.lap_counter(position);
        let seq = self.slot_seq_atomic(position).load(Ordering::Acquire);
        if seq < expected {
            return PositionRead::NotWritten;
        }
        if seq > expected {
            return self.lost_at(position);
        }
        // `read_slot` keeps a copy only when the counter was even and
        // unchanged across it, so a copy showing `expected` is this
        // position's pulse whatever the writer has done since.
        match self.read_slot(position) {
            Some(pulse) if pulse.seq_lock() == expected => PositionRead::Pulse(pulse),
            _ => self.lost_at(position),
        }
    }

    /// [`PulseRing::read_position_by_counter`] for a version-2 ring, watching
    /// the slot's ready line instead of its counter: the writer stores the
    /// ready line once per write, after the slot is stable, so a reader
    /// waiting on it never touches the slot's two lines while the writer is
    /// still storing them. On a version-1 ring it is
    /// `read_position_by_counter`. The same contract: a ring written only
    /// through its cursor.
    pub fn read_position_by_ready(&self, position: u64) -> PositionRead {
        let Some(ready) = self.ready_line_atomic(position) else {
            return self.read_position_by_counter(position);
        };
        // One increment per completed write of the slot, so after the write
        // for `position`'s lap it shows the lap's number, counted from one.
        // Wrapping, as the writer's increments of the ready line are.
        let lap = (position / self.capacity).wrapping_add(1);
        let shown = ready.load(Ordering::Acquire);
        if shown < lap {
            return PositionRead::NotWritten;
        }
        if shown > lap {
            return self.lost_at(position);
        }
        let expected = self.lap_counter(position);
        match self.read_slot(position) {
            Some(pulse) if pulse.seq_lock() == expected => PositionRead::Pulse(pulse),
            _ => self.lost_at(position),
        }
    }

    /// The counter a slot shows once the write for `position`'s lap is done.
    /// Wrapping, as the writer's `wrapping_add(2)` on the counter is: a
    /// position a caller or a bent header puts past `u64::MAX / 2` laps of a
    /// small ring compares unequal and reads as not written or lost, where a
    /// plain product would overflow.
    #[inline(always)]
    fn lap_counter(&self, position: u64) -> u64 {
        (position / self.capacity).wrapping_add(1).wrapping_mul(2)
    }

    /// `position` is lost: the next to read is the oldest the ring still
    /// holds, or the one after `position` if the cursor is not past it yet.
    #[cold]
    fn lost_at(&self, position: u64) -> PositionRead {
        let oldest = oldest_held(self.cursor_position(), self.capacity);
        PositionRead::Lost {
            next: oldest.max(position.saturating_add(1)),
        }
    }
}

/// The oldest position a ring of `capacity` slots still holds when its
/// write cursor is `head`.
fn oldest_held(head: u64, capacity: u64) -> u64 {
    head.saturating_sub(capacity)
}

/// Whether a stable copy of the slot for `position`, whose counter read
/// `seq`, may hold a later lap than `position`'s, given the write cursor
/// `head` loaded after the copy.
///
/// A cursor more than a capacity ahead proves it. Exactly a capacity ahead,
/// the writer may have refilled the slot and not yet moved the cursor, so
/// the counter decides: it starts at zero and each completed write adds
/// two, so the slot holding lap `position / capacity` has taken at least
/// that lap plus one writes, and a counter showing more may be the next
/// lap's. The counter never falls behind the laps (the write after a dead
/// writer's odd mark re-bases it, at the same position). It runs ahead
/// after `publish_at_slot`, or when a writer dies between a slot write and
/// its cursor move; an ahead counter costs a good copy, never a duplicate.
fn lapped(position: u64, head: u64, capacity: u64, seq: u64) -> bool {
    let ahead = head.saturating_sub(position);
    // `ahead == capacity >= 1` puts `position` below `u64::MAX`, so the sum
    // cannot overflow.
    ahead > capacity || (ahead == capacity && seq / 2 > position / capacity + 1)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use std::sync::atomic::Ordering;
    use std::sync::Barrier;

    /// A ring name no other test or concurrent run can share.
    fn name(tag: &str) -> String {
        format!("/ovr-{tag}-{:x}", std::process::id())
    }

    /// A Data pulse carrying `mark` in its chain step.
    fn marked(mark: u64) -> Pulse {
        let mut pulse = Pulse::zeroed();
        pulse.instruction = pulse_canon::Instruction::Data as u16;
        pulse.chain_step = mark;
        pulse
    }

    /// The mark of the pulse a read returned, or `None` for any other
    /// outcome.
    fn mark(read: PositionRead) -> Option<u64> {
        match read {
            PositionRead::Pulse(pulse) => Some(pulse.chain_step),
            _ => None,
        }
    }

    #[test]
    fn below_the_boundary_the_counter_is_not_consulted() {
        assert!(!lapped(4, 11, 8, u64::MAX));
        assert!(!lapped(4, 5, 8, u64::MAX));
    }

    #[test]
    fn a_cursor_more_than_a_capacity_ahead_voids_the_copy() {
        assert!(lapped(0, 9, 8, 0));
        assert!(lapped(12, 30, 8, 4));
    }

    #[test]
    fn at_exactly_a_capacity_the_counter_decides() {
        // Position 12 is lap 1 of a capacity-8 ring: its slot has taken the
        // writes of positions 4 and 12, so its counter is 4.
        assert!(!lapped(12, 20, 8, 4));
        // Position 20 written, the cursor not yet moved to 21.
        assert!(lapped(12, 20, 8, 6));
        // Lap 0 of a full ring, and the same slot refilled by lap 1.
        assert!(!lapped(0, 8, 8, 2));
        assert!(lapped(0, 8, 8, 4));
        // A one-slot ring: every position is exactly a capacity behind.
        assert!(!lapped(5, 6, 1, 12));
        assert!(lapped(5, 6, 1, 14));
    }

    #[test]
    fn the_oldest_position_held_trails_the_cursor_by_the_capacity() {
        assert_eq!(oldest_held(3, 8), 0);
        assert_eq!(oldest_held(8, 8), 0);
        assert_eq!(oldest_held(20, 8), 12);
    }

    #[test]
    fn a_lapped_reader_resumes_at_the_oldest_position_held() {
        let mut ring = PulseRing::create(&name("lap"), 8).expect("ring");
        for m in 0..20 {
            ring.publish(&marked(m));
        }
        assert!(matches!(
            ring.read_position(0),
            PositionRead::Lost { next: 12 }
        ));
        for position in 12..20 {
            assert_eq!(mark(ring.read_position(position)), Some(position));
        }
        assert!(matches!(ring.read_position(20), PositionRead::NotWritten));
    }

    #[test]
    fn a_full_ring_still_returns_its_oldest_position() {
        let mut ring = PulseRing::create(&name("full"), 8).expect("ring");
        for m in 0..8 {
            ring.publish(&marked(m));
        }
        for position in 0..8 {
            assert_eq!(mark(ring.read_position(position)), Some(position));
        }
    }

    #[test]
    fn a_writer_paused_between_its_slot_write_and_its_cursor_move_is_not_read_early() {
        let ring_name = name("pause");
        let mut ring = PulseRing::create(&ring_name, 8).expect("ring");
        for m in 0..8 {
            ring.publish(&marked(m));
        }
        // The reader's own handle: the writer's is borrowed by its thread.
        let reader = PulseRing::open(&ring_name, 8).expect("reader");
        let barrier = Barrier::new(2);
        // The reads the reader makes while the writer is paused, checked
        // once the writer has finished so a failure cannot strand it.
        let paused = std::thread::scope(|s| {
            s.spawn(|| {
                // The first half of publishing position 8: its slot, which
                // held position 0, is refilled under the SeqLock, and the
                // cursor still says 8.
                ring.publish_at_slot(8, &marked(8));
                barrier.wait();
                // Paused here while the reader reads.
                barrier.wait();
                // The second half: the counters move.
                ring.total_writes().fetch_add(1, Ordering::Release);
                ring.write_cursor().fetch_add(1, Ordering::Release);
            });
            barrier.wait();
            let reads: Vec<PositionRead> = (0..9).map(|p| reader.read_position(p)).collect();
            barrier.wait();
            reads
        });
        let mut paused = paused.into_iter();
        assert!(
            matches!(paused.next(), Some(PositionRead::Lost { next: 1 })),
            "position 0's slot holds position 8's pulse"
        );
        for position in 1..8 {
            assert_eq!(paused.next().and_then(mark), Some(position));
        }
        assert!(matches!(paused.next(), Some(PositionRead::NotWritten)));
        assert_eq!(mark(ring.read_position(8)), Some(8));
    }

    #[test]
    fn a_writer_that_died_mid_write_costs_the_position_it_was_refilling() {
        let mut ring = PulseRing::create(&name("died"), 8).expect("ring");
        for m in 0..8 {
            ring.publish(&marked(m));
        }
        // The writer of position 8 dies after its odd mark on slot 0.
        ring.slot_seq_atomic(0).fetch_or(1, Ordering::AcqRel);
        assert!(matches!(
            ring.read_position(0),
            PositionRead::Lost { next: 1 }
        ));
        // Its successor finds the cursor still at 8, writes position 8 and
        // re-bases the odd counter: slot 0 counts two writes for its two
        // positions, so the counter does not fall behind the laps.
        for m in 8..16 {
            ring.publish(&marked(m));
        }
        assert_eq!(ring.slot_seq_atomic(0).load(Ordering::Acquire), 4);
        for position in 8..16 {
            assert_eq!(mark(ring.read_position(position)), Some(position));
        }
    }

    #[test]
    fn a_counter_ahead_of_its_laps_costs_a_good_copy_never_a_duplicate() {
        let mut ring = PulseRing::create(&name("ahead"), 8).expect("ring");
        for m in 0..8 {
            ring.publish(&marked(m));
        }
        // The writer of position 8 dies after its slot write and before its
        // cursor move; its successor writes position 8 again.
        ring.publish_at_slot(8, &marked(999));
        ring.publish(&marked(8));
        assert_eq!(mark(ring.read_position(8)), Some(8));
        for m in 9..16 {
            ring.publish(&marked(m));
        }
        // Slot 0 has taken three writes for two positions. Exactly a
        // capacity behind, the reader cannot tell position 8 from a later
        // lap and gives it up.
        assert!(matches!(
            ring.read_position(8),
            PositionRead::Lost { next: 9 }
        ));
        for position in 9..16 {
            assert_eq!(mark(ring.read_position(position)), Some(position));
        }
    }
}
