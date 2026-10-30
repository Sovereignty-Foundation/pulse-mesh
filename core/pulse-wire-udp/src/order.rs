// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! Delivery options, opt-in: duplicate suppression and in-order delivery.
//!
//! The receiver delivers every frame that decodes, as it arrives: with NACK
//! or FEC on a sequence number can arrive twice, and frames come in the
//! order the network gives them. A [`Sequencer`] between the intake and the
//! caller changes that, in one of two modes:
//!
//! - [`Order::Unique`]: each sequence number is delivered once, in arrival
//!   order. A frame whose numbers were delivered within the window is
//!   dropped as a duplicate.
//! - [`Order::InOrder`]: frames are delivered in sequence order, each once.
//!   A frame ahead of a gap is held until the gap fills (by the wire, a
//!   retransmission or FEC), and no longer than
//!   [`DeliveryConfig::gap_timeout`] from its own arrival: then the gaps
//!   before it are skipped. Gaps are skipped sooner when a frame arrives
//!   that starts more than the window past the next number expected, or
//!   when the held frames pass [`DeliveryConfig::max_held_bytes`]. A frame
//!   that arrives behind the next number expected is dropped: as a
//!   duplicate when it was delivered, as late when its gap was skipped.
//!
//! A run of fragments, reassembled, occupies its whole span of sequence
//! numbers. The order starts at [`DeliveryConfig::first`] when the caller
//! knows the stream's first number (a [`crate::Sender`] numbers from 0).
//! Otherwise unique starts at the first frame, and in order at the lowest
//! number that arrives within the gap timeout of the first frame, which is
//! held that long, once, so that a frame that overtakes the stream's first
//! does not leave it behind the order. A frame more than a window behind is
//! dropped as late, unless a second one arrives within a window of it: the
//! sender has restarted its numbering, and the order starts again there, as
//! the stream tracking confirms a jump.

use std::collections::{BTreeMap, VecDeque};
use std::time::{Duration, Instant};

/// The widest window: the sequence numbers a [`Sequencer`] remembers.
pub const MAX_ORDER_WINDOW: u64 = 1 << 16;

/// The default window: as many numbers as the default send cache holds,
/// so a frame NACK can still bring back is within it.
pub const DEFAULT_ORDER_WINDOW: u64 = crate::backpressure::DEFAULT_SEND_CACHE_CAPACITY as u64;

/// The default gap timeout: above the 12 ms NACK takes to give up on a
/// frame at the default ACK period ([`crate::MAX_NACK_ATTEMPTS`] requests,
/// [`crate::NACK_RETRY_PERIODS`] periods apart).
pub const DEFAULT_GAP_TIMEOUT: Duration = Duration::from_millis(20);

/// What a [`Sequencer`] guarantees.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Order {
    /// Each sequence number once, in arrival order.
    Unique,
    /// Each sequence number once, in sequence order, gaps skipped when they
    /// hold delivery back too long.
    InOrder,
}

/// A [`Sequencer`]'s mode and bounds.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeliveryConfig {
    /// The guarantee.
    pub order: Order,
    /// Sequence numbers the order covers: how far back a delivered number
    /// is remembered, and, in order, how far ahead of the next number
    /// expected a frame may be held. Taken within 1 to
    /// [`MAX_ORDER_WINDOW`]; default [`DEFAULT_ORDER_WINDOW`].
    pub window: u64,
    /// In order, the longest a frame is held ahead of a gap, from its
    /// arrival; then the gaps before it are skipped. Default
    /// [`DEFAULT_GAP_TIMEOUT`].
    pub gap_timeout: Duration,
    /// In order, the most envelope bytes held ahead of a gap; past it the
    /// gap is skipped. Default 4 MiB.
    pub max_held_bytes: usize,
    /// The stream's first sequence number, when the caller knows it: the
    /// order starts there, and in order holds nothing at the start. `None`
    /// (the default) starts it from what arrives.
    pub first: Option<u64>,
}

impl DeliveryConfig {
    /// Each sequence number once, in arrival order, with the default
    /// window.
    #[must_use]
    pub fn unique() -> Self {
        Self {
            order: Order::Unique,
            ..Self::in_order()
        }
    }

    /// Each sequence number once, in sequence order, with the default
    /// bounds.
    #[must_use]
    pub fn in_order() -> Self {
        Self {
            order: Order::InOrder,
            window: DEFAULT_ORDER_WINDOW,
            gap_timeout: DEFAULT_GAP_TIMEOUT,
            max_held_bytes: 4 << 20,
            first: None,
        }
    }

    /// The same options, the order starting at `first`
    /// ([`Self::first`]).
    #[must_use]
    pub fn starting_at(mut self, first: u64) -> Self {
        self.first = Some(first);
        self
    }
}

/// A frame held ahead of a gap.
struct Held<T> {
    /// One past its last sequence number.
    end: u128,
    bytes: usize,
    arrived: Instant,
    item: T,
}

/// Puts frames in the order its [`DeliveryConfig`] asks for: frames go in
/// with [`Self::push`], in arrival order, and come out with [`Self::pop`].
///
/// Sequence numbers are counted in `u128` inside, so a span that ends past
/// `u64::MAX` needs no special case.
pub struct Sequencer<T> {
    order: Order,
    window: u128,
    gap_timeout: Duration,
    max_held_bytes: usize,
    /// In order, the next number expected; unique, one past the highest
    /// delivered. `None` before the first frame.
    next: Option<u128>,
    /// Which numbers below `next`, within the window, were delivered: bit
    /// `n % (64 * seen.len())`.
    seen: Vec<u64>,
    /// In order, the frames held ahead of a gap, by first number.
    held: BTreeMap<u128, Held<T>>,
    held_bytes: usize,
    /// In order, the held frames' arrivals, oldest first, by first number;
    /// an entry whose frame has left `held` is dropped on reaching the
    /// front.
    arrivals: VecDeque<(Instant, u128)>,
    ready: VecDeque<T>,
    /// A frame far behind, taken for a restart once a second confirms it.
    restart: Option<u128>,
    delivered: u64,
    duplicates: u64,
    late: u64,
    skipped: u64,
    resyncs: u64,
}

impl<T> Sequencer<T> {
    /// A sequencer holding nothing yet.
    #[must_use]
    pub fn new(cfg: &DeliveryConfig) -> Self {
        let window = cfg.window.clamp(1, MAX_ORDER_WINDOW);
        Self {
            order: cfg.order,
            window: u128::from(window),
            gap_timeout: cfg.gap_timeout,
            max_held_bytes: cfg.max_held_bytes,
            next: cfg.first.map(u128::from),
            seen: vec![0; window.div_ceil(64) as usize],
            held: BTreeMap::new(),
            held_bytes: 0,
            arrivals: VecDeque::new(),
            ready: VecDeque::new(),
            restart: None,
            delivered: 0,
            duplicates: 0,
            late: 0,
            skipped: 0,
            resyncs: 0,
        }
    }

    /// Take a frame that arrived at `now`: `item`, numbered `seq` and
    /// spanning `span` numbers (a frame one, a run of fragments its count),
    /// carrying `bytes` of envelope. It is delivered, held, or dropped and
    /// counted; first, a gap that has held delivery back past the timeout is
    /// skipped, as [`Self::poll`] does.
    pub fn push(&mut self, seq: u64, span: u64, bytes: usize, item: T, now: Instant) {
        self.poll(now);
        let seq = u128::from(seq);
        let end = seq + u128::from(span.max(1));
        let Some(next) = self.next else {
            match self.order {
                Order::Unique => {
                    self.advance(end);
                    self.deliver(seq, end, item);
                }
                Order::InOrder => self.hold(seq, end, bytes, item, now),
            }
            return;
        };
        if seq + self.window < next {
            self.far_behind(seq, end, item);
            return;
        }
        self.restart = None;
        match self.order {
            Order::Unique => self.push_unique(seq, end, item),
            Order::InOrder => self.push_in_order(seq, end, bytes, item, now),
        }
    }

    /// Release, at `now`, every frame held past the timeout, skipping the
    /// gaps before it.
    pub fn poll(&mut self, now: Instant) {
        loop {
            self.tidy();
            let Some(&(arrived, seq)) = self.arrivals.front() else {
                return;
            };
            if now.saturating_duration_since(arrived) < self.gap_timeout {
                return;
            }
            if self.next.is_none() {
                self.start();
            } else {
                self.skip_to(seq);
            }
        }
    }

    /// Deliver every frame held, in order, skipping the gaps between them.
    pub fn release_all(&mut self) {
        self.flush();
    }

    /// The guarantee this sequencer gives.
    pub fn order(&self) -> Order {
        self.order
    }

    /// The next frame to deliver.
    pub fn pop(&mut self) -> Option<T> {
        self.ready.pop_front()
    }

    /// Frames ready to deliver.
    pub fn ready_count(&self) -> usize {
        self.ready.len()
    }

    /// When the oldest frame held reaches the timeout, if one is held: a
    /// receive call waits no longer than this before calling [`Self::poll`].
    pub fn deadline(&self) -> Option<Instant> {
        self.arrivals
            .iter()
            .find(|&&(arrived, seq)| self.is_held(arrived, seq))
            .map(|&(arrived, _)| arrived + self.gap_timeout)
    }

    /// Frames held ahead of a gap.
    pub fn held_count(&self) -> usize {
        self.held.len()
    }

    /// Envelope bytes held ahead of a gap.
    pub fn held_bytes(&self) -> usize {
        self.held_bytes
    }

    /// Frames delivered, ready or taken.
    pub fn delivered_count(&self) -> u64 {
        self.delivered
    }

    /// Frames dropped because their numbers were delivered already.
    pub fn duplicate_count(&self) -> u64 {
        self.duplicates
    }

    /// Frames dropped because they arrived behind the order: after their
    /// gap was skipped, or more than a window behind.
    pub fn late_count(&self) -> u64 {
        self.late
    }

    /// Sequence numbers skipped over in gaps that did not fill in time;
    /// it stops at `u64::MAX`.
    pub fn skipped_count(&self) -> u64 {
        self.skipped
    }

    /// Times the order started again after the sender restarted its
    /// numbering.
    pub fn resync_count(&self) -> u64 {
        self.resyncs
    }

    fn push_unique(&mut self, seq: u128, end: u128, item: T) {
        let next = self.next.unwrap_or(seq);
        if seq < next && self.any_seen(seq, end.min(next)) {
            self.duplicates += 1;
            return;
        }
        if end > next {
            self.advance(end);
        }
        self.deliver(seq, end, item);
    }

    fn push_in_order(&mut self, seq: u128, end: u128, bytes: usize, item: T, now: Instant) {
        let next = self.next.unwrap_or(seq);
        if seq < next {
            self.drop_behind(seq, end.min(next));
            return;
        }
        // Starting past the window, it moves the window up to it, and the
        // gaps it leaves behind are skipped. A run longer than the window
        // is held, or delivered, whole.
        if seq - next > self.window {
            self.skip_to(seq - self.window);
        }
        if self.next == Some(seq) {
            self.advance(end);
            self.deliver(seq, end, item);
            self.release();
            return;
        }
        if self.next.is_some_and(|n| seq < n) {
            self.drop_behind(seq, end);
            return;
        }
        self.hold(seq, end, bytes, item, now);
    }

    /// Hold a frame ahead of the order, or of its start, keeping the held
    /// frames within the bounds.
    fn hold(&mut self, seq: u128, end: u128, bytes: usize, item: T, now: Instant) {
        if self.held.contains_key(&seq) {
            self.duplicates += 1;
            return;
        }
        self.held.insert(
            seq,
            Held {
                end,
                bytes,
                arrived: now,
                item,
            },
        );
        self.arrivals.push_back((now, seq));
        self.held_bytes += bytes;
        while self.held_bytes > self.max_held_bytes {
            let Some(&first) = self.held.keys().next() else {
                break;
            };
            if self.next.is_none() {
                self.start();
            } else {
                self.skip_to(first);
            }
        }
        if self.next.is_none() && self.held.len() as u128 > self.window {
            self.start();
        }
    }

    /// Start the order at the lowest number held, delivering from there;
    /// frames held more than the window past it move the window up, as one
    /// arriving there would.
    fn start(&mut self) {
        if self.next.is_none() {
            if let Some(&first) = self.held.keys().next() {
                self.advance(first);
            }
        }
        self.release();
        if let (Some(next), Some(&last)) = (self.next, self.held.keys().next_back()) {
            if last - next > self.window {
                self.skip_to(last - self.window);
            }
        }
    }

    /// A frame more than a window behind: late, or the first of a
    /// restarted numbering, which a second within a window of it confirms.
    fn far_behind(&mut self, seq: u128, end: u128, item: T) {
        match self.restart {
            Some(first) if first != seq && first.abs_diff(seq) <= self.window => {
                self.resyncs += 1;
                self.flush();
                self.next = None;
                self.restart = None;
                self.seen.fill(0);
                self.advance(end);
                self.deliver(seq, end, item);
            }
            _ => {
                self.restart = Some(seq);
                self.late += 1;
            }
        }
    }

    /// A frame at least partly behind the next number expected, in order.
    fn drop_behind(&mut self, seq: u128, end: u128) {
        if self.any_seen(seq, end) {
            self.duplicates += 1;
        } else {
            self.late += 1;
        }
    }

    /// Move the order on to `target`, skipping the gaps on the way and
    /// releasing the frames held there.
    fn skip_to(&mut self, target: u128) {
        while let Some(next) = self.next.filter(|&n| n < target) {
            // The gap at `next` runs to the first frame held, or to the
            // target; a frame held at `next` is released instead.
            let gap_end = self
                .held
                .keys()
                .next()
                .map_or(target, |&first| first.clamp(next, target));
            if gap_end > next {
                let gap = u64::try_from(gap_end - next).unwrap_or(u64::MAX);
                self.skipped = self.skipped.saturating_add(gap);
                self.advance(gap_end);
            }
            self.release();
        }
        self.release();
    }

    /// Deliver the held frames that the order has reached, dropping those
    /// it has passed.
    fn release(&mut self) {
        while let Some(entry) = self.held.first_entry() {
            let next = self.next.unwrap_or(*entry.key());
            let seq = *entry.key();
            if seq > next {
                break;
            }
            let held = entry.remove();
            self.held_bytes -= held.bytes;
            if seq < next {
                self.drop_behind(seq, held.end.min(next));
                continue;
            }
            self.advance(held.end);
            self.deliver(seq, held.end, held.item);
        }
        self.tidy();
    }

    /// True while the frame that arrived at `arrived` as `seq` is held.
    fn is_held(&self, arrived: Instant, seq: u128) -> bool {
        self.held.get(&seq).is_some_and(|h| h.arrived == arrived)
    }

    /// Drop the arrivals at the front whose frames are no longer held.
    fn tidy(&mut self) {
        while let Some(&(arrived, seq)) = self.arrivals.front() {
            if self.is_held(arrived, seq) {
                return;
            }
            self.arrivals.pop_front();
        }
        if self.held.is_empty() {
            self.arrivals.clear();
        }
    }

    /// Deliver every held frame in order, skipping the gaps between them,
    /// before the order starts again.
    fn flush(&mut self) {
        self.start();
        if let Some(last) = self.held.values().map(|h| h.end).max() {
            self.skip_to(last);
        }
    }

    /// Move `next` up to `to`, forgetting what the bits held for the
    /// numbers in between.
    fn advance(&mut self, to: u128) {
        let from = self.next.unwrap_or(to).min(to);
        let bits = 64 * self.seen.len() as u128;
        if to - from >= bits {
            self.seen.fill(0);
        } else {
            for n in from..to {
                self.set_seen(n, false);
            }
        }
        self.next = Some(self.next.map_or(to, |n| n.max(to)));
    }

    fn deliver(&mut self, seq: u128, end: u128, item: T) {
        let bits = 64 * self.seen.len() as u128;
        for n in seq.max(end.saturating_sub(bits))..end {
            self.set_seen(n, true);
        }
        self.ready.push_back(item);
        self.delivered += 1;
    }

    fn any_seen(&self, seq: u128, end: u128) -> bool {
        let bits = 64 * self.seen.len() as u128;
        (seq.max(end.saturating_sub(bits))..end).any(|n| {
            let i = (n % bits) as usize;
            self.seen[i / 64] & (1 << (i % 64)) != 0
        })
    }

    fn set_seen(&mut self, n: u128, on: bool) {
        let i = (n % (64 * self.seen.len() as u128)) as usize;
        if on {
            self.seen[i / 64] |= 1 << (i % 64);
        } else {
            self.seen[i / 64] &= !(1 << (i % 64));
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn drain(s: &mut Sequencer<u64>) -> Vec<u64> {
        std::iter::from_fn(|| s.pop()).collect()
    }

    fn push_all(s: &mut Sequencer<u64>, seqs: &[u64], now: Instant) -> Vec<u64> {
        for &seq in seqs {
            s.push(seq, 1, 10, seq, now);
        }
        drain(s)
    }

    /// A sequencer started at `first`: unique delivers it at once, in order
    /// holds it for the gap timeout first. Returns the time it started.
    fn started(cfg: &DeliveryConfig, first: u64) -> (Sequencer<u64>, Instant) {
        let mut s = Sequencer::new(cfg);
        let t0 = Instant::now();
        let at_once = push_all(&mut s, &[first], t0);
        if cfg.order == Order::Unique {
            assert_eq!(at_once, vec![first]);
            return (s, t0);
        }
        assert_eq!(at_once, Vec::<u64>::new());
        let now = t0 + cfg.gap_timeout;
        s.poll(now);
        assert_eq!(drain(&mut s), vec![first]);
        (s, now)
    }

    #[test]
    fn unique_delivers_each_number_once_in_arrival_order() {
        let mut s = Sequencer::new(&DeliveryConfig::unique());
        let now = Instant::now();
        assert_eq!(
            push_all(&mut s, &[5, 7, 6, 7, 5, 8, 6], now),
            vec![5, 7, 6, 8]
        );
        assert_eq!((s.delivered_count(), s.duplicate_count()), (4, 3));
        assert_eq!(s.held_count(), 0, "unique holds nothing");
    }

    #[test]
    fn in_order_holds_frames_until_the_gap_fills() {
        let (mut s, now) = started(&DeliveryConfig::in_order(), 10);
        assert_eq!(push_all(&mut s, &[12, 13], now), Vec::<u64>::new());
        assert_eq!((s.held_count(), s.held_bytes()), (2, 20));
        assert!(s.deadline().is_some());
        assert_eq!(push_all(&mut s, &[11], now), vec![11, 12, 13]);
        assert_eq!(push_all(&mut s, &[12, 14], now), vec![14]);
        assert_eq!(
            (s.held_count(), s.duplicate_count(), s.late_count()),
            (0, 1, 0)
        );
        assert!(s.deadline().is_none());
    }

    #[test]
    fn a_gap_that_outlives_the_timeout_is_skipped_and_its_frame_is_late() {
        let cfg = DeliveryConfig::in_order();
        let (mut s, t0) = started(&cfg, 0);
        assert_eq!(push_all(&mut s, &[2, 3, 5], t0), Vec::<u64>::new());
        s.poll(t0 + cfg.gap_timeout / 2);
        assert!(drain(&mut s).is_empty(), "skipped before the timeout");
        assert_eq!(s.deadline(), Some(t0 + cfg.gap_timeout));
        let t1 = t0 + cfg.gap_timeout;
        s.poll(t1);
        // Every frame held since t0 is due: the gaps at 1 and 4 both go.
        assert_eq!(drain(&mut s), vec![2, 3, 5]);
        assert_eq!(s.skipped_count(), 2);
        assert_eq!(s.deadline(), None);
        // A frame held later waits its own timeout.
        assert_eq!(push_all(&mut s, &[8], t1), Vec::<u64>::new());
        s.poll(t1 + cfg.gap_timeout / 2);
        assert!(drain(&mut s).is_empty());
        s.poll(t1 + cfg.gap_timeout);
        assert_eq!(drain(&mut s), vec![8]);
        assert_eq!(push_all(&mut s, &[1, 3], t1), Vec::<u64>::new());
        assert_eq!((s.late_count(), s.duplicate_count()), (1, 1));
        assert_eq!(s.skipped_count(), 4);
    }

    #[test]
    fn a_frame_past_the_window_moves_it_on() {
        let mut cfg = DeliveryConfig::in_order();
        cfg.window = 8;
        let (mut s, now) = started(&cfg, 0);
        assert_eq!(push_all(&mut s, &[3, 5], now), Vec::<u64>::new());
        // 20 needs the window at 12: everything below goes.
        assert_eq!(push_all(&mut s, &[20], now), vec![3, 5]);
        assert_eq!(s.held_count(), 1);
        assert_eq!(s.skipped_count(), 2 + 1 + (12 - 6));
        assert_eq!(
            push_all(&mut s, &[12, 13, 14, 15, 16, 17, 18, 19], now),
            vec![12, 13, 14, 15, 16, 17, 18, 19, 20]
        );
        // A run longer than the window, next or held ahead, goes whole.
        s.push(21, 20, 1, 21, now);
        s.push(49, 1, 1, 49, now);
        s.push(41, 8, 1, 41, now);
        s.push(55, 20, 1, 55, now);
        s.push(50, 5, 1, 50, now);
        assert_eq!(drain(&mut s), vec![21, 41, 49, 50, 55]);
        assert_eq!(s.late_count(), 0);
    }

    #[test]
    fn the_byte_bound_skips_the_gap() {
        let mut cfg = DeliveryConfig::in_order();
        cfg.max_held_bytes = 25;
        let (mut s, now) = started(&cfg, 0);
        assert_eq!(push_all(&mut s, &[2, 3], now), Vec::<u64>::new());
        assert_eq!(push_all(&mut s, &[5], now), vec![2, 3]);
        assert_eq!((s.held_count(), s.held_bytes()), (1, 10));
    }

    #[test]
    fn a_run_occupies_its_span() {
        let (mut s, now) = started(&DeliveryConfig::in_order(), 99);
        s.push(100, 1, 1, 100, now);
        s.push(105, 1, 1, 105, now);
        s.push(101, 4, 4000, 101, now);
        assert_eq!(drain(&mut s), vec![100, 101, 105]);
        // The run again, completed from retransmitted fragments.
        s.push(101, 4, 4000, 101, now);
        assert_eq!(drain(&mut s), Vec::<u64>::new());
        assert_eq!(s.duplicate_count(), 1);

        let mut u = Sequencer::new(&DeliveryConfig::unique());
        u.push(7, 3, 1, 7, now);
        u.push(8, 1, 1, 8, now);
        u.push(10, 1, 1, 10, now);
        assert_eq!(drain(&mut u), vec![7, 10]);
    }

    #[test]
    fn a_sender_that_restarts_its_numbering_is_followed_after_two_frames() {
        let far = 1_000_000;
        for cfg in [DeliveryConfig::unique(), DeliveryConfig::in_order()] {
            let (mut s, now) = started(&cfg, far);
            assert_eq!(push_all(&mut s, &[far + 1], now), vec![far + 1]);
            assert_eq!(push_all(&mut s, &[0], now), Vec::<u64>::new());
            assert_eq!(push_all(&mut s, &[1, 2], now), vec![1, 2]);
            assert_eq!((s.resync_count(), s.late_count()), (1, 1));
        }
    }

    #[test]
    fn numbers_at_the_top_of_the_range_order_as_any_other() {
        let top = u64::MAX;
        let (mut s, now) = started(&DeliveryConfig::in_order(), top - 2);
        assert_eq!(push_all(&mut s, &[top, top - 1], now), vec![top - 1, top]);
        assert_eq!(push_all(&mut s, &[top], now), Vec::<u64>::new());
        assert_eq!(s.duplicate_count(), 1);
    }

    #[test]
    fn in_order_starts_at_the_lowest_number_of_its_first_timeout() {
        let cfg = DeliveryConfig::in_order();
        let mut s = Sequencer::new(&cfg);
        let t0 = Instant::now();
        assert_eq!(push_all(&mut s, &[5], t0), Vec::<u64>::new());
        let t1 = t0 + cfg.gap_timeout / 2;
        assert_eq!(push_all(&mut s, &[3, 4, 3], t1), Vec::<u64>::new());
        assert_eq!(s.deadline(), Some(t0 + cfg.gap_timeout));
        s.poll(t0 + cfg.gap_timeout);
        assert_eq!(drain(&mut s), vec![3, 4, 5]);
        assert_eq!(push_all(&mut s, &[2, 6], t1), vec![6]);
        assert_eq!((s.late_count(), s.duplicate_count()), (1, 1));
        // The bounds start it sooner: a window's worth of frames held.
        let mut cfg = DeliveryConfig::in_order();
        cfg.window = 2;
        let mut s = Sequencer::new(&cfg);
        assert_eq!(push_all(&mut s, &[9, 8, 7], t0), vec![7, 8, 9]);
        // Started with frames held past the window, it moves the window.
        let mut s = Sequencer::new(&cfg);
        // 20 moves it to 18, past 9, which goes out on the way.
        assert_eq!(push_all(&mut s, &[5, 9, 20], t0), vec![5, 9]);
        assert!(s.held_count() as u64 <= cfg.window);
        assert_eq!(push_all(&mut s, &[19], t0), Vec::<u64>::new());
        assert_eq!(push_all(&mut s, &[18], t0), vec![18, 19, 20]);
    }

    #[test]
    fn a_known_first_number_starts_the_order_without_a_wait() {
        let mut s = Sequencer::new(&DeliveryConfig::in_order().starting_at(40));
        let now = Instant::now();
        assert_eq!(push_all(&mut s, &[40, 42, 41], now), vec![40, 41, 42]);
        assert_eq!(push_all(&mut s, &[39], now), Vec::<u64>::new());
        assert_eq!(s.late_count(), 1);
    }

    #[test]
    fn a_window_out_of_range_is_taken_within_it() {
        let mut cfg = DeliveryConfig::unique();
        cfg.window = 0;
        let mut s = Sequencer::new(&cfg);
        let now = Instant::now();
        assert_eq!(push_all(&mut s, &[1, 1, 2], now), vec![1, 2]);
        cfg.window = u64::MAX;
        let s: Sequencer<u64> = Sequencer::new(&cfg);
        assert_eq!(s.seen.len() as u64, MAX_ORDER_WINDOW / 64);
    }
}
