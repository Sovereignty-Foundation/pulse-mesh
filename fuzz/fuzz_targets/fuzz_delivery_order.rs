// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//
// Fuzz target: `pulse_wire_udp::order::Sequencer`, the receiver's opt-in
// duplicate suppression and in-order delivery, over frames in any order,
// repeated, and with gaps, on a clock the input moves forward.
//
// The input picks the mode (unique or in order), the window (from one
// number up), the gap timeout (zero included), the bound on bytes held and
// whether the order is told the stream's first number, then a sequence of
// steps: frames numbered near the stream's position,
// ahead of it, behind it, far from it (as a sender that restarts its
// numbering) or at the top of the range, each spanning one number or a
// run's several, with an envelope length; repeats of earlier frames; the
// clock moving on, with a poll; and taking the ready frames.
//
// Invariants, after every step:
// - every frame taken was pushed, once, and is taken at most once;
// - pushed frames are accounted for: each is delivered (ready or taken),
//   dropped as a duplicate or as late, or held;
// - between two restarts of the order, no sequence number is delivered
//   twice; in order, each frame delivered starts at or after the end of the
//   one before;
// - unique holds nothing, and delivers in arrival order; in order, the
//   frames held stay within the window ahead of the order and within the
//   byte bound, and a gap is pending exactly while frames are held;
// - after a poll at any time, no gap is pending whose timeout has passed;
// - in order, a frame that is the next expected, with nothing held, is
//   delivered at once;
// - at the end, a poll after every timeout releases everything held.

#![no_main]

use std::collections::BTreeSet;
use std::time::{Duration, Instant};

use libfuzzer_sys::arbitrary::{Result, Unstructured};
use libfuzzer_sys::fuzz_target;
use pulse_wire_udp::order::{DeliveryConfig, Order, Sequencer};

/// Most steps in one input.
const MAX_STEPS: usize = 1024;
/// Widest window drawn.
const MAX_WINDOW: u64 = 256;

/// A frame as it was pushed: its numbers, `[seq, end)`, counted wide.
#[derive(Clone, Copy, Debug)]
struct Pushed {
    seq: u64,
    span: u64,
    bytes: usize,
}

impl Pushed {
    fn end(&self) -> u128 {
        u128::from(self.seq) + u128::from(self.span.max(1))
    }
}

struct Run {
    s: Sequencer<usize>,
    order: Order,
    window: u64,
    max_held_bytes: usize,
    start: Instant,
    now: u64,
    pushed: Vec<Pushed>,
    taken: BTreeSet<usize>,
    /// Numbers delivered since the order last started again.
    delivered: BTreeSet<u128>,
    /// End of the last frame delivered, in order, since the last restart.
    last_end: Option<u128>,
    /// Index of the last frame delivered, unique: arrival order.
    last_index: Option<usize>,
}

impl Run {
    fn at(&self) -> Instant {
        self.start + Duration::from_micros(self.now)
    }

    fn push(&mut self, frame: Pushed) {
        // Nothing ready before the push, so what comes out is this push's.
        self.take();
        let index = self.pushed.len();
        self.pushed.push(frame);
        let next_expected = self.last_end;
        let nothing_held = self.s.held_count() == 0;
        let resyncs = self.s.resync_count();
        self.s
            .push(frame.seq, frame.span, frame.bytes, index, self.at());
        if self.order == Order::InOrder
            && nothing_held
            && next_expected == Some(u128::from(frame.seq))
        {
            assert_eq!(
                self.s.ready_count(),
                1,
                "the next frame expected, with nothing held, was not delivered"
            );
        }
        if self.s.resync_count() != resyncs {
            // The order started again: the frames held from before come
            // out first, in their order, and this frame last, the first of
            // the new order.
            let out: Vec<usize> = std::iter::from_fn(|| self.s.pop()).collect();
            let (&last, before) = out.split_last().expect("a restart delivers its frame");
            assert_eq!(last, index, "a restart delivered another frame last");
            for &i in before {
                self.taken_one(i);
            }
            self.delivered.clear();
            self.last_end = None;
            self.last_index = None;
            self.taken_one(last);
        }
        self.check();
    }

    fn take(&mut self) {
        while let Some(index) = self.s.pop() {
            self.taken_one(index);
        }
        self.check();
    }

    fn taken_one(&mut self, index: usize) {
        let frame = *self
            .pushed
            .get(index)
            .expect("a frame taken was never pushed");
        assert!(self.taken.insert(index), "frame {index} taken twice");
        let (seq, end) = (u128::from(frame.seq), frame.end());
        for n in seq..end {
            assert!(
                self.delivered.insert(n),
                "number {n} delivered twice ({frame:?})"
            );
        }
        match self.order {
            Order::InOrder => {
                if let Some(last) = self.last_end {
                    assert!(seq >= last, "in order, {frame:?} came after {last}");
                }
            }
            Order::Unique => {
                if let Some(last) = self.last_index {
                    assert!(index > last, "unique delivered out of arrival order");
                }
            }
        }
        self.last_end = Some(end);
        self.last_index = Some(index);
    }

    fn poll(&mut self) {
        self.s.poll(self.at());
        assert!(
            self.s.deadline().is_none_or(|d| d > self.at()),
            "a gap past its timeout is still pending after a poll"
        );
        self.check();
    }

    fn check(&self) {
        let s = &self.s;
        assert_eq!(
            self.pushed.len() as u64,
            s.delivered_count() + s.duplicate_count() + s.late_count() + s.held_count() as u64,
            "pushed frames are not all accounted for"
        );
        assert_eq!(
            s.delivered_count(),
            (self.taken.len() + s.ready_count()) as u64,
            "delivered frames are neither ready nor taken"
        );
        match self.order {
            Order::Unique => assert_eq!(s.held_count(), 0, "unique held a frame"),
            Order::InOrder => {
                assert!(s.held_count() as u64 <= self.window, "held past the window");
                assert!(
                    s.held_bytes() <= self.max_held_bytes,
                    "held past the byte bound"
                );
                assert_eq!(
                    s.deadline().is_some(),
                    s.held_count() > 0,
                    "a gap pending without frames held, or frames held with no gap"
                );
            }
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let _ = fuzz(data);
});

fn fuzz(data: &[u8]) -> Result<()> {
    let mut u = Unstructured::new(data);
    let mut cfg = if u.arbitrary()? {
        DeliveryConfig::in_order()
    } else {
        DeliveryConfig::unique()
    };
    cfg.window = u.int_in_range(1..=MAX_WINDOW)?;
    cfg.gap_timeout = Duration::from_micros(u.int_in_range(0..=10_000)?);
    cfg.max_held_bytes = u.int_in_range(0..=4096)?;
    let mut base: u64 = match u.int_in_range(0..=3u8)? {
        0 => u64::MAX - u64::from(u.arbitrary::<u8>()?),
        _ => u.arbitrary::<u32>()?.into(),
    };
    if u.arbitrary()? {
        cfg.first = Some(base);
    }
    let mut run = Run {
        s: Sequencer::new(&cfg),
        order: cfg.order,
        window: cfg.window,
        max_held_bytes: cfg.max_held_bytes,
        start: Instant::now(),
        now: 0,
        pushed: Vec::new(),
        taken: BTreeSet::new(),
        delivered: BTreeSet::new(),
        // Told the first number, the order expects it next.
        last_end: cfg.first.map(u128::from),
        last_index: None,
    };
    let w = i64::try_from(cfg.window).unwrap_or(i64::MAX);

    for _ in 0..MAX_STEPS {
        if u.is_empty() {
            break;
        }
        match u.int_in_range(0..=9u8)? {
            // A frame near the stream's position: just behind it to a
            // little past the window ahead.
            0..=4 => {
                let seq = base.wrapping_add_signed(u.int_in_range(-w..=w + 4)?);
                let span = if u.ratio(1, 8)? {
                    u.int_in_range(2..=16)?
                } else {
                    1
                };
                let bytes = u.int_in_range(0..=200)?;
                if u.ratio(1, 2)? {
                    base = base.wrapping_add(span);
                }
                run.push(Pushed { seq, span, bytes });
            }
            // An earlier frame again.
            5 if !run.pushed.is_empty() => {
                let frame = run.pushed[u.choose_index(run.pushed.len())?];
                run.push(frame);
            }
            // Far from the stream: a sender that restarted its numbering,
            // or a frame from long ago; sometimes the stream moves there.
            6 => {
                let seq = match u.int_in_range(0..=2u8)? {
                    0 => u.arbitrary()?,
                    1 => u64::MAX - u64::from(u.arbitrary::<u8>()?),
                    _ => base.wrapping_sub(cfg.window + u64::from(u.arbitrary::<u16>()?)),
                };
                if u.arbitrary()? {
                    base = seq;
                }
                run.push(Pushed {
                    seq,
                    span: 1,
                    bytes: u.int_in_range(0..=200)?,
                });
            }
            // The clock moves on.
            7 => {
                run.now += u.int_in_range(0..=20_000)?;
                run.poll();
            }
            // The receiver takes what is ready.
            _ => run.take(),
        }
    }

    // After every timeout, nothing is held.
    run.now += cfg.gap_timeout.as_micros() as u64 * 2 + 1;
    run.poll();
    run.take();
    assert_eq!(
        run.s.held_count(),
        0,
        "frames still held after every timeout"
    );
    Ok(())
}
