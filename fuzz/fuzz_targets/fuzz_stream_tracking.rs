// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//
// Fuzz target: the UDP receiver's stream tracking, `StreamTracker`: the
// ACK cursor, the contiguous head, the out-of-order set, NACK staging and
// the horizon, driven with the sequence number of every frame a receiver
// decodes, and the NACKs its feedback thread takes each ACK period. The
// receiver hands the tracker every decoded frame's number and nothing else,
// so this is the whole of its gap tracking without a socket.
//
// The input picks the configuration (the recovery window, NACK on or off,
// the ACK period) and a run: frames that continue the stream, fill its
// holes, repeat, arrive late, jump ahead a little or far (to the top of the
// range included, in pairs that confirm a jump now and then), and NACK
// takes at times that move forward by any step.
//
// A frame is tracked when it lies within the horizon, twice the recovery
// window beyond the contiguous head, or when it and the pending jump, the
// last frame beyond the horizon, lie within one recovery window of each
// other (then both are). The oracle keeps the set of frames tracked by
// that rule, as `Receiver::beyond_horizon_count` documents it, and the
// requests the takes made: how many for each frame, and when. From those
// alone it knows which frames are missing, which must be staged and which
// requests are due, without asking how the tracker keeps them.
//
// Invariants, after every step:
// - a frame beyond the horizon that confirms nothing moves nothing, is
//   counted, and a frame numbered `u64::MAX` is never tracked;
// - the cursor is one past the highest frame tracked, zero before any, and
//   never goes down; the head never goes down and never passes the cursor;
//   the highest frame tracked lies at most one recovery window above it;
// - every frame tracked lies below the head or in the out-of-order set,
//   and the head itself has not arrived; the out-of-order set holds only
//   frames tracked, strictly between the head and the cursor;
// - the staged set holds only frames missing between the head and the
//   cursor, and never more than the recovery window of them;
// - with NACK on, it holds all of them that still have requests left:
//   a frame an arrival reveals missing is staged at once, before the next
//   NACK take, and stays staged until it arrives, the head passes it or its
//   last request goes out;
// - the head passes a missing frame only when that frame lies more than the
//   recovery window below the highest frame tracked, out of the sender's
//   cache, and the frames it passes before any request for them are the
//   ones counted dropped, no more and no fewer;
// - counts never go down;
// - a NACK take returns at most its budget, only frames staged just before
//   it, each at most MAX_NACK_ATTEMPTS times in all, a repeat no sooner
//   than the retry interval after the request before it, and first
//   requests lowest first; exactly the requests due, as `NackStaging`
//   orders them: repeats that have fallen due, oldest request first, then
//   first requests, lowest first, up to the budget;
// - every frame still missing is requested in the end, and again until it
//   has had MAX_NACK_ATTEMPTS requests: takes a retry interval apart empty
//   the staged set;
// - whatever came before, the stream continuing from the cursor is tracked
//   and moves the head: nothing a peer sends switches the tracking off.

#![no_main]

use std::collections::{BTreeMap, BTreeSet};
use std::net::{Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use libfuzzer_sys::arbitrary::{Result, Unstructured};
use libfuzzer_sys::fuzz_target;
use pulse_wire_udp::backpressure::StreamTracker;
use pulse_wire_udp::{
    BackpressureConfig, MAX_NACKS_PER_CYCLE, MAX_NACK_ATTEMPTS, NACK_RETRY_PERIODS,
};

/// Most steps in one run.
const MAX_STEPS: usize = 512;
/// Largest recovery window drawn.
const MAX_WINDOW: usize = 64;

/// The horizon rule, kept by the oracle.
struct Rule {
    window: u64,
    pending: Option<u64>,
}

impl Rule {
    /// The frames an arrival of `seq` tracks, given the head before it.
    fn tracks(&mut self, seq: u64, head: u64) -> Vec<u64> {
        if seq != u64::MAX && seq.saturating_sub(head) <= 2 * self.window {
            return vec![seq];
        }
        match self.pending {
            Some(first)
                if seq != u64::MAX && seq != first && seq.abs_diff(first) <= self.window =>
            {
                self.pending = None;
                vec![seq.max(first), seq.min(first)]
            }
            _ => {
                if seq != u64::MAX {
                    self.pending = Some(seq);
                }
                Vec::new()
            }
        }
    }
}

/// What the oracle knows of the NACKs requested.
#[derive(Default)]
struct Requests {
    /// Per frame: the requests made, when the last went out, and that
    /// request's place among all those made.
    sent: BTreeMap<u64, (u32, Instant, u64)>,
    /// Requests made so far.
    made: u64,
}

impl Requests {
    /// Requests made for `seq`.
    fn count(&self, seq: u64) -> u32 {
        self.sent.get(&seq).map_or(0, |r| r.0)
    }
}

fuzz_target!(|data: &[u8]| {
    let _ = fuzz(data);
});

fn fuzz(data: &[u8]) -> Result<()> {
    let mut u = Unstructured::new(data);
    let any: SocketAddr = (Ipv4Addr::LOCALHOST, 0).into();
    let mut cfg = BackpressureConfig::new(any, any);
    let window = u.int_in_range(0..=MAX_WINDOW)?;
    if u.arbitrary()? {
        cfg = cfg.with_nack(window);
    } else {
        cfg.send_cache_capacity = window;
    }
    cfg.ack_period = Duration::from_micros(u.int_in_range(1..=5000)?);
    let retry = cfg.ack_period.saturating_mul(NACK_RETRY_PERIODS);
    let tracker = StreamTracker::new(&cfg);
    let window = window.max(1) as u64;
    let mut rule = Rule {
        window,
        pending: None,
    };

    let mut tracked: BTreeSet<u64> = BTreeSet::new();
    let mut requests = Requests::default();
    let start = Instant::now();
    let mut now = start;
    let (mut head, mut cursor, mut beyond, mut resyncs, mut dropped) = (0, 0, 0, 0, 0);

    for _ in 0..MAX_STEPS {
        if u.is_empty() {
            break;
        }
        let before = (tracker.contiguous_head(), tracker.nack_drop_count());
        if u.ratio(1, 6)? {
            now += Duration::from_micros(u.int_in_range(0..=40_000)?);
            let budget = u.int_in_range(0..=20)?;
            take_nacks(&tracker, &mut requests, now, retry, &tracked, budget);
        } else {
            let seq = next_seq(&mut u, &tracker, window)?;
            let moved = rule.tracks(seq, tracker.contiguous_head());
            tracker.arrived(seq);
            if moved.is_empty() {
                assert_eq!(
                    tracker.beyond_horizon_count(),
                    beyond + 1,
                    "a frame beyond the horizon went uncounted"
                );
                assert_eq!(
                    tracker.recv_cursor(),
                    cursor,
                    "a frame beyond the horizon moved the cursor"
                );
                assert_eq!(
                    tracker.contiguous_head(),
                    head,
                    "a frame beyond the horizon moved the head"
                );
            }
            tracked.extend(moved);
        }
        (head, cursor, beyond, resyncs, dropped) = check(
            &tracker,
            &tracked,
            window,
            (head, cursor, beyond, resyncs, dropped),
        );
        check_passed(&tracker, &tracked, &requests, window, before);
        check_staged(&tracker, &tracked, &requests);
    }

    // Every frame still missing is requested in the end, and again until it
    // has had its last request: with every request a retry interval old,
    // each take serves the budget or all that is staged, and a frame needs
    // MAX_NACK_ATTEMPTS requests.
    if tracker.nack_enabled() {
        let missing = tracker.staged();
        let takes = MAX_NACK_ATTEMPTS as usize * (missing.len() / MAX_NACKS_PER_CYCLE + 1);
        for _ in 0..takes {
            now += retry;
            let before = (tracker.contiguous_head(), tracker.nack_drop_count());
            take_nacks(
                &tracker,
                &mut requests,
                now,
                retry,
                &tracked,
                MAX_NACKS_PER_CYCLE,
            );
            check_passed(&tracker, &tracked, &requests, window, before);
            check_staged(&tracker, &tracked, &requests);
        }
        let left = tracker.staged();
        assert!(
            left.is_empty(),
            "{left:?} still staged after {takes} takes a retry interval apart"
        );
        for seq in missing {
            assert_eq!(
                requests.count(seq),
                MAX_NACK_ATTEMPTS,
                "{seq} was not requested to the last attempt"
            );
        }
    }

    // Whatever came before, the stream that continues from the cursor is
    // tracked, and moves the head.
    let from = tracker.recv_cursor();
    if from < u64::MAX - 2 * window {
        let head_before = tracker.contiguous_head();
        for seq in from..from + 2 * window {
            let before = (tracker.contiguous_head(), tracker.nack_drop_count());
            let moved = rule.tracks(seq, tracker.contiguous_head());
            assert_eq!(
                moved,
                vec![seq],
                "the continuing stream fell beyond the horizon at {seq}"
            );
            tracker.arrived(seq);
            tracked.extend(moved);
            check(
                &tracker,
                &tracked,
                window,
                (head, cursor, beyond, resyncs, dropped),
            );
            check_passed(&tracker, &tracked, &requests, window, before);
            check_staged(&tracker, &tracked, &requests);
        }
        assert_eq!(tracker.recv_cursor(), from + 2 * window);
        assert!(
            tracker.contiguous_head() > head_before,
            "the continuing stream never moved the head"
        );
    }
    Ok(())
}

/// The invariants that hold after every step; returns the counts to hold
/// the next step to.
fn check(
    tracker: &StreamTracker,
    tracked: &BTreeSet<u64>,
    window: u64,
    (head0, cursor0, beyond0, resyncs0, dropped0): (u64, u64, u64, u64, u64),
) -> (u64, u64, u64, u64, u64) {
    let head = tracker.contiguous_head();
    let cursor = tracker.recv_cursor();
    let (beyond, resyncs, dropped) = (
        tracker.beyond_horizon_count(),
        tracker.gap_resyncs(),
        tracker.nack_drop_count(),
    );
    assert!(cursor >= cursor0, "the cursor went down");
    assert!(head >= head0, "the head went down");
    assert!(
        beyond >= beyond0 && resyncs >= resyncs0 && dropped >= dropped0,
        "a count went down"
    );
    assert_eq!(
        cursor,
        tracked.last().map_or(0, |&s| s + 1),
        "the cursor is not one past the highest frame tracked"
    );
    assert!(head <= cursor, "the head passed the cursor");
    if cursor > head {
        assert!(
            cursor - 1 - head <= window,
            "the highest frame is more than a window above the head"
        );
    }
    assert!(!tracked.contains(&head), "the head has arrived");
    let ooo: BTreeSet<u64> = tracker.out_of_order().into_iter().collect();
    for &s in &ooo {
        assert!(
            tracked.contains(&s),
            "{s} is out of order but never arrived"
        );
        assert!(
            head < s && s < cursor,
            "{s} is out of order outside (head, cursor)"
        );
    }
    for &s in tracked.range(head..) {
        assert!(
            ooo.contains(&s),
            "{s} arrived above the head but is not out of order"
        );
    }
    let staged = tracker.staged();
    assert!(staged.len() as u64 <= window, "more than a window staged");
    for &s in &staged {
        assert!(tracker.nack_enabled(), "a frame staged with NACK off");
        assert!(head <= s && s < cursor, "{s} staged outside [head, cursor)");
        assert!(!tracked.contains(&s), "{s} staged though it arrived");
    }
    (head, cursor, beyond, resyncs, dropped)
}

/// With NACK on, the staged set is exactly the frames missing between the
/// head and the cursor that still have requests left, so that the next
/// NACK take can request every one of them; nothing else is staged.
fn check_staged(tracker: &StreamTracker, tracked: &BTreeSet<u64>, requests: &Requests) {
    if !tracker.nack_enabled() {
        // `check` holds the staged set empty.
        return;
    }
    let (head, cursor) = (tracker.contiguous_head(), tracker.recv_cursor());
    let missing: Vec<u64> = (head..cursor)
        .filter(|seq| !tracked.contains(seq) && requests.count(*seq) < MAX_NACK_ATTEMPTS)
        .collect();
    assert_eq!(
        tracker.staged(),
        missing,
        "the staged set is not the frames missing between the head and the cursor with requests left"
    );
}

/// After one step, which started with the head and the drop count at
/// `before`: every missing frame the head passed lies more than the recovery
/// window below the highest frame tracked, out of the sender's cache; and,
/// with NACK on, the drop count grew by exactly the missing frames it passed
/// that never had a request.
fn check_passed(
    tracker: &StreamTracker,
    tracked: &BTreeSet<u64>,
    requests: &Requests,
    window: u64,
    (head0, dropped0): (u64, u64),
) {
    let head = tracker.contiguous_head();
    // The highest missing frame passed lies below the frames that arrived
    // just under the head, at most a window of them.
    let mut seq = head;
    while seq > head0 {
        seq -= 1;
        if !tracked.contains(&seq) {
            let highest = tracker.recv_cursor() - 1;
            assert!(
                highest - seq > window,
                "the head passed {seq}, missing and within the recovery window below {highest}"
            );
            break;
        }
    }
    let passed = head - head0;
    let arrived = tracked.range(head0..head).count() as u64;
    let requested = requests
        .sent
        .range(head0..head)
        .filter(|(seq, _)| !tracked.contains(seq))
        .count() as u64;
    let given_up = passed - arrived - requested;
    let expected = if tracker.nack_enabled() {
        dropped0.saturating_add(given_up)
    } else {
        dropped0
    };
    assert_eq!(
        tracker.nack_drop_count(),
        expected,
        "the drop count is not the missing frames the head passed before any request"
    );
}

/// One NACK take of at most `budget` requests, as the feedback thread makes
/// it every ACK period: exactly the requests due, repeats that have fallen
/// due, oldest request first, then first requests, lowest first.
fn take_nacks(
    tracker: &StreamTracker,
    requests: &mut Requests,
    now: Instant,
    retry: Duration,
    tracked: &BTreeSet<u64>,
    budget: usize,
) {
    let staged: BTreeSet<u64> = tracker.staged().into_iter().collect();
    let mut repeats: Vec<(u64, u64)> = staged
        .iter()
        .filter_map(|&seq| {
            let &(count, last, place) = requests.sent.get(&seq)?;
            (count < MAX_NACK_ATTEMPTS && last + retry <= now).then_some((place, seq))
        })
        .collect();
    repeats.sort_unstable();
    let due: Vec<u64> = repeats
        .into_iter()
        .map(|(_, seq)| seq)
        .chain(
            staged
                .iter()
                .copied()
                .filter(|&seq| requests.count(seq) == 0),
        )
        .take(budget)
        .collect();

    let mut out = Vec::new();
    tracker.take_nacks_due(now, budget, &mut out);
    assert!(out.len() <= budget, "a take returned more than its budget");
    let mut firsts = Vec::new();
    for &seq in &out {
        assert!(staged.contains(&seq), "{seq} requested but not staged");
        assert!(!tracked.contains(&seq), "{seq} requested though it arrived");
        let entry = requests.sent.entry(seq).or_insert((0, now, 0));
        if entry.0 == 0 {
            firsts.push(seq);
        } else {
            assert!(
                now.duration_since(entry.1) >= retry,
                "{seq} requested again before the retry interval"
            );
        }
        *entry = (entry.0 + 1, now, requests.made);
        requests.made += 1;
        assert!(
            entry.0 <= MAX_NACK_ATTEMPTS,
            "{seq} requested more than {MAX_NACK_ATTEMPTS} times"
        );
    }
    assert!(
        firsts.windows(2).all(|w| w[0] < w[1]),
        "first requests out of order: {firsts:?}"
    );
    assert_eq!(
        out, due,
        "the take is not the requests due: repeats fallen due, oldest first, then first requests, lowest first"
    );
}

/// The next frame's number: the stream going on, a hole filled, a repeat,
/// a late frame, a small or large jump, or the top of the range.
fn next_seq(u: &mut Unstructured<'_>, tracker: &StreamTracker, window: u64) -> Result<u64> {
    let head = tracker.contiguous_head();
    let cursor = tracker.recv_cursor();
    Ok(match u.int_in_range(0..=9u8)? {
        0..=2 => cursor,
        3 => cursor.saturating_add(u.int_in_range(1..=window)?),
        4 if cursor > head => u.int_in_range(head..=cursor - 1)?,
        5 => head.saturating_sub(u.int_in_range(0..=window)?),
        6 => cursor.saturating_add(u.int_in_range(window..=3 * window)?),
        7 => u64::MAX - u.int_in_range(0..=2 * window)?,
        8 => u.arbitrary()?,
        _ => cursor.saturating_add(u.int_in_range(0..=4 * window)?),
    })
}
