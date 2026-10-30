// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! Congestion control on the backpressure feedback, opt-in
//! ([`crate::BackpressureConfig::with_congestion_control`]): a window of
//! frames in flight that grows while ACKs advance and halves on loss, with
//! optional pacing of sends across a round trip.
//!
//! The window narrows what backpressure lets out: a send waits while the
//! window's worth of frames, or `target_queue_depth` frames if that is
//! fewer, is in flight beyond the receiver's cursor. The window starts at
//! `initial_window` and grows by every frame an ACK confirms while it is
//! below the slow-start threshold, which doubles it each round trip, and by
//! about one frame per round trip above it: additive increase. A NACK is the
//! loss signal: the threshold becomes half the window, not below
//! `min_window`, and the window drops to it, at most once per window of
//! frames, since NACKs for frames sent before the last decrease report the
//! same loss: multiplicative decrease. The receiver sends NACKs only with
//! NACK on; without them nothing signals loss, and the window grows to
//! `target_queue_depth` and stays.
//!
//! The round trip is sampled once per round: the send path marks one frame,
//! and the first ACK past it gives the sample, which a NACK for that frame
//! cancels, since its ACK may then answer the retransmission. With pacing on,
//! a single send waits until the smoothed round trip divided by the window
//! has passed since the last one, so the window goes out across the round
//! trip rather than as a burst; a batch goes out as the window allows,
//! unpaced.

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use parking_lot::Mutex;

/// Default `initial_window`: four frames in flight before the first ACK.
pub const DEFAULT_INITIAL_WINDOW: u32 = 4;

/// Default `min_window`: a loss never takes the window below two frames.
pub const DEFAULT_MIN_WINDOW: u32 = 2;

/// Configuration for congestion control. The largest window is the
/// backpressure config's `target_queue_depth`; `initial_window` and
/// `min_window` are taken within `1..=target_queue_depth`.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CongestionConfig {
    /// The window before the first ACK. Default [`DEFAULT_INITIAL_WINDOW`].
    pub initial_window: u32,
    /// The smallest window a loss leaves. Default [`DEFAULT_MIN_WINDOW`].
    pub min_window: u32,
    /// Space single sends by the smoothed round trip over the window.
    /// Default off.
    pub pacing: bool,
}

impl Default for CongestionConfig {
    fn default() -> Self {
        Self {
            initial_window: DEFAULT_INITIAL_WINDOW,
            min_window: DEFAULT_MIN_WINDOW,
            pacing: false,
        }
    }
}

impl CongestionConfig {
    /// Turn pacing on.
    #[must_use]
    pub fn with_pacing(mut self) -> Self {
        self.pacing = true;
        self
    }
}

/// The window arithmetic, without threads or clocks: what an ACK and a loss
/// do to the window.
#[derive(Clone, Debug)]
pub(crate) struct Aimd {
    cwnd: f64,
    ssthresh: f64,
    min: f64,
    max: f64,
    /// The cursor the last ACK reported.
    acked: u64,
    /// Losses below this sequence number belong to the last decrease.
    recovery: u64,
}

impl Aimd {
    /// A window for `cfg` of at most `max_window` frames, whose receiver has
    /// acknowledged up to `cursor` and whose sender has sent up to
    /// `next_seq`, so nothing sent before it starts counts as a new loss.
    pub(crate) fn new(cfg: &CongestionConfig, max_window: u32, cursor: u64, next_seq: u64) -> Self {
        let max = f64::from(max_window.max(1));
        let min = f64::from(cfg.min_window.max(1)).min(max);
        Self {
            cwnd: f64::from(cfg.initial_window).clamp(min, max),
            ssthresh: max,
            min,
            max,
            acked: cursor,
            recovery: next_seq,
        }
    }

    /// An ACK reporting the receiver's cursor at `cursor`.
    pub(crate) fn on_ack(&mut self, cursor: u64) {
        if cursor <= self.acked {
            return;
        }
        let confirmed = (cursor - self.acked) as f64;
        self.acked = cursor;
        if self.cwnd < self.ssthresh {
            self.cwnd += confirmed;
        } else {
            self.cwnd += confirmed / self.cwnd;
        }
        self.cwnd = self.cwnd.min(self.max);
    }

    /// A NACK for `seq`, with the sender's next sequence number at
    /// `next_seq`; true when it decreased the window.
    pub(crate) fn on_loss(&mut self, seq: u64, next_seq: u64) -> bool {
        if seq < self.recovery {
            return false;
        }
        self.ssthresh = (self.cwnd / 2.0).max(self.min);
        self.cwnd = self.ssthresh;
        self.recovery = next_seq;
        true
    }

    /// The window in whole frames.
    pub(crate) fn window(&self) -> u32 {
        // In range: `cwnd` stays within `min..=max`, both `u32` values.
        self.cwnd.clamp(self.min, self.max) as u32
    }
}

/// No frame is marked for a round-trip sample.
const NO_SAMPLE: u64 = u64::MAX;

/// The congestion state the send path and the feedback thread share: the
/// window the send path reads, the frames it reports, and the round-trip
/// sample between them.
pub(crate) struct Congestion {
    /// Written by the feedback thread only.
    aimd: Mutex<Aimd>,
    /// The window as of the last ACK or loss, for the send path.
    window: AtomicU32,
    /// The sender's next sequence number, as the send path last reported.
    next_seq: AtomicU64,
    /// The frame marked for a round-trip sample, or [`NO_SAMPLE`].
    sample_seq: AtomicU64,
    /// When the marked frame went out, in nanoseconds since `epoch`.
    sample_sent: AtomicU64,
    /// The smoothed round trip in nanoseconds; zero before the first sample.
    srtt_ns: AtomicU64,
    decreases: AtomicU64,
    epoch: Instant,
    pacing: bool,
    cfg: CongestionConfig,
}

impl Congestion {
    /// The state for `cfg` with a window of at most `max_window` frames, for
    /// a sender whose receiver has acknowledged `cursor` and whose next
    /// sequence number is `next_seq`.
    pub(crate) fn new(cfg: &CongestionConfig, max_window: u32, cursor: u64, next_seq: u64) -> Self {
        let aimd = Aimd::new(cfg, max_window, cursor, next_seq);
        Self {
            window: AtomicU32::new(aimd.window()),
            aimd: Mutex::new(aimd),
            next_seq: AtomicU64::new(next_seq),
            sample_seq: AtomicU64::new(NO_SAMPLE),
            sample_sent: AtomicU64::new(0),
            srtt_ns: AtomicU64::new(0),
            decreases: AtomicU64::new(0),
            epoch: Instant::now(),
            pacing: cfg.pacing,
            cfg: cfg.clone(),
        }
    }

    /// The configuration this state was made for.
    pub(crate) fn config(&self) -> &CongestionConfig {
        &self.cfg
    }

    /// The window in frames.
    pub(crate) fn window(&self) -> u32 {
        self.window.load(Ordering::Acquire)
    }

    /// The smoothed round trip, once a sample has been taken.
    pub(crate) fn srtt(&self) -> Option<Duration> {
        match self.srtt_ns.load(Ordering::Acquire) {
            0 => None,
            ns => Some(Duration::from_nanos(ns)),
        }
    }

    /// Window decreases so far.
    pub(crate) fn decreases(&self) -> u64 {
        self.decreases.load(Ordering::Relaxed)
    }

    /// The send path's report that frames `first..end` went out: the next
    /// sequence number is `end`, and `first` is marked for a round-trip
    /// sample when none is marked.
    pub(crate) fn sent(&self, first: u64, end: u64) {
        self.next_seq.store(end, Ordering::Release);
        if self.sample_seq.load(Ordering::Acquire) == NO_SAMPLE {
            self.sample_sent.store(self.now_ns(), Ordering::Relaxed);
            // Release: the feedback thread that sees the mark sees its time.
            self.sample_seq.store(first, Ordering::Release);
        }
    }

    /// The feedback thread's ACK at `cursor`.
    pub(crate) fn on_ack(&self, cursor: u64) {
        {
            let mut aimd = self.aimd.lock();
            aimd.on_ack(cursor);
            self.window.store(aimd.window(), Ordering::Release);
        }
        let marked = self.sample_seq.load(Ordering::Acquire);
        if marked != NO_SAMPLE && cursor > marked {
            let rtt = self
                .now_ns()
                .saturating_sub(self.sample_sent.load(Ordering::Relaxed));
            // Only the feedback thread writes the estimate.
            let srtt = match self.srtt_ns.load(Ordering::Relaxed) {
                0 => rtt,
                old => old - old / 8 + rtt / 8,
            };
            self.srtt_ns.store(srtt.max(1), Ordering::Release);
            let _ = self.sample_seq.compare_exchange(
                marked,
                NO_SAMPLE,
                Ordering::AcqRel,
                Ordering::Relaxed,
            );
        }
    }

    /// The feedback thread's NACK for `seq`.
    pub(crate) fn on_loss(&self, seq: u64) {
        let next_seq = self.next_seq.load(Ordering::Acquire);
        {
            let mut aimd = self.aimd.lock();
            if aimd.on_loss(seq, next_seq) {
                self.decreases.fetch_add(1, Ordering::Relaxed);
            }
            self.window.store(aimd.window(), Ordering::Release);
        }
        // Its ACK may answer the retransmission: no sample from it.
        let _ =
            self.sample_seq
                .compare_exchange(seq, NO_SAMPLE, Ordering::AcqRel, Ordering::Relaxed);
    }

    /// The gap pacing leaves between two single sends: the smoothed round
    /// trip over the window, or `None` with pacing off or before the first
    /// sample.
    pub(crate) fn pace_interval(&self) -> Option<Duration> {
        if !self.pacing {
            return None;
        }
        Some(self.srtt()? / self.window().max(1))
    }

    fn now_ns(&self) -> u64 {
        u64::try_from(self.epoch.elapsed().as_nanos()).unwrap_or(u64::MAX)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn aimd(initial: u32, min: u32, max: u32) -> Aimd {
        let cfg = CongestionConfig {
            initial_window: initial,
            min_window: min,
            pacing: false,
        };
        Aimd::new(&cfg, max, 0, 0)
    }

    #[test]
    fn slow_start_doubles_the_window_each_round_until_the_cap() {
        let mut a = aimd(4, 2, 64);
        let mut cursor = 0;
        for want in [8, 16, 32, 64, 64] {
            // A round: every frame of the window acknowledged.
            cursor += u64::from(a.window());
            a.on_ack(cursor);
            assert_eq!(a.window(), want);
        }
    }

    #[test]
    fn a_loss_halves_the_window_once_per_window_then_it_grows_by_one_a_round() {
        let mut a = aimd(32, 2, 64);
        // Frames 0..32 are out; a NACK for 10.
        assert!(a.on_loss(10, 32));
        assert_eq!(a.window(), 16);
        // NACKs for other frames sent before the decrease are the same loss.
        assert!(!a.on_loss(20, 40));
        assert!(!a.on_loss(31, 40));
        assert_eq!(a.window(), 16);
        // Above the threshold, a round of ACKs, a window's worth of frames
        // confirmed, adds about one frame.
        let mut cursor = 0;
        for want in [17, 18, 19] {
            cursor += u64::from(a.window());
            a.on_ack(cursor);
            assert_eq!(a.window(), want);
        }
        // A loss among frames sent after the decrease is a new one.
        assert!(a.on_loss(40, 90));
        assert_eq!(a.window(), 9);
    }

    #[test]
    fn the_window_stays_within_its_floor_and_cap() {
        let mut a = aimd(100, 0, 8);
        assert_eq!(a.window(), 8, "the initial window is capped");
        for next in 8..18 {
            a.on_loss(next, next + 1);
        }
        assert_eq!(a.window(), 1, "a zero floor is taken as one");
        let mut b = aimd(4, 3, 64);
        b.on_loss(0, 4);
        assert_eq!(
            b.window(),
            3,
            "a loss never takes the window below the floor"
        );
    }

    #[test]
    fn a_stale_or_repeated_ack_changes_nothing() {
        let mut a = aimd(4, 2, 64);
        a.on_ack(4);
        assert_eq!(a.window(), 8);
        a.on_ack(4);
        a.on_ack(2);
        assert_eq!(a.window(), 8);
    }

    #[test]
    fn a_loss_from_before_the_window_was_made_is_not_counted() {
        let cfg = CongestionConfig::default();
        // Made with frames up to 100 already sent, as a reconfigure does.
        let mut a = Aimd::new(&cfg, 64, 90, 100);
        assert!(!a.on_loss(95, 100));
        assert!(a.on_loss(100, 110));
    }

    #[test]
    fn the_round_trip_is_sampled_from_the_marked_frame_and_a_loss_cancels_it() {
        let c = Congestion::new(&CongestionConfig::default().with_pacing(), 64, 0, 0);
        assert_eq!(c.srtt(), None);
        assert_eq!(c.pace_interval(), None, "no pacing before a sample");
        c.sent(0, 1);
        std::thread::sleep(Duration::from_millis(2));
        c.sent(1, 2);
        c.on_ack(1);
        let srtt = c.srtt().unwrap();
        assert!(srtt >= Duration::from_millis(2), "{srtt:?}");
        assert_eq!(c.pace_interval(), Some(srtt / c.window()));
        // The next frame is marked; a NACK for it cancels the sample.
        c.sent(2, 3);
        c.on_loss(2);
        assert_eq!(c.decreases(), 1);
        std::thread::sleep(Duration::from_millis(20));
        c.on_ack(3);
        assert_eq!(
            c.srtt(),
            Some(srtt),
            "no sample from a frame that was NACKed"
        );
    }
}
