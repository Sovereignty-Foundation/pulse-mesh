// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! `Backoff`: a spin, yield, sleep state machine for waits that may be long, tier 1.
//!
//! As a wait lengthens, [`Backoff::snooze`] spins (through step
//! [`PHASE_1_THRESHOLD`]), then yields to the operating system (through
//! [`PHASE_2_THRESHOLD`]), then sleeps an increment the caller sets;
//! [`Backoff::reset`] returns to spinning once progress is seen.
//!
//! This is for stalls the operating system can see, such as the UDP sender
//! waiting on a receiver's cursor. The ring's SeqLock retry stays a bare
//! spin, since its writer finishes in nanoseconds and escalation would only
//! add jitter; the HFT ring's wait strategies monitor a slot address in
//! hardware.
//!
//! In the book: <https://pulse-mesh.net/docs/reference/spec/06-udp-transport.html> (section 6.2).
#![forbid(unsafe_code)]

use std::hint::spin_loop;
use std::thread;
use std::time::Duration;

/// Phase boundary (inclusive) for hot-spin → OS-yield.
pub const PHASE_1_THRESHOLD: u32 = 1_000;
/// Phase boundary (inclusive) for OS-yield → microsleep.
pub const PHASE_2_THRESHOLD: u32 = 5_000;

/// Three-phase spin-wait state machine.
#[derive(Debug, Clone)]
pub struct Backoff {
    step: u32,
    /// Phase 3 sleep increment.
    sleep: Duration,
}

/// Default Phase 3 sleep increment.
const DEFAULT_SLEEP: Duration = Duration::from_micros(1);

/// Identifies which spin/yield/sleep phase the next `snooze()` will use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackoffPhase {
    /// Hot spin via `core::hint::spin_loop()`.
    Spin,
    /// OS-level cooperative yield via `thread::yield_now()`.
    Yield,
    /// `thread::sleep` for the sleep increment (1 µs by default).
    Sleep,
}

impl Backoff {
    /// Construct a fresh backoff at step 0 (the spin phase).
    #[inline(always)]
    pub const fn new() -> Self {
        Self {
            step: 0,
            sleep: DEFAULT_SLEEP,
        }
    }

    /// Construct a fresh backoff whose Phase 3 sleeps `sleep` per step
    /// instead of the 1 µs default.
    #[inline(always)]
    pub const fn with_sleep(sleep: Duration) -> Self {
        Self { step: 0, sleep }
    }

    /// Construct a backoff already at `step`, to start in a later phase.
    #[inline(always)]
    pub const fn from_step(step: u32) -> Self {
        Self {
            step,
            sleep: DEFAULT_SLEEP,
        }
    }

    /// Wait for one step using the current phase's primitive, then advance
    /// the step counter. Saturates at `u32::MAX` (no overflow).
    #[inline(always)]
    pub fn snooze(&mut self) {
        if self.step <= PHASE_1_THRESHOLD {
            spin_loop();
        } else if self.step <= PHASE_2_THRESHOLD {
            thread::yield_now();
        } else {
            thread::sleep(self.sleep);
        }
        self.step = self.step.saturating_add(1);
    }

    /// Return to step 0, the spin phase: call it as soon as progress is
    /// seen.
    #[inline(always)]
    pub fn reset(&mut self) {
        self.step = 0;
    }

    /// Current step count.
    #[inline(always)]
    pub fn step(&self) -> u32 {
        self.step
    }

    /// The Phase 3 sleep increment.
    #[inline(always)]
    pub fn sleep(&self) -> Duration {
        self.sleep
    }

    /// Which phase the next `snooze()` call will use.
    pub fn phase(&self) -> BackoffPhase {
        if self.step <= PHASE_1_THRESHOLD {
            BackoffPhase::Spin
        } else if self.step <= PHASE_2_THRESHOLD {
            BackoffPhase::Yield
        } else {
            BackoffPhase::Sleep
        }
    }
}

impl Default for Backoff {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn phases_follow_the_thresholds() {
        let mut b = Backoff::new();
        assert_eq!(b.phase(), BackoffPhase::Spin);
        for _ in 0..=PHASE_1_THRESHOLD {
            b.snooze();
        }
        assert_eq!(b.phase(), BackoffPhase::Yield);
        assert_eq!(
            Backoff::from_step(PHASE_2_THRESHOLD).phase(),
            BackoffPhase::Yield
        );
        assert_eq!(
            Backoff::from_step(PHASE_2_THRESHOLD + 1).phase(),
            BackoffPhase::Sleep
        );
    }

    #[test]
    fn reset_returns_to_the_hot_spin() {
        let mut b = Backoff::from_step(PHASE_2_THRESHOLD + 10);
        b.snooze();
        b.reset();
        assert_eq!(b.step(), 0);
        assert_eq!(b.phase(), BackoffPhase::Spin);
    }

    #[test]
    fn sleep_increment_is_configurable() {
        let b = Backoff::with_sleep(Duration::from_micros(50));
        assert_eq!(b.sleep(), Duration::from_micros(50));
        assert_eq!(Backoff::new().sleep(), Duration::from_micros(1));
        assert_eq!(Backoff::from_step(3).sleep(), Duration::from_micros(1));
    }

    #[test]
    fn step_saturates() {
        let mut b = Backoff::from_step(u32::MAX);
        b.snooze();
        assert_eq!(b.step(), u32::MAX);
    }
}
