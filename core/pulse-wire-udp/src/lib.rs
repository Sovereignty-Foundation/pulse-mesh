// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! `pulse-wire-udp`: the reference UDP transport, tier 1.
//!
//! One datagram carries one Pulse and at most one envelope, under a CRC32C:
//! at most [`MAX_ENVELOPE`] bytes of envelope, or [`FEC_MAX_ENVELOPE`] with
//! FEC on, so that parity fits a datagram too. Mechanisms, each opt-in, sit
//! on top: backpressure that keeps the sender within a window of the
//! receiver's cursor, congestion control that sizes that window to the
//! path, NACK retransmission from a bounded send cache, single-parity
//! forward error correction, multicast to every receiver in a group, and
//! fragmentation, which sends an envelope up to [`MAX_MESSAGE`] bytes as a
//! run of datagrams and reassembles it. Sealing, ADR-0018's authenticated
//! and encrypted datagrams, is opt-in as well: **the review by someone who
//! does cryptographic engineering that ADR-0018 item 9 requires is pending,
//! and sealed mode should not be relied on in production until it is
//! done.**
//!
//! - [`wire`]: the frame layout and codec. A frame's envelope reaches the
//!   caller as the bytes that arrived; [`wire::decode_with_envelope`]
//!   decodes them as a canonical envelope and checks its id.
//! - [`sender`] and [`receiver`]: the two ends. A receiver refuses a
//!   datagram whose CRC does not match.
//! - [`backpressure`]: the ACK and NACK feedback from receiver to sender.
//! - [`congestion`]: an additive-increase, multiplicative-decrease window
//!   on that feedback, with optional pacing.
//! - [`fec`]: parity that rebuilds one lost frame per window without a
//!   round trip.
//! - [`multicast`]: one send to a group, received by every member.
//! - [`fragment`]: the fragment layout and the receiver's bounded
//!   reassembly.
//! - [`sealed`]: a Noise handshake between nodes that know each other's
//!   keys, then each whole datagram, fragments included, authenticated and
//!   encrypted. Plaintext stays the default.
//!
//! In the book: <https://pulse-mesh.net/docs/reference/spec/06-udp-transport.html> and
//! <https://pulse-mesh.net/docs/explanation/transport-design.html>.

#![deny(unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]
// `deny`, not `forbid`: the batch send and receive paths need `unsafe` for
// libc calls and a buffer lent to socket2, and `monotonic_nanos` for its
// clock read, each item under an `#[allow(unsafe_code)]` of its own.
#![deny(unsafe_code)]

pub mod backpressure;
pub mod congestion;
pub mod fec;
pub mod fragment;
pub mod multicast;
pub mod order;
pub mod receiver;
mod retry;
pub mod sealed;
pub mod sender;
mod transport_impl;
pub mod wire;

pub use backpressure::{
    decode_ack, decode_nack, encode_ack, encode_nack, BackpressureConfig, ACK_BYTES, ACK_MAGIC,
    DEFAULT_ACK_PERIOD, DEFAULT_SEND_CACHE_CAPACITY, DEFAULT_STALL_TIMEOUT,
    DEFAULT_TARGET_QUEUE_DEPTH, MAX_NACKS_PER_CYCLE, MAX_NACK_ATTEMPTS, NACK_BYTES, NACK_MAGIC,
    NACK_RETRY_PERIODS, STALL_SLEEP,
};
pub use congestion::{CongestionConfig, DEFAULT_INITIAL_WINDOW, DEFAULT_MIN_WINDOW};
pub use fec::{
    decode_fec, encode_fec, FecDecoder, FecEncoder, FecError, FecHeader, DEFAULT_FEC_WINDOW,
    FEC_HEADER_BYTES, FEC_MAGIC, FEC_MAX_ENVELOPE,
};
pub use fragment::{ReassemblyConfig, FRAG_MAGIC, MAX_MESSAGE};
pub use multicast::{MulticastConfig, DEFAULT_MULTICAST_TTL};
pub use receiver::{
    BatchRecvError, BatchRecvFrameError, BatchRecvResult, Receiver, ReceiverError, RecvMeta,
};
pub use sealed::{
    bind_sealed_pair, bind_sealed_pair_with, Allowlist, NodeKey, PublicKey, SealCounts, SealError,
    Sealing, SealingConfig, SEALED_FEC_MAX_ENVELOPE, SEALED_INNER_BUDGET, SEALED_MAX_ENVELOPE,
    SEALED_OVERHEAD,
};
pub use sender::{BatchSendError, Sender, SenderError, MAX_BATCH_FRAMES};
pub use wire::{
    datagram_size, decode, encode, encode_header_into, encode_into, Frame, WireError, HEADER_BYTES,
    MAGIC, MAX_ENVELOPE, MTU_BYTES, TRAILER_BYTES, VERSION,
};

/// The host's monotonic clock now, in nanoseconds: the clock a Pulse's
/// `monotonic_nanos` is defined on (chapter 2 of the specification), one
/// clock for every process on the host, and the one to stamp a frame's
/// `send_ns` with, so a receiver on the same host can subtract it from its
/// own reading. It reads CLOCK_MONOTONIC on Linux and CLOCK_UPTIME_RAW on
/// Apple platforms, both counting in nanoseconds and neither counting time
/// asleep. Zero if the clock cannot be read, which
/// none of the platforms the crate builds for does.
#[must_use]
#[allow(unsafe_code)]
pub fn monotonic_nanos() -> u64 {
    let mut now = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `now` is a valid, writable `timespec` for the duration of the
    // call, and `clock_gettime` writes nothing else.
    if unsafe { libc::clock_gettime(HOST_MONOTONIC, &mut now) } != 0 {
        return 0;
    }
    let seconds = u64::try_from(now.tv_sec).unwrap_or(0);
    let nanos = u64::try_from(now.tv_nsec).unwrap_or(0);
    seconds.saturating_mul(1_000_000_000).saturating_add(nanos)
}

/// The clock [`monotonic_nanos`] reads. On Apple platforms CLOCK_MONOTONIC
/// steps in whole microseconds and keeps counting while the machine sleeps,
/// so a Pulse stamped there would lose its sub-microsecond timing and
/// disagree with every clock that stops for sleep (std's `Instant`, Python's
/// `time.monotonic`); CLOCK_UPTIME_RAW is the one that matches them.
#[cfg(target_vendor = "apple")]
const HOST_MONOTONIC: libc::clockid_t = libc::CLOCK_UPTIME_RAW;
/// The clock [`monotonic_nanos`] reads: CLOCK_MONOTONIC, which counts
/// nanoseconds and stops while the machine is suspended.
#[cfg(not(target_vendor = "apple"))]
const HOST_MONOTONIC: libc::clockid_t = libc::CLOCK_MONOTONIC;

#[cfg(test)]
mod clock_tests {
    use std::time::{Duration, Instant};

    /// The clock counts nanoseconds, at the rate std's monotonic clock does,
    /// not the ticks of a faster counter.
    #[test]
    fn monotonic_nanos_counts_nanoseconds() {
        let window = Instant::now();
        let before = super::monotonic_nanos();
        std::thread::sleep(Duration::from_millis(20));
        let after = super::monotonic_nanos();
        let elapsed = u64::try_from(window.elapsed().as_nanos()).unwrap_or(u64::MAX);
        assert!(before > 0);
        let delta = after.saturating_sub(before);
        assert!(delta >= 20_000_000, "the sleep lasted 20 ms: {delta} ns");
        assert!(
            delta <= elapsed.saturating_add(1_000_000),
            "{delta} ns inside {elapsed} ns"
        );
    }

    /// The clock resolves below a microsecond. macOS's CLOCK_MONOTONIC steps
    /// in whole microseconds, so every one of its readings ends in 000; one
    /// thousand readings that all did would mean the coarse clock is back.
    #[test]
    fn readings_resolve_below_a_microsecond() {
        let fine = (0..1000).any(|_| !super::monotonic_nanos().is_multiple_of(1000));
        assert!(fine, "every reading was a whole microsecond");
    }
}
