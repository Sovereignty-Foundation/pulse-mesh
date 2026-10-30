// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! The UDP loopback run behind `pulse bench`: pulses sent across
//! `pulse-wire-udp` on this host, timed for throughput and latency percentiles.

use std::time::{Duration, Instant};

use pulse_canon::{Instruction, Pulse};
use pulse_wire_udp::{Receiver, ReceiverError, Sender, SenderError};
use serde::Serialize;

/// Throughput + latency summary returned by [`run_smoke`].
#[derive(Debug, Clone, Serialize)]
pub struct BenchSummary {
    /// Pulses the sender attempted.
    pub pulses_sent: usize,
    /// Pulses the receiver actually decoded.
    pub pulses_received: usize,
    /// Payload size in bytes for each pulse.
    pub payload_bytes: usize,
    /// Wall-clock nanoseconds the sender spent dispatching pulses.
    pub send_elapsed_ns: u128,
    /// Nanoseconds from the receiver's first read to its last decode. The
    /// read timeout that ends a run short of `pulses_sent` is not counted.
    pub recv_elapsed_ns: u128,
    /// Receiver-side throughput in pulses per second.
    pub throughput_pulses_per_sec: f64,
    /// End-to-end (sender-timestamp → receiver-timestamp) latency p50, in ns.
    pub p50_ns: u64,
    /// p99 latency in ns.
    pub p99_ns: u64,
    /// p99.9 latency in ns.
    pub p999_ns: u64,
}

/// The payload size of every smoke pulse, in bytes.
pub const PAYLOAD_BYTES: usize = 64;
/// The pulse count when the caller passes 0, and the default `--count` of
/// both `pulse bench` and `pms bench smoke`.
pub const DEFAULT_PULSE_COUNT: usize = 10_000;

/// Errors from [`run_smoke`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SmokeError {
    /// The receiving socket could not be bound or configured.
    #[error("receiver setup failed: {0}")]
    ReceiverSetup(#[from] std::io::Error),
    /// Sender-side failure (bind, connect, or per-pulse send).
    #[error("sender failed: {0}")]
    Sender(#[from] SenderError),
    /// Receiving or decoding a pulse failed.
    #[error("recv failed: {0}")]
    Recv(#[from] ReceiverError),
    /// The sending thread panicked.
    #[error("send thread panicked")]
    SendThreadPanic,
}

/// Send `pulse_count` pulses ([`DEFAULT_PULSE_COUNT`] when 0) over UDP
/// loopback and summarise what arrived. A receive that waits 5 s ends the run
/// early, so `pulses_received` can fall short of `pulses_sent`; that wait is
/// not counted in `recv_elapsed_ns` or the throughput.
///
/// # Errors
/// [`SmokeError`] when the sockets cannot be set up, a send or receive fails,
/// or the sending thread panics.
pub fn run_smoke(pulse_count: usize) -> Result<BenchSummary, SmokeError> {
    let n = if pulse_count == 0 {
        DEFAULT_PULSE_COUNT
    } else {
        pulse_count
    };

    let mut receiver = Receiver::bind("127.0.0.1:0")?;
    receiver.set_read_timeout(Some(Duration::from_millis(5_000)))?;
    let recv_addr = receiver.local_addr()?;

    let mut sender = Sender::bind("127.0.0.1:0")?;
    sender.connect(recv_addr)?;

    let payload = vec![0u8; PAYLOAD_BYTES];

    // Both ends read `pulse_wire_udp::monotonic_nanos` (CLOCK_UPTIME_RAW on
    // Apple hosts, CLOCK_MONOTONIC elsewhere), so a latency is one reading
    // taken from another, in nanoseconds on every platform.
    let send_thread = std::thread::spawn({
        move || -> Result<u128, SenderError> {
            let mut pulse = Pulse::zeroed();
            pulse.instruction = Instruction::Data as u16;
            let start = Instant::now();
            for i in 0..n {
                pulse.monotonic_nanos = pulse_wire_udp::monotonic_nanos();
                pulse.scope = i as u32;
                sender.send(pulse.monotonic_nanos, &pulse, &payload)?;
            }
            Ok(start.elapsed().as_nanos())
        }
    });

    // The receive clock stops at the last decode: a run that loses Pulses ends
    // on the read timeout, and that wait is not receiving. The decode's own
    // clock reading is reused, so the loop reads the clock once per Pulse.
    let mut latencies_ns: Vec<u64> = Vec::with_capacity(n);
    let recv_start_ns = pulse_wire_udp::monotonic_nanos();
    let mut last_decode_ns = recv_start_ns;
    for _ in 0..n {
        match receiver.recv() {
            Ok((_pulse, _envelope, meta)) => {
                last_decode_ns = pulse_wire_udp::monotonic_nanos();
                latencies_ns.push(last_decode_ns.saturating_sub(meta.send_ns));
            }
            Err(e) if e.is_timeout() => break,
            Err(e) => return Err(e.into()),
        }
    }
    let recv_elapsed_ns = u128::from(last_decode_ns.saturating_sub(recv_start_ns));
    let send_elapsed_ns = send_thread
        .join()
        .map_err(|_| SmokeError::SendThreadPanic)??;

    latencies_ns.sort_unstable();
    let throughput_pulses_per_sec = if recv_elapsed_ns > 0 {
        (latencies_ns.len() as f64) * 1e9 / recv_elapsed_ns as f64
    } else {
        0.0
    };

    Ok(BenchSummary {
        pulses_sent: n,
        pulses_received: latencies_ns.len(),
        payload_bytes: PAYLOAD_BYTES,
        send_elapsed_ns,
        recv_elapsed_ns,
        throughput_pulses_per_sec,
        p50_ns: pct(&latencies_ns, 500),
        p99_ns: pct(&latencies_ns, 990),
        p999_ns: pct(&latencies_ns, 999),
    })
}

fn pct(sorted: &[u64], permille: u32) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let idx = ((permille as u64) * (sorted.len() as u64 - 1) / 1000) as usize;
    sorted[idx.min(sorted.len() - 1)]
}
