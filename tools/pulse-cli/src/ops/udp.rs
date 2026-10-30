// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! The UDP send and receive loops behind `pulse send` and `pulse recv`, over
//! [`pulse_wire_udp::Sender`] and [`pulse_wire_udp::Receiver`].

use std::net::SocketAddr;
use std::time::Duration;

use pulse_canon::{Instruction, Pulse};
use pulse_wire_udp::{Receiver, ReceiverError, Sender, SenderError};
use serde::Serialize;

/// Summary of a single received pulse.
#[derive(Debug, Clone, Serialize)]
pub struct RecvSummary {
    /// Monotonic per-run sequence (set by the sender).
    pub seq: u64,
    /// The sender's CLOCK_MONOTONIC reading in nanoseconds, as the frame
    /// carried it.
    pub send_ns: u64,
    /// Decoded instruction opcode.
    pub instruction: String,
    /// Envelope payload size in bytes.
    pub envelope_len: usize,
}

/// Aggregate result of a [`send_pulses`] call.
#[derive(Debug, Clone, Serialize)]
pub struct SendStats {
    /// Number of frames the kernel accepted.
    pub sent: usize,
    /// Wall-clock duration in microseconds.
    pub elapsed_us: u128,
}

/// Errors from [`send_pulses`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SendError {
    /// Underlying socket bind failed.
    #[error("bind failed: {0}")]
    Bind(std::io::Error),
    /// Underlying sender failed.
    #[error("send failed: {0}")]
    Send(#[from] SenderError),
}

/// Send `count` data pulses, each with `payload_size` zero bytes, to `dest`.
///
/// # Errors
/// [`SendError::Bind`] when the source socket cannot be bound, or
/// [`SendError::Send`] when connecting or any send fails.
pub fn send_pulses(
    dest: SocketAddr,
    count: usize,
    payload_size: usize,
) -> Result<SendStats, SendError> {
    let mut sender = Sender::bind("0.0.0.0:0").map_err(|e| SendError::Bind(unwrap_io(e)))?;
    sender.connect(dest)?;

    let payload = vec![0u8; payload_size];
    let mut pulse = Pulse::zeroed();
    pulse.instruction = Instruction::Data as u16;

    let start = std::time::Instant::now();
    for i in 0..count {
        pulse.monotonic_nanos = pulse_wire_udp::monotonic_nanos();
        pulse.scope = i as u32;
        sender.send(pulse.monotonic_nanos, &pulse, &payload)?;
    }
    Ok(SendStats {
        sent: count,
        elapsed_us: start.elapsed().as_micros(),
    })
}

/// Receive up to `count` pulses on `bind_addr`. Waiting longer than `timeout`
/// for the next pulse ends the loop early and is not an error.
///
/// # Errors
/// [`RecvError::Bind`] when the socket cannot be bound or configured, or
/// [`RecvError::Recv`] when a receive or decode fails.
pub fn recv_pulses(
    bind_addr: SocketAddr,
    count: usize,
    timeout: Duration,
) -> Result<Vec<RecvSummary>, RecvError> {
    let mut receiver = Receiver::bind(bind_addr).map_err(RecvError::Bind)?;
    receiver
        .set_read_timeout(Some(timeout))
        .map_err(RecvError::Bind)?;

    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        match receiver.recv() {
            Ok((pulse, envelope, meta)) => out.push(RecvSummary {
                seq: meta.seq,
                send_ns: meta.send_ns,
                instruction: pulse.instruction_code().to_string(),
                envelope_len: envelope.len(),
            }),
            Err(e) if e.is_timeout() => break,
            Err(e) => return Err(RecvError::Recv(e)),
        }
    }
    Ok(out)
}

/// Errors from [`recv_pulses`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RecvError {
    /// The socket could not be bound or configured.
    #[error("bind failed: {0}")]
    Bind(std::io::Error),
    /// Underlying receiver failed.
    #[error("recv failed: {0}")]
    Recv(#[from] ReceiverError),
}

// The `io::Error` a failed sender bind carries, for `SendError::Bind`.
fn unwrap_io(e: SenderError) -> std::io::Error {
    match e {
        SenderError::Io(io) => io,
        other => std::io::Error::other(other.to_string()),
    }
}
