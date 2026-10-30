// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! `pulse send` and `pulse recv` — UDP loopback demo subcommands.

use std::process::ExitCode;
use std::time::Duration;

use anyhow::Context;

/// Implementation of `pulse send` (and `pms send`).
///
/// # Errors
/// Returns an error if `dest` does not parse as a socket address, the local
/// socket cannot be bound, or a datagram cannot be sent.
pub fn run_send(dest: &str, count: usize, payload: usize) -> anyhow::Result<ExitCode> {
    let dest_addr = dest
        .parse()
        .with_context(|| format!("dest is not a socket address: {dest}"))?;
    let stats = crate::ops::udp::send_pulses(dest_addr, count, payload)
        .with_context(|| format!("send to {dest} failed"))?;
    println!(
        "sent {} pulse(s) ({} byte payload each) to {} in {} µs",
        stats.sent, payload, dest_addr, stats.elapsed_us
    );
    Ok(ExitCode::SUCCESS)
}

/// Implementation of `pulse recv` (and `pms recv`).
///
/// # Errors
/// Returns an error if `bind` does not parse as a socket address or the
/// socket cannot be bound; a timeout with nothing received is not an error.
pub fn run_recv(bind: &str, count: usize, timeout_ms: u64, json: bool) -> anyhow::Result<ExitCode> {
    let bind_addr = bind
        .parse()
        .with_context(|| format!("bind is not a socket address: {bind}"))?;
    let timeout = Duration::from_millis(timeout_ms);
    let summaries = crate::ops::udp::recv_pulses(bind_addr, count, timeout)
        .with_context(|| format!("recv on {bind} failed"))?;

    if json {
        println!("{}", serde_json::to_string_pretty(&summaries)?);
    } else if summaries.is_empty() {
        println!("recv timed out after {timeout_ms} ms on {bind_addr} with no pulses");
    } else {
        println!(
            "received {}/{} pulse(s) on {} (timeout {} ms):",
            summaries.len(),
            count,
            bind_addr,
            timeout_ms
        );
        for s in &summaries {
            println!(
                "  seq={:>6}  send_ns={:>20}  inst={:<10}  envelope={} B",
                s.seq, s.send_ns, s.instruction, s.envelope_len
            );
        }
    }
    Ok(ExitCode::SUCCESS)
}
