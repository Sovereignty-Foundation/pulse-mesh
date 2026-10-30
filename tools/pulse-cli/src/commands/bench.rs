// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! `pulse bench` — the throughput and latency of pulses over UDP loopback on this host.

use std::process::ExitCode;

/// Implementation of `pulse bench`.
///
/// # Errors
/// Returns an error if the loopback socket pair cannot be bound or any
/// send/recv operation fails irrecoverably.
pub fn run(count: usize, json: bool) -> anyhow::Result<ExitCode> {
    let s = crate::ops::bench::run_smoke(count)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&s)?);
    } else {
        println!(
            "pulse bench smoke — UDP loopback ({} B payload)",
            s.payload_bytes
        );
        println!("------------------------------------------------");
        println!("pulses sent      {}", s.pulses_sent);
        println!("pulses received  {}", s.pulses_received);
        println!(
            "throughput       {:>10.0} pulses/sec",
            s.throughput_pulses_per_sec
        );
        println!("latency p50      {:>10} ns", s.p50_ns);
        println!("latency p99      {:>10} ns", s.p99_ns);
        println!("latency p99.9    {:>10} ns", s.p999_ns);
        println!();
        println!("These figures are UDP loopback on this host: compare runs here, not machines or systems.");
    }
    Ok(ExitCode::SUCCESS)
}
