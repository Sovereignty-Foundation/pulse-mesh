// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! `pulse`: the standard's command line. Encode, decode and verify
//! envelopes, send and receive Pulses over UDP, print the version stamp,
//! run the loopback smoke bench. Nothing here needs a daemon.
#![forbid(unsafe_code)]
#![allow(clippy::print_stdout, clippy::print_stderr)]

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(
    name = "pulse",
    version,
    about = "Pulse Mesh: the standard's command line"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Encode a JSON envelope spec and report the canonical wire bytes.
    Encode {
        /// Path to a JSON spec file (schema: `EnvelopeSpec` in
        /// `pulse_cli::commands::encode_decode`).
        #[arg(long = "json", value_name = "FILE")]
        json_path: PathBuf,
        /// Emit JSON instead of human-readable output.
        #[arg(long = "json-out")]
        json_out: bool,
    },
    /// Decode canonical wire hex back into an envelope summary, verifying it.
    ///
    /// Exits with status 1 when the envelope does not verify: its content
    /// does not produce the identifier it carries.
    Decode {
        /// Hex string (whitespace trimmed).
        hex: String,
        /// Emit JSON instead of human-readable output.
        #[arg(long)]
        json: bool,
    },
    /// Print the workspace and codec version stamp.
    Version {
        /// Emit JSON instead of human-readable output.
        #[arg(long)]
        json: bool,
    },
    /// Send pulses to a UDP destination.
    Send {
        /// Destination address (e.g. 127.0.0.1:9000).
        dest: String,
        /// Number of pulses to send.
        #[arg(long, default_value_t = 1)]
        count: usize,
        /// Envelope payload size in bytes.
        #[arg(long, default_value_t = 16)]
        payload: usize,
    },
    /// Bind a UDP address and print received pulses.
    Recv {
        /// Local bind address (e.g. 127.0.0.1:9000).
        bind: String,
        /// Maximum pulses to receive before exiting.
        #[arg(long, default_value_t = 1)]
        count: usize,
        /// Per-recv timeout in milliseconds.
        #[arg(long, default_value_t = 5000)]
        timeout_ms: u64,
        /// Emit JSON instead of human-readable output.
        #[arg(long)]
        json: bool,
    },
    /// Throughput and latency of pulses over UDP loopback on this host.
    Bench {
        /// Number of pulses to send through the loopback.
        #[arg(long, default_value_t = pulse_cli::ops::bench::DEFAULT_PULSE_COUNT)]
        count: usize,
        /// Emit JSON instead of human-readable output.
        #[arg(long)]
        json: bool,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Encode {
            json_path,
            json_out,
        } => pulse_cli::commands::encode_decode::run_encode(&json_path, json_out),
        Command::Decode { hex, json } => pulse_cli::commands::encode_decode::run_decode(&hex, json),
        Command::Version { json } => pulse_cli::commands::version::run("pulse (pulse-cli)", json),
        Command::Send {
            dest,
            count,
            payload,
        } => pulse_cli::commands::send_recv::run_send(&dest, count, payload),
        Command::Recv {
            bind,
            count,
            timeout_ms,
            json,
        } => pulse_cli::commands::send_recv::run_recv(&bind, count, timeout_ms, json),
        Command::Bench { count, json } => pulse_cli::commands::bench::run(count, json),
    };
    match result {
        Ok(code) => code,
        Err(e) => {
            eprintln!("pulse: {e:#}");
            ExitCode::from(2)
        }
    }
}
