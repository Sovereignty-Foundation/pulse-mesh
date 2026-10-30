// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! Example 02 — UDP loopback round-trip (Rust).
//!
//! Spawns a receiver thread on `127.0.0.1:0` (kernel-chosen port), sends
//! `N` pulses to it, asserts every pulse arrives. Mirrors what `pms send`
//! and `pms recv` do as separate binaries, in one process for end-to-end
//! verification.
#![forbid(unsafe_code)]
// This is an end-to-end example demonstrating loopback UDP — the
// expected control flow is "everything works, prints a summary line,
// exits 0." `unwrap`, `expect`, `panic!`, and `println!` are
// intentional fail-fast / output idioms for this demonstration shape
// rather than real failure modes to surface; see the production
// `pms send` / `pms recv` paths for the equivalent error-propagating
// signatures.
#![allow(
    clippy::print_stdout,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

use std::time::Duration;

use pulse_canon::{Instruction, Pulse};
use pulse_wire_udp::{Receiver, Sender};

const PULSE_COUNT: usize = 1_000;
const PAYLOAD: &[u8] = b"loopback";

fn main() {
    let mut receiver = Receiver::bind("127.0.0.1:0").expect("bind receiver");
    receiver
        .set_read_timeout(Some(Duration::from_millis(2_000)))
        .expect("set timeout");
    let recv_addr = receiver.local_addr().expect("recv local_addr");

    let recv_handle = std::thread::spawn(move || -> usize {
        let mut got = 0usize;
        for _ in 0..PULSE_COUNT {
            match receiver.recv() {
                Ok(_) => got += 1,
                Err(e) if e.is_timeout() => break,
                Err(e) => panic!("recv: {e}"),
            }
        }
        got
    });

    let mut sender = Sender::bind("127.0.0.1:0").expect("bind sender");
    sender.connect(recv_addr).expect("connect");

    let mut pulse = Pulse::zeroed();
    pulse.instruction = Instruction::Data as u16;
    for i in 0..PULSE_COUNT {
        pulse.monotonic_nanos = pulse_wire_udp::monotonic_nanos();
        pulse.scope = i as u32;
        sender
            .send(pulse.monotonic_nanos, &pulse, PAYLOAD)
            .expect("send");
    }

    let received = recv_handle.join().expect("recv thread");
    assert_eq!(received, PULSE_COUNT, "all pulses must arrive on loopback");
    println!(
        "OK — {} pulses sent and received on {} ({} B payload each).",
        PULSE_COUNT,
        recv_addr,
        PAYLOAD.len()
    );
}
