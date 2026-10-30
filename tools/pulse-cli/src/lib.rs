// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! `pulse`, the standard's own command line, and the operations behind it:
//! encode, decode and verify envelopes; send and receive Pulses over UDP;
//! the loopback smoke bench. Everything here stands on `pulse-canon` and
//! `pulse-wire-udp` alone, so it works with nothing else installed. The
//! daemon's `pms` reaches the same operations and printers through this
//! crate rather than carrying copies.

#![deny(unsafe_code)]

pub mod commands;
pub mod ops;
