// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! Typed operations over the standard: the codec round trip and hex
//! decoding, the UDP send and receive loops, the version stamp and the
//! loopback smoke bench. The `pulse` and `pms` command lines and the
//! `pms-mcp` server are thin shells over them.

pub mod bench;
pub mod codec;
pub mod udp;
pub mod version;
