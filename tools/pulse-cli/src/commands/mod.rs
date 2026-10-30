// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! The subcommands as they print: each returns the process exit code.
//! Printing is what these do, so the workspace's print lints stop here.

#![allow(clippy::print_stdout, clippy::print_stderr)]

pub mod bench;
pub mod encode_decode;
pub mod send_recv;
pub mod version;
