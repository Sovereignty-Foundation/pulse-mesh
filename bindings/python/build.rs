// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! Build script: link the library as a Python extension module, so that
//! `cargo build` makes a loadable module, as maturin does. The module
//! takes the `_Py*` symbols from the interpreter that loads it, so on
//! macOS the link must leave them undefined (`-undefined dynamic_lookup`);
//! without it the link fails. Elsewhere this adds nothing today.

fn main() {
    pyo3_build_config::add_extension_module_link_args();
}
