# API Reference

<p class="pm-kind"><b>Reference</b> · where each API surface is documented and how to generate it</p>

This book is a guided path; the crate- and binding-level API reference is generated straight from source, not duplicated into book chapters where it would drift. Each page in this section covers one surface:

- **Rust**: the workspace's own crates, via rustdoc. `cargo doc --workspace --no-deps --open` builds and opens it; every crate opens with an overview and every public item is documented, which the workspace's `missing_docs` lint enforces. The Rust client for the daemon is documented [in the daemon's book](/docs/daemon/reference/rust.html).
- [Python bindings](python.md): the `pulse_wire` PyO3 module.
- [Node bindings](node.md): the napi-rs module.
- [C bindings](c.md): the `cbindgen`-generated header.

Every page below generates its reference locally from the code actually in this repository.

## Why generate instead of write

Rustdoc and the FFI headers already carry the authoritative signatures, types, and per-item documentation the workspace's `missing_docs` lint enforces (see [Developer Onboarding](../contributing/onboarding.md)). A hand-written API reference in this book would either duplicate that content and drift out of sync, or omit detail the generated reference already has for free. Generating it is also how the gate keeps the pages honest: a generated page that differs from its generator fails the docs check.
