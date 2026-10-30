// SPDX-License-Identifier: LicenseRef-Proprietary
//! napi-build: generates the `.node` binding metadata at build time.
extern crate napi_build;

fn main() {
    napi_build::setup();
}
