// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! The `code` an error thrown or rejected by the binding carries.
//!
//! napi-rs sets a JavaScript error's `code` property from the status of the
//! `napi::Error` it is made from. napi's own statuses name no channel or
//! codec condition, so the binding's errors are `napi::Error<Code>`, whose
//! `code` is one of the names below. `InvalidArg` and `GenericFailure` are
//! napi's own names, so an error that was one of those before keeps its code.
//!
//! A function napi exports returns `Result<T, Code>`, napi's own `Result`
//! with this status type, spelled out: napi's macro recognises a result by
//! its name, so an alias of it would not be thrown as an error.

use napi::bindgen_prelude::*;
use napi_derive::napi;

/// The `code` property of an error the binding throws or rejects with,
/// exported as `ErrorCode`, each value its own name, so a caller can write
/// `err.code === ErrorCode.ChannelClosed`.
#[napi(string_enum, js_name = "ErrorCode")]
#[non_exhaustive]
#[derive(Debug, PartialEq, Eq)]
pub enum Code {
    /// A bad argument, a malformed buffer, or an operation on the wrong or a
    /// closed end: napi's own `InvalidArg`.
    InvalidArg,
    /// A socket, ring or store failure: napi's own `GenericFailure`.
    GenericFailure,
    /// A wait that throws when its time runs out: `Channel.open` finding no
    /// channel, or `Channel.send` finding no room.
    Timeout,
    /// A synchronous receive on an object an asynchronous one is waiting on.
    Busy,
    /// The channel's writer closed it and every message it sent was read.
    ChannelClosed,
    /// A channel message too large for the envelope store's entry.
    EnvelopeTooLarge,
    /// A decoded envelope whose stated id is not the id of its content.
    EnvelopeIdMismatch,
}

impl AsRef<str> for Code {
    fn as_ref(&self) -> &str {
        match self {
            Self::InvalidArg => "InvalidArg",
            Self::GenericFailure => "GenericFailure",
            Self::Timeout => "Timeout",
            Self::Busy => "Busy",
            Self::ChannelClosed => "ChannelClosed",
            Self::EnvelopeTooLarge => "EnvelopeTooLarge",
            Self::EnvelopeIdMismatch => "EnvelopeIdMismatch",
        }
    }
}

/// An error with `code` and `message`.
pub(crate) fn coded(code: Code, message: impl ToString) -> Error<Code> {
    Error::new(code, message)
}

/// The JavaScript error `error` describes, `code` included, wrapped as a
/// plain `napi::Error` so a promise can be rejected with it: a rejection
/// made from a status-typed error alone would carry only napi's statuses.
pub(crate) fn into_js_error(env: Env, error: Error<Code>) -> Error {
    Error::from(JsError::from(error).into_unknown(env))
}
