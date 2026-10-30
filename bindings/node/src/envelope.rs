// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! The canonical `PulseEnvelope` codec (chapter 3 of the specification):
//! `encodeEnvelope`, `decodeEnvelope` and `envelopeId`, each the Rust codec
//! in `pulse-canon` itself, so the bytes are the Rust and Python bindings'.
//!
//! An envelope is described in JavaScript as
//! `{ envelopeType, typeName?, payload, origin?, monotonicNanos?, flags? }`,
//! where `payload` is a Buffer (a raw payload) or an array of envelopes
//! described the same way (a nested one). The id is always computed from
//! the type, the type name and the payload, never given.

use napi::bindgen_prelude::*;
use napi::{JsNumber, JsObject, JsString, JsUnknown, ValueType};
use napi_derive::napi;

use pulse_wire_core::envelope::MAX_NESTING_DEPTH;
use pulse_wire_core::{PayloadData, PulseEnvelope, PulseEnvelopeFlags};

use crate::bigint_u64;
use crate::error::{coded, Code};

/// An envelope as `encodeEnvelope` and `envelopeId` take it, declared here
/// for the type napi-rs writes into `index.d.ts`. The functions read the
/// object themselves rather than through this struct, so that its nesting
/// is bounded as the decoder bounds it and an error names the field at
/// fault.
#[napi(object, object_to_js = false)]
pub struct EnvelopeInput {
    /// The numeric envelope type (0 to 65535); 0 for an envelope routed by
    /// `typeName` alone.
    pub envelope_type: u32,
    /// The string routing key, if any.
    #[napi(ts_type = "string | null")]
    pub type_name: Option<String>,
    /// A Buffer for a raw payload, or the nested envelopes (at most 32
    /// levels deep).
    #[napi(ts_type = "Buffer | EnvelopeInput[]")]
    pub payload: JsUnknown,
    /// The 16-byte origin node identifier; zeros when omitted.
    pub origin: Option<Buffer>,
    /// The producer's monotonic clock in nanoseconds; 0 when omitted.
    pub monotonic_nanos: Option<BigInt>,
    /// The flags word, of the defined bits only (`BROADCAST` 1,
    /// `ACK_REQUIRED` 2, `PRIORITY` 4, `COMPRESSED` 8); 0 when omitted.
    pub flags: Option<u32>,
}

/// An envelope `decodeEnvelope` returns: its stated id, verified, and its
/// fields. `payload` is a Buffer for a raw payload and an array of decoded
/// envelopes for a nested one.
#[napi(object, object_from_js = false)]
pub struct DecodedEnvelope {
    /// The 16-byte content id.
    pub id: Buffer,
    /// The numeric envelope type (0 to 65535).
    pub envelope_type: u32,
    /// The string routing key, or `null`.
    #[napi(ts_type = "string | null")]
    pub type_name: Either<String, Null>,
    /// The payload: a Buffer (raw) or the nested envelopes.
    #[napi(ts_type = "Buffer | DecodedEnvelope[]")]
    pub payload: Either<Buffer, Vec<DecodedEnvelope>>,
    /// The 16-byte origin node identifier.
    pub origin: Buffer,
    /// The producer's monotonic clock in nanoseconds.
    pub monotonic_nanos: BigInt,
    /// The flags word: `BROADCAST` 1, `ACK_REQUIRED` 2, `PRIORITY` 4,
    /// `COMPRESSED` 8.
    pub flags: u32,
}

/// The canonical bytes of the envelope `envelope` describes:
/// `{ envelopeType, typeName?, payload, origin?, monotonicNanos?, flags? }`,
/// with `payload` a Buffer or an array of envelopes described the same way.
/// The id is computed from the type, the type name and the payload. Throws
/// `InvalidArg` for a description that is not an envelope's.
#[napi(ts_args_type = "envelope: EnvelopeInput")]
pub fn encode_envelope(envelope: JsObject) -> Result<Buffer> {
    Ok(envelope_from_js(&envelope, 0)?.to_canonical_bytes().into())
}

/// The 16-byte content id of the envelope `envelope` describes, as
/// `encodeEnvelope` would write it: the BLAKE3 hash of the
/// `pulse-envelope-id/v2` preimage of its type, type name and payload,
/// truncated. The origin, the clock and the flags are not hashed, but a
/// nested child's are, as part of the payload's bytes.
#[napi(ts_args_type = "envelope: EnvelopeInput")]
pub fn envelope_id(envelope: JsObject) -> Result<Buffer> {
    Ok(envelope_from_js(&envelope, 0)?.id().0.to_vec().into())
}

/// Decode exactly one envelope's canonical bytes and check that the id each
/// envelope in it states, nested ones included, is the id of its content.
/// Throws `InvalidArg` for bytes that are not one envelope's canonical
/// encoding (trailing bytes included) and `EnvelopeIdMismatch` for a stated
/// id that is not its content's.
#[napi]
pub fn decode_envelope(bytes: Buffer) -> Result<DecodedEnvelope, Code> {
    let envelope = PulseEnvelope::from_canonical_bytes(&bytes)
        .map_err(|e| coded(Code::InvalidArg, format!("not a canonical envelope: {e}")))?;
    verify(&envelope, "the envelope")?;
    Ok(into_js(envelope))
}

/// `envelope`'s id checked against its content, then each nested child's;
/// `at` names the envelope in the error.
fn verify(envelope: &PulseEnvelope, at: &str) -> Result<(), Code> {
    if !envelope.verify() {
        return Err(coded(
            Code::EnvelopeIdMismatch,
            format!(
                "{at} states id {} but its content's id is {}",
                envelope.id().to_hex(),
                PulseEnvelope::with_content(
                    envelope.envelope_type(),
                    envelope.type_name().map(str::to_owned),
                    envelope.payload().clone(),
                )
                .id()
                .to_hex()
            ),
        ));
    }
    if let Some(children) = envelope.payload().as_nested() {
        for (index, child) in children.iter().enumerate() {
            verify(child, &format!("{at}'s nested child {index}"))?;
        }
    }
    Ok(())
}

fn into_js(envelope: PulseEnvelope) -> DecodedEnvelope {
    let id = envelope.id().0.to_vec().into();
    let envelope_type = u32::from(envelope.envelope_type());
    let type_name = match envelope.type_name() {
        Some(name) => Either::A(name.to_owned()),
        None => Either::B(Null),
    };
    let origin = envelope.origin.to_vec().into();
    let monotonic_nanos = BigInt::from(envelope.monotonic_nanos);
    let flags = u32::from(envelope.flags.bits());
    let payload = match envelope.into_payload() {
        PayloadData::Raw(bytes) => Either::A(bytes.into()),
        PayloadData::Nested(children) => Either::B(children.into_iter().map(into_js).collect()),
    };
    DecodedEnvelope {
        id,
        envelope_type,
        type_name,
        payload,
        origin,
        monotonic_nanos,
        flags,
    }
}

/// The envelope `object` describes, at nesting depth `depth`.
fn envelope_from_js(object: &JsObject, depth: usize) -> Result<PulseEnvelope> {
    if depth > MAX_NESTING_DEPTH {
        return Err(invalid(format!(
            "an envelope nests deeper than {MAX_NESTING_DEPTH} levels, which the decoder refuses"
        )));
    }
    let envelope_type = match property(object, "envelopeType")? {
        Some(value) if value.get_type()? == ValueType::Number => {
            let number = JsNumber::try_from(value)?.get_double()?;
            if number.fract() != 0.0 || !(0.0..=f64::from(u16::MAX)).contains(&number) {
                return Err(invalid(format!(
                    "envelopeType must be an integer from 0 to 65535, got {number}"
                )));
            }
            number as u16
        }
        _ => return Err(invalid("envelopeType must be a number from 0 to 65535")),
    };
    let type_name = match property(object, "typeName")? {
        None => None,
        Some(value) if value.get_type()? == ValueType::String => {
            Some(JsString::try_from(value)?.into_utf8()?.into_owned()?)
        }
        Some(_) => return Err(invalid("typeName must be a string, null or undefined")),
    };
    let payload = match property(object, "payload")? {
        Some(value) if value.is_buffer()? => PayloadData::Raw(buffer_bytes(object, "payload")?),
        Some(value) if value.is_array()? => {
            let children = JsObject::try_from(value)?;
            let count = children.get_array_length()?;
            // Grown as the children are read, not reserved for `count`: a
            // sparse array's length need not be its children.
            let mut nested = Vec::new();
            for index in 0..count {
                let child: JsUnknown = children.get_element(index)?;
                if child.get_type()? != ValueType::Object || child.is_buffer()? {
                    return Err(invalid(format!(
                        "nested payload element {index} must be an envelope object"
                    )));
                }
                nested.push(envelope_from_js(&JsObject::try_from(child)?, depth + 1)?);
            }
            PayloadData::Nested(nested)
        }
        _ => {
            return Err(invalid(
                "payload must be a Buffer (raw) or an array of envelopes (nested)",
            ))
        }
    };
    let mut envelope = PulseEnvelope::with_content(envelope_type, type_name, payload);
    if let Some(value) = property(object, "origin")? {
        if !value.is_buffer()? {
            return Err(invalid("origin must be a 16-byte Buffer"));
        }
        let origin = buffer_bytes(object, "origin")?;
        envelope.origin = origin.as_slice().try_into().map_err(|_| {
            invalid(format!(
                "origin must be exactly 16 bytes (got {})",
                origin.len()
            ))
        })?;
    }
    if let Some(value) = property(object, "monotonicNanos")? {
        if value.get_type()? != ValueType::BigInt {
            return Err(invalid(
                "monotonicNanos must be a BigInt from 0 to 2^64 - 1",
            ));
        }
        if let Some(nanos) = object.get::<_, BigInt>("monotonicNanos")? {
            envelope.monotonic_nanos = bigint_u64(&nanos, "monotonicNanos")?;
        }
    }
    if let Some(value) = property(object, "flags")? {
        let bits = match value.get_type()? {
            ValueType::Number => JsNumber::try_from(value)?.get_double()?,
            _ => f64::NAN,
        };
        envelope.flags = (bits.fract() == 0.0 && (0.0..=f64::from(u16::MAX)).contains(&bits))
            .then(|| PulseEnvelopeFlags::from_bits(bits as u16))
            .flatten()
            .ok_or_else(|| {
                invalid(format!(
                    "flags must be an integer of the defined bits (BROADCAST 1, ACK_REQUIRED 2, \
                     PRIORITY 4, COMPRESSED 8), got {bits}"
                ))
            })?;
    }
    Ok(envelope)
}

/// `object[name]`, or `None` when it is `undefined` or `null`.
fn property(object: &JsObject, name: &str) -> Result<Option<JsUnknown>> {
    match object.get::<_, JsUnknown>(name)? {
        Some(value) if value.get_type()? == ValueType::Null => Ok(None),
        value => Ok(value),
    }
}

/// A copy of the bytes of `object[name]`, a Buffer. Read as napi's `Buffer`,
/// which takes an empty Buffer's null data pointer as no bytes: the older
/// `JsBuffer::into_value` makes a `Vec` of it, which a debug build aborts on.
fn buffer_bytes(object: &JsObject, name: &str) -> Result<Vec<u8>> {
    Ok(object
        .get::<_, Buffer>(name)?
        .map(|bytes| bytes.to_vec())
        .unwrap_or_default())
}

fn invalid(message: impl ToString) -> Error {
    Error::new(Status::InvalidArg, message)
}
