// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! WebAssembly binding for the Pulse Mesh canonical codec.
//!
//! Exposes `pulse-canon` to JavaScript so a page can encode, decode, verify
//! and content-address envelopes, decode 128-byte Pulses, and re-run the
//! conformance fixtures against the reference implementation itself. Codec
//! only: no ring, no store, no transport, no I/O.
//!
//! Every function takes and returns plain data (byte slices, strings, JSON
//! text) so the JavaScript side needs no generated classes. Values that do
//! not fit a JavaScript number losslessly (`u64` fields) are rendered as
//! decimal strings.
//!
//! Build with `./build.sh` in this directory; it emits an ES module plus the
//! `.wasm` into `pkg/` (or the directory given as the first argument).

use pulse_canon::{
    HeartbeatPayload, Instruction, NodeId, PayloadData, Pulse, PulseEnvelope, PulseEnvelopeFlags,
    PulseEnvelopeId, PULSE_WIRE_SIZE,
};
use serde::Deserialize;
use serde_json::{json, Value};
use wasm_bindgen::prelude::*;

/// Version of the codec this binding wraps (the binding tracks it 1:1).
#[wasm_bindgen]
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

// ---------------------------------------------------------------------------
// Small parsers shared by the JSON entry points
// ---------------------------------------------------------------------------

fn err(msg: impl Into<String>) -> JsError {
    JsError::new(&msg.into())
}

fn parse_u64(v: &Value, what: &str) -> Result<u64, JsError> {
    match v {
        Value::Null => Ok(0),
        Value::Number(n) => n.as_u64().ok_or_else(|| err(format!("{what}: not a u64"))),
        Value::String(s) => {
            let s = s.trim();
            if let Some(h) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
                u64::from_str_radix(h, 16).map_err(|_| err(format!("{what}: bad hex")))
            } else {
                s.parse::<u64>()
                    .map_err(|_| err(format!("{what}: bad number")))
            }
        }
        _ => Err(err(format!("{what}: expected a number or string"))),
    }
}

fn parse_u16(v: &Value, what: &str) -> Result<u16, JsError> {
    u16::try_from(parse_u64(v, what)?).map_err(|_| err(format!("{what}: exceeds u16")))
}

/// A flags word, refused when it sets a reserved bit (4 to 15), as the
/// canonical decoder refuses one: an envelope built from it would encode
/// bytes no decoder accepts, and dropping the bits would build another
/// envelope than the one described.
fn parse_flags(v: &Value, what: &str) -> Result<PulseEnvelopeFlags, JsError> {
    let bits = parse_u16(v, what)?;
    PulseEnvelopeFlags::from_bits(bits).ok_or_else(|| {
        err(format!(
            "{what}: {bits:#06x} sets reserved bits {:#06x}; only bits 0 to 3 are defined",
            bits & !PulseEnvelopeFlags::all().bits()
        ))
    })
}

fn parse_u32(v: &Value, what: &str) -> Result<u32, JsError> {
    u32::try_from(parse_u64(v, what)?).map_err(|_| err(format!("{what}: exceeds u32")))
}

fn parse_hex(v: &Value, what: &str) -> Result<Vec<u8>, JsError> {
    match v {
        Value::Null => Ok(Vec::new()),
        Value::String(s) => {
            hex::decode(s.trim().trim_start_matches("0x")).map_err(|e| err(format!("{what}: {e}")))
        }
        _ => Err(err(format!("{what}: expected a hex string"))),
    }
}

fn parse_hex_array<const N: usize>(v: &Value, what: &str) -> Result<[u8; N], JsError> {
    let bytes = parse_hex(v, what)?;
    if bytes.is_empty() {
        return Ok([0u8; N]);
    }
    <[u8; N]>::try_from(bytes).map_err(|_| err(format!("{what}: expected {N} bytes")))
}

fn flag_names(flags: PulseEnvelopeFlags) -> Vec<&'static str> {
    let mut names = Vec::new();
    if flags.contains(PulseEnvelopeFlags::BROADCAST) {
        names.push("BROADCAST");
    }
    if flags.contains(PulseEnvelopeFlags::ACK_REQUIRED) {
        names.push("ACK_REQUIRED");
    }
    if flags.contains(PulseEnvelopeFlags::PRIORITY) {
        names.push("PRIORITY");
    }
    if flags.contains(PulseEnvelopeFlags::COMPRESSED) {
        names.push("COMPRESSED");
    }
    names
}

// ---------------------------------------------------------------------------
// Envelopes
// ---------------------------------------------------------------------------

/// JSON description of an envelope to encode. Every field is optional.
#[derive(Deserialize, Default)]
struct EnvelopeSpec {
    #[serde(default)]
    envelope_type: Value,
    #[serde(default)]
    type_name: Option<String>,
    #[serde(default)]
    flags: Value,
    #[serde(default)]
    origin_hex: Value,
    #[serde(default)]
    monotonic_nanos: Value,
    #[serde(default)]
    payload_hex: Value,
    #[serde(default)]
    payload_text: Option<String>,
    #[serde(default)]
    nested: Option<Vec<EnvelopeSpec>>,
}

fn build_envelope(spec: &EnvelopeSpec) -> Result<PulseEnvelope, JsError> {
    let envelope_type = parse_u16(&spec.envelope_type, "envelope_type")?;
    let payload = match (&spec.nested, &spec.payload_text) {
        (Some(children), _) => PayloadData::Nested(
            children
                .iter()
                .map(build_envelope)
                .collect::<Result<Vec<_>, _>>()?,
        ),
        (None, Some(text)) => PayloadData::Raw(text.as_bytes().to_vec()),
        (None, None) => PayloadData::Raw(parse_hex(&spec.payload_hex, "payload_hex")?),
    };
    let mut envelope = PulseEnvelope::with_content(envelope_type, spec.type_name.clone(), payload);
    envelope.origin = parse_hex_array::<16>(&spec.origin_hex, "origin_hex")?;
    envelope.monotonic_nanos = parse_u64(&spec.monotonic_nanos, "monotonic_nanos")?;
    envelope.flags = parse_flags(&spec.flags, "flags")?;
    Ok(envelope)
}

fn envelope_json(e: &PulseEnvelope) -> Value {
    let payload = match e.payload() {
        PayloadData::Raw(bytes) => json!({
            "variant": "Raw",
            "hex": hex::encode(bytes),
            "len": bytes.len(),
        }),
        PayloadData::Nested(children) => json!({
            "variant": "Nested",
            "count": children.len(),
            "children": children.iter().map(envelope_json).collect::<Vec<_>>(),
        }),
    };
    json!({
        "id_hex": e.id().to_hex(),
        "origin_hex": hex::encode(e.origin),
        "monotonic_nanos": e.monotonic_nanos.to_string(),
        "envelope_type": e.envelope_type(),
        "envelope_type_hex": format!("0x{:04x}", e.envelope_type()),
        "type_name": e.type_name(),
        "effective_type_name": e.effective_type_name(),
        "flags": e.flags.bits(),
        "flag_names": flag_names(e.flags),
        "payload": payload,
        "payload_len": e.payload_len(),
        "canonical_size": e.canonical_size(),
        "verified": e.verify(),
    })
}

/// Encode an envelope described as JSON into its canonical wire bytes.
///
/// Fields: `envelope_type` (number or `"0x0001"`), `type_name`, `flags`,
/// `origin_hex` (16 bytes), `monotonic_nanos`, and one of `payload_hex`,
/// `payload_text` or `nested` (an array of the same shape).
#[wasm_bindgen]
pub fn envelope_encode(spec_json: &str) -> Result<Vec<u8>, JsError> {
    let spec: EnvelopeSpec = serde_json::from_str(spec_json).map_err(|e| err(e.to_string()))?;
    Ok(build_envelope(&spec)?.to_canonical_bytes())
}

/// Encode an envelope described as JSON and return its decoded description
/// (id, sizes, flags, payload tree) together with the canonical hex.
#[wasm_bindgen]
pub fn envelope_describe(spec_json: &str) -> Result<String, JsError> {
    let spec: EnvelopeSpec = serde_json::from_str(spec_json).map_err(|e| err(e.to_string()))?;
    let env = build_envelope(&spec)?;
    let mut v = envelope_json(&env);
    v["canonical_hex"] = Value::String(hex::encode(env.to_canonical_bytes()));
    Ok(v.to_string())
}

/// Decode canonical wire bytes into a JSON description of the envelope.
#[wasm_bindgen]
pub fn envelope_decode(bytes: &[u8]) -> Result<String, JsError> {
    let env = PulseEnvelope::from_canonical_bytes(bytes).map_err(|e| err(e.to_string()))?;
    Ok(envelope_json(&env).to_string())
}

/// Recompute the content id of canonical bytes and compare it with the id
/// they carry.
#[wasm_bindgen]
pub fn envelope_verify(bytes: &[u8]) -> Result<bool, JsError> {
    let env = PulseEnvelope::from_canonical_bytes(bytes).map_err(|e| err(e.to_string()))?;
    Ok(env.verify())
}

/// The 16-byte content id, as hex, of `(envelope_type, type_name, payload)`.
#[wasm_bindgen]
pub fn envelope_id_hex(envelope_type: u16, type_name: Option<String>, payload: &[u8]) -> String {
    PulseEnvelopeId::compute_from_payload(
        envelope_type,
        type_name.as_deref(),
        &PayloadData::Raw(payload.to_vec()),
    )
    .to_hex()
}

/// The domain tag mixed into every envelope id.
#[wasm_bindgen]
pub fn envelope_id_domain_tag() -> String {
    String::from_utf8_lossy(pulse_canon::ENVELOPE_ID_DOMAIN_TAG).into_owned()
}

// ---------------------------------------------------------------------------
// Pulses
// ---------------------------------------------------------------------------

fn heartbeat_json(hb: &HeartbeatPayload) -> Value {
    json!({
        "schema_version": hb.schema_version.to_string(),
        "uptime_ms": hb.uptime_ms.to_string(),
        "error_count": hb.error_count,
        "stage_count": hb.stage_count,
        "path_count": hb.path_count,
        "consecutive_errors": hb.consecutive_errors,
        "wake_state": hb.wake_state,
        "health_state": hb.health_state,
    })
}

/// The 128-byte Pulse layout: field name, byte offset, byte size, cache line.
#[wasm_bindgen]
pub fn pulse_layout() -> String {
    let fields = [
        ("seq_lock", Pulse::SEQ_LOCK_OFFSET, 8),
        ("origin_id", std::mem::offset_of!(Pulse, origin_id), 16),
        (
            "monotonic_nanos",
            std::mem::offset_of!(Pulse, monotonic_nanos),
            8,
        ),
        ("chain_step", std::mem::offset_of!(Pulse, chain_step), 8),
        ("instruction", std::mem::offset_of!(Pulse, instruction), 2),
        ("_pad0", std::mem::offset_of!(Pulse, _pad0), 2),
        ("scope", std::mem::offset_of!(Pulse, scope), 4),
        (
            "envelope_ref",
            std::mem::offset_of!(Pulse, envelope_ref),
            16,
        ),
        ("preimage", std::mem::offset_of!(Pulse, preimage), 32),
        ("_pad2", std::mem::offset_of!(Pulse, _pad2), 32),
    ];
    let rows: Vec<Value> = fields
        .iter()
        .map(|(name, offset, size)| {
            json!({ "field": name, "offset": offset, "size": size, "cache_line": offset / 64 + 1 })
        })
        .collect();
    json!({ "size": PULSE_WIRE_SIZE, "align": std::mem::align_of::<Pulse>(), "fields": rows })
        .to_string()
}

/// Decode a 128-byte Pulse into its fields (u64 fields as decimal strings).
#[wasm_bindgen]
pub fn pulse_decode(bytes: &[u8]) -> Result<String, JsError> {
    let pulse = Pulse::from_bytes(bytes).ok_or_else(|| err("a Pulse is exactly 128 bytes"))?;
    Ok(json!({
        "seq_lock": pulse.seq_lock().to_string(),
        "origin_id_hex": hex::encode(pulse.origin_id),
        "monotonic_nanos": pulse.monotonic_nanos.to_string(),
        "chain_step": pulse.chain_step.to_string(),
        "instruction": pulse.instruction,
        "instruction_name": format!("{:?}", pulse.instruction_code()),
        "scope": pulse.scope,
        "scope_hex": format!("0x{:08x}", pulse.scope),
        "envelope_ref_hex": hex::encode(pulse.envelope_ref),
        "has_envelope": pulse.has_envelope(),
        "preimage_hex": hex::encode(pulse.preimage),
        "pad2_hex": hex::encode(pulse._pad2),
        "heartbeat": pulse.heartbeat_payload().as_ref().map(heartbeat_json),
    })
    .to_string())
}

/// Build a Pulse from a JSON description and return its 128 wire bytes.
///
/// Fields (all optional): `origin_id_hex`, `monotonic_nanos`, `chain_step`,
/// `instruction` (number, `"0x0001"`, or `"Heartbeat (0x0001)"`), `scope`
/// or `scope_hex`, `envelope_ref_hex`, `preimage_hex`, `heartbeat_overlay`.
#[wasm_bindgen]
pub fn pulse_encode(spec_json: &str) -> Result<Vec<u8>, JsError> {
    let spec: Value = serde_json::from_str(spec_json).map_err(|e| err(e.to_string()))?;
    Ok(build_pulse(&spec)?.as_bytes().to_vec())
}

fn parse_instruction(v: &Value) -> Result<u16, JsError> {
    if let Value::String(s) = v {
        if let (Some(open), Some(close)) = (s.find('('), s.find(')')) {
            if open < close {
                return parse_u16(
                    &Value::String(s[open + 1..close].to_string()),
                    "instruction",
                );
            }
        }
    }
    parse_u16(v, "instruction")
}

fn build_pulse(spec: &Value) -> Result<Pulse, JsError> {
    let mut pulse = Pulse::zeroed();
    pulse.origin_id = parse_hex_array::<16>(&spec["origin_id_hex"], "origin_id_hex")?;
    pulse.monotonic_nanos = parse_u64(&spec["monotonic_nanos"], "monotonic_nanos")?;
    pulse.chain_step = parse_u64(&spec["chain_step"], "chain_step")?;
    pulse.scope = if spec["scope_hex"].is_null() {
        parse_u32(&spec["scope"], "scope")?
    } else {
        parse_u32(&spec["scope_hex"], "scope_hex")?
    };
    pulse.envelope_ref = parse_hex_array::<16>(&spec["envelope_ref_hex"], "envelope_ref_hex")?;
    pulse.preimage = parse_hex_array::<32>(&spec["preimage_hex"], "preimage_hex")?;
    if let Some(hb) = spec.get("heartbeat_overlay").filter(|v| !v.is_null()) {
        let overlay = HeartbeatPayload {
            schema_version: parse_u64(&hb["schema_version"], "schema_version")?,
            uptime_ms: parse_u64(&hb["uptime_ms"], "uptime_ms")?,
            error_count: parse_u32(&hb["error_count"], "error_count")?,
            stage_count: parse_u16(&hb["stage_count"], "stage_count")?,
            path_count: parse_u16(&hb["path_count"], "path_count")?,
            consecutive_errors: parse_u16(&hb["consecutive_errors"], "consecutive_errors")?,
            wake_state: u8::try_from(parse_u64(&hb["wake_state"], "wake_state")?)
                .map_err(|_| err("wake_state: exceeds u8"))?,
            health_state: u8::try_from(parse_u64(&hb["health_state"], "health_state")?)
                .map_err(|_| err("health_state: exceeds u8"))?,
            _reserved: [0u8; 4],
        };
        pulse.set_heartbeat_payload(&overlay);
    }
    if !spec["instruction"].is_null() {
        pulse.instruction = parse_instruction(&spec["instruction"])?;
    }
    Ok(pulse)
}

// ---------------------------------------------------------------------------
// Conformance fixtures
// ---------------------------------------------------------------------------

fn fixture_envelope(node: &Value) -> Result<PulseEnvelope, JsError> {
    let envelope_type = parse_u16(&node["envelope_type"], "envelope_type")?;
    let type_name = node["type_name"].as_str().map(str::to_string);
    let payload = if node["payload_variant"].as_str() == Some("Nested") {
        let children = node["children"]
            .as_array()
            .ok_or_else(|| err("Nested fixture node without children"))?;
        PayloadData::Nested(
            children
                .iter()
                .map(fixture_envelope)
                .collect::<Result<Vec<_>, _>>()?,
        )
    } else {
        PayloadData::Raw(parse_hex(&node["payload_hex"], "payload_hex")?)
    };
    let mut envelope = PulseEnvelope::with_content(envelope_type, type_name, payload);
    envelope.origin = parse_hex_array::<16>(&node["origin_hex"], "origin_hex")?;
    envelope.monotonic_nanos = parse_u64(&node["monotonic_nanos"], "monotonic_nanos")?;
    envelope.flags = parse_flags(&node["flags"], "flags")?;
    Ok(envelope)
}

fn collect_node_ids(node: &Value, env: &PulseEnvelope, out: &mut Vec<Value>) {
    if let Some(expected) = node["id_hex"].as_str() {
        out.push(json!({
            "envelope_type_hex": format!("0x{:04x}", env.envelope_type()),
            "expected": expected,
            "actual": env.id().to_hex(),
            "ok": expected.eq_ignore_ascii_case(&env.id().to_hex()),
        }));
    }
    if let (Some(children), PayloadData::Nested(envs)) =
        (node["children"].as_array(), env.payload())
    {
        for (child, child_env) in children.iter().zip(envs) {
            collect_node_ids(child, child_env, out);
        }
    }
}

/// Re-run one conformance fixture from `pulse/pulse-spec/test-vectors/`.
///
/// `fixture_json` is the fixture's `.json` text; `expected_hex` is the
/// companion `.hex` text (optional for envelope fixtures, which also carry
/// `expected.canonical_hex`). Returns a JSON report: overall `ok`, the
/// canonical bytes this binding produced, and one entry per check.
#[wasm_bindgen]
pub fn check_fixture(fixture_json: &str, expected_hex: Option<String>) -> Result<String, JsError> {
    let fx: Value = serde_json::from_str(fixture_json).map_err(|e| err(e.to_string()))?;
    let name = fx["name"].as_str().unwrap_or("fixture").to_string();
    let expected_hex = expected_hex
        .map(|h| h.trim().to_lowercase())
        .filter(|h| !h.is_empty())
        .or_else(|| {
            fx["expected"]["canonical_hex"]
                .as_str()
                .map(|s| s.to_lowercase())
        });
    let mut checks: Vec<Value> = Vec::new();
    let mut push = |check: &str, expected: String, actual: String| {
        let ok = expected.eq_ignore_ascii_case(&actual);
        checks.push(json!({ "check": check, "expected": expected, "actual": actual, "ok": ok }));
    };

    let (kind, actual_hex) = if fx["inputs"]["instruction"].is_string() {
        let pulse = build_pulse(&fx["inputs"])?;
        let bytes = pulse.as_bytes();
        push(
            "size_bytes",
            fx["expected"]["size_bytes"].to_string(),
            bytes.len().to_string(),
        );
        ("pulse", hex::encode(bytes))
    } else {
        let (node, env) = if fx["structure"]["outer"].is_object() {
            let node = &fx["structure"]["outer"];
            (node.clone(), fixture_envelope(node)?)
        } else {
            let node = &fx["inputs"];
            (node.clone(), fixture_envelope(node)?)
        };
        let bytes = env.to_canonical_bytes();
        if let Some(id) = fx["expected"]["id_hex"].as_str() {
            push("id_hex", id.to_string(), env.id().to_hex());
        }
        push(
            "size_bytes",
            fx["expected"]["size_bytes"].to_string(),
            bytes.len().to_string(),
        );
        push("verify", "true".to_string(), env.verify().to_string());
        let decoded =
            PulseEnvelope::from_canonical_bytes(&bytes).map_err(|e| err(e.to_string()))?;
        push("round_trip_id", env.id().to_hex(), decoded.id().to_hex());
        let mut node_ids = Vec::new();
        collect_node_ids(&node, &env, &mut node_ids);
        for entry in node_ids {
            let expected = entry["expected"].as_str().unwrap_or_default().to_string();
            let actual = entry["actual"].as_str().unwrap_or_default().to_string();
            push(
                &format!(
                    "node_id {}",
                    entry["envelope_type_hex"].as_str().unwrap_or("")
                ),
                expected,
                actual,
            );
        }
        ("envelope", hex::encode(bytes))
    };
    if let Some(expected) = expected_hex {
        push("canonical_hex", expected, actual_hex.clone());
    }
    let ok = checks.iter().all(|c| c["ok"].as_bool() == Some(true));
    Ok(json!({ "name": name, "kind": kind, "ok": ok, "canonical_hex": actual_hex, "checks": checks }).to_string())
}

// ---------------------------------------------------------------------------
// Nodes
// ---------------------------------------------------------------------------

/// A node id derived from a name, as hex.
#[wasm_bindgen]
pub fn node_id_from_name(name: &str) -> String {
    NodeId::from_name(name).to_hex()
}

/// The name the codec gives an instruction code (unknown codes included).
#[wasm_bindgen]
pub fn instruction_name(code: u16) -> String {
    format!("{:?}", Instruction::from_u16(code))
}
