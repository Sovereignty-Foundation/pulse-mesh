// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//
// Fuzz target: the Lexicon, `mesh-lex`: its byte decoders, the JSON forms
// of its types, bundle schemas decoded from an entry's schema bytes, and a
// registry built from entries the input draws, with its Merkle root.
//
// The first byte picks the mode. Text: the rest of the input is parsed as
// each JSON type the crate reads (`LexEntry`, `LineSet`, `LineValue`,
// `MerkleChangeEvent`) and as a bundle schema's bytes. Registry: the input
// draws entries (names, kinds, boundaries, schema bytes that are a bundle
// schema's JSON or anything) and registers them.
//
// The oracles for the byte layouts and the root are written from the
// module documentation, not from the code: an entry's canonical bytes,
// a line value's and a line set's are encoded again here, and the root is
// folded here from BLAKE3 of those bytes.
//
// Invariants:
// - `DescriptorKind::from_byte` and `Boundary::from_byte` accept exactly
//   the documented discriminants and `as_byte` returns them;
// - whatever parses as one of the JSON types serialises, and the
//   serialisation parses back to an equal value and serialises to itself;
//   a bundle schema's bytes do the same through `from_schema_bytes` and
//   `to_schema_bytes`;
// - `canonical_bytes` of an entry, a line value and a line set are the
//   documented layouts; a line set's does not depend on insertion order;
//   an entry's content hash is BLAKE3 of its canonical bytes;
// - the registry refuses exactly a duplicate `(type_id, kind)`, looks up
//   what was inserted, iterates in key order, and `validate` reports the
//   first name used twice in key order, naming both holders;
// - `lex_root` is the documented fold over the public entries' content
//   hashes in key order (the empty sentinel for none), whatever the order
//   of insertion; `commit_tick` carries it with the previous root and the
//   tick;
// - the schema view yields exactly the bundle-schema entries whose bytes
//   decode, and `lookup_bundle` agrees with it.

#![no_main]

use std::collections::btree_map::Entry;
use std::collections::BTreeMap;

use libfuzzer_sys::arbitrary::{Result, Unstructured};
use libfuzzer_sys::fuzz_target;
use mesh_lex::{
    commit_tick, lex_root, lex_root_hex, Boundary, BundleSchema, DescriptorKind, LexEntry,
    LexMerkle, LexRegistry, LexRegistryError, LexSchemaRegistry, LineKind, LineSchema, LineSet,
    LineValue, MerkleChangeEvent, MerkleDiff,
};
use pulse_mesh_fuzz::take;
use serde::de::DeserializeOwned;
use serde::Serialize;

/// Most entries in one registry.
const MAX_ENTRIES: usize = 24;

fuzz_target!(|data: &[u8]| {
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };
    check_bytes(mode);
    if mode & 1 == 0 {
        text(rest);
    } else {
        let _ = registry(&mut Unstructured::new(rest));
    }
});

/// The one-byte decoders.
fn check_bytes(b: u8) {
    let kind = DescriptorKind::from_byte(b);
    assert_eq!(
        kind.is_some(),
        (1..=4).contains(&b),
        "DescriptorKind::from_byte({b})"
    );
    if let Some(kind) = kind {
        assert_eq!(kind.as_byte(), b);
    }
    let boundary = Boundary::from_byte(b);
    assert_eq!(
        boundary.is_some(),
        (1..=3).contains(&b),
        "Boundary::from_byte({b})"
    );
    if let Some(boundary) = boundary {
        assert_eq!(boundary.as_byte(), b);
        assert_eq!(boundary.is_public(), b == 1);
    }
}

/// Every JSON type, and a bundle schema's bytes, over the same text.
fn text(bytes: &[u8]) {
    if let Ok(schema) = BundleSchema::from_schema_bytes(bytes) {
        let again = schema.to_schema_bytes().expect("a schema serialises");
        let back = BundleSchema::from_schema_bytes(&again).expect("a schema's bytes decode");
        assert_eq!(
            back, schema,
            "a schema changed on its way through its bytes"
        );
        assert_eq!(back.to_schema_bytes().expect("serialises"), again);
        check_schema(&schema);
    }
    let Ok(text) = std::str::from_utf8(bytes) else {
        return;
    };
    if let Some(entry) = round_trip::<LexEntry>(text) {
        check_entry(&entry);
    }
    if let Some(set) = round_trip::<LineSet>(text) {
        check_line_set(&set);
    }
    if let Some(value) = round_trip::<LineValue>(text) {
        assert_eq!(value.canonical_bytes(), value_bytes(&value));
    }
    if let Some(event) = round_trip::<MerkleChangeEvent>(text) {
        assert_eq!(
            event.root_changed(),
            event.prev_root != Some(event.next_root),
            "root_changed"
        );
        assert_eq!(event.next_root_hex(), hex(&event.next_root));
    }
}

/// Parse `text` as `T`; what parses serialises, parses back equal, and
/// serialises to itself.
fn round_trip<T: Serialize + DeserializeOwned + PartialEq + std::fmt::Debug>(
    text: &str,
) -> Option<T> {
    let value: T = serde_json::from_str(text).ok()?;
    let json = serde_json::to_string(&value).expect("a parsed value serialises");
    let back: T = serde_json::from_str(&json)
        .unwrap_or_else(|e| panic!("the serialisation {json} does not parse: {e}"));
    assert_eq!(
        back, value,
        "the round trip through {json} changed the value"
    );
    assert_eq!(
        serde_json::to_string(&back).expect("serialises"),
        json,
        "not a fixed point"
    );
    Some(value)
}

/// An entry's canonical bytes are the documented layout, and its content
/// hash is BLAKE3 of them.
fn check_entry(entry: &LexEntry) {
    let bytes = entry_bytes(entry);
    assert_eq!(entry.canonical_bytes(), bytes, "an entry's canonical bytes");
    assert_eq!(
        entry.content_hash(),
        *blake3::hash(&bytes).as_bytes(),
        "content_hash"
    );
}

/// A schema turned into an entry carries it, and its bytes decode back.
fn check_schema(schema: &BundleSchema) {
    for line in &schema.lines {
        let d = line.kind.discriminant();
        assert!((1..=5).contains(&d), "a line kind's discriminant {d}");
    }
    let entry = schema
        .clone()
        .into_lex_entry(7, Boundary::Public)
        .expect("a schema makes an entry");
    assert_eq!(entry.kind, DescriptorKind::BundleSchema);
    assert_eq!(
        (entry.name.as_str(), entry.version),
        (schema.name.as_str(), schema.version)
    );
    assert_eq!(
        BundleSchema::from_schema_bytes(&entry.schema_bytes).expect("decodes"),
        *schema
    );
    check_entry(&entry);
}

/// A line set's canonical bytes are the documented layout, in name order
/// whatever the order of insertion.
fn check_line_set(set: &LineSet) {
    let mut names: Vec<(&str, &LineValue)> = set.iter().collect();
    names.sort_by(|a, b| a.0.cmp(b.0));
    let mut expect = (set.len() as u32).to_le_bytes().to_vec();
    for (name, value) in &names {
        expect.extend_from_slice(&(name.len() as u32).to_le_bytes());
        expect.extend_from_slice(name.as_bytes());
        expect.extend_from_slice(&value_bytes(value));
    }
    let mut reversed = LineSet::new();
    for &(name, value) in names.iter().rev() {
        reversed.insert(name, value.clone());
    }
    assert_eq!(
        set.canonical_bytes(),
        expect,
        "a line set's canonical bytes"
    );
    assert_eq!(
        reversed.canonical_bytes(),
        expect,
        "insertion order changed the bytes"
    );
}

/// The documented layout of a line value.
fn value_bytes(value: &LineValue) -> Vec<u8> {
    let mut out = Vec::new();
    match value {
        LineValue::Bytes(b) => {
            out.push(1);
            out.extend_from_slice(&(b.len() as u32).to_le_bytes());
            out.extend_from_slice(b);
        }
        LineValue::Text(s) => {
            out.push(2);
            out.extend_from_slice(&(s.len() as u32).to_le_bytes());
            out.extend_from_slice(s.as_bytes());
        }
        LineValue::U64(n) => {
            out.push(3);
            out.extend_from_slice(&n.to_le_bytes());
        }
        LineValue::I64(n) => {
            out.push(4);
            out.extend_from_slice(&n.to_le_bytes());
        }
        LineValue::Bool(b) => {
            out.push(5);
            out.push(u8::from(*b));
        }
    }
    out
}

/// The documented layout of an entry.
fn entry_bytes(e: &LexEntry) -> Vec<u8> {
    let mut out = e.type_id.to_le_bytes().to_vec();
    out.extend_from_slice(&(e.name.len() as u32).to_le_bytes());
    out.extend_from_slice(e.name.as_bytes());
    out.extend_from_slice(&e.version.to_le_bytes());
    out.push(e.kind as u8);
    out.push(e.boundary as u8);
    out.extend_from_slice(&(e.schema_bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(&e.schema_bytes);
    out
}

/// The documented root: BLAKE3 of `mesh-lex/empty/v1` for no leaf; else the
/// leaves folded pairwise, level by level, an odd leaf promoted unchanged.
fn root_of(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        return *blake3::hash(b"mesh-lex/empty/v1").as_bytes();
    }
    let mut level = leaves.to_vec();
    while level.len() > 1 {
        level = level
            .chunks(2)
            .map(|pair| match pair {
                [a, b] => {
                    let mut joined = a.to_vec();
                    joined.extend_from_slice(b);
                    *blake3::hash(&joined).as_bytes()
                }
                [a] => *a,
                _ => unreachable!("chunks of two"),
            })
            .collect();
    }
    level[0]
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A registry built from entries the input draws, against a model.
fn registry(u: &mut Unstructured<'_>) -> Result<()> {
    let mut reg = LexRegistry::new();
    let mut model: BTreeMap<(u16, u8), LexEntry> = BTreeMap::new();
    let mut inserted = Vec::new();
    for _ in 0..u.int_in_range(0..=MAX_ENTRIES)? {
        let entry = entry(u)?;
        check_entry(&entry);
        let key = (entry.type_id, entry.kind as u8);
        let got = reg.insert(entry.clone());
        match model.entry(key) {
            Entry::Occupied(_) => assert_eq!(
                got,
                Err(LexRegistryError::Duplicate {
                    type_id: entry.type_id,
                    kind: entry.kind
                })
            ),
            Entry::Vacant(slot) => {
                assert_eq!(got, Ok(()));
                slot.insert(entry.clone());
                inserted.push(entry);
            }
        }
    }
    assert_eq!(reg.len(), model.len());
    assert_eq!(reg.is_empty(), model.is_empty());
    let in_order: Vec<&LexEntry> = reg.iter().collect();
    assert_eq!(
        in_order,
        model.values().collect::<Vec<_>>(),
        "iteration is not key order"
    );
    for (&(type_id, kind), entry) in &model {
        let kind = DescriptorKind::from_byte(kind).expect("a kind");
        assert_eq!(reg.lookup(type_id, kind), Some(entry));
    }
    if let Some(probe) = model.values().next() {
        assert_eq!(
            reg.lookup_by_name(&probe.name),
            model.values().find(|e| e.name == probe.name)
        );
    }

    // `validate`: the first name used twice, in key order.
    let mut seen: BTreeMap<&str, &LexEntry> = BTreeMap::new();
    let mut conflict = None;
    for e in model.values() {
        if let Some(a) = seen.get(e.name.as_str()) {
            conflict = Some(LexRegistryError::NameConflict {
                name: e.name.clone(),
                a_type_id: a.type_id,
                a_kind: a.kind,
                b_type_id: e.type_id,
                b_kind: e.kind,
            });
            break;
        }
        seen.insert(&e.name, e);
    }
    assert_eq!(reg.validate(), conflict.map_or(Ok(()), Err));

    // The root, folded here, and independent of the order of insertion.
    let leaves: Vec<[u8; 32]> = model
        .values()
        .filter(|e| e.boundary == Boundary::Public)
        .map(|e| *blake3::hash(&entry_bytes(e)).as_bytes())
        .collect();
    let root = root_of(&leaves);
    assert_eq!(lex_root(&reg), root, "lex_root is not the documented fold");
    assert_eq!(lex_root_hex(&reg), hex(&root));
    let merkle = LexMerkle::from_registry(&reg);
    assert_eq!(merkle.leaves(), leaves.as_slice());
    assert_eq!(merkle.root(), root);
    let mut reversed = LexRegistry::new();
    for e in inserted.iter().rev() {
        reversed
            .insert(e.clone())
            .expect("no duplicate among the inserted");
    }
    assert_eq!(
        lex_root(&reversed),
        root,
        "the root depends on the order of insertion"
    );

    let prev: Option<[u8; 32]> = if u.arbitrary()? {
        Some(u.arbitrary()?)
    } else {
        None
    };
    let tick: u64 = u.arbitrary()?;
    let event = commit_tick(&reg, prev, tick);
    assert_eq!(
        (event.prev_root, event.next_root, event.tick_id),
        (prev, root, tick)
    );
    assert_eq!(event.root_changed(), prev != Some(root));
    let diff = MerkleDiff::between(prev.unwrap_or(root), root);
    assert_eq!(diff.unchanged(), prev.is_none_or(|p| p == root));
    assert_eq!(diff.next_hex(), hex(&root));

    // The schema view.
    let view = LexSchemaRegistry::from_registry(&reg);
    let bundles: Vec<(u16, BundleSchema)> = view.iter_bundles().collect();
    let expect: Vec<(u16, BundleSchema)> = model
        .values()
        .filter(|e| e.kind == DescriptorKind::BundleSchema)
        .filter_map(|e| {
            serde_json::from_slice::<BundleSchema>(&e.schema_bytes)
                .ok()
                .map(|s| (e.type_id, s))
        })
        .collect();
    assert_eq!(bundles, expect, "the schema view");
    for e in model.values() {
        let got = view.lookup_bundle(e.type_id);
        match model.get(&(e.type_id, DescriptorKind::BundleSchema as u8)) {
            None => assert!(matches!(got, Ok(None))),
            Some(b) => match serde_json::from_slice::<BundleSchema>(&b.schema_bytes) {
                Ok(s) => assert_eq!(got.ok(), Some(Some(s))),
                Err(_) => assert!(got.is_err()),
            },
        }
    }
    Ok(())
}

/// An entry drawn from the input: names from a small set, so that names
/// repeat; schema bytes a bundle schema's JSON, or anything.
fn entry(u: &mut Unstructured<'_>) -> Result<LexEntry> {
    const NAMES: [&str; 5] = ["canon/vector", "trace/event", "a", "", "b/c"];
    let name = if u.ratio(3, 4)? {
        NAMES[u.choose_index(NAMES.len())?].to_owned()
    } else {
        u.arbitrary::<String>()?
    };
    let kind = DescriptorKind::from_byte(u.int_in_range(1..=4)?).expect("a kind");
    let boundary = Boundary::from_byte(u.int_in_range(1..=3)?).expect("a boundary");
    let type_id = u.int_in_range(0..=7)?;
    let version = u.arbitrary()?;
    let schema_bytes = if u.arbitrary()? {
        let mut lines = Vec::new();
        for _ in 0..u.int_in_range(0..=3)? {
            let kind = match u.int_in_range(0..=4u8)? {
                0 => LineKind::Bytes {
                    max_len: u.arbitrary()?,
                },
                1 => LineKind::Text {
                    max_len: u.arbitrary()?,
                },
                2 => LineKind::U64,
                3 => LineKind::I64,
                _ => LineKind::Bool,
            };
            lines.push(LineSchema {
                name: u.arbitrary()?,
                kind,
                required: u.arbitrary()?,
            });
        }
        let schema = BundleSchema {
            name: name.clone(),
            version,
            lines,
        };
        check_schema(&schema);
        schema.to_schema_bytes().expect("serialises")
    } else {
        take(u, 32)?.to_vec()
    };
    Ok(LexEntry::new(
        type_id,
        name,
        version,
        kind,
        boundary,
        schema_bytes,
    ))
}
