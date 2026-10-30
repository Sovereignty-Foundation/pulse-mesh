// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! A store's creator unlinks its name when it drops only while the name is
//! still its store: a store a later owner put under the name outlives the
//! earlier owner's handle, as a ring a later owner marked outlives its
//! creator's.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use core_store::{EnvelopeStore, EnvelopeStoreError};
use pulse_canon::PulseEnvelope;

/// `ENOENT` on every platform this crate builds for.
const ENOENT: i32 = 2;

/// A store name private to this process and test, at most 30 bytes.
fn name(tag: &str) -> String {
    format!("/st-own-{tag}-{:x}", std::process::id())
}

fn gone(name: &str) -> bool {
    matches!(
        EnvelopeStore::open_existing(name),
        Err(EnvelopeStoreError::Open(ENOENT))
    )
}

#[test]
fn a_creator_unlinks_the_name_while_it_is_still_its_store() {
    let name = name("own");
    let creator = EnvelopeStore::create_exclusive(&name, 1).unwrap();
    let reader = EnvelopeStore::open_existing(&name).unwrap();
    drop(reader);
    assert!(!gone(&name), "a reader's drop leaves the name");
    drop(creator);
    assert!(gone(&name), "the creator's drop removes it");
}

#[test]
fn an_earlier_creator_leaves_a_later_owners_store_under_the_name() {
    let name = name("later");
    let earlier = EnvelopeStore::create_exclusive(&name, 1).unwrap();
    // A later owner takes the name: it removes the store it finds there and
    // makes its own, which it goes on using while the earlier handle lives.
    assert!(EnvelopeStore::unlink(&name).unwrap());
    let later = EnvelopeStore::create_exclusive(&name, 2).unwrap();
    let envelope = PulseEnvelope::typed("app/later", vec![1]);
    later.store(&envelope).unwrap();

    drop(earlier);
    let under_the_name = EnvelopeStore::open_existing(&name)
        .expect("the earlier creator's drop left the later owner's store");
    assert_eq!(under_the_name.capacity(), 2);
    assert_eq!(
        under_the_name.fetch(&envelope.id()).map(|e| e.id()),
        Some(envelope.id())
    );
    drop(under_the_name);

    drop(later);
    assert!(gone(&name), "the later owner still removes its own name");
}

#[test]
fn a_creator_whose_name_was_removed_leaves_it_gone() {
    let name = name("gone");
    let creator = EnvelopeStore::create_exclusive(&name, 1).unwrap();
    assert!(EnvelopeStore::unlink(&name).unwrap());
    drop(creator);
    assert!(gone(&name));
    // The name is free for the next creator, whose drop removes it.
    drop(EnvelopeStore::create_exclusive(&name, 1).unwrap());
    assert!(gone(&name));
}

#[test]
fn a_creator_that_gave_up_the_name_leaves_it() {
    let name = name("disown");
    let mut creator = EnvelopeStore::create_exclusive(&name, 1).unwrap();
    // A hub whose ring another owner has marked gives its store's name up to
    // that owner, which replaces the store without waiting for it.
    creator.disown();
    drop(creator);
    assert!(!gone(&name), "the name is left to whoever took it over");
    assert_eq!(EnvelopeStore::open_existing(&name).unwrap().capacity(), 1);
    assert!(EnvelopeStore::unlink(&name).unwrap());
}
