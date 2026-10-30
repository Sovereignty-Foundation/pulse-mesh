// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! A channel's two ends over the ring and the store, with no napi in them.
//!
//! The same protocol as the Python binding's `channel.rs`, so a channel's
//! writer and reader may be in either language: the ring `name`, the store
//! `name + "-e"`, one `"pulse/channel"` envelope per message holding the
//! framed payload `count:u32_le`, then for each frame `len:u32_le ‖ bytes`,
//! and a Data pulse naming its store cursor and id.

use std::time::{Duration, Instant};

use core_ring::{PositionRead, PulseRing, RingError};
use core_store::{EnvelopeStore, EnvelopeStoreError, MAX_ENTRY_SIZE};
use pulse_wire_core::{Pulse as RustPulse, PulseEnvelope};

use crate::error::{coded, Code};

/// The type name every channel envelope carries.
const ENVELOPE_TYPE_NAME: &str = "pulse/channel";

/// Longest POSIX shared-memory name, leading slash included, that every
/// supported host accepts: macOS's `PSHMNAMLEN` is 31.
const MAX_SHM_NAME: usize = 31;

/// Suffix of the store's name after the ring's.
const STORE_SUFFIX: &str = "-e";

/// How long a waiter spins before it starts to sleep.
const SPIN: Duration = Duration::from_micros(50);
/// First sleep after the spin; each later one doubles, up to [`MAX_SLEEP`].
const FIRST_SLEEP: Duration = Duration::from_micros(20);
/// Longest single sleep of a waiter.
const MAX_SLEEP: Duration = Duration::from_millis(1);

/// A wait that spins for [`SPIN`], then sleeps from [`FIRST_SLEEP`] doubling
/// to [`MAX_SLEEP`], never past its deadline.
pub(crate) struct Backoff {
    spin_until: Instant,
    sleep: Duration,
    deadline: Option<Instant>,
}

impl Backoff {
    /// A wait of at most `timeout` from now (`None`: no limit).
    pub(crate) fn new(timeout: Option<Duration>) -> Self {
        Self::until(timeout.and_then(|t| Instant::now().checked_add(t)))
    }

    /// A wait that ends at `deadline` (`None`: never).
    pub(crate) fn until(deadline: Option<Instant>) -> Self {
        Self {
            spin_until: Instant::now() + SPIN,
            sleep: FIRST_SLEEP,
            deadline,
        }
    }

    /// Wait one step; `false` once the deadline has passed.
    pub(crate) fn step(&mut self) -> bool {
        let now = Instant::now();
        if let Some(deadline) = self.deadline {
            if now >= deadline {
                return false;
            }
        }
        if now < self.spin_until {
            std::hint::spin_loop();
            return true;
        }
        let nap = match self.deadline {
            Some(deadline) => self.sleep.min(deadline - now),
            None => self.sleep,
        };
        std::thread::sleep(nap);
        self.sleep = (self.sleep * 2).min(MAX_SLEEP);
        true
    }
}

/// What went wrong in a channel operation, turned into a coded JavaScript
/// error by [`ChannelError::into_coded`].
#[derive(Debug)]
pub(crate) enum ChannelError {
    Invalid(String),
    TooLarge {
        actual: usize,
    },
    Stalled {
        in_flight: u64,
        waited: Duration,
    },
    Closed,
    Lost {
        position: u64,
        next: u64,
    },
    NotStored {
        position: u64,
        cursor: Option<u64>,
    },
    Malformed(String),
    Ring(RingError),
    Store(EnvelopeStoreError),
    OpenTimedOut {
        name: String,
        waited: Duration,
        last: String,
    },
}

impl ChannelError {
    /// The coded error a caller sees: `EnvelopeTooLarge`, `ChannelClosed` and
    /// `Timeout` for the conditions a caller handles, `InvalidArg` for a bad
    /// name or message, `GenericFailure` for the rest.
    pub(crate) fn into_coded(self) -> napi::Error<Code> {
        match self {
            Self::Invalid(why) => coded(Code::InvalidArg, why),
            Self::TooLarge { actual } => coded(
                Code::EnvelopeTooLarge,
                format!(
                    "message envelope is {actual} bytes; a Channel message is limited to the \
                     envelope store's {MAX_ENTRY_SIZE}-byte (64 KB) entry, framing included. \
                     Nothing was sent"
                ),
            ),
            Self::Stalled { in_flight, waited } => coded(
                Code::Timeout,
                format!(
                    "Channel.send waited {waited:?} with {in_flight} messages unread; the reader \
                     stopped, died or never opened the channel. Nothing was sent"
                ),
            ),
            Self::Closed => coded(
                Code::ChannelClosed,
                "the writer closed the channel; every message was read",
            ),
            Self::Lost { position, next } => coded(
                Code::GenericFailure,
                format!(
                    "Channel lost positions {position}..{next}: the ring was overwritten before \
                     they were read, which a channel with one writer and one reader never does"
                ),
            ),
            Self::NotStored { position, cursor } => coded(
                Code::GenericFailure,
                format!(
                    "Channel position {position} names an envelope not in the store at cursor \
                     {cursor:?}: its slot was reused before it was read"
                ),
            ),
            Self::Malformed(why) => coded(
                Code::InvalidArg,
                format!("malformed Channel message: {why}"),
            ),
            Self::Ring(e) => coded(Code::GenericFailure, format!("ring: {e}")),
            Self::Store(e) => coded(Code::GenericFailure, format!("envelope store: {e}")),
            Self::OpenTimedOut { name, waited, last } => coded(
                Code::Timeout,
                format!("Channel.open('{name}') found no channel within {waited:?}: {last}"),
            ),
        }
    }
}

/// The ring and store names for a channel `name`: a leading slash is added
/// when missing, and the longer of the two must fit [`MAX_SHM_NAME`].
pub(crate) fn shm_names(name: &str) -> Result<(String, String), ChannelError> {
    let ring = if name.starts_with('/') {
        name.to_owned()
    } else {
        format!("/{name}")
    };
    if ring.len() < 2 || ring[1..].contains('/') || ring.contains('\0') {
        return Err(ChannelError::Invalid(format!(
            "Channel name '{name}' must be non-empty, with no '/' after an optional leading \
             one and no NUL"
        )));
    }
    let store = format!("{ring}{STORE_SUFFIX}");
    if store.len() > MAX_SHM_NAME {
        return Err(ChannelError::Invalid(format!(
            "Channel name '{name}' is too long: its store's shared-memory name '{store}' is \
             {} bytes and macOS allows {MAX_SHM_NAME} (leading slash included), so a name may \
             be at most {} bytes with its leading slash",
            store.len(),
            MAX_SHM_NAME - STORE_SUFFIX.len()
        )));
    }
    Ok((ring, store))
}

/// A random 16-byte origin for one writer, never all zeros, made as the hub
/// runtime makes an instance id.
fn new_origin() -> [u8; 16] {
    use std::hash::BuildHasher;
    use std::sync::atomic::{AtomicU64, Ordering};
    static MADE: AtomicU64 = AtomicU64::new(0);
    let made = MADE.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    let mut id = [0u8; 16];
    for (half, bytes) in (0u8..).zip(id.chunks_exact_mut(8)) {
        let hash = std::collections::hash_map::RandomState::new().hash_one((pid, made, half));
        bytes.copy_from_slice(&hash.to_le_bytes());
    }
    if id == [0u8; 16] {
        id[0] = 1;
    }
    id
}

/// Bytes of a channel envelope's canonical encoding besides its payload.
fn envelope_overhead() -> usize {
    PulseEnvelope::typed(ENVELOPE_TYPE_NAME, Vec::new()).canonical_size()
}

/// Largest framed payload (count and lengths included) a message may have.
pub(crate) fn max_payload() -> usize {
    MAX_ENTRY_SIZE - envelope_overhead()
}

/// The framed payload of a message of `frames`, or
/// [`ChannelError::TooLarge`] once it is too large for the store, without
/// copying the rest.
pub(crate) fn encode_frames<'a>(
    frames: impl ExactSizeIterator<Item = &'a [u8]>,
) -> Result<Vec<u8>, ChannelError> {
    let too_large = |framed: usize| ChannelError::TooLarge {
        actual: framed.saturating_add(envelope_overhead()),
    };
    let count = u32::try_from(frames.len()).map_err(|_| too_large(usize::MAX))?;
    let mut payload = Vec::new();
    payload.extend_from_slice(&count.to_le_bytes());
    for frame in frames {
        let framed = payload.len() + 4 + frame.len();
        let len = u32::try_from(frame.len()).map_err(|_| too_large(framed))?;
        if framed > max_payload() {
            return Err(too_large(framed));
        }
        payload.extend_from_slice(&len.to_le_bytes());
        payload.extend_from_slice(frame);
    }
    Ok(payload)
}

/// Split a framed payload back into its frames.
fn decode_frames(payload: &[u8]) -> Result<Vec<&[u8]>, ChannelError> {
    let take_u32 = |at: usize| -> Result<usize, ChannelError> {
        payload
            .get(at..at + 4)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize)
            .ok_or_else(|| ChannelError::Malformed(format!("truncated at byte {at}")))
    };
    let count = take_u32(0)?;
    let mut at = 4;
    let mut frames = Vec::with_capacity(count.min(payload.len() / 4));
    for _ in 0..count {
        let len = take_u32(at)?;
        at += 4;
        let frame = payload
            .get(at..at + len)
            .ok_or_else(|| ChannelError::Malformed(format!("frame overruns at byte {at}")))?;
        frames.push(frame);
        at += len;
    }
    if at != payload.len() {
        return Err(ChannelError::Malformed(format!(
            "{} bytes after the last frame",
            payload.len() - at
        )));
    }
    Ok(frames)
}

/// The open ends of a channel.
pub(crate) struct Ends {
    ring: PulseRing,
    store: EnvelopeStore,
    writer: bool,
    name: String,
    /// The reader's next position to read.
    next: u64,
    /// The writer's most messages unread at once: the ring's capacity or the
    /// store's slots, whichever is fewer, so neither is overwritten unread.
    window: u64,
    /// The writer's origin, stamped on its pulses and envelopes.
    origin: [u8; 16],
}

impl Ends {
    /// The writer end of channel `name`: a ring of `capacity` slots and a
    /// store of `store_slots` entries. Objects left under either name by an
    /// earlier run are removed first.
    pub(crate) fn create(
        name: &str,
        capacity: u64,
        store_slots: usize,
    ) -> Result<Self, ChannelError> {
        let (ring_name, store_name) = shm_names(name)?;
        if capacity == 0 || store_slots == 0 {
            return Err(ChannelError::Invalid(
                "capacity and storeSlots must be positive".into(),
            ));
        }
        let _ = PulseRing::unlink(&ring_name);
        let _ = EnvelopeStore::unlink(&store_name);
        let ring = PulseRing::create_exclusive(&ring_name, capacity).map_err(ChannelError::Ring)?;
        let store = EnvelopeStore::create_exclusive(&store_name, store_slots)
            .map_err(ChannelError::Store)?;
        Ok(Self {
            window: capacity.min(store_slots as u64),
            ring,
            store,
            writer: true,
            name: ring_name,
            next: 0,
            origin: new_origin(),
        })
    }

    /// The reader end of channel `name`, retrying for up to `timeout` while
    /// its writer has not created it yet.
    pub(crate) fn open(name: &str, timeout: Duration) -> Result<Self, ChannelError> {
        let (ring_name, store_name) = shm_names(name)?;
        let started = Instant::now();
        let mut backoff = Backoff::new(Some(timeout));
        loop {
            let last = match PulseRing::open_existing(&ring_name) {
                Ok(ring) => match EnvelopeStore::open_existing(&store_name) {
                    Ok(store) => {
                        // Resume where the reader last reported: zero on a
                        // new ring.
                        let next = ring.read_cursor_position();
                        return Ok(Self {
                            window: 0,
                            ring,
                            store,
                            writer: false,
                            name: ring_name,
                            next,
                            origin: [0; 16],
                        });
                    }
                    Err(e) => format!("store {store_name}: {e}"),
                },
                Err(e) => format!("ring {ring_name}: {e}"),
            };
            // Polled every millisecond at most: the writer may take a while
            // to start.
            if !backoff.step() {
                return Err(ChannelError::OpenTimedOut {
                    name: ring_name,
                    waited: started.elapsed(),
                    last,
                });
            }
        }
    }

    /// The ring's shared-memory name (leading slash included).
    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    /// True for the writer end.
    pub(crate) fn is_writer(&self) -> bool {
        self.writer
    }

    /// Slots in the ring.
    pub(crate) fn capacity(&self) -> u64 {
        self.ring.capacity()
    }

    /// Entries in the envelope store.
    pub(crate) fn store_slots(&self) -> usize {
        self.store.capacity()
    }

    /// Messages sent and not yet read, as the writer counts them.
    pub(crate) fn pending(&self) -> u64 {
        self.ring
            .cursor_position()
            .saturating_sub(self.ring.read_cursor_position())
    }

    /// Store `payload` as one envelope and publish the Data pulse naming it,
    /// once the reader has left room, waiting at most `timeout`.
    pub(crate) fn send(&mut self, payload: Vec<u8>, timeout: Duration) -> Result<(), ChannelError> {
        // The hub's broadcast: an envelope stamped with the writer's origin
        // and the host's monotonic clock, stored, then a Data pulse naming
        // its store cursor and id.
        let mut envelope = PulseEnvelope::typed(ENVELOPE_TYPE_NAME, payload);
        let actual = envelope.canonical_size();
        if actual > MAX_ENTRY_SIZE {
            return Err(ChannelError::TooLarge { actual });
        }
        envelope.origin = self.origin;
        envelope.monotonic_nanos = pulse_wire_udp_transport::monotonic_nanos();

        // Room in the store as well as the ring: the store reuses slot
        // `cursor % slots`, so with `window` unread the next store overwrites
        // only an envelope already read.
        let started = Instant::now();
        let mut backoff = Backoff::new(Some(timeout));
        loop {
            let in_flight = self.pending();
            if in_flight < self.window {
                break;
            }
            if !backoff.step() {
                return Err(ChannelError::Stalled {
                    in_flight,
                    waited: started.elapsed(),
                });
            }
        }

        let cursor = self.store.store(&envelope).map_err(|e| match e {
            EnvelopeStoreError::EnvelopeTooLarge { actual, .. } => {
                ChannelError::TooLarge { actual }
            }
            e => ChannelError::Store(e),
        })?;
        let mut signal = RustPulse::zeroed();
        signal.set_store_cursor(cursor);
        signal.monotonic_nanos = envelope.monotonic_nanos;
        signal.origin_id = self.origin;
        signal.set_envelope_id(&envelope.id());
        // The room was waited for above, so this does not wait.
        let remaining = timeout.saturating_sub(started.elapsed());
        match self.ring.publish_blocking(&signal, remaining) {
            Ok(_) => Ok(()),
            Err(RingError::Stalled {
                in_flight, waited, ..
            }) => Err(ChannelError::Stalled { in_flight, waited }),
            Err(e) => Err(ChannelError::Ring(e)),
        }
    }

    /// The next message's frames, waiting until `deadline` (`None`: no
    /// limit); `Ok(None)` when none came in time. A deadline already passed
    /// still takes a message already there.
    pub(crate) fn recv(
        &mut self,
        deadline: Option<Instant>,
    ) -> Result<Option<Vec<Vec<u8>>>, ChannelError> {
        let mut backoff = Backoff::until(deadline);
        loop {
            // Read before the position: a mark seen here was set after every
            // publish, so a position still not written is never coming.
            let closed = self.ring.is_superseded();
            match self.ring.read_position_by_counter(self.next) {
                PositionRead::Pulse(pulse) => {
                    let position = self.next;
                    self.next += 1;
                    let frames = self.fetch(position, &pulse);
                    // Every message: the writer reads the cursor only once
                    // its window looks full, so this costs the writer nothing
                    // until then, and frees its slot as soon as it is read.
                    self.ring.advance_read_cursor(self.next);
                    match frames? {
                        Some(frames) => return Ok(Some(frames)),
                        // A pulse naming no envelope: not a message.
                        None => continue,
                    }
                }
                PositionRead::NotWritten => {
                    if closed {
                        return Err(ChannelError::Closed);
                    }
                    if !backoff.step() {
                        return Ok(None);
                    }
                }
                PositionRead::Lost { next } => {
                    return Err(ChannelError::Lost {
                        position: self.next,
                        next,
                    });
                }
            }
        }
    }

    /// The frames of the envelope `pulse` names, or `None` for a pulse that
    /// names none.
    fn fetch(
        &self,
        position: u64,
        pulse: &RustPulse,
    ) -> Result<Option<Vec<Vec<u8>>>, ChannelError> {
        // The hub's delivery: the id and the store cursor the pulse names.
        let Some(id) = pulse.envelope_id() else {
            return Ok(None);
        };
        let cursor = pulse.store_cursor();
        let envelope = cursor
            .and_then(|cursor| self.store.fetch_at(cursor, &id))
            .ok_or(ChannelError::NotStored { position, cursor })?;
        let payload = envelope
            .payload()
            .as_raw()
            .ok_or_else(|| ChannelError::Malformed("nested payload".into()))?;
        Ok(Some(
            decode_frames(payload)?
                .into_iter()
                .map(<[u8]>::to_vec)
                .collect(),
        ))
    }
}
