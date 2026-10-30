// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! `Channel`: one-way, lossless, in-order messages between processes on one
//! host, over a Pulse ring and an envelope store in shared memory.
//!
//! A channel is a ring named `name` and a store named `name + "-e"`. The
//! writer stores each message as one `PulseEnvelope` and publishes a Data
//! pulse naming its store cursor and id, as the hub runtime's broadcast does;
//! the reader walks the ring's positions in order and fetches each envelope
//! the pulse names, as the hub's poll does. Each channel has exactly one
//! writer and one reader, so the ring's single-writer rule holds and its read
//! cursor, which follows the furthest reader, is that reader's: the writer
//! waits for it instead of overwriting what it has not read. The protocol is
//! the Python binding's (`ends.rs`), so either end may be in either language.
//!
//! The ends live behind a mutex shared with the channel's [`Waiter`] thread.
//! `recvAsync` takes the lock only for each look at the ring and sleeps
//! between looks without it, so `close`, `pending` and the other accessors
//! never wait long for a receive in progress.

mod ends;

use std::sync::{Arc, Mutex, MutexGuard, PoisonError, TryLockError};
use std::time::{Duration, Instant};

use napi::bindgen_prelude::*;
use napi::{Env, JsObject};
use napi_derive::napi;

use crate::error::{coded, Code};
use crate::waiter::Waiter;
use ends::{Backoff, Ends};

/// `Channel.create`'s ring slots when none are given, as in Python.
const DEFAULT_CAPACITY: u32 = 4096;
/// `Channel.create`'s store entries when none are given, as in Python.
const DEFAULT_STORE_SLOTS: u32 = 256;
/// How long `Channel.open` looks for the channel when no timeout is given.
const DEFAULT_OPEN_TIMEOUT_MS: u32 = 10_000;
/// How long `send` waits for room when no timeout is given.
const DEFAULT_SEND_TIMEOUT_MS: u32 = 5_000;

/// One end of a one-way, lossless, in-order message channel over Pulse's
/// shared-memory ring and envelope store.
///
/// `Channel.create(name)` makes the writer end and `Channel.open(name)`
/// attaches the reader end, usually in another process. A channel has one
/// writer and one reader; for two directions, use two channels. A message is
/// a list of Buffers whose framed size (4 bytes for the count and 4 for each
/// frame's length, plus the frames) is at most `Channel.maxPayload()` bytes.
///
/// `send`, `recv` and `Channel.open` wait on the calling thread, which in
/// Node is the event loop; `recvAsync` waits on a thread of the channel's
/// own and returns a promise.
#[napi]
pub struct Channel {
    /// The ends, `None` once closed.
    ends: Arc<Mutex<Option<Ends>>>,
    /// The thread `recvAsync` waits on.
    waiter: Waiter,
}

#[napi]
impl Channel {
    /// Largest framed payload of one message, in bytes: 4 for the frame
    /// count, then 4 and the frame's length for each frame.
    #[napi]
    pub fn max_payload() -> u32 {
        ends::max_payload() as u32
    }

    /// Create the writer end of channel `name`: a ring of `capacity` slots
    /// (4096 when omitted) and a store of `storeSlots` entries (256), each
    /// 64 KB of shared memory. Objects left under either name by an earlier
    /// run are removed first. At most `min(capacity, storeSlots)` messages
    /// are unread at once; `send` waits for the reader beyond that.
    ///
    /// Throws `InvalidArg` for a name too long for macOS (29 bytes with its
    /// leading slash, so the store's `name + "-e"` fits 31).
    #[napi(factory)]
    pub fn create(
        name: String,
        capacity: Option<u32>,
        store_slots: Option<u32>,
    ) -> Result<Self, Code> {
        let capacity = capacity.unwrap_or(DEFAULT_CAPACITY);
        let store_slots = store_slots.unwrap_or(DEFAULT_STORE_SLOTS);
        let ends = Ends::create(&name, u64::from(capacity), store_slots as usize)
            .map_err(ends::ChannelError::into_coded)?;
        Ok(Self::with(ends))
    }

    /// Attach the reader end of channel `name`, retrying for up to
    /// `timeoutMs` milliseconds (10 000 when omitted) while its writer has
    /// not created it yet. Throws `Timeout` if it never appears. Waits on
    /// the event loop.
    #[napi(factory)]
    pub fn open(name: String, timeout_ms: Option<u32>) -> Result<Self, Code> {
        let timeout = millis(timeout_ms.unwrap_or(DEFAULT_OPEN_TIMEOUT_MS));
        let ends = Ends::open(&name, timeout).map_err(ends::ChannelError::into_coded)?;
        Ok(Self::with(ends))
    }

    /// Send one message: `frames`, an array of Buffers, or one Buffer as a
    /// single frame. Waits up to `timeoutMs` milliseconds (5000 when
    /// omitted) while the reader has `min(capacity, storeSlots)` messages
    /// unread, then throws `Timeout` with nothing sent. Throws
    /// `EnvelopeTooLarge` for a message over the 64 KB limit, with nothing
    /// sent. Writer end only. Waits on the event loop.
    #[napi(ts_args_type = "frames: Buffer | Buffer[], timeoutMs?: number | undefined | null")]
    pub fn send(
        &mut self,
        frames: Either<Buffer, Vec<Buffer>>,
        timeout_ms: Option<u32>,
    ) -> Result<(), Code> {
        let timeout = millis(timeout_ms.unwrap_or(DEFAULT_SEND_TIMEOUT_MS));
        let payload = match &frames {
            Either::A(one) => ends::encode_frames(std::iter::once(&one[..])),
            Either::B(many) => ends::encode_frames(many.iter().map(|frame| &frame[..])),
        }
        .map_err(ends::ChannelError::into_coded)?;
        let mut guard = self.lock();
        let ends = open_end(&mut guard)?;
        if !ends.is_writer() {
            return Err(coded(Code::InvalidArg, "Channel.send on the reader end"));
        }
        ends.send(payload, timeout)
            .map_err(ends::ChannelError::into_coded)
    }

    /// Receive the next message as an array of Buffers, waiting up to
    /// `timeoutMs` milliseconds (without limit when omitted); `null` if none
    /// came in time. Throws `ChannelClosed` once the writer has closed the
    /// channel and every message has been read, and `Busy` while a
    /// `recvAsync` on this end has not settled. Reader end only. Waits on
    /// the event loop: `recvAsync` does not.
    #[napi]
    pub fn recv(&mut self, timeout_ms: Option<u32>) -> Result<Option<Vec<Buffer>>, Code> {
        let deadline = deadline(timeout_ms.map(millis));
        if self.waiter.pending() > 0 {
            return Err(busy());
        }
        let mut guard = match self.ends.try_lock() {
            Ok(guard) => guard,
            Err(TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
            Err(TryLockError::WouldBlock) => return Err(busy()),
        };
        let ends = reader_end(&mut guard)?;
        let frames = ends
            .recv(deadline)
            .map_err(ends::ChannelError::into_coded)?;
        Ok(frames.map(into_buffers))
    }

    /// `recv` off the event loop: a promise of the next message's Buffers,
    /// or of `null` if none came within `timeoutMs` milliseconds (without
    /// limit when omitted), counted from this call. Rejects with code
    /// `ChannelClosed` once the writer has closed the channel and every
    /// message has been read, and `InvalidArg` on the writer end or if this
    /// end is closed before a message comes. Receives asked for together
    /// settle in order, each with the next message.
    #[napi(ts_return_type = "Promise<Buffer[] | null>")]
    pub fn recv_async(&mut self, env: Env, timeout_ms: Option<u32>) -> Result<JsObject> {
        let deadline = deadline(timeout_ms.map(millis));
        let shared = Arc::clone(&self.ends);
        self.waiter.run(
            &env,
            move || {
                let mut backoff = Backoff::until(deadline);
                loop {
                    // One look, holding the lock only for it: a deadline of
                    // now takes a message already there and waits for none.
                    let look = {
                        let mut guard = shared.lock().unwrap_or_else(PoisonError::into_inner);
                        let ends = guard.as_mut().ok_or_else(|| {
                            coded(
                                Code::InvalidArg,
                                "operation on a closed Channel: it was closed before \
                                 recvAsync took a message",
                            )
                        })?;
                        if ends.is_writer() {
                            return Err(coded(
                                Code::InvalidArg,
                                "Channel.recvAsync on the writer end",
                            ));
                        }
                        ends.recv(Some(Instant::now()))
                            .map_err(ends::ChannelError::into_coded)?
                    };
                    if look.is_some() || !backoff.step() {
                        return Ok(look);
                    }
                }
            },
            |_env, frames: Option<Vec<Vec<u8>>>| Ok(frames.map(into_buffers)),
        )
    }

    /// Close this end. The writer's close removes the ring's and the store's
    /// names (a reader still attached keeps reading what was sent, then gets
    /// `ChannelClosed`); the reader's only detaches. Closing twice is a
    /// no-op. A `recvAsync` waiting on this end rejects.
    #[napi]
    pub fn close(&mut self) {
        let ends = self.lock().take();
        drop(ends);
    }

    /// The ring's shared-memory name (leading slash included).
    #[napi(getter)]
    pub fn name(&self) -> Result<String, Code> {
        self.with_end(|ends| ends.name().to_owned())
    }

    /// True for the writer end.
    #[napi(getter)]
    pub fn is_writer(&self) -> Result<bool, Code> {
        self.with_end(Ends::is_writer)
    }

    /// True once `close()` has run.
    #[napi(getter)]
    pub fn closed(&self) -> bool {
        self.lock().is_none()
    }

    /// Slots in the ring.
    #[napi(getter)]
    pub fn capacity(&self) -> Result<f64, Code> {
        self.with_end(|ends| ends.capacity() as f64)
    }

    /// Entries in the envelope store.
    #[napi(getter)]
    pub fn store_slots(&self) -> Result<f64, Code> {
        self.with_end(|ends| ends.store_slots() as f64)
    }

    /// Messages sent and not yet read, as the writer counts them.
    #[napi(getter)]
    pub fn pending(&self) -> Result<f64, Code> {
        self.with_end(|ends| ends.pending() as f64)
    }
}

impl Channel {
    fn with(ends: Ends) -> Self {
        Self {
            ends: Arc::new(Mutex::new(Some(ends))),
            waiter: Waiter::new("pulse-wire channel"),
        }
    }

    /// The ends' lock, which `recvAsync`'s thread holds only for a look at
    /// the ring.
    fn lock(&self) -> MutexGuard<'_, Option<Ends>> {
        self.ends.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// `f` of the open ends, or `InvalidArg` once closed.
    fn with_end<T>(&self, f: impl FnOnce(&Ends) -> T) -> Result<T, Code> {
        let mut guard = self.lock();
        Ok(f(open_end(&mut guard)?))
    }
}

/// The ends `guard` holds, or `InvalidArg` once closed.
fn open_end<'a>(guard: &'a mut MutexGuard<'_, Option<Ends>>) -> Result<&'a mut Ends, Code> {
    guard
        .as_mut()
        .ok_or_else(|| coded(Code::InvalidArg, "operation on a closed Channel"))
}

/// The reader end `guard` holds, or `InvalidArg` on the writer end or once
/// closed.
fn reader_end<'a>(guard: &'a mut MutexGuard<'_, Option<Ends>>) -> Result<&'a mut Ends, Code> {
    let ends = open_end(guard)?;
    if ends.is_writer() {
        return Err(coded(Code::InvalidArg, "Channel.recv on the writer end"));
    }
    Ok(ends)
}

fn busy() -> napi::Error<Code> {
    coded(
        Code::Busy,
        "a recvAsync on this Channel has not settled; await it before a synchronous recv",
    )
}

fn millis(ms: u32) -> Duration {
    Duration::from_millis(u64::from(ms))
}

/// The instant `timeout` from now (`None`: no limit).
fn deadline(timeout: Option<Duration>) -> Option<Instant> {
    timeout.and_then(|t| Instant::now().checked_add(t))
}

fn into_buffers(frames: Vec<Vec<u8>>) -> Vec<Buffer> {
    frames.into_iter().map(Buffer::from).collect()
}
