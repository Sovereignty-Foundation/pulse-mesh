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
//! waits for it instead of overwriting what it has not read.
//!
//! A message is a list of byte frames, carried as one raw payload:
//! `count:u32_le`, then for each frame `len:u32_le ‖ bytes`.

use std::time::{Duration, Instant};

use pyo3::buffer::PyBuffer;
use pyo3::exceptions::{PyEOFError, PyRuntimeError, PyTimeoutError, PyTypeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyList};

use core_ring::{PositionRead, PulseRing, RingError};
use core_store::{EnvelopeStore, EnvelopeStoreError, MAX_ENTRY_SIZE};
use pulse_wire_core::{Pulse as RustPulse, PulseEnvelope};

pyo3::create_exception!(
    pulse_wire,
    EnvelopeTooLarge,
    PyValueError,
    "A Channel message whose envelope exceeds the store's 65,536-byte entry limit; nothing was sent."
);
pyo3::create_exception!(
    pulse_wire,
    ChannelClosed,
    PyEOFError,
    "The Channel's writer closed it and the reader has read every message it sent."
);

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
struct Backoff {
    spin_until: Instant,
    sleep: Duration,
    deadline: Option<Instant>,
}

impl Backoff {
    fn new(timeout: Option<Duration>) -> Self {
        let now = Instant::now();
        Self {
            spin_until: now + SPIN,
            sleep: FIRST_SLEEP,
            deadline: timeout.and_then(|t| now.checked_add(t)),
        }
    }

    /// Wait one step; `false` once the deadline has passed.
    fn step(&mut self) -> bool {
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

/// What went wrong in a channel operation run with the GIL released, turned
/// into a Python exception once it is held again.
enum ChannelError {
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

impl From<ChannelError> for PyErr {
    fn from(e: ChannelError) -> Self {
        match e {
            ChannelError::TooLarge { actual } => EnvelopeTooLarge::new_err(format!(
                "message envelope is {actual} bytes; a Channel message is limited to the \
                 envelope store's {MAX_ENTRY_SIZE}-byte (64 KB) entry, framing included"
            )),
            ChannelError::Stalled { in_flight, waited } => PyTimeoutError::new_err(format!(
                "Channel.send waited {waited:?} with {in_flight} messages unread; the reader \
                 stopped, died or never opened the channel. Nothing was sent"
            )),
            ChannelError::Closed => {
                ChannelClosed::new_err("the writer closed the channel; every message was read")
            }
            ChannelError::Lost { position, next } => PyRuntimeError::new_err(format!(
                "Channel lost positions {position}..{next}: the ring was overwritten before \
                 they were read, which a channel with one writer and one reader never does"
            )),
            ChannelError::NotStored { position, cursor } => PyRuntimeError::new_err(format!(
                "Channel position {position} names an envelope not in the store at cursor \
                 {cursor:?}: its slot was reused before it was read"
            )),
            ChannelError::Malformed(why) => {
                PyValueError::new_err(format!("malformed Channel message: {why}"))
            }
            ChannelError::Ring(e) => PyRuntimeError::new_err(format!("ring: {e}")),
            ChannelError::Store(e) => PyRuntimeError::new_err(format!("envelope store: {e}")),
            ChannelError::OpenTimedOut { name, waited, last } => PyTimeoutError::new_err(format!(
                "Channel.open('{name}') found no channel within {waited:?}: {last}"
            )),
        }
    }
}

/// The ring and store names for a channel `name`: a leading slash is added
/// when missing, and the longer of the two must fit [`MAX_SHM_NAME`].
fn shm_names(name: &str) -> PyResult<(String, String)> {
    let ring = if name.starts_with('/') {
        name.to_owned()
    } else {
        format!("/{name}")
    };
    if ring.len() < 2 || ring[1..].contains('/') || ring.contains('\0') {
        return Err(PyValueError::new_err(format!(
            "Channel name '{name}' must be non-empty, with no '/' after an optional leading \
             one and no NUL"
        )));
    }
    let store = format!("{ring}{STORE_SUFFIX}");
    if store.len() > MAX_SHM_NAME {
        return Err(PyValueError::new_err(format!(
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
fn max_payload() -> usize {
    MAX_ENTRY_SIZE - envelope_overhead()
}

/// Append `frame` to the framed payload `out`.
fn push_frame(py: Python<'_>, out: &mut Vec<u8>, frame: &Bound<'_, PyAny>) -> PyResult<()> {
    if let Ok(bytes) = frame.cast::<PyBytes>() {
        let bytes = bytes.as_bytes();
        out.extend_from_slice(&(frame_len(bytes.len())?).to_le_bytes());
        out.extend_from_slice(bytes);
        return Ok(());
    }
    let buffer: PyBuffer<u8> = match PyBuffer::get(frame) {
        Ok(buffer) => buffer,
        // A buffer of another item format, such as a memoryview of a typed
        // array: its bytes, through a byte-format view.
        Err(_) => {
            let view = py
                .import("builtins")?
                .getattr("memoryview")?
                .call1((frame,))
                .and_then(|view| view.call_method1("cast", ("B",)))
                .map_err(|e| {
                    PyTypeError::new_err(format!(
                        "a Channel frame must be bytes or a C-contiguous buffer: {e}"
                    ))
                })?;
            PyBuffer::get(&view)?
        }
    };
    if !buffer.is_c_contiguous() {
        return Err(PyTypeError::new_err(
            "a Channel frame buffer must be C-contiguous",
        ));
    }
    let len = buffer.item_count();
    out.extend_from_slice(&(frame_len(len)?).to_le_bytes());
    let start = out.len();
    out.resize(start + len, 0);
    buffer.copy_to_slice(py, &mut out[start..])?;
    Ok(())
}

fn frame_len(len: usize) -> PyResult<u32> {
    u32::try_from(len).map_err(|_| EnvelopeTooLarge::new_err(format!("frame of {len} bytes")))
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
struct Ends {
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
    /// Store `payload` as one envelope and publish the Data pulse naming it,
    /// once the reader has left room, waiting at most `timeout`.
    fn send(&mut self, payload: Vec<u8>, timeout: Duration) -> Result<(), ChannelError> {
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
            let in_flight = self
                .ring
                .cursor_position()
                .saturating_sub(self.ring.read_cursor_position());
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

    /// The next message's frames, waiting at most `timeout` (`None`: no
    /// limit); `Ok(None)` when none came in time.
    fn recv(&mut self, timeout: Option<Duration>) -> Result<Option<Vec<Vec<u8>>>, ChannelError> {
        let mut backoff = Backoff::new(timeout);
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

/// One end of a one-way, lossless, in-order message channel over Pulse's
/// shared-memory ring and envelope store.
///
/// `Channel.create(name)` makes the writer end and `Channel.open(name)`
/// attaches the reader end, usually in another process. A channel has one
/// writer and one reader; for two directions, use two channels. A message is
/// a list of byte frames whose framed size, with the envelope around it, fits
/// the store's 65,536-byte entry (`Channel.MAX_PAYLOAD` bytes of frames and
/// their 4-byte lengths, plus 4).
///
/// Each end is for one thread at a time. `send` and `recv` release the GIL
/// while they wait.
#[pyclass(name = "Channel", module = "pulse_wire")]
pub(crate) struct PyChannel {
    ends: Option<Ends>,
}

impl PyChannel {
    fn ends(&mut self) -> PyResult<&mut Ends> {
        self.ends
            .as_mut()
            .ok_or_else(|| PyValueError::new_err("operation on a closed Channel"))
    }
}

#[pymethods]
impl PyChannel {
    /// Largest framed payload of one message, in bytes: 4 for the frame
    /// count, then 4 and the frame's length for each frame.
    #[classattr]
    #[allow(non_snake_case)]
    fn MAX_PAYLOAD() -> usize {
        max_payload()
    }

    /// Create the writer end of channel `name`: a ring of `capacity` slots
    /// and a store of `store_slots` entries (each 64 KB of shared memory).
    /// Objects left under either name by an earlier run are removed first.
    /// At most `min(capacity, store_slots)` messages are unread at once;
    /// `send` waits for the reader beyond that.
    ///
    /// Raises `ValueError` for a name too long for macOS (29 bytes with its
    /// leading slash, so the store's `name + "-e"` fits 31).
    #[staticmethod]
    #[pyo3(signature = (name, capacity = 4096, store_slots = 256))]
    fn create(py: Python<'_>, name: &str, capacity: u64, store_slots: usize) -> PyResult<Self> {
        let (ring_name, store_name) = shm_names(name)?;
        if capacity == 0 || store_slots == 0 {
            return Err(PyValueError::new_err(
                "capacity and store_slots must be positive",
            ));
        }
        let ends = py.detach(|| -> Result<Ends, ChannelError> {
            let _ = PulseRing::unlink(&ring_name);
            let _ = EnvelopeStore::unlink(&store_name);
            let ring =
                PulseRing::create_exclusive(&ring_name, capacity).map_err(ChannelError::Ring)?;
            let store = EnvelopeStore::create_exclusive(&store_name, store_slots)
                .map_err(ChannelError::Store)?;
            Ok(Ends {
                window: capacity.min(store_slots as u64),
                ring,
                store,
                writer: true,
                name: ring_name,
                next: 0,
                origin: new_origin(),
            })
        })?;
        Ok(Self { ends: Some(ends) })
    }

    /// Attach the reader end of channel `name`, retrying for up to
    /// `timeout_s` seconds while its writer has not created it yet. Raises
    /// `TimeoutError` if it never appears.
    #[staticmethod]
    #[pyo3(signature = (name, timeout_s = 10.0))]
    fn open(py: Python<'_>, name: &str, timeout_s: f64) -> PyResult<Self> {
        let (ring_name, store_name) = shm_names(name)?;
        let timeout = seconds(timeout_s)?;
        let ends = py.detach(|| -> Result<Ends, ChannelError> {
            let started = Instant::now();
            let mut backoff = Backoff::new(Some(timeout));
            loop {
                let last = match PulseRing::open_existing(&ring_name) {
                    Ok(ring) => match EnvelopeStore::open_existing(&store_name) {
                        Ok(store) => {
                            // Resume where the reader last reported: zero on
                            // a new ring.
                            let next = ring.read_cursor_position();
                            return Ok(Ends {
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
                // Polled every millisecond at most: the writer may take a
                // while to start.
                if !backoff.step() {
                    return Err(ChannelError::OpenTimedOut {
                        name: ring_name,
                        waited: started.elapsed(),
                        last,
                    });
                }
            }
        })?;
        Ok(Self { ends: Some(ends) })
    }

    /// Send one message: `frames`, a list of `bytes`-like frames, or one
    /// `bytes`-like object as a single frame. Waits up to `timeout_s`
    /// seconds while the reader has `min(capacity, store_slots)` messages
    /// unread, then raises `TimeoutError` with nothing sent. Raises
    /// `EnvelopeTooLarge` (a `ValueError`) for a message over the 64 KB
    /// limit, with nothing sent. Writer end only.
    #[pyo3(signature = (frames, timeout_s = 5.0))]
    fn send(&mut self, py: Python<'_>, frames: &Bound<'_, PyAny>, timeout_s: f64) -> PyResult<()> {
        let timeout = seconds(timeout_s)?;
        let ends = self.ends()?;
        if !ends.writer {
            return Err(PyValueError::new_err("Channel.send on the reader end"));
        }
        let mut payload = Vec::new();
        let single = frames.cast::<PyBytes>().is_ok()
            || frames.cast::<pyo3::types::PyByteArray>().is_ok()
            || frames.cast::<pyo3::types::PyMemoryView>().is_ok();
        if single {
            payload.extend_from_slice(&1u32.to_le_bytes());
            push_frame(py, &mut payload, frames)?;
        } else {
            let list: Vec<Bound<'_, PyAny>> = frames
                .try_iter()
                .map_err(|_| {
                    PyTypeError::new_err("Channel.send takes a list of bytes-like frames, or one")
                })?
                .collect::<PyResult<_>>()?;
            let count = u32::try_from(list.len())
                .map_err(|_| EnvelopeTooLarge::new_err("too many frames"))?;
            payload.extend_from_slice(&count.to_le_bytes());
            for frame in &list {
                push_frame(py, &mut payload, frame)?;
                if payload.len() > MAX_ENTRY_SIZE {
                    // Already too large: stop copying.
                    return Err(ChannelError::TooLarge {
                        actual: payload.len() + envelope_overhead(),
                    }
                    .into());
                }
            }
        }
        py.detach(|| ends.send(payload, timeout))?;
        Ok(())
    }

    /// Receive the next message as a list of `bytes` frames, waiting up to
    /// `timeout_s` seconds (`None`: without limit); `None` if none came in
    /// time. Raises `ChannelClosed` (an `EOFError`) once the writer has
    /// closed the channel and every message has been read. Reader end only.
    #[pyo3(signature = (timeout_s = None))]
    fn recv<'py>(
        &mut self,
        py: Python<'py>,
        timeout_s: Option<f64>,
    ) -> PyResult<Option<Bound<'py, PyList>>> {
        let timeout = timeout_s.map(seconds).transpose()?;
        let ends = self.ends()?;
        if ends.writer {
            return Err(PyValueError::new_err("Channel.recv on the writer end"));
        }
        let Some(frames) = py.detach(|| ends.recv(timeout))? else {
            return Ok(None);
        };
        let frames = frames.iter().map(|frame| PyBytes::new(py, frame));
        Ok(Some(PyList::new(py, frames)?))
    }

    /// Close this end. The writer's close removes the ring's and the store's
    /// names (a reader still attached keeps reading what was sent, then gets
    /// `ChannelClosed`); the reader's only detaches. Closing twice is a
    /// no-op.
    fn close(&mut self) {
        self.ends = None;
    }

    fn __enter__(slf: Py<Self>) -> Py<Self> {
        slf
    }

    #[pyo3(signature = (*_args))]
    fn __exit__(&mut self, _args: &Bound<'_, pyo3::types::PyTuple>) -> bool {
        self.close();
        false
    }

    /// The ring's shared-memory name (leading slash included).
    #[getter]
    fn name(&mut self) -> PyResult<String> {
        Ok(self.ends()?.name.clone())
    }

    /// True for the writer end.
    #[getter]
    fn is_writer(&mut self) -> PyResult<bool> {
        Ok(self.ends()?.writer)
    }

    /// True once `close()` has run.
    #[getter]
    fn closed(&self) -> bool {
        self.ends.is_none()
    }

    /// Slots in the ring.
    #[getter]
    fn capacity(&mut self) -> PyResult<u64> {
        Ok(self.ends()?.ring.capacity())
    }

    /// Entries in the envelope store.
    #[getter]
    fn store_slots(&mut self) -> PyResult<usize> {
        Ok(self.ends()?.store.capacity())
    }

    /// Messages sent and not yet read, as the writer counts them.
    #[getter]
    fn pending(&mut self) -> PyResult<u64> {
        let ends = self.ends()?;
        Ok(ends
            .ring
            .cursor_position()
            .saturating_sub(ends.ring.read_cursor_position()))
    }

    fn __repr__(&self) -> String {
        match &self.ends {
            Some(ends) => format!(
                "Channel(name='{}', {}, capacity={}, store_slots={})",
                ends.name,
                if ends.writer { "writer" } else { "reader" },
                ends.ring.capacity(),
                ends.store.capacity()
            ),
            None => "Channel(closed)".into(),
        }
    }
}

/// A non-negative, finite number of seconds.
fn seconds(s: f64) -> PyResult<Duration> {
    Duration::try_from_secs_f64(s).map_err(|_| {
        PyValueError::new_err(format!(
            "timeout must be a non-negative number of seconds, got {s}"
        ))
    })
}
