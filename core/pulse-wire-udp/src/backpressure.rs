// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! Backpressure and NACK retransmission: the feedback from receiver to
//! sender, off the data path.
//!
//! The receiver's feedback thread sends its receive cursor, one past the
//! highest sequence number it has tracked, as an ACK every `ack_period`,
//! and with NACK on the NACKs that have fallen due. The sender's feedback
//! thread raises its view of the cursor and queues the NACKs, which the
//! send path serves from its send cache. A send waits while
//! `target_queue_depth` frames or more are in flight beyond the cursor, for
//! at most `stall_timeout` (`Sender::send_to`). A frame too far beyond the
//! receiver's contiguous head moves nothing until the next frame confirms
//! the jump (`Receiver::beyond_horizon_count`).
//!
//! With congestion control on ([`BackpressureConfig::with_congestion_control`],
//! [`crate::congestion`]), the ACKs grow a window within
//! `target_queue_depth` and the NACKs shrink it.
//!
//! With sealing on ([`crate::sealed`]), the receiver's feedback thread seals
//! each ACK and NACK under the session of the peer whose data it last took,
//! and the sender's feedback thread opens what its socket reads; the
//! layouts below are then the inner datagrams.
//!
//! Feedback is opt-in and lossy: a lost ACK delays the sender's view by one
//! `ack_period`. The feedback threads end only when the state that owns
//! them is dropped: a timeout or an interrupted call is a reason to go
//! round again, and any other socket error is counted, logged at the first
//! and each doubling, and survived.
//!
//! ## ACK wire format
//!
//! ```text
//! +--------+--------------+
//! | magic  | recv_cursor  |
//! | 4 B    | 8 B          |
//! +--------+--------------+
//! ```
//!
//! `magic` is [`ACK_MAGIC`]; a NACK is laid out the same, with
//! [`NACK_MAGIC`] and the missing sequence number.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use parking_lot::Mutex;
use std::thread;
use std::time::{Duration, Instant};

use crate::congestion::{Congestion, CongestionConfig};
use crate::retry::{count_error, is_retry, retry_interrupted};
use crate::sealed::{Opened, SealSlot, SEALED_OVERHEAD};

/// Magic prefixing every ACK datagram: `0x50 0x4D 0x53 0x41`, ASCII
/// `"PMSA"`, on the wire. Distinct from the data magic, so cross-traffic is
/// refused at both ends.
pub const ACK_MAGIC: u32 = 0x41534D50;

/// Magic prefixing every NACK datagram: `0x50 0x4D 0x53 0x4E`, ASCII
/// `"PMSN"`, on the wire. Distinct from the data magic and [`ACK_MAGIC`].
pub const NACK_MAGIC: u32 = 0x4E534D50;

/// Length on the wire of one ACK datagram in bytes
/// (`magic(4) + cursor(8)`).
pub const ACK_BYTES: usize = 4 + 8;

/// Length on the wire of one NACK datagram in bytes
/// (`magic(4) + missing_seq(8)`).
pub const NACK_BYTES: usize = 4 + 8;

/// The sender's feedback receive buffer: one byte longer than the longer
/// feedback datagram. A UDP receive cuts a longer datagram silently, so
/// with no byte to spare one that starts like an ACK or a NACK would pass
/// as one; with a byte to spare it arrives too long for the exact-length
/// decoders (checked by `tests/feedback_length.rs`).
pub(crate) const FEEDBACK_BUF_BYTES: usize = if ACK_BYTES > NACK_BYTES {
    ACK_BYTES + 1
} else {
    NACK_BYTES + 1
};

/// How long the sender's feedback thread waits in one receive before it
/// looks at its stop flag again, so the longest a drop waits for it.
const FEEDBACK_READ_TIMEOUT: Duration = Duration::from_millis(100);

/// The pause after an unexpected error on a feedback socket before the
/// thread tries again, so that an error that repeats at once cannot spin it.
const FEEDBACK_ERROR_PAUSE: Duration = Duration::from_millis(1);

/// The sender's feedback thread's name, within the 15 bytes of a name
/// Linux keeps.
const SENDER_FEEDBACK_THREAD: &str = "pw-udp-ack-recv";

/// The receiver's feedback thread's name; see [`SENDER_FEEDBACK_THREAD`].
const RECEIVER_FEEDBACK_THREAD: &str = "pw-udp-ack-send";

/// Default `target_queue_depth`: 16 outstanding Pulses (tunable per call).
pub const DEFAULT_TARGET_QUEUE_DEPTH: u32 = 16;

/// Default `ack_period`: one ACK per millisecond.
pub const DEFAULT_ACK_PERIOD: Duration = Duration::from_millis(1);

/// How long a waiting send sleeps between looks at the cursor, well below
/// the ACK period and a loopback round trip.
pub const STALL_SLEEP: Duration = Duration::from_micros(50);

/// Default `stall_timeout`: a send waits at most five seconds for the
/// receiver's cursor before it fails with
/// [`SenderError::Stalled`](crate::SenderError::Stalled).
pub const DEFAULT_STALL_TIMEOUT: Duration = Duration::from_secs(5);

/// Default `send_cache_capacity`: 1024 frames (≈256 KB at 256-B payload).
pub const DEFAULT_SEND_CACHE_CAPACITY: usize = 1024;

/// Cap on NACKs a receiver emits per ACK period, and on retransmits a
/// sender performs per frame it sends, singly or in a batch; staged
/// requests beyond it go out in later periods.
pub const MAX_NACKS_PER_CYCLE: usize = 16;

/// ACK periods a receiver waits after requesting a missing sequence
/// before it requests the sequence again.
pub const NACK_RETRY_PERIODS: u32 = 4;

/// Requests a receiver sends for one missing sequence before it gives up
/// on it: the first, then a repeat every [`NACK_RETRY_PERIODS`] ACK
/// periods while the sequence is still missing.
pub const MAX_NACK_ATTEMPTS: u32 = 3;

/// Configuration for backpressure, for both ends; each reads its fields:
///
/// | Field | Sender | Receiver |
/// |---|---|---|
/// | `target_queue_depth` | stall threshold | (ignored) |
/// | `stall_timeout` | stall deadline | (ignored) |
/// | `ack_period` | (ignored) | ACK and NACK cadence |
/// | `ack_bind_addr` | ACK-recv socket bind | (ignored) |
/// | `ack_target_addr` | (ignored) | ACK destination |
/// | `nack_enabled` | retransmit on request | stage and request gaps |
/// | `send_cache_capacity` | retransmit cache size | recovery window, NACK staging cap, horizon (twice it) |
/// | `feedback_peer` | feedback source filter | (ignored) |
/// | `congestion` | window within `target_queue_depth`, pacing | (ignored) |
///
/// Build it with [`Self::new`], then set fields or use the builders.
#[non_exhaustive]
#[derive(Clone, Debug)]
pub struct BackpressureConfig {
    /// Frames in flight beyond the receiver's cursor at which a send waits;
    /// at least 1
    /// ([`SenderError::InvalidQueueDepth`](crate::SenderError::InvalidQueueDepth)).
    /// Default [`DEFAULT_TARGET_QUEUE_DEPTH`].
    pub target_queue_depth: u32,
    /// How long one send waits for the cursor before it fails, unsent, with
    /// [`SenderError::Stalled`](crate::SenderError::Stalled); `None` waits
    /// as long as it takes, forever for a dead receiver. Default
    /// [`DEFAULT_STALL_TIMEOUT`].
    pub stall_timeout: Option<Duration>,
    /// Receiver ACK-send cadence. Default: [`DEFAULT_ACK_PERIOD`].
    pub ack_period: Duration,
    /// Local UDP address the **sender** binds for ACK receive. Port 0
    /// picks a free port; read it back with `Sender::ack_local_addr`.
    pub ack_bind_addr: SocketAddr,
    /// Remote UDP address the **receiver** sends ACKs to. Equal to
    /// the sender's `ack_bind_addr` from the receiver's perspective.
    pub ack_target_addr: SocketAddr,
    /// NACK and retransmission, on both ends or it does nothing. Off by
    /// default; see [`Self::with_nack`].
    pub nack_enabled: bool,
    /// The sender's retransmit cache, in frames. On the receiver, the
    /// recovery window: the widest gap it requests, the most sequence
    /// numbers it stages, and half its horizon
    /// (`Receiver::beyond_horizon_count`).
    pub send_cache_capacity: usize,
    /// When set, the sender drops and counts
    /// (`Sender::feedback_rejected_count`) feedback from any other source
    /// IP. Not taken from `connect`, since a multi-homed receiver may answer
    /// from another address.
    pub feedback_peer: Option<IpAddr>,
    /// Congestion control on the sender, `None` (the default) for none: a
    /// window of frames in flight, at most `target_queue_depth`, that ACKs
    /// grow and NACKs halve ([`crate::congestion`]). It hears of loss only
    /// from NACKs, so the receiver needs NACK on.
    pub congestion: Option<CongestionConfig>,
}

impl BackpressureConfig {
    /// A config with the default depth, stall timeout, ACK period and cache
    /// capacity, NACK off and no feedback filter.
    pub fn new(ack_bind_addr: SocketAddr, ack_target_addr: SocketAddr) -> Self {
        Self {
            target_queue_depth: DEFAULT_TARGET_QUEUE_DEPTH,
            stall_timeout: Some(DEFAULT_STALL_TIMEOUT),
            ack_period: DEFAULT_ACK_PERIOD,
            ack_bind_addr,
            ack_target_addr,
            nack_enabled: false,
            send_cache_capacity: DEFAULT_SEND_CACHE_CAPACITY,
            feedback_peer: None,
            congestion: None,
        }
    }

    /// Only accept ACK and NACK datagrams from `peer` (sender side).
    pub fn with_feedback_peer(mut self, peer: IpAddr) -> Self {
        self.feedback_peer = Some(peer);
        self
    }

    /// Set [`Self::stall_timeout`]: `Some(Duration::ZERO)` fails at once
    /// rather than wait, `None` waits as long as the cursor takes.
    pub fn with_stall_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.stall_timeout = timeout;
        self
    }

    /// Turn NACK on, with a send cache of `send_cache_capacity` frames. Set
    /// on both ends.
    pub fn with_nack(mut self, send_cache_capacity: usize) -> Self {
        self.nack_enabled = true;
        self.send_cache_capacity = send_cache_capacity;
        self
    }

    /// Turn congestion control on for the sender ([`Self::congestion`]).
    pub fn with_congestion_control(mut self, cfg: CongestionConfig) -> Self {
        self.congestion = Some(cfg);
        self
    }
}

/// Write an ACK carrying `cursor` into `out`, which is cleared first.
pub fn encode_ack(cursor: u64, out: &mut Vec<u8>) {
    out.clear();
    out.extend_from_slice(&ACK_MAGIC.to_le_bytes());
    out.extend_from_slice(&cursor.to_le_bytes());
    debug_assert_eq!(out.len(), ACK_BYTES);
}

/// Decode an ACK datagram. Returns `Some(cursor)` on success,
/// `None` if the buffer is the wrong length or carries a foreign
/// magic.
pub fn decode_ack(bytes: &[u8]) -> Option<u64> {
    if bytes.len() != ACK_BYTES {
        return None;
    }
    let magic = u32::from_le_bytes(bytes[0..4].try_into().ok()?);
    if magic != ACK_MAGIC {
        return None;
    }
    let cursor = u64::from_le_bytes(bytes[4..12].try_into().ok()?);
    Some(cursor)
}

/// Write a NACK for `missing_seq` into `out`, which is cleared first.
pub fn encode_nack(missing_seq: u64, out: &mut Vec<u8>) {
    out.clear();
    out.extend_from_slice(&NACK_MAGIC.to_le_bytes());
    out.extend_from_slice(&missing_seq.to_le_bytes());
    debug_assert_eq!(out.len(), NACK_BYTES);
}

/// Decode a NACK datagram. Returns `Some(missing_seq)` on
/// success, `None` on length mismatch or foreign magic.
pub fn decode_nack(bytes: &[u8]) -> Option<u64> {
    if bytes.len() != NACK_BYTES {
        return None;
    }
    let magic = u32::from_le_bytes(bytes[0..4].try_into().ok()?);
    if magic != NACK_MAGIC {
        return None;
    }
    let seq = u64::from_le_bytes(bytes[4..12].try_into().ok()?);
    Some(seq)
}

/// The sender's ring of recently sent datagrams, by sequence number, for
/// retransmission as they went out; public only for the fuzz harness.
#[doc(hidden)]
#[derive(Debug)]
pub struct SendCache {
    capacity: usize,
    slots: Vec<Option<CachedFrame>>,
}

/// One frame in a [`SendCache`].
#[doc(hidden)]
#[derive(Clone, Debug)]
pub struct CachedFrame {
    /// The sequence number the frame was sent under.
    pub seq: u64,
    /// The datagram as it was sent.
    pub encoded: Vec<u8>,
}

impl SendCache {
    /// A cache of `capacity` frames; zero is taken as one.
    pub fn new(capacity: usize) -> Self {
        let capacity = capacity.max(1);
        Self {
            capacity,
            slots: vec![None; capacity],
        }
    }

    /// Keep the encoded frame sent as `seq`, in place of the frame
    /// `capacity` sequence numbers before it.
    pub fn store(&mut self, seq: u64, encoded: &[u8]) {
        let idx = (seq as usize) % self.capacity;
        self.slots[idx] = Some(CachedFrame {
            seq,
            encoded: encoded.to_vec(),
        });
    }

    /// The frame sent as `seq`, while the cache still holds it.
    pub fn lookup(&self, seq: u64) -> Option<&CachedFrame> {
        let idx = (seq as usize) % self.capacity;
        self.slots[idx].as_ref().filter(|f| f.seq == seq)
    }

    /// Frames the cache holds at most.
    pub fn capacity(&self) -> usize {
        self.capacity
    }
}

/// Take up to `budget` retransmission requests from the front of `queue`,
/// oldest first: what the send path serves before each frame it sends.
pub(crate) fn drain_front(queue: &Mutex<VecDeque<u64>>, budget: usize) -> Vec<u64> {
    let mut q = queue.lock();
    let n = q.len().min(budget);
    q.drain(..n).collect()
}

/// The sender's backpressure: the feedback socket and thread, the cursor
/// and the NACK queue they fill, and the send cache the send path serves
/// the queue from.
pub(crate) struct SenderBpState {
    pub(crate) recv_cursor: Arc<AtomicU64>,
    pub(crate) target_queue_depth: u32,
    /// Longest one send stalls before it fails; `None` waits forever.
    pub(crate) stall_timeout: Option<Duration>,
    /// Bounded ring of recent encoded datagrams; `None` when NACK is off.
    pub(crate) send_cache: Option<Arc<Mutex<SendCache>>>,
    /// NACK requests the send path has yet to serve; empty with NACK off.
    pub(crate) pending_nacks: Arc<Mutex<VecDeque<u64>>>,
    /// See `Sender::retransmit_count`.
    pub(crate) retransmits: Arc<AtomicU64>,
    /// See `Sender::cache_miss_count`.
    pub(crate) cache_misses: Arc<AtomicU64>,
    /// Feedback datagrams dropped by the `feedback_peer` filter.
    pub(crate) feedback_rejected: Arc<AtomicU64>,
    /// NACKs dropped because the pending queue was full.
    pub(crate) nacks_dropped: Arc<AtomicU64>,
    /// See `Sender::feedback_error_count`.
    pub(crate) feedback_errors: Arc<AtomicU64>,
    /// The congestion window and round trip, with congestion control on.
    pub(crate) congestion: Option<Arc<Congestion>>,
    /// The feedback socket, shared with the thread that reads it, so that
    /// it outlives a thread that is stopped to be replaced.
    socket: Arc<UdpSocket>,
    /// Where the feedback socket actually bound (port 0 resolves here).
    pub(crate) local_addr: SocketAddr,
    /// The sender's sealing, which opens the feedback when installed.
    seal: SealSlot,
    stop: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}

/// Bind a feedback socket at `addr` with the read timeout its thread
/// needs, and return it with the address it bound.
fn bind_feedback(addr: SocketAddr) -> std::io::Result<(Arc<UdpSocket>, SocketAddr)> {
    let socket = UdpSocket::bind(addr)?;
    let local_addr = socket.local_addr()?;
    socket.set_read_timeout(Some(FEEDBACK_READ_TIMEOUT))?;
    Ok((Arc::new(socket), local_addr))
}

impl SenderBpState {
    /// Start backpressure for `cfg` on a sender whose next sequence number
    /// is `next_seq` and whose sealing, if any, `seal` holds.
    pub(crate) fn start(
        cfg: &BackpressureConfig,
        next_seq: u64,
        seal: SealSlot,
    ) -> std::io::Result<Self> {
        let (socket, local_addr) = bind_feedback(cfg.ack_bind_addr)?;
        let mut state = Self {
            recv_cursor: Arc::new(AtomicU64::new(0)),
            target_queue_depth: cfg.target_queue_depth,
            stall_timeout: cfg.stall_timeout,
            send_cache: None,
            pending_nacks: Arc::new(Mutex::new(VecDeque::new())),
            retransmits: Arc::new(AtomicU64::new(0)),
            cache_misses: Arc::new(AtomicU64::new(0)),
            feedback_rejected: Arc::new(AtomicU64::new(0)),
            nacks_dropped: Arc::new(AtomicU64::new(0)),
            feedback_errors: Arc::new(AtomicU64::new(0)),
            congestion: None,
            socket,
            local_addr,
            seal,
            stop: Arc::new(AtomicBool::new(true)),
            thread: None,
        };
        state.apply(cfg, next_seq);
        state.spawn(cfg)?;
        Ok(state)
    }

    /// Change the running state to `cfg` in place, as
    /// `Sender::enable_backpressure` describes.
    ///
    /// # Errors
    /// The I/O error from binding a new address, with nothing changed; or
    /// from starting the feedback thread again, after which the state has
    /// no thread and [`Self::is_running`] is false.
    pub(crate) fn reconfigure(
        &mut self,
        cfg: &BackpressureConfig,
        next_seq: u64,
    ) -> std::io::Result<()> {
        let rebound = if cfg.ack_bind_addr == self.local_addr {
            None
        } else {
            Some(bind_feedback(cfg.ack_bind_addr)?)
        };
        self.stop_thread();
        if let Some((socket, local_addr)) = rebound {
            self.socket = socket;
            self.local_addr = local_addr;
        }
        self.apply(cfg, next_seq);
        self.spawn(cfg)
    }

    /// Whether the feedback thread runs; only a failed
    /// [`Self::reconfigure`] leaves it stopped.
    pub(crate) fn is_running(&self) -> bool {
        self.thread.is_some()
    }

    /// Take the settings the send path reads from `cfg`, for a sender whose
    /// next sequence number is `next_seq`.
    fn apply(&mut self, cfg: &BackpressureConfig, next_seq: u64) {
        // The window carries over while its settings and its cap do.
        self.congestion = match (self.congestion.take(), &cfg.congestion) {
            (_, None) => None,
            (Some(running), Some(want))
                if running.config() == want
                    && self.target_queue_depth == cfg.target_queue_depth =>
            {
                Some(running)
            }
            (_, Some(want)) => Some(Arc::new(Congestion::new(
                want,
                cfg.target_queue_depth,
                self.recv_cursor.load(Ordering::Acquire),
                next_seq,
            ))),
        };
        self.target_queue_depth = cfg.target_queue_depth;
        self.stall_timeout = cfg.stall_timeout;
        let capacity = cfg.send_cache_capacity.max(1);
        self.send_cache = match self.send_cache.take() {
            _ if !cfg.nack_enabled => None,
            Some(cache) if cache.lock().capacity() == capacity => Some(cache),
            _ => Some(Arc::new(Mutex::new(SendCache::new(capacity)))),
        };
        // Queued requests the new settings would not have admitted go.
        let mut pending = self.pending_nacks.lock();
        pending.truncate(if cfg.nack_enabled { capacity } else { 0 });
    }

    /// Start the feedback thread on the current socket.
    fn spawn(&mut self, cfg: &BackpressureConfig) -> std::io::Result<()> {
        self.stop = Arc::new(AtomicBool::new(false));
        let feedback = SenderFeedback {
            socket: Arc::clone(&self.socket),
            seal: SealSlot::clone(&self.seal),
            stop: Arc::clone(&self.stop),
            intake: FeedbackIntake::sharing(
                Arc::clone(&self.recv_cursor),
                Arc::clone(&self.pending_nacks),
                Arc::clone(&self.feedback_rejected),
                Arc::clone(&self.nacks_dropped),
                self.congestion.clone(),
                cfg,
            ),
            errors: Arc::clone(&self.feedback_errors),
        };
        let thread = thread::Builder::new()
            .name(SENDER_FEEDBACK_THREAD.into())
            .spawn(move || feedback.run())?;
        self.thread = Some(thread);
        Ok(())
    }

    /// Stop the feedback thread and wait for it to end, at most one read
    /// timeout.
    fn stop_thread(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

/// The sender's feedback thread: it reads the feedback socket until
/// stopped and hands each datagram to its intake.
struct SenderFeedback {
    socket: Arc<UdpSocket>,
    seal: SealSlot,
    stop: Arc<AtomicBool>,
    intake: FeedbackIntake,
    errors: Arc<AtomicU64>,
}

impl SenderFeedback {
    /// [`FeedbackIntake::run`] on the socket, pausing
    /// [`FEEDBACK_ERROR_PAUSE`] after an unexpected error. With sealing on,
    /// each datagram is read whole and opened, and its inner datagram, cut
    /// to the intake's buffer as the socket would cut it, is what the intake
    /// takes; one the sealing takes (a refusal, a keepalive) reaches the
    /// intake empty, which it ignores.
    fn run(mut self) {
        let socket = &self.socket;
        let seal = &self.seal;
        let mut sealed = [0u8; FEEDBACK_BUF_BYTES + SEALED_OVERHEAD];
        self.intake.run(
            &self.stop,
            &self.errors,
            |buf| {
                let Some(sealing) = seal.read().clone() else {
                    return socket.recv_from(buf);
                };
                let (n, peer) = socket.recv_from(&mut sealed)?;
                let len = match sealing.open_feedback(&mut sealed, n, peer) {
                    Opened::Inner(len) => len.min(buf.len()),
                    Opened::Consumed => 0,
                };
                buf[..len].copy_from_slice(&sealed[..len]);
                Ok((len, peer))
            },
            || thread::sleep(FEEDBACK_ERROR_PAUSE),
        );
    }
}

/// What the sender does with feedback, without the socket or the thread:
/// an ACK raises the cursor the send path sees, a NACK queues a
/// retransmission request while NACK is on and the queue has room, and a
/// datagram from a source `feedback_peer` does not admit is dropped and
/// counted. Public only for the fuzz harness in `fuzz`.
#[doc(hidden)]
pub struct FeedbackIntake {
    recv_cursor: Arc<AtomicU64>,
    pending_nacks: Arc<Mutex<VecDeque<u64>>>,
    /// Whether NACKs are queued at all.
    nack_enabled: bool,
    /// Most NACKs queued at once.
    nack_cap: usize,
    /// The only source feedback is taken from, when set.
    expected_peer: Option<IpAddr>,
    /// A datagram from another source has been logged.
    warned_peer: bool,
    rejected: Arc<AtomicU64>,
    nacks_dropped: Arc<AtomicU64>,
    /// Told of every ACK and NACK, with congestion control on.
    congestion: Option<Arc<Congestion>>,
}

impl FeedbackIntake {
    /// An intake that has taken nothing yet, for a sender configured by
    /// `cfg`: it reads `nack_enabled`, `send_cache_capacity` (the most
    /// requests queued at once; zero is taken as one), `feedback_peer` and
    /// `congestion`.
    pub fn new(cfg: &BackpressureConfig) -> Self {
        Self::sharing(
            Arc::new(AtomicU64::new(0)),
            Arc::new(Mutex::new(VecDeque::new())),
            Arc::new(AtomicU64::new(0)),
            Arc::new(AtomicU64::new(0)),
            cfg.congestion
                .as_ref()
                .map(|c| Arc::new(Congestion::new(c, cfg.target_queue_depth, 0, 0))),
            cfg,
        )
    }

    /// An intake that keeps its cursor, queue and counts in the sender's
    /// shared state.
    fn sharing(
        recv_cursor: Arc<AtomicU64>,
        pending_nacks: Arc<Mutex<VecDeque<u64>>>,
        rejected: Arc<AtomicU64>,
        nacks_dropped: Arc<AtomicU64>,
        congestion: Option<Arc<Congestion>>,
        cfg: &BackpressureConfig,
    ) -> Self {
        Self {
            recv_cursor,
            pending_nacks,
            nack_enabled: cfg.nack_enabled,
            // The cache window: a request beyond it cannot be served, and
            // the receiver repeats one still missing.
            nack_cap: cfg.send_cache_capacity.max(1),
            expected_peer: cfg.feedback_peer.map(|ip| ip.to_canonical()),
            warned_peer: false,
            rejected,
            nacks_dropped,
            congestion,
        }
    }

    /// The congestion window, with congestion control on.
    pub fn congestion_window(&self) -> Option<u32> {
        self.congestion.as_ref().map(|c| c.window())
    }

    /// The receiver's cursor as the ACKs taken so far report it: the
    /// highest, or zero before the first.
    pub fn recv_cursor(&self) -> u64 {
        self.recv_cursor.load(Ordering::Acquire)
    }

    /// The retransmission requests queued and not yet drained, oldest
    /// first.
    pub fn pending_nacks(&self) -> Vec<u64> {
        self.pending_nacks.lock().iter().copied().collect()
    }

    /// Take up to `budget` queued requests, oldest first, as the send path
    /// does before each frame it sends.
    pub fn drain_nacks(&self, budget: usize) -> Vec<u64> {
        drain_front(&self.pending_nacks, budget)
    }

    /// Datagrams dropped because their source was not the `feedback_peer`.
    pub fn rejected_count(&self) -> u64 {
        self.rejected.load(Ordering::Relaxed)
    }

    /// NACKs dropped because the queue was full.
    pub fn nack_drop_count(&self) -> u64 {
        self.nacks_dropped.load(Ordering::Relaxed)
    }

    /// Take the datagrams `recv` returns until `stop` is set, which alone
    /// ends the loop. `recv` fills the buffer it is lent, one byte longer
    /// than the longer feedback datagram, as a UDP socket does, and returns
    /// the length and the source. A timeout or an interrupted call goes
    /// round again, past the stop flag; any other error is counted in
    /// `errors`, logged at the first and each doubling, and followed by
    /// `pause`, so a repeating error cannot spin the thread.
    pub fn run(
        &mut self,
        stop: &AtomicBool,
        errors: &AtomicU64,
        mut recv: impl FnMut(&mut [u8]) -> std::io::Result<(usize, SocketAddr)>,
        mut pause: impl FnMut(),
    ) {
        let mut buf = [0u8; FEEDBACK_BUF_BYTES];
        while !stop.load(Ordering::Acquire) {
            match recv(&mut buf) {
                Ok((n, peer)) => self.take(&buf[..n], peer),
                Err(e) if is_retry(&e) => {}
                Err(e) => {
                    if let Some(errors) = count_error(errors) {
                        tracing::warn!(
                            error = %e,
                            errors,
                            "feedback receive failed; the sender's feedback thread carries on"
                        );
                    }
                    pause();
                }
            }
        }
    }

    /// Take one feedback datagram that arrived from `peer`.
    pub fn take(&mut self, datagram: &[u8], peer: SocketAddr) {
        if let Some(want) = self.expected_peer {
            if peer.ip().to_canonical() != want {
                self.rejected.fetch_add(1, Ordering::Relaxed);
                if !self.warned_peer {
                    self.warned_peer = true;
                    tracing::warn!(
                        %peer,
                        expected = %want,
                        "feedback datagram from an unexpected peer dropped"
                    );
                }
                return;
            }
        }
        let Some(magic_bytes) = datagram.get(0..4).and_then(|s| <[u8; 4]>::try_from(s).ok()) else {
            return;
        };
        match u32::from_le_bytes(magic_bytes) {
            ACK_MAGIC => {
                if let Some(cursor) = decode_ack(datagram) {
                    // An ACK only ever raises the cursor, so a replayed or
                    // reordered one is harmless.
                    self.recv_cursor.fetch_max(cursor, Ordering::AcqRel);
                    if let Some(congestion) = &self.congestion {
                        congestion.on_ack(cursor);
                    }
                }
            }
            NACK_MAGIC => {
                if let Some(seq) = decode_nack(datagram) {
                    // A loss, whether or not this sender retransmits.
                    if let Some(congestion) = &self.congestion {
                        congestion.on_loss(seq);
                    }
                    if self.nack_enabled {
                        let mut q = self.pending_nacks.lock();
                        if q.len() < self.nack_cap {
                            q.push_back(seq);
                        } else {
                            self.nacks_dropped.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
            }
            // Unknown magic: ignored.
            _ => {}
        }
    }
}

impl Drop for SenderBpState {
    fn drop(&mut self) {
        self.stop_thread();
    }
}

/// The receiver's NACK staging, by sequence number.
///
/// A missing sequence number is staged once, by the arrival that reveals
/// it, and leaves when it arrives, when the contiguous head passes it, or
/// after its last request. Each ACK period takes at most
/// [`MAX_NACKS_PER_CYCLE`] requests: repeats that have fallen due first,
/// since older numbers leave the sender's cache first, then first
/// requests, lowest first. A number still missing [`NACK_RETRY_PERIODS`]
/// periods after a request is requested again, up to [`MAX_NACK_ATTEMPTS`]
/// requests in all.
///
/// At most `cap`, the recovery window, are staged at once; the head stays
/// within that window of the highest number seen, so what a wider gap
/// leaves outside is counted in `dropped` instead.
#[derive(Debug)]
pub(crate) struct NackStaging {
    /// Staged sequences and the requests sent for each so far.
    staged: BTreeMap<u64, u32>,
    /// Staged numbers from this one up have not been requested: gaps are
    /// revealed and first requests made in ascending order, so they are
    /// the tail of `staged`.
    first_unrequested: u64,
    /// Repeats as `(due, seq)`, sorted, since each is pushed one retry
    /// interval after its request; one whose number has left `staged` is
    /// skipped.
    repeats: VecDeque<(Instant, u64)>,
    /// Most sequences staged at once.
    cap: usize,
    /// Wait between a request and its repeat.
    retry_after: Duration,
    /// Missing sequences given up on before a single request.
    dropped: u64,
}

impl NackStaging {
    pub(crate) fn new(cap: usize, retry_after: Duration) -> Self {
        Self {
            staged: BTreeMap::new(),
            first_unrequested: 0,
            repeats: VecDeque::new(),
            cap: cap.max(1),
            retry_after,
            dropped: 0,
        }
    }

    /// Stage `from..to`, a run of sequences just revealed missing that
    /// lies above everything staged before. What does not fit under the
    /// cap is counted as dropped; the receiver's head jump keeps the run
    /// inside the window, so the cap is a backstop.
    pub(crate) fn stage(&mut self, from: u64, to: u64) {
        for seq in from..to {
            if self.staged.len() >= self.cap {
                self.dropped = self.dropped.saturating_add(to - seq);
                return;
            }
            self.staged.insert(seq, 0);
        }
    }

    /// `seq` arrived, so it is no longer missing.
    pub(crate) fn arrived(&mut self, seq: u64) {
        self.staged.remove(&seq);
    }

    /// The head jumped to `floor` past a gap the sender can no longer
    /// fill: stop requesting everything below it. Staged sequences below
    /// it that were never requested count as dropped, and so do
    /// `never_staged` sequences that the same arrival revealed missing
    /// below it.
    pub(crate) fn give_up_below(&mut self, floor: u64, never_staged: u64) {
        let kept = self.staged.split_off(&floor);
        let unrequested = self.staged.range(self.first_unrequested..).count() as u64;
        self.staged = kept;
        self.first_unrequested = self.first_unrequested.max(floor);
        self.dropped = self
            .dropped
            .saturating_add(unrequested)
            .saturating_add(never_staged);
    }

    /// Fill `out` with the requests due by `now`, at most `max`: repeats
    /// that have fallen due, then first requests, lowest sequence first.
    pub(crate) fn take_due(&mut self, now: Instant, max: usize, out: &mut Vec<u64>) {
        out.clear();
        while out.len() < max {
            let Some(&(due, seq)) = self.repeats.front() else {
                break;
            };
            if due > now {
                break;
            }
            self.repeats.pop_front();
            let Some(attempts) = self.staged.get_mut(&seq) else {
                // Arrived, or passed by the head, since its last request.
                continue;
            };
            *attempts += 1;
            let attempts = *attempts;
            out.push(seq);
            self.requested(seq, attempts, now);
        }
        while out.len() < max {
            let Some((&seq, attempts)) = self.staged.range_mut(self.first_unrequested..).next()
            else {
                break;
            };
            *attempts = 1;
            // Staged sequences lie below an arrival, so below u64::MAX.
            self.first_unrequested = seq.saturating_add(1);
            out.push(seq);
            self.requested(seq, 1, now);
        }
    }

    /// After the `attempts`-th request for `seq`: schedule its repeat, or
    /// stop tracking it once it has had its last request.
    fn requested(&mut self, seq: u64, attempts: u32, now: Instant) {
        if attempts >= MAX_NACK_ATTEMPTS {
            self.staged.remove(&seq);
        } else if let Some(due) = now.checked_add(self.retry_after) {
            self.repeats.push_back((due, seq));
        }
    }

    /// Missing sequences given up on before a single request.
    pub(crate) fn dropped(&self) -> u64 {
        self.dropped
    }

    /// The sequences staged, in order.
    pub(crate) fn staged(&self) -> Vec<u64> {
        self.staged.keys().copied().collect()
    }
}

/// The receiver's tracking of the stream, without its socket or thread:
/// the ACK cursor, the contiguous head, the out-of-order set, NACK staging
/// and the horizon, fed every decoded frame's number ([`Self::arrived`]).
/// Public only for the fuzz harness, whose `fuzz_stream_tracking` target
/// checks its invariants.
#[doc(hidden)]
pub struct StreamTracker {
    /// One past the highest seq tracked: the cursor the ACKs publish.
    recv_cursor: AtomicU64,
    /// The lowest seq not arrived that no resync gave up on.
    contiguous_head: AtomicU64,
    /// Seqs received above the contiguous head.
    out_of_order: Mutex<BTreeSet<u64>>,
    /// Missing seqs staged for NACK.
    nack_staging: Mutex<NackStaging>,
    /// Whether NACKs are staged and emitted at all.
    nack_enabled: bool,
    /// The sender's retransmit cache size: nothing older than
    /// `seq - recovery_window` can be recovered. Also the staging cap.
    recovery_window: u64,
    /// How far beyond the contiguous head a frame may lie and still move
    /// the cursor and gap tracking: twice the recovery window.
    horizon: u64,
    /// The last frame that arrived beyond the horizon without moving
    /// anything, waiting for a second to confirm that the stream jumped.
    pending_jump: Mutex<Option<u64>>,
    /// See `Receiver::beyond_horizon_count`.
    beyond_horizon: AtomicU64,
    /// Times the contiguous head jumped forward past an unrecoverable gap.
    gap_resyncs: AtomicU64,
}

impl StreamTracker {
    /// Tracking that has seen no frame, for a receiver configured by `cfg`:
    /// it reads `send_cache_capacity` (the recovery window; zero is taken
    /// as one), `nack_enabled`, and `ack_period`, which times the repeats.
    pub fn new(cfg: &BackpressureConfig) -> Self {
        let recovery_window = cfg.send_cache_capacity.max(1);
        let nack_staging = NackStaging::new(
            recovery_window,
            cfg.ack_period.saturating_mul(NACK_RETRY_PERIODS),
        );
        let recovery_window = recovery_window as u64;
        Self {
            recv_cursor: AtomicU64::new(0),
            contiguous_head: AtomicU64::new(0),
            out_of_order: Mutex::new(BTreeSet::new()),
            nack_staging: Mutex::new(nack_staging),
            nack_enabled: cfg.nack_enabled,
            recovery_window,
            horizon: recovery_window.saturating_mul(2),
            pending_jump: Mutex::new(None),
            beyond_horizon: AtomicU64::new(0),
            gap_resyncs: AtomicU64::new(0),
        }
    }

    /// A frame numbered `seq` arrived: within the horizon, advance the ACK
    /// cursor to `max(current, seq + 1)` and feed gap tracking.
    ///
    /// Beyond it (`Receiver::beyond_horizon_count` says why) the frame
    /// moves nothing, is counted, and waits as the pending jump, until a
    /// second frame beyond the horizon replaces it or, within one recovery
    /// window of it, confirms the jump: both are then tracked, the later
    /// first.
    pub fn arrived(&self, seq: u64) {
        let head = self.contiguous_head.load(Ordering::Acquire);
        // `u64::MAX` has no successor for the cursor to hold, and only a
        // forged or corrupt frame carries it: it is never tracked, nor
        // taken as the start of a jump.
        if seq != u64::MAX && seq.saturating_sub(head) <= self.horizon {
            self.track(seq);
            return;
        }
        let confirmed = {
            let mut pending = self.pending_jump.lock();
            match *pending {
                Some(first)
                    if seq != u64::MAX
                        && seq != first
                        && seq.abs_diff(first) <= self.recovery_window =>
                {
                    *pending = None;
                    Some(first)
                }
                _ => {
                    if seq != u64::MAX {
                        *pending = Some(seq);
                    }
                    None
                }
            }
        };
        match confirmed {
            Some(first) => {
                self.track(seq.max(first));
                self.track(seq.min(first));
            }
            None => {
                if let Some(count) = count_error(&self.beyond_horizon) {
                    tracing::warn!(
                        seq,
                        contiguous_head = head,
                        beyond_horizon = count,
                        "frame far beyond the contiguous head left the ACK cursor and gap tracking alone"
                    );
                }
            }
        }
    }

    /// What a frame within the horizon does to the tracking: the cursor
    /// goes to `max(current, seq + 1)`, and the head, the out-of-order set
    /// and NACK staging follow. Only an arrival above the highest seq seen
    /// reveals missing seqs, those between the two, so each is staged once.
    /// `seq` is below `u64::MAX`. The invariants are those
    /// `fuzz_stream_tracking` checks.
    fn track(&self, seq: u64) {
        // One past the highest seq seen before this frame.
        let prev_cursor = self.recv_cursor.fetch_max(seq + 1, Ordering::AcqRel);
        let head = self.contiguous_head.load(Ordering::Acquire);
        if seq < head {
            // Stale, or a late retransmit.
            return;
        }
        let mut ooo = self.out_of_order.lock();
        if seq == head {
            let mut new_head = seq + 1;
            while ooo.remove(&new_head) {
                new_head += 1;
            }
            self.contiguous_head.store(new_head, Ordering::Release);
            if seq < prev_cursor && self.nack_enabled {
                // It filled the hole at the head, which was staged.
                self.nack_staging.lock().arrived(seq);
            }
            return;
        }
        if seq < prev_cursor {
            // It filled a hole between the head and the highest seq.
            ooo.insert(seq);
            if self.nack_enabled {
                self.nack_staging.lock().arrived(seq);
            }
            return;
        }
        // The highest seq yet: [prev_cursor, seq) is newly missing. A gap
        // wider than the retransmit cache cannot be recovered, so the head
        // first jumps into the window, which keeps the work per arrival and
        // both sets bounded, a joiner's far jump included. It lands on the
        // first seq from the floor up that has not arrived.
        let mut staging = self.nack_enabled.then(|| self.nack_staging.lock());
        let mut stage_from = prev_cursor.max(head);
        let mut new_head = head;
        if seq - head > self.recovery_window {
            let floor = seq - self.recovery_window;
            *ooo = ooo.split_off(&floor);
            new_head = floor;
            while ooo.remove(&new_head) {
                new_head += 1;
            }
            self.gap_resyncs.fetch_add(1, Ordering::Relaxed);
            if let Some(staged) = staging.as_mut() {
                staged.give_up_below(floor, floor.saturating_sub(stage_from));
            }
            stage_from = stage_from.max(floor);
        }
        if new_head == seq {
            // Everything from the floor up to this frame had arrived.
            new_head = seq + 1;
        } else {
            ooo.insert(seq);
        }
        if new_head != head {
            self.contiguous_head.store(new_head, Ordering::Release);
        }
        if let Some(staged) = staging.as_mut() {
            staged.stage(stage_from, seq);
        }
    }

    /// The ACK cursor: one past the highest seq tracked, zero before the
    /// first.
    pub fn recv_cursor(&self) -> u64 {
        self.recv_cursor.load(Ordering::Acquire)
    }

    /// The lowest seq that has not arrived and that no resync gave up on.
    pub fn contiguous_head(&self) -> u64 {
        self.contiguous_head.load(Ordering::Acquire)
    }

    /// The seqs that arrived above the contiguous head, in order.
    pub fn out_of_order(&self) -> Vec<u64> {
        self.out_of_order.lock().iter().copied().collect()
    }

    /// The missing seqs staged for NACK and not yet given up on, in order.
    pub fn staged(&self) -> Vec<u64> {
        self.nack_staging.lock().staged()
    }

    /// Fill `out` with the NACKs due by `now`, at most `max`, as the
    /// feedback thread does every ACK period.
    pub fn take_nacks_due(&self, now: Instant, max: usize, out: &mut Vec<u64>) {
        self.nack_staging.lock().take_due(now, max, out);
    }

    /// Whether NACKs are staged at all.
    pub fn nack_enabled(&self) -> bool {
        self.nack_enabled
    }

    /// Frames that arrived beyond the horizon and moved nothing.
    pub fn beyond_horizon_count(&self) -> u64 {
        self.beyond_horizon.load(Ordering::Relaxed)
    }

    /// Times the contiguous head jumped past an unrecoverable gap.
    pub fn gap_resyncs(&self) -> u64 {
        self.gap_resyncs.load(Ordering::Relaxed)
    }

    /// Missing seqs given up on before a single request.
    pub fn nack_drop_count(&self) -> u64 {
        self.nack_staging.lock().dropped()
    }
}

/// The receiver's backpressure: the stream tracking and the feedback
/// thread that reports it every `ack_period`.
pub(crate) struct ReceiverBpState {
    /// The stream tracking the receiver feeds and the thread reads.
    pub(crate) tracker: Arc<StreamTracker>,
    /// See `Receiver::nacks_sent`.
    pub(crate) nacks_sent: Arc<AtomicU64>,
    /// See `Receiver::feedback_error_count`.
    pub(crate) feedback_errors: Arc<AtomicU64>,
    stop: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}

impl ReceiverBpState {
    /// Start the feedback thread for `cfg`, sealing with the sealing `seal`
    /// holds when there is one.
    pub(crate) fn start(cfg: &BackpressureConfig, seal: SealSlot) -> std::io::Result<Self> {
        // Any local port, in the target's family: an IPv4 socket cannot
        // reach an IPv6 feedback address.
        let local: SocketAddr = match cfg.ack_target_addr {
            SocketAddr::V4(_) => (Ipv4Addr::UNSPECIFIED, 0).into(),
            SocketAddr::V6(_) => (Ipv6Addr::UNSPECIFIED, 0).into(),
        };
        let socket = UdpSocket::bind(local)?;
        socket.connect(cfg.ack_target_addr)?;
        let tracker = Arc::new(StreamTracker::new(cfg));
        let nacks_sent = Arc::new(AtomicU64::new(0));
        let feedback_errors = Arc::new(AtomicU64::new(0));
        let stop = Arc::new(AtomicBool::new(false));

        let feedback = ReceiverFeedback {
            socket,
            seal,
            stop: Arc::clone(&stop),
            tracker: Arc::clone(&tracker),
            nacks_sent: Arc::clone(&nacks_sent),
            errors: Arc::clone(&feedback_errors),
            ack_period: cfg.ack_period,
        };
        let thread = thread::Builder::new()
            .name(RECEIVER_FEEDBACK_THREAD.into())
            .spawn(move || feedback.run())?;

        Ok(Self {
            tracker,
            nacks_sent,
            feedback_errors,
            stop,
            thread: Some(thread),
        })
    }
}

/// The receiver's feedback thread: every ACK period it sends the cursor as
/// an ACK and the NACKs that have fallen due, until the receiver stops it.
struct ReceiverFeedback {
    socket: UdpSocket,
    seal: SealSlot,
    stop: Arc<AtomicBool>,
    tracker: Arc<StreamTracker>,
    nacks_sent: Arc<AtomicU64>,
    errors: Arc<AtomicU64>,
    ack_period: Duration,
}

impl ReceiverFeedback {
    /// Send feedback every ACK period until the stop flag is set, which
    /// alone ends the loop. A datagram that cannot be sent is counted; the
    /// next period's ACK carries the cursor as it is then, and a lost NACK
    /// is repeated after its retry interval, while it has requests left.
    fn run(self) {
        let mut buf = Vec::with_capacity(ACK_BYTES.max(NACK_BYTES));
        let mut sealed = Vec::with_capacity(ACK_BYTES.max(NACK_BYTES) + SEALED_OVERHEAD);
        let mut due = Vec::with_capacity(MAX_NACKS_PER_CYCLE);
        while !self.stop.load(Ordering::Acquire) {
            encode_ack(self.tracker.recv_cursor(), &mut buf);
            self.send(&buf, &mut sealed);

            // Each NACK is its own datagram, so a lost one loses no other.
            if self.tracker.nack_enabled() {
                self.tracker
                    .take_nacks_due(Instant::now(), MAX_NACKS_PER_CYCLE, &mut due);
                for &missing in &due {
                    encode_nack(missing, &mut buf);
                    if self.send(&buf, &mut sealed) {
                        self.nacks_sent.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }

            // `thread::sleep` sleeps again for what is left when a signal
            // cuts it short.
            thread::sleep(self.ack_period);
        }
    }

    /// Send one feedback datagram, again if a signal interrupts it; count a
    /// failure and log the first and each doubling. With sealing on it is
    /// sealed into `sealed` first; with no session to seal under yet it is
    /// not sent, and the sealing counts it.
    fn send(&self, datagram: &[u8], sealed: &mut Vec<u8>) -> bool {
        let sealing = self.seal.read().clone();
        let datagram = match &sealing {
            None => datagram,
            Some(sealing) => {
                if !sealing.seal_feedback(datagram, sealed) {
                    return false;
                }
                sealed.as_slice()
            }
        };
        match retry_interrupted(|| self.socket.send(datagram)) {
            Ok(_) => true,
            Err(e) => {
                if let Some(errors) = count_error(&self.errors) {
                    tracing::warn!(
                        error = %e,
                        errors,
                        "feedback datagram not sent; the receiver's feedback thread carries on"
                    );
                }
                false
            }
        }
    }
}

impl Drop for ReceiverBpState {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn ack_round_trip() {
        let mut buf = Vec::new();
        encode_ack(0, &mut buf);
        assert_eq!(buf.len(), ACK_BYTES);
        assert_eq!(decode_ack(&buf), Some(0));

        encode_ack(u64::MAX, &mut buf);
        assert_eq!(decode_ack(&buf), Some(u64::MAX));

        encode_ack(123_456_789, &mut buf);
        assert_eq!(decode_ack(&buf), Some(123_456_789));
    }

    #[test]
    fn decode_rejects_wrong_length() {
        assert_eq!(decode_ack(&[]), None);
        assert_eq!(decode_ack(&[0; ACK_BYTES - 1]), None);
        assert_eq!(decode_ack(&[0; ACK_BYTES + 1]), None);
    }

    #[test]
    fn decode_rejects_foreign_magic() {
        let mut buf = Vec::new();
        // Use the data magic instead of ACK_MAGIC.
        buf.extend_from_slice(&crate::wire::MAGIC.to_le_bytes());
        buf.extend_from_slice(&123u64.to_le_bytes());
        assert_eq!(decode_ack(&buf), None);
    }

    #[test]
    fn ack_magic_distinct_from_data_magic() {
        assert_ne!(ACK_MAGIC, crate::wire::MAGIC);
    }

    #[test]
    fn config_default_constants() {
        assert_eq!(DEFAULT_TARGET_QUEUE_DEPTH, 16);
        assert_eq!(DEFAULT_ACK_PERIOD, Duration::from_millis(1));
        assert_eq!(DEFAULT_STALL_TIMEOUT, Duration::from_secs(5));
    }

    const RETRY: Duration = Duration::from_millis(40);

    fn take(s: &mut NackStaging, at: Instant) -> Vec<u64> {
        let mut out = Vec::new();
        s.take_due(at, MAX_NACKS_PER_CYCLE, &mut out);
        out
    }

    #[test]
    fn a_missing_seq_is_requested_once_per_attempt_up_to_the_limit() {
        let t0 = Instant::now();
        let mut s = NackStaging::new(64, RETRY);
        s.stage(1, 2);
        let mut requests = 0;
        for step in 0..(4 * MAX_NACK_ATTEMPTS) {
            let now = t0 + RETRY * step;
            let first = take(&mut s, now);
            assert!(first.iter().all(|&seq| seq == 1), "{first:?}");
            requests += first.len();
            let early = take(&mut s, now + RETRY / 2);
            assert!(early.is_empty(), "repeat before the interval: {early:?}");
        }
        assert_eq!(requests, MAX_NACK_ATTEMPTS as usize);
        assert!(s.staged.is_empty(), "the seq leaves after its last request");
        assert!(s.repeats.is_empty());
        assert_eq!(s.dropped(), 0);
    }

    #[test]
    fn requests_go_out_at_most_max_per_cycle_lowest_first() {
        let t0 = Instant::now();
        let mut s = NackStaging::new(64, RETRY);
        s.stage(0, 40);
        assert_eq!(take(&mut s, t0), (0..16).collect::<Vec<_>>());
        assert_eq!(take(&mut s, t0), (16..32).collect::<Vec<_>>());
        assert_eq!(take(&mut s, t0), (32..40).collect::<Vec<_>>());
        assert!(take(&mut s, t0).is_empty());
        // Repeats come due in the order the first requests went out.
        assert_eq!(take(&mut s, t0 + RETRY), (0..16).collect::<Vec<_>>());
    }

    #[test]
    fn an_arrived_seq_is_not_requested_again() {
        let t0 = Instant::now();
        let mut s = NackStaging::new(64, RETRY);
        s.stage(0, 4);
        assert_eq!(take(&mut s, t0), vec![0, 1, 2, 3]);
        s.arrived(1);
        s.arrived(2);
        s.stage(10, 12);
        s.arrived(10);
        assert_eq!(take(&mut s, t0 + RETRY), vec![0, 3, 11]);
    }

    #[test]
    fn giving_up_below_a_floor_counts_only_what_was_never_requested() {
        let t0 = Instant::now();
        let mut s = NackStaging::new(64, RETRY);
        s.stage(0, 10);
        let mut out = Vec::new();
        s.take_due(t0, 4, &mut out);
        assert_eq!(out, vec![0, 1, 2, 3]);
        // 0..4 were requested; 4 and 5 were staged but not yet requested;
        // 5 more were revealed below the floor without being staged.
        s.give_up_below(6, 5);
        assert_eq!(s.dropped(), 7);
        assert_eq!(take(&mut s, t0), vec![6, 7, 8, 9]);
        let repeats = take(&mut s, t0 + RETRY);
        assert!(repeats.iter().all(|&seq| seq >= 6), "{repeats:?}");
    }

    #[test]
    fn the_cap_bounds_the_staged_set_and_counts_the_rest() {
        let t0 = Instant::now();
        let mut s = NackStaging::new(8, RETRY);
        s.stage(0, 20);
        assert_eq!(s.staged.len(), 8);
        assert_eq!(s.dropped(), 12);
        assert_eq!(take(&mut s, t0), (0..8).collect::<Vec<_>>());
    }

    #[test]
    fn stall_timeout_defaults_on_and_can_be_cleared() {
        let any: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let cfg = BackpressureConfig::new(any, any);
        assert_eq!(cfg.stall_timeout, Some(DEFAULT_STALL_TIMEOUT));
        let cfg = cfg.with_stall_timeout(Some(Duration::from_millis(300)));
        assert_eq!(cfg.stall_timeout, Some(Duration::from_millis(300)));
        assert_eq!(cfg.with_stall_timeout(None).stall_timeout, None);
    }
}
