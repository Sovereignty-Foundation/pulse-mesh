// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! The receiving end: [`Receiver`]. A datagram that does not decode is an
//! error of the call that read it ([`ReceiverError::Decode`]), and a read
//! timeout an I/O error [`ReceiverError::is_timeout`] recognises.

use std::collections::VecDeque;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

use pulse_canon::Pulse;

use crate::backpressure::{BackpressureConfig, ReceiverBpState, StreamTracker};
use crate::fec::{decode_fec, FecDecoder, FEC_MAGIC};
use crate::fragment::{decode_fragment, Fragment, Reassembler, ReassemblyConfig, FRAG_MAGIC};
use crate::order::{DeliveryConfig, Order, Sequencer};
use crate::retry::retry_interrupted;
use crate::sealed::{Opened, PublicKey, SealSlot, Sealing, SEALED_OVERHEAD};
use crate::wire::{decode, HEADER_BYTES, MAGIC as DATA_MAGIC, MAX_ENVELOPE, MTU_BYTES};

/// A received frame's sequence number, send time and sender.
#[derive(Debug, Clone, Copy)]
pub struct RecvMeta {
    /// The sender's sequence number.
    pub seq: u64,
    /// The sender's clock in nanoseconds, as its caller gave it.
    pub send_ns: u64,
    /// Peer that sent the datagram (from `recvfrom`). A source address can
    /// be forged; with sealing, [`Self::sealed_by`] names the sender.
    pub peer: SocketAddr,
    /// With sealing, the public key of the peer whose session opened the
    /// datagram ([`crate::sealed`]): the sender, authenticated. For a run
    /// of fragments, the key that opened every fragment of it (a run is made
    /// only of fragments one key opened); for a frame rebuilt from parity,
    /// the key that opened the datagram completing its window. `None` for a
    /// datagram taken in plaintext.
    pub sealed_by: Option<PublicKey>,
}

#[non_exhaustive]
/// Errors returned by [`Receiver::recv`] and [`Receiver::recv_into`].
#[derive(Debug, thiserror::Error)]
pub enum ReceiverError {
    /// Socket I/O error. `WouldBlock` from a timeout is one of these.
    #[error("udp recv failed: {0}")]
    Io(#[from] std::io::Error),
    /// The datagram failed wire-format validation (magic, version, length
    /// or CRC).
    #[error("frame decode failed: {0}")]
    Decode(#[from] crate::wire::WireError),
    /// The envelope does not fit the buffer given to
    /// [`Receiver::recv_into`]; the frame is consumed.
    #[error("envelope buffer too small: needed {needed} bytes, provided {provided}")]
    BufferTooSmall {
        /// Envelope length on the wire in bytes.
        needed: usize,
        /// Buffer length the caller provided.
        provided: usize,
    },
    /// A decoded frame's 128 pulse bytes are not a [`pulse_canon::Pulse`]:
    /// a sender bug.
    #[error("pulse bytes could not be decoded into a Pulse struct")]
    InvalidPulseBytes,
}

impl ReceiverError {
    /// Whether this is a read whose timeout passed (`WouldBlock` on Unix,
    /// `TimedOut` on Windows).
    pub fn is_timeout(&self) -> bool {
        matches!(
        self,
        Self::Io(e)
        if e.kind() == std::io::ErrorKind::WouldBlock
        || e.kind() == std::io::ErrorKind::TimedOut
        )
    }
}

/// Errors returned by [`Receiver::recv_batch_into`] for failures of the
/// call as a whole. Per-datagram failures are reported in
/// [`BatchRecvResult::errors`] rather than here.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum BatchRecvError {
    /// Reading the first datagram failed, so nothing was read; a timeout
    /// (`WouldBlock` or `TimedOut`) means none arrived within the socket's
    /// read timeout.
    #[error("batch receive failed: {0}")]
    Io(std::io::Error),
    /// `max_frames` exceeded [`crate::sender::MAX_BATCH_FRAMES`].
    #[error("batch size {got} exceeds maximum {max}")]
    BatchTooLarge {
        /// Requested batch size.
        got: usize,
        /// Hard limit ([`crate::sender::MAX_BATCH_FRAMES`]).
        max: usize,
    },
    /// `envelopes.len()` is smaller than `max_frames`.
    #[error("envelope buffer slice has {buffers} entries, need at least {requested}")]
    InsufficientBuffers {
        /// Number of buffers the caller provided.
        buffers: usize,
        /// Minimum required (= `max_frames`).
        requested: usize,
    },
}

/// A per-item failure from [`Receiver::recv_batch_into`]: a datagram
/// that arrived but could not be decoded or delivered, or a frame rebuilt
/// from parity whose envelope did not fit its slot.
#[derive(Debug)]
pub struct BatchRecvFrameError {
    /// Position of the failing item among those the call took, counting
    /// from 0: first the datagrams it read, in arrival order and parity
    /// included, then the frames rebuilt from parity or held from an
    /// earlier call that it took, in delivery order.
    pub frame_index: usize,
    /// The decode or buffer error.
    pub error: ReceiverError,
}

/// Return value of a successful [`Receiver::recv_batch_into`] call.
/// `envelopes[j]` holds the envelope bytes for `frames[j]`; an item that
/// fails uses no slot and surfaces in `errors`.
#[derive(Debug)]
pub struct BatchRecvResult {
    /// Frames delivered: those decoded from the datagrams this call read,
    /// in arrival order, then frames rebuilt from parity; or, in a call
    /// that found frames held from an earlier call, those.
    pub frames: Vec<(Pulse, usize, RecvMeta)>,
    /// Items that failed. `frame_index` says which item, not which
    /// envelope slot.
    pub errors: Vec<BatchRecvFrameError>,
    /// Datagrams this call read from the socket, parity included. A parity
    /// datagram yields no frame, and a rebuilt or held frame has no
    /// datagram in this call, so this need not equal
    /// `frames.len() + errors.len()`.
    pub received: usize,
}

/// A frame rebuilt from parity, or a run of fragments reassembled, held
/// until a receive call delivers it; public only as part of [`DataIntake`],
/// the fuzz harness's way in.
#[doc(hidden)]
#[derive(Debug)]
pub struct PendingRecovered {
    /// The rebuilt frame's Pulse.
    pub pulse: Pulse,
    /// The rebuilt frame's envelope.
    pub envelope: Vec<u8>,
    /// The rebuilt frame's sequence number and send time, and the peer
    /// whose datagram completed its window; for a run, its first sequence
    /// number and the peer whose datagram completed it.
    pub meta: RecvMeta,
    /// A run of fragments reassembled: each fragment reached the stream
    /// tracking as it arrived, so delivering the run feeds it nothing.
    pub reassembled: bool,
    /// Sequence numbers it spans: one for a frame, the fragments for a run.
    pub span: u16,
}

/// What [`DataIntake::dispatch`] made of one datagram; public only as part
/// of [`DataIntake`], the fuzz harness's way in.
#[doc(hidden)]
#[derive(Debug)]
// A data frame carries its Pulse and metadata, the key that sealed it
// included, and the other outcomes nothing: the value is returned once per
// datagram and consumed at once, never stored, so boxing the frame would only
// add an allocation to every receive.
#[allow(clippy::large_enum_variant)]
pub enum Dispatched {
    /// A data frame, its envelope given as a place in the datagram, so the
    /// caller copies it once, before the next read overwrites it.
    Data {
        /// The frame's Pulse.
        pulse: Pulse,
        /// Where the envelope starts in the datagram.
        env_offset: usize,
        /// The envelope's length in bytes.
        env_len: usize,
        /// The frame's sequence number and send time, and the datagram's
        /// peer.
        meta: RecvMeta,
    },
    /// Parity, taken by the FEC decoder or, with FEC off, dropped; the
    /// caller looks for held frames, then reads on.
    ParityConsumed,
    /// A fragment, taken by the reassembler, which holds a run it completes
    /// for delivery as a rebuilt frame is held, or, with reassembly off,
    /// dropped and counted; the caller looks for held frames, then reads on.
    FragmentConsumed,
    /// A datagram from a source the data-peer filter does not admit was
    /// dropped and counted; the caller loops on the wire.
    Foreign,
}

/// Receives frames over UDP into a one-MTU buffer.
///
/// Opt-in: acknowledgements and NACKs to the sender
/// ([`Receiver::enable_backpressure`]), recovery from parity
/// ([`Receiver::enable_fec`]), a source filter
/// ([`Receiver::with_data_peer`]), sealing ([`Receiver::with_sealing`]),
/// reassembly of runs of fragments ([`Receiver::enable_reassembly`]) and
/// delivery options ([`Receiver::enable_delivery`]).
///
/// By default every frame that decodes is delivered as it arrives, and
/// duplicates are not suppressed: with NACK or FEC on, a sequence number
/// can arrive twice, as a retransmission or a rebuilt frame whose original
/// arrived too. The delivery options deliver each once, in arrival order
/// or in sequence order ([`crate::order`]).
pub struct Receiver {
    socket: UdpSocket,
    recv_buf: Vec<u8>,
    bp: Option<ReceiverBpState>,
    /// The filter, decode, FEC and tracking each datagram read goes through.
    intake: DataIntake,
    /// With sealing on: every datagram read is opened before the intake.
    sealing: Option<Sealing>,
    /// The sealing the feedback thread seals ACKs and NACKs with.
    seal_slot: SealSlot,
    /// With delivery options on: every frame taken goes through it on its
    /// way to the caller. Boxed: its `u128` counters align to 16, and a
    /// receiver held inline by a binding's object must align to no more
    /// than 8, what that object's allocator promises.
    order: Option<Box<Sequencer<PendingRecovered>>>,
    /// Frames the sequencer held when delivery options were turned off,
    /// delivered first.
    released: VecDeque<PendingRecovered>,
}

/// The address `recvmmsg(2)` wrote into `ss`, or `None` for a family other
/// than AF_INET and AF_INET6.
///
/// # Safety
/// `ss` must have been written by the kernel with at least `len` bytes and
/// contain a valid `sockaddr_in` (AF_INET) or `sockaddr_in6` (AF_INET6).
#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
unsafe fn sockaddr_storage_to_socket_addr(
    ss: &libc::sockaddr_storage,
    len: libc::socklen_t,
) -> Option<std::net::SocketAddr> {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    if len == 0 {
        return None;
    }
    match ss.ss_family as libc::c_int {
        libc::AF_INET => {
            // SAFETY: caller guarantees `ss` was written by the kernel with
            // at least `len` bytes as a valid `sockaddr_in` (AF_INET).
            let sa = unsafe { &*(ss as *const libc::sockaddr_storage as *const libc::sockaddr_in) };
            let ip = Ipv4Addr::from(u32::from_be(sa.sin_addr.s_addr));
            let port = u16::from_be(sa.sin_port);
            Some(SocketAddr::new(IpAddr::V4(ip), port))
        }
        libc::AF_INET6 => {
            // SAFETY: caller guarantees `ss` was written by the kernel with
            // at least `len` bytes as a valid `sockaddr_in6` (AF_INET6).
            let sa =
                unsafe { &*(ss as *const libc::sockaddr_storage as *const libc::sockaddr_in6) };
            let ip = Ipv6Addr::from(sa.sin6_addr.s6_addr);
            let port = u16::from_be(sa.sin6_port);
            Some(SocketAddr::new(IpAddr::V6(ip), port))
        }
        _ => None,
    }
}

/// Flags for a later read of a non-Linux batch, which must not wait:
/// `MSG_DONTWAIT`, as `recvmmsg(2)`'s MSG_WAITFORONE does after the first
/// datagram.
#[cfg(all(unix, not(target_os = "linux")))]
const DONT_WAIT: std::ffi::c_int = libc::MSG_DONTWAIT;

/// Windows has no per-call non-blocking read, so a later batch read there
/// waits for a datagram as the first does, and a timeout ends the call.
#[cfg(not(unix))]
const DONT_WAIT: std::ffi::c_int = 0;

impl Receiver {
    /// Bind a receiver to `local_addr`.
    ///
    /// # Errors
    ///
    /// The [`UdpSocket::bind`] error (`EADDRINUSE`, `EACCES`,
    /// `EADDRNOTAVAIL`, ...).
    pub fn bind<A: std::net::ToSocketAddrs>(local_addr: A) -> std::io::Result<Self> {
        let socket = UdpSocket::bind(local_addr)?;
        Ok(Self::from_socket(socket))
    }

    /// Bind a receiver to the multicast `group`'s address and port, shared
    /// with other receivers on the host, and join the group on `cfg`'s
    /// interface
    /// ([`crate::multicast`]): it receives every frame sent to the group.
    ///
    /// # Errors
    ///
    /// `InvalidInput` when `group` is not a multicast address; otherwise
    /// the error of the bind or of the join (`ENODEV` or `EADDRNOTAVAIL`
    /// for an interface that cannot join, `ENOBUFS` past the system's limit
    /// on memberships).
    pub fn bind_multicast(
        group: SocketAddr,
        cfg: &crate::multicast::MulticastConfig,
    ) -> std::io::Result<Self> {
        Ok(Self::from_socket(crate::multicast::join(group, cfg)?))
    }

    /// Wrap an already-bound socket. Useful when the caller wants to set
    /// `SO_RCVTIMEO` / `SO_RCVBUF` before receiving.
    pub fn from_socket(socket: UdpSocket) -> Self {
        Self {
            socket,
            recv_buf: vec![0u8; MTU_BYTES],
            bp: None,
            intake: DataIntake::default(),
            sealing: None,
            seal_slot: SealSlot::default(),
            order: None,
            released: VecDeque::new(),
        }
    }

    /// Open every datagram this receiver reads with `sealing`, answer the
    /// handshakes that arrive, and seal its feedback with it
    /// ([`crate::sealed`]). The socket should be the one `sealing` was made
    /// with, which [`crate::bind_sealed_pair`] sees to. A datagram that
    /// does not open, and plaintext the sealing does not admit, is dropped
    /// and counted in [`Sealing::counts`], as the source filter drops one;
    /// an inner datagram then goes where a plaintext datagram goes.
    #[must_use]
    pub fn with_sealing(mut self, sealing: Sealing) -> Self {
        *self.seal_slot.write() = Some(sealing.clone());
        self.sealing = Some(sealing);
        self
    }

    /// The sealing installed with [`Self::with_sealing`].
    pub fn sealing(&self) -> Option<&Sealing> {
        self.sealing.as_ref()
    }

    /// The largest datagram, as the unsealed transport builds it, that this
    /// receiver takes whole: [`MTU_BYTES`], or [`MTU_BYTES`] less
    /// [`SEALED_OVERHEAD`] while sealing, since the sealed datagram must fit
    /// the receive buffer.
    pub fn max_inner_datagram(&self) -> usize {
        if self.sealing.is_some() {
            MTU_BYTES - SEALED_OVERHEAD
        } else {
            MTU_BYTES
        }
    }

    /// Take datagrams on the data socket only from `peer`: data frames and
    /// parity from any other source IP are dropped undecoded and counted in
    /// [`Self::data_rejected_count`] (the counterpart of the sender's
    /// [`BackpressureConfig::with_feedback_peer`]). The address is compared,
    /// not the port, and an IPv4 address matches its IPv4-mapped IPv6 form.
    /// Source addresses can be forged, so this shuts out stray and off-path
    /// traffic, not a spoofer. Without it, any source is taken.
    #[must_use]
    pub fn with_data_peer(mut self, peer: IpAddr) -> Self {
        self.intake.set_data_peer(peer);
        self
    }

    /// Datagrams, data frames and parity alike, dropped because their
    /// source IP was not the one [`Self::with_data_peer`] named (0 without
    /// a filter). Logged at the first and each doubling. Diagnostic.
    pub fn data_rejected_count(&self) -> u64 {
        self.intake.data_rejected_count()
    }

    /// Start backpressure: a feedback thread sends the receive cursor to
    /// `cfg.ack_target_addr`, IPv4 or IPv6, every `cfg.ack_period`, with the
    /// NACKs due when NACK is on. Calling it again replaces the running
    /// backpressure: the new thread starts, the old one is stopped and
    /// joined, and the tracking and counters start afresh, as for a
    /// receiver that joins the stream.
    ///
    /// # Errors
    /// Propagates any `std::io::Error` from binding the ACK socket or
    /// connecting it to `cfg.ack_target_addr`; the running backpressure,
    /// if any, is left as it was.
    pub fn enable_backpressure(&mut self, cfg: BackpressureConfig) -> std::io::Result<()> {
        let state = ReceiverBpState::start(&cfg, SealSlot::clone(&self.seal_slot))?;
        self.intake.set_tracker(Arc::clone(&state.tracker));
        self.bp = Some(state);
        Ok(())
    }

    /// Whether [`Self::enable_backpressure`] has been called and the
    /// ACK-send thread is running.
    pub fn backpressure_enabled(&self) -> bool {
        self.bp.is_some()
    }

    /// The receive cursor the ACKs carry: one past the highest sequence
    /// number tracked, which is every frame decoded but one beyond the
    /// horizon ([`Self::beyond_horizon_count`]). Diagnostic.
    pub fn published_recv_cursor(&self) -> u64 {
        match &self.bp {
            Some(s) => s.tracker.recv_cursor(),
            None => 0,
        }
    }

    /// The lowest sequence number not yet arrived that no resync gave up
    /// on; the receive cursor when nothing is missing. Diagnostic.
    pub fn contiguous_head(&self) -> u64 {
        match &self.bp {
            Some(s) => s.tracker.contiguous_head(),
            None => 0,
        }
    }

    /// Times the contiguous head jumped past a gap wider than the sender's
    /// retransmit cache, a confirmed jump beyond the horizon included.
    /// Diagnostic.
    pub fn gap_resyncs(&self) -> u64 {
        match &self.bp {
            Some(s) => s.tracker.gap_resyncs(),
            None => 0,
        }
    }

    /// Frames that arrived beyond the horizon and so moved neither the ACK
    /// cursor nor gap tracking (0 with backpressure off). Diagnostic,
    /// logged at the first and each doubling.
    ///
    /// The horizon lies twice the recovery window (`send_cache_capacity`)
    /// beyond the contiguous head, which stays within a window of the
    /// highest sequence number seen, so it lies at least a window past that:
    /// further than a sender held by backpressure, its queue depth within
    /// the window, gets. A frame beyond it is still delivered; it only
    /// leaves the tracking alone, so one forged frame cannot pin the cursor
    /// near `u64::MAX` and switch backpressure and loss recovery off.
    /// A stream that really jumped (a late joiner, a restart, a loss longer
    /// than the horizon) confirms it with its next frame: a second frame
    /// within a recovery window of the first resyncs the tracking there,
    /// both taken as arrived, and only the first is counted. Two forged
    /// frames that close together pass for a jump; [`Self::with_data_peer`]
    /// is the defence. A frame numbered `u64::MAX` is always counted and
    /// never tracked.
    pub fn beyond_horizon_count(&self) -> u64 {
        match &self.bp {
            Some(s) => s.tracker.beyond_horizon_count(),
            None => 0,
        }
    }

    /// NACKs sent, repeats included; a missing sequence number is requested
    /// at most [`crate::MAX_NACK_ATTEMPTS`] times. Diagnostic.
    pub fn nacks_sent(&self) -> u64 {
        match &self.bp {
            Some(s) => s.nacks_sent.load(Ordering::Relaxed),
            None => 0,
        }
    }

    /// ACK and NACK datagrams the feedback thread failed to send (0 with
    /// backpressure off), typically `ConnectionRefused` while nothing
    /// listens at `ack_target_addr`. The thread logs the first and each
    /// doubling and carries on until backpressure is dropped. Diagnostic.
    pub fn feedback_error_count(&self) -> u64 {
        match &self.bp {
            Some(s) => s.feedback_errors.load(Ordering::Relaxed),
            None => 0,
        }
    }

    /// Missing sequence numbers given up on before a single request: a gap
    /// wider than the recovery window keeps its newest window staged and
    /// counts the rest here, as a late joiner does for what came before
    /// its window. 0 with NACK off. Diagnostic.
    pub fn nack_drop_count(&self) -> u64 {
        match &self.bp {
            Some(s) => s.tracker.nack_drop_count(),
            None => 0,
        }
    }

    /// Rebuild lost frames from parity, with the sender's `window_size` and
    /// at most `max_windows` windows tracked ([`FecDecoder`] has the
    /// rules). Calling it again replaces the decoder, dropping its windows.
    pub fn enable_fec(&mut self, window_size: u16, max_windows: usize) {
        self.intake.enable_fec(window_size, max_windows);
    }

    /// True after [`Self::enable_fec`] has been called.
    pub fn fec_enabled(&self) -> bool {
        self.intake.fec_decoder().is_some()
    }

    /// Reassemble the runs of fragments a sender with fragmentation on sends
    /// for envelopes longer than a frame carries, up to
    /// [`MAX_MESSAGE`](crate::MAX_MESSAGE) bytes ([`crate::fragment`]),
    /// within `cfg`'s bounds. A run completes once its last missing fragment
    /// arrives, by the wire, a retransmission or FEC, and is delivered as one
    /// frame whose [`RecvMeta::seq`] is the run's first sequence number; the
    /// receive buffers [`Self::recv_into`] and [`Self::recv_batch_into`] are
    /// given must then hold [`MAX_MESSAGE`](crate::MAX_MESSAGE) bytes. Each
    /// fragment counts as a datagram of its own for backpressure, NACK and
    /// FEC. Without reassembly, fragments are dropped and counted
    /// ([`Self::fragments_dropped_count`]). Calling it again replaces the
    /// reassembler, dropping the runs in progress.
    pub fn enable_reassembly(&mut self, cfg: ReassemblyConfig) {
        self.intake.enable_reassembly(cfg);
    }

    /// Stop reassembling, dropping the runs in progress.
    pub fn disable_reassembly(&mut self) {
        self.intake.disable_reassembly();
    }

    /// True while reassembly is on.
    pub fn reassembly_enabled(&self) -> bool {
        self.intake.reassembler().is_some()
    }

    /// Runs reassembled whole. Diagnostic.
    pub fn reassembled_count(&self) -> u64 {
        self.intake
            .reassembler()
            .map_or(0, Reassembler::completed_count)
    }

    /// Runs dropped incomplete: timed out, pushed out by the bounds, too
    /// large, or disagreeing with themselves. Diagnostic.
    pub fn reassembly_dropped_count(&self) -> u64 {
        self.intake
            .reassembler()
            .map_or(0, Reassembler::dropped_count)
    }

    /// Fragments dropped because reassembly was off. Diagnostic.
    pub fn fragments_dropped_count(&self) -> u64 {
        self.intake.fragments_dropped_count()
    }

    /// Fragments rebuilt from parity, which went to reassembly rather than
    /// being held, so [`Self::fec_recovered_count`] does not count them.
    /// Diagnostic.
    pub fn fec_rebuilt_fragment_count(&self) -> u64 {
        self.intake.fec_rebuilt_fragment_count()
    }

    /// Deliver each sequence number once, in arrival order or in sequence
    /// order, as `cfg` says ([`crate::order`]). Every frame taken (from the
    /// wire, rebuilt from parity, or a run reassembled, which occupies its
    /// whole span of numbers) goes through it. In order, a frame ahead of a
    /// gap is held no longer than [`DeliveryConfig::gap_timeout`]: while
    /// frames are held, a receive call waits for the socket no longer than
    /// the next of them is due, and returns it then, though nothing more
    /// arrives. The caller's read timeout still ends a call that has
    /// nothing to deliver. A receiver that knows where the stream starts
    /// says so with [`DeliveryConfig::starting_at`] (a fresh [`crate::Sender`]
    /// numbers from 0); otherwise in order holds the first frame up to the
    /// gap timeout, to start at the lowest number that comes. Calling it
    /// again delivers what the old options held first.
    pub fn enable_delivery(&mut self, cfg: DeliveryConfig) {
        self.disable_delivery();
        self.order = Some(Box::new(Sequencer::new(&cfg)));
    }

    /// Deliver frames as they arrive again. The frames held are delivered
    /// first, in order, the gaps between them skipped.
    pub fn disable_delivery(&mut self) {
        if let Some(mut order) = self.order.take() {
            order.release_all();
            self.released.extend(std::iter::from_fn(|| order.pop()));
        }
    }

    /// The delivery option on, if one is.
    pub fn delivery_order(&self) -> Option<Order> {
        self.order.as_deref().map(Sequencer::order)
    }

    /// Frames the delivery options dropped because their numbers were
    /// delivered already. Diagnostic.
    pub fn delivery_duplicate_count(&self) -> u64 {
        self.order.as_deref().map_or(0, Sequencer::duplicate_count)
    }

    /// Frames the delivery options dropped because they arrived behind the
    /// order: after their gap was skipped, or more than a window behind.
    /// Diagnostic.
    pub fn delivery_late_count(&self) -> u64 {
        self.order.as_deref().map_or(0, Sequencer::late_count)
    }

    /// Sequence numbers skipped over in order, in gaps that did not fill in
    /// time. Diagnostic.
    pub fn delivery_skipped_count(&self) -> u64 {
        self.order.as_deref().map_or(0, Sequencer::skipped_count)
    }

    /// Times the order started again after the sender restarted its
    /// numbering. Diagnostic.
    pub fn delivery_resync_count(&self) -> u64 {
        self.order.as_deref().map_or(0, Sequencer::resync_count)
    }

    /// Frames held in order ahead of a gap.
    pub fn delivery_held_count(&self) -> usize {
        self.order.as_deref().map_or(0, Sequencer::held_count)
    }

    /// Parity datagrams decoded. Diagnostic.
    pub fn parity_received_count(&self) -> u64 {
        self.intake.parity_received_count()
    }

    /// Frames rebuilt from parity. Diagnostic.
    pub fn fec_recovered_count(&self) -> u64 {
        self.intake.fec_recovered_count()
    }

    /// Parity that yielded nothing, with FEC on: the datagram did not
    /// decode (shorter than the header, a window of zero, or cut short by
    /// the receive buffer, which a sender's own parity never is, given
    /// [`crate::FEC_MAX_ENVELOPE`]), or the frame rebuilt from it failed the
    /// frame checks, as a rebuild from forged or mismatched parity does.
    /// Logged at the first and each doubling. Diagnostic.
    pub fn parity_undecodable_count(&self) -> u64 {
        self.intake.parity_undecodable_count()
    }

    /// Parity datagrams the FEC decoder refused since FEC was last enabled
    /// ([`FecDecoder`] has the rules); 0 with FEC off. A sender's own parity
    /// is refused only for a different window size, a loss run longer than
    /// the table spans, or too small a `max_windows`, so a count that climbs
    /// otherwise points at parity from elsewhere. Diagnostic.
    pub fn fec_refused_count(&self) -> u64 {
        self.intake
            .fec_decoder()
            .map_or(0, FecDecoder::refused_count)
    }

    /// Local address the socket is bound to.
    ///
    /// # Errors
    /// Propagates the underlying [`UdpSocket::local_addr`] error.
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// [`MAX_ENVELOPE`]: an envelope buffer this long takes any frame.
    pub fn max_envelope() -> usize {
        MAX_ENVELOPE
    }

    /// Set the socket's read timeout. `None` blocks forever; `Some(d)`
    /// returns `WouldBlock` / `TimedOut` after `d` with no datagram.
    ///
    /// # Errors
    /// Propagates the underlying `setsockopt` error.
    pub fn set_read_timeout(&self, timeout: Option<std::time::Duration>) -> std::io::Result<()> {
        self.socket.set_read_timeout(timeout)
    }

    /// Wait for the next frame and return its Pulse, its envelope in a new
    /// `Vec`, and its metadata. A frame rebuilt from parity and held comes
    /// first; parity, and datagrams the source filter drops, are consumed on
    /// the way. With backpressure on, each frame decoded advances the
    /// receive cursor ([`Self::published_recv_cursor`]). A signal does not
    /// end the wait: it starts again, with the whole read timeout.
    ///
    /// # Errors
    /// [`ReceiverError::Io`] from the socket, a read timeout included
    /// ([`ReceiverError::is_timeout`]); [`ReceiverError::Decode`] for a
    /// datagram that does not decode.
    pub fn recv(&mut self) -> Result<(Pulse, Vec<u8>, RecvMeta), ReceiverError> {
        loop {
            if let Some(p) = self.next_ready() {
                return Ok((p.pulse, p.envelope, p.meta));
            }
            let Some((n, peer)) = self.read_bounded()? else {
                continue;
            };
            match self.intake_datagram(n, peer)? {
                Some(Dispatched::Data {
                    pulse,
                    env_offset,
                    env_len,
                    meta,
                }) => {
                    let env_vec = self.recv_buf[env_offset..env_offset + env_len].to_vec();
                    if self.order.is_none() {
                        return Ok((pulse, env_vec, meta));
                    }
                    self.order_frame(pulse, env_vec, meta);
                }
                Some(
                    Dispatched::ParityConsumed | Dispatched::FragmentConsumed | Dispatched::Foreign,
                )
                | None => {}
            }
        }
    }

    /// [`Receiver::recv`] into the caller's `envelope` rather than a new
    /// `Vec`: returns the Pulse, the envelope's length and the metadata,
    /// and leaves the bytes after the envelope as they were.
    ///
    /// # Errors
    /// [`ReceiverError::BufferTooSmall`] if the envelope does not fit
    /// `envelope`; the frame is consumed. Otherwise as [`Receiver::recv`].
    pub fn recv_into(
        &mut self,
        envelope: &mut [u8],
    ) -> Result<(Pulse, usize, RecvMeta), ReceiverError> {
        loop {
            if let Some(p) = self.next_ready() {
                let env_len = p.envelope.len();
                if env_len > envelope.len() {
                    return Err(ReceiverError::BufferTooSmall {
                        needed: env_len,
                        provided: envelope.len(),
                    });
                }
                envelope[..env_len].copy_from_slice(&p.envelope);
                return Ok((p.pulse, env_len, p.meta));
            }
            let Some((n, peer)) = self.read_bounded()? else {
                continue;
            };
            match self.intake_datagram(n, peer)? {
                Some(Dispatched::Data {
                    pulse,
                    env_offset,
                    env_len,
                    meta,
                }) => {
                    let bytes = &self.recv_buf[env_offset..env_offset + env_len];
                    if self.order.is_some() {
                        let env_vec = bytes.to_vec();
                        self.order_frame(pulse, env_vec, meta);
                        continue;
                    }
                    if env_len > envelope.len() {
                        return Err(ReceiverError::BufferTooSmall {
                            needed: env_len,
                            provided: envelope.len(),
                        });
                    }
                    envelope[..env_len].copy_from_slice(bytes);
                    return Ok((pulse, env_len, meta));
                }
                Some(
                    Dispatched::ParityConsumed | Dispatched::FragmentConsumed | Dispatched::Foreign,
                )
                | None => {}
            }
        }
    }

    /// The next frame for the caller, without reading the socket: one
    /// released when the delivery options were turned off; with them on,
    /// one the sequencer has ready, after the frames the intake holds go
    /// into it and the gaps past their timeout are skipped; otherwise one
    /// the intake holds. A frame the intake held reaches the stream
    /// tracking as it leaves the intake.
    fn next_ready(&mut self) -> Option<PendingRecovered> {
        if let Some(p) = self.released.pop_front() {
            return Some(p);
        }
        let Some(order) = &mut self.order else {
            let p = self.intake.pop_recovered()?;
            self.intake.delivered(&p);
            return Some(p);
        };
        let now = Instant::now();
        while let Some(p) = self.intake.pop_recovered() {
            self.intake.delivered(&p);
            let (seq, span, bytes) = (p.meta.seq, u64::from(p.span), p.envelope.len());
            order.push(seq, span, bytes, p, now);
        }
        order.poll(now);
        order.pop()
    }

    /// True when a receive call has a frame to deliver without reading.
    fn has_ready(&self) -> bool {
        !self.released.is_empty()
            || self.intake.held_count() > 0
            || self.order.as_deref().is_some_and(|o| {
                o.ready_count() > 0 || o.deadline().is_some_and(|d| d <= Instant::now())
            })
    }

    /// Give a data frame just taken from the wire, already tracked, to the
    /// sequencer.
    fn order_frame(&mut self, pulse: Pulse, envelope: Vec<u8>, meta: RecvMeta) {
        if let Some(order) = &mut self.order {
            let bytes = envelope.len();
            let frame = PendingRecovered {
                pulse,
                envelope,
                meta,
                reassembled: false,
                span: 1,
            };
            order.push(meta.seq, 1, bytes, frame, Instant::now());
        }
    }

    /// How long a read may wait while the sequencer holds frames: until
    /// the next of them is due, unless the caller's read timeout, returned
    /// beside it, comes first. `None` when nothing bounds the wait but the
    /// caller's timeout.
    fn read_bound(&self) -> std::io::Result<Option<(Duration, Option<Duration>)>> {
        let Some(deadline) = self.order.as_deref().and_then(Sequencer::deadline) else {
            return Ok(None);
        };
        let wait = deadline.saturating_duration_since(Instant::now());
        let caller = self.socket.read_timeout()?;
        if caller.is_some_and(|c| c <= wait) {
            return Ok(None);
        }
        Ok(Some((wait, caller)))
    }

    /// Run `read` with the socket's read timeout cut to `bound`, then put
    /// the caller's back; a read the cut timeout ended is `Ok(None)`. A
    /// bound already passed reads nothing.
    fn bounded<R>(
        &mut self,
        bound: (Duration, Option<Duration>),
        read: impl FnOnce(&mut Self) -> std::io::Result<R>,
    ) -> std::io::Result<Option<R>> {
        let (wait, caller) = bound;
        if wait.is_zero() {
            return Ok(None);
        }
        self.socket.set_read_timeout(Some(wait))?;
        let result = read(self);
        self.socket.set_read_timeout(caller)?;
        match result {
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                Ok(None)
            }
            other => other.map(Some),
        }
    }

    /// Read the next datagram, waiting no longer than the next frame the
    /// sequencer holds is due: `None` when that came first.
    fn read_bounded(&mut self) -> std::io::Result<Option<(usize, SocketAddr)>> {
        match self.read_bound()? {
            None => self.read_datagram().map(Some),
            Some(bound) => self.bounded(bound, Self::read_datagram),
        }
    }

    /// Receive up to `max_frames` frames, the j-th delivered writing its
    /// envelope into `envelopes[j]`: datagrams are read with one
    /// `recvmmsg(2)` call on Linux, one at a time elsewhere.
    ///
    /// Each datagram gets what [`Self::recv`] does with it; parity yields no
    /// frame and no error. Frames rebuilt from parity follow the call's
    /// frames in the slots left, and the rest are held; a call that finds
    /// frames held returns those without reading the socket.
    ///
    /// With none held, the call waits for the first datagram, up to the
    /// read timeout (a signal restarts the wait), then takes those already
    /// queued, up to `max_frames`. On Windows, which has no per-call
    /// non-blocking read, each further read waits too, and a timeout ends
    /// the call. A failed read after the first ends it. A call can deliver
    /// no frames when every datagram it read was parity.
    ///
    /// # Errors
    /// - [`BatchRecvError::Io`] when reading the first datagram fails,
    ///   including the read timeout passing with nothing received.
    /// - [`BatchRecvError::BatchTooLarge`] if `max_frames >
    ///   crate::sender::MAX_BATCH_FRAMES`.
    /// - [`BatchRecvError::InsufficientBuffers`] if
    ///   `envelopes.len() < max_frames`.
    pub fn recv_batch_into(
        &mut self,
        max_frames: usize,
        envelopes: &mut [&mut [u8]],
    ) -> Result<BatchRecvResult, BatchRecvError> {
        use crate::sender::MAX_BATCH_FRAMES;
        let mut out = BatchRecvResult {
            frames: Vec::new(),
            errors: Vec::new(),
            received: 0,
        };
        if max_frames == 0 {
            return Ok(out);
        }
        if max_frames > MAX_BATCH_FRAMES {
            return Err(BatchRecvError::BatchTooLarge {
                got: max_frames,
                max: MAX_BATCH_FRAMES,
            });
        }
        if envelopes.len() < max_frames {
            return Err(BatchRecvError::InsufficientBuffers {
                buffers: envelopes.len(),
                requested: max_frames,
            });
        }
        out.frames.reserve(max_frames);
        if self.has_ready() {
            self.deliver_recovered(max_frames, envelopes, &mut out);
            return Ok(out);
        }
        if let Some(sealing) = self.sealing.clone() {
            if sealing.has_stashed() {
                // Datagrams read while this receiver was not receiving come
                // first, without a read.
                while out.received < max_frames {
                    let Some((n, peer)) = sealing.take_stashed(&mut self.recv_buf) else {
                        break;
                    };
                    let index = out.received;
                    out.received += 1;
                    self.batch_take(n, Some(peer), index, envelopes, &mut out);
                }
                self.deliver_recovered(max_frames, envelopes, &mut out);
                return Ok(out);
            }
        }
        let reading = self.sealing.as_ref().map(Sealing::reading);
        let read = match self.read_bound() {
            Ok(None) => self.recv_batch_read(max_frames, envelopes, &mut out),
            // Waiting on frames the sequencer holds: a read their deadline
            // ended delivers them.
            Ok(Some(bound)) => self
                .bounded(bound, |rx| {
                    rx.recv_batch_read(max_frames, envelopes, &mut out)
                })
                .map(|_| ()),
            Err(e) => Err(e),
        };
        drop(reading);
        read.map_err(BatchRecvError::Io)?;
        self.deliver_recovered(max_frames, envelopes, &mut out);
        Ok(out)
    }

    /// Read the next datagram into `recv_buf`: with sealing on, one kept
    /// for this receiver by a read it did not make comes first.
    fn read_datagram(&mut self) -> std::io::Result<(usize, SocketAddr)> {
        let Some(sealing) = &self.sealing else {
            return retry_interrupted(|| self.socket.recv_from(&mut self.recv_buf));
        };
        if let Some(found) = sealing.take_stashed(&mut self.recv_buf) {
            return Ok(found);
        }
        let _reading = sealing.reading();
        retry_interrupted(|| self.socket.recv_from(&mut self.recv_buf))
    }

    /// The one way a datagram read, now in `recv_buf[..n]`, reaches the
    /// decode: with sealing on, it is opened first, and its inner datagram
    /// (or plaintext the sealing admits) goes on, moved to the front of the
    /// buffer, to [`DataIntake::dispatch`], the path a plaintext datagram
    /// takes; `None` when the sealing took it (a handshake message, a
    /// keepalive, or a refusal it counted).
    fn intake_datagram(
        &mut self,
        n: usize,
        peer: SocketAddr,
    ) -> Result<Option<Dispatched>, ReceiverError> {
        let (n, sealed_by) = match &self.sealing {
            None => (n, None),
            Some(sealing) => match sealing.open_sealed_by(&mut self.recv_buf, n, peer) {
                (Opened::Inner(len), sealed_by) => (len, sealed_by),
                (Opened::Consumed, _) => return Ok(None),
            },
        };
        self.intake
            .dispatch_sealed(&self.recv_buf[..n], peer, sealed_by)
            .map(Some)
    }

    /// Take a datagram a batch read, now in `recv_buf[..n]`, through the
    /// dispatch `recv` uses, delivering a data frame into the next slot.
    /// `index` is its place among the datagrams read; a `peer` of `None` is
    /// a family other than IPv4 and IPv6.
    fn batch_take(
        &mut self,
        n: usize,
        peer: Option<SocketAddr>,
        index: usize,
        envelopes: &mut [&mut [u8]],
        out: &mut BatchRecvResult,
    ) {
        let Some(peer) = peer else {
            out.errors.push(BatchRecvFrameError {
                frame_index: index,
                error: ReceiverError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "unknown peer address family",
                )),
            });
            return;
        };
        match self.intake_datagram(n, peer) {
            Ok(Some(Dispatched::Data {
                pulse,
                env_offset,
                env_len,
                meta,
            })) if self.order.is_some() => {
                let env_vec = self.recv_buf[env_offset..env_offset + env_len].to_vec();
                self.order_frame(pulse, env_vec, meta);
            }
            Ok(Some(Dispatched::Data {
                pulse,
                env_offset,
                env_len,
                meta,
            })) => {
                // The slot exists: a datagram yields at most one frame, at
                // most `max_frames <= envelopes.len()` are read, and rebuilt
                // frames come after. A frame too large is consumed and
                // reported, as in `recv_into`.
                let slot = &mut envelopes[out.frames.len()];
                if env_len > slot.len() {
                    out.errors.push(BatchRecvFrameError {
                        frame_index: index,
                        error: ReceiverError::BufferTooSmall {
                            needed: env_len,
                            provided: slot.len(),
                        },
                    });
                    return;
                }
                slot[..env_len].copy_from_slice(&self.recv_buf[env_offset..env_offset + env_len]);
                out.frames.push((pulse, env_len, meta));
            }
            // Parity, a fragment, a datagram the filter dropped, or one the
            // sealing took: counted in `received`, neither a frame nor an
            // error.
            Ok(
                Some(
                    Dispatched::ParityConsumed | Dispatched::FragmentConsumed | Dispatched::Foreign,
                )
                | None,
            ) => {}
            Err(error) => out.errors.push(BatchRecvFrameError {
                frame_index: index,
                error,
            }),
        }
    }

    /// Deliver held frames, oldest first (with delivery options on, as the
    /// sequencer releases them), into the slots after `out.frames` until
    /// `out` holds `max_frames`; the rest stay held. As in `recv_into`, a
    /// frame that does not fit is dropped and reported. Errors are numbered
    /// after the datagrams the call read.
    fn deliver_recovered(
        &mut self,
        max_frames: usize,
        envelopes: &mut [&mut [u8]],
        out: &mut BatchRecvResult,
    ) {
        let mut index = out.received;
        while out.frames.len() < max_frames {
            let Some(p) = self.next_ready() else {
                break;
            };
            let slot = &mut envelopes[out.frames.len()];
            let env_len = p.envelope.len();
            if env_len > slot.len() {
                out.errors.push(BatchRecvFrameError {
                    frame_index: index,
                    error: ReceiverError::BufferTooSmall {
                        needed: env_len,
                        provided: slot.len(),
                    },
                });
            } else {
                slot[..env_len].copy_from_slice(&p.envelope);
                out.frames.push((p.pulse, env_len, p.meta));
            }
            index += 1;
        }
    }

    /// The platform's batch read for [`Self::recv_batch_into`].
    fn recv_batch_read(
        &mut self,
        max_frames: usize,
        envelopes: &mut [&mut [u8]],
        out: &mut BatchRecvResult,
    ) -> std::io::Result<()> {
        #[cfg(target_os = "linux")]
        let read = self.recv_batch_linux(max_frames, envelopes, out);
        #[cfg(not(target_os = "linux"))]
        let read = self.recv_batch_fallback(max_frames, envelopes, out);
        read
    }

    /// The `recvmmsg(2)` path of [`Self::recv_batch_into`]. The pointers
    /// handed to the kernel point into `Vec`s filled before any pointer is
    /// taken, which do not move during the call.
    #[cfg(target_os = "linux")]
    #[allow(unsafe_code)]
    fn recv_batch_linux(
        &mut self,
        max_frames: usize,
        envelopes: &mut [&mut [u8]],
        out: &mut BatchRecvResult,
    ) -> std::io::Result<()> {
        use std::os::unix::io::AsRawFd;

        let n = max_frames;

        // One MTU each, so any frame fits.
        let mut raw_bufs: Vec<Vec<u8>> = (0..n).map(|_| vec![0u8; MTU_BYTES]).collect();

        // SAFETY: sockaddr_storage is a POD struct; zeroing is correct
        // initialisation per the POSIX spec.
        let mut peer_stores: Vec<libc::sockaddr_storage> =
            (0..n).map(|_| unsafe { std::mem::zeroed() }).collect();
        // The kernel overwrites each msg_namelen with the length it wrote.
        let peer_store_len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;

        let mut iovecs: Vec<libc::iovec> = Vec::with_capacity(n);
        for buf in raw_bufs.iter_mut() {
            iovecs.push(libc::iovec {
                iov_base: buf.as_mut_ptr() as *mut libc::c_void,
                iov_len: MTU_BYTES,
            });
        }

        let mut mmsghdrs: Vec<libc::mmsghdr> = Vec::with_capacity(n);
        for i in 0..n {
            // SAFETY: `msghdr` is plain data, valid all-zero; the fields
            // left zero (no control buffer, no flags) mean none to recvmmsg.
            let mut mh: libc::msghdr = unsafe { std::mem::zeroed() };
            mh.msg_name = &mut peer_stores[i] as *mut libc::sockaddr_storage as *mut libc::c_void;
            mh.msg_namelen = peer_store_len;
            mh.msg_iov = &mut iovecs[i] as *mut libc::iovec;
            mh.msg_iovlen = 1;
            mmsghdrs.push(libc::mmsghdr {
                msg_hdr: mh,
                msg_len: 0,
            });
        }

        let fd = self.socket.as_raw_fd();
        // MSG_WAITFORONE: wait for the first datagram, then take those
        // already queued, up to n.
        let ret = loop {
            // SAFETY: fd is a valid UDP socket; mmsghdrs length matches n;
            // every msg_iov and msg_name pointer is backed by a Vec we own
            // that does not move during the call.
            let ret = unsafe {
                libc::recvmmsg(
                    fd,
                    mmsghdrs.as_mut_ptr(),
                    n as libc::c_uint,
                    libc::MSG_WAITFORONE,
                    std::ptr::null_mut(),
                )
            };
            if ret >= 0 {
                break ret;
            }
            let error = std::io::Error::last_os_error();
            if error.kind() != std::io::ErrorKind::Interrupted {
                return Err(error);
            }
            // A signal cut the wait short before the first datagram (once
            // one has arrived, the call returns the count instead). Wait
            // again, with every address length as the kernel first saw it.
            for mh in mmsghdrs.iter_mut() {
                mh.msg_hdr.msg_namelen = peer_store_len;
            }
        };
        out.received = ret as usize;

        // Each datagram's buffer is swapped into `recv_buf`, both one MTU,
        // for the dispatch `recv` uses: no copy.
        for i in 0..out.received {
            let datagram_len = mmsghdrs[i].msg_len as usize;
            let actual_name_len = mmsghdrs[i].msg_hdr.msg_namelen;
            // SAFETY: peer_stores[i] was written by the kernel with
            // actual_name_len bytes. We read only the ss_family field
            // first, then cast to the matching type.
            let peer = unsafe { sockaddr_storage_to_socket_addr(&peer_stores[i], actual_name_len) };
            std::mem::swap(&mut self.recv_buf, &mut raw_bufs[i]);
            self.batch_take(datagram_len, peer, i, envelopes, out);
        }
        Ok(())
    }

    /// The other platforms' path of `recv_batch_into`, one read per
    /// datagram: the first waits, up to the read timeout; later ones take
    /// only datagrams already queued (`DONT_WAIT`), and the first that finds
    /// none, or fails, ends the call.
    #[cfg(not(target_os = "linux"))]
    fn recv_batch_fallback(
        &mut self,
        max_frames: usize,
        envelopes: &mut [&mut [u8]],
        out: &mut BatchRecvResult,
    ) -> std::io::Result<()> {
        use std::sync::Once;
        static WARN_ONCE: Once = Once::new();
        WARN_ONCE.call_once(|| {
            tracing::warn!(
                "Receiver::recv_batch_into fallback: recvmmsg(2) is Linux-only; \
 falling back to one read per datagram (no syscall amortization). \
 Build on Linux for the fast path."
            );
        });

        let (n, peer) = retry_interrupted(|| self.recv_datagram(0))?;
        out.received = 1;
        self.batch_take(n, peer, 0, envelopes, out);
        while out.received < max_frames {
            let Ok((n, peer)) = retry_interrupted(|| self.recv_datagram(DONT_WAIT)) else {
                break;
            };
            let index = out.received;
            out.received += 1;
            self.batch_take(n, peer, index, envelopes, out);
        }
        Ok(())
    }

    /// Read one datagram into `recv_buf` with `flags`, for the non-Linux
    /// batch path. The peer is `None` for an address family other than
    /// IPv4 or IPv6.
    #[cfg(not(target_os = "linux"))]
    fn recv_datagram(
        &mut self,
        flags: std::ffi::c_int,
    ) -> std::io::Result<(usize, Option<SocketAddr>)> {
        recv_with_flags(&self.socket, &mut self.recv_buf, flags)
    }

    /// The socket, for configuration.
    pub fn socket(&self) -> &UdpSocket {
        &self.socket
    }
}

/// Read one datagram from `socket` into `buf` with `flags`: the non-Linux
/// batch path's reads, and on Unix the sealing's reads that must not wait
/// (`MSG_DONTWAIT`). The peer is `None` for an address family other than
/// IPv4 or IPv6.
#[allow(unsafe_code)]
pub(crate) fn recv_with_flags(
    socket: &UdpSocket,
    buf: &mut [u8],
    flags: std::ffi::c_int,
) -> std::io::Result<(usize, Option<SocketAddr>)> {
    use std::mem::MaybeUninit;
    // SAFETY: `MaybeUninit<u8>` has the size, alignment and validity of
    // `u8`, and socket2's receive calls write only initialised bytes into
    // the buffer they are given, so viewing this initialised buffer as
    // `MaybeUninit<u8>` for the call leaves it initialised when `buf` is
    // used as `[u8]` again.
    let uninit = unsafe { &mut *(buf as *mut [u8] as *mut [MaybeUninit<u8>]) };
    let (n, addr) = socket2::SockRef::from(socket).recv_from_with_flags(uninit, flags)?;
    Ok((n, addr.as_socket()))
}

/// What the receiver does with a datagram, without the socket: the source
/// filter, the dispatch on the first four bytes, the decode, the FEC
/// decoder and the frames it rebuilds, held here, and the stream tracking.
/// Public only for the fuzz harness in `fuzz`.
#[doc(hidden)]
#[derive(Default)]
pub struct DataIntake {
    /// Fed every frame decoded or delivered, with backpressure on.
    tracker: Option<Arc<StreamTracker>>,
    /// With FEC on; its rebuilt frames go to `recovered_queue`.
    fec: Option<FecDecoder>,
    /// Rebuilt frames awaiting delivery, oldest first.
    recovered_queue: VecDeque<PendingRecovered>,
    /// Parity datagrams decoded.
    parity_received: u64,
    /// Frames rebuilt from parity.
    fec_recovered: u64,
    /// Parity that yielded nothing because it could not be decoded, as a
    /// datagram or as the frame rebuilt from it.
    parity_undecodable: u64,
    /// The only source IP datagrams are taken from, when set.
    data_peer: Option<IpAddr>,
    /// Datagrams dropped by the data-peer filter.
    data_rejected: u64,
    /// With reassembly on; the runs it completes go to `recovered_queue`.
    reassembler: Option<Reassembler>,
    /// Fragments dropped because reassembly was off.
    fragments_dropped: u64,
    /// Fragments rebuilt from parity, which go to reassembly, not the
    /// held frames.
    fec_rebuilt_fragments: u64,
    /// The sequence number of the fragment last rebuilt from parity.
    last_rebuilt_fragment: Option<u64>,
}

impl DataIntake {
    /// Take datagrams only from `peer`, as [`Receiver::with_data_peer`]
    /// describes.
    pub fn set_data_peer(&mut self, peer: IpAddr) {
        self.data_peer = Some(peer.to_canonical());
    }

    /// Datagrams dropped by the data-peer filter; see
    /// [`Receiver::data_rejected_count`].
    pub fn data_rejected_count(&self) -> u64 {
        self.data_rejected
    }

    /// Feed `tracker`, in place of any tracking fed before, with the
    /// sequence number of every data frame dispatched and of every held
    /// frame delivered.
    pub fn set_tracker(&mut self, tracker: Arc<StreamTracker>) {
        self.tracker = Some(tracker);
    }

    /// Take parity with a new decoder, as [`Receiver::enable_fec`]
    /// describes.
    pub fn enable_fec(&mut self, window_size: u16, max_windows: usize) {
        self.fec = Some(FecDecoder::new(window_size, max_windows));
    }

    /// Reassemble fragments, as [`Receiver::enable_reassembly`] describes.
    pub fn enable_reassembly(&mut self, cfg: ReassemblyConfig) {
        self.reassembler = Some(Reassembler::new(cfg));
    }

    /// Drop fragments again, and the runs in progress.
    pub fn disable_reassembly(&mut self) {
        self.reassembler = None;
    }

    /// The reassembler, while reassembly is on.
    pub fn reassembler(&self) -> Option<&Reassembler> {
        self.reassembler.as_ref()
    }

    /// Fragments dropped because reassembly was off.
    pub fn fragments_dropped_count(&self) -> u64 {
        self.fragments_dropped
    }

    /// Fragments rebuilt from parity; see
    /// [`Receiver::fec_rebuilt_fragment_count`].
    pub fn fec_rebuilt_fragment_count(&self) -> u64 {
        self.fec_rebuilt_fragments
    }

    /// The sequence number of the fragment last rebuilt from parity, which
    /// reached the stream tracking when it was rebuilt. Diagnostic.
    pub fn last_rebuilt_fragment(&self) -> Option<u64> {
        self.last_rebuilt_fragment
    }

    /// Give a decoded fragment to the reassembler, holding the run it
    /// completes for delivery, or with reassembly off drop and count it.
    fn take_fragment(
        &mut self,
        fragment: &Fragment<'_>,
        peer: SocketAddr,
        sealed_by: Option<PublicKey>,
    ) {
        let Some(reassembler) = self.reassembler.as_mut() else {
            self.fragments_dropped = self.fragments_dropped.wrapping_add(1);
            return;
        };
        if let Some(message) = reassembler.add_sealed(fragment, peer, sealed_by, Instant::now()) {
            self.recovered_queue.push_back(PendingRecovered {
                pulse: message.pulse,
                envelope: message.envelope,
                meta: RecvMeta {
                    seq: message.first_seq,
                    send_ns: message.send_ns,
                    peer,
                    sealed_by,
                },
                reassembled: true,
                span: message.count,
            });
        }
    }

    /// The FEC decoder, while FEC is on.
    pub fn fec_decoder(&self) -> Option<&FecDecoder> {
        self.fec.as_ref()
    }

    /// Parity datagrams decoded; see [`Receiver::parity_received_count`].
    pub fn parity_received_count(&self) -> u64 {
        self.parity_received
    }

    /// Frames rebuilt from parity that decoded and were held; see
    /// [`Receiver::fec_recovered_count`].
    pub fn fec_recovered_count(&self) -> u64 {
        self.fec_recovered
    }

    /// Parity that yielded nothing because it could not be decoded; see
    /// [`Receiver::parity_undecodable_count`].
    pub fn parity_undecodable_count(&self) -> u64 {
        self.parity_undecodable
    }

    /// Frames rebuilt from parity and held for delivery.
    pub fn held_count(&self) -> usize {
        self.recovered_queue.len()
    }

    /// Take the oldest frame held for delivery. Its sequence number reaches
    /// the stream tracking only once the caller delivers it and says so
    /// with [`Self::delivered`].
    pub fn pop_recovered(&mut self) -> Option<PendingRecovered> {
        self.recovered_queue.pop_front()
    }

    /// A frame taken with [`Self::pop_recovered`] was delivered: advance
    /// the backpressure cursor and feed gap tracking with its sequence
    /// number, as dispatching a data frame does. A reassembled run feeds
    /// nothing: its fragments were tracked as they arrived.
    pub fn delivered(&self, frame: &PendingRecovered) {
        if !frame.reassembled {
            self.track(frame.meta.seq);
        }
    }

    /// Take a datagram that arrived from `peer`. One the source filter does
    /// not admit is dropped undecoded and counted. A data frame is decoded,
    /// fed to the tracking and the FEC decoder, and returned for delivery;
    /// parity goes to the decoder, or with FEC off is dropped. A frame
    /// rebuilt from a completed window is decoded and held, or counted when
    /// it does not decode.
    ///
    /// # Errors
    /// [`ReceiverError::Decode`] for a datagram shorter than 4 bytes, one
    /// whose magic is neither the data magic nor the parity magic, and a
    /// data frame that fails [`crate::wire::decode`]; nothing is changed.
    pub fn dispatch(
        &mut self,
        datagram: &[u8],
        peer: SocketAddr,
    ) -> Result<Dispatched, ReceiverError> {
        self.dispatch_sealed(datagram, peer, None)
    }

    /// [`Self::dispatch`] for the inner datagram of a sealed one, which the
    /// session of the peer whose key is `sealed_by` opened (`None` for a
    /// datagram taken in plaintext): the frames it yields carry the key in
    /// [`RecvMeta::sealed_by`].
    ///
    /// # Errors
    /// As [`Self::dispatch`].
    pub fn dispatch_sealed(
        &mut self,
        datagram: &[u8],
        peer: SocketAddr,
        sealed_by: Option<PublicKey>,
    ) -> Result<Dispatched, ReceiverError> {
        if let Some(want) = self.data_peer {
            if peer.ip().to_canonical() != want {
                self.data_rejected = self.data_rejected.wrapping_add(1);
                if self.data_rejected.is_power_of_two() {
                    tracing::warn!(
                        %peer,
                        expected = %want,
                        rejected = self.data_rejected,
                        "datagram from an unexpected peer dropped"
                    );
                }
                return Ok(Dispatched::Foreign);
            }
        }
        let n = datagram.len();
        let magic_bytes: [u8; 4] = datagram
            .get(0..4)
            .and_then(|s| <[u8; 4]>::try_from(s).ok())
            .ok_or(ReceiverError::Decode(
                crate::wire::WireError::BufferTooSmall { got: n, min: 4 },
            ))?;
        let magic = u32::from_le_bytes(magic_bytes);
        match magic {
            DATA_MAGIC => {
                let frame = decode(datagram)?;
                let pulse = Pulse::from_bytes(&frame.pulse).ok_or(
                    crate::wire::WireError::UnsupportedVersion {
                        got: 0,
                        expected: crate::wire::VERSION,
                    },
                )?;
                let (seq, send_ns, env_len) = (frame.seq, frame.send_ns, frame.envelope.len());
                let env_offset = HEADER_BYTES;
                self.track(seq);
                if self.fec.is_some() {
                    self.feed_fec_original(seq, datagram, peer, sealed_by);
                }
                Ok(Dispatched::Data {
                    pulse,
                    env_offset,
                    env_len,
                    meta: RecvMeta {
                        seq,
                        send_ns,
                        peer,
                        sealed_by,
                    },
                })
            }
            FRAG_MAGIC => {
                let fragment = decode_fragment(datagram)?;
                // Each fragment is a datagram of its own to the stream
                // tracking and the FEC windows.
                self.track(fragment.seq);
                if self.fec.is_some() {
                    self.feed_fec_original(fragment.seq, datagram, peer, sealed_by);
                }
                self.take_fragment(&fragment, peer, sealed_by);
                Ok(Dispatched::FragmentConsumed)
            }
            FEC_MAGIC if self.fec.is_some() => {
                self.feed_fec_parity(datagram, peer, sealed_by);
                Ok(Dispatched::ParityConsumed)
            }
            FEC_MAGIC => {
                // Parity with FEC off is dropped, not an error.
                Ok(Dispatched::ParityConsumed)
            }
            _ => Err(ReceiverError::Decode(crate::wire::WireError::BadMagic {
                got: magic,
                expected: DATA_MAGIC,
            })),
        }
    }

    /// Feed `seq` to the stream tracking
    /// ([`crate::backpressure::StreamTracker::arrived`]), with backpressure
    /// on.
    fn track(&self, seq: u64) {
        if let Some(tracker) = &self.tracker {
            tracker.arrived(seq);
        }
    }

    /// Count parity that could not be decoded, and log the first and each
    /// doubling.
    fn count_undecodable_parity(&mut self, what: &'static str) {
        self.parity_undecodable = self.parity_undecodable.wrapping_add(1);
        if self.parity_undecodable.is_power_of_two() {
            tracing::warn!(
                undecodable = self.parity_undecodable,
                "{what}; parity dropped"
            );
        }
    }

    /// Feed a data frame to the FEC decoder, holding any frame it rebuilds.
    fn feed_fec_original(
        &mut self,
        seq: u64,
        datagram: &[u8],
        peer: SocketAddr,
        sealed_by: Option<PublicKey>,
    ) {
        let rebuilt = match self.fec.as_mut() {
            Some(dec) => dec.add_original(seq, datagram),
            None => None,
        };
        if let Some((rec_seq, rec_bytes)) = rebuilt {
            self.queue_recovered(rec_seq, rec_bytes, peer, sealed_by);
        }
    }

    /// Decode a parity datagram and feed it to the decoder, holding any frame
    /// it rebuilds; one that does not decode, cut short included, is
    /// counted.
    fn feed_fec_parity(&mut self, datagram: &[u8], peer: SocketAddr, sealed_by: Option<PublicKey>) {
        let (header, parity_bytes) = match decode_fec(datagram) {
            Ok(parsed) => parsed,
            Err(_) => {
                self.count_undecodable_parity("parity datagram does not decode");
                return;
            }
        };
        self.parity_received = self.parity_received.wrapping_add(1);
        let rebuilt = match self.fec.as_mut() {
            Some(dec) => dec.add_parity(header, parity_bytes),
            None => None,
        };
        if let Some((rec_seq, rec_bytes)) = rebuilt {
            self.queue_recovered(rec_seq, rec_bytes, peer, sealed_by);
        }
    }

    /// Decode rebuilt bytes as a frame and hold it for delivery; bytes that
    /// do not decode (forged parity or frames, another stream's) are
    /// dropped and counted.
    fn queue_recovered(
        &mut self,
        _hint_seq: u64,
        encoded: Vec<u8>,
        peer: SocketAddr,
        sealed_by: Option<PublicKey>,
    ) {
        // A rebuilt fragment goes to the reassembler, not the queue; nothing
        // will deliver it alone, so it reaches the stream tracking now.
        if encoded.get(0..4) == Some(&FRAG_MAGIC.to_le_bytes()[..]) {
            let Ok(fragment) = decode_fragment(&encoded) else {
                self.count_undecodable_parity("fragment rebuilt from parity does not decode");
                return;
            };
            self.fec_rebuilt_fragments = self.fec_rebuilt_fragments.wrapping_add(1);
            self.last_rebuilt_fragment = Some(fragment.seq);
            self.track(fragment.seq);
            self.take_fragment(&fragment, peer, sealed_by);
            return;
        }
        let Ok(frame) = decode(&encoded) else {
            self.count_undecodable_parity("frame rebuilt from parity does not decode");
            return;
        };
        let Some(pulse) = Pulse::from_bytes(&frame.pulse) else {
            self.count_undecodable_parity("frame rebuilt from parity carries invalid pulse bytes");
            return;
        };
        self.fec_recovered = self.fec_recovered.wrapping_add(1);
        self.recovered_queue.push_back(PendingRecovered {
            pulse,
            envelope: frame.envelope.to_vec(),
            meta: RecvMeta {
                seq: frame.seq,
                send_ns: frame.send_ns,
                peer,
                sealed_by,
            },
            reassembled: false,
            span: 1,
        });
    }
}
