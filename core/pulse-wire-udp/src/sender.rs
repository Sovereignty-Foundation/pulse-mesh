// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! The sending end: [`Sender`].

use std::io::IoSlice;
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use core_backoff::Backoff;
use pulse_canon::Pulse;

use crate::backpressure::{
    drain_front, BackpressureConfig, SenderBpState, MAX_NACKS_PER_CYCLE, STALL_SLEEP,
};
use crate::fec::{FecEncoder, FEC_MAX_ENVELOPE};
use crate::fragment::{encode_fragments, MAX_MESSAGE};
use crate::retry::retry_interrupted;
use crate::sealed::{SealError, SealSlot, Sealing, SEALED_OVERHEAD};
use crate::wire::{encode_header_into, encode_into, WireError, MAX_ENVELOPE, MTU_BYTES};

#[non_exhaustive]
/// Errors returned by [`Sender::send`].
#[derive(Debug, thiserror::Error)]
pub enum SenderError {
    /// Underlying socket I/O failure.
    #[error("udp send failed: {0}")]
    Io(#[from] std::io::Error),
    /// The frame failed to encode: [`WireError::EnvelopeTooLarge`] for an
    /// envelope over [`Sender::envelope_limit`]. The sender does not
    /// fragment.
    #[error("encode failed: {0}")]
    Encode(#[from] crate::wire::WireError),
    /// No destination — caller must `connect()` or use
    /// [`Sender::send_to`].
    #[error("no destination configured for connectionless send")]
    NoDestination,
    /// Backpressure held the send past `stall_timeout`: the receiver's
    /// cursor did not come within `target_queue_depth` frames of the next
    /// sequence number. The frame was not sent and its sequence number not
    /// used, so the call can be retried.
    #[error("send stalled for {waited:?} with {in_flight} frames unacknowledged")]
    Stalled {
        /// Frames sent beyond the receiver's acknowledged cursor when the
        /// send gave up.
        in_flight: u64,
        /// How long this send waited for the cursor before giving up.
        waited: Duration,
    },
    /// [`Sender::enable_backpressure`] was given a `target_queue_depth` of
    /// zero, which admits no frame; the sender's backpressure stays as it
    /// was.
    #[error("target_queue_depth must be at least 1")]
    InvalidQueueDepth,
    /// Sealing is installed and the frame could not be sealed:
    /// [`SealError::NoSession`] when no session to the destination is in
    /// use ([`Sealing::connect`] first). Found before the send waits on
    /// backpressure; the frame was not sent and its sequence number not
    /// used.
    #[error("seal failed: {0}")]
    Seal(#[from] SealError),
}

#[non_exhaustive]
/// Errors returned by [`Sender::send_batch`].
///
/// Frames go out in order, so every error leaves a sent prefix and an
/// unsent tail: [`Sender::next_seq`] stands one past the last frame sent,
/// and the unsent frames' sequence numbers are unused.
#[derive(Debug, thiserror::Error)]
pub enum BatchSendError {
    /// The frame at `index` failed: its encode, a backpressure stall past
    /// `stall_timeout`, or its send (on Linux, a `sendmmsg(2)` failure after
    /// earlier frames went out). The frames before `index` were sent; the
    /// rest were not.
    #[error("batch frame {index} failed: {error}")]
    FrameError {
        /// 0-indexed position of the failing frame.
        index: usize,
        /// Underlying single-frame sender error.
        #[source]
        error: SenderError,
    },
    /// The batch is longer than [`MAX_BATCH_FRAMES`]. Nothing was sent.
    #[error("batch too large: {got} frames; max {max}")]
    BatchTooLarge {
        /// Frame count caller passed.
        got: usize,
        /// Compile-time per-call limit.
        max: usize,
    },
    /// `sendmmsg(2)` took fewer frames than it was given (Linux): the first
    /// `sent` were sent, the rest not. The kernel drops the error of any
    /// frame after a call's first, so resending the tail is how to learn it.
    #[error("sendmmsg sent {sent} of {total} frames (kernel stopped early)")]
    PartialSend {
        /// Frames successfully dispatched.
        sent: usize,
        /// Frames the caller requested.
        total: usize,
    },
    /// `sendmmsg(2)` returned -1 for the batch's first frame (Linux);
    /// carries the underlying `errno`. Nothing was sent.
    #[error("sendmmsg syscall failed: {0}")]
    Io(#[from] std::io::Error),
}

/// The most frames [`Sender::send_batch`] takes in one call: Linux's
/// `UIO_MAXIOV`, the kernel's per-call limit.
pub const MAX_BATCH_FRAMES: usize = 1024;

/// Sends frames over UDP, each stamped with the next of this sender's
/// sequence numbers ([`crate::wire::Frame::seq`]), from 0.
///
/// Backpressure with NACK retransmission ([`Sender::enable_backpressure`]),
/// FEC ([`Sender::enable_fec`]) and sealing ([`Sender::with_sealing`]) are
/// opt-in.
pub struct Sender {
    socket: UdpSocket,
    dest: Option<SocketAddr>,
    seq: u64,
    encode_buf: Vec<u8>,
    bp: Option<SenderBpState>,
    /// Fed every frame sent; its parity goes, best effort, to the
    /// destination of the frame that completes a window.
    fec: Option<FecEncoder>,
    /// Parity datagrams sent.
    parity_sent: u64,
    /// When the last single send went out, for pacing.
    last_send: Option<Instant>,
    /// Envelopes longer than a frame go as runs of fragments.
    fragmenting: bool,
    /// With sealing on: every datagram is sealed before it leaves.
    sealing: Option<Sealing>,
    /// The sealed datagram, built here from `encode_buf`.
    seal_buf: Vec<u8>,
    /// The sealing the feedback thread opens ACKs and NACKs with.
    seal_slot: SealSlot,
}

impl Sender {
    /// Bind a sender to `local_addr`. `0.0.0.0:0` lets the OS pick a
    /// free port. Equivalent to `UdpSocket::bind`.
    ///
    /// # Errors
    /// Propagates any `std::io::Error` from the bind.
    pub fn bind<A: std::net::ToSocketAddrs>(local_addr: A) -> Result<Self, SenderError> {
        let socket = UdpSocket::bind(local_addr)?;
        Ok(Self::from_socket(socket))
    }

    /// Wrap an already-bound `UdpSocket` (lets the caller set socket
    /// options before constructing the sender).
    pub fn from_socket(socket: UdpSocket) -> Self {
        Self {
            socket,
            dest: None,
            seq: 0,
            encode_buf: Vec::with_capacity(crate::wire::MTU_BYTES),
            bp: None,
            fec: None,
            parity_sent: 0,
            last_send: None,
            fragmenting: false,
            sealing: None,
            seal_buf: Vec::new(),
            seal_slot: SealSlot::default(),
        }
    }

    /// Seal every datagram this sender sends, data, fragments, parity and
    /// retransmissions, with `sealing`, and open its feedback with it
    /// ([`crate::sealed`]). The socket should be the one `sealing` was made
    /// with, which [`crate::bind_sealed_pair`] sees to. A send to an address
    /// with no session in use fails with [`SealError::NoSession`];
    /// [`Sealing::connect`] makes one. A frame then carries
    /// [`SEALED_OVERHEAD`] fewer envelope bytes ([`Self::envelope_limit`]),
    /// fragments are as much shorter ([`Self::max_datagram`]), and
    /// [`Self::send_batch`] sends frame by frame.
    #[must_use]
    pub fn with_sealing(mut self, sealing: Sealing) -> Self {
        *self.seal_slot.write() = Some(sealing.clone());
        self.seal_buf = Vec::with_capacity(MTU_BYTES);
        self.sealing = Some(sealing);
        self
    }

    /// The sealing installed with [`Self::with_sealing`].
    pub fn sealing(&self) -> Option<&Sealing> {
        self.sealing.as_ref()
    }

    /// The largest datagram, as the unsealed transport builds it, that this
    /// sender can send whole: [`MTU_BYTES`], or [`MTU_BYTES`] less
    /// [`SEALED_OVERHEAD`] while sealing, so that the sealed datagram fits.
    pub fn max_inner_datagram(&self) -> usize {
        if self.sealing.is_some() {
            MTU_BYTES - SEALED_OVERHEAD
        } else {
            MTU_BYTES
        }
    }

    /// Start backpressure: a feedback thread listens on
    /// `cfg.ack_bind_addr` for the receiver's ACKs, and NACKs with NACK on,
    /// and a send waits while `cfg.target_queue_depth` frames are in flight
    /// beyond the receiver's cursor, for at most `cfg.stall_timeout`.
    ///
    /// Calling it again reconfigures the running backpressure in place,
    /// from the next send: the cursor and the counters carry over, and the
    /// retransmission cache while NACK stays on at the same capacity. Given
    /// the address the feedback socket holds ([`Self::ack_local_addr`], or
    /// the fixed `ack_bind_addr` it was bound with), the socket carries over
    /// too; any other address is bound before anything changes, so a failed
    /// bind changes nothing. An address that clashes with the running socket
    /// without being its own (the wildcard address against a specific one on
    /// the same port, say) fails with `AddrInUse`;
    /// [`Self::disable_backpressure`] first makes way for it.
    ///
    /// # Errors
    /// [`SenderError::InvalidQueueDepth`] if `cfg.target_queue_depth` is
    /// zero, before anything is bound or changed. Otherwise
    /// [`SenderError::Io`] from binding the feedback socket, which changes
    /// nothing, or from starting its thread, after which the sender has no
    /// backpressure, as [`Self::backpressure_enabled`] reports.
    pub fn enable_backpressure(&mut self, cfg: BackpressureConfig) -> Result<(), SenderError> {
        // Refused, not clamped: a config that cannot work fails where it is
        // applied rather than run with a depth nobody asked for.
        if cfg.target_queue_depth == 0 {
            return Err(SenderError::InvalidQueueDepth);
        }
        let Some(running) = self.bp.as_mut() else {
            self.bp = Some(SenderBpState::start(
                &cfg,
                self.seq,
                SealSlot::clone(&self.seal_slot),
            )?);
            return Ok(());
        };
        if let Err(e) = running.reconfigure(&cfg, self.seq) {
            // Without its feedback thread the state would stall every send.
            if !running.is_running() {
                self.bp = None;
            }
            return Err(e.into());
        }
        Ok(())
    }

    /// Switch backpressure off: stop the feedback thread and close its
    /// socket, so later sends never stall or answer NACKs. Does nothing when
    /// it is off already.
    pub fn disable_backpressure(&mut self) {
        self.bp = None;
    }

    /// True after [`Self::enable_backpressure`].
    pub fn backpressure_enabled(&self) -> bool {
        self.bp.is_some()
    }

    /// The address the feedback socket is bound to, with backpressure on:
    /// bind `ack_bind_addr` to port 0 and hand this to the receiver as its
    /// `ack_target_addr`.
    pub fn ack_local_addr(&self) -> Option<SocketAddr> {
        self.bp.as_ref().map(|s| s.local_addr)
    }

    /// Set how this sender's frames to a multicast group travel: `cfg`'s
    /// TTL (hop limit for IPv6), whether they loop back to receivers on
    /// this host, and the interface they leave by, for the socket's address
    /// family ([`crate::multicast`]). Frames then go to a group address as
    /// to any other.
    ///
    /// # Errors
    ///
    /// [`SenderError::Io`] when the socket refuses an option.
    pub fn set_multicast(
        &self,
        cfg: &crate::multicast::MulticastConfig,
    ) -> Result<(), SenderError> {
        crate::multicast::configure_sender(&self.socket, cfg)?;
        Ok(())
    }

    /// Send a parity datagram after every aligned window of `window_size`
    /// frames (K), to the destination of the frame that completes it
    /// ([`FecEncoder`]). Enabled mid-window, it starts at the next window,
    /// so up to K − 1 frames go out without parity; calling it again
    /// replaces the encoder, and its window in progress, the same way.
    ///
    /// While FEC is on, envelopes are limited to [`FEC_MAX_ENVELOPE`]
    /// ([`Self::envelope_limit`]).
    pub fn enable_fec(&mut self, window_size: u16) {
        self.fec = Some(FecEncoder::new(window_size));
    }

    /// Stop sending parity; the window in progress gets none.
    pub fn disable_fec(&mut self) {
        self.fec = None;
    }

    /// True after [`Self::enable_fec`].
    pub fn fec_enabled(&self) -> bool {
        self.fec.is_some()
    }

    /// Parity datagrams sent. Diagnostic.
    pub fn parity_sent_count(&self) -> u64 {
        self.parity_sent
    }

    /// The congestion window in frames, with congestion control on
    /// ([`crate::BackpressureConfig::with_congestion_control`]): the most
    /// frames a send lets be in flight, within `target_queue_depth`.
    pub fn congestion_window(&self) -> Option<u32> {
        self.bp.as_ref()?.congestion.as_ref().map(|c| c.window())
    }

    /// The smoothed round trip congestion control has measured, once it has
    /// a sample.
    pub fn smoothed_rtt(&self) -> Option<Duration> {
        self.bp.as_ref()?.congestion.as_ref()?.srtt()
    }

    /// Times congestion control has decreased the window for a loss. Zero
    /// with it off.
    pub fn congestion_decreases(&self) -> u64 {
        self.bp
            .as_ref()
            .and_then(|bp| bp.congestion.as_ref())
            .map_or(0, |c| c.decreases())
    }

    /// The highest receive cursor the receiver has acknowledged, or 0 with
    /// backpressure off. Diagnostic.
    pub fn observed_recv_cursor(&self) -> u64 {
        match &self.bp {
            Some(s) => s.recv_cursor.load(Ordering::Acquire),
            None => 0,
        }
    }

    /// Set the destination of [`Sender::send`]: the first address `dest`
    /// resolves to. The socket itself is not connected.
    ///
    /// # Errors
    /// Propagates I/O errors from address resolution or `connect`.
    pub fn connect<A: std::net::ToSocketAddrs>(&mut self, dest: A) -> Result<(), SenderError> {
        let addr = dest
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "no addrs"))?;
        self.dest = Some(addr);
        Ok(())
    }

    /// Local address the socket is bound to.
    ///
    /// # Errors
    /// Propagates the underlying [`UdpSocket::local_addr`] error.
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// [`MAX_ENVELOPE`], the envelope limit without FEC;
    /// [`Self::envelope_limit`] gives a sender's own.
    pub fn max_envelope() -> usize {
        MAX_ENVELOPE
    }

    /// The largest envelope this sender accepts now: [`MAX_ENVELOPE`], or
    /// [`FEC_MAX_ENVELOPE`] while FEC is on, each less [`SEALED_OVERHEAD`]
    /// while sealing, or with fragmentation on [`MAX_MESSAGE`] for a single
    /// send. A larger one is refused with [`WireError::EnvelopeTooLarge`]
    /// carrying this limit, before the send waits on backpressure or uses a
    /// sequence number.
    pub fn envelope_limit(&self) -> usize {
        if self.fragmenting {
            MAX_MESSAGE
        } else {
            self.frame_limit()
        }
    }

    /// The largest envelope one frame carries: [`MAX_ENVELOPE`], or
    /// [`FEC_MAX_ENVELOPE`] while FEC is on, each less [`SEALED_OVERHEAD`]
    /// while sealing.
    fn frame_limit(&self) -> usize {
        let limit = if self.fec.is_some() {
            FEC_MAX_ENVELOPE
        } else {
            MAX_ENVELOPE
        };
        if self.sealing.is_some() {
            limit - SEALED_OVERHEAD
        } else {
            limit
        }
    }

    /// The largest datagram this sender sends, as the unsealed transport
    /// builds it, and so the size of its fragments:
    /// [`Self::max_inner_datagram`] ([`MTU_BYTES`], or [`SEALED_OVERHEAD`]
    /// less while sealing), less, while FEC is on, the room its parity's
    /// header needs, as [`FEC_MAX_ENVELOPE`] leaves it in a frame.
    pub fn max_datagram(&self) -> usize {
        let inner = self.max_inner_datagram();
        if self.fec.is_some() {
            inner - (MAX_ENVELOPE - FEC_MAX_ENVELOPE)
        } else {
            inner
        }
    }

    /// Send envelopes longer than a frame carries, up to [`MAX_MESSAGE`]
    /// bytes, as runs of fragments ([`crate::fragment`]): each fragment is a
    /// datagram of its own, at most [`Self::max_datagram`] bytes, with a
    /// sequence number of its own, waiting on backpressure, cached for
    /// NACK, fed to FEC and counted by congestion control as any frame is.
    /// The receiver needs reassembly on
    /// ([`crate::Receiver::enable_reassembly`]). An envelope that fits a
    /// frame still goes as one.
    pub fn enable_fragmentation(&mut self) {
        self.fragmenting = true;
    }

    /// Refuse envelopes longer than a frame again.
    pub fn disable_fragmentation(&mut self) {
        self.fragmenting = false;
    }

    /// True after [`Self::enable_fragmentation`].
    pub fn fragmentation_enabled(&self) -> bool {
        self.fragmenting
    }

    /// Refuse an envelope over `max`.
    fn check_envelope(&self, envelope: &[u8], max: usize) -> Result<(), SenderError> {
        if envelope.len() > max {
            return Err(SenderError::Encode(WireError::EnvelopeTooLarge {
                got: envelope.len(),
                max,
            }));
        }
        Ok(())
    }

    /// Send one frame to the destination [`Sender::connect`] set, as
    /// [`Sender::send_to`] does.
    ///
    /// # Errors
    /// [`SenderError::NoDestination`] if none is set; otherwise as
    /// [`Sender::send_to`].
    pub fn send(
        &mut self,
        send_ns: u64,
        pulse: &Pulse,
        envelope: &[u8],
    ) -> Result<u64, SenderError> {
        let dest = self.dest.ok_or(SenderError::NoDestination)?;
        self.send_to(send_ns, pulse, envelope, dest)
    }

    /// Send one frame to `dest`, stamped with the next sequence number and
    /// `send_ns`, and return the sequence number.
    ///
    /// With backpressure on, the send first waits (spinning, yielding, then
    /// sleeping [`STALL_SLEEP`] at a time) while `target_queue_depth` or
    /// more frames are in flight beyond the receiver's cursor, for at most
    /// `stall_timeout`; a cursor ahead of the next sequence number counts as
    /// none in flight. With congestion control on, the congestion window
    /// takes the place of `target_queue_depth` when it is smaller, and with
    /// pacing on the send then waits until the smoothed round trip over the
    /// window has passed since the last single send. With NACK on, it first retransmits up to
    /// [`MAX_NACKS_PER_CYCLE`] requested frames, and it caches the frame it
    /// sends.
    ///
    /// # Errors
    ///
    /// - [`SenderError::Stalled`] if backpressure held the send past
    ///   `stall_timeout`: the frame was not sent and [`Sender::next_seq`] is
    ///   unchanged; retransmits made before the wait went out.
    /// - [`SenderError::Encode`] for an envelope over
    ///   [`Self::envelope_limit`], found before any wait or sequence number.
    /// - [`SenderError::Seal`] while sealing, when no session to `dest` is
    ///   in use, found before any wait or sequence number.
    /// - [`SenderError::Io`] when the socket refuses the datagram
    ///   (`ENOBUFS`, `ENETUNREACH`, ...). A send a signal interrupts is made
    ///   again, not returned.
    pub fn send_to(
        &mut self,
        send_ns: u64,
        pulse: &Pulse,
        envelope: &[u8],
        dest: SocketAddr,
    ) -> Result<u64, SenderError> {
        if self.fragmenting && envelope.len() > self.frame_limit() {
            return self.send_fragments(send_ns, pulse, envelope, dest);
        }
        self.check_envelope(envelope, self.frame_limit())?;
        self.before_send(dest)?;
        let seq = self.seq;
        self.encode_buf.clear();

        // The send cache, the FEC encoder and sealing need the whole
        // datagram; without them the envelope goes out from the caller's
        // buffer.
        let needs_contiguous_buf = matches!(&self.bp, Some(bp) if bp.send_cache.is_some())
            || self.fec.is_some()
            || self.sealing.is_some();

        if needs_contiguous_buf {
            encode_into(seq, send_ns, pulse, envelope, &mut self.encode_buf)?;
            send_datagram(
                &self.socket,
                self.sealing.as_ref(),
                &mut self.seal_buf,
                &self.encode_buf,
                dest,
            )?;

            // Cached once sent; a retransmit sends these bytes as they are.
            if let Some(bp) = &self.bp {
                if let Some(cache) = &bp.send_cache {
                    cache.lock().store(seq, &self.encode_buf);
                }
            }

            if let Some(enc) = self.fec.as_mut() {
                if let Some(parity_bytes) = enc.add_original(seq, &self.encode_buf) {
                    let sent = send_datagram(
                        &self.socket,
                        self.sealing.as_ref(),
                        &mut self.seal_buf,
                        &parity_bytes,
                        dest,
                    );
                    if sent.is_ok() {
                        self.parity_sent = self.parity_sent.wrapping_add(1);
                    }
                }
            }
        } else {
            // Header, envelope and trailer as three iovecs of one
            // `sendmsg(2)`: the contiguous path's bytes (`frame_crc`).
            encode_header_into(seq, send_ns, pulse, envelope.len(), &mut self.encode_buf)?;
            let crc = crate::wire::frame_crc(&self.encode_buf, envelope);
            let crc_bytes = crc.to_le_bytes();
            let iovs = [
                IoSlice::new(&self.encode_buf),
                IoSlice::new(envelope),
                IoSlice::new(&crc_bytes),
            ];
            let sock = socket2::SockRef::from(&self.socket);
            let to = socket2::SockAddr::from(dest);
            retry_interrupted(|| sock.send_to_vectored(&iovs, &to))?;
        }

        self.after_send(seq);
        Ok(seq)
    }

    /// What every single send does first: while sealing, refuse a
    /// destination with no session; with backpressure on, retransmit what is
    /// requested, wait for room, and with pacing on wait its turn.
    fn before_send(&mut self, dest: SocketAddr) -> Result<(), SenderError> {
        if let Some(sealing) = &self.sealing {
            // A rekey's response may wait on the socket for nobody else.
            sealing.pump_if_pending();
            if !sealing.can_seal_to(dest) {
                return Err(SealError::NoSession(dest).into());
            }
        }
        if let Some(bp) = &self.bp {
            // Retransmits go first, for a short NACK turnaround, and are
            // capped, so a NACK flood cannot make one send thousands.
            retransmit_pending(
                bp,
                &self.socket,
                self.sealing.as_ref(),
                dest,
                MAX_NACKS_PER_CYCLE,
            );
            wait_for_room(bp, self.seq)?;
            if let Some(interval) = bp.congestion.as_ref().and_then(|c| c.pace_interval()) {
                pace(self.last_send, interval);
            }
        }
        Ok(())
    }

    /// What every single send does last: report it to congestion control
    /// and take the next sequence number.
    fn after_send(&mut self, seq: u64) {
        if let Some(congestion) = self.bp.as_ref().and_then(|bp| bp.congestion.as_ref()) {
            congestion.sent(seq, seq.wrapping_add(1));
            self.last_send = Some(Instant::now());
        }
        self.seq = self.seq.wrapping_add(1);
    }

    /// Send `envelope` as the run of fragments that starts at the next
    /// sequence number, each fragment as a single send; returns the run's
    /// first sequence number. A fragment that stalls or fails ends the run
    /// there: the fragments before it went out, the receiver drops the
    /// incomplete run at its timeout, and the next send starts after them.
    fn send_fragments(
        &mut self,
        send_ns: u64,
        pulse: &Pulse,
        envelope: &[u8],
        dest: SocketAddr,
    ) -> Result<u64, SenderError> {
        let first = self.seq;
        let datagrams = encode_fragments(first, send_ns, pulse, envelope, self.max_datagram())?;
        for datagram in &datagrams {
            self.before_send(dest)?;
            let seq = self.seq;
            // Sealed, when sealing is on, as a datagram of its own; the
            // cache and the encoder keep the fragment unsealed, so that a
            // retransmission is sealed afresh.
            send_datagram(
                &self.socket,
                self.sealing.as_ref(),
                &mut self.seal_buf,
                datagram,
                dest,
            )?;
            if let Some(bp) = &self.bp {
                if let Some(cache) = &bp.send_cache {
                    cache.lock().store(seq, datagram);
                }
            }
            if let Some(enc) = self.fec.as_mut() {
                if let Some(parity_bytes) = enc.add_original(seq, datagram) {
                    let sent = send_datagram(
                        &self.socket,
                        self.sealing.as_ref(),
                        &mut self.seal_buf,
                        &parity_bytes,
                        dest,
                    );
                    if sent.is_ok() {
                        self.parity_sent = self.parity_sent.wrapping_add(1);
                    }
                }
            }
            self.after_send(seq);
        }
        Ok(first)
    }

    /// Frames retransmitted for NACKs. Diagnostic.
    pub fn retransmit_count(&self) -> u64 {
        match &self.bp {
            Some(s) => s.retransmits.load(Ordering::Relaxed),
            None => 0,
        }
    }

    /// NACKs for frames the send cache no longer held. Diagnostic.
    pub fn cache_miss_count(&self) -> u64 {
        match &self.bp {
            Some(s) => s.cache_misses.load(Ordering::Relaxed),
            None => 0,
        }
    }

    /// Feedback datagrams dropped because their source IP did not match
    /// `BackpressureConfig::feedback_peer` (0 when no filter is set).
    pub fn feedback_rejected_count(&self) -> u64 {
        match &self.bp {
            Some(s) => s.feedback_rejected.load(Ordering::Relaxed),
            None => 0,
        }
    }

    /// NACKs dropped because the pending queue was already full (its
    /// bound is the send-cache capacity).
    pub fn nack_drop_count(&self) -> u64 {
        match &self.bp {
            Some(s) => s.nacks_dropped.load(Ordering::Relaxed),
            None => 0,
        }
    }

    /// Errors the feedback socket's receive returned, other than a timeout
    /// or an interruption (0 with backpressure off). The feedback thread
    /// logs the first and each doubling, pauses a millisecond and carries
    /// on until backpressure is dropped, so an error never leaves the sender
    /// without ACKs. Diagnostic.
    pub fn feedback_error_count(&self) -> u64 {
        match &self.bp {
            Some(s) => s.feedback_errors.load(Ordering::Relaxed),
            None => 0,
        }
    }

    /// Send `frames`, each `(send_ns, pulse, envelope)`, to `dest` in
    /// order, and return their sequence numbers: in `sendmmsg(2)` calls on
    /// Linux, through [`Self::send_to`] frame by frame elsewhere (with a
    /// warning, once per process) and while sealing, where each frame is
    /// sealed as `send_to` seals it. Nothing is buffered or held for a
    /// timer.
    ///
    /// A batch sends no runs of fragments: with fragmentation on, an
    /// envelope longer than a frame is refused here as it is without it.
    ///
    /// Each frame gets what [`Self::send_to`] gives one: backpressure admits
    /// it only while fewer than `target_queue_depth` frames, or the
    /// congestion window's worth, are in flight (on Linux a batch goes out as
    /// the window allows, unpaced),
    /// and a frame that waits past `stall_timeout` ends the batch; with NACK
    /// on, up to [`MAX_NACKS_PER_CYCLE`] requests are retransmitted per frame
    /// and every frame sent is cached; with FEC on, a window's parity goes
    /// out right after the frame that completes it. On Linux the batch is
    /// one call, or with backpressure or FEC several: each within the window
    /// the receiver's cursor leaves open and none past a parity window's
    /// last frame, the NACKs for a call's frames retransmitted before it.
    ///
    /// # Errors
    ///
    /// The frames before the failing one were sent, the rest not
    /// ([`BatchSendError`]).
    ///
    /// - [`BatchSendError::BatchTooLarge`] for more than
    ///   [`MAX_BATCH_FRAMES`] frames, before anything is sent.
    /// - [`BatchSendError::FrameError`] when the frame at `index` fails to
    ///   encode (an envelope over [`Self::envelope_limit`] included), stalls
    ///   past `stall_timeout` ([`SenderError::Stalled`]), or fails to send.
    /// - [`BatchSendError::PartialSend`] when `sendmmsg(2)` took only some
    ///   of the frames it was given, and [`BatchSendError::Io`] when it
    ///   failed on the batch's first frame (both Linux only).
    pub fn send_batch(
        &mut self,
        frames: &[(u64, &Pulse, &[u8])],
        dest: SocketAddr,
    ) -> Result<Vec<u64>, BatchSendError> {
        if frames.is_empty() {
            return Ok(Vec::new());
        }
        if frames.len() > MAX_BATCH_FRAMES {
            return Err(BatchSendError::BatchTooLarge {
                got: frames.len(),
                max: MAX_BATCH_FRAMES,
            });
        }
        if self.sealing.is_some() {
            return self.send_batch_each(frames, dest);
        }
        #[cfg(target_os = "linux")]
        {
            self.send_batch_linux(frames, dest)
        }
        #[cfg(not(target_os = "linux"))]
        {
            self.send_batch_fallback(frames, dest)
        }
    }

    /// The `sendmmsg(2)` path of [`Self::send_batch`]. Every frame is
    /// encoded first, frame `i` stamped `first_seq + i`; `self.seq` advances
    /// only past frames the kernel took, so an unsent frame's number stays
    /// unused and the frame never reaches the cache or the encoder.
    #[cfg(target_os = "linux")]
    #[allow(unsafe_code)]
    fn send_batch_linux(
        &mut self,
        frames: &[(u64, &Pulse, &[u8])],
        dest: SocketAddr,
    ) -> Result<Vec<u64>, BatchSendError> {
        use std::os::unix::io::AsRawFd;

        let first_seq = self.seq;
        let sa = socket2::SockAddr::from(dest);
        let sa_ptr = sa.as_ptr() as *mut libc::c_void;
        let sa_len = sa.len();

        // Each Vec below is filled before any pointer into it is taken and
        // never grows after, so the pointers in `iovecs` and `mmsghdrs` stay
        // valid through the calls.
        let mut headers: Vec<Vec<u8>> = Vec::with_capacity(frames.len());
        let mut crc_bufs: Vec<[u8; 4]> = Vec::with_capacity(frames.len());

        // A frame that fails to encode ends the batch: the frames before it
        // are sent, then its error is returned, as on the other path.
        let mut encode_failure = None;
        for (index, (send_ns, pulse, envelope)) in frames.iter().enumerate() {
            let seq = first_seq.wrapping_add(index as u64);
            // With FEC on the limit is below MAX_ENVELOPE, all the header
            // encoder checks.
            if let Err(error) = self.check_envelope(envelope, self.frame_limit()) {
                encode_failure = Some(BatchSendError::FrameError { index, error });
                break;
            }
            let mut header: Vec<u8> = Vec::with_capacity(crate::wire::HEADER_BYTES);
            if let Err(e) = encode_header_into(seq, *send_ns, pulse, envelope.len(), &mut header) {
                encode_failure = Some(BatchSendError::FrameError {
                    index,
                    error: SenderError::Encode(e),
                });
                break;
            }
            let crc = crate::wire::frame_crc(&header, envelope);
            headers.push(header);
            crc_bufs.push(crc.to_le_bytes());
        }
        let n = headers.len();

        let mut iovecs: Vec<[libc::iovec; 3]> = Vec::with_capacity(n);
        for i in 0..n {
            iovecs.push([
                libc::iovec {
                    iov_base: headers[i].as_ptr() as *mut libc::c_void,
                    iov_len: headers[i].len(),
                },
                libc::iovec {
                    iov_base: frames[i].2.as_ptr() as *mut libc::c_void,
                    iov_len: frames[i].2.len(),
                },
                libc::iovec {
                    iov_base: crc_bufs[i].as_ptr() as *mut libc::c_void,
                    iov_len: 4,
                },
            ]);
        }

        let mut mmsghdrs: Vec<libc::mmsghdr> = Vec::with_capacity(n);
        for iov in iovecs.iter_mut() {
            // SAFETY: `msghdr` is plain data, valid all-zero; the fields
            // left zero (no control data, no flags) mean none to sendmmsg.
            let mut mh: libc::msghdr = unsafe { std::mem::zeroed() };
            mh.msg_name = sa_ptr;
            mh.msg_namelen = sa_len;
            mh.msg_iov = iov.as_mut_ptr();
            mh.msg_iovlen = 3;
            mmsghdrs.push(libc::mmsghdr {
                msg_hdr: mh,
                msg_len: 0,
            });
        }

        let fd = self.socket.as_raw_fd();
        // With NACK or FEC on, each frame the kernel takes is reassembled
        // in `sent_bytes`, as it went out, for the cache and the encoder.
        let keeps_bytes =
            matches!(&self.bp, Some(bp) if bp.send_cache.is_some()) || self.fec.is_some();
        let mut sent_bytes: Vec<u8> = Vec::new();
        let mut sent = 0usize;
        while sent < n {
            // Backpressure: at most the window the cursor leaves open, at
            // least one frame once the wait succeeds; NACKs are drained
            // before the wait, as in `send_to`.
            let mut count = n - sent;
            if let Some(bp) = &self.bp {
                retransmit_pending(bp, &self.socket, None, dest, MAX_NACKS_PER_CYCLE);
                let room = wait_for_room(bp, self.seq)
                    .map_err(|error| BatchSendError::FrameError { index: sent, error })?;
                count = count.min(usize::try_from(room).unwrap_or(usize::MAX));
            }
            // FEC: no call runs past a window's last frame, so its parity
            // follows that frame; at least one frame of the window remains.
            if let Some(enc) = &self.fec {
                count = count.min(usize::from(enc.window_size() - enc.pending_count()));
            }
            // The NACKs `send_to` would drain before the call's other
            // frames go now: the same budget per frame, and each
            // retransmission still precedes the frames after its request.
            if let Some(bp) = &self.bp {
                let rest = MAX_NACKS_PER_CYCLE.saturating_mul(count - 1);
                retransmit_pending(bp, &self.socket, None, dest, rest);
            }
            let chunk = &mut mmsghdrs[sent..sent + count];
            let ret = loop {
                // SAFETY: fd is a valid UDP socket; `chunk` is `count`
                // initialised mmsghdrs (count <= MAX_BATCH_FRAMES, so the
                // c_uint cast is exact); every pointer inside them (msg_name,
                // msg_iov and the iovecs' buffers) points into storage this
                // function owns or borrows, none of which moves or is written
                // during this call.
                let ret =
                    unsafe { libc::sendmmsg(fd, chunk.as_mut_ptr(), count as libc::c_uint, 0) };
                if ret >= 0 {
                    break ret;
                }
                let error = std::io::Error::last_os_error();
                // Interrupted before any frame went (once one has, the call
                // returns the count), so the same frames go again.
                if error.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(if sent == 0 {
                    BatchSendError::Io(error)
                } else {
                    BatchSendError::FrameError {
                        index: sent,
                        error: SenderError::Io(error),
                    }
                });
            };
            let took = (ret as usize).min(count);
            if keeps_bytes {
                // As `send_to` does after each frame: cache it, then feed
                // the encoder. Only the call's last frame can complete a
                // window, so the parity goes out before the next call.
                for i in sent..sent + took {
                    let seq = first_seq.wrapping_add(i as u64);
                    sent_bytes.clear();
                    sent_bytes.extend_from_slice(&headers[i]);
                    sent_bytes.extend_from_slice(frames[i].2);
                    sent_bytes.extend_from_slice(&crc_bufs[i]);
                    if let Some(bp) = &self.bp {
                        if let Some(cache) = &bp.send_cache {
                            cache.lock().store(seq, &sent_bytes);
                        }
                    }
                    if let Some(enc) = self.fec.as_mut() {
                        if let Some(parity_bytes) = enc.add_original(seq, &sent_bytes) {
                            if retry_interrupted(|| self.socket.send_to(&parity_bytes, dest))
                                .is_ok()
                            {
                                self.parity_sent = self.parity_sent.wrapping_add(1);
                            }
                        }
                    }
                }
            }
            if let Some(congestion) = self.bp.as_ref().and_then(|bp| bp.congestion.as_ref()) {
                congestion.sent(self.seq, self.seq.wrapping_add(took as u64));
            }
            self.seq = self.seq.wrapping_add(took as u64);
            sent += took;
            if took < count {
                return Err(BatchSendError::PartialSend {
                    sent,
                    total: frames.len(),
                });
            }
        }
        if let Some(failure) = encode_failure {
            return Err(failure);
        }
        Ok((0..n as u64).map(|i| first_seq.wrapping_add(i)).collect())
    }

    #[cfg(not(target_os = "linux"))]
    fn send_batch_fallback(
        &mut self,
        frames: &[(u64, &Pulse, &[u8])],
        dest: SocketAddr,
    ) -> Result<Vec<u64>, BatchSendError> {
        use std::sync::Once;
        static WARN_ONCE: Once = Once::new();
        WARN_ONCE.call_once(|| {
            tracing::warn!(
                "Sender::send_batch fallback: sendmmsg(2) is Linux-only; \
 falling back to serial send_to loop (no syscall amortization). \
 Build on Linux for the fast path."
            );
        });
        self.send_batch_each(frames, dest)
    }

    /// [`Self::send_batch`] frame by frame, through [`Self::send_to`]: the
    /// path off Linux and while sealing.
    fn send_batch_each(
        &mut self,
        frames: &[(u64, &Pulse, &[u8])],
        dest: SocketAddr,
    ) -> Result<Vec<u64>, BatchSendError> {
        let mut seqs = Vec::with_capacity(frames.len());
        for (index, (send_ns, pulse, envelope)) in frames.iter().enumerate() {
            // Frame by frame, as the Linux path: a batch sends no runs.
            if let Err(error) = self.check_envelope(envelope, self.frame_limit()) {
                return Err(BatchSendError::FrameError { index, error });
            }
            match self.send_to(*send_ns, pulse, envelope, dest) {
                Ok(seq) => seqs.push(seq),
                Err(e) => {
                    return Err(BatchSendError::FrameError { index, error: e });
                }
            }
        }
        Ok(seqs)
    }

    /// The sequence number the next frame will carry.
    pub fn next_seq(&self) -> u64 {
        self.seq
    }

    /// The socket, for configuration such as its send buffer size.
    pub fn socket(&self) -> &UdpSocket {
        &self.socket
    }
}

/// Send `datagram` to `dest`, sealed into `seal_buf` first when `sealing` is
/// installed.
fn send_datagram(
    socket: &UdpSocket,
    sealing: Option<&Sealing>,
    seal_buf: &mut Vec<u8>,
    datagram: &[u8],
    dest: SocketAddr,
) -> Result<(), SenderError> {
    match sealing {
        None => retry_interrupted(|| socket.send_to(datagram, dest))?,
        Some(sealing) => {
            sealing.seal_to(dest, datagram, seal_buf)?;
            retry_interrupted(|| socket.send_to(seal_buf, dest))?
        }
    };
    Ok(())
}

/// Retransmit up to `budget` of the queued NACK requests, oldest first: each
/// requested frame's cached bytes go to `dest` as they are, sealed afresh
/// with `sealing`, and a request for a frame no longer cached counts as a
/// miss. Nothing with NACK off.
fn retransmit_pending(
    bp: &SenderBpState,
    socket: &UdpSocket,
    sealing: Option<&Sealing>,
    dest: SocketAddr,
    budget: usize,
) {
    let Some(send_cache) = &bp.send_cache else {
        return;
    };
    let to_retransmit = drain_front(&bp.pending_nacks, budget);
    if to_retransmit.is_empty() {
        return;
    }
    let cache = send_cache.lock();
    let mut seal_buf = Vec::new();
    for missing in to_retransmit {
        if let Some(cached) = cache.lookup(missing) {
            if send_datagram(socket, sealing, &mut seal_buf, &cached.encoded, dest).is_ok() {
                bp.retransmits.fetch_add(1, Ordering::Relaxed);
            }
        } else {
            bp.cache_misses.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Wait until backpressure lets at least one more frame go, and return how
/// many may go now: `target_queue_depth` less the frames in flight beyond
/// the receiver's cursor, `next_seq` being the next frame's number. Past
/// `stall_timeout` it fails with `Stalled`, and the caller sends nothing.
///
/// The count saturates, not wraps: a cursor ahead of `next_seq` is a
/// receiver that outlived a restart of this sender, or a forged ACK, and
/// nothing of this run is in flight then (checked by
/// `tests/stall_deadline.rs`).
fn wait_for_room(bp: &SenderBpState, next_seq: u64) -> Result<u64, SenderError> {
    let depth = u64::from(bp.target_queue_depth);
    // The ACK usually lands within microseconds, so spinning and yielding
    // catch it before a sleep would; the clock is read only once the send
    // has had to wait.
    let mut backoff = Backoff::with_sleep(STALL_SLEEP);
    let mut stalled_since: Option<Instant> = None;
    loop {
        // The window moves as ACKs and NACKs arrive, so it is read each time.
        let target = bp
            .congestion
            .as_ref()
            .map_or(depth, |c| depth.min(u64::from(c.window())));
        let cursor = bp.recv_cursor.load(Ordering::Acquire);
        let in_flight = next_seq.saturating_sub(cursor);
        if in_flight < target {
            return Ok(target - in_flight);
        }
        if let Some(limit) = bp.stall_timeout {
            let waited = stalled_since.get_or_insert_with(Instant::now).elapsed();
            if waited >= limit {
                return Err(SenderError::Stalled { in_flight, waited });
            }
        }
        backoff.snooze();
    }
}

/// Wait until `interval` has passed since `last`, the last paced send, as
/// a backpressure wait does: spinning, yielding, then sleeping
/// [`STALL_SLEEP`] at a time.
fn pace(last: Option<Instant>, interval: Duration) {
    let Some(due) = last.map(|at| at + interval) else {
        return;
    };
    let mut backoff = Backoff::with_sleep(STALL_SLEEP);
    while Instant::now() < due {
        backoff.snooze();
    }
}
