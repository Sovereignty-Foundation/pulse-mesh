// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! `PulseSender` and `PulseReceiver`: the transport contract, tier 1.
//!
//! A transport backend implements two one-way traits, a sender half and a
//! receiver half, each of which can be pinned to its own thread and its
//! own socket. The reference UDP transport implements them. Another
//! backend implements them in a crate of its own that depends only on this
//! one, so a new backend never touches the crates that use a transport: the
//! AF_XDP transport (`pulse-wire-xdp`) implements them so. The traits carry
//! Pulses and envelope bytes, not framing; each backend owns its wire
//! layout.
//!
//! In the book: <https://pulse-mesh.net/docs/architecture/core.html>.
#![forbid(unsafe_code)]

use std::net::SocketAddr;

use pulse_canon::Pulse;

#[non_exhaustive]
/// Errors common to every transport; a backend with richer errors of its
/// own converts them at the trait boundary.
#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    /// Underlying I/O failure (socket, file, kernel).
    #[error("transport io: {0}")]
    Io(#[from] std::io::Error),
    /// The caller's envelope buffer is smaller than the incoming envelope.
    #[error("envelope buffer too small: needed {needed} bytes, provided {provided}")]
    BufferTooSmall {
        /// Envelope length on the wire in bytes.
        needed: usize,
        /// Buffer length the caller provided.
        provided: usize,
    },
    /// A frame failed the wire format's validation (magic, version, length,
    /// CRC, or the backend's own checks).
    #[error("transport decode failed: {0}")]
    Decode(String),
    /// The envelope exceeds the transport's `max_envelope()`.
    #[error("envelope too large: {len} bytes (max {max})")]
    EnvelopeTooLarge {
        /// Envelope length the caller tried to send.
        len: usize,
        /// Maximum the transport accepts (`max_envelope()`).
        max: usize,
    },
    /// A send failed for a reason `Io` does not fit, such as the backend's
    /// flow control stalling (the UDP transport's backpressure window, which
    /// its opt-in congestion control sizes).
    #[error("transport send failed: {0}")]
    Send(String),
    /// A receive failed for a reason `Io` and `Decode` do not fit.
    #[error("transport recv failed: {0}")]
    Recv(String),
}

impl TransportError {
    /// Whether this is an I/O `WouldBlock` or `TimedOut`: no frame before
    /// the deadline.
    pub fn is_timeout(&self) -> bool {
        match self {
            Self::Io(e) => {
                e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut
            }
            _ => false,
        }
    }
}

/// The sending half of a transport; `Send`, so it can move to a thread of
/// its own.
pub trait PulseSender: Send {
    /// Send one Pulse and its envelope bytes to the configured peer.
    ///
    /// Implementations **should** not allocate per call, **must** stamp
    /// their own per-frame metadata (sequence number, send time), and
    /// **may** block under backpressure until the receiver catches up.
    ///
    /// # Errors
    ///
    /// - [`TransportError::EnvelopeTooLarge`] if `envelope` exceeds
    ///   [`PulseSender::max_envelope`].
    /// - [`TransportError::Io`] for a socket or kernel failure (such as
    ///   `ECONNREFUSED` or `ENOBUFS`).
    /// - [`TransportError::Send`] for a backend refusal `Io` does not fit.
    fn send(&mut self, pulse: &Pulse, envelope: &[u8]) -> Result<(), TransportError>;

    /// The largest envelope, in bytes, one [`PulseSender::send`] accepts:
    /// 0 for a backend that carries none.
    fn max_envelope(&self) -> usize;

    /// The local address the transport is bound to; `None` for one without
    /// a network address.
    fn local_addr(&self) -> Option<SocketAddr>;
}

/// The receiving half of a transport; `Send`, as [`PulseSender`] is.
pub trait PulseReceiver: Send {
    /// Receive one Pulse and its envelope into `envelope`, returning the
    /// Pulse and the envelope's length `n`: `envelope[..n]` holds it and
    /// `envelope[n..]` is untouched.
    ///
    /// Implementations **must not** allocate per call.
    ///
    /// # Errors
    ///
    /// - [`TransportError::BufferTooSmall`] when the envelope is larger
    ///   than `envelope`, which implementations **must** return. The frame
    ///   is consumed: grow the buffer for the next.
    /// - [`TransportError::Io`] for a socket or kernel failure; `WouldBlock`
    ///   or `TimedOut` after the read timeout means no frame came
    ///   ([`TransportError::is_timeout`]).
    /// - [`TransportError::Decode`] when the frame fails the transport's
    ///   validation; the text names the check.
    /// - [`TransportError::Recv`] for a backend failure the others do not
    ///   fit.
    fn recv_into(&mut self, envelope: &mut [u8]) -> Result<(Pulse, usize), TransportError>;

    /// The largest envelope, in bytes, the transport delivers.
    fn max_envelope(&self) -> usize;

    /// The local address the transport is bound to, if any.
    fn local_addr(&self) -> Option<SocketAddr>;
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    /// A no-op sender used to verify trait-object dispatch and the
    /// `Send` bound at compile time. Purely a trait-shape sanity check.
    struct NopSender;

    impl PulseSender for NopSender {
        fn send(&mut self, _pulse: &Pulse, _envelope: &[u8]) -> Result<(), TransportError> {
            Ok(())
        }
        fn max_envelope(&self) -> usize {
            0
        }
        fn local_addr(&self) -> Option<SocketAddr> {
            None
        }
    }

    struct NopReceiver;
    impl PulseReceiver for NopReceiver {
        fn recv_into(&mut self, _envelope: &mut [u8]) -> Result<(Pulse, usize), TransportError> {
            Ok((Pulse::zeroed(), 0))
        }
        fn max_envelope(&self) -> usize {
            0
        }
        fn local_addr(&self) -> Option<SocketAddr> {
            None
        }
    }

    #[test]
    fn trait_object_dispatch_compiles() {
        let mut tx: Box<dyn PulseSender> = Box::new(NopSender);
        let mut rx: Box<dyn PulseReceiver> = Box::new(NopReceiver);
        let p = Pulse::zeroed();
        tx.send(&p, &[]).unwrap();
        let mut buf = [0u8; 0];
        let (_got, n) = rx.recv_into(&mut buf).unwrap();
        assert_eq!(n, 0);
        // Pulse doesn't derive PartialEq (it's a 128-byte SeqLock'd
        // struct); compile-time dispatch is what we're verifying here,
        // bit-equality of zeroed Pulses is covered elsewhere.
    }

    #[test]
    fn buffer_too_small_carries_sizes() {
        let e = TransportError::BufferTooSmall {
            needed: 1024,
            provided: 256,
        };
        let s = format!("{}", e);
        assert!(s.contains("1024"));
        assert!(s.contains("256"));
    }

    #[test]
    fn envelope_too_large_carries_sizes() {
        let e = TransportError::EnvelopeTooLarge {
            len: 2048,
            max: 1450,
        };
        let s = format!("{}", e);
        assert!(s.contains("2048"));
        assert!(s.contains("1450"));
    }

    #[test]
    fn is_timeout_recognises_wouldblock_and_timedout() {
        let e1 = TransportError::Io(std::io::Error::from(std::io::ErrorKind::WouldBlock));
        assert!(e1.is_timeout());
        let e2 = TransportError::Io(std::io::Error::from(std::io::ErrorKind::TimedOut));
        assert!(e2.is_timeout());
        let e3 = TransportError::Decode("x".into());
        assert!(!e3.is_timeout());
    }
}
