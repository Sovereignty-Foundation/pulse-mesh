// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! The `core_transport` `PulseSender` and `PulseReceiver` impls for
//! [`crate::Sender`] and [`crate::Receiver`].
//!
//! The traits carry no clock, so a trait send stamps `send_ns = 0`, which
//! the specification allows; a caller that measures latency uses
//! [`crate::Sender::send`], which takes `send_ns`.

use std::net::SocketAddr;

use core_transport::{PulseReceiver, PulseSender, TransportError};
use pulse_canon::Pulse;

use crate::receiver::{Receiver, ReceiverError};
use crate::sender::{Sender, SenderError};
use crate::wire::WireError;

impl From<SenderError> for TransportError {
    fn from(e: SenderError) -> Self {
        match e {
            SenderError::Io(io) => TransportError::Io(io),
            SenderError::Encode(WireError::EnvelopeTooLarge { got, max }) => {
                TransportError::EnvelopeTooLarge { len: got, max }
            }
            SenderError::Encode(other) => TransportError::Send(format!("encode: {other}")),
            SenderError::NoDestination => TransportError::Send("no destination configured".into()),
            // A stalled flow-control window, which `Send` is for; not an I/O timeout, which
            // callers take as a graceful drain.
            stalled @ SenderError::Stalled { .. } => TransportError::Send(stalled.to_string()),
            // A configuration error; only `enable_backpressure` returns it.
            invalid @ SenderError::InvalidQueueDepth => TransportError::Send(invalid.to_string()),
            // No session to seal under: a send that cannot go yet.
            seal @ SenderError::Seal(_) => TransportError::Send(seal.to_string()),
        }
    }
}

impl From<ReceiverError> for TransportError {
    fn from(e: ReceiverError) -> Self {
        match e {
            ReceiverError::Io(io) => TransportError::Io(io),
            ReceiverError::Decode(d) => TransportError::Decode(format!("{d}")),
            ReceiverError::BufferTooSmall { needed, provided } => {
                TransportError::BufferTooSmall { needed, provided }
            }
            ReceiverError::InvalidPulseBytes => {
                TransportError::Decode("pulse bytes could not be decoded".into())
            }
        }
    }
}

impl PulseSender for Sender {
    fn send(&mut self, pulse: &Pulse, envelope: &[u8]) -> Result<(), TransportError> {
        Sender::send(self, 0, pulse, envelope)?;
        Ok(())
    }

    fn max_envelope(&self) -> usize {
        // What this sender accepts now: less while FEC is on.
        self.envelope_limit()
    }

    fn local_addr(&self) -> Option<SocketAddr> {
        Sender::local_addr(self).ok()
    }
}

impl PulseReceiver for Receiver {
    fn recv_into(&mut self, envelope: &mut [u8]) -> Result<(Pulse, usize), TransportError> {
        let (pulse, n, _meta) = Receiver::recv_into(self, envelope)?;
        Ok((pulse, n))
    }

    fn max_envelope(&self) -> usize {
        Receiver::max_envelope()
    }

    fn local_addr(&self) -> Option<SocketAddr> {
        Receiver::local_addr(self).ok()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use std::time::Duration;

    use pulse_canon::Instruction;

    fn pair() -> (Sender, Receiver) {
        let mut sender = Sender::bind("127.0.0.1:0").unwrap();
        let receiver = Receiver::bind("127.0.0.1:0").unwrap();
        receiver
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let recv_addr = receiver.local_addr().unwrap();
        sender.connect(recv_addr).unwrap();
        (sender, receiver)
    }

    #[test]
    fn trait_round_trip_zero_envelope() {
        let (mut sender, mut receiver) = pair();
        let mut p = Pulse::zeroed();
        p.instruction = Instruction::Data as u16;
        p.scope = 7;

        let tx: &mut dyn PulseSender = &mut sender;
        tx.send(&p, &[]).unwrap();

        let rx: &mut dyn PulseReceiver = &mut receiver;
        let mut buf = [0u8; 0];
        let (recv_pulse, n) = rx.recv_into(&mut buf).unwrap();
        assert_eq!(n, 0);
        assert_eq!(recv_pulse.scope, 7);
    }

    #[test]
    fn trait_round_trip_with_envelope() {
        let (mut sender, mut receiver) = pair();
        let p = Pulse::zeroed();
        let env: Vec<u8> = (0..256).map(|i| (i & 0xFF) as u8).collect();

        let tx: &mut dyn PulseSender = &mut sender;
        tx.send(&p, &env).unwrap();

        let rx: &mut dyn PulseReceiver = &mut receiver;
        let mut buf = vec![0u8; 1024];
        let (_, n) = rx.recv_into(&mut buf).unwrap();
        assert_eq!(n, 256);
        assert_eq!(&buf[..n], env.as_slice());
    }

    #[test]
    fn buffer_too_small_returns_error() {
        let (mut sender, mut receiver) = pair();
        let p = Pulse::zeroed();
        let env: Vec<u8> = vec![0xAA; 512];

        let tx: &mut dyn PulseSender = &mut sender;
        tx.send(&p, &env).unwrap();

        let rx: &mut dyn PulseReceiver = &mut receiver;
        let mut tiny = [0u8; 64];
        match rx.recv_into(&mut tiny) {
            Err(TransportError::BufferTooSmall { needed, provided }) => {
                assert_eq!(needed, 512);
                assert_eq!(provided, 64);
            }
            other => panic!("expected BufferTooSmall, got {other:?}"),
        }
    }

    #[test]
    fn envelope_too_large_returns_error() {
        let mut sender = Sender::bind("127.0.0.1:0").unwrap();
        sender.connect("127.0.0.1:9").unwrap();
        let p = Pulse::zeroed();
        let too_big = vec![0u8; Sender::max_envelope() + 1];
        let tx: &mut dyn PulseSender = &mut sender;
        match tx.send(&p, &too_big) {
            Err(TransportError::EnvelopeTooLarge { len, max }) => {
                assert_eq!(len, Sender::max_envelope() + 1);
                assert_eq!(max, Sender::max_envelope());
            }
            other => panic!("expected EnvelopeTooLarge, got {other:?}"),
        }
    }

    #[test]
    fn with_fec_on_the_trait_reports_and_enforces_the_lower_limit() {
        let mut sender = Sender::bind("127.0.0.1:0").unwrap();
        sender.connect("127.0.0.1:9").unwrap();
        sender.enable_fec(4);
        let too_big = vec![0u8; crate::FEC_MAX_ENVELOPE + 1];
        let tx: &mut dyn PulseSender = &mut sender;
        assert_eq!(tx.max_envelope(), crate::FEC_MAX_ENVELOPE);
        match tx.send(&Pulse::zeroed(), &too_big) {
            Err(TransportError::EnvelopeTooLarge { len, max }) => {
                assert_eq!((len, max), (too_big.len(), crate::FEC_MAX_ENVELOPE));
            }
            other => panic!("expected EnvelopeTooLarge, got {other:?}"),
        }
        sender.disable_fec();
        let tx: &mut dyn PulseSender = &mut sender;
        assert_eq!(tx.max_envelope(), Sender::max_envelope());
    }

    #[test]
    fn stalled_maps_to_send_not_to_a_timeout() {
        let e = TransportError::from(SenderError::Stalled {
            in_flight: 16,
            waited: Duration::from_millis(300),
        });
        assert!(
            matches!(&e, TransportError::Send(m) if m.contains("stalled")),
            "got {e:?}"
        );
        assert!(!e.is_timeout(), "a stall is not a graceful drain");
    }

    #[test]
    fn local_addrs_present_for_udp() {
        let (sender, receiver) = pair();
        let tx: &dyn PulseSender = &sender;
        let rx: &dyn PulseReceiver = &receiver;
        assert!(tx.local_addr().is_some());
        assert!(rx.local_addr().is_some());
    }
}
