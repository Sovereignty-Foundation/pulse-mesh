// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! Interrupted calls and counted errors, shared by the send, receive and
//! feedback paths.
//!
//! An interrupted call is never an error here. Linux does not restart a
//! socket receive that has a timeout, even under `SA_RESTART` (`signal(7)`),
//! and every receive here may have one: the feedback threads set one to wake
//! and check their stop flag, and a caller may set one on the data socket.
//! A caller's blocking call goes through [`retry_interrupted`]; a feedback
//! thread takes an interrupted call as one more pass round its loop, which
//! checks the stop flag first.

use std::io;
use std::sync::atomic::{AtomicU64, Ordering};

/// Make `call` again for as long as a signal interrupts it, and return the
/// first result that is not `Interrupted`.
pub(crate) fn retry_interrupted<T>(mut call: impl FnMut() -> io::Result<T>) -> io::Result<T> {
    loop {
        match call() {
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            result => return result,
        }
    }
}

/// Whether a feedback thread's receive failed only in a way that means
/// "try again": its read timeout passed (`WouldBlock` on Unix, `TimedOut` on
/// Windows), or a signal interrupted it.
pub(crate) fn is_retry(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::Interrupted
    )
}

/// Count one error in `errors`, and return the new total when it is one to
/// log: the first and each doubling after (1, 2, 4, ...), with no clock.
pub(crate) fn count_error(errors: &AtomicU64) -> Option<u64> {
    let n = errors.fetch_add(1, Ordering::Relaxed).wrapping_add(1);
    n.is_power_of_two().then_some(n)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn an_interrupted_call_is_made_again() {
        let mut calls = 0;
        let result = retry_interrupted(|| {
            calls += 1;
            if calls < 4 {
                Err(io::Error::from(io::ErrorKind::Interrupted))
            } else {
                Ok(calls)
            }
        });
        assert_eq!(result.unwrap(), 4);
    }

    #[test]
    fn any_other_error_is_returned_at_once() {
        let mut calls = 0;
        let result: io::Result<()> = retry_interrupted(|| {
            calls += 1;
            Err(io::Error::from(io::ErrorKind::ConnectionRefused))
        });
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::ConnectionRefused);
        assert_eq!(calls, 1);
    }

    #[test]
    fn only_a_timeout_or_an_interruption_means_try_again() {
        for kind in [
            io::ErrorKind::WouldBlock,
            io::ErrorKind::TimedOut,
            io::ErrorKind::Interrupted,
        ] {
            assert!(is_retry(&io::Error::from(kind)), "{kind:?}");
        }
        for kind in [
            io::ErrorKind::ConnectionRefused,
            io::ErrorKind::OutOfMemory,
            io::ErrorKind::Other,
        ] {
            assert!(!is_retry(&io::Error::from(kind)), "{kind:?}");
        }
    }

    #[test]
    fn errors_are_logged_at_the_first_and_each_doubling() {
        let errors = AtomicU64::new(0);
        let logged: Vec<u64> = (0..100).filter_map(|_| count_error(&errors)).collect();
        assert_eq!(logged, vec![1, 2, 4, 8, 16, 32, 64]);
        assert_eq!(errors.load(Ordering::Relaxed), 100);
    }
}
