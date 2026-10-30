// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! A signal ends no transport thread and fails no receive.
//!
//! On Linux a receive on a socket with a read timeout returns `EINTR`
//! whenever a signal handler runs on the waiting thread, even one installed
//! with `SA_RESTART` (`signal(7)`). The sender's feedback thread and a
//! caller's own receive both wait in such receives. The test installs a
//! no-op SIGUSR1 handler with `SA_RESTART` and signals each waiting thread
//! directly, found by name under `/proc/self/task`, since a signal sent to
//! the process lands on whichever thread the kernel picks. Everything runs
//! in one test, in a binary of its own, so no other test's threads are
//! signalled. Linux only: elsewhere the file is empty.

#[cfg(target_os = "linux")]
mod signals {
    use std::net::{SocketAddr, UdpSocket};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::thread;
    use std::time::{Duration, Instant};

    use pulse_canon::Pulse;
    use pulse_wire_udp::{encode_ack, BackpressureConfig, Receiver, Sender, MAX_ENVELOPE};

    /// The names the crate gives its feedback threads.
    const SENDER_FEEDBACK: &str = "pw-udp-ack-recv";
    const RECEIVER_FEEDBACK: &str = "pw-udp-ack-send";

    /// Signals the handler has taken.
    static HANDLED: AtomicUsize = AtomicUsize::new(0);

    extern "C" fn count_signal(_: libc::c_int) {
        HANDLED.fetch_add(1, Ordering::SeqCst);
    }

    /// Install `count_signal` for SIGUSR1 with `SA_RESTART`, the flag a program
    /// sets when it expects the calls a signal interrupts to be restarted.
    fn install_handler() {
        // SAFETY: an all-zero `sigaction` is a valid value of the C struct; the
        // fields that matter are set below.
        let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
        let handler: extern "C" fn(libc::c_int) = count_signal;
        action.sa_sigaction = handler as libc::sighandler_t;
        action.sa_flags = libc::SA_RESTART;
        // SAFETY: `action.sa_mask` is a valid, writable signal set.
        unsafe { libc::sigemptyset(&mut action.sa_mask) };
        // SAFETY: `action` is initialised, and the handler only increments an
        // atomic, which is async-signal-safe.
        let rc = unsafe { libc::sigaction(libc::SIGUSR1, &action, std::ptr::null_mut()) };
        assert_eq!(rc, 0, "sigaction: {}", std::io::Error::last_os_error());
    }

    /// The Linux thread ids of this process's threads named `name`.
    fn threads_named(name: &str) -> Vec<libc::pid_t> {
        let mut tids = Vec::new();
        for entry in std::fs::read_dir("/proc/self/task").unwrap() {
            let entry = entry.unwrap();
            let comm = std::fs::read_to_string(entry.path().join("comm")).unwrap_or_default();
            if comm.trim_end() == name {
                tids.push(entry.file_name().to_string_lossy().parse().unwrap());
            }
        }
        tids
    }

    /// The one thread named `name`, once it exists.
    fn the_thread_named(name: &str) -> libc::pid_t {
        let started = Instant::now();
        loop {
            match threads_named(name).as_slice() {
                [tid] => return *tid,
                [] if started.elapsed() < Duration::from_secs(2) => {
                    thread::sleep(Duration::from_millis(5));
                }
                other => panic!("threads named {name}: {other:?}"),
            }
        }
    }

    fn wait_for(mut cond: impl FnMut() -> bool) -> bool {
        let started = Instant::now();
        while started.elapsed() < Duration::from_secs(2) {
            if cond() {
                return true;
            }
            thread::sleep(Duration::from_millis(5));
        }
        cond()
    }

    /// Signal thread `tid` five times, 30 ms apart, so that the signals land
    /// while it waits in a call, and check the handler ran for each. A thread
    /// that ends on a signal fails the next one with `ESRCH`.
    fn interrupt(tid: libc::pid_t) {
        let before = HANDLED.load(Ordering::SeqCst);
        for signal in 0..5 {
            // SAFETY: tgkill with this process's id, one of its thread ids and a
            // signal whose handler is installed touches no memory of ours.
            let rc = unsafe { libc::syscall(libc::SYS_tgkill, libc::getpid(), tid, libc::SIGUSR1) };
            let error = std::io::Error::last_os_error();
            if rc != 0 && error.raw_os_error() == Some(libc::ESRCH) {
                panic!("thread {tid} ended after {signal} signal(s)");
            }
            assert_eq!(rc, 0, "tgkill: {error}");
            thread::sleep(Duration::from_millis(30));
        }
        assert!(
            wait_for(|| HANDLED.load(Ordering::SeqCst) >= before + 5),
            "the handler did not run for every signal"
        );
    }

    fn inject_ack(feedback: SocketAddr, cursor: u64) {
        let injector = UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut ack = Vec::new();
        encode_ack(cursor, &mut ack);
        injector.send_to(&ack, feedback).unwrap();
    }

    /// The sender's feedback thread outlives the signals: an ACK injected after
    /// them is seen, and the sends it admits go out without a stall.
    fn the_senders_feedback_thread_outlives_signals() {
        let sink = UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut sender = Sender::bind("127.0.0.1:0").unwrap();
        sender.connect(sink.local_addr().unwrap()).unwrap();
        let any: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let mut cfg =
            BackpressureConfig::new(any, any).with_stall_timeout(Some(Duration::from_millis(300)));
        cfg.target_queue_depth = 4;
        sender.enable_backpressure(cfg).unwrap();
        let feedback = sender.ack_local_addr().unwrap();

        // Four frames fill the window; nothing acknowledges them yet.
        for seq in 0..4u64 {
            assert_eq!(sender.send(0, &Pulse::zeroed(), &[]).unwrap(), seq);
        }
        let tid = the_thread_named(SENDER_FEEDBACK);
        interrupt(tid);
        assert_eq!(
            threads_named(SENDER_FEEDBACK),
            vec![tid],
            "the sender's feedback thread ended"
        );

        inject_ack(feedback, 4);
        assert!(
            wait_for(|| sender.observed_recv_cursor() == 4),
            "the ACK sent after the signals was never seen"
        );
        for seq in 4..8u64 {
            let sent = sender
                .send(0, &Pulse::zeroed(), &[])
                .unwrap_or_else(|e| panic!("send {seq} after the signals failed: {e}"));
            assert_eq!(sent, seq);
        }
        assert_eq!(
            sender.feedback_error_count(),
            0,
            "an interrupted receive is not an error"
        );
    }

    /// A receive a signal interrupts waits again, for `recv` and for the batch
    /// receive, and the receiver's feedback thread outlives the signals too.
    fn a_receive_and_the_receivers_feedback_thread_outlive_signals() {
        let mut receiver = Receiver::bind("127.0.0.1:0").unwrap();
        receiver
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let recv_addr = receiver.local_addr().unwrap();
        let mut sender = Sender::bind("127.0.0.1:0").unwrap();
        sender.connect(recv_addr).unwrap();
        let any: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let mut cfg =
            BackpressureConfig::new(any, any).with_stall_timeout(Some(Duration::from_secs(1)));
        cfg.target_queue_depth = 64;
        sender.enable_backpressure(cfg.clone()).unwrap();
        cfg.ack_target_addr = sender.ack_local_addr().unwrap();
        receiver.enable_backpressure(cfg).unwrap();
        interrupt(the_thread_named(RECEIVER_FEEDBACK));

        // `recv`, signalled while it waits for the first frame.
        let waiting = thread::Builder::new()
            .name("eintr-recv".into())
            .spawn(move || {
                let result = receiver.recv().map(|(_, _, meta)| meta.seq);
                (receiver, result)
            })
            .unwrap();
        interrupt(the_thread_named("eintr-recv"));
        sender
            .send(0, &Pulse::zeroed(), b"after the signals")
            .unwrap();
        let (mut receiver, result) = waiting.join().unwrap();
        assert_eq!(
            result.unwrap_or_else(|e| panic!("recv failed after the signals: {e}")),
            0
        );

        // The batch receive, signalled while it waits for the next frames.
        let waiting = thread::Builder::new()
            .name("eintr-batch".into())
            .spawn(move || {
                let mut slots = vec![vec![0u8; MAX_ENVELOPE]; 4];
                let result = {
                    let mut refs: Vec<&mut [u8]> =
                        slots.iter_mut().map(|s| s.as_mut_slice()).collect();
                    receiver
                        .recv_batch_into(4, &mut refs)
                        .map(|batch| batch.frames.len())
                };
                (receiver, result)
            })
            .unwrap();
        interrupt(the_thread_named("eintr-batch"));
        sender
            .send(0, &Pulse::zeroed(), b"after the signals")
            .unwrap();
        let (receiver, result) = waiting.join().unwrap();
        let frames =
            result.unwrap_or_else(|e| panic!("batch receive failed after the signals: {e}"));
        assert!(frames >= 1, "the batch receive returned no frame");

        // The receiver's feedback thread still acknowledges what it took.
        assert_eq!(threads_named(RECEIVER_FEEDBACK).len(), 1);
        assert!(
            wait_for(|| sender.observed_recv_cursor() == 2),
            "the receiver's ACKs stopped: the sender sees cursor {}",
            sender.observed_recv_cursor()
        );
        assert_eq!(receiver.feedback_error_count(), 0);
    }

    #[test]
    fn a_signal_ends_no_transport_thread_and_fails_no_receive() {
        install_handler();
        the_senders_feedback_thread_outlives_signals();
        a_receive_and_the_receivers_feedback_thread_outlive_signals();
    }
}
