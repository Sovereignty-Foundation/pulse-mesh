// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//
// Fuzz target: what the UDP receiver does with each datagram its data
// socket reads, `receiver::DataIntake`, the socket-free core that
// `Receiver` hands every datagram and takes its frames from: the data-peer
// filter, the dispatch on the first four bytes, the decode of a data frame
// or a fragment, the FEC decoder with the frames it rebuilds and holds for
// delivery, the reassembly of runs of fragments, and the stream tracking
// that every frame and fragment feeds.
//
// The input describes a receiver (a data peer or none; FEC with its window
// K and table size, or not; backpressure tracking with its recovery window
// and NACK, or not; reassembly with its bounds, or not) and a sender's run:
// frames with consecutive sequence numbers from a base, each with its own
// Pulse, send time and envelope, encoded by the sender's encoder
// (`wire::encode`), with, when the sender has fragmentation on, runs of
// fragments (`fragment::encode_fragments`) for envelopes longer than a
// frame carries among them, and, when the sender has FEC on, usually with
// the receiver's K, the parity its `FecEncoder` emits. The target keeps
// its own record of what was sent. The network then delivers, from sources
// the input picks (the peer, another address, the peer's IPv4-mapped form,
// its IPv4-compatible form, any port): the run's frames, fragments and
// parity in any order and any number of times, cut short or with a bit
// flipped or bytes appended; forged frames, fragments, runs and parity;
// and raw bytes. The receiver takes held frames now and then, as its
// receive calls do. Every datagram is first cut to the socket's one-MTU
// buffer, as the kernel cuts it.
//
// The target judges each datagram by the specification: the fuzz crate's
// `udp` module reads data frames (section 6.1, with its own CRC32C),
// parity (section 6.3) and fragments without calling the transport.
//
// Invariants:
// - a datagram from a source the filter does not admit yields `Foreign` and
//   changes nothing but the rejection count, and not even later: a second
//   intake without the filter, given only the admitted datagrams, yields the
//   same for each of them and holds the same frames in the same order;
// - an admitted datagram is a data frame exactly when the specification's
//   framing accepts it, and then yields that frame: its sequence number,
//   send time, Pulse and envelope, with the datagram's peer; for a frame of
//   the run as sent, that is what the sender encoded for its sequence
//   number, from the target's own record;
// - an admitted datagram is consumed as a fragment exactly when the
//   fragment layout accepts it; it is tracked and fed to FEC as a data
//   frame is, and goes to the reassembly, or with reassembly off is
//   dropped and counted;
// - parity is taken when FEC is on and dropped unread when it is off;
//   parity whose layout the specification refuses is counted undecodable;
//   anything else is refused; a datagram refused or dropped changes
//   nothing else;
// - one datagram rebuilds at most once: it holds one rebuilt frame and
//   counts it as recovered, or passes one rebuilt fragment to the
//   reassembly and counts it, or counts one rebuild undecodable; a
//   fragment rebuilt in a window that no forged datagram reached lies in
//   that window, is not the datagram that completed it, and is one the
//   sender sent;
// - the frames held are those rebuilt and the runs completed, a frame the
//   datagram rebuilt before the run its own fragment completed, and they
//   come out oldest first; a frame rebuilt in a window that no forged
//   datagram reached lies in that window, is not the frame that completed
//   it, and is the original the sender sent under its sequence number,
//   field for field, from the peer whose datagram completed the window; a
//   run completed is delivered under its first sequence number, from the
//   peer whose datagram completed it, and when no forged fragment named it
//   is the Pulse, send time and envelope the sender sent;
// - the stream tracking sees exactly the sequence numbers of the data
//   frames yielded, of the fragments taken or rebuilt, and of the rebuilt
//   frames delivered, in that order, and nothing for a run delivered: it
//   matches a tracker the target feeds with them;
// - nothing grows without bound: the FEC table stays within its size, the
//   runs in progress and the bytes they reserve within the reassembly's
//   bounds, and held frames within twice the datagrams dispatched since
//   they were last taken;
// - whatever came before, forged traffic included, fresh frames from the
//   peer are yielded, one from any other source is dropped when a filter is
//   set, a fresh FEC window that loses one frame has it rebuilt, held and
//   delivered, and with reassembly on a fresh run from the peer completes
//   and is delivered as sent.

#![no_main]

use std::collections::{BTreeMap, HashSet, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use libfuzzer_sys::arbitrary::{Result, Unstructured};
use libfuzzer_sys::fuzz_target;
use pulse_canon::Pulse;
use pulse_mesh_fuzz::{take, udp};
use pulse_wire_udp::backpressure::StreamTracker;
use pulse_wire_udp::fec::{encode_fec, FecEncoder, FecHeader};
use pulse_wire_udp::fragment::encode_fragments;
use pulse_wire_udp::receiver::{DataIntake, Dispatched, PendingRecovered};
use pulse_wire_udp::{
    wire, BackpressureConfig, ReassemblyConfig, ReceiverError, FEC_MAX_ENVELOPE, MAX_ENVELOPE,
    MTU_BYTES,
};

/// Most frames in the sender's run.
const MAX_FRAMES: usize = 96;
/// Most steps in one input.
const MAX_STEPS: usize = 384;
/// Largest FEC window drawn.
const MAX_K: u16 = 16;
/// Most windows the FEC decoder is configured to track.
const MAX_WINDOWS: usize = 16;
/// Largest recovery window the tracking is configured with.
const MAX_RECOVERY_WINDOW: usize = 64;
/// Longest forged payload or raw datagram.
const MAX_FORGED: usize = MTU_BYTES + 64;
/// The longest datagram a sender with FEC on sends, so that its parity
/// fits the receiver's buffer: its fragments are this long.
const FEC_DATAGRAM: usize = MTU_BYTES - (MAX_ENVELOPE - FEC_MAX_ENVELOPE);
/// Longest envelope sent as a run of fragments.
const MAX_RUN_ENVELOPE: usize = 8 * MAX_ENVELOPE;
/// Most runs in progress the reassembly is configured to keep.
const MAX_RUNS: usize = 8;
/// The probe's run's envelope: two fragments, whether FEC is on or off.
const PROBE_RUN: usize = MAX_ENVELOPE + 1;
/// How long a run may stay incomplete: longer than any input takes, so the
/// clock decides nothing.
const RUN_TIMEOUT: Duration = Duration::from_secs(3600);

/// The sources a datagram comes from.
const PEERS: [IpAddr; 5] = [
    IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
    IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3)),
    IpAddr::V6(Ipv6Addr::LOCALHOST),
    // 127.0.0.1 in its IPv4-mapped IPv6 form: the same source as the first.
    IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0x7f00, 0x0001)),
    // 127.0.0.1 in the deprecated IPv4-compatible form: another source.
    IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0x7f00, 0x0001)),
];

/// A frame as the sender sent it.
struct Sent {
    pulse: [u8; 128],
    send_ns: u64,
    envelope: Vec<u8>,
    encoded: Vec<u8>,
}

/// A run of fragments as the sender sent it.
struct SentRun {
    pulse: [u8; 128],
    send_ns: u64,
    envelope: Vec<u8>,
}

/// What the target knows of a held frame.
enum Held {
    /// A frame rebuilt from parity: where the datagram that completed its
    /// window came from, and what it was.
    Rebuilt {
        /// The window the datagram reached.
        window: u64,
        /// The datagram's source.
        peer: SocketAddr,
        /// The datagram's own sequence number, for a data frame or a
        /// fragment.
        own: Option<u64>,
    },
    /// A run reassembled, completed by a datagram from `peer`.
    Run { peer: SocketAddr },
}

/// What the specification makes of a datagram.
enum Expect {
    /// Not a frame or parity the receiver can take.
    Refused,
    /// A data frame.
    Frame(udp::Frame),
    /// A fragment.
    Fragment(udp::FragmentSpec),
    /// Parity, with FEC on.
    Parity(udp::Parity),
    /// Something that starts like parity, with FEC on, and is not parity.
    BadParity,
    /// Parity or not, with FEC off.
    IgnoredParity,
}

/// One intake and the tracking it feeds.
struct Side {
    intake: DataIntake,
    tracker: Option<Arc<StreamTracker>>,
}

/// What the intake shows of itself, but for its rejection count, and of the
/// tracking it feeds.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Snapshot {
    parity_received: u64,
    recovered: u64,
    undecodable: u64,
    held: usize,
    fec: Option<(usize, u64, u64)>,
    tracking: Option<Tracking>,
    fragments_dropped: u64,
    rebuilt_fragments: u64,
    last_rebuilt_fragment: Option<u64>,
    /// Runs in progress, bytes reserved, runs completed and dropped.
    reassembly: Option<(usize, usize, u64, u64)>,
}

/// The tracking's cursor, head, out-of-order and staged sets and counts.
type Tracking = (u64, u64, Vec<u64>, Vec<u64>, u64, u64, u64);

fn tracking(t: &StreamTracker) -> Tracking {
    (
        t.recv_cursor(),
        t.contiguous_head(),
        t.out_of_order(),
        t.staged(),
        t.beyond_horizon_count(),
        t.gap_resyncs(),
        t.nack_drop_count(),
    )
}

impl Side {
    fn new(
        filter: Option<IpAddr>,
        fec: Option<(u16, usize)>,
        bp: Option<&BackpressureConfig>,
        reassembly: Option<&ReassemblyConfig>,
    ) -> Self {
        let mut intake = DataIntake::default();
        if let Some(peer) = filter {
            intake.set_data_peer(peer);
        }
        if let Some((k, windows)) = fec {
            intake.enable_fec(k, windows);
        }
        if let Some(cfg) = reassembly {
            intake.enable_reassembly(cfg.clone());
        }
        let tracker = bp.map(|cfg| Arc::new(StreamTracker::new(cfg)));
        if let Some(t) = &tracker {
            intake.set_tracker(Arc::clone(t));
        }
        Self { intake, tracker }
    }

    fn snapshot(&self) -> Snapshot {
        Snapshot {
            parity_received: self.intake.parity_received_count(),
            recovered: self.intake.fec_recovered_count(),
            undecodable: self.intake.parity_undecodable_count(),
            held: self.intake.held_count(),
            fec: self
                .intake
                .fec_decoder()
                .map(|d| (d.active_windows(), d.refused_count(), d.evicted_count())),
            tracking: self.tracker.as_deref().map(tracking),
            fragments_dropped: self.intake.fragments_dropped_count(),
            rebuilt_fragments: self.intake.fec_rebuilt_fragment_count(),
            last_rebuilt_fragment: self.intake.last_rebuilt_fragment(),
            reassembly: self.intake.reassembler().map(|r| {
                (
                    r.in_progress(),
                    r.reserved_bytes(),
                    r.completed_count(),
                    r.dropped_count(),
                )
            }),
        }
    }
}

/// The receiver under test, the filterless one beside it, and the target's
/// model of both.
struct Rx {
    main: Side,
    shadow: Side,
    /// A tracker the target feeds with the frames it expects to be tracked.
    reference: Option<StreamTracker>,
    filter: Option<IpAddr>,
    /// The receiver's FEC window and table size, when FEC is on.
    fec: Option<(u16, usize)>,
    /// The receiver's reassembly bounds, when reassembly is on.
    reassembly: Option<ReassemblyConfig>,
    /// Every frame the sender sent, by sequence number.
    sent: BTreeMap<u64, Sent>,
    /// Every run of fragments the sender sent, by first sequence number.
    runs: BTreeMap<u64, SentRun>,
    /// The sequence numbers of the fragments the sender sent.
    fragments: HashSet<u64>,
    /// Windows a forged datagram reached.
    forged: HashSet<u64>,
    /// Runs a forged fragment named, by first sequence number.
    forged_runs: HashSet<u64>,
    /// A fragment was rebuilt in a window a forged datagram reached: it
    /// can name any run.
    forged_rebuild: bool,
    /// What the target knows of the held frames, oldest first.
    held: VecDeque<Held>,
}

impl Rx {
    fn k(&self) -> Option<u64> {
        self.fec.map(|(k, _)| u64::from(k))
    }

    fn admits(&self, from: SocketAddr) -> bool {
        self.filter
            .is_none_or(|peer| udp::source(peer) == udp::source(from.ip()))
    }

    /// Take one datagram as it left its sender, from `from`. `genuine` says
    /// whether it is one of the sender's datagrams, as sent.
    fn datagram(&mut self, sent: &[u8], from: SocketAddr, genuine: bool) {
        // The socket's buffer holds one MTU; the rest of a longer datagram
        // is lost in the kernel.
        let bytes = &sent[..sent.len().min(MTU_BYTES)];
        let before = self.main.snapshot();
        let rejected = self.main.intake.data_rejected_count();
        let result = self.main.intake.dispatch(bytes, from);
        if !self.admits(from) {
            assert!(
                matches!(result, Ok(Dispatched::Foreign)),
                "a datagram from a filtered source was not dropped as foreign"
            );
            assert_eq!(
                self.main.intake.data_rejected_count(),
                rejected + 1,
                "a datagram from a filtered source went uncounted"
            );
            assert_eq!(
                self.main.snapshot(),
                before,
                "a datagram from a filtered source changed something"
            );
            return;
        }
        assert_eq!(
            self.main.intake.data_rejected_count(),
            rejected,
            "an admitted datagram was counted as rejected"
        );
        let shadow = self.shadow.intake.dispatch(bytes, from);
        assert_same(&result, &shadow, bytes);

        let fec_on = self.fec.is_some();
        let expect = match bytes.get(..4) {
            Some(m) if m == udp::FRAME_MAGIC => {
                udp::parse_frame(bytes).map_or(Expect::Refused, Expect::Frame)
            }
            Some(m) if m == udp::FRAGMENT_MAGIC => {
                udp::parse_fragment(bytes).map_or(Expect::Refused, Expect::Fragment)
            }
            Some(m) if m == udp::PARITY_MAGIC && !fec_on => Expect::IgnoredParity,
            Some(m) if m == udp::PARITY_MAGIC => {
                udp::parse_parity(bytes).map_or(Expect::BadParity, Expect::Parity)
            }
            _ => Expect::Refused,
        };
        let mut reached = None;
        match &expect {
            Expect::Refused => {
                assert!(
                    result.is_err(),
                    "a datagram the specification refuses was taken: {bytes:02x?}"
                );
            }
            Expect::Frame(frame) => {
                let Ok(Dispatched::Data {
                    pulse,
                    env_offset,
                    env_len,
                    meta,
                }) = &result
                else {
                    panic!("a data frame the specification accepts was not taken: {result:?}");
                };
                assert_eq!(pulse.as_bytes(), &frame.pulse, "the Pulse differs");
                assert_eq!(
                    bytes.get(*env_offset..env_offset + env_len),
                    Some(frame.envelope.as_slice()),
                    "the envelope differs"
                );
                assert_eq!(
                    (meta.seq, meta.send_ns, meta.peer),
                    (frame.seq, frame.send_ns, from),
                    "the frame's metadata differs"
                );
                if genuine {
                    let original = self
                        .sent
                        .get(&frame.seq)
                        .expect("the sender sent every genuine frame");
                    assert_eq!(
                        (&frame.pulse, frame.send_ns, &frame.envelope),
                        (&original.pulse, original.send_ns, &original.envelope),
                        "the frame yielded for seq {} is not the one the sender encoded",
                        frame.seq
                    );
                }
                if let Some(reference) = &self.reference {
                    reference.arrived(frame.seq);
                }
                reached = self.k().map(|k| (frame.seq / k * k, Some(frame.seq)));
            }
            Expect::Fragment(fragment) => {
                assert!(
                    matches!(result, Ok(Dispatched::FragmentConsumed)),
                    "a fragment the specification accepts was not consumed: {result:?}"
                );
                if genuine {
                    assert!(
                        self.fragments.contains(&fragment.seq),
                        "a genuine fragment the sender did not send"
                    );
                } else {
                    self.forged_runs.insert(fragment.first_seq);
                }
                if let Some(reference) = &self.reference {
                    reference.arrived(fragment.seq);
                }
                reached = self.k().map(|k| (fragment.seq / k * k, Some(fragment.seq)));
            }
            Expect::Parity(parity) => {
                assert!(
                    matches!(result, Ok(Dispatched::ParityConsumed)),
                    "parity was not consumed: {result:?}"
                );
                reached = Some((parity.window_start, None));
            }
            Expect::BadParity | Expect::IgnoredParity => {
                assert!(
                    matches!(result, Ok(Dispatched::ParityConsumed)),
                    "a datagram with the parity magic was not consumed: {result:?}"
                );
            }
        }
        if !genuine {
            if let Some((window, _)) = reached {
                self.forged.insert(window);
            }
        }

        let after = self.main.snapshot();
        self.check_rebuilt_fragment(&before, &after, reached);
        let mut expected = before.clone();
        match &expect {
            Expect::Refused | Expect::IgnoredParity => {}
            Expect::BadParity => expected.undecodable += 1,
            Expect::Frame(_) | Expect::Parity(_) | Expect::Fragment(_) => {
                if matches!(expect, Expect::Parity(_)) {
                    expected.parity_received += 1;
                }
                expected.tracking = self.reference.as_ref().map(tracking);
                if fec_on || matches!(expect, Expect::Fragment(_)) {
                    // What the FEC decoder and the reassembly did with it
                    // is checked below.
                    expected.recovered = after.recovered;
                    expected.undecodable = after.undecodable;
                    expected.held = after.held;
                    expected.fec = after.fec;
                    expected.fragments_dropped = after.fragments_dropped;
                    expected.rebuilt_fragments = after.rebuilt_fragments;
                    expected.last_rebuilt_fragment = after.last_rebuilt_fragment;
                    expected.reassembly = after.reassembly;
                }
            }
        }
        assert_eq!(
            after, expected,
            "the datagram changed what it cannot change"
        );
        self.check_held(&before, &after, &expect, from, reached);
        self.check_fec(&before, &after, &expect);
        assert_eq!(
            self.shadow.snapshot(),
            after,
            "the intake without the filter differs"
        );
    }

    /// A fragment the datagram rebuilt reached the stream tracking, and, in
    /// a window no forged datagram reached, is one the sender sent, in that
    /// window, other than the datagram itself.
    fn check_rebuilt_fragment(
        &mut self,
        before: &Snapshot,
        after: &Snapshot,
        reached: Option<(u64, Option<u64>)>,
    ) {
        let rebuilt = after
            .rebuilt_fragments
            .checked_sub(before.rebuilt_fragments)
            .expect("the rebuilt fragment count went down");
        if rebuilt == 0 {
            return;
        }
        assert_eq!(rebuilt, 1, "one datagram rebuilt {rebuilt} fragments");
        let (window, own) =
            reached.expect("a fragment rebuilt by a datagram that reached no window");
        let seq = after
            .last_rebuilt_fragment
            .expect("a fragment rebuilt and not recorded");
        if let Some(reference) = &self.reference {
            reference.arrived(seq);
        }
        if self.forged.contains(&window) {
            self.forged_rebuild = true;
            return;
        }
        let k = self.k().expect("a fragment rebuilt with FEC off");
        assert!(
            seq.checked_sub(window).is_some_and(|o| o < k),
            "fragment {seq} was rebuilt outside the window at {window}"
        );
        assert_ne!(
            Some(seq),
            own,
            "rebuilt the datagram that completed the window"
        );
        assert!(
            self.fragments.contains(&seq),
            "rebuilt fragment {seq}, which the sender did not send"
        );
    }

    /// What one datagram held, and what the reassembly did with it.
    fn check_held(
        &mut self,
        before: &Snapshot,
        after: &Snapshot,
        expect: &Expect,
        from: SocketAddr,
        reached: Option<(u64, Option<u64>)>,
    ) {
        let held = after
            .held
            .checked_sub(before.held)
            .expect("a datagram took a held frame away") as u64;
        let recovered = after
            .recovered
            .checked_sub(before.recovered)
            .expect("the recovered count went down");
        let undecodable = after
            .undecodable
            .checked_sub(before.undecodable)
            .expect("the undecodable count went down");
        let rebuilt = after.rebuilt_fragments - before.rebuilt_fragments;
        let dropped = after
            .fragments_dropped
            .checked_sub(before.fragments_dropped)
            .expect("the dropped fragment count went down");
        let own = u64::from(matches!(expect, Expect::Fragment(_)));
        let completed = match (before.reassembly, after.reassembly, &self.reassembly) {
            (Some(was), Some(now), Some(cfg)) => {
                assert_eq!(dropped, 0, "a fragment was dropped with reassembly on");
                assert!(
                    now.0 <= cfg.max_messages,
                    "{} runs in progress, configured for {}",
                    now.0,
                    cfg.max_messages
                );
                assert!(
                    now.1 <= cfg.max_bytes,
                    "{} bytes reserved, configured for {}",
                    now.1,
                    cfg.max_bytes
                );
                assert!(now.3 >= was.3, "the dropped run count went down");
                now.2
                    .checked_sub(was.2)
                    .expect("the completed run count went down")
            }
            (None, None, None) => {
                assert_eq!(
                    dropped,
                    own + rebuilt,
                    "with reassembly off, a fragment was not dropped and counted"
                );
                0
            }
            _ => panic!("reassembly turned itself on or off"),
        };
        assert!(
            completed <= own + rebuilt,
            "{completed} runs completed by {} fragments",
            own + rebuilt
        );
        assert!(
            recovered + rebuilt + undecodable <= 1,
            "one datagram rebuilt more than once"
        );
        assert_eq!(
            held,
            recovered + completed,
            "held frames, the recovered count and the runs completed differ"
        );
        // A frame the datagram rebuilt is held before the run its own
        // fragment completed.
        if recovered == 1 {
            let (window, own) =
                reached.expect("a frame held from a datagram that reached no window");
            self.held.push_back(Held::Rebuilt {
                window,
                peer: from,
                own,
            });
        }
        for _ in 0..completed {
            self.held.push_back(Held::Run { peer: from });
        }
    }

    /// What the FEC decoder did with one datagram.
    fn check_fec(&mut self, before: &Snapshot, after: &Snapshot, expect: &Expect) {
        let (Some((k, windows)), Some(fec)) = (self.fec, after.fec) else {
            return;
        };
        assert!(
            fec.0 <= windows.max(1),
            "the decoder tracks {} windows, configured for {windows}",
            fec.0
        );
        let (refused_before, evicted_before) = before.fec.map_or((0, 0), |f| (f.1, f.2));
        let refused = fec
            .1
            .checked_sub(refused_before)
            .expect("the refusal count went down");
        assert!(fec.2 >= evicted_before, "the eviction count went down");
        match expect {
            Expect::Parity(parity) => {
                assert!(refused <= 1, "one parity datagram refused twice");
                let misfit =
                    parity.window_n != k || !parity.window_start.is_multiple_of(u64::from(k));
                if misfit {
                    assert_eq!(refused, 1, "parity that fits no window was not refused");
                    assert_eq!(
                        (
                            after.held - before.held,
                            after.undecodable - before.undecodable,
                            after.rebuilt_fragments - before.rebuilt_fragments,
                            Some(fec.0)
                        ),
                        (0, 0, 0, before.fec.map(|f| f.0)),
                        "refused parity changed the decoder"
                    );
                }
            }
            _ => assert_eq!(refused, 0, "a datagram that is not parity was refused"),
        }
    }

    /// Deliver the oldest held frame, as a receive call does; false when
    /// none is held.
    fn deliver_held(&mut self) -> bool {
        let main = self.main.intake.pop_recovered();
        let shadow = self.shadow.intake.pop_recovered();
        let info = self.held.pop_front();
        let (main, shadow, info) = match (main, shadow, info) {
            (None, None, None) => return false,
            (Some(main), Some(shadow), Some(info)) => (main, shadow, info),
            (main, shadow, info) => panic!(
                "held frames disagree: the intake {}, the one without the filter {}, the target {}",
                main.is_some(),
                shadow.is_some(),
                info.is_some()
            ),
        };
        assert!(
            same_frame(&main, &shadow),
            "the intake without the filter holds another frame"
        );
        let seq = main.meta.seq;
        match info {
            Held::Rebuilt { window, peer, own } => {
                assert!(!main.reassembled, "a rebuilt frame is held as a run");
                assert_eq!(main.meta.peer, peer, "the held frame names another peer");
                if let Some(k) = self.k().filter(|_| !self.forged.contains(&window)) {
                    assert!(
                        seq.checked_sub(window).is_some_and(|o| o < k),
                        "seq {seq} was rebuilt outside the window at {window}"
                    );
                    assert_ne!(
                        Some(seq),
                        own,
                        "rebuilt the frame that completed the window"
                    );
                    let original = self
                        .sent
                        .get(&seq)
                        .expect("a window no forged datagram reached holds only frames sent");
                    assert_eq!(
                        (main.pulse.as_bytes(), main.meta.send_ns, &main.envelope),
                        (&original.pulse, original.send_ns, &original.envelope),
                        "seq {seq} rebuilt differs from the original"
                    );
                }
            }
            Held::Run { peer } => {
                assert!(main.reassembled, "a run is held as a rebuilt frame");
                assert_eq!(main.meta.peer, peer, "the run names another peer");
                if !self.forged_rebuild && !self.forged_runs.contains(&seq) {
                    let run = self
                        .runs
                        .get(&seq)
                        .expect("a run no forged fragment named is one the sender sent");
                    assert_eq!(
                        (main.pulse.as_bytes(), main.meta.send_ns, &main.envelope),
                        (&run.pulse, run.send_ns, &run.envelope),
                        "the run at {seq} reassembled differs from the one sent"
                    );
                }
            }
        }
        self.main.intake.delivered(&main);
        self.shadow.intake.delivered(&shadow);
        if let Some(reference) = self.reference.as_ref().filter(|_| !main.reassembled) {
            reference.arrived(seq);
        }
        let expected = self.reference.as_ref().map(tracking);
        assert_eq!(
            self.main.tracker.as_deref().map(tracking),
            expected,
            "delivering a held frame fed the tracking otherwise"
        );
        assert_eq!(self.shadow.tracker.as_deref().map(tracking), expected);
        true
    }
}

/// The two intakes' answers to one datagram agree.
fn assert_same(
    main: &std::result::Result<Dispatched, ReceiverError>,
    shadow: &std::result::Result<Dispatched, ReceiverError>,
    bytes: &[u8],
) {
    let same = match (main, shadow) {
        (
            Ok(Dispatched::Data {
                pulse: a,
                env_offset: ao,
                env_len: al,
                meta: am,
            }),
            Ok(Dispatched::Data {
                pulse: b,
                env_offset: bo,
                env_len: bl,
                meta: bm,
            }),
        ) => {
            a.as_bytes() == b.as_bytes()
                && (ao, al) == (bo, bl)
                && (am.seq, am.send_ns, am.peer) == (bm.seq, bm.send_ns, bm.peer)
        }
        (Ok(Dispatched::ParityConsumed), Ok(Dispatched::ParityConsumed))
        | (Ok(Dispatched::FragmentConsumed), Ok(Dispatched::FragmentConsumed)) => true,
        (Err(a), Err(b)) => format!("{a:?}") == format!("{b:?}"),
        _ => false,
    };
    assert!(
        same,
        "the intake without the filter answered otherwise: {main:?} against {shadow:?} for {bytes:02x?}"
    );
}

fn same_frame(a: &PendingRecovered, b: &PendingRecovered) -> bool {
    a.pulse.as_bytes() == b.pulse.as_bytes()
        && (a.reassembled, a.span) == (b.reassembled, b.span)
        && a.envelope == b.envelope
        && (a.meta.seq, a.meta.send_ns, a.meta.peer) == (b.meta.seq, b.meta.send_ns, b.meta.peer)
}

fuzz_target!(|data: &[u8]| {
    let _ = fuzz(data);
});

fn fuzz(data: &[u8]) -> Result<()> {
    let mut u = Unstructured::new(data);
    let filter = if u.arbitrary()? {
        Some(PEERS[u.choose_index(PEERS.len())?])
    } else {
        None
    };
    let fec = if u.ratio(3, 4)? {
        Some((u.int_in_range(1..=MAX_K)?, u.int_in_range(0..=MAX_WINDOWS)?))
    } else {
        None
    };
    let bp = if u.arbitrary()? {
        let any: SocketAddr = (Ipv4Addr::LOCALHOST, 0).into();
        let mut cfg = BackpressureConfig::new(any, any);
        let window = u.int_in_range(0..=MAX_RECOVERY_WINDOW)?;
        if u.arbitrary()? {
            cfg = cfg.with_nack(window);
        } else {
            cfg.send_cache_capacity = window;
        }
        Some(cfg)
    } else {
        None
    };
    // The sender's FEC: usually the receiver's K, sometimes another, and
    // sometimes on while the receiver's is off, or off while it is on.
    let sender_k = match (fec, u.int_in_range(0..=7u8)?) {
        (_, 0) => None,
        (Some((k, _)), 1..=5) => Some(k),
        _ => Some(u.int_in_range(1..=MAX_K)?),
    };
    let reassembly = if u.ratio(3, 4)? {
        let mut cfg = ReassemblyConfig::default();
        cfg.max_messages = u.int_in_range(0..=MAX_RUNS)?;
        cfg.max_bytes = u.int_in_range(0..=2 * MAX_RUN_ENVELOPE)?;
        cfg.timeout = RUN_TIMEOUT;
        Some(cfg)
    } else {
        None
    };
    let fragmenting: bool = u.arbitrary()?;

    let mut rx = Rx {
        main: Side::new(filter, fec, bp.as_ref(), reassembly.as_ref()),
        shadow: Side::new(None, fec, bp.as_ref(), reassembly.as_ref()),
        reference: bp.as_ref().map(StreamTracker::new),
        filter,
        fec,
        reassembly,
        sent: BTreeMap::new(),
        runs: BTreeMap::new(),
        fragments: HashSet::new(),
        forged: HashSet::new(),
        forged_runs: HashSet::new(),
        forged_rebuild: false,
        held: VecDeque::new(),
    };

    // The sender's run.
    let frames = u.int_in_range(0..=MAX_FRAMES)?;
    let envelope_cap = if sender_k.is_some() {
        FEC_MAX_ENVELOPE
    } else {
        MAX_ENVELOPE
    };
    let top = u64::MAX - (frames as u64).saturating_sub(1);
    let mut base = u.arbitrary::<u64>()?.min(top);
    if let Some(k) = sender_k.map(u64::from) {
        if u.ratio(3, 4)? {
            base = base / k * k;
        }
    }
    let max_datagram = if sender_k.is_some() {
        FEC_DATAGRAM
    } else {
        MTU_BYTES
    };
    let mut encoder = sender_k.map(FecEncoder::new);
    let mut datagrams: Vec<Vec<u8>> = Vec::new();
    let mut parity: Vec<Vec<u8>> = Vec::new();
    let pulse_seed: u8 = u.arbitrary()?;
    while datagrams.len() < frames {
        let seq = base + datagrams.len() as u64;
        let send_ns = u.arbitrary()?;
        let pulse = pulse_bytes(pulse_seed, seq);
        // With fragmentation on, now and then an envelope longer than a
        // frame carries goes as a run, cut off where the sender's run ends.
        let sent = if fragmenting && u.ratio(1, 6)? {
            let len = u.int_in_range(envelope_cap + 1..=MAX_RUN_ENVELOPE)?;
            let envelope = pattern(len, u.arbitrary()?);
            let mut run = encode_fragments(
                seq,
                send_ns,
                &Pulse::from_array(&pulse),
                &envelope,
                max_datagram,
            )
            .expect("an envelope within MAX_MESSAGE fragments");
            run.truncate(frames - datagrams.len());
            rx.runs.insert(
                seq,
                SentRun {
                    pulse,
                    send_ns,
                    envelope,
                },
            );
            for i in 0..run.len() {
                rx.fragments.insert(seq + i as u64);
            }
            run
        } else {
            let envelope = body(&mut u, envelope_cap)?;
            let sent = send(seq, send_ns, pulse, envelope);
            let encoded = sent.encoded.clone();
            rx.sent.insert(seq, sent);
            vec![encoded]
        };
        for datagram in sent {
            let seq = base + datagrams.len() as u64;
            if let Some(parity_datagram) = encoder
                .as_mut()
                .and_then(|e| e.add_original(seq, &datagram))
            {
                parity.push(parity_datagram);
            }
            datagrams.push(datagram);
        }
    }
    let run_end = base.checked_add(frames as u64);

    for _ in 0..MAX_STEPS {
        if u.is_empty() {
            break;
        }
        let from = source(&mut u, filter)?;
        match u.int_in_range(0..=10u8)? {
            // A frame or fragment of the run, as sent: again and again, in
            // any order.
            0..=2 if !datagrams.is_empty() => {
                let i = u.choose_index(datagrams.len())?;
                let bytes = datagrams[i].clone();
                rx.datagram(&bytes, from, true);
            }
            // A parity datagram of the run, as sent.
            3 if !parity.is_empty() => {
                let bytes = parity[u.choose_index(parity.len())?].clone();
                rx.datagram(&bytes, from, true);
            }
            // A datagram of the run cut short, or with a bit flipped, or
            // with bytes after it.
            4 | 5 if !datagrams.is_empty() || !parity.is_empty() => {
                let all = datagrams.len() + parity.len();
                let i = u.choose_index(all)?;
                let mut bytes = if i < datagrams.len() {
                    datagrams[i].clone()
                } else {
                    parity[i - datagrams.len()].clone()
                };
                match u.int_in_range(0..=2u8)? {
                    0 => bytes.truncate(u.int_in_range(0..=bytes.len())?),
                    1 if !bytes.is_empty() => {
                        let at = u.choose_index(bytes.len())?;
                        bytes[at] ^= 1 << u.int_in_range(0..=7u8)?;
                    }
                    _ => bytes.extend_from_slice(take(&mut u, 32)?),
                }
                rx.datagram(&bytes, from, false);
            }
            // A forged data frame under any sequence number.
            6 => {
                let seq = seq_near(&mut u, base, frames, rx.k())?;
                let envelope = body(&mut u, MAX_ENVELOPE)?;
                let pulse = Pulse::from_array(&pulse_bytes(u.arbitrary()?, seq));
                let bytes = wire::encode(seq, u.arbitrary()?, &pulse, &envelope)
                    .expect("an envelope within MAX_ENVELOPE encodes");
                rx.datagram(&bytes, from, false);
            }
            // A forged parity datagram, mostly shaped like the sender's.
            7 => {
                let payload = take(&mut u, MAX_FORGED)?;
                let k = rx.fec.map_or(1, |(k, _)| k);
                let mut window_start = seq_near(&mut u, base, frames, rx.k())?;
                if u.ratio(3, 4)? {
                    window_start = window_start / u64::from(k) * u64::from(k);
                }
                let window_n = if u.ratio(3, 4)? { k } else { u.arbitrary()? };
                let header = FecHeader {
                    window_start,
                    window_n,
                    parity_len: payload.len() as u32,
                };
                let mut bytes = Vec::new();
                encode_fec(header, payload, &mut bytes);
                rx.datagram(&bytes, from, false);
            }
            // Raw bytes, sometimes behind a magic.
            8 => {
                let mut bytes = match u.int_in_range(0..=3u8)? {
                    0 => udp::FRAME_MAGIC.to_vec(),
                    1 => udp::PARITY_MAGIC.to_vec(),
                    2 => udp::FRAGMENT_MAGIC.to_vec(),
                    _ => Vec::new(),
                };
                bytes.extend_from_slice(take(&mut u, MAX_FORGED)?);
                rx.datagram(&bytes, from, false);
            }
            // A forged run of fragments under any sequence number, whole or
            // one fragment of it.
            9 => {
                let first = seq_near(&mut u, base, frames, rx.k())?;
                let envelope = body(&mut u, MAX_RUN_ENVELOPE)?;
                let pulse = Pulse::from_array(&pulse_bytes(u.arbitrary()?, first));
                let run = encode_fragments(first, u.arbitrary()?, &pulse, &envelope, MTU_BYTES)
                    .expect("an envelope within MAX_MESSAGE fragments");
                if u.ratio(1, 4)? {
                    for fragment in &run {
                        rx.datagram(fragment, from, false);
                    }
                } else {
                    let fragment = &run[u.choose_index(run.len())?];
                    rx.datagram(fragment, from, false);
                }
            }
            // The receiver takes some of the frames it holds.
            _ => {
                for _ in 0..u.int_in_range(0..=3u8)? {
                    rx.deliver_held();
                }
            }
        }
    }
    probe(&mut rx, run_end);
    while rx.deliver_held() {}
    Ok(())
}

/// After everything the input delivered, fresh traffic from the peer still
/// gets through: frames beyond the run are yielded, one from any other
/// source is dropped when a filter is set, and a fresh FEC window with one
/// frame lost has it rebuilt, held and delivered. Skipped past the top of
/// the sequence range, or when forged traffic already claimed the windows.
fn probe(rx: &mut Rx, run_end: Option<u64>) {
    let Some(end) = run_end else {
        return;
    };
    let peer = SocketAddr::new(rx.filter.unwrap_or(PEERS[0]), 9);
    if let Some(stranger) = rx.filter.and_then(|f| {
        PEERS
            .into_iter()
            .find(|p| udp::source(*p) != udp::source(f))
    }) {
        let sent = send(end, 1, [0x5a; 128], b"stranger".to_vec());
        let rejected = rx.main.intake.data_rejected_count();
        rx.datagram(&sent.encoded, SocketAddr::new(stranger, 9), false);
        assert_eq!(rx.main.intake.data_rejected_count(), rejected + 1);
    }
    let Some(k) = rx.k() else {
        for seq in end..end.saturating_add(2) {
            let sent = send(seq, seq, pulse_bytes(0x3c, seq), vec![seq as u8; 3]);
            let bytes = sent.encoded.clone();
            rx.sent.insert(seq, sent);
            rx.datagram(&bytes, peer, true);
        }
        if let Some(first) = end.checked_add(2) {
            probe_run(rx, first, peer);
        }
        return;
    };
    let Some(first) = end.div_ceil(k).checked_mul(k) else {
        return;
    };
    let Some(second) = first.checked_add(k) else {
        return;
    };
    let Some(last) = second.checked_add(k - 1) else {
        return;
    };
    if rx.forged.contains(&first) || rx.forged.contains(&second) {
        return;
    }
    // The held frames go first, so the probe's is the only one held.
    while rx.deliver_held() {}
    let lost = second + (first / k) % k;
    let mut encoder = FecEncoder::new(k as u16);
    let mut parity = None;
    for seq in first..=last {
        let envelope = vec![seq as u8; 1 + (seq % 7) as usize];
        let sent = send(seq, seq, pulse_bytes(0xa5, seq), envelope);
        let bytes = sent.encoded.clone();
        rx.sent.insert(seq, sent);
        if seq >= second {
            parity = encoder.add_original(seq, &bytes);
        }
        if seq != lost {
            rx.datagram(&bytes, peer, true);
        }
    }
    let parity = parity.expect("a whole aligned window has parity");
    rx.datagram(&parity, peer, true);
    let held = rx.main.intake.held_count();
    assert_eq!(
        held, 1,
        "a fresh window with one loss was not rebuilt: recovery is off"
    );
    let window = match rx.held.front() {
        Some(Held::Rebuilt { window, .. }) => Some(*window),
        _ => None,
    };
    assert_eq!(
        window,
        Some(second),
        "the probe's frame was rebuilt elsewhere"
    );
    assert!(rx.deliver_held());
    if let Some(first) = last.checked_add(1) {
        probe_run(rx, first, peer);
    }
}

/// With reassembly on, a fresh run of fragments from `peer` starting at
/// `first` completes and is delivered as sent. Skipped when the reassembly
/// cannot hold it, the run would pass the top of the sequence range, or a
/// forged datagram named it or reached its windows.
fn probe_run(rx: &mut Rx, first: u64, peer: SocketAddr) {
    let Some(cfg) = &rx.reassembly else {
        return;
    };
    if cfg.max_messages == 0 || cfg.max_bytes < PROBE_RUN {
        return;
    }
    let pulse = pulse_bytes(0x69, first);
    let envelope = pattern(PROBE_RUN, 0x17);
    let run = encode_fragments(
        first,
        first,
        &Pulse::from_array(&pulse),
        &envelope,
        FEC_DATAGRAM,
    )
    .expect("a short envelope fragments");
    let Some(last) = first.checked_add(run.len() as u64) else {
        return;
    };
    let forged_window = rx
        .k()
        .is_some_and(|k| (first..last).any(|seq| rx.forged.contains(&(seq / k * k))));
    if forged_window || rx.forged_rebuild || rx.forged_runs.contains(&first) {
        return;
    }
    while rx.deliver_held() {}
    rx.runs.insert(
        first,
        SentRun {
            pulse,
            send_ns: first,
            envelope,
        },
    );
    rx.fragments.extend(first..last);
    for fragment in &run {
        rx.datagram(fragment, peer, true);
    }
    assert_eq!(
        rx.main.intake.held_count(),
        1,
        "a fresh run from the peer was not reassembled"
    );
    assert!(matches!(rx.held.front(), Some(Held::Run { .. })));
    assert!(rx.deliver_held());
}

/// The frame the sender sends as `seq`, encoded as it encodes it.
fn send(seq: u64, send_ns: u64, pulse: [u8; 128], envelope: Vec<u8>) -> Sent {
    let encoded = wire::encode(seq, send_ns, &Pulse::from_array(&pulse), &envelope)
        .expect("an envelope within MAX_ENVELOPE encodes");
    Sent {
        pulse,
        send_ns,
        envelope,
        encoded,
    }
}

/// Pulse bytes that differ from one sequence number to the next.
fn pulse_bytes(seed: u8, seq: u64) -> [u8; 128] {
    let mut bytes = [0u8; 128];
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = seed.wrapping_mul(i as u8 | 1).wrapping_add(i as u8);
    }
    bytes[16..24].copy_from_slice(&seq.to_le_bytes());
    bytes
}

/// A source for the next datagram: with a filter, mostly the peer (in
/// either of its forms), any port.
fn source(u: &mut Unstructured<'_>, filter: Option<IpAddr>) -> Result<SocketAddr> {
    let ip = match filter {
        Some(peer) if u.ratio(3, 4)? => peer,
        _ => PEERS[u.choose_index(PEERS.len())?],
    };
    Ok(SocketAddr::new(ip, u.arbitrary()?))
}

/// An envelope of any length up to `cap`, costing the input a few bytes: a
/// length and a pattern, or short bytes from the input itself.
fn body(u: &mut Unstructured<'_>, cap: usize) -> Result<Vec<u8>> {
    if u.ratio(1, 2)? {
        return Ok(take(u, 32.min(cap))?.to_vec());
    }
    let len = if u.ratio(1, 4)? {
        cap - usize::from(u.int_in_range(0..=3u8)?)
    } else {
        u.int_in_range(0..=cap)?
    };
    Ok(pattern(len, u.arbitrary()?))
}

/// `len` bytes counting up from `seed`.
fn pattern(len: usize, seed: u8) -> Vec<u8> {
    (0..len).map(|i| seed.wrapping_add(i as u8)).collect()
}

/// A sequence number for a forged datagram: in or near the run, so that it
/// lands in the run's windows, or anywhere, the top of the range included.
fn seq_near(u: &mut Unstructured<'_>, base: u64, frames: usize, k: Option<u64>) -> Result<u64> {
    Ok(match u.int_in_range(0..=3u8)? {
        0 => u.arbitrary()?,
        1 => u64::MAX - u64::from(u.arbitrary::<u8>()?),
        _ => {
            let k = k.unwrap_or(1) as i64;
            base.wrapping_add_signed(u.int_in_range(-2 * k..=frames as i64 + 2 * k)?)
        }
    })
}
