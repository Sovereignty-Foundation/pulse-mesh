// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//
// Fuzz target: `pulse_wire_udp::fec::FecDecoder`, the receiver's FEC state
// machine, over sequences of datagrams taken the way the receiver takes
// them, and `FecEncoder`, which makes the parity it is fed.
//
// Every datagram goes through the receiver's own handling of it,
// `receiver::DataIntake`, the socket-free core `Receiver` hands each
// datagram it reads, here with FEC on and after the cut to the receiver's
// one-MTU buffer (`MTU_BYTES`) that its socket makes. The intake feeds its
// decoder and keeps the raw bytes the decoder rebuilds to itself, so beside
// it the target keeps a second decoder and feeds it what the intake's was
// fed, as the intake reports it: a data frame it yielded, whole, as the
// buffer holds it, and parity it counted as received, read by the
// specification's layout (the fuzz crate's `udp` module). The two decoders
// must agree on everything they show, and the XOR checks below judge the
// raw rebuilds of the second.
//
// The input describes a sender's run and what the network delivers of it.
// The run is real data frames (`wire::encode`), and now and then a run of
// fragments (`fragment::encode_fragments`) for an envelope longer than a
// frame carries, with consecutive sequence numbers from a base, usually a
// multiple of the window K, as for a sender that enables FEC before its
// first frame, and sometimes not, as for one that enables it mid-window;
// the frames' envelopes run from empty to `FEC_MAX_ENVELOPE`, the largest a
// sender with FEC on sends, and now and then to `MAX_ENVELOPE`, as a sender
// without that cap would, and the fragments are as long as a sender with
// FEC on makes them. They go through `FecEncoder`, which emits a parity
// datagram per full aligned window. K runs to 64 and the decoder tracks up
// to 64 windows. The delivery is a sequence drawn from the input: any of
// those frames, fragments and parity datagrams, in any order and any
// number of times, mixed with forged ones: data frames and fragments under
// any sequence number, parity datagrams with any header (mostly shaped
// like the sender's), and raw bytes. The decoder files a data frame or a
// fragment under its own window and a parity datagram under its header's.
// The intake reassembles nothing: a fragment, sent or rebuilt, goes to its
// reassembly, which is off and drops and counts it.
//
// Invariants:
// - every parity datagram the encoder emits covers one whole aligned window
//   of the run, and its payload is the XOR of that window's frames; one
//   whose window's envelopes are all within `FEC_MAX_ENVELOPE`, and whose
//   fragments are as long as a sender with FEC on makes them, fits the
//   receiver's buffer; a longer one is cut short there, counted
//   undecodable and rebuilds nothing;
// - the intake's decoder and the one beside it agree after every datagram
//   on the windows they track and on their refusal and eviction counts:
//   the intake fed its decoder exactly the frames it yielded, the fragments
//   it consumed and the parity it counted;
// - after every datagram the decoder tracks no more windows than
//   configured, and its refusal and eviction counts never go down; a data
//   frame refuses nothing, and parity whose window size is not K or whose
//   start is not a multiple of K is always refused, changing nothing;
// - a rebuilt frame lies in the window the datagram reached and is not the
//   frame the datagram delivered; one rebuilt by a parity datagram is as
//   long as that parity;
// - in a window no forged datagram ever reached, the rebuilt frame is the
//   original with that sequence number, zero-padded to the longest
//   datagram of its window, and the receiver delivers it as that frame, or
//   for a fragment, reads from it the fragment that was sent;
// - the receiver takes a data frame exactly when the specification's
//   framing accepts it, a fragment exactly when the fragment layout does,
//   and parity exactly when its layout does, and counts parity it cannot
//   take undecodable; it holds for delivery exactly the rebuilt frames the
//   framing accepts, as the framing reads them, passes the rebuilt
//   fragments the layout accepts to reassembly, counted as rebuilt
//   fragments, and counts the rest undecodable;
// - whatever came before, forged traffic included, a fresh window the
//   stream fills afterwards with one frame lost is rebuilt and delivered:
//   nothing a peer sends can switch recovery off.
//
// A forged datagram marks its window for the rest of the input: FEC is not
// authenticated, so a forged parity rebuilds whatever it says, and only the
// windows it never touched keep the promise that a rebuild is an original.

#![no_main]

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use libfuzzer_sys::arbitrary::{Result, Unstructured};
use libfuzzer_sys::fuzz_target;
use pulse_canon::Pulse;
use pulse_mesh_fuzz::udp;
use pulse_wire_udp::fec::{decode_fec, encode_fec, FecDecoder, FecEncoder, FecHeader};
use pulse_wire_udp::fragment::encode_fragments;
use pulse_wire_udp::receiver::{DataIntake, Dispatched};
use pulse_wire_udp::{wire, FEC_MAX_ENVELOPE, MAX_ENVELOPE, MTU_BYTES};

/// Largest FEC window drawn. The receiver's K is configuration, not input.
const MAX_K: u16 = 64;
/// Most windows a decoder is configured to track.
const MAX_WINDOWS: usize = 64;
/// Most data frames in the sender's run.
const MAX_FRAMES: usize = 256;
/// Most datagrams delivered by one input.
const MAX_DELIVERIES: usize = 2048;
/// Longest forged payload or raw datagram.
const MAX_FORGED: usize = MTU_BYTES + 64;
/// The longest datagram whose parity fits the receiver's buffer: a frame
/// with a `FEC_MAX_ENVELOPE` envelope, and the fragments a sender with FEC
/// on makes.
const FEC_DATAGRAM: usize = MTU_BYTES - (MAX_ENVELOPE - FEC_MAX_ENVELOPE);
/// Longest envelope the sender's run sends as fragments.
const MAX_RUN_ENVELOPE: usize = 16 * MAX_ENVELOPE;
/// Where every datagram comes from.
const PEER: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9);

/// The sender's side of one input.
struct Run {
    /// The FEC window both ends use.
    k: u16,
    /// Sequence number of the first frame.
    base: u64,
    /// Encoded data frames and fragments; `frames[i]` carries sequence
    /// `base + i`.
    frames: Vec<Vec<u8>>,
}

impl Run {
    /// The window key the decoder files `seq` under.
    fn window_of(&self, seq: u64) -> u64 {
        let k = u64::from(self.k);
        seq / k * k
    }

    /// The frame the sender sent as `seq`, if it sent one.
    fn frame(&self, seq: u64) -> Option<&[u8]> {
        let i = usize::try_from(seq.checked_sub(self.base)?).ok()?;
        self.frames.get(i).map(Vec::as_slice)
    }
}

/// One datagram's view, for checking what it rebuilt.
struct Delivery {
    /// The window key the datagram was filed under.
    window: u64,
    /// The data frame's or fragment's sequence number, for an original.
    seq: Option<u64>,
    /// The parity payload's length, for a parity datagram.
    parity_len: Option<usize>,
}

/// The receiver's handling of datagrams, `DataIntake` with FEC on, and
/// beside it a decoder fed what the intake's decoder is fed.
struct Rx {
    intake: DataIntake,
    /// Fed what the intake's decoder is fed: the target judges its raw
    /// rebuilds.
    beside: FecDecoder,
    /// Frames rebuilt from parity and delivered: sequence number and the
    /// raw rebuilt bytes.
    delivered: Vec<(u64, Vec<u8>)>,
}

/// What one datagram did.
struct Taken {
    /// How the decoder filed it, when it reached the decoder.
    delivery: Option<Delivery>,
    /// Whether it reached the decoder as parity.
    parity: bool,
    /// What the decoder rebuilt from it.
    rebuilt: Option<(u64, Vec<u8>)>,
}

impl Rx {
    fn new(k: u16, max_windows: usize) -> Self {
        let mut intake = DataIntake::default();
        intake.enable_fec(k, max_windows);
        Self {
            intake,
            beside: FecDecoder::new(k, max_windows),
            delivered: Vec::new(),
        }
    }

    /// The intake's decoder.
    fn decoder(&self) -> &FecDecoder {
        self.intake.fec_decoder().expect("FEC is on")
    }

    /// Parity that yielded nothing because it or its rebuild did not decode.
    fn undecodable(&self) -> u64 {
        self.intake.parity_undecodable_count()
    }

    /// Take one datagram as the receiver takes it from its socket.
    fn datagram(&mut self, sent: &[u8], k: u16) -> Taken {
        // The receive buffer holds one MTU; the rest of a longer datagram
        // is lost in the socket.
        let bytes = &sent[..sent.len().min(MTU_BYTES)];
        let received = self.intake.parity_received_count();
        let undecodable = self.undecodable();
        let held = self.intake.held_count();
        let fragments_dropped = self.intake.fragments_dropped_count();
        let rebuilt_fragments = self.intake.fec_rebuilt_fragment_count();
        let result = self.intake.dispatch(bytes, PEER);
        let mut bad_parity = false;
        let mut fragment = false;
        let (delivery, parity, rebuilt) = match &result {
            Ok(Dispatched::Data { meta, .. }) => {
                let seq = meta.seq;
                assert!(
                    udp::parse_frame(bytes).is_some_and(|f| f.seq == seq),
                    "the receiver took a frame the specification refuses"
                );
                let k = u64::from(k);
                let delivery = Delivery {
                    window: seq / k * k,
                    seq: Some(seq),
                    parity_len: None,
                };
                (Some(delivery), false, self.beside.add_original(seq, bytes))
            }
            Ok(Dispatched::FragmentConsumed) => {
                let spec = udp::parse_fragment(bytes)
                    .expect("the receiver took a fragment the specification refuses");
                fragment = true;
                let k = u64::from(k);
                let delivery = Delivery {
                    window: spec.seq / k * k,
                    seq: Some(spec.seq),
                    parity_len: None,
                };
                (
                    Some(delivery),
                    false,
                    self.beside.add_original(spec.seq, bytes),
                )
            }
            Ok(Dispatched::ParityConsumed) if self.intake.parity_received_count() != received => {
                let parity = udp::parse_parity(bytes)
                    .expect("the receiver took parity the specification refuses");
                let header = FecHeader {
                    window_start: parity.window_start,
                    window_n: parity.window_n,
                    parity_len: parity.parity.len() as u32,
                };
                let delivery = Delivery {
                    window: parity.window_start,
                    seq: None,
                    parity_len: Some(parity.parity.len()),
                };
                let rebuilt = self.beside.add_parity(header, &parity.parity);
                (Some(delivery), true, rebuilt)
            }
            Ok(Dispatched::ParityConsumed) => {
                assert!(
                    udp::parse_parity(bytes).is_none(),
                    "the receiver refused parity the specification accepts"
                );
                bad_parity = true;
                (None, false, None)
            }
            Ok(Dispatched::Foreign) => {
                panic!("a datagram was dropped as foreign with no filter set")
            }
            Err(_) => {
                assert!(
                    udp::parse_frame(bytes).is_none(),
                    "the receiver refused a frame the specification accepts"
                );
                assert!(
                    udp::parse_fragment(bytes).is_none(),
                    "the receiver refused a fragment the specification accepts"
                );
                (None, false, None)
            }
        };
        let (mine, beside) = (self.decoder(), &self.beside);
        assert_eq!(
            (
                mine.active_windows(),
                mine.refused_count(),
                mine.evicted_count()
            ),
            (
                beside.active_windows(),
                beside.refused_count(),
                beside.evicted_count()
            ),
            "the receiver fed its decoder otherwise"
        );
        // A rebuild the framing accepts is held, as the framing reads it; one
        // the fragment layout accepts goes to reassembly; any other is
        // counted undecodable.
        let now_held = self.intake.held_count();
        let rebuilt_frame = rebuilt
            .as_ref()
            .map(|(_, raw)| (udp::parse_frame(raw), udp::parse_fragment(raw)));
        let rebuilt_fragment = matches!(rebuilt_frame, Some((None, Some(_))));
        assert_eq!(
            self.intake.fec_rebuilt_fragment_count(),
            rebuilt_fragments + u64::from(rebuilt_fragment),
            "a rebuilt fragment went uncounted, or something else was counted"
        );
        assert_eq!(
            self.intake.fragments_dropped_count(),
            fragments_dropped + u64::from(fragment) + u64::from(rebuilt_fragment),
            "with reassembly off, a fragment was not dropped and counted"
        );
        match rebuilt_frame {
            Some((Some(frame), _)) => {
                assert_eq!(
                    now_held,
                    held + 1,
                    "a rebuilt frame that decodes was not held"
                );
                assert_eq!(self.undecodable(), undecodable);
                let got = self.intake.pop_recovered().expect("a frame is held");
                assert_eq!(
                    (
                        got.meta.seq,
                        got.meta.send_ns,
                        got.pulse.as_bytes(),
                        &got.envelope
                    ),
                    (frame.seq, frame.send_ns, &frame.pulse, &frame.envelope),
                    "the receiver holds the rebuilt frame otherwise than the framing reads it"
                );
                assert_eq!(got.meta.peer, PEER);
                if let Some((_, raw)) = &rebuilt {
                    self.delivered.push((frame.seq, raw.clone()));
                }
            }
            Some((None, Some(_))) => {
                assert_eq!(now_held, held, "a rebuilt fragment was held");
                assert_eq!(
                    self.undecodable(),
                    undecodable,
                    "a rebuilt fragment was counted undecodable"
                );
            }
            Some((None, None)) => {
                assert_eq!(
                    now_held, held,
                    "a rebuilt frame that does not decode was held"
                );
                assert_eq!(
                    self.undecodable(),
                    undecodable + 1,
                    "a rebuilt frame that does not decode went uncounted"
                );
            }
            None => {
                assert_eq!(now_held, held, "a frame was held from nothing");
                assert_eq!(
                    self.undecodable(),
                    undecodable + u64::from(bad_parity),
                    "parity that does not decode went uncounted, or something else was counted"
                );
            }
        }
        Taken {
            delivery,
            parity,
            rebuilt,
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let _ = fuzz(data);
});

fn fuzz(data: &[u8]) -> Result<()> {
    let mut u = Unstructured::new(data);
    let k = u.int_in_range(1..=MAX_K)?;
    let max_windows = u.int_in_range(0..=MAX_WINDOWS)?;
    let frames = u.int_in_range(0..=MAX_FRAMES)?;
    // Envelopes as a sender with FEC on sends them, and now and then as one
    // without the FEC cap would.
    let envelope_cap = if u.ratio(1, 16)? {
        MAX_ENVELOPE
    } else {
        FEC_MAX_ENVELOPE
    };

    // A base low enough that every frame's sequence number exists: the last
    // frame may be u64::MAX itself, where a window's end needs checked
    // arithmetic. Usually aligned to K; otherwise the encoder must wait for
    // the first boundary.
    let wide = u64::from(k);
    let top = u64::MAX - (frames as u64).saturating_sub(1);
    let mut base = u.arbitrary::<u64>()?.min(top);
    if u.ratio(3, 4)? {
        base = base / wide * wide;
    }

    let pulse = Pulse::zeroed();
    let mut encoder = FecEncoder::new(k);
    let mut run = Run {
        k,
        base,
        frames: Vec::with_capacity(frames),
    };
    let mut parity = Vec::new();
    let mut window_fits = true;
    while run.frames.len() < frames {
        let i = run.frames.len();
        let seq = base + i as u64;
        // Now and then a run of fragments, cut off where the sender's run
        // ends.
        let datagrams = if u.ratio(1, 8)? {
            let len = u.int_in_range(FEC_MAX_ENVELOPE + 1..=MAX_RUN_ENVELOPE)?;
            let envelope = pattern(len, u.arbitrary()?);
            let mut fragments = encode_fragments(seq, i as u64, &pulse, &envelope, FEC_DATAGRAM)
                .expect("an envelope within MAX_MESSAGE fragments");
            fragments.truncate(frames - i);
            fragments
        } else {
            let envelope = body(&mut u, envelope_cap)?;
            vec![wire::encode(seq, i as u64, &pulse, &envelope)
                .expect("an envelope within MAX_ENVELOPE encodes")]
        };
        for datagram in datagrams {
            let seq = base + run.frames.len() as u64;
            if seq.is_multiple_of(wide) {
                window_fits = true;
            }
            window_fits &= datagram.len() <= FEC_DATAGRAM;
            if let Some(parity_datagram) = encoder.add_original(seq, &datagram) {
                run.frames.push(datagram);
                check_parity(&run, seq, &parity_datagram);
                if window_fits {
                    assert!(
                        parity_datagram.len() <= MTU_BYTES,
                        "parity of {} bytes for datagrams within FEC_DATAGRAM",
                        parity_datagram.len()
                    );
                }
                parity.push(parity_datagram);
            } else {
                run.frames.push(datagram);
            }
        }
    }

    let mut rx = Rx::new(k, max_windows);
    let bound = max_windows.max(1);
    let mut forged = HashSet::new();
    let (mut refused, mut evicted) = (0, 0);
    for _ in 0..MAX_DELIVERIES {
        if u.is_empty() {
            break;
        }
        // Whether the datagram must be refused as parity that fits no
        // window.
        let mut misfit = false;
        let active = rx.decoder().active_windows();
        let undecodable = rx.undecodable();
        let delivered = rx.delivered.len();
        let taken = match u.int_in_range(0..=5u8)? {
            // A frame or fragment of the run, as sent.
            0 if !run.frames.is_empty() => {
                let i = u.choose_index(run.frames.len())?;
                rx.datagram(&run.frames[i], k)
            }
            // A parity datagram of the run, as the encoder emitted it.
            1 if !parity.is_empty() => {
                let datagram = &parity[u.choose_index(parity.len())?];
                let taken = rx.datagram(datagram, k);
                if datagram.len() > MTU_BYTES {
                    assert!(
                        taken.delivery.is_none(),
                        "parity longer than the buffer reached the decoder"
                    );
                    assert_eq!(
                        rx.undecodable(),
                        undecodable + 1,
                        "parity cut short went uncounted"
                    );
                }
                taken
            }
            // A forged parity datagram: mostly shaped like the sender's,
            // aligned and of window K, so it gets past the shape check.
            2 => {
                let payload = take(&mut u, MAX_FORGED)?;
                let mut window_start = seq_near(&mut u, &run)?;
                if u.ratio(3, 4)? {
                    window_start = window_start / wide * wide;
                }
                let window_n = if u.ratio(3, 4)? {
                    k
                } else {
                    u.arbitrary::<u16>()?.max(1)
                };
                let header = FecHeader {
                    window_start,
                    window_n,
                    parity_len: payload.len() as u32,
                };
                let mut datagram = Vec::new();
                encode_fec(header, payload, &mut datagram);
                let (decoded, bytes) = decode_fec(&datagram).expect("encode_fec's output decodes");
                assert_eq!(decoded, header, "a header survives encode and decode");
                assert_eq!(
                    bytes, payload,
                    "a parity payload survives encode and decode"
                );
                forged.insert(header.window_start);
                misfit = datagram.len() <= MTU_BYTES && misfits(&header, k);
                rx.datagram(&datagram, k)
            }
            // Raw bytes, taken as the receiver takes any datagram.
            3 => {
                let datagram = take(&mut u, MAX_FORGED)?.to_vec();
                let cut = &datagram[..datagram.len().min(MTU_BYTES)];
                if let Some(parity) = udp::parse_parity(cut) {
                    forged.insert(parity.window_start);
                    misfit = misfits(
                        &FecHeader {
                            window_start: parity.window_start,
                            window_n: parity.window_n,
                            parity_len: parity.parity.len() as u32,
                        },
                        k,
                    );
                }
                if let Some(frame) = udp::parse_frame(cut) {
                    forged.insert(run.window_of(frame.seq));
                }
                if let Some(fragment) = udp::parse_fragment(cut) {
                    forged.insert(run.window_of(fragment.seq));
                }
                rx.datagram(&datagram, k)
            }
            // A forged data frame under any sequence number.
            4 => {
                let seq = seq_near(&mut u, &run)?;
                let envelope = body(&mut u, envelope_cap)?;
                let bytes = wire::encode(seq, 0, &pulse, &envelope)
                    .expect("an envelope within MAX_ENVELOPE encodes");
                forged.insert(run.window_of(seq));
                rx.datagram(&bytes, k)
            }
            // A fragment of a forged run that starts at any sequence number.
            5 => {
                let first = seq_near(&mut u, &run)?;
                let envelope = body(&mut u, MAX_RUN_ENVELOPE)?;
                let fragments = encode_fragments(first, 0, &pulse, &envelope, FEC_DATAGRAM)
                    .expect("an envelope within MAX_MESSAGE fragments");
                let index = u.choose_index(fragments.len())?;
                let seq = first.wrapping_add(index as u64);
                forged.insert(run.window_of(seq));
                rx.datagram(&fragments[index], k)
            }
            _ => continue,
        };

        assert!(
            rx.decoder().active_windows() <= bound,
            "the decoder tracks {} windows, configured for at most {bound}",
            rx.decoder().active_windows()
        );
        let (now_refused, now_evicted) =
            (rx.decoder().refused_count(), rx.decoder().evicted_count());
        assert!(now_evicted >= evicted, "the eviction count went down");
        assert!(
            now_refused == refused || (taken.parity && now_refused == refused + 1),
            "refusals went from {refused} to {now_refused} on one datagram"
        );
        if misfit {
            assert_eq!(
                now_refused,
                refused + 1,
                "parity that fits no window was not refused"
            );
            assert!(taken.rebuilt.is_none(), "refused parity rebuilt a frame");
            assert_eq!(
                rx.decoder().active_windows(),
                active,
                "refused parity changed the table"
            );
        }
        (refused, evicted) = (now_refused, now_evicted);
        assert!(
            rx.undecodable() >= undecodable,
            "the undecodable count went down"
        );
        match (&taken.rebuilt, &taken.delivery) {
            (Some((seq, bytes)), Some(delivery)) => {
                check_rebuilt(&run, &forged, delivery, *seq, bytes);
                let decodes = udp::parse_frame(bytes).is_some();
                let fragment = udp::parse_fragment(bytes).is_some();
                assert_eq!(
                    rx.delivered.len(),
                    delivered + usize::from(decodes),
                    "a rebuilt frame that decodes was not delivered, or one that does not was"
                );
                assert_eq!(
                    rx.undecodable(),
                    undecodable + u64::from(!decodes && !fragment)
                );
                if let Some((got, delivered_bytes)) = rx.delivered.last().filter(|_| decodes) {
                    assert_eq!(delivered_bytes, bytes);
                    assert_eq!(udp::parse_frame(bytes).map(|f| f.seq), Some(*got));
                }
            }
            (Some(_), None) => panic!("a datagram that never reached the decoder rebuilt a frame"),
            (None, _) => assert_eq!(
                rx.delivered.len(),
                delivered,
                "a frame was delivered from nothing"
            ),
        }
    }

    probe(&mut rx, &run, &forged, &pulse);
    Ok(())
}

/// Parity whose shape no sender's parity has: another window size, or a
/// start that is not a multiple of K.
fn misfits(header: &FecHeader, k: u16) -> bool {
    header.window_n != k || !header.window_start.is_multiple_of(u64::from(k))
}

/// A parity datagram the encoder emitted after `last` covers the aligned
/// window ending there, every frame of which the run sent, and carries
/// their XOR.
fn check_parity(run: &Run, last: u64, datagram: &[u8]) {
    let (header, bytes) = decode_fec(datagram).expect("the encoder's parity decodes");
    let k = u64::from(run.k);
    assert_eq!(header.window_n, run.k, "the encoder's window is K");
    assert!(
        header.window_start.is_multiple_of(k),
        "the encoder's window is aligned"
    );
    assert_eq!(
        header.window_start + (k - 1),
        last,
        "parity came after a frame that does not end its window"
    );
    let mut xor = Vec::new();
    for seq in header.window_start..=last {
        let frame = run
            .frame(seq)
            .expect("parity covers only frames the run sent");
        if frame.len() > xor.len() {
            xor.resize(frame.len(), 0);
        }
        for (x, b) in xor.iter_mut().zip(frame) {
            *x ^= b;
        }
    }
    assert_eq!(bytes, xor.as_slice(), "the parity is not the window's XOR");
}

/// What a rebuilt frame must satisfy.
fn check_rebuilt(run: &Run, forged: &HashSet<u64>, delivery: &Delivery, seq: u64, bytes: &[u8]) {
    let offset = seq.checked_sub(delivery.window);
    assert!(
        offset.is_some_and(|o| o < u64::from(run.k)),
        "rebuilt seq {seq} outside the window keyed {}",
        delivery.window
    );
    if let Some(own) = delivery.seq {
        assert_ne!(seq, own, "rebuilt the frame that was just delivered");
    }
    if let Some(len) = delivery.parity_len {
        assert_eq!(bytes.len(), len, "a rebuild is as long as its parity");
    }
    if forged.contains(&delivery.window) {
        return;
    }

    // Only the run's own datagrams ever reached this window, so its parity
    // is the encoder's and all K of its frames were sent.
    assert_eq!(
        run.window_of(seq),
        delivery.window,
        "rebuilt seq {seq} from another window"
    );
    let last = delivery
        .window
        .checked_add(u64::from(run.k) - 1)
        .expect("a window the encoder covered ends inside the sequence range");
    let longest = (delivery.window..=last)
        .map(|s| run.frame(s).map(<[u8]>::len))
        .collect::<Option<Vec<_>>>()
        .expect("a window rebuilt from the encoder's parity was sent in full")
        .into_iter()
        .max()
        .unwrap_or(0);
    let original = run.frame(seq).expect("the rebuilt seq was sent");
    assert_rebuilds(bytes, original, longest, seq);
}

/// `bytes` is `original`, sent as `seq`, zero-padded to `longest`, and the
/// specification's framing, which the receiver's holds to, reads the
/// original frame from it, or the fragment layout the original fragment.
fn assert_rebuilds(bytes: &[u8], original: &[u8], longest: usize, seq: u64) {
    assert_eq!(
        bytes.len(),
        longest,
        "a rebuild is padded to its window's longest datagram"
    );
    assert_eq!(
        &bytes[..original.len()],
        original,
        "rebuilt seq {seq} differs from the original"
    );
    assert!(
        bytes[original.len()..].iter().all(|&b| b == 0),
        "the padding after rebuilt seq {seq} is not zero"
    );
    if let Some(want) = udp::parse_fragment(original) {
        let got = udp::parse_fragment(bytes).expect("a rebuilt fragment decodes");
        assert_eq!(got.seq, seq, "the rebuilt fragment carries another seq");
        assert_eq!(got, want, "the rebuilt fragment differs");
        return;
    }
    let got = udp::parse_frame(bytes).expect("a rebuilt frame decodes");
    let want = udp::parse_frame(original).expect("the original decodes");
    assert_eq!(got.seq, seq, "the rebuilt frame carries another seq");
    assert_eq!(got.send_ns, want.send_ns);
    assert_eq!(got.pulse, want.pulse);
    assert_eq!(got.envelope, want.envelope, "the rebuilt envelope differs");
}

/// After everything the input delivered: the stream moves on to two fresh
/// windows past the run, the first whole and the second with one frame
/// lost, and the lost frame is rebuilt from the second window's parity and
/// delivered. Skipped when those windows would pass the top of the
/// sequence range or a forged datagram already claimed them.
fn probe(rx: &mut Rx, run: &Run, forged: &HashSet<u64>, pulse: &Pulse) {
    let k = u64::from(run.k);
    let Some(end) = run.base.checked_add(run.frames.len() as u64) else {
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
    if forged.contains(&first) || forged.contains(&second) {
        return;
    }
    let frame = |seq: u64| {
        let envelope = vec![seq as u8; 1 + (seq % 7) as usize];
        wire::encode(seq, seq, pulse, &envelope).expect("a short envelope encodes")
    };
    for seq in first..second {
        let _ = rx.datagram(&frame(seq), run.k);
    }
    let lost = second + (first / k) % k;
    let mut encoder = FecEncoder::new(run.k);
    let mut parity = None;
    let mut longest = 0;
    for seq in second..=last {
        let bytes = frame(seq);
        longest = longest.max(bytes.len());
        parity = encoder.add_original(seq, &bytes);
        if seq != lost {
            assert!(
                rx.datagram(&bytes, run.k).rebuilt.is_none(),
                "rebuilt before the parity arrived"
            );
        }
    }
    let parity = parity.expect("a whole aligned window has parity");
    let delivered = rx.delivered.len();
    let (seq, rebuilt) = rx
        .datagram(&parity, run.k)
        .rebuilt
        .expect("a fresh window with one loss was not rebuilt: recovery is off");
    assert_eq!(seq, lost, "the probe rebuilt another frame");
    assert_rebuilds(&rebuilt, &frame(lost), longest, lost);
    assert_eq!(
        rx.delivered.len(),
        delivered + 1,
        "the rebuilt frame was not delivered"
    );
    assert_eq!(rx.delivered.last().map(|d| d.0), Some(lost));
}

/// `len` bytes counting up from `seed`.
fn pattern(len: usize, seed: u8) -> Vec<u8> {
    (0..len).map(|i| seed.wrapping_add(i as u8)).collect()
}

/// Up to `max` bytes of input, fewer when the input runs out.
fn take<'a>(u: &mut Unstructured<'a>, max: usize) -> Result<&'a [u8]> {
    let len = u.int_in_range(0..=max)?;
    u.bytes(len.min(u.len()))
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

/// A sequence number for a forged datagram: near the run, so it lands in
/// the run's windows, or anywhere, the top of the range included.
fn seq_near(u: &mut Unstructured<'_>, run: &Run) -> Result<u64> {
    Ok(match u.int_in_range(0..=3u8)? {
        0 => u.arbitrary()?,
        1 => u64::MAX - u64::from(u.arbitrary::<u8>()?),
        _ => {
            let span = run.frames.len() as i64 + 2 * i64::from(run.k);
            run.base
                .wrapping_add_signed(u.int_in_range(-2 * i64::from(run.k)..=span)?)
        }
    })
}
