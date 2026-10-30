// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//
// Fuzz target: `pulse_wire_udp::fragment`, the fragment format
// (`encode_fragments`, `decode_fragment`) and the `Reassembler` that puts
// runs of fragments back together, judged by the fuzz crate's `udp` module,
// which reads fragments without calling the transport, and by a model of
// the reassembler's documented contract.
//
// The input describes the reassembler's bounds (runs and bytes in progress,
// from none up, and a timeout) and a few senders' runs: an envelope of any
// length up to past `MAX_MESSAGE`, with a Pulse and send time, encoded as
// the run that starts at any sequence number, the top of the range
// included, in datagrams of any size, from too small for a chunk up past
// the MTU, from one of three peers. Then a delivery, on a clock the target
// keeps and the input moves forward: fragments of the runs in any order and
// any number of times, from their peer or another, as sent, padded with
// zeros as FEC rebuilds them, or with bytes after them; whole runs in
// order; forged fragments that name a run's first sequence number and
// disagree with it; and raw bytes, sometimes behind the fragment magic,
// and fragments of the runs cut short or with a bit flipped.
//
// The model keeps, per peer and run, the fragments taken, the run's count,
// total length and send time from its first fragment, and when it started;
// at each fragment it drops the runs older than the timeout, drops a
// fragment of a run that cannot be held at all (longer than the byte bound,
// or no runs allowed), makes room for a new run by dropping the runs that
// started first, drops a run a fragment disagrees with (its count, total
// length or send time, or chunks longer than the total), ignores a
// repeated fragment, and once every fragment has arrived returns the
// envelope, or drops the run when its chunks do not add up to its length.
//
// Invariants:
// - `encode_fragments` refuses exactly an envelope over `MAX_MESSAGE`, one
//   that needs more than `MAX_FRAGMENTS` fragments, and a datagram size
//   with no room for a chunk; otherwise every datagram fits the size, and
//   the specification reads from them the run's sequence numbers, indexes,
//   count, total length and send time, the Pulse in the first only, and
//   chunks that make up the envelope, as many as the sizes say;
// - `decode_fragment` accepts exactly what the specification accepts,
//   with bytes after the fragment, zeros or not, and reads the same fields;
// - after every fragment the reassembler returns what the model returns,
//   and agrees with it on the runs in progress, the bytes they reserve and
//   the runs completed and dropped; the runs in progress and the bytes stay
//   within the bounds;
// - a run returned whose first sequence number no forged fragment named is
//   the envelope, Pulse and send time its sender sent;
// - whatever came before, a fresh run that fits the bounds, delivered whole
//   from one peer, is returned on its last fragment, as sent.

#![no_main]

use std::collections::{BTreeMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use libfuzzer_sys::arbitrary::{Result, Unstructured};
use libfuzzer_sys::fuzz_target;
use pulse_canon::Pulse;
use pulse_mesh_fuzz::{take, udp};
use pulse_wire_udp::fragment::{
    decode_fragment, encode_fragments, Fragment, Reassembler, MAX_FRAGMENTS, MAX_MESSAGE,
};
use pulse_wire_udp::{ReassemblyConfig, MTU_BYTES};

/// Most runs the senders send.
const MAX_SENT: usize = 4;
/// Most steps in one input.
const MAX_STEPS: usize = 512;
/// Most runs in progress the reassembler is configured to keep.
const MAX_RUNS: usize = 8;
/// Longest timeout drawn, in the clock's milliseconds.
const MAX_TIMEOUT_MS: u64 = 1000;
/// Largest datagram size drawn: past the MTU, as for jumbo frames.
const MAX_DATAGRAM: usize = 9000;
/// The peers the fragments come from.
const PEERS: [SocketAddr; 3] = [
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9),
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 10),
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3)), 9),
];
/// The header before the Pulse or the chunk, and the CRC after the chunk.
const HEADER: usize = udp::FRAGMENT_HEADER;
const CRC: usize = 4;

/// A run as its sender sent it.
struct Sent {
    peer: usize,
    first_seq: u64,
    send_ns: u64,
    pulse: [u8; 128],
    envelope: Vec<u8>,
    datagrams: Vec<Vec<u8>>,
}

/// A run in progress in the model.
struct Run {
    count: u16,
    total_len: u32,
    send_ns: u64,
    pulse: Option<[u8; 128]>,
    chunks: Vec<Option<Vec<u8>>>,
    bytes: usize,
    started: u64,
    serial: u64,
}

/// What the reassembler and the model return for a completed run.
type Whole = ([u8; 128], Vec<u8>, u64, u64);

/// The reassembler's contract, from its documentation.
struct Model {
    max_messages: usize,
    max_bytes: usize,
    timeout: u64,
    runs: BTreeMap<(usize, u64), Run>,
    serial: u64,
    completed: u64,
    dropped: u64,
}

impl Model {
    fn reserved(&self) -> usize {
        self.runs.values().map(|r| r.total_len as usize).sum()
    }

    fn drop_run(&mut self, key: (usize, u64)) {
        if self.runs.remove(&key).is_some() {
            self.dropped += 1;
        }
    }

    fn add(&mut self, f: udp::FragmentSpec, peer: usize, now: u64) -> Option<Whole> {
        let timeout = self.timeout;
        let before = self.runs.len();
        self.runs.retain(|_, r| now - r.started <= timeout);
        self.dropped += (before - self.runs.len()) as u64;
        let total = f.total_len as usize;
        if total > self.max_bytes || self.max_messages == 0 {
            self.dropped += 1;
            return None;
        }
        let key = (peer, f.first_seq);
        if !self.runs.contains_key(&key) {
            while !self.runs.is_empty()
                && (self.runs.len() >= self.max_messages
                    || self.reserved() + total > self.max_bytes)
            {
                let oldest = self
                    .runs
                    .iter()
                    .min_by_key(|(_, r)| r.serial)
                    .map(|(k, _)| *k)
                    .expect("not empty");
                self.drop_run(oldest);
            }
            self.serial += 1;
            self.runs.insert(
                key,
                Run {
                    count: f.count,
                    total_len: f.total_len,
                    send_ns: f.send_ns,
                    pulse: None,
                    chunks: vec![None; usize::from(f.count)],
                    bytes: 0,
                    started: now,
                    serial: self.serial,
                },
            );
        }
        let run = self.runs.get_mut(&key).expect("just inserted");
        if (run.count, run.total_len, run.send_ns) != (f.count, f.total_len, f.send_ns) {
            self.drop_run(key);
            return None;
        }
        let index = usize::from(f.index);
        if run.chunks[index].is_some() {
            return None;
        }
        run.bytes += f.chunk.len();
        if run.bytes > total {
            self.drop_run(key);
            return None;
        }
        run.chunks[index] = Some(f.chunk);
        if let Some(pulse) = f.pulse {
            run.pulse = Some(pulse);
        }
        if run.chunks.iter().any(Option::is_none) {
            return None;
        }
        let run = self.runs.remove(&key).expect("present");
        let envelope: Vec<u8> = run.chunks.into_iter().flatten().flatten().collect();
        match run.pulse {
            Some(pulse) if envelope.len() == total => {
                self.completed += 1;
                Some((pulse, envelope, f.first_seq, run.send_ns))
            }
            _ => {
                self.dropped += 1;
                None
            }
        }
    }
}

/// The reassembler, the model beside it, the clock and the target's record.
struct Rx {
    reassembler: Reassembler,
    model: Model,
    start: Instant,
    /// The clock, in milliseconds from `start`.
    now: u64,
    sent: Vec<Sent>,
    /// First sequence numbers a returned run's content is not checked
    /// under: a forged fragment named it, or two runs share it.
    forged: HashSet<u64>,
}

impl Rx {
    /// Take one datagram from `PEERS[peer]`: decode it as the specification
    /// reads it, and give a fragment to both the reassembler and the model.
    fn datagram(&mut self, bytes: &[u8], peer: usize) -> Option<Whole> {
        let spec = udp::parse_fragment(bytes);
        let fragment = decode_fragment(bytes);
        let fragment = match (fragment, &spec) {
            (Ok(fragment), Some(spec)) => {
                assert_same(&fragment, spec);
                fragment
            }
            (Err(_), None) => return None,
            (got, _) => panic!(
                "the transport and the specification disagree: {:?} against {spec:?}",
                got.map(|f| f.seq)
            ),
        };
        let spec = spec.expect("matched above");
        let at = self.start + Duration::from_millis(self.now);
        let got = self
            .reassembler
            .add(&fragment, PEERS[peer], at)
            .map(|m| (*m.pulse.as_bytes(), m.envelope, m.first_seq, m.send_ns));
        let want = self.model.add(spec, peer, self.now);
        assert_eq!(
            got, want,
            "the reassembler returned otherwise than the model"
        );
        let r = &self.reassembler;
        assert_eq!(
            (
                r.in_progress(),
                r.reserved_bytes(),
                r.completed_count(),
                r.dropped_count()
            ),
            (
                self.model.runs.len(),
                self.model.reserved(),
                self.model.completed,
                self.model.dropped
            ),
            "the reassembler's state differs from the model's"
        );
        assert!(r.in_progress() <= self.model.max_messages);
        assert!(r.reserved_bytes() <= self.model.max_bytes);
        if let Some((pulse, envelope, first_seq, send_ns)) = &got {
            if !self.forged.contains(first_seq) {
                let run = self
                    .sent
                    .iter()
                    .find(|s| s.first_seq == *first_seq)
                    .expect("a run no forged fragment named was sent");
                assert!(
                    (pulse, envelope, *send_ns) == (&run.pulse, &run.envelope, run.send_ns),
                    "the run at {first_seq} came back otherwise than it was sent"
                );
            }
        }
        got
    }
}

/// `decode_fragment` reads what the specification reads.
fn assert_same(got: &Fragment<'_>, want: &udp::FragmentSpec) {
    assert_eq!(
        (
            got.seq,
            got.send_ns,
            got.first_seq,
            got.index,
            got.count,
            got.total_len,
            got.pulse,
            got.chunk
        ),
        (
            want.seq,
            want.send_ns,
            want.first_seq,
            want.index,
            want.count,
            want.total_len,
            want.pulse,
            want.chunk.as_slice()
        ),
        "the transport reads a fragment otherwise than the specification"
    );
}

/// The run `encode_fragments` makes of `envelope`, checked against the
/// format; `None` when it refuses, and then it must.
fn encode(
    first_seq: u64,
    send_ns: u64,
    pulse: &[u8; 128],
    envelope: &[u8],
    max_datagram: usize,
) -> Option<Vec<Vec<u8>>> {
    let result = encode_fragments(
        first_seq,
        send_ns,
        &Pulse::from_array(pulse),
        envelope,
        max_datagram,
    );
    // The chunks a datagram of this size has room for, the first after
    // the Pulse; a chunk's length is a u16.
    let room = |pulse: usize| {
        max_datagram
            .checked_sub(HEADER + pulse + CRC)
            .filter(|&n| n > 0)
            .map(|n| n.min(usize::from(u16::MAX)))
    };
    let count = match (room(128), room(0)) {
        (Some(first), Some(rest)) => Some(1 + envelope.len().saturating_sub(first).div_ceil(rest)),
        _ => None,
    };
    let fits =
        envelope.len() <= MAX_MESSAGE && count.is_some_and(|n| n <= usize::from(MAX_FRAGMENTS));
    let Ok(run) = result else {
        assert!(!fits, "a run that fits was refused");
        return None;
    };
    assert!(fits, "a run that does not fit was encoded");
    assert_eq!(
        Some(run.len()),
        count,
        "the run has another number of fragments"
    );
    let mut joined = Vec::with_capacity(envelope.len());
    for (i, datagram) in run.iter().enumerate() {
        assert!(
            datagram.len() <= max_datagram,
            "a fragment longer than its size"
        );
        let f = udp::parse_fragment(datagram).expect("an encoded fragment parses");
        assert_eq!(
            (
                f.seq,
                f.first_seq,
                usize::from(f.index),
                usize::from(f.count)
            ),
            (first_seq.wrapping_add(i as u64), first_seq, i, run.len())
        );
        assert_eq!((f.total_len as usize, f.send_ns), (envelope.len(), send_ns));
        assert_eq!(f.pulse.as_ref(), (i == 0).then_some(pulse));
        joined.extend_from_slice(&f.chunk);
    }
    assert!(joined == envelope, "the chunks do not make up the envelope");
    Some(run)
}

fuzz_target!(|data: &[u8]| {
    let _ = fuzz(data);
});

/// AddressSanitizer's options for this target: a 32 MiB quarantine, not
/// the default. Runs of 64 KiB envelopes, copied as the format and the
/// model need, churn enough freed memory through the default quarantine
/// to pass libFuzzer's 2 GB limit within a minute, with a few MiB live.
/// The quarantine catches a use after free, which the code under test,
/// safe Rust throughout, cannot commit.
#[no_mangle]
pub extern "C" fn __asan_default_options() -> *const std::ffi::c_char {
    c"quarantine_size_mb=32".as_ptr()
}

fn fuzz(data: &[u8]) -> Result<()> {
    let mut u = Unstructured::new(data);
    let mut cfg = ReassemblyConfig::default();
    cfg.max_messages = u.int_in_range(0..=MAX_RUNS)?;
    cfg.max_bytes = if u.ratio(1, 4)? {
        u.int_in_range(0..=MAX_MESSAGE)?
    } else {
        u.int_in_range(0..=4 * MAX_MESSAGE)?
    };
    let timeout = u.int_in_range(0..=MAX_TIMEOUT_MS)?;
    cfg.timeout = Duration::from_millis(timeout);
    let mut rx = Rx {
        reassembler: Reassembler::new(cfg.clone()),
        model: Model {
            max_messages: cfg.max_messages,
            max_bytes: cfg.max_bytes,
            timeout,
            runs: BTreeMap::new(),
            serial: 0,
            completed: 0,
            dropped: 0,
        },
        start: Instant::now(),
        now: 0,
        sent: Vec::new(),
        forged: HashSet::new(),
    };

    for _ in 0..u.int_in_range(1..=MAX_SENT)? {
        let first_seq = match u.int_in_range(0..=3u8)? {
            0 => u64::MAX - u64::from(u.arbitrary::<u8>()?),
            _ => u.arbitrary()?,
        };
        let send_ns = u.arbitrary()?;
        let mut pulse = [0u8; 128];
        pulse[..8].copy_from_slice(&u.arbitrary::<u64>()?.to_le_bytes());
        let len = match u.int_in_range(0..=7u8)? {
            0 => MAX_MESSAGE + usize::from(u.int_in_range(0..=2u8)?) - 1,
            1 => u.int_in_range(0..=MAX_MESSAGE + 1)?,
            _ => u.int_in_range(0..=4 * MTU_BYTES)?,
        };
        let envelope = pattern(len, u.arbitrary()?);
        let max_datagram = if u.ratio(1, 8)? {
            u.int_in_range(0..=MAX_DATAGRAM)?
        } else {
            u.int_in_range(HEADER + 128 + CRC + 1..=MTU_BYTES)?
        };
        let Some(datagrams) = encode(first_seq, send_ns, &pulse, &envelope, max_datagram) else {
            continue;
        };
        if rx.sent.iter().any(|s| s.first_seq == first_seq) {
            rx.forged.insert(first_seq);
        }
        rx.sent.push(Sent {
            peer: u.choose_index(PEERS.len())?,
            first_seq,
            send_ns,
            pulse,
            envelope,
            datagrams,
        });
    }

    for _ in 0..MAX_STEPS {
        if u.is_empty() {
            break;
        }
        match u.int_in_range(0..=9u8)? {
            // A fragment of a run, as sent, padded as FEC rebuilds it, or
            // with bytes after it; mostly from its own peer.
            0..=3 if !rx.sent.is_empty() => {
                let s = &rx.sent[u.choose_index(rx.sent.len())?];
                let mut bytes = s.datagrams[u.choose_index(s.datagrams.len())?].clone();
                let peer = if u.ratio(7, 8)? {
                    s.peer
                } else {
                    u.choose_index(PEERS.len())?
                };
                match u.int_in_range(0..=5u8)? {
                    0 => bytes.resize(bytes.len() + usize::from(u.arbitrary::<u8>()?), 0),
                    1 => bytes.extend_from_slice(take(&mut u, 32)?),
                    _ => {}
                }
                rx.datagram(&bytes, peer);
            }
            // A whole run, in order, from its peer.
            4 if !rx.sent.is_empty() => {
                let i = u.choose_index(rx.sent.len())?;
                // Lent out for the run, not copied: a run of a 64 KiB
                // envelope copied at every step churns enough memory to
                // run the sanitizer's quarantine past the fuzzer's limit.
                let (peer, datagrams) =
                    (rx.sent[i].peer, std::mem::take(&mut rx.sent[i].datagrams));
                for d in &datagrams {
                    rx.datagram(d, peer);
                }
                rx.sent[i].datagrams = datagrams;
            }
            // The clock moves on, sometimes past the timeout.
            5 => rx.now += u.int_in_range(0..=2 * timeout + 1)?,
            // A forged fragment that names a run's first sequence number,
            // or any.
            6 => {
                let first_seq = match rx.sent.len() {
                    n if n > 0 && u.ratio(3, 4)? => rx.sent[u.choose_index(n)?].first_seq,
                    _ => u.arbitrary()?,
                };
                let envelope = pattern(u.int_in_range(0..=4 * MTU_BYTES)?, u.arbitrary()?);
                let max_datagram = u.int_in_range(HEADER + 128 + CRC + 1..=MTU_BYTES)?;
                let pulse = [u.arbitrary()?; 128];
                let Some(run) = encode(first_seq, u.arbitrary()?, &pulse, &envelope, max_datagram)
                else {
                    continue;
                };
                rx.forged.insert(first_seq);
                let fragment = &run[u.choose_index(run.len())?];
                rx.datagram(fragment, u.choose_index(PEERS.len())?);
            }
            // Raw bytes, sometimes behind the magic, or a fragment of a run
            // cut short or with a bit flipped.
            7 => {
                let mut bytes = match rx.sent.len() {
                    n if n > 0 && u.ratio(1, 2)? => {
                        let s = &rx.sent[u.choose_index(n)?];
                        s.datagrams[u.choose_index(s.datagrams.len())?].clone()
                    }
                    _ if u.arbitrary()? => udp::FRAGMENT_MAGIC.to_vec(),
                    _ => Vec::new(),
                };
                match u.int_in_range(0..=2u8)? {
                    0 => bytes.truncate(u.int_in_range(0..=bytes.len())?),
                    1 if !bytes.is_empty() => {
                        let at = u.choose_index(bytes.len())?;
                        bytes[at] ^= 1 << u.int_in_range(0..=7u8)?;
                    }
                    _ => bytes.extend_from_slice(take(&mut u, 64)?),
                }
                if let Some(f) = udp::parse_fragment(&bytes) {
                    rx.forged.insert(f.first_seq);
                }
                rx.datagram(&bytes, u.choose_index(PEERS.len())?);
            }
            _ => continue,
        }
    }

    probe(&mut rx);
    Ok(())
}

/// A fresh run that fits the bounds, delivered whole from one peer, is
/// returned on its last fragment, as sent. Skipped when the bounds hold no
/// run of it, or the forged traffic took every sequence number tried.
fn probe(rx: &mut Rx) {
    let envelope = pattern(3 * MTU_BYTES, 0x5a);
    if rx.model.max_messages == 0 || rx.model.max_bytes < envelope.len() {
        return;
    }
    let Some(first_seq) = (1..=64u64)
        .map(|n| n.wrapping_mul(0x9e37_79b9_7f4a_7c15))
        .find(|s| !rx.forged.contains(s) && rx.sent.iter().all(|r| r.first_seq != *s))
    else {
        return;
    };
    let pulse = [0xc3; 128];
    let datagrams = encode(first_seq, 7, &pulse, &envelope, MTU_BYTES).expect("the probe fits");
    rx.sent.push(Sent {
        peer: 0,
        first_seq,
        send_ns: 7,
        pulse,
        envelope: envelope.clone(),
        datagrams: datagrams.clone(),
    });
    let last = datagrams.len() - 1;
    for (i, d) in datagrams.iter().enumerate() {
        let got = rx.datagram(d, 0);
        assert_eq!(
            got.is_some(),
            i == last,
            "the probe's run was returned at fragment {i} of {}",
            last + 1
        );
    }
}

/// `len` bytes counting up from `seed`.
fn pattern(len: usize, seed: u8) -> Vec<u8> {
    (0..len).map(|i| seed.wrapping_add(i as u8)).collect()
}
