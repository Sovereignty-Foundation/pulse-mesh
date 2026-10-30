// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! Fragmentation, opt-in: an envelope longer than one datagram carries, up
//! to [`MAX_MESSAGE`] bytes (the envelope store's entry size and room for
//! framing around it), goes as a run of fragment datagrams, and the receiver
//! reassembles it.
//!
//! Each fragment is a datagram of its own with a sequence number of its own,
//! the run's numbers consecutive, so backpressure, NACK retransmission, FEC
//! and congestion control treat fragments as they treat any frame, and a
//! lost fragment is requested or rebuilt alone. A fragment says which run
//! it belongs to (the first fragment's sequence number), its place in it,
//! how many there are and how long the whole envelope is; only the first
//! carries the Pulse.
//!
//! ## Layout (little-endian, no padding)
//!
//! ```text
//! magic "PMSG" (4) | v = 1 (1) | seq (8) | send_ns (8) | first_seq (8)
//! | index (u16) | count (u16) | total_len (u32) | chunk_len (u16)
//! | pulse (128 bytes, in the fragment at index 0 only)
//! | chunk (chunk_len bytes) | crc32c (4)
//! ```
//!
//! A fragment's `seq` is `first_seq + index`. Its chunk's length is in the
//! header, as a data frame's envelope length is, so bytes after the CRC are
//! not the fragment's: a fragment FEC rebuilds comes back padded to its
//! window's longest datagram, and decodes all the same. The receiver's
//! [`Reassembler`] keeps a bounded number of runs, and bytes, in progress,
//! drops a run that outlives its timeout or disagrees with itself, and
//! returns a run's envelope only once every fragment has arrived. With
//! sealing, each fragment is sealed as a datagram of its own, and only an
//! unsealed fragment reaches the reassembler, with the key of the peer whose
//! session opened it: a run is made only of fragments one key opened
//! ([`Reassembler::add_sealed`]).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use pulse_canon::{Pulse, PULSE_WIRE_SIZE};

use crate::sealed::PublicKey;
use crate::wire::{frame_crc, WireError, TRAILER_BYTES};

/// Magic prefixing every fragment: ASCII `"PMSG"` on the wire, beside the
/// data frame's `"PMSW"`, parity's `"PMSF"` and feedback's `"PMSA"` and `"PMSN"`.
pub const FRAG_MAGIC: u32 = u32::from_le_bytes(*b"PMSG");

/// Fragment format version.
pub const FRAG_VERSION: u8 = 1;

/// A fragment's header before the Pulse or the chunk:
/// `magic(4) + v(1) + seq(8) + send_ns(8) + first_seq(8) + index(2) +
/// count(2) + total_len(4) + chunk_len(2) = 39`.
pub const FRAG_HEADER_BYTES: usize = 4 + 1 + 8 + 8 + 8 + 2 + 2 + 4 + 2;

/// The longest envelope a run carries: the envelope store's entry size,
/// 64 KiB, and 1 KiB beside it, so that a stored envelope inside framing
/// of its own (a link's forward, about 90 bytes) still goes as one run.
pub const MAX_MESSAGE: usize = 65_536 + 1_024;

/// The most fragments in one run.
pub const MAX_FRAGMENTS: u16 = 1024;

const O_SEQ: usize = 5;
const O_SEND_NS: usize = 13;
const O_FIRST: usize = 21;
const O_INDEX: usize = 29;
const O_COUNT: usize = 31;
const O_TOTAL: usize = 33;
const O_CHUNK: usize = 37;

/// A decoded fragment, borrowing its chunk from the datagram.
#[derive(Debug, Clone, Copy)]
pub struct Fragment<'a> {
    /// This fragment's sequence number, `first_seq + index`.
    pub seq: u64,
    /// The sender's clock when it sent the run.
    pub send_ns: u64,
    /// The run's first sequence number, which names the run.
    pub first_seq: u64,
    /// This fragment's place in the run, from zero.
    pub index: u16,
    /// Fragments in the run.
    pub count: u16,
    /// The whole envelope's length.
    pub total_len: u32,
    /// The Pulse, in the fragment at index 0 only.
    pub pulse: Option<[u8; PULSE_WIRE_SIZE]>,
    /// This fragment's part of the envelope.
    pub chunk: &'a [u8],
}

/// The chunk a fragment at `index` carries in a datagram of
/// `max_datagram` bytes, or `None` when the datagram has no room for one.
fn chunk_room(max_datagram: usize, index: u16) -> Option<usize> {
    let pulse = if index == 0 { PULSE_WIRE_SIZE } else { 0 };
    max_datagram
        .checked_sub(FRAG_HEADER_BYTES + pulse + TRAILER_BYTES)
        .filter(|&room| room > 0)
}

/// Encode `envelope`, with `pulse`, as the run of fragments that starts at
/// `first_seq`, each datagram at most `max_datagram` bytes.
///
/// # Errors
/// [`WireError::EnvelopeTooLarge`] for an envelope over [`MAX_MESSAGE`],
/// or one that needs more than [`MAX_FRAGMENTS`] fragments of that size, or
/// a `max_datagram` with no room for a chunk.
pub fn encode_fragments(
    first_seq: u64,
    send_ns: u64,
    pulse: &Pulse,
    envelope: &[u8],
    max_datagram: usize,
) -> Result<Vec<Vec<u8>>, WireError> {
    let too_large = WireError::EnvelopeTooLarge {
        got: envelope.len(),
        max: MAX_MESSAGE,
    };
    if envelope.len() > MAX_MESSAGE {
        return Err(too_large);
    }
    let (Some(first), Some(rest)) = (chunk_room(max_datagram, 0), chunk_room(max_datagram, 1))
    else {
        return Err(too_large);
    };
    // A chunk's length is a u16.
    let (first, rest) = (
        first.min(usize::from(u16::MAX)),
        rest.min(usize::from(u16::MAX)),
    );
    let count = 1 + envelope.len().saturating_sub(first).div_ceil(rest);
    let Ok(count) = u16::try_from(count) else {
        return Err(too_large);
    };
    if count > MAX_FRAGMENTS {
        return Err(too_large);
    }
    let mut out = Vec::with_capacity(count as usize);
    let mut offset = 0;
    for index in 0..count {
        let room = if index == 0 { first } else { rest };
        let end = (offset + room).min(envelope.len());
        let mut datagram = Vec::with_capacity(max_datagram);
        datagram.extend_from_slice(&FRAG_MAGIC.to_le_bytes());
        datagram.push(FRAG_VERSION);
        datagram.extend_from_slice(&first_seq.wrapping_add(u64::from(index)).to_le_bytes());
        datagram.extend_from_slice(&send_ns.to_le_bytes());
        datagram.extend_from_slice(&first_seq.to_le_bytes());
        datagram.extend_from_slice(&index.to_le_bytes());
        datagram.extend_from_slice(&count.to_le_bytes());
        // Both fit: the envelope is at most MAX_MESSAGE, and a chunk at most
        // a u16.
        datagram.extend_from_slice(&(envelope.len() as u32).to_le_bytes());
        datagram.extend_from_slice(&((end - offset) as u16).to_le_bytes());
        if index == 0 {
            datagram.extend_from_slice(pulse.as_bytes());
        }
        datagram.extend_from_slice(&envelope[offset..end]);
        let crc = frame_crc(&datagram, &[]);
        datagram.extend_from_slice(&crc.to_le_bytes());
        out.push(datagram);
        offset = end;
    }
    Ok(out)
}

/// Decode a fragment datagram, checking its length, magic, version, chunk
/// length and CRC32C (bytes after the CRC, such as the padding of a fragment
/// rebuilt from parity, are not the fragment's), then that it agrees with
/// itself: `index < count <=` [`MAX_FRAGMENTS`], `total_len <=`
/// [`MAX_MESSAGE`] and `seq == first_seq + index`. The fragment at index 0
/// carries the Pulse.
///
/// # Errors
/// The [`WireError`] of the first check that fails;
/// [`WireError::InvalidFragment`] for a fragment that disagrees with
/// itself.
pub fn decode_fragment(buf: &[u8]) -> Result<Fragment<'_>, WireError> {
    let min = FRAG_HEADER_BYTES + TRAILER_BYTES;
    if buf.len() < min {
        return Err(WireError::BufferTooSmall {
            got: buf.len(),
            min,
        });
    }
    let u16_at = |at: usize| u16::from_le_bytes([buf[at], buf[at + 1]]);
    let u32_at = |at: usize| u32::from_le_bytes([buf[at], buf[at + 1], buf[at + 2], buf[at + 3]]);
    let u64_at = |at: usize| {
        let mut b = [0u8; 8];
        b.copy_from_slice(&buf[at..at + 8]);
        u64::from_le_bytes(b)
    };
    let magic = u32_at(0);
    if magic != FRAG_MAGIC {
        return Err(WireError::BadMagic {
            got: magic,
            expected: FRAG_MAGIC,
        });
    }
    if buf[4] != FRAG_VERSION {
        return Err(WireError::UnsupportedVersion {
            got: buf[4],
            expected: FRAG_VERSION,
        });
    }
    let index = u16_at(O_INDEX);
    let pulse_len = if index == 0 { PULSE_WIRE_SIZE } else { 0 };
    let crc_off = FRAG_HEADER_BYTES + pulse_len + usize::from(u16_at(O_CHUNK));
    if crc_off + TRAILER_BYTES > buf.len() {
        return Err(WireError::BufferTooSmall {
            got: buf.len(),
            min: crc_off + TRAILER_BYTES,
        });
    }
    let crc_got = u32_at(crc_off);
    let crc_computed = frame_crc(&buf[..crc_off], &[]);
    if crc_got != crc_computed {
        return Err(WireError::CrcMismatch {
            got: crc_got,
            computed: crc_computed,
        });
    }
    let (seq, first_seq) = (u64_at(O_SEQ), u64_at(O_FIRST));
    let (count, total_len) = (u16_at(O_COUNT), u32_at(O_TOTAL));
    if count == 0 || count > MAX_FRAGMENTS || index >= count {
        return Err(WireError::InvalidFragment("index or count out of range"));
    }
    if total_len as usize > MAX_MESSAGE {
        return Err(WireError::InvalidFragment("total length over MAX_MESSAGE"));
    }
    if seq != first_seq.wrapping_add(u64::from(index)) {
        return Err(WireError::InvalidFragment("seq is not first_seq + index"));
    }
    let (pulse, chunk_off) = if index == 0 {
        let end = FRAG_HEADER_BYTES + PULSE_WIRE_SIZE;
        let mut pulse = [0u8; PULSE_WIRE_SIZE];
        pulse.copy_from_slice(&buf[FRAG_HEADER_BYTES..end]);
        (Some(pulse), end)
    } else {
        (None, FRAG_HEADER_BYTES)
    };
    Ok(Fragment {
        seq,
        send_ns: u64_at(O_SEND_NS),
        first_seq,
        index,
        count,
        total_len,
        pulse,
        chunk: &buf[chunk_off..crc_off],
    })
}

/// Bounds on what a [`Reassembler`] holds.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReassemblyConfig {
    /// Runs in progress at once; past it the oldest is dropped. Default 64.
    pub max_messages: usize,
    /// Bytes reserved for runs in progress (each run reserves its whole
    /// envelope's length); past it the oldest are dropped. Default 4 MiB.
    pub max_bytes: usize,
    /// How long a run may stay incomplete before it is dropped. Default
    /// one second.
    pub timeout: Duration,
}

impl Default for ReassemblyConfig {
    fn default() -> Self {
        Self {
            max_messages: 64,
            max_bytes: 4 << 20,
            timeout: Duration::from_secs(1),
        }
    }
}

/// A run reassembled whole.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    /// The run's Pulse.
    pub pulse: Pulse,
    /// The whole envelope.
    pub envelope: Vec<u8>,
    /// The run's first sequence number.
    pub first_seq: u64,
    /// Fragments in the run: it spans the sequence numbers from
    /// `first_seq`, this many.
    pub count: u16,
    /// The sender's clock when it sent the run.
    pub send_ns: u64,
}

/// A run in progress.
struct Partial {
    count: u16,
    total_len: u32,
    send_ns: u64,
    pulse: Option<[u8; PULSE_WIRE_SIZE]>,
    chunks: Vec<Option<Vec<u8>>>,
    have: u16,
    bytes: usize,
    started: Instant,
    /// Order of arrival among the runs, which decides the oldest.
    serial: u64,
}

/// A run's place among those in progress: the address its fragments came
/// from, the key of the session that opened them (`None` in plaintext), and
/// its first sequence number.
type RunKey = (SocketAddr, Option<PublicKey>, u64);

/// Reassembles runs of fragments, per sender and run, within the bounds of
/// its [`ReassemblyConfig`]. With sealing, a sender is its address and the
/// key that opened its fragments, so a run is made only of fragments one
/// peer's session opened.
pub struct Reassembler {
    cfg: ReassemblyConfig,
    partials: HashMap<RunKey, Partial>,
    /// Bytes reserved by the runs in progress.
    reserved: usize,
    completed: u64,
    dropped: u64,
    /// The next run's [`Partial::serial`].
    next_serial: u64,
}

impl Reassembler {
    /// A reassembler holding nothing yet.
    #[must_use]
    pub fn new(cfg: ReassemblyConfig) -> Self {
        Self {
            cfg,
            partials: HashMap::new(),
            reserved: 0,
            completed: 0,
            dropped: 0,
            next_serial: 0,
        }
    }

    /// Take `fragment`, which arrived from `peer` at `now`; returns the run
    /// it completes, if it does. A repeated fragment changes nothing; one
    /// that disagrees with its run's others (its count, total length or
    /// send time, or chunks longer than the total) drops the run. A run
    /// that cannot be held at all, longer than `max_bytes` or with
    /// `max_messages` zero, is dropped fragment by fragment.
    pub fn add(
        &mut self,
        fragment: &Fragment<'_>,
        peer: SocketAddr,
        now: Instant,
    ) -> Option<Message> {
        self.add_sealed(fragment, peer, None, now)
    }

    /// [`Self::add`] for a fragment the session of the peer whose key is
    /// `sealed_by` opened (`None` for one taken in plaintext): it joins only
    /// a run of fragments that key opened, so a fragment another peer seals,
    /// whatever its source address, starts a run of its own and cannot
    /// complete or spoil this one.
    pub fn add_sealed(
        &mut self,
        fragment: &Fragment<'_>,
        peer: SocketAddr,
        sealed_by: Option<PublicKey>,
        now: Instant,
    ) -> Option<Message> {
        self.expire(now);
        let total = fragment.total_len as usize;
        if total > self.cfg.max_bytes || self.cfg.max_messages == 0 {
            self.dropped = self.dropped.wrapping_add(1);
            return None;
        }
        let key = (peer, sealed_by, fragment.first_seq);
        if !self.partials.contains_key(&key) {
            while !self.partials.is_empty()
                && (self.partials.len() >= self.cfg.max_messages
                    || self.reserved + total > self.cfg.max_bytes)
            {
                self.drop_oldest();
            }
            self.reserved += total;
            self.next_serial += 1;
            self.partials.insert(
                key,
                Partial {
                    count: fragment.count,
                    total_len: fragment.total_len,
                    send_ns: fragment.send_ns,
                    pulse: None,
                    chunks: vec![None; fragment.count as usize],
                    have: 0,
                    bytes: 0,
                    started: now,
                    serial: self.next_serial,
                },
            );
        }
        let partial = self.partials.get_mut(&key)?;
        let index = fragment.index as usize;
        if partial.count != fragment.count
            || partial.total_len != fragment.total_len
            || partial.send_ns != fragment.send_ns
        {
            self.drop_run(&key);
            return None;
        }
        if partial.chunks[index].is_some() {
            return None;
        }
        partial.bytes += fragment.chunk.len();
        if partial.bytes > total {
            self.drop_run(&key);
            return None;
        }
        partial.chunks[index] = Some(fragment.chunk.to_vec());
        if let Some(pulse) = fragment.pulse {
            partial.pulse = Some(pulse);
        }
        partial.have += 1;
        if partial.have < partial.count {
            return None;
        }
        let partial = self.partials.remove(&key)?;
        self.reserved -= total;
        let pulse = partial.pulse.as_ref().map(Pulse::from_array);
        let envelope: Vec<u8> = partial.chunks.into_iter().flatten().flatten().collect();
        match pulse {
            Some(pulse) if envelope.len() == total => {
                self.completed = self.completed.wrapping_add(1);
                Some(Message {
                    pulse,
                    envelope,
                    first_seq: fragment.first_seq,
                    count: partial.count,
                    send_ns: partial.send_ns,
                })
            }
            _ => {
                self.dropped = self.dropped.wrapping_add(1);
                None
            }
        }
    }

    /// Runs in progress.
    pub fn in_progress(&self) -> usize {
        self.partials.len()
    }

    /// Bytes reserved by the runs in progress.
    pub fn reserved_bytes(&self) -> usize {
        self.reserved
    }

    /// Runs reassembled whole.
    pub fn completed_count(&self) -> u64 {
        self.completed
    }

    /// Runs dropped: timed out, pushed out by the bounds, or disagreeing
    /// with themselves; and each fragment of a run too large to hold.
    pub fn dropped_count(&self) -> u64 {
        self.dropped
    }

    /// Drop the runs older than the timeout.
    fn expire(&mut self, now: Instant) {
        let timeout = self.cfg.timeout;
        let stale: Vec<_> = self
            .partials
            .iter()
            .filter(|(_, p)| now.saturating_duration_since(p.started) > timeout)
            .map(|(key, _)| *key)
            .collect();
        for key in stale {
            self.drop_run(&key);
        }
    }

    fn drop_oldest(&mut self) {
        if let Some(key) = self
            .partials
            .iter()
            .min_by_key(|(_, p)| p.serial)
            .map(|(key, _)| *key)
        {
            self.drop_run(&key);
        }
    }

    fn drop_run(&mut self, key: &RunKey) {
        if let Some(partial) = self.partials.remove(key) {
            self.reserved -= partial.total_len as usize;
            self.dropped = self.dropped.wrapping_add(1);
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::wire::MTU_BYTES;

    fn peer() -> SocketAddr {
        "127.0.0.1:9".parse().unwrap()
    }

    fn pulse(step: u64) -> Pulse {
        let mut p = Pulse::zeroed();
        p.chain_step = step;
        p
    }

    fn envelope(len: usize, seed: u8) -> Vec<u8> {
        (0..len)
            .map(|i| (i as u8).wrapping_mul(13).wrapping_add(seed))
            .collect()
    }

    #[test]
    fn a_run_round_trips_through_encode_decode_and_reassembly() {
        for len in [0, 1, 1000, 1306, 1307, 5000, MAX_MESSAGE] {
            let env = envelope(len, 3);
            let frags = encode_fragments(100, 7, &pulse(5), &env, MTU_BYTES).unwrap();
            assert!(frags.iter().all(|d| d.len() <= MTU_BYTES));
            let mut r = Reassembler::new(ReassemblyConfig::default());
            let now = Instant::now();
            let mut done = None;
            for (i, d) in frags.iter().enumerate() {
                let f = decode_fragment(d).unwrap();
                assert_eq!(
                    (f.seq, f.first_seq, f.index as usize),
                    (100 + i as u64, 100, i)
                );
                done = r.add(&f, peer(), now);
                assert_eq!(done.is_some(), i + 1 == frags.len());
            }
            let m = done.unwrap();
            assert_eq!((m.envelope, m.first_seq, m.send_ns), (env, 100, 7));
            assert_eq!(m.pulse.chain_step, 5);
            assert_eq!((r.in_progress(), r.reserved_bytes()), (0, 0));
        }
    }

    #[test]
    fn a_fragment_padded_as_fec_rebuilds_it_decodes_the_same() {
        let frags = encode_fragments(5, 1, &pulse(2), &envelope(3000, 4), MTU_BYTES).unwrap();
        let last = frags.last().unwrap();
        let mut padded = last.clone();
        padded.resize(MTU_BYTES, 0);
        let (a, b) = (
            decode_fragment(last).unwrap(),
            decode_fragment(&padded).unwrap(),
        );
        assert_eq!((a.seq, a.index, a.chunk), (b.seq, b.index, b.chunk));
    }

    #[test]
    fn fragments_in_any_order_with_repeats_reassemble_once() {
        let env = envelope(9000, 1);
        let frags = encode_fragments(0, 0, &pulse(1), &env, 600).unwrap();
        let mut order: Vec<usize> = (0..frags.len()).rev().collect();
        order.insert(3, 0);
        order.push(2);
        let mut r = Reassembler::new(ReassemblyConfig::default());
        let got: Vec<_> = order
            .iter()
            .filter_map(|&i| r.add(&decode_fragment(&frags[i]).unwrap(), peer(), Instant::now()))
            .collect();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].envelope, env);
    }

    #[test]
    fn two_senders_runs_with_one_first_seq_do_not_mix() {
        let (a, b) = (envelope(4000, 1), envelope(4000, 2));
        let fa = encode_fragments(0, 0, &pulse(1), &a, MTU_BYTES).unwrap();
        let fb = encode_fragments(0, 0, &pulse(2), &b, MTU_BYTES).unwrap();
        let other: SocketAddr = "127.0.0.1:10".parse().unwrap();
        let mut r = Reassembler::new(ReassemblyConfig::default());
        let now = Instant::now();
        let mut done = Vec::new();
        for (x, y) in fa.iter().zip(&fb) {
            done.extend(r.add(&decode_fragment(x).unwrap(), peer(), now));
            done.extend(r.add(&decode_fragment(y).unwrap(), other, now));
        }
        assert_eq!(done.len(), 2);
        assert!(done.iter().any(|m| m.envelope == a) && done.iter().any(|m| m.envelope == b));
    }

    /// Fragments from one address that two peers' sessions opened are two
    /// runs: one peer's fragment, whatever address it comes from, neither
    /// completes nor spoils the other's run.
    #[test]
    fn fragments_two_keys_opened_at_one_address_do_not_mix() {
        let (a, b) = (envelope(4000, 1), envelope(4000, 2));
        let fa = encode_fragments(0, 0, &pulse(1), &a, MTU_BYTES).unwrap();
        let fb = encode_fragments(0, 0, &pulse(2), &b, MTU_BYTES).unwrap();
        let (ka, kb) = (
            Some(PublicKey::from_bytes([1; 32])),
            Some(PublicKey::from_bytes([2; 32])),
        );
        let mut r = Reassembler::new(ReassemblyConfig::default());
        let now = Instant::now();
        // B's last fragment, sent from A's address, does not finish A's run.
        for x in &fa[..fa.len() - 1] {
            assert!(r
                .add_sealed(&decode_fragment(x).unwrap(), peer(), ka, now)
                .is_none());
        }
        let last = decode_fragment(fb.last().unwrap()).unwrap();
        assert!(r.add_sealed(&last, peer(), kb, now).is_none());
        let done = r
            .add_sealed(
                &decode_fragment(fa.last().unwrap()).unwrap(),
                peer(),
                ka,
                now,
            )
            .expect("A's run completes with A's fragment");
        assert_eq!(done.envelope, a);
        let mut b_run = None;
        for y in &fb[..fb.len() - 1] {
            b_run = r.add_sealed(&decode_fragment(y).unwrap(), peer(), kb, now);
        }
        assert_eq!(b_run.expect("B's run, from its own fragments").envelope, b);
        assert_eq!(r.in_progress(), 0);
    }

    #[test]
    fn the_bounds_and_the_timeout_drop_runs_in_progress() {
        let env = envelope(3000, 0);
        let mut r = Reassembler::new(ReassemblyConfig {
            max_messages: 2,
            timeout: Duration::from_millis(10),
            ..Default::default()
        });
        let t0 = Instant::now();
        for first in [0u64, 100, 200] {
            let frags = encode_fragments(first, 0, &pulse(0), &env, MTU_BYTES).unwrap();
            assert!(r
                .add(&decode_fragment(&frags[0]).unwrap(), peer(), t0)
                .is_none());
        }
        assert_eq!(
            (r.in_progress(), r.dropped_count()),
            (2, 1),
            "the oldest went for the third"
        );
        assert_eq!(r.reserved_bytes(), 2 * env.len());
        let frags = encode_fragments(300, 0, &pulse(0), &env, MTU_BYTES).unwrap();
        r.add(
            &decode_fragment(&frags[0]).unwrap(),
            peer(),
            t0 + Duration::from_millis(50),
        );
        assert_eq!(
            (r.in_progress(), r.dropped_count()),
            (1, 3),
            "the two old ones timed out"
        );

        let mut r = Reassembler::new(ReassemblyConfig {
            max_bytes: 2000,
            ..Default::default()
        });
        let frags = encode_fragments(0, 0, &pulse(0), &env, MTU_BYTES).unwrap();
        assert!(r
            .add(&decode_fragment(&frags[0]).unwrap(), peer(), t0)
            .is_none());
        assert_eq!(
            (r.in_progress(), r.dropped_count()),
            (0, 1),
            "a run over max_bytes is refused"
        );
    }

    #[test]
    fn a_fragment_that_disagrees_with_its_run_drops_the_run() {
        let a = encode_fragments(0, 0, &pulse(0), &envelope(3000, 0), MTU_BYTES).unwrap();
        let longer = encode_fragments(0, 0, &pulse(0), &envelope(5000, 0), MTU_BYTES).unwrap();
        let later = encode_fragments(0, 1, &pulse(0), &envelope(3000, 0), MTU_BYTES).unwrap();
        for other in [&longer, &later] {
            let mut r = Reassembler::new(ReassemblyConfig::default());
            let now = Instant::now();
            assert!(r
                .add(&decode_fragment(&a[0]).unwrap(), peer(), now)
                .is_none());
            assert!(r
                .add(&decode_fragment(&other[1]).unwrap(), peer(), now)
                .is_none());
            assert_eq!((r.in_progress(), r.dropped_count()), (0, 1));
        }
    }

    #[test]
    fn the_run_dropped_for_room_is_the_first_to_start() {
        let env = envelope(3000, 0);
        let runs: Vec<_> = [0u64, 100, 200]
            .into_iter()
            .map(|first| encode_fragments(first, 0, &pulse(0), &env, MTU_BYTES).unwrap())
            .collect();
        // All at one instant, many times over: the order they started in
        // decides, not the clock or the table's order.
        for _ in 0..32 {
            let mut r = Reassembler::new(ReassemblyConfig {
                max_messages: 2,
                ..Default::default()
            });
            let now = Instant::now();
            for run in &runs {
                assert!(r
                    .add(&decode_fragment(&run[0]).unwrap(), peer(), now)
                    .is_none());
            }
            for run in &runs[1..] {
                let done = run[1..]
                    .iter()
                    .map(|d| r.add(&decode_fragment(d).unwrap(), peer(), now))
                    .last()
                    .unwrap();
                assert!(done.is_some(), "a later run was dropped for the third");
            }
        }
    }

    #[test]
    fn decode_refuses_bent_fragments() {
        let good = encode_fragments(10, 0, &pulse(0), &envelope(2000, 0), MTU_BYTES).unwrap();
        let mut bad = good[1].clone();
        let last = bad.len() - 1;
        bad[last] ^= 1;
        assert!(matches!(
            decode_fragment(&bad),
            Err(WireError::CrcMismatch { .. })
        ));
        let reseal = |mut d: Vec<u8>, at: usize, bytes: &[u8]| {
            d[at..at + bytes.len()].copy_from_slice(bytes);
            // Fragment 1 carries no Pulse, and its chunk runs to the trailer.
            let crc_off = d.len() - TRAILER_BYTES;
            let crc = frame_crc(&d[..crc_off], &[]);
            d[crc_off..].copy_from_slice(&crc.to_le_bytes());
            d
        };
        for (at, bytes) in [
            (O_INDEX, 9u16.to_le_bytes().to_vec()),
            (O_COUNT, 0u16.to_le_bytes().to_vec()),
            (O_TOTAL, (MAX_MESSAGE as u32 + 1).to_le_bytes().to_vec()),
            (O_SEQ, 99u64.to_le_bytes().to_vec()),
        ] {
            assert!(matches!(
                decode_fragment(&reseal(good[1].clone(), at, &bytes)),
                Err(WireError::InvalidFragment(_))
            ));
        }
        assert!(matches!(
            decode_fragment(&good[0][..20]),
            Err(WireError::BufferTooSmall { .. })
        ));
    }

    #[test]
    fn encode_refuses_what_cannot_be_sent() {
        assert!(
            encode_fragments(0, 0, &pulse(0), &envelope(MAX_MESSAGE + 1, 0), MTU_BYTES).is_err()
        );
        assert!(
            encode_fragments(0, 0, &pulse(0), &envelope(10, 0), 100).is_err(),
            "no room for a chunk"
        );
        // The smallest datagram with room for a chunk still carries
        // MAX_MESSAGE within MAX_FRAGMENTS, and every fragment decodes.
        let tiny = FRAG_HEADER_BYTES + PULSE_WIRE_SIZE + TRAILER_BYTES + 1;
        let frags = encode_fragments(0, 0, &pulse(0), &envelope(MAX_MESSAGE, 0), tiny).unwrap();
        assert!(frags.len() <= MAX_FRAGMENTS as usize);
        assert!(frags
            .iter()
            .all(|d| d.len() <= tiny && decode_fragment(d).is_ok()));
    }
}
