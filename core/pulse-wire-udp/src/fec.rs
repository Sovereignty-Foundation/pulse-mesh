// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! Forward error correction: single-parity XOR over windows of K frames.
//!
//! A receiver rebuilds one lost frame per window without a round trip; a
//! window that loses more falls through to NACK recovery. Windows are
//! aligned: window `w` is the frames with sequence numbers `w·K` to
//! `w·K + K − 1`, so a data frame, which carries no window, is placed by
//! its sequence number alone. The sender's [`FecEncoder`] emits a parity
//! datagram on the data socket after each window's last frame; the
//! receiver's [`FecDecoder`] rebuilds, admitting parity on its own terms,
//! since nothing authenticates it.
//!
//! ## Wire format
//!
//! ```text
//! +--------+--------------+----------+------------+----------------+
//! | magic | window_start | window_n | parity_len | parity_bytes |
//! | 4 B | 8 B | 2 B | 4 B | parity_len B |
//! +--------+--------------+----------+------------+----------------+
//! ```
//!
//! `magic` is [`FEC_MAGIC`], `window_n` is K, `window_start` a multiple of
//! K, and `parity_bytes` the XOR of the window's frames, each zero-padded
//! to the longest; [`FEC_MAX_ENVELOPE`] keeps it within one datagram.

use std::collections::{BTreeMap, HashMap};

/// Magic prefixing every FEC parity datagram: `0x50 0x4D 0x53 0x46`,
/// ASCII `"PMSF"`, on the wire. Distinct from the data, ACK and NACK
/// magics, so a receiver dispatches on the first 4 bytes.
pub const FEC_MAGIC: u32 = 0x46534D50;

/// FEC datagram header length: `magic(4) + window_start(8) +
/// window_n(2) + parity_len(4) = 18` bytes.
pub const FEC_HEADER_BYTES: usize = 4 + 8 + 2 + 4;

/// The largest envelope a [`Sender`](crate::Sender) with FEC on accepts,
/// 1,297 bytes: [`MAX_ENVELOPE`](crate::wire::MAX_ENVELOPE) less
/// [`FEC_HEADER_BYTES`], so that a parity datagram, the FEC header and the
/// XOR of the longest frame, fits one
/// [`MTU_BYTES`](crate::wire::MTU_BYTES) datagram as a data frame does. A
/// full-size envelope would make its parity 1,490 bytes, cut short by
/// every receiver's one-MTU buffer and never decoded.
pub const FEC_MAX_ENVELOPE: usize = crate::wire::MAX_ENVELOPE - FEC_HEADER_BYTES;

/// Default FEC window — one parity per 16 originals (~6% bandwidth
/// for single-loss recovery).
pub const DEFAULT_FEC_WINDOW: u16 = 16;

#[non_exhaustive]
/// Errors raised by [`encode_fec`] / [`decode_fec`].
#[derive(Debug, thiserror::Error)]
pub enum FecError {
    /// Buffer is shorter than [`FEC_HEADER_BYTES`].
    #[error("FEC datagram too short: {len} bytes, need at least {min}")]
    TooShort {
        /// Length on the wire.
        len: usize,
        /// Minimum length ([`FEC_HEADER_BYTES`]).
        min: usize,
    },
    /// First 4 bytes don't match [`FEC_MAGIC`].
    #[error("FEC magic mismatch: got 0x{got:08x}, expected 0x{expected:08x}")]
    MagicMismatch {
        /// Magic on the wire.
        got: u32,
        /// Expected magic ([`FEC_MAGIC`]).
        expected: u32,
    },
    /// Length-prefix says the parity payload is `parity_len` bytes
    /// but the buffer doesn't actually carry that many.
    #[error("FEC parity length truncated: header says {parity_len}, buffer has {available}")]
    Truncated {
        /// Declared parity length.
        parity_len: u32,
        /// Bytes available after the header.
        available: usize,
    },
    /// The header declares a window of zero frames, which could rebuild
    /// nothing; refused here, before it reaches the decoder's arithmetic.
    #[error("FEC window_n must be at least 1, got {window_n}")]
    InvalidWindow {
        /// Declared window size.
        window_n: u16,
    },
}

/// Decoded FEC datagram header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FecHeader {
    /// First seq in the window the parity covers.
    pub window_start: u64,
    /// Window size `K`.
    pub window_n: u16,
    /// Length of the parity payload in bytes.
    pub parity_len: u32,
}

/// Write one parity datagram, `header` then `parity_bytes`, into `out`,
/// which is cleared first. `parity_bytes` must be `header.parity_len` long.
pub fn encode_fec(header: FecHeader, parity_bytes: &[u8], out: &mut Vec<u8>) {
    out.clear();
    out.extend_from_slice(&FEC_MAGIC.to_le_bytes());
    out.extend_from_slice(&header.window_start.to_le_bytes());
    out.extend_from_slice(&header.window_n.to_le_bytes());
    debug_assert_eq!(parity_bytes.len() as u32, header.parity_len);
    out.extend_from_slice(&header.parity_len.to_le_bytes());
    out.extend_from_slice(parity_bytes);
}

/// Decode an FEC datagram. Returns the parsed header and a slice
/// pointing at the parity payload inside `bytes`.
///
/// # Errors
///
/// - [`FecError::TooShort`] if `bytes` is shorter than
///   [`FEC_HEADER_BYTES`].
/// - [`FecError::MagicMismatch`] if it does not start with [`FEC_MAGIC`].
/// - [`FecError::InvalidWindow`] if the header declares `window_n == 0`.
/// - [`FecError::Truncated`] if fewer than `parity_len` bytes follow the
///   header.
pub fn decode_fec(bytes: &[u8]) -> Result<(FecHeader, &[u8]), FecError> {
    let (magic_b, rest) = bytes.split_first_chunk::<4>().ok_or(FecError::TooShort {
        len: bytes.len(),
        min: FEC_HEADER_BYTES,
    })?;
    let (ws_b, rest) = rest.split_first_chunk::<8>().ok_or(FecError::TooShort {
        len: bytes.len(),
        min: FEC_HEADER_BYTES,
    })?;
    let (wn_b, rest) = rest.split_first_chunk::<2>().ok_or(FecError::TooShort {
        len: bytes.len(),
        min: FEC_HEADER_BYTES,
    })?;
    let (pl_b, _) = rest.split_first_chunk::<4>().ok_or(FecError::TooShort {
        len: bytes.len(),
        min: FEC_HEADER_BYTES,
    })?;

    let magic = u32::from_le_bytes(*magic_b);
    if magic != FEC_MAGIC {
        return Err(FecError::MagicMismatch {
            got: magic,
            expected: FEC_MAGIC,
        });
    }
    let window_start = u64::from_le_bytes(*ws_b);
    let window_n = u16::from_le_bytes(*wn_b);
    if window_n == 0 {
        return Err(FecError::InvalidWindow { window_n });
    }
    let parity_len = u32::from_le_bytes(*pl_b);
    let available = bytes.len() - FEC_HEADER_BYTES;
    if (parity_len as usize) > available {
        return Err(FecError::Truncated {
            parity_len,
            available,
        });
    }
    Ok((
        FecHeader {
            window_start,
            window_n,
            parity_len,
        },
        &bytes[FEC_HEADER_BYTES..FEC_HEADER_BYTES + parity_len as usize],
    ))
}

/// The sender's side: [`FecEncoder::add_original`] folds each frame sent
/// into its window's XOR and returns the parity datagram after the window's
/// last frame. An encoder that starts mid-window, as FEC enabled at a
/// sequence number not a multiple of K does, sends no parity until the next
/// window.
pub struct FecEncoder {
    window_size: u16,
    /// First sequence number of the window in progress, a multiple of K.
    window_start: u64,
    /// Originals added to the window in progress; 0 when none is.
    count: u16,
    /// Accumulated XOR; grows to the longest original seen.
    parity: Vec<u8>,
}

impl FecEncoder {
    /// An encoder for windows of `window_size` frames; 0 is taken as 1.
    pub fn new(window_size: u16) -> Self {
        Self {
            window_size: window_size.max(1),
            window_start: 0,
            count: 0,
            parity: Vec::new(),
        }
    }

    /// Add the encoded frame sent as `seq`; returns the parity datagram,
    /// [`FEC_HEADER_BYTES`] longer than the window's longest frame, when
    /// `seq` completes its window. A caller that drives the encoder itself
    /// keeps envelopes within [`FEC_MAX_ENVELOPE`], as the sender does.
    ///
    /// Frames go in in the order sent. One that does not continue the
    /// window in progress abandons it, and one that is not the first of its
    /// window starts nothing.
    pub fn add_original(&mut self, seq: u64, bytes: &[u8]) -> Option<Vec<u8>> {
        let k = u64::from(self.window_size);
        let offset = seq % k;
        let window_start = seq - offset;
        if self.count > 0 && (window_start != self.window_start || offset != u64::from(self.count))
        {
            self.reset();
        }
        if self.count == 0 {
            if offset != 0 {
                return None;
            }
            self.window_start = window_start;
        }
        if bytes.len() > self.parity.len() {
            self.parity.resize(bytes.len(), 0);
        }
        for (i, b) in bytes.iter().enumerate() {
            self.parity[i] ^= *b;
        }
        self.count += 1;
        if self.count < self.window_size {
            return None;
        }
        let header = FecHeader {
            window_start: self.window_start,
            window_n: self.window_size,
            parity_len: self.parity.len() as u32,
        };
        let mut out = Vec::with_capacity(FEC_HEADER_BYTES + self.parity.len());
        encode_fec(header, &self.parity, &mut out);
        self.reset();
        Some(out)
    }

    /// Forget the window in progress.
    fn reset(&mut self) {
        self.parity.clear();
        self.count = 0;
    }

    /// Frames in the window in progress; 0 when none is. Diagnostic.
    pub fn pending_count(&self) -> u16 {
        self.count
    }

    /// Window size.
    pub fn window_size(&self) -> u16 {
        self.window_size
    }
}

/// The receiver's side: rebuilds a window's one lost frame from its other
/// K − 1 and its parity.
///
/// A data frame is filed under its window, a parity datagram under the
/// window its header names. The call that brings a window to K − 1 frames
/// and its parity returns `Some((missing_seq, bytes))`, the lost frame's
/// encoded bytes zero-padded to the parity's length, which `wire::decode`
/// reads; the window then closes, as one does that got all K frames and
/// its parity.
///
/// Nothing authenticates a datagram, and the table holds at most
/// `max_windows` windows, so parity is admitted on the decoder's terms:
///
/// - Parity whose window size is not K, or whose start is not a multiple of
///   K, is refused: no sender's parity looks like that.
/// - Parity that would open a window is refused when the window starts
///   more than `K · max_windows` sequence numbers beyond the highest data
///   frame received, or when no room can be made for it.
/// - A full table makes room by dropping, least recently used first, a
///   window that holds all K frames, else one opened by parity alone,
///   else, for a data frame only, one that frames are filling.
///
/// So parity, forged or not, never pushes out a window the stream is
/// filling, and windows forged data frames opened give way when the stream
/// needs their places. Refusals and drops are counted.
pub struct FecDecoder {
    /// `window_start` -> window state.
    windows: HashMap<u64, FecWindow>,
    /// K: frames per window.
    window_size: u16,
    /// Maximum number of windows kept at once.
    max_windows: usize,
    /// The highest sequence number of any data frame added: parity may open
    /// a window at most `span()` beyond it.
    highest_seq: Option<u64>,
    /// Advances with every datagram, so windows can be ordered by last use.
    clock: u64,
    /// Parity datagrams refused.
    refused: u64,
    /// Windows dropped to make room for another.
    evicted: u64,
}

/// What a window can still do. The order is the order in which a full
/// table gives windows up, lowest first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Standing {
    /// All K frames arrived; the window waits only for its parity, which
    /// closes it.
    Complete,
    /// Only parity has arrived.
    ParityOnly,
    /// Some frames have arrived, not all.
    Filling,
}

#[derive(Debug, Default)]
struct FecWindow {
    /// Originals received, indexed by seq; emptied once all K are in.
    originals: BTreeMap<u64, Vec<u8>>,
    /// All K originals arrived.
    complete: bool,
    /// Parity bytes, when received.
    parity: Option<Vec<u8>>,
    /// The decoder's clock when a datagram last reached the window.
    last_used: u64,
}

impl FecDecoder {
    /// A decoder for windows of `window_size` frames, the sender's K (0 is
    /// taken as 1, as [`FecEncoder::new`] takes it), tracking at most
    /// `max_windows` windows at once (0 is taken as 1).
    pub fn new(window_size: u16, max_windows: usize) -> Self {
        Self {
            windows: HashMap::new(),
            window_size: window_size.max(1),
            max_windows: max_windows.max(1),
            highest_seq: None,
            clock: 0,
            refused: 0,
            evicted: 0,
        }
    }

    /// Add an original frame: its seq and the full encoded datagram bytes.
    /// Returns `Some((recovered_seq, recovered_bytes))` if this arrival
    /// completes a recoverable window (`K - 1` originals + parity in hand).
    pub fn add_original(&mut self, seq: u64, bytes: &[u8]) -> Option<(u64, Vec<u8>)> {
        let start = seq - seq % u64::from(self.window_size);
        self.highest_seq = Some(self.highest_seq.map_or(seq, |h| h.max(seq)));
        if !self.windows.contains_key(&start) {
            // A data frame's window may take any place: this succeeds.
            self.make_room(Standing::Filling);
        }
        let now = self.tick();
        let window = self.windows.entry(start).or_default();
        window.last_used = now;
        if window.complete {
            // A repeat of a frame in a window with nothing left to rebuild.
            return None;
        }
        window.originals.insert(seq, bytes.to_vec());
        self.settle(start)
    }

    /// Add a parity datagram. Returns `Some((recovered_seq,
    /// recovered_bytes))` if the parity completes a recoverable window.
    /// Parity the decoder does not admit ([`FecDecoder`] has the rules) is
    /// refused and counted.
    pub fn add_parity(&mut self, header: FecHeader, parity_bytes: &[u8]) -> Option<(u64, Vec<u8>)> {
        let start = header.window_start;
        if header.window_n != self.window_size || !start.is_multiple_of(u64::from(self.window_size))
        {
            self.refused += 1;
            return None;
        }
        if !self.windows.contains_key(&start) {
            let too_far = self
                .highest_seq
                .is_some_and(|highest| start > highest.saturating_add(self.span()));
            if too_far || !self.make_room(Standing::ParityOnly) {
                self.refused += 1;
                return None;
            }
        }
        let now = self.tick();
        let window = self.windows.entry(start).or_default();
        window.last_used = now;
        if window.complete {
            // Every frame arrived: the parity closes the window.
            self.windows.remove(&start);
            return None;
        }
        window.parity = Some(parity_bytes.to_vec());
        self.settle(start)
    }

    /// Number of in-flight windows. Diagnostic.
    pub fn active_windows(&self) -> usize {
        self.windows.len()
    }

    /// Parity datagrams refused, by the rules of [`FecDecoder`]. Diagnostic.
    pub fn refused_count(&self) -> u64 {
        self.refused
    }

    /// Windows dropped to make room for another. Diagnostic.
    pub fn evicted_count(&self) -> u64 {
        self.evicted
    }

    /// How far beyond the highest data frame received parity may open a
    /// window: the sequence numbers the table can cover at once.
    fn span(&self) -> u64 {
        let windows = u64::try_from(self.max_windows).unwrap_or(u64::MAX);
        u64::from(self.window_size).saturating_mul(windows)
    }

    /// Advance the clock and return it.
    fn tick(&mut self) -> u64 {
        self.clock = self.clock.wrapping_add(1);
        self.clock
    }

    /// Make room for one more window, whose standing is `newcomer`: a full
    /// table drops its window of lowest standing, least recently used among
    /// equals, but none of higher standing than the newcomer. `false`, with
    /// nothing dropped, when no window qualifies.
    fn make_room(&mut self, newcomer: Standing) -> bool {
        if self.windows.len() < self.max_windows {
            return true;
        }
        let victim = self
            .windows
            .iter()
            .map(|(&start, window)| (window.standing(), window.last_used, start))
            .filter(|&(standing, ..)| standing <= newcomer)
            .min();
        let Some((_, _, start)) = victim else {
            return false;
        };
        self.windows.remove(&start);
        self.evicted += 1;
        true
    }

    /// After a datagram reached window `start`: close the window when all K
    /// frames and the parity are in, rebuild its missing frame when K − 1
    /// frames and the parity are, and return what was rebuilt.
    fn settle(&mut self, start: u64) -> Option<(u64, Vec<u8>)> {
        let k = usize::from(self.window_size);
        let window = self.windows.get_mut(&start)?;
        let held = window.originals.len();
        if held == k {
            if window.parity.is_none() {
                // Nothing to rebuild. Keep only that fact, until the parity
                // closes the window or the table needs its place.
                window.complete = true;
                window.originals.clear();
                return None;
            }
            self.windows.remove(&start);
            return None;
        }
        if held + 1 != k || window.parity.is_none() {
            return None;
        }
        let recovered = window.try_recover(start, self.window_size)?;
        self.windows.remove(&start);
        Some(recovered)
    }
}

impl FecWindow {
    /// What the window can still do.
    fn standing(&self) -> Standing {
        if self.complete {
            Standing::Complete
        } else if self.originals.is_empty() {
            Standing::ParityOnly
        } else {
            Standing::Filling
        }
    }

    /// With `K - 1` originals and the parity in hand, XOR the originals
    /// against the parity to recover the missing one. Returns
    /// `Some((missing_seq, recovered_bytes))` on success.
    fn try_recover(&self, window_start: u64, window_n: u16) -> Option<(u64, Vec<u8>)> {
        let parity = self.parity.as_ref()?;
        // The window covers [window_start, window_start + window_n), and
        // every original held lies in it, so exactly one seq is missing.
        let mut missing_seq = None;
        for offset in 0..u64::from(window_n) {
            // A window past u64::MAX recovers nothing. Aligned windows never
            // get here (the top window cannot hold K − 1 frames); the check
            // is defence in depth.
            let seq = window_start.checked_add(offset)?;
            if !self.originals.contains_key(&seq) {
                missing_seq = Some(seq);
                break;
            }
        }
        let missing = missing_seq?;
        let mut recovered = parity.clone();
        for bytes in self.originals.values() {
            for (i, b) in bytes.iter().enumerate() {
                if i < recovered.len() {
                    recovered[i] ^= *b;
                }
            }
        }
        // Left padded: `wire::decode` reads the frame's own length.
        Some((missing, recovered))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn fec_round_trip_single_parity() {
        let mut buf = Vec::new();
        let header = FecHeader {
            window_start: 100,
            window_n: 16,
            parity_len: 4,
        };
        encode_fec(header, &[0xDE, 0xAD, 0xBE, 0xEF], &mut buf);
        let (decoded, parity) = decode_fec(&buf).unwrap();
        assert_eq!(decoded, header);
        assert_eq!(parity, &[0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn fec_decode_rejects_short() {
        match decode_fec(&[0; 10]) {
            Err(FecError::TooShort { .. }) => {}
            other => panic!("expected TooShort, got {other:?}"),
        }
    }

    #[test]
    fn fec_decode_rejects_foreign_magic() {
        let mut bad = vec![0u8; FEC_HEADER_BYTES];
        bad[..4].copy_from_slice(&0x12345678u32.to_le_bytes());
        match decode_fec(&bad) {
            Err(FecError::MagicMismatch { .. }) => {}
            other => panic!("expected MagicMismatch, got {other:?}"),
        }
    }

    #[test]
    fn fec_decode_rejects_truncated_parity() {
        let mut buf = Vec::new();
        encode_fec(
            FecHeader {
                window_start: 0,
                window_n: 1,
                parity_len: 4,
            },
            &[0; 4],
            &mut buf,
        );
        // Drop the last 2 bytes of the parity payload.
        buf.truncate(buf.len() - 2);
        match decode_fec(&buf) {
            Err(FecError::Truncated { .. }) => {}
            other => panic!("expected Truncated, got {other:?}"),
        }
    }

    #[test]
    fn encoder_emits_parity_at_window_boundary() {
        let mut enc = FecEncoder::new(3);
        assert!(enc.add_original(0, &[1, 2, 3]).is_none());
        assert!(enc.add_original(1, &[4, 5, 6]).is_none());
        let parity_dgram = enc.add_original(2, &[7, 8, 9]).expect("expected parity");
        let (hdr, parity) = decode_fec(&parity_dgram).unwrap();
        assert_eq!(hdr.window_start, 0);
        assert_eq!(hdr.window_n, 3);
        assert_eq!(parity, &[1 ^ 4 ^ 7, 2 ^ 5 ^ 8, 3 ^ 6 ^ 9]);
    }

    #[test]
    fn encoder_pads_short_to_long() {
        let mut enc = FecEncoder::new(2);
        assert!(enc.add_original(0, &[1, 2, 3, 4]).is_none());
        let parity_dgram = enc.add_original(1, &[5, 6]).expect("expected parity");
        let (_hdr, parity) = decode_fec(&parity_dgram).unwrap();
        // The shorter frame is zero-padded.
        assert_eq!(parity, &[1 ^ 5, 2 ^ 6, 3, 4]);
    }

    /// An encoder started mid-window covers only whole aligned windows, the
    /// grouping the receiver files frames under.
    #[test]
    fn an_encoder_started_mid_window_starts_at_the_next_boundary() {
        let mut enc = FecEncoder::new(4);
        for seq in 5..8u64 {
            assert!(enc.add_original(seq, &[seq as u8]).is_none(), "seq {seq}");
            assert_eq!(enc.pending_count(), 0, "seq {seq} is before the boundary");
        }
        for seq in 8..11u64 {
            assert!(enc.add_original(seq, &[seq as u8]).is_none(), "seq {seq}");
        }
        let (header, parity) = {
            let datagram = enc.add_original(11, &[11]).expect("parity after seq 11");
            let (header, parity) = decode_fec(&datagram).unwrap();
            (header, parity.to_vec())
        };
        assert_eq!((header.window_start, header.window_n), (8, 4));
        assert_eq!(parity, vec![8 ^ 9 ^ 10 ^ 11]);
    }

    /// A frame that does not continue the window in progress abandons it:
    /// that window's parity could no longer cover what was sent.
    #[test]
    fn an_encoder_abandons_a_window_it_cannot_complete() {
        let mut enc = FecEncoder::new(4);
        assert!(enc.add_original(0, &[1]).is_none());
        assert!(enc.add_original(1, &[2]).is_none());
        // Seq 2 never reaches the encoder; seq 3 cannot complete window 0.
        assert!(enc.add_original(3, &[4]).is_none());
        assert_eq!(enc.pending_count(), 0);
        for seq in 4..7u64 {
            assert!(enc.add_original(seq, &[seq as u8]).is_none());
        }
        let datagram = enc.add_original(7, &[7]).expect("parity for window 4");
        let (header, parity) = decode_fec(&datagram).unwrap();
        assert_eq!(header.window_start, 4);
        assert_eq!(parity, &[4 ^ 5 ^ 6 ^ 7]);
    }

    #[test]
    fn decoder_recovers_single_loss() {
        // Window of 3, drop seq=1.
        let mut dec = FecDecoder::new(3, 8);
        let parity_payload: Vec<u8> = (0..16)
            .map(|i| (i ^ 0xAA) as u8 ^ (i ^ 0xBB) as u8 ^ (i ^ 0xCC) as u8)
            .collect();
        let header = FecHeader {
            window_start: 0,
            window_n: 3,
            parity_len: parity_payload.len() as u32,
        };

        // Add seq=0 and seq=2 (skipping seq=1).
        let seq0: Vec<u8> = (0..16).map(|i| (i ^ 0xAA) as u8).collect();
        let seq2: Vec<u8> = (0..16).map(|i| (i ^ 0xCC) as u8).collect();
        assert!(dec.add_original(0, &seq0).is_none());
        assert!(dec.add_original(2, &seq2).is_none());

        // Add the parity. Should recover seq=1.
        let recovered = dec.add_parity(header, &parity_payload).unwrap();
        assert_eq!(recovered.0, 1);
        // XOR of seq0 ^ seq2 ^ parity should equal what seq1 would be.
        let expected_seq1: Vec<u8> = (0..16).map(|i| (i ^ 0xBB) as u8).collect();
        assert_eq!(recovered.1, expected_seq1);
        assert_eq!(dec.active_windows(), 0, "a window that rebuilt is closed");
    }

    #[test]
    fn decoder_does_not_recover_two_missing() {
        let mut dec = FecDecoder::new(3, 8);
        let header = FecHeader {
            window_start: 99,
            window_n: 3,
            parity_len: 8,
        };
        // Only one original of three; can't recover two missing.
        dec.add_original(99, &[0x11; 8]);
        assert!(dec.add_parity(header, &[0; 8]).is_none());
        assert_eq!(dec.active_windows(), 1);
    }

    /// A window that received every frame needs nothing, so its parity
    /// closes it instead of opening a window of its own.
    #[test]
    fn a_window_with_every_frame_is_closed_by_its_parity() {
        let mut dec = FecDecoder::new(4, 8);
        let mut enc = FecEncoder::new(4);
        let mut parity = None;
        for seq in 0..4u64 {
            assert!(dec.add_original(seq, &[seq as u8; 4]).is_none());
            parity = enc.add_original(seq, &[seq as u8; 4]);
        }
        assert_eq!(dec.active_windows(), 1);
        let parity = parity.unwrap();
        let (header, bytes) = decode_fec(&parity).unwrap();
        assert!(dec.add_parity(header, bytes).is_none());
        assert_eq!(dec.active_windows(), 0);
        assert_eq!(dec.refused_count(), 0);
    }

    /// A window's frames that arrived, by seq, and its parity datagram.
    type Window = (Vec<(u64, Vec<u8>)>, Vec<u8>);

    /// The frames of window `start` except `lost`, and the window's
    /// parity from the encoder; each frame's bytes name its seq.
    fn window_with_a_loss(start: u64, k: u16, lost: u64) -> Window {
        let mut enc = FecEncoder::new(k);
        let mut frames = Vec::new();
        let mut parity = None;
        for seq in start..start + u64::from(k) {
            let bytes = seq.to_le_bytes().to_vec();
            parity = enc.add_original(seq, &bytes);
            if seq != lost {
                frames.push((seq, bytes));
            }
        }
        (frames, parity.expect("a whole window has parity"))
    }

    /// Deliver a window with one loss and check the lost frame comes back.
    fn assert_rebuilt(dec: &mut FecDecoder, start: u64, k: u16, lost: u64) {
        let (frames, parity) = window_with_a_loss(start, k, lost);
        for (seq, bytes) in &frames {
            assert!(dec.add_original(*seq, bytes).is_none());
        }
        let (header, bytes) = decode_fec(&parity).unwrap();
        let (seq, rebuilt) = dec
            .add_parity(header, bytes)
            .unwrap_or_else(|| panic!("seq {lost} of window {start} was not rebuilt"));
        assert_eq!((seq, rebuilt), (lost, lost.to_le_bytes().to_vec()));
    }

    /// A parity datagram claiming window `start`, with the window size `n`.
    fn forged(start: u64, n: u16) -> FecHeader {
        FecHeader {
            window_start: start,
            window_n: n,
            parity_len: 8,
        }
    }

    /// A burst of forged parity for windows far above the stream cannot
    /// hold the table: parity alone never displaces a window frames are
    /// filling, and parity far beyond the frames received is refused.
    #[test]
    fn a_burst_of_forged_high_parity_does_not_turn_recovery_off() {
        let mut dec = FecDecoder::new(4, 8);
        let high = u64::MAX / 4 * 4 - 4 * 64;
        // Before any frame there is nothing to measure from: the burst fills
        // the table with windows opened by parity alone.
        for i in 0..8u64 {
            assert!(dec
                .add_parity(forged(high - 4 * i, 4), &[0x5A; 8])
                .is_none());
        }
        assert_eq!(dec.active_windows(), 8);
        assert_eq!(dec.refused_count(), 0);
        // The stream's window takes the place of one of them.
        assert_rebuilt(&mut dec, 0, 4, 2);
        assert_eq!(dec.evicted_count(), 1);

        // Once frames have arrived, a burst for windows far above them is
        // refused and counted, as are parity for another window size and an
        // unaligned start.
        for i in 0..8u64 {
            let start = high - 4 * (64 + i);
            assert!(dec.add_parity(forged(start, 4), &[0x5A; 8]).is_none());
        }
        assert!(dec.add_parity(forged(4, 16), &[0x5A; 8]).is_none());
        assert!(dec.add_parity(forged(6, 4), &[0x5A; 8]).is_none());
        assert_eq!(dec.refused_count(), 10);
        assert_rebuilt(&mut dec, 4, 4, 5);
        assert_rebuilt(&mut dec, 8, 4, 8);
    }

    /// Windows opened by forged data frames age out: a full table gives up
    /// its least recently used window, whatever the windows' starts.
    #[test]
    fn windows_forged_data_frames_opened_age_out() {
        let mut dec = FecDecoder::new(4, 4);
        for i in 1..=4u64 {
            assert!(dec.add_original(u64::MAX - 4 * i, &[0xEE; 8]).is_none());
        }
        assert_eq!(dec.active_windows(), 4);
        // The stream fills four windows, one frame lost in each, before any
        // of their parity arrives: each takes a forged window's place.
        let windows: Vec<(u64, Window)> = [0u64, 4, 8, 12]
            .into_iter()
            .map(|start| (start, window_with_a_loss(start, 4, start + 1)))
            .collect();
        for (_, (frames, _)) in &windows {
            for (seq, bytes) in frames {
                assert!(dec.add_original(*seq, bytes).is_none());
            }
        }
        assert_eq!(dec.evicted_count(), 4, "every forged window went");
        for (start, (_, parity)) in &windows {
            let (header, bytes) = decode_fec(parity).unwrap();
            assert_eq!(dec.add_parity(header, bytes).map(|r| r.0), Some(start + 1));
        }
    }

    /// With the table full of windows that frames are filling, parity for
    /// any other window is refused rather than let in at their expense, and
    /// the filling windows still rebuild when their parity comes.
    #[test]
    fn parity_never_displaces_a_window_frames_are_filling() {
        let mut dec = FecDecoder::new(4, 2);
        let (first, first_parity) = window_with_a_loss(0, 4, 2);
        let (second, second_parity) = window_with_a_loss(4, 4, 6);
        for (seq, bytes) in first.iter().chain(&second) {
            assert!(dec.add_original(*seq, bytes).is_none());
        }
        assert!(dec.add_parity(forged(8, 4), &[0x5A; 8]).is_none());
        assert_eq!((dec.refused_count(), dec.evicted_count()), (1, 0));
        for (parity, lost) in [(&first_parity, 2u64), (&second_parity, 6)] {
            let (header, bytes) = decode_fec(parity).unwrap();
            assert_eq!(dec.add_parity(header, bytes).map(|r| r.0), Some(lost));
        }
    }

    /// A full table gives up first a window with every frame, then one
    /// opened by parity alone, then the least recently used window frames
    /// are filling.
    #[test]
    fn a_full_table_gives_up_the_window_that_can_do_least() {
        let mut dec = FecDecoder::new(2, 3);
        // Window 0 complete, window 2 parity only, window 4 filling.
        dec.add_original(0, &[0]);
        dec.add_original(1, &[1]);
        dec.add_parity(forged(2, 2), &[0]);
        dec.add_original(4, &[4]);
        assert_eq!(dec.active_windows(), 3);
        // Window 6 takes the place of window 0, which had every frame.
        dec.add_original(6, &[6]);
        assert_eq!(dec.evicted_count(), 1);
        // Parity for window 0 now opens a window, in the place of window 2,
        // the one opened by parity alone.
        assert!(dec.add_parity(forged(0, 2), &[0]).is_none());
        assert_eq!((dec.evicted_count(), dec.refused_count()), (2, 0));
        // Window 8 takes the place of that parity-only window 0, and window
        // 10 the place of window 4, used before window 6.
        dec.add_original(8, &[8]);
        dec.add_original(10, &[10]);
        assert_eq!(dec.evicted_count(), 4);
        assert_eq!(dec.add_parity(forged(6, 2), &[6 ^ 7]).map(|r| r.0), Some(7));
        assert!(
            dec.add_parity(forged(4, 2), &[4 ^ 5]).is_none(),
            "window 4 is gone"
        );
    }

    /// At the smallest table, one window, recovery works window after
    /// window with forged parity arriving in between.
    #[test]
    fn recovery_works_at_a_table_of_one_window() {
        let mut dec = FecDecoder::new(4, 1);
        for w in 0..16u64 {
            let start = 4 * w;
            let (frames, parity) = window_with_a_loss(start, 4, start + w % 4);
            for (seq, bytes) in &frames {
                assert!(dec.add_original(*seq, bytes).is_none());
            }
            assert!(dec.add_parity(forged(start + 4, 4), &[0x5A; 8]).is_none());
            let (header, bytes) = decode_fec(&parity).unwrap();
            assert_eq!(
                dec.add_parity(header, bytes).map(|r| r.0),
                Some(start + w % 4)
            );
            assert!(dec.active_windows() <= 1);
        }
        assert_eq!(dec.refused_count(), 16);
    }

    /// The largest parity a sender makes is exactly one MTU: the FEC header
    /// and the longest frame an envelope of `FEC_MAX_ENVELOPE` bytes makes.
    #[test]
    fn the_largest_parity_fits_the_mtu_budget() {
        use crate::wire::{datagram_size, MAX_ENVELOPE, MTU_BYTES};
        assert_eq!(FEC_MAX_ENVELOPE, 1297);
        assert_eq!(
            FEC_HEADER_BYTES + datagram_size(FEC_MAX_ENVELOPE),
            MTU_BYTES
        );
        assert_eq!(FEC_HEADER_BYTES + datagram_size(MAX_ENVELOPE), 1490);
    }

    #[test]
    fn fec_constants_are_distinct_from_other_magics() {
        assert_ne!(FEC_MAGIC, crate::wire::MAGIC);
        assert_ne!(FEC_MAGIC, crate::backpressure::ACK_MAGIC);
        assert_ne!(FEC_MAGIC, crate::backpressure::NACK_MAGIC);
    }

    /// A datagram with a valid magic and `window_n == 0` is refused.
    #[test]
    fn zero_window_is_rejected() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&FEC_MAGIC.to_le_bytes());
        bytes.extend_from_slice(&7u64.to_le_bytes()); // window_start
        bytes.extend_from_slice(&0u16.to_le_bytes()); // window_n = 0
        bytes.extend_from_slice(&4u32.to_le_bytes()); // parity_len
        bytes.extend_from_slice(&[0xd7; 4]);
        assert!(
            matches!(
                decode_fec(&bytes),
                Err(FecError::InvalidWindow { window_n: 0 })
            ),
            "window_n = 0 accepted"
        );
    }

    /// A forged parity header whose window runs past the top of the
    /// sequence range decodes, each field being in range, and the decoder
    /// refuses it: its start is not a multiple of K. An aligned window at
    /// the top neither panics nor wraps.
    #[test]
    fn a_window_past_the_top_of_the_sequence_range_is_rejected() {
        let mut forged_top = Vec::new();
        encode_fec(
            FecHeader {
                window_start: u64::MAX,
                window_n: 2,
                parity_len: 4,
            },
            &[0xA5; 4],
            &mut forged_top,
        );
        let (header, parity) = decode_fec(&forged_top).unwrap();
        let mut dec = FecDecoder::new(2, 8);
        assert!(dec.add_parity(header, parity).is_none());
        assert_eq!(dec.refused_count(), 1);
        assert!(dec.add_original(u64::MAX, &[1, 2, 3, 4]).is_none());

        // K = 3 divides 2^64 - 1, so the top window starts at u64::MAX and
        // holds one frame of its three: it can never rebuild.
        let mut dec = FecDecoder::new(3, 8);
        assert!(dec.add_original(u64::MAX, &[1, 2, 3, 4]).is_none());
        assert!(dec.add_parity(forged(u64::MAX, 3), &[0; 4]).is_none());

        // A window that ends exactly at u64::MAX still recovers.
        let mut dec = FecDecoder::new(2, 8);
        let header = FecHeader {
            window_start: u64::MAX - 1,
            window_n: 2,
            parity_len: 4,
        };
        assert!(dec.add_original(u64::MAX - 1, &[1, 2, 3, 4]).is_none());
        let (seq, bytes) = dec
            .add_parity(header, &[1 ^ 5, 2 ^ 6, 3 ^ 7, 4 ^ 8])
            .unwrap();
        assert_eq!(seq, u64::MAX);
        assert_eq!(bytes, vec![5, 6, 7, 8]);
    }
}
